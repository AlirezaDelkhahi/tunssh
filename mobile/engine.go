package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AlirezaDelkhahi/tunssh/internal/dns"
	"github.com/AlirezaDelkhahi/tunssh/internal/splitroute"
	"github.com/AlirezaDelkhahi/tunssh/internal/sshclient"
	"github.com/AlirezaDelkhahi/tunssh/internal/tun"
)

const (
	defaultStatsInterval    = 1 * time.Second
	defaultStopTimeout      = 5 * time.Second
	defaultResolveTimeout   = 4 * time.Second
	perTargetResolveTimeout = 2500 * time.Millisecond
	defaultMobileBypassDNS  = "178.22.122.100:53"
	defaultMobileIfaceName  = "tun0"
	defaultRTTProbeTimeout  = 4 * time.Second
	defaultPeerResolveDNS1  = "1.1.1.1:53"
	defaultPeerResolveDNS2  = "8.8.8.8:53"
)

// Engine orchestrates the SSH tunnel, embedded DNS server, and FD-backed TUN runner
// for Android via gomobile without touching OS netlink or desktop dependencies.
type Engine struct {
	listener EventListener
	scrubber *secretScrubber
	logs     *logBuffer
	logger   *slog.Logger
	ssh      *sshclient.Client

	teardownMu   sync.Mutex
	bypassSyncMu sync.Mutex
	tunOpWG      sync.WaitGroup
	bgTeardownWG sync.WaitGroup

	mu               sync.Mutex
	lifecycleCtx     context.Context
	lifecycleCancel  context.CancelFunc
	stopRequested    bool
	protector        SocketProtector
	lastProfileID    string
	bypassIranLAN    bool
	enableIPv6       bool
	upstreamDNS      []string
	dnsSrv           *dns.Server
	dnsCancel        context.CancelFunc
	tunRunner        *tun.Runner
	tunAttached      bool
	tunTransitioning bool
	tickerCancel     context.CancelFunc
	tickerDone       chan struct{}
	lastStatsTime    time.Time
	lastRxBytes      uint64
	lastTxBytes      uint64
	lastRxRate       uint64
	lastTxRate       uint64
}

// NewEngine constructs a mobile Engine that emits redacted logs and status/host-key events to listener.
func NewEngine(listener EventListener) *Engine {
	scrubber := newSecretScrubber()
	logs := newLogBuffer(defaultLogBufferCapacity)

	handler := newRedactingHandler(nil, scrubber, logs, func(entry logEntryDTO) {
		if listener == nil {
			return
		}
		b, err := json.Marshal(entry)
		if err != nil {
			return
		}
		listener.OnLog(string(b))
	})

	eng := &Engine{
		listener: listener,
		scrubber: scrubber,
		logs:     logs,
		logger:   slog.New(handler),
		ssh:      sshclient.NewClient(),
	}

	eng.ssh.Subscribe(func(snap sshclient.EngineSnapshot) {
		eng.handleSSHSnapshot(snap)
	})

	return eng
}

// ConnectSsh validates configJSON, scrubs secrets, resolves the peer IP using protected sockets,
// and establishes the TOFU-verified SSH session.
func (e *Engine) ConnectSsh(configJSON string, protector SocketProtector) error {
	var cfg connectConfigDTO
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("mobile: invalid connect config JSON: %w", err)
	}

	cfg.ProfileID = strings.TrimSpace(cfg.ProfileID)
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.AuthType = strings.TrimSpace(cfg.AuthType)

	if cfg.Host == "" {
		return errors.New("mobile: host must not be empty")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("mobile: invalid port %d", cfg.Port)
	}
	if cfg.Username == "" {
		return errors.New("mobile: username must not be empty")
	}
	if cfg.AuthType != string(sshclient.AuthPassword) && cfg.AuthType != string(sshclient.AuthKey) {
		return fmt.Errorf("mobile: unsupported auth_type %q", cfg.AuthType)
	}

	// Register secrets before any logging or dialing.
	e.scrubber.setSecrets([]string{cfg.Password, cfg.PrivateKey, cfg.KeyPassphrase})

	// Cancel any prior session, wait for in-flight TUN transitions/background teardowns, and tear down TUN/DNS.
	e.mu.Lock()
	e.stopRequested = true
	prevCancel := e.lifecycleCancel
	e.mu.Unlock()
	if prevCancel != nil {
		prevCancel()
	}
	e.tunOpWG.Wait()
	e.bgTeardownWG.Wait()
	e.teardownTUNAndDNS()

	normalizedDNS := normalizeUpstreamDNSList(cfg.UpstreamDNS)

	e.mu.Lock()
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	e.lifecycleCtx = lifecycleCtx
	e.lifecycleCancel = lifecycleCancel
	e.stopRequested = false
	e.protector = protector
	e.lastProfileID = cfg.ProfileID
	e.bypassIranLAN = cfg.BypassIranLAN
	e.enableIPv6 = cfg.EnableIPv6
	e.upstreamDNS = slices.Clone(normalizedDNS)
	e.lastStatsTime = time.Time{}
	e.lastRxBytes = 0
	e.lastTxBytes = 0
	e.lastRxRate = 0
	e.lastTxRate = 0
	e.mu.Unlock()

	resolvedIP, err := resolvePeerIP(lifecycleCtx, cfg.Host, normalizedDNS, protector)
	if err != nil {
		e.logger.Error("Failed to resolve SSH host", "host", cfg.Host, "error", err)
		return err
	}

	var pinned *sshclient.HostKeyPin
	if cfg.PinnedHostKey != nil && (strings.TrimSpace(cfg.PinnedHostKey.Algorithm) != "" || strings.TrimSpace(cfg.PinnedHostKey.SHA256) != "") {
		pinned = &sshclient.HostKeyPin{
			Algorithm: strings.TrimSpace(cfg.PinnedHostKey.Algorithm),
			SHA256:    strings.TrimSpace(cfg.PinnedHostKey.SHA256),
		}
	}

	sshCfg := sshclient.ConnectConfig{
		ProfileID: cfg.ProfileID,
		Host:      cfg.Host,
		DialHost:  resolvedIP,
		Port:      cfg.Port,
		Username:  cfg.Username,
		Auth: sshclient.AuthConfig{
			Type:          sshclient.AuthType(cfg.AuthType),
			Password:      cfg.Password,
			PrivateKey:    cfg.PrivateKey,
			KeyPassphrase: cfg.KeyPassphrase,
		},
		PinnedHostKey: pinned,
		DialControl:   protectControl(protector),
	}

	e.logger.Info("Connecting SSH tunnel", "profile_id", cfg.ProfileID, "host", cfg.Host, "port", cfg.Port)
	if err := e.ssh.Connect(lifecycleCtx, sshCfg); err != nil {
		e.logger.Error("SSH connection failed", "host", cfg.Host, "port", cfg.Port, "error", e.scrubber.scrub(err.Error()))
		return err
	}

	e.logger.Info("SSH tunnel connected", "profile_id", cfg.ProfileID, "host", cfg.Host, "port", cfg.Port)
	return nil
}

// AttachTun takes ownership of tunFD, starts the embedded DNS server and FD-backed TUN runner,
// and begins periodic status/rate updates. On any error, tunFD is guaranteed closed.
func (e *Engine) AttachTun(tunFD int32) error {
	var fdOnce sync.Once
	closeUnusedFD := func() {
		fdOnce.Do(func() {
			if tunFD >= 0 {
				closeFD(int(tunFD))
			}
		})
	}
	fdHandedToRunner := false
	committed := false

	if tunFD < 0 {
		return fmt.Errorf("mobile: invalid tun fd %d", tunFD)
	}

	snap := e.ssh.Snapshot()
	if snap.State != sshclient.StateConnected {
		closeUnusedFD()
		return errors.New("mobile: SSH tunnel must be connected before attaching TUN")
	}

	e.mu.Lock()
	if e.stopRequested || e.lifecycleCtx == nil || e.lifecycleCtx.Err() != nil {
		e.mu.Unlock()
		closeUnusedFD()
		return errors.New("mobile: engine lifecycle is not active")
	}
	if e.tunAttached || e.tunRunner != nil || e.dnsSrv != nil || e.tunTransitioning {
		e.mu.Unlock()
		closeUnusedFD()
		return errors.New("mobile: TUN is already attached or transitioning")
	}
	e.tunTransitioning = true
	e.tunOpWG.Add(1)
	protector := e.protector
	bypassIranLAN := e.bypassIranLAN
	enableIPv6 := e.enableIPv6
	upstreamDNS := slices.Clone(e.upstreamDNS)
	lifecycleCtx := e.lifecycleCtx
	e.mu.Unlock()

	defer func() {
		if !committed {
			if !fdHandedToRunner {
				closeUnusedFD()
			}
			e.mu.Lock()
			if e.lifecycleCtx == lifecycleCtx {
				e.tunTransitioning = false
			}
			e.mu.Unlock()
		}
		e.tunOpWG.Done()
	}()

	dnsSrv := dns.NewServer()
	dnsRunCtx, dnsRunCancel := context.WithCancel(lifecycleCtx)
	dnsCfg := dns.DNSConfig{
		ListenAddr:      dns.DefaultListenAddr,
		TunnelDialer:    e.ssh,
		BypassDialer:    protectedBypassDialer{protector: protector},
		BypassUpstreams: normalizeBypassUpstreams(upstreamDNS),
		BypassIranLAN:   bypassIranLAN,
		SuppressAAAA:    true,
	}
	if err := dnsSrv.Start(dnsRunCtx, dnsCfg); err != nil {
		dnsRunCancel()
		return fmt.Errorf("mobile: start embedded DNS: %w", err)
	}

	tunRunner := tun.NewFDRunner(int(tunFD))
	tunCfg := tun.Config{
		IfaceName:     defaultMobileIfaceName,
		MTU:           splitroute.TUNMTU,
		IPv4CIDR:      splitroute.TUNIPv4CIDR,
		IPv6CIDR:      splitroute.TUNIPv6CIDR,
		EnableIPv6:    enableIPv6,
		BlockIPv6Data: enableIPv6,
		TunnelDialer:  e.ssh,
		DNSUDPAddr:    dnsSrv.UDPAddr(),
		DNSTCPAddr:    dnsSrv.TCPAddr(),
	}
	fdHandedToRunner = true
	if _, err := tunRunner.Start(lifecycleCtx, tunCfg); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), defaultStopTimeout)
		_ = dnsSrv.Stop(stopCtx)
		cancel()
		dnsRunCancel()
		return fmt.Errorf("mobile: start FD TUN runner: %w", err)
	}

	if lifecycleCtx.Err() != nil || e.ssh.Snapshot().State != sshclient.StateConnected {
		stopCtx, cancel := context.WithTimeout(context.Background(), defaultStopTimeout)
		_ = tunRunner.Stop(stopCtx)
		_ = dnsSrv.Stop(stopCtx)
		cancel()
		dnsRunCancel()
		return errors.New("mobile: tunnel disconnected while attaching TUN")
	}

	tickerCtx, tickerCancel := context.WithCancel(lifecycleCtx)
	tickerDone := make(chan struct{})

	e.mu.Lock()
	if e.stopRequested || e.lifecycleCtx != lifecycleCtx || lifecycleCtx.Err() != nil {
		e.mu.Unlock()
		tickerCancel()
		close(tickerDone)
		stopCtx, cancel := context.WithTimeout(context.Background(), defaultStopTimeout)
		_ = tunRunner.Stop(stopCtx)
		_ = dnsSrv.Stop(stopCtx)
		cancel()
		dnsRunCancel()
		return context.Canceled
	}
	dnsChanged := !slices.Equal(e.upstreamDNS, upstreamDNS)
	e.dnsSrv = dnsSrv
	e.dnsCancel = dnsRunCancel
	e.tunRunner = tunRunner
	e.tunAttached = true
	e.tunTransitioning = false
	e.tickerCancel = tickerCancel
	e.tickerDone = tickerDone
	e.lastStatsTime = time.Now()
	committed = true
	e.mu.Unlock()

	if dnsChanged {
		if err := e.syncBypassUpstreams(dnsSrv); err != nil {
			e.logger.Warn("Failed to sync updated bypass DNS upstreams during AttachTun", "error", err)
		}
	}

	go e.statsTickerLoop(tickerCtx, tickerDone)

	e.logger.Info("TUN attached", "iface", defaultMobileIfaceName, "ipv6", enableIPv6)
	e.emitStatus()
	return nil
}

// ReplaceTun atomically swaps the active TUN runner with a new FD-backed runner (e.g., on Android
// VpnService.Builder re-establishment) without interrupting the SSH session or DNS server.
func (e *Engine) ReplaceTun(tunFD int32) error {
	var fdOnce sync.Once
	closeUnusedFD := func() {
		fdOnce.Do(func() {
			if tunFD >= 0 {
				closeFD(int(tunFD))
			}
		})
	}
	fdHandedToRunner := false
	committed := false

	if tunFD < 0 {
		return fmt.Errorf("mobile: invalid tun fd %d", tunFD)
	}

	e.mu.Lock()
	if e.stopRequested || !e.tunAttached || e.tunRunner == nil || e.dnsSrv == nil || e.lifecycleCtx == nil || e.lifecycleCtx.Err() != nil {
		e.mu.Unlock()
		closeUnusedFD()
		return errors.New("mobile: cannot replace TUN when no TUN session is active")
	}
	if e.tunTransitioning {
		e.mu.Unlock()
		closeUnusedFD()
		return errors.New("mobile: TUN transition already in progress")
	}
	e.tunTransitioning = true
	e.tunOpWG.Add(1)
	oldRunner := e.tunRunner
	dnsUDP := e.dnsSrv.UDPAddr()
	dnsTCP := e.dnsSrv.TCPAddr()
	enableIPv6 := e.enableIPv6
	lifecycleCtx := e.lifecycleCtx
	e.mu.Unlock()

	defer func() {
		if !committed {
			if !fdHandedToRunner {
				closeUnusedFD()
			}
			e.mu.Lock()
			if e.lifecycleCtx == lifecycleCtx {
				e.tunTransitioning = false
			}
			e.mu.Unlock()
		}
		e.tunOpWG.Done()
	}()

	newRunner := tun.NewFDRunner(int(tunFD))
	tunCfg := tun.Config{
		IfaceName:     defaultMobileIfaceName,
		MTU:           splitroute.TUNMTU,
		IPv4CIDR:      splitroute.TUNIPv4CIDR,
		IPv6CIDR:      splitroute.TUNIPv6CIDR,
		EnableIPv6:    enableIPv6,
		BlockIPv6Data: enableIPv6,
		TunnelDialer:  e.ssh,
		DNSUDPAddr:    dnsUDP,
		DNSTCPAddr:    dnsTCP,
	}
	fdHandedToRunner = true
	if _, err := newRunner.Start(lifecycleCtx, tunCfg); err != nil {
		return fmt.Errorf("mobile: start replacement FD TUN runner: %w", err)
	}

	e.mu.Lock()
	if e.stopRequested || !e.tunAttached || e.tunRunner != oldRunner || e.lifecycleCtx != lifecycleCtx || lifecycleCtx.Err() != nil {
		e.mu.Unlock()
		stopCtx, cancel := context.WithTimeout(context.Background(), defaultStopTimeout)
		_ = newRunner.Stop(stopCtx)
		cancel()
		return context.Canceled
	}
	e.tunRunner = newRunner
	e.tunTransitioning = false
	committed = true
	e.mu.Unlock()

	stopCtx, cancel := context.WithTimeout(context.Background(), defaultStopTimeout)
	stopErr := oldRunner.Stop(stopCtx)
	cancel()
	if stopErr != nil {
		e.logger.Warn("Failed to cleanly stop replaced TUN runner", "error", stopErr)
	}

	e.logger.Info("Replaced TUN device", "iface", defaultMobileIfaceName)
	e.emitStatus()
	return nil
}

// SetBypass dynamically toggles Iran/LAN DNS bypass and emits an updated status event.
func (e *Engine) SetBypass(bypassIranLan bool) error {
	e.mu.Lock()
	e.bypassIranLAN = bypassIranLan
	dnsSrv := e.dnsSrv
	e.mu.Unlock()

	if dnsSrv != nil {
		dnsSrv.SetBypassIranLAN(bypassIranLan)
	}

	e.logger.Info("Updated bypass setting", "bypass_iran_lan", bypassIranLan)
	e.emitStatus()
	return nil
}

// NotifyNetworkChanged parses an optional JSON array of upstream DNS IPs, updates bypass DNS
// forwarding and flushes the DNS cache, and triggers a bounded non-blocking SSH RTT probe.
func (e *Engine) NotifyNetworkChanged(upstreamDnsJSON string) error {
	var normalized []string
	trimmed := strings.TrimSpace(upstreamDnsJSON)
	if trimmed != "" {
		var raw []string
		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			return fmt.Errorf("mobile: invalid upstream DNS JSON: %w", err)
		}
		normalized = normalizeUpstreamDNSList(raw)
	}

	e.mu.Lock()
	e.upstreamDNS = slices.Clone(normalized)
	dnsSrv := e.dnsSrv
	lifecycleCtx := e.lifecycleCtx
	e.mu.Unlock()

	if dnsSrv != nil {
		if err := e.syncBypassUpstreams(dnsSrv); err != nil {
			return fmt.Errorf("mobile: update bypass DNS upstreams: %w", err)
		}
	}

	if lifecycleCtx != nil && lifecycleCtx.Err() == nil && e.ssh.Snapshot().State == sshclient.StateConnected {
		go func(ctx context.Context) {
			rttCtx, cancel := context.WithTimeout(ctx, defaultRTTProbeTimeout)
			defer cancel()
			if _, err := e.ssh.MeasureRTT(rttCtx); err == nil {
				e.emitStatus()
			}
		}(lifecycleCtx)
	}

	e.logger.Info("Network change processed", "upstream_dns_count", len(normalized))
	return nil
}

// Stop tears down any in-flight TUN operations, background error teardowns, ticker,
// TUN runner, embedded DNS server, and SSH connection, clears active secrets, and emits final status.
func (e *Engine) Stop() error {
	e.mu.Lock()
	e.stopRequested = true
	lifecycleCancel := e.lifecycleCancel
	e.mu.Unlock()

	if lifecycleCancel != nil {
		lifecycleCancel()
	}

	// Wait for any in-flight AttachTun/ReplaceTun and async StateError teardowns before stopping SSH.
	e.tunOpWG.Wait()
	e.bgTeardownWG.Wait()

	var errs []error
	if err := e.teardownTUNAndDNS(); err != nil {
		errs = append(errs, err)
	}

	e.mu.Lock()
	e.lifecycleCancel = nil
	e.lifecycleCtx = nil
	e.protector = nil
	e.lastStatsTime = time.Time{}
	e.lastRxBytes = 0
	e.lastTxBytes = 0
	e.lastRxRate = 0
	e.lastTxRate = 0
	e.mu.Unlock()

	stopCtx, cancel := context.WithTimeout(context.Background(), defaultStopTimeout)
	defer cancel()
	if err := e.ssh.Disconnect(stopCtx); err != nil {
		errs = append(errs, fmt.Errorf("mobile: disconnect SSH: %w", err))
	}

	e.logger.Info("Mobile tunnel stopped")
	e.scrubber.setSecrets(nil)
	e.emitStatus()

	return errors.Join(errs...)
}

// StatusJson returns the current tunnel status serialized as JSON.
func (e *Engine) StatusJson() string {
	dto := e.buildStatusDTO(e.ssh.Snapshot(), false)
	b, err := json.Marshal(dto)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// LogsJson returns all buffered redacted log entries serialized as a JSON array.
func (e *Engine) LogsJson() string {
	entries := e.logs.snapshot()
	b, err := json.Marshal(entries)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ClearLogs clears all buffered diagnostic log entries.
func (e *Engine) ClearLogs() {
	e.logs.clear()
}

func (e *Engine) syncBypassUpstreams(dnsSrv *dns.Server) error {
	e.bypassSyncMu.Lock()
	defer e.bypassSyncMu.Unlock()

	e.mu.Lock()
	latestDNS := slices.Clone(e.upstreamDNS)
	activeSrv := e.dnsSrv
	e.mu.Unlock()

	if dnsSrv == nil || activeSrv != dnsSrv {
		return nil
	}
	return dnsSrv.UpdateBypassUpstreams(normalizeBypassUpstreams(latestDNS))
}

func (e *Engine) teardownTUNAndDNS() error {
	e.teardownMu.Lock()
	defer e.teardownMu.Unlock()

	e.mu.Lock()
	tickerCancel := e.tickerCancel
	tickerDone := e.tickerDone
	tunRunner := e.tunRunner
	dnsSrv := e.dnsSrv
	dnsCancel := e.dnsCancel
	e.tickerCancel = nil
	e.tickerDone = nil
	e.tunRunner = nil
	e.dnsSrv = nil
	e.dnsCancel = nil
	e.tunAttached = false
	e.tunTransitioning = false
	e.mu.Unlock()

	if tickerCancel != nil {
		tickerCancel()
	}
	if tickerDone != nil {
		<-tickerDone
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), defaultStopTimeout)
	defer cancel()

	var errs []error
	if tunRunner != nil {
		if err := tunRunner.Stop(stopCtx); err != nil {
			errs = append(errs, fmt.Errorf("mobile: stop TUN runner: %w", err))
		}
	}
	if dnsSrv != nil {
		if err := dnsSrv.Stop(stopCtx); err != nil {
			errs = append(errs, fmt.Errorf("mobile: stop DNS server: %w", err))
		}
	}
	if dnsCancel != nil {
		dnsCancel()
	}
	return errors.Join(errs...)
}

func (e *Engine) statsTickerLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(defaultStatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dto := e.buildStatusDTO(e.ssh.Snapshot(), true)
			e.emitStatusDTO(dto)
		}
	}
}

func (e *Engine) handleSSHSnapshot(snap sshclient.EngineSnapshot) {
	if snap.State == sshclient.StateError {
		e.mu.Lock()
		shouldTeardown := (e.tunAttached || e.tunTransitioning) && !e.stopRequested
		if shouldTeardown {
			if e.lifecycleCancel != nil {
				e.lifecycleCancel()
			}
			e.bgTeardownWG.Add(1)
		}
		e.mu.Unlock()

		if shouldTeardown {
			go func() {
				defer e.bgTeardownWG.Done()
				e.tunOpWG.Wait()
				if err := e.teardownTUNAndDNS(); err != nil {
					e.logger.Warn("Failed to tear down TUN after SSH runtime error", "error", err)
				}
				e.emitStatus()
			}()
		}
	}

	if e.listener == nil {
		return
	}

	if snap.HostKeyMismatch != nil {
		m := snap.HostKeyMismatch
		prompt := hostKeyPromptDTO{
			Host:              m.Host,
			Port:              m.Port,
			Algorithm:         m.ActualAlg,
			SHA256:            m.ActualSHA256,
			Mismatch:          true,
			ExpectedAlgorithm: m.ExpectedAlg,
			ExpectedSHA256:    m.ExpectedSHA256,
		}
		if b, err := json.Marshal(prompt); err == nil {
			e.listener.OnHostKeyPrompt(string(b))
		}
	} else if snap.HostKeyPrompt != nil {
		u := snap.HostKeyPrompt
		prompt := hostKeyPromptDTO{
			Host:      u.Host,
			Port:      u.Port,
			Algorithm: u.Algorithm,
			SHA256:    u.SHA256,
			Mismatch:  false,
		}
		if b, err := json.Marshal(prompt); err == nil {
			e.listener.OnHostKeyPrompt(string(b))
		}
	}

	e.emitStatusDTO(e.buildStatusDTO(snap, false))
}

func (e *Engine) emitStatus() {
	e.emitStatusDTO(e.buildStatusDTO(e.ssh.Snapshot(), false))
}

func (e *Engine) emitStatusDTO(dto statusDTO) {
	if e.listener == nil {
		return
	}
	b, err := json.Marshal(dto)
	if err != nil {
		return
	}
	e.listener.OnStatusChanged(string(b))
}

func (e *Engine) buildStatusDTO(snap sshclient.EngineSnapshot, updateRates bool) statusDTO {
	e.mu.Lock()
	tunRunner := e.tunRunner
	tunAttached := e.tunAttached
	bypassIranLAN := e.bypassIranLAN
	profileID := snap.ProfileID
	if profileID == "" {
		profileID = e.lastProfileID
	}
	lastRxRate := e.lastRxRate
	lastTxRate := e.lastTxRate
	e.mu.Unlock()

	rxBytes := snap.RxBytes
	txBytes := snap.TxBytes
	if tunRunner != nil {
		tunStats := tunRunner.Stats()
		if tunStats.RxBytes > rxBytes {
			rxBytes = tunStats.RxBytes
		}
		if tunStats.TxBytes > txBytes {
			txBytes = tunStats.TxBytes
		}
	}

	var rxRate, txRate uint64
	if snap.State == sshclient.StateConnected {
		if updateRates {
			now := time.Now()
			e.mu.Lock()
			if !e.lastStatsTime.IsZero() {
				dt := now.Sub(e.lastStatsTime).Seconds()
				if dt > 0 {
					if rxBytes >= e.lastRxBytes {
						rxRate = uint64(float64(rxBytes-e.lastRxBytes) / dt)
					}
					if txBytes >= e.lastTxBytes {
						txRate = uint64(float64(txBytes-e.lastTxBytes) / dt)
					}
				}
			}
			e.lastStatsTime = now
			e.lastRxBytes = rxBytes
			e.lastTxBytes = txBytes
			e.lastRxRate = rxRate
			e.lastTxRate = txRate
			e.mu.Unlock()
		} else {
			rxRate = lastRxRate
			txRate = lastTxRate
		}
	}

	var connectedAtUnix int64
	if snap.State == sshclient.StateConnected && !snap.ConnectedAt.IsZero() {
		connectedAtUnix = snap.ConnectedAt.Unix()
	}

	var lastErrDTO *errorDTO
	if snap.LastError != nil {
		lastErrDTO = &errorDTO{
			Code:       snap.LastError.Code,
			Message:    e.scrubber.scrub(snap.LastError.Message),
			ActionHint: e.scrubber.scrub(snap.LastError.ActionHint),
			Retryable:  snap.LastError.Retryable,
		}
	}

	return statusDTO{
		State:           string(snap.State),
		ProfileID:       profileID,
		Attempt:         snap.Attempt,
		RTTMs:           snap.RTTMs,
		RxBytes:         rxBytes,
		TxBytes:         txBytes,
		RxRateBPS:       rxRate,
		TxRateBPS:       txRate,
		ConnectedAtUnix: connectedAtUnix,
		TunAttached:     tunAttached,
		BypassIranLAN:   bypassIranLAN,
		LastError:       lastErrDTO,
	}
}

type protectedBypassDialer struct {
	protector SocketProtector
}

func (d protectedBypassDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var control func(network, address string, c syscall.RawConn) error
	if d.protector != nil {
		if host, _, err := net.SplitHostPort(address); err == nil {
			if ip, parseErr := netip.ParseAddr(strings.TrimSpace(host)); parseErr == nil {
				if !ip.Unmap().IsLoopback() {
					control = protectControl(d.protector)
				}
			} else {
				control = protectControl(d.protector)
			}
		} else {
			control = protectControl(d.protector)
		}
	}
	dialer := &net.Dialer{
		Timeout: defaultResolveTimeout,
		Control: control,
	}
	return dialer.DialContext(ctx, network, address)
}

func protectControl(protector SocketProtector) func(network, address string, c syscall.RawConn) error {
	if protector == nil {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		if c == nil {
			return nil
		}
		var ok bool
		if err := c.Control(func(fd uintptr) {
			ok = protector.Protect(int32(fd))
		}); err != nil {
			return err
		}
		if !ok {
			return errors.New("mobile: VpnService.protect failed")
		}
		return nil
	}
}

func resolvePeerIP(ctx context.Context, host string, upstreamDNS []string, protector SocketProtector) (string, error) {
	trimmed := strings.TrimSpace(host)
	trimmed = strings.TrimPrefix(trimmed, "[")
	trimmed = strings.TrimSuffix(trimmed, "]")
	if trimmed == "" {
		return "", errors.New("mobile: host must not be empty")
	}

	if ip, err := netip.ParseAddr(trimmed); err == nil {
		u := ip.Unmap()
		if !u.IsValid() || u.IsUnspecified() || u.IsMulticast() {
			return "", fmt.Errorf("mobile: unsupported SSH peer IP literal %q", host)
		}
		return u.String(), nil
	}

	targets := normalizeDNSAddrTargets(upstreamDNS)
	if protector != nil {
		for _, fb := range []string{defaultPeerResolveDNS1, defaultPeerResolveDNS2} {
			if !slices.Contains(targets, fb) {
				targets = append(targets, fb)
			}
		}
	}

	if len(targets) > 0 {
		ctrl := protectControl(protector)
		var lastErr error
		for _, target := range targets {
			if ctx.Err() != nil {
				break
			}
			resolved, err := lookupHostWithTarget(ctx, trimmed, target, ctrl)
			if err == nil {
				return resolved, nil
			}
			lastErr = err
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if lastErr != nil {
			return "", lastErr
		}
		return "", fmt.Errorf("mobile: resolve %q: no usable IP address returned", host)
	}

	resolveCtx, cancel := context.WithTimeout(ctx, defaultResolveTimeout)
	defer cancel()
	return lookupWithResolver(resolveCtx, net.DefaultResolver, trimmed)
}

func lookupHostWithTarget(ctx context.Context, host string, target string, ctrl func(string, string, syscall.RawConn) error) (string, error) {
	tCtx, cancel := context.WithTimeout(ctx, perTargetResolveTimeout)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{
				Timeout: perTargetResolveTimeout,
				Control: ctrl,
			}
			return d.DialContext(dialCtx, network, target)
		},
	}
	return lookupWithResolver(tCtx, resolver, host)
}

func lookupWithResolver(ctx context.Context, resolver *net.Resolver, host string) (string, error) {
	ips4, err4 := resolver.LookupNetIP(ctx, "ip4", host)
	if err4 == nil {
		for _, ip := range ips4 {
			u := ip.Unmap()
			if u.IsValid() && u.Is4() && !u.IsUnspecified() && !u.IsMulticast() {
				return u.String(), nil
			}
		}
	}

	var err6 error
	if ctx.Err() == nil {
		var ips6 []netip.Addr
		ips6, err6 = resolver.LookupNetIP(ctx, "ip6", host)
		if err6 == nil {
			for _, ip := range ips6 {
				if ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() {
					return ip.String(), nil
				}
			}
		}
	}

	if err4 != nil && err6 != nil {
		return "", fmt.Errorf("mobile: resolve %q: ipv4=%v; ipv6=%w", host, err4, err6)
	}
	if err4 != nil {
		return "", fmt.Errorf("mobile: resolve %q: %w", host, err4)
	}
	if err6 != nil {
		return "", fmt.Errorf("mobile: resolve %q: %w", host, err6)
	}
	return "", fmt.Errorf("mobile: resolve %q: no usable IP address returned", host)
}

func normalizeUpstreamDNSList(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}
		var hostPort string
		if h, p, err := net.SplitHostPort(s); err == nil {
			ip, parseErr := netip.ParseAddr(strings.TrimSpace(h))
			if parseErr != nil || !isUsableBypassDNSIP(ip) || strings.TrimSpace(p) == "" {
				continue
			}
			hostPort = net.JoinHostPort(ip.Unmap().String(), strings.TrimSpace(p))
		} else {
			ip, parseErr := netip.ParseAddr(s)
			if parseErr != nil || !isUsableBypassDNSIP(ip) {
				continue
			}
			hostPort = ip.Unmap().String()
		}
		if _, exists := seen[hostPort]; exists {
			continue
		}
		seen[hostPort] = struct{}{}
		out = append(out, hostPort)
	}
	return out
}

func normalizeDNSAddrTargets(normalized []string) []string {
	if len(normalized) == 0 {
		return nil
	}
	out := make([]string, 0, len(normalized))
	for _, entry := range normalized {
		if _, _, err := net.SplitHostPort(entry); err == nil {
			out = append(out, entry)
			continue
		}
		if ip, err := netip.ParseAddr(entry); err == nil && ip.IsValid() {
			out = append(out, net.JoinHostPort(ip.String(), "53"))
		}
	}
	return out
}

func normalizeBypassUpstreams(normalized []string) []string {
	targets := normalizeDNSAddrTargets(normalized)
	if len(targets) == 0 {
		return []string{defaultMobileBypassDNS}
	}
	return targets
}

func isUsableBypassDNSIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	u := ip.Unmap()
	return !u.IsUnspecified() && !u.IsLoopback() && !u.IsMulticast() && !u.IsLinkLocalUnicast()
}
