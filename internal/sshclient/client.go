package sshclient

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

const (
	defaultDialTimeout = 15 * time.Second
	defaultBackoffBase = 1 * time.Second
	defaultBackoffMax  = 30 * time.Second
)

// TunnelDialer is the sole outbound network contract consumed by proxy, tun2socks, and dns.
// Concurrency: safe for concurrent goroutines; zero locks held across DialContext or I/O.
type TunnelDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Engine owns the SSH connection lifecycle, watchdog, epoch transitions, and byte counters.
type Engine interface {
	TunnelDialer
	Connect(ctx context.Context, cfg ConnectConfig) error
	Disconnect(ctx context.Context) error
	MeasureRTT(ctx context.Context) (time.Duration, error)
	Snapshot() EngineSnapshot
	Subscribe(fn func(EngineSnapshot)) (unsubscribe func())
}

// ConnectionState describes the current SSH engine lifecycle state.
type ConnectionState string

const (
	StateDisconnected ConnectionState = "disconnected"
	StateConnecting   ConnectionState = "connecting"
	StateConnected    ConnectionState = "connected"
	StateReconnecting ConnectionState = "reconnecting"
	StateError        ConnectionState = "error"
)

// ConnectConfig defines SSH endpoint, credentials, TOFU pin, watchdog, and backoff settings.
type ConnectConfig struct {
	ProfileID     string
	Host          string
	Port          int
	Username      string
	Auth          AuthConfig
	PinnedHostKey *HostKeyPin
	DialTimeout   time.Duration
	Watchdog      WatchdogConfig
	BackoffBase   time.Duration
	BackoffMax    time.Duration
	// DialHost, when non-empty, overrides Host as the TCP dial target (e.g., pre-resolved VPS IP
	// in TUN mode) while preserving Host:Port for TOFU host-key pinning, snapshots, and errors.
	DialHost string
	// DialControl, when non-nil and dialTCP is nil, is passed to net.Dialer.Control so TUN mode
	// can bind the SSH transport socket to a physical egress interface before connecting.
	DialControl func(network, address string, c syscall.RawConn) error
}

// EngineSnapshot is an immutable point-in-time view of engine state and telemetry.
type EngineSnapshot struct {
	State           ConnectionState
	ProfileID       string
	Host            string
	Port            int
	Attempt         int
	RTTMs           int64
	RxBytes         uint64
	TxBytes         uint64
	ConnectedAt     time.Time
	LastError       *MappedError
	HostKeyPrompt   *ErrHostKeyUntrusted
	HostKeyMismatch *ErrHostKeyMismatch
}

type sshSession struct {
	epoch   uint64
	client  *ssh.Client
	rawConn net.Conn
	cfg     ConnectConfig
	cancel  context.CancelFunc
	closed  atomic.Bool
}

func (s *sshSession) close() {
	if s == nil {
		return
	}
	if s.closed.Swap(true) {
		return
	}
	// Close rawConn before canceling watchdog ctx so any wedged SendRequest unblocks immediately.
	if s.rawConn != nil {
		_ = s.rawConn.Close()
	}
	if s.client != nil {
		_ = s.client.Close()
	}
	if s.cancel != nil {
		s.cancel()
	}
}

type runControl struct {
	ctx    context.Context
	cancel context.CancelFunc
	cfg    ConnectConfig
	wg     sync.WaitGroup
}

type subscriberEntry struct {
	id uint64
	fn func(EngineSnapshot)
}

// Client implements Engine with lock-free active session lookup and epoch-guarded reconnect.
type Client struct {
	epoch   atomic.Uint64
	active  atomic.Pointer[sshSession]
	rxBytes atomic.Uint64
	txBytes atomic.Uint64
	rttMs   atomic.Int64

	stateMu     sync.Mutex
	snap        EngineSnapshot
	run         *runControl
	nextSubID   uint64
	subscribers []subscriberEntry

	// Package-private dial hook for deterministic unit tests; nil uses net.Dialer.
	dialTCP func(ctx context.Context, network, addr string) (net.Conn, error)
}

var _ Engine = (*Client)(nil)

// NewClient constructs a disconnected SSH tunnel Engine.
func NewClient() *Client {
	return &Client{
		snap: EngineSnapshot{
			State: StateDisconnected,
		},
	}
}

// Connect establishes an SSH tunnel session, tearing down any prior session cleanly first.
func (e *Client) Connect(ctx context.Context, cfg ConnectConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg = normalizeConnectConfig(cfg)

	myEpoch, prevRun, newRun := e.beginRun(cfg)
	if prev := e.active.Swap(nil); prev != nil {
		prev.close()
	}
	if prevRun != nil {
		prevRun.cancel()
		if err := waitForWG(ctx, &prevRun.wg); err != nil {
			newRun.cancel()
			newRun.wg.Done()
			return err
		}
	}

	e.rxBytes.Store(0)
	e.txBytes.Store(0)
	e.rttMs.Store(0)

	e.updateStateIfEpoch(myEpoch, func(s *EngineSnapshot) {
		*s = EngineSnapshot{
			State:     StateConnecting,
			ProfileID: cfg.ProfileID,
			Host:      cfg.Host,
			Port:      cfg.Port,
			Attempt:   1,
		}
	})

	if err := validateConnectConfig(cfg); err != nil {
		mapped := ClassifyError(err, cfg.Port, PhaseDial)
		e.failInitialDial(myEpoch, newRun, mapped, nil, nil)
		return mapped
	}

	if _, err := BuildAuthMethods(cfg.Auth); err != nil {
		mapped := ClassifyError(err, cfg.Port, PhaseAuth)
		e.failInitialDial(myEpoch, newRun, mapped, nil, nil)
		return mapped
	}

	dialCtx, dialCancel := context.WithCancel(newRun.ctx)
	stopCallerWatch := context.AfterFunc(ctx, dialCancel)
	attemptCtx, attemptCancel := context.WithTimeout(dialCtx, cfg.DialTimeout)

	sess, probe, phase, err := e.dialOnce(attemptCtx, cfg, myEpoch)
	attemptCancel()
	stopCallerWatch()
	dialCancel()

	if err != nil {
		if e.epoch.Load() != myEpoch || newRun.ctx.Err() != nil {
			newRun.cancel()
			newRun.wg.Done()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return context.Canceled
		}
		if errors.Is(err, context.Canceled) && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = ctx.Err()
		}
		mapped, prompt, mismatch := classifyDialFailure(err, cfg.Port, phase, probe)
		e.failInitialDial(myEpoch, newRun, mapped, prompt, mismatch)
		return mapped
	}

	// Publish active session and verify epoch atomically to avoid store/Disconnect races.
	e.active.Store(sess)
	if e.epoch.Load() != myEpoch || newRun.ctx.Err() != nil {
		e.active.CompareAndSwap(sess, nil)
		sess.close()
		newRun.cancel()
		newRun.wg.Done()
		return context.Canceled
	}

	e.startSessionMonitors(newRun, sess)
	newRun.wg.Done()

	e.updateStateIfEpoch(myEpoch, func(s *EngineSnapshot) {
		s.State = StateConnected
		s.ProfileID = cfg.ProfileID
		s.Host = cfg.Host
		s.Port = cfg.Port
		s.Attempt = 0
		s.ConnectedAt = time.Now()
		s.LastError = nil
		s.HostKeyPrompt = nil
		s.HostKeyMismatch = nil
	})
	return nil
}

// Disconnect terminates any active or reconnecting session and resets state to StateDisconnected.
func (e *Client) Disconnect(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	disconnEpoch := e.epoch.Add(1)
	if prev := e.active.Swap(nil); prev != nil {
		prev.close()
	}

	e.stateMu.Lock()
	prevRun := e.run
	e.run = nil
	e.stateMu.Unlock()

	if prevRun != nil {
		prevRun.cancel()
		if err := waitForWG(ctx, &prevRun.wg); err != nil {
			return err
		}
	}

	e.rttMs.Store(0)
	e.updateStateIfEpoch(disconnEpoch, func(s *EngineSnapshot) {
		s.State = StateDisconnected
		s.Attempt = 0
		s.ConnectedAt = time.Time{}
		s.LastError = nil
		s.HostKeyPrompt = nil
		s.HostKeyMismatch = nil
	})
	return nil
}

// DialContext opens a direct-tcpip channel over the active SSH session and wraps it with byte counters.
func (e *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("sshclient: nil context")
	}
	sess := e.active.Load()
	if sess == nil {
		return nil, ErrNotConnected
	}

	conn, err := sess.client.DialContext(ctx, network, address)
	if err != nil {
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) && openErr.Reason == ssh.Prohibited {
			return nil, ClassifyError(err, sess.cfg.Port, PhaseChannel)
		}
		return nil, err
	}

	return &countingConn{
		Conn: conn,
		rx:   &e.rxBytes,
		tx:   &e.txBytes,
	}, nil
}

// MeasureRTT sends a single keepalive@openssh.com global request and records measured round-trip latency.
func (e *Client) MeasureRTT(ctx context.Context) (time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sess := e.active.Load()
	if sess == nil {
		return 0, ErrNotConnected
	}

	type rttResult struct {
		rtt time.Duration
		err error
	}
	ch := make(chan rttResult, 1)
	go func() {
		start := time.Now()
		_, _, err := sess.client.SendRequest("keepalive@openssh.com", true, nil)
		ch <- rttResult{rtt: time.Since(start), err: err}
	}()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return 0, res.err
		}
		if e.epoch.Load() == sess.epoch {
			e.rttMs.Store(res.rtt.Milliseconds())
		}
		return res.rtt, nil
	}
}

// Snapshot returns a consistent snapshot of connection state and atomic telemetry counters.
func (e *Client) Snapshot() EngineSnapshot {
	e.stateMu.Lock()
	snap := e.snap
	e.stateMu.Unlock()

	snap.RxBytes = e.rxBytes.Load()
	snap.TxBytes = e.txBytes.Load()
	snap.RTTMs = e.rttMs.Load()
	return snap
}

// Subscribe registers a callback invoked on connection state changes without holding locks.
func (e *Client) Subscribe(fn func(EngineSnapshot)) (unsubscribe func()) {
	if fn == nil {
		return func() {}
	}

	e.stateMu.Lock()
	e.nextSubID++
	id := e.nextSubID
	e.subscribers = append(e.subscribers, subscriberEntry{id: id, fn: fn})
	e.stateMu.Unlock()

	var once atomic.Bool
	return func() {
		if once.Swap(true) {
			return
		}
		e.stateMu.Lock()
		for i, entry := range e.subscribers {
			if entry.id == id {
				e.subscribers = slices.Delete(e.subscribers, i, i+1)
				break
			}
		}
		e.stateMu.Unlock()
	}
}

func (e *Client) beginRun(cfg ConnectConfig) (uint64, *runControl, *runControl) {
	runCtx, runCancel := context.WithCancel(context.Background())
	newRun := &runControl{
		ctx:    runCtx,
		cancel: runCancel,
		cfg:    cfg,
	}
	newRun.wg.Add(1)

	e.stateMu.Lock()
	myEpoch := e.epoch.Add(1)
	prevRun := e.run
	e.run = newRun
	e.snap.ProfileID = cfg.ProfileID
	e.snap.Host = cfg.Host
	e.snap.Port = cfg.Port
	e.stateMu.Unlock()

	return myEpoch, prevRun, newRun
}

func (e *Client) failInitialDial(
	myEpoch uint64,
	run *runControl,
	mapped *MappedError,
	prompt *ErrHostKeyUntrusted,
	mismatch *ErrHostKeyMismatch,
) {
	e.updateStateIfEpoch(myEpoch, func(s *EngineSnapshot) {
		s.State = StateError
		s.Attempt = 0
		s.ConnectedAt = time.Time{}
		s.LastError = mapped
		s.HostKeyPrompt = prompt
		s.HostKeyMismatch = mismatch
	})
	run.cancel()
	run.wg.Done()
}

func (e *Client) updateStateIfEpoch(targetEpoch uint64, mutate func(*EngineSnapshot)) {
	e.stateMu.Lock()
	if e.epoch.Load() != targetEpoch {
		e.stateMu.Unlock()
		return
	}
	mutate(&e.snap)
	snap := e.snap
	subs := slices.Clone(e.subscribers)
	e.stateMu.Unlock()

	snap.RxBytes = e.rxBytes.Load()
	snap.TxBytes = e.txBytes.Load()
	snap.RTTMs = e.rttMs.Load()

	for _, sub := range subs {
		sub.fn(snap)
	}
}

func (e *Client) dialOnce(
	dialCtx context.Context,
	cfg ConnectConfig,
	myEpoch uint64,
) (*sshSession, *HostKeyProbeResult, DialPhase, error) {
	authMethods, err := BuildAuthMethods(cfg.Auth)
	if err != nil {
		return nil, nil, PhaseAuth, err
	}

	var phaseVal atomic.Value
	phaseVal.Store(PhaseDial)

	dialFn := e.dialTCP
	if dialFn == nil {
		dialer := &net.Dialer{
			Control: cfg.DialControl,
		}
		dialFn = dialer.DialContext
	}

	dialHost := cfg.Host
	if cfg.DialHost != "" {
		dialHost = cfg.DialHost
	}
	dialAddr := net.JoinHostPort(dialHost, strconv.Itoa(cfg.Port))
	rawConn, err := dialFn(dialCtx, "tcp", dialAddr)
	if err != nil {
		return nil, nil, PhaseDial, err
	}

	phaseVal.Store(PhaseHandshake)
	tofuCB, probe := NewTOFUHostKeyCallback(cfg.Host, cfg.Port, cfg.PinnedHostKey)

	sshCfg := &ssh.ClientConfig{
		User: cfg.Username,
		Auth: authMethods,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			phaseVal.Store(PhaseHostKey)
			cbErr := tofuCB(hostname, remote, key)
			if cbErr == nil {
				phaseVal.Store(PhaseHandshake)
			}
			return cbErr
		},
		BannerCallback: func(_ string) error {
			phaseVal.Store(PhaseAuth)
			return nil
		},
		AuthCallback: func(_ *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			phaseVal.Store(PhaseAuth)
			return nil, nil
		},
	}

	stopClose := context.AfterFunc(dialCtx, func() {
		_ = rawConn.Close()
	})
	logicalAddr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, logicalAddr, sshCfg)
	stoppedCleanly := stopClose()

	curPhase, _ := phaseVal.Load().(DialPhase)
	if err != nil {
		_ = rawConn.Close()
		if !stoppedCleanly && dialCtx.Err() != nil {
			return nil, probe, curPhase, dialCtx.Err()
		}
		return nil, probe, curPhase, err
	}
	if !stoppedCleanly || dialCtx.Err() != nil {
		_ = sshConn.Close()
		_ = rawConn.Close()
		return nil, probe, curPhase, dialCtx.Err()
	}

	sshClient := ssh.NewClient(sshConn, chans, reqs)
	return &sshSession{
		epoch:   myEpoch,
		client:  sshClient,
		rawConn: rawConn,
		cfg:     cfg,
	}, probe, PhaseRuntime, nil
}

func (e *Client) startSessionMonitors(run *runControl, sess *sshSession) {
	sessCtx, sessCancel := context.WithCancel(run.ctx)
	prevCancel := sess.cancel
	sess.cancel = func() {
		sessCancel()
		if prevCancel != nil {
			prevCancel()
		}
	}

	wdWait := StartWatchdog(
		sessCtx,
		sess.client,
		sess.rawConn,
		sess.cfg.Watchdog,
		func(rtt time.Duration) {
			if e.epoch.Load() == sess.epoch {
				e.rttMs.Store(rtt.Milliseconds())
			}
		},
		func(err error) {
			e.handleSessionExit(sess.epoch, err)
		},
	)

	run.wg.Add(1)
	go func() {
		defer run.wg.Done()
		err := sess.client.Wait()
		if err == nil {
			err = errors.New("sshclient: session closed")
		}
		e.handleSessionExit(sess.epoch, err)
		wdWait()
	}()
}

// handleSessionExit atomically validates myEpoch, tears down the dying session,
// and transitions into the bounded exponential reconnect loop if run is active.
func (e *Client) handleSessionExit(myEpoch uint64, exitErr error) {
	if !e.epoch.CompareAndSwap(myEpoch, myEpoch+1) {
		return
	}
	nextEpoch := myEpoch + 1

	e.stateMu.Lock()
	run := e.run
	e.stateMu.Unlock()
	if run == nil || run.ctx.Err() != nil {
		return
	}

	cfg := run.cfg
	if sess := e.active.Load(); sess != nil && sess.epoch == myEpoch {
		cfg = sess.cfg
		if e.active.CompareAndSwap(sess, nil) {
			sess.close()
		}
	}

	e.rttMs.Store(0)
	run.wg.Add(1)
	go e.reconnectLoop(run, cfg, nextEpoch, exitErr)
}

func (e *Client) reconnectLoop(run *runControl, cfg ConnectConfig, myEpoch uint64, initialErr error) {
	defer run.wg.Done()

	lastMapped := ClassifyError(initialErr, cfg.Port, PhaseRuntime)
	if lastMapped != nil && !lastMapped.Retryable {
		e.updateStateIfEpoch(myEpoch, func(s *EngineSnapshot) {
			s.State = StateError
			s.Attempt = 0
			s.ConnectedAt = time.Time{}
			s.LastError = lastMapped
		})
		return
	}

	rng := newJitterRand()
	attempt := 1

	for {
		if run.ctx.Err() != nil || e.epoch.Load() != myEpoch {
			return
		}

		e.updateStateIfEpoch(myEpoch, func(s *EngineSnapshot) {
			s.State = StateReconnecting
			s.Attempt = attempt
			s.ConnectedAt = time.Time{}
			s.LastError = lastMapped
			s.HostKeyPrompt = nil
			s.HostKeyMismatch = nil
		})

		delay := jitteredBackoff(cfg.BackoffBase, cfg.BackoffMax, attempt, rng)
		timer := time.NewTimer(delay)
		select {
		case <-run.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if run.ctx.Err() != nil || e.epoch.Load() != myEpoch {
			return
		}

		attemptCtx, attemptCancel := context.WithTimeout(run.ctx, cfg.DialTimeout)
		sess, probe, phase, dialErr := e.dialOnce(attemptCtx, cfg, myEpoch)
		attemptCancel()

		if dialErr == nil {
			e.active.Store(sess)
			if e.epoch.Load() != myEpoch || run.ctx.Err() != nil {
				e.active.CompareAndSwap(sess, nil)
				sess.close()
				return
			}
			e.startSessionMonitors(run, sess)
			e.updateStateIfEpoch(myEpoch, func(s *EngineSnapshot) {
				s.State = StateConnected
				s.Attempt = 0
				s.ConnectedAt = time.Now()
				s.LastError = nil
				s.HostKeyPrompt = nil
				s.HostKeyMismatch = nil
			})
			return
		}

		if run.ctx.Err() != nil || e.epoch.Load() != myEpoch {
			return
		}

		mapped, prompt, mismatch := classifyDialFailure(dialErr, cfg.Port, phase, probe)
		if !mapped.Retryable {
			e.updateStateIfEpoch(myEpoch, func(s *EngineSnapshot) {
				s.State = StateError
				s.Attempt = 0
				s.ConnectedAt = time.Time{}
				s.LastError = mapped
				s.HostKeyPrompt = prompt
				s.HostKeyMismatch = mismatch
			})
			return
		}

		lastMapped = mapped
		attempt++
		if !e.epoch.CompareAndSwap(myEpoch, myEpoch+1) {
			return
		}
		myEpoch++
	}
}

func classifyDialFailure(
	err error,
	port int,
	phase DialPhase,
	probe *HostKeyProbeResult,
) (*MappedError, *ErrHostKeyUntrusted, *ErrHostKeyMismatch) {
	if probe != nil {
		if probe.Mismatch != nil {
			return ClassifyError(probe.Mismatch, port, PhaseHostKey), nil, probe.Mismatch
		}
		if probe.Untrusted != nil {
			return ClassifyError(probe.Untrusted, port, PhaseHostKey), probe.Untrusted, nil
		}
	}
	mapped := ClassifyError(err, port, phase)
	var untrusted *ErrHostKeyUntrusted
	if errors.As(err, &untrusted) {
		return mapped, untrusted, nil
	}
	var mismatch *ErrHostKeyMismatch
	if errors.As(err, &mismatch) {
		return mapped, nil, mismatch
	}
	return mapped, nil, nil
}

func normalizeConnectConfig(cfg ConnectConfig) ConnectConfig {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	cfg.Watchdog = cfg.Watchdog.withDefaults()
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = defaultBackoffBase
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = defaultBackoffMax
	}
	if cfg.BackoffMax < cfg.BackoffBase {
		cfg.BackoffMax = cfg.BackoffBase
	}
	return cfg
}

func validateConnectConfig(cfg ConnectConfig) error {
	if strings.TrimSpace(cfg.Host) == "" {
		return errors.New("sshclient: host must not be empty")
	}
	if cfg.DialHost != "" {
		if strings.IndexFunc(cfg.DialHost, unicode.IsSpace) >= 0 {
			return errors.New("sshclient: dial host must not contain whitespace")
		}
		if _, err := netip.ParseAddr(cfg.DialHost); err != nil {
			if _, portStr, splitErr := net.SplitHostPort(cfg.DialHost); splitErr == nil {
				if portStr == "" {
					return errors.New("sshclient: dial host must not include an empty port")
				}
				return errors.New("sshclient: dial host must not include a port")
			}
			if strings.ContainsAny(cfg.DialHost, "[]") {
				return errors.New("sshclient: dial host must not contain brackets")
			}
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("sshclient: invalid port %d", cfg.Port)
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return errors.New("sshclient: username must not be empty")
	}
	return nil
}

func newJitterRand() *mathrand.Rand {
	var seed [32]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		binary.LittleEndian.PutUint64(seed[:8], uint64(time.Now().UnixNano()))
	}
	return mathrand.New(mathrand.NewChaCha8(seed))
}

func jitteredBackoff(base, maxDelay time.Duration, attempt int, rng *mathrand.Rand) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := base
	for i := 1; i < attempt; i++ {
		if delay >= maxDelay {
			delay = maxDelay
			break
		}
		if delay > maxDelay/2 {
			delay = maxDelay
			break
		}
		delay *= 2
	}
	if delay > maxDelay {
		delay = maxDelay
	}
	// Apply +-20% jitter: multiplier in [0.8, 1.2).
	factor := 0.8 + rng.Float64()*0.4
	jittered := time.Duration(float64(delay) * factor)
	if jittered < time.Millisecond {
		return time.Millisecond
	}
	return jittered
}

func waitForWG(ctx context.Context, wg *sync.WaitGroup) error {
	if wg == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type countingConn struct {
	net.Conn
	rx *atomic.Uint64
	tx *atomic.Uint64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rx.Add(uint64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.tx.Add(uint64(n))
	}
	return n, err
}

// CloseWrite forwards TCP half-close notifications to underlying SSH channels when supported.
func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// CloseRead forwards TCP read-side shutdowns to underlying SSH channels when supported.
func (c *countingConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}
