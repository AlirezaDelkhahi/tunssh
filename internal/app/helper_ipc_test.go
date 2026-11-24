package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/AlirezaDelkhahi/tunssh/internal/dns"
	"github.com/AlirezaDelkhahi/tunssh/internal/recovery"
	"github.com/AlirezaDelkhahi/tunssh/internal/splitroute"
	"github.com/AlirezaDelkhahi/tunssh/internal/tun"
)

type mockRouteManager struct {
	mu sync.Mutex

	captureSnap splitroute.NetworkSnapshot
	captureErr  error

	applyErr   error
	bypassErr  error
	restoreErr error

	isActive    bool
	isActiveErr error

	appliedPlans   []splitroute.RoutePlan
	appliedSnaps   []splitroute.NetworkSnapshot
	bypassCalls    []bool
	restoredSnaps  []splitroute.NetworkSnapshot
	isActiveCalls  int
	eventLog       *[]string
	eventLogMu     *sync.Mutex
	onApply        func()
	onRestore      func()
	captureCalls   int
	applyCalls     int
	restoreCalls   int
	setBypassCalls int
}

func (m *mockRouteManager) record(ev string) {
	if m.eventLog == nil || m.eventLogMu == nil {
		return
	}
	m.eventLogMu.Lock()
	*m.eventLog = append(*m.eventLog, ev)
	m.eventLogMu.Unlock()
}

func (m *mockRouteManager) CaptureNetworkSnapshot(ctx context.Context) (splitroute.NetworkSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return splitroute.NetworkSnapshot{}, err
	}
	m.mu.Lock()
	m.captureCalls++
	snap := m.captureSnap
	err := m.captureErr
	m.mu.Unlock()
	m.record("route.capture")
	return snap, err
}

func (m *mockRouteManager) ApplySplitTunnel(ctx context.Context, plan splitroute.RoutePlan) error {
	return m.ApplySplitTunnelWithSnapshot(ctx, plan, splitroute.NetworkSnapshot{})
}

func (m *mockRouteManager) ApplySplitTunnelWithSnapshot(ctx context.Context, plan splitroute.RoutePlan, snap splitroute.NetworkSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	m.applyCalls++
	m.appliedPlans = append(m.appliedPlans, plan)
	m.appliedSnaps = append(m.appliedSnaps, snap)
	err := m.applyErr
	cb := m.onApply
	m.mu.Unlock()
	m.record("route.apply")
	if cb != nil {
		cb()
	}
	return err
}

func (m *mockRouteManager) SetBypassIranLAN(ctx context.Context, snap splitroute.NetworkSnapshot, enable bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	m.setBypassCalls++
	m.bypassCalls = append(m.bypassCalls, enable)
	err := m.bypassErr
	m.mu.Unlock()
	m.record(fmt.Sprintf("route.set_bypass:%v", enable))
	return err
}

func (m *mockRouteManager) RestoreNetwork(ctx context.Context, snap splitroute.NetworkSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	m.restoreCalls++
	m.restoredSnaps = append(m.restoredSnaps, snap)
	err := m.restoreErr
	cb := m.onRestore
	m.mu.Unlock()
	m.record("route.restore")
	if cb != nil {
		cb()
	}
	return err
}

func (m *mockRouteManager) IsTUNStateActive(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	m.isActiveCalls++
	active := m.isActive
	err := m.isActiveErr
	m.mu.Unlock()
	m.record("route.is_active")
	return active, err
}

type mockTunRunner struct {
	mu sync.Mutex

	startIfIndex int
	startErr     error
	stopErr      error
	stats        tun.Stats
	startedCfgs  []tun.Config
	startCalls   int
	stopCalls    int
	running      bool
	eventLog     *[]string
	eventLogMu   *sync.Mutex
}

func (r *mockTunRunner) record(ev string) {
	if r.eventLog == nil || r.eventLogMu == nil {
		return
	}
	r.eventLogMu.Lock()
	*r.eventLog = append(*r.eventLog, ev)
	r.eventLogMu.Unlock()
}

func (r *mockTunRunner) Start(ctx context.Context, cfg tun.Config) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.mu.Lock()
	r.startCalls++
	r.startedCfgs = append(r.startedCfgs, cfg)
	err := r.startErr
	ifIdx := r.startIfIndex
	if ifIdx == 0 {
		ifIdx = 42
	}
	if err == nil {
		r.running = true
		r.stats.Running = true
		r.stats.IfaceName = cfg.IfaceName
		r.stats.IfaceIndex = ifIdx
	}
	r.mu.Unlock()
	r.record("tun.start")
	return ifIdx, err
}

func (r *mockTunRunner) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	r.stopCalls++
	r.running = false
	r.stats.Running = false
	err := r.stopErr
	r.mu.Unlock()
	r.record("tun.stop")
	return err
}

func (r *mockTunRunner) Stats() tun.Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *mockTunRunner) LastConfig() (tun.Config, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.startedCfgs) == 0 {
		return tun.Config{}, false
	}
	return r.startedCfgs[len(r.startedCfgs)-1], true
}

type localEchoTunnelDialer struct {
	mu       sync.Mutex
	calls    int
	override func(ctx context.Context, network, address string) (net.Conn, error)
}

func (d *localEchoTunnelDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	ov := d.override
	d.mu.Unlock()
	if ov != nil {
		return ov(ctx, network, address)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, address)
}

type funcHelperLauncher struct {
	mu       sync.Mutex
	calls    int
	launchFn func(ctx context.Context) (io.ReadWriteCloser, func(), error)
	cleanups atomic.Int32
}

func (l *funcHelperLauncher) Launch(ctx context.Context) (io.ReadWriteCloser, func(), error) {
	l.mu.Lock()
	l.calls++
	fn := l.launchFn
	l.mu.Unlock()
	conn, cleanup, err := fn(ctx)
	if err != nil {
		return nil, nil, err
	}
	return conn, func() {
		l.cleanups.Add(1)
		if cleanup != nil {
			cleanup()
		}
	}, nil
}

func (l *funcHelperLauncher) Calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func startLocalTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		wg.Wait()
	}
}

func startLocalTCPDNSServer(t *testing.T, answerIP string) (string, *atomic.Int32, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp dns: %v", err)
	}
	var queries atomic.Int32
	srv := &mdns.Server{
		Listener: ln,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
			queries.Add(1)
			resp := new(mdns.Msg)
			resp.SetReply(r)
			if len(r.Question) > 0 {
				rr, rrErr := mdns.NewRR(fmt.Sprintf("%s 60 IN A %s", r.Question[0].Name, answerIP))
				if rrErr == nil {
					resp.Answer = append(resp.Answer, rr)
				}
			}
			_ = w.WriteMsg(resp)
		}),
	}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	return ln.Addr().String(), &queries, func() {
		_ = srv.Shutdown()
	}
}

func startLocalUDPDNSServer(t *testing.T, answerIP string) (string, *atomic.Int32, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp dns: %v", err)
	}
	var queries atomic.Int32
	srv := &mdns.Server{
		PacketConn: pc,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
			queries.Add(1)
			resp := new(mdns.Msg)
			resp.SetReply(r)
			if len(r.Question) > 0 {
				rr, rrErr := mdns.NewRR(fmt.Sprintf("%s 60 IN A %s", r.Question[0].Name, answerIP))
				if rrErr == nil {
					resp.Answer = append(resp.Answer, rr)
				}
			}
			_ = w.WriteMsg(resp)
		}),
	}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()
	<-ready
	return pc.LocalAddr().String(), &queries, func() {
		_ = srv.Shutdown()
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSnapshotConvertersRoundTrip(t *testing.T) {
	orig := splitroute.NetworkSnapshot{
		VPSPeerIP:      "203.0.113.10",
		OrigGateway:    "192.168.1.1",
		OrigGateway6:   "fe80::1",
		OrigIfaceName:  "eth0",
		OrigIfaceIndex: 3,
		OrigDNSServers: []string{"1.1.1.1", "9.9.9.9"},
		WinAdapterDNSBackups: []splitroute.WinAdapterDNSBackup{
			{
				IfaceIndex: 11,
				IfaceName:  "Ethernet",
				IPv4DNS:    []string{"192.168.1.1"},
				IPv6DNS:    []string{"fd00::1"},
			},
		},
		LinuxDNSBackups: []splitroute.LinuxDNSBackup{
			{
				IfIndex:      3,
				IfName:       "eth0",
				DNSServers:   []string{"192.168.1.1"},
				DefaultRoute: true,
			},
		},
		DNSStrategy:      "systemd-resolved",
		ResolvConfBackup: "nameserver 192.168.1.1\n",
		TUNIfaceName:     "tunssh0",
		InstalledRoutes:  []string{"203.0.113.10/32", "0.0.0.0/1", "128.0.0.0/1"},
	}

	rec := NetworkSnapshotToRecovery(orig)
	round := RecoverySnapshotToNetwork(rec)

	if round.VPSPeerIP != orig.VPSPeerIP ||
		round.OrigGateway != orig.OrigGateway ||
		round.OrigGateway6 != orig.OrigGateway6 ||
		round.OrigIfaceName != orig.OrigIfaceName ||
		round.OrigIfaceIndex != orig.OrigIfaceIndex ||
		round.DNSStrategy != orig.DNSStrategy ||
		round.ResolvConfBackup != orig.ResolvConfBackup ||
		round.TUNIfaceName != orig.TUNIfaceName {
		t.Fatalf("scalar fields mismatch: got %+v want %+v", round, orig)
	}
	if !slices.Equal(round.OrigDNSServers, orig.OrigDNSServers) {
		t.Fatalf("OrigDNSServers mismatch: got %v want %v", round.OrigDNSServers, orig.OrigDNSServers)
	}
	if !slices.Equal(round.InstalledRoutes, orig.InstalledRoutes) {
		t.Fatalf("InstalledRoutes mismatch: got %v want %v", round.InstalledRoutes, orig.InstalledRoutes)
	}
	if len(round.WinAdapterDNSBackups) != 1 || !slices.Equal(round.WinAdapterDNSBackups[0].IPv4DNS, orig.WinAdapterDNSBackups[0].IPv4DNS) {
		t.Fatalf("WinAdapterDNSBackups mismatch: %+v", round.WinAdapterDNSBackups)
	}
	if len(round.LinuxDNSBackups) != 1 || !slices.Equal(round.LinuxDNSBackups[0].DNSServers, orig.LinuxDNSBackups[0].DNSServers) || !round.LinuxDNSBackups[0].DefaultRoute {
		t.Fatalf("LinuxDNSBackups mismatch: %+v", round.LinuxDNSBackups)
	}

	// Mutating converted slices must not mutate original.
	rec.OrigDNSServers[0] = "8.8.4.4"
	rec.WinAdapterDNSBackups[0].IPv4DNS[0] = "10.0.0.1"
	rec.LinuxDNSBackups[0].DNSServers[0] = "10.0.0.2"
	rec.InstalledRoutes[0] = "0.0.0.0/0"
	if orig.OrigDNSServers[0] != "1.1.1.1" ||
		orig.WinAdapterDNSBackups[0].IPv4DNS[0] != "192.168.1.1" ||
		orig.LinuxDNSBackups[0].DNSServers[0] != "192.168.1.1" ||
		orig.InstalledRoutes[0] != "203.0.113.10/32" {
		t.Fatalf("snapshot conversion shared underlying slice memory")
	}

	// Verify recovery.TUNSnapshot type matches expectation.
	var _ recovery.TUNSnapshot = rec
}

func TestDirectTUNControllerRollbackOrderAndStopIdempotency(t *testing.T) {
	var evMu sync.Mutex
	var events []string

	routeMgr := &mockRouteManager{
		applyErr:   errors.New("simulated route apply failure"),
		eventLog:   &events,
		eventLogMu: &evMu,
	}
	tunRunner := &mockTunRunner{
		startIfIndex: 77,
		eventLog:     &events,
		eventLogMu:   &evMu,
	}
	var createdDNS *dns.Server
	ctrl := NewDirectTUNController(
		TUNCapsDTO{Supported: true},
		routeMgr,
		func() *dns.Server {
			createdDNS = dns.NewServer()
			return createdDNS
		},
		func() tun.TunRunner { return tunRunner },
		discardLogger(),
	)

	req := TUNStartRequest{
		Snapshot: splitroute.NetworkSnapshot{
			VPSPeerIP:      "203.0.113.55",
			OrigGateway:    "192.168.1.1",
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 2,
		},
		BypassIranLAN: true,
		EnableIPv6:    true,
	}
	dialer := &localEchoTunnelDialer{}
	err := ctrl.StartTUN(context.Background(), req, dialer)
	if err == nil || !strings.Contains(err.Error(), "simulated route apply failure") {
		t.Fatalf("expected apply error, got %v", err)
	}

	// Verify rollback ran route.restore BEFORE tun.stop, and DNS server was stopped.
	evMu.Lock()
	gotEvents := slices.Clone(events)
	evMu.Unlock()
	wantEvents := []string{"tun.start", "route.apply", "route.restore", "tun.stop"}
	if !slices.Equal(gotEvents, wantEvents) {
		t.Fatalf("rollback order mismatch: got %v want %v", gotEvents, wantEvents)
	}
	if createdDNS == nil {
		t.Fatalf("expected DNS server to be created")
	}
	if _, exErr := createdDNS.Exchange(context.Background(), new(mdns.Msg)); exErr == nil {
		t.Fatalf("expected DNS server to be stopped after rollback")
	}

	// Clear error and verify StartTUN -> Stop -> idempotent Stop.
	routeMgr.mu.Lock()
	routeMgr.applyErr = nil
	routeMgr.mu.Unlock()
	evMu.Lock()
	events = nil
	evMu.Unlock()

	if err := ctrl.StartTUN(context.Background(), req, dialer); err != nil {
		t.Fatalf("StartTUN retry failed: %v", err)
	}
	if !ctrl.Stats().Running {
		t.Fatalf("expected Stats().Running == true after StartTUN")
	}
	if err := ctrl.Stop(context.Background()); err != nil {
		t.Fatalf("first Stop failed: %v", err)
	}
	if err := ctrl.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop (idempotent) failed: %v", err)
	}
	if ctrl.Stats().Running {
		t.Fatalf("expected Stats().Running == false after Stop")
	}

	evMu.Lock()
	stopEvents := slices.Clone(events)
	evMu.Unlock()
	wantStopEvents := []string{"tun.start", "route.apply", "route.restore", "tun.stop"}
	if !slices.Equal(stopEvents, wantStopEvents) {
		t.Fatalf("stop order mismatch: got %v want %v", stopEvents, wantStopEvents)
	}
}

func TestHelperIPCHappyPathAndMultiplexedStreams(t *testing.T) {
	echoAddr, stopEcho := startLocalTCPEchoServer(t)
	defer stopEcho()

	bypassDNSAddr, bypassQueries, stopBypassDNS := startLocalUDPDNSServer(t, "10.20.30.40")
	defer stopBypassDNS()

	tunnelDNSAddr, tunnelQueries, stopTunnelDNS := startLocalTCPDNSServer(t, "93.184.216.34")
	defer stopTunnelDNS()

	var evMu sync.Mutex
	var events []string
	routeMgr := &mockRouteManager{
		captureSnap: splitroute.NetworkSnapshot{
			OrigGateway:    "192.168.1.1",
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 2,
			OrigDNSServers: []string{bypassDNSAddr},
			TUNIfaceName:   splitroute.TUNIfaceName,
		},
		eventLog:   &events,
		eventLogMu: &evMu,
	}
	tunRunner := &mockTunRunner{
		startIfIndex: 88,
		stats: tun.Stats{
			RxBytes: 1234,
			TxBytes: 5678,
		},
		eventLog:   &events,
		eventLogMu: &evMu,
	}

	helperCtrl := NewDirectTUNController(
		TUNCapsDTO{Supported: true, IfaceName: splitroute.TUNIfaceName, TUNIPv4: splitroute.TUNIPv4Addr, TUNDNS: splitroute.TUNDNSServer},
		routeMgr,
		dns.NewServer,
		func() tun.TunRunner { return tunRunner },
		discardLogger(),
	)

	var helperDone chan error
	launcher := &funcHelperLauncher{
		launchFn: func(ctx context.Context) (io.ReadWriteCloser, func(), error) {
			guiConn, helperConn := net.Pipe()
			helperDone = make(chan error, 1)
			go func() {
				helperDone <- RunHelperOnConn(context.Background(), helperConn, helperCtrl, discardLogger())
			}()
			return guiConn, func() {
				_ = guiConn.Close()
			}, nil
		},
	}

	localMgr := &mockRouteManager{isActive: false}
	guiCtrl := newHelperTUNController(
		TUNCapsDTO{Supported: true, RequiresElevation: true, IfaceName: splitroute.TUNIfaceName, TUNIPv4: splitroute.TUNIPv4Addr, TUNDNS: splitroute.TUNDNSServer},
		launcher,
		localMgr,
		discardLogger(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. PrepareSession captures NetworkSnapshot via helper.
	snap, err := guiCtrl.PrepareSession(ctx)
	if err != nil {
		t.Fatalf("PrepareSession failed: %v", err)
	}
	if snap.OrigGateway != "192.168.1.1" || snap.OrigIfaceName != "eth0" || snap.OrigIfaceIndex != 2 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	snap.VPSPeerIP = "203.0.113.10"

	// GUI dialer routes 1.1.1.1:53 / 8.8.8.8:53 to our local TCP DNS server, and everything else to dialTarget.
	guiDialer := &localEchoTunnelDialer{
		override: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "1.1.1.1:53" || address == "8.8.8.8:53" {
				var nd net.Dialer
				return nd.DialContext(ctx, "tcp", tunnelDNSAddr)
			}
			var nd net.Dialer
			return nd.DialContext(ctx, network, address)
		},
	}

	// 2. StartTUN starts DNS server + TunRunner + ApplySplitTunnelWithSnapshot on helper.
	req := TUNStartRequest{
		Snapshot:      snap,
		BypassIranLAN: true,
		EnableIPv6:    false,
	}
	if err := guiCtrl.StartTUN(ctx, req, guiDialer); err != nil {
		t.Fatalf("StartTUN failed: %v", err)
	}
	if launcher.Calls() != 1 {
		t.Fatalf("expected launcher reuse (1 launch), got %d", launcher.Calls())
	}

	tunCfg, ok := tunRunner.LastConfig()
	if !ok {
		t.Fatalf("expected mockTunRunner.Start to be called")
	}
	if tunCfg.DNSUDPAddr == "" || tunCfg.DNSTCPAddr == "" {
		t.Fatalf("expected DNS addresses passed to TunRunner, got UDP=%q TCP=%q", tunCfg.DNSUDPAddr, tunCfg.DNSTCPAddr)
	}

	// Verify embedded DNS works over the yamux bridge (tunnel domain) and bypass dialer (.ir domain).
	dnsClient := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}
	qTunnel := new(mdns.Msg)
	qTunnel.SetQuestion("example.com.", mdns.TypeA)
	rTunnel, _, err := dnsClient.Exchange(qTunnel, tunCfg.DNSUDPAddr)
	if err != nil || len(rTunnel.Answer) == 0 {
		t.Fatalf("embedded tunnel DNS query failed: err=%v resp=%v", err, rTunnel)
	}
	if tunnelQueries.Load() == 0 {
		t.Fatalf("expected tunnel DNS upstream query via yamux bridge")
	}

	qBypass := new(mdns.Msg)
	qBypass.SetQuestion("nic.ir.", mdns.TypeA)
	rBypass, _, err := dnsClient.Exchange(qBypass, tunCfg.DNSUDPAddr)
	if err != nil || len(rBypass.Answer) == 0 {
		t.Fatalf("embedded bypass DNS query failed: err=%v resp=%v", err, rBypass)
	}
	if bypassQueries.Load() == 0 {
		t.Fatalf("expected bypass DNS query for .ir domain")
	}

	// 3. 5 concurrent multiplexed TCP dial streams through yamux to local echo server.
	const streamCount = 5
	var streamWG sync.WaitGroup
	streamErrs := make(chan error, streamCount)
	for i := 0; i < streamCount; i++ {
		streamWG.Add(1)
		go func(idx int) {
			defer streamWG.Done()
			c, err := tunCfg.TunnelDialer.DialContext(ctx, "tcp", echoAddr)
			if err != nil {
				streamErrs <- fmt.Errorf("stream %d dial: %w", idx, err)
				return
			}
			defer c.Close()

			payload := bytes.Repeat([]byte{byte('A' + idx)}, 4096)
			if _, err := c.Write(payload); err != nil {
				streamErrs <- fmt.Errorf("stream %d write: %w", idx, err)
				return
			}
			if cw, ok := c.(interface{ CloseWrite() error }); ok {
				if err := cw.CloseWrite(); err != nil {
					streamErrs <- fmt.Errorf("stream %d CloseWrite: %w", idx, err)
					return
				}
			} else {
				streamErrs <- fmt.Errorf("stream %d does not implement CloseWrite", idx)
				return
			}
			got, err := io.ReadAll(c)
			if err != nil {
				streamErrs <- fmt.Errorf("stream %d read: %w", idx, err)
				return
			}
			if !bytes.Equal(got, payload) {
				streamErrs <- fmt.Errorf("stream %d payload mismatch: got len %d want %d", idx, len(got), len(payload))
				return
			}
		}(i)
	}
	streamWG.Wait()
	close(streamErrs)
	for err := range streamErrs {
		if err != nil {
			t.Fatal(err)
		}
	}

	// 4. SetBypass updates both DNS and RouteManager on helper.
	if err := guiCtrl.SetBypass(ctx, false); err != nil {
		t.Fatalf("SetBypass(false) failed: %v", err)
	}
	routeMgr.mu.Lock()
	bypassCalls := slices.Clone(routeMgr.bypassCalls)
	routeMgr.mu.Unlock()
	if !slices.Equal(bypassCalls, []bool{false}) {
		t.Fatalf("expected SetBypassIranLAN(false), got %v", bypassCalls)
	}

	// 5. Stats returns helper's TunRunner stats.
	st := guiCtrl.Stats()
	if !st.Running || st.IfaceIndex != 88 || st.RxBytes != 1234 || st.TxBytes != 5678 {
		t.Fatalf("unexpected Stats(): %+v", st)
	}

	// 6. Stop tears down helper cleanly and idempotently.
	if err := guiCtrl.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if err := guiCtrl.Stop(ctx); err != nil {
		t.Fatalf("second Stop failed: %v", err)
	}

	select {
	case err := <-helperDone:
		if err != nil {
			t.Fatalf("RunHelperOnConn exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for RunHelperOnConn exit")
	}

	evMu.Lock()
	gotEvents := slices.Clone(events)
	evMu.Unlock()
	wantEvents := []string{"route.capture", "tun.start", "route.apply", "route.set_bypass:false", "route.restore", "tun.stop"}
	if !slices.Equal(gotEvents, wantEvents) {
		t.Fatalf("lifecycle event order mismatch: got %v want %v", gotEvents, wantEvents)
	}
}

func TestHelperIPCCrashSafetyCleanupWithoutRecoveryFile(t *testing.T) {
	tmpCfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpCfg)
	t.Setenv("HOME", tmpCfg)

	var evMu sync.Mutex
	var events []string
	routeMgr := &mockRouteManager{
		captureSnap: splitroute.NetworkSnapshot{
			OrigGateway:    "192.168.10.1",
			OrigIfaceName:  "wlan0",
			OrigIfaceIndex: 4,
			TUNIfaceName:   splitroute.TUNIfaceName,
		},
		eventLog:   &events,
		eventLogMu: &evMu,
	}
	tunRunner := &mockTunRunner{
		startIfIndex: 55,
		eventLog:     &events,
		eventLogMu:   &evMu,
	}
	var helperDNS *dns.Server
	helperCtrl := NewDirectTUNController(
		TUNCapsDTO{Supported: true},
		routeMgr,
		func() *dns.Server {
			helperDNS = dns.NewServer()
			return helperDNS
		},
		func() tun.TunRunner { return tunRunner },
		discardLogger(),
	)

	guiConn, helperConn := net.Pipe()
	helperDone := make(chan error, 1)
	go func() {
		helperDone <- RunHelperOnConn(context.Background(), helperConn, helperCtrl, discardLogger())
	}()

	var capturedGUI net.Conn
	launcher := &funcHelperLauncher{
		launchFn: func(ctx context.Context) (io.ReadWriteCloser, func(), error) {
			capturedGUI = guiConn
			return guiConn, func() { _ = guiConn.Close() }, nil
		},
	}

	guiCtrl := newHelperTUNController(
		TUNCapsDTO{Supported: true, RequiresElevation: true},
		launcher,
		&mockRouteManager{},
		discardLogger(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	snap, err := guiCtrl.PrepareSession(ctx)
	if err != nil {
		t.Fatalf("PrepareSession failed: %v", err)
	}
	snap.VPSPeerIP = "203.0.113.99"

	if err := guiCtrl.StartTUN(ctx, TUNStartRequest{
		Snapshot:      snap,
		BypassIranLAN: true,
	}, &localEchoTunnelDialer{}); err != nil {
		t.Fatalf("StartTUN failed: %v", err)
	}

	// Simulate abrupt GUI crash by closing the underlying IPC connection directly (without Stop RPC).
	if err := capturedGUI.Close(); err != nil {
		t.Fatalf("close guiConn: %v", err)
	}

	select {
	case err := <-helperDone:
		if err != nil {
			t.Fatalf("expected clean crash-cleanup exit from RunHelperOnConn, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for helper crash cleanup")
	}

	evMu.Lock()
	gotEvents := slices.Clone(events)
	evMu.Unlock()
	wantEvents := []string{"route.capture", "tun.start", "route.apply", "route.restore", "tun.stop"}
	if !slices.Equal(gotEvents, wantEvents) {
		t.Fatalf("crash cleanup order mismatch: got %v want %v", gotEvents, wantEvents)
	}
	if helperDNS == nil {
		t.Fatalf("expected helper DNS server to have been started")
	}
	if _, err := helperDNS.Exchange(context.Background(), new(mdns.Msg)); err == nil {
		t.Fatalf("expected helper DNS server to be stopped on crash cleanup")
	}

	// Verify elevated helper NEVER created or touched recovery_state.json anywhere.
	var foundRecovery []string
	if walkErr := filepath.WalkDir(tmpCfg, func(path string, d os.DirEntry, err error) error {
		if err == nil && d != nil && d.Name() == recovery.StateFileName {
			foundRecovery = append(foundRecovery, path)
		}
		return nil
	}); walkErr != nil {
		t.Fatalf("walk tmpCfg: %v", walkErr)
	}
	if len(foundRecovery) > 0 {
		t.Fatalf("helper unexpectedly created recovery_state.json: %v", foundRecovery)
	}
}

func TestHelperIPCRestoreFromSnapshotOneShot(t *testing.T) {
	routeMgr := &mockRouteManager{}
	helperCtrl := NewDirectTUNController(
		TUNCapsDTO{Supported: true},
		routeMgr,
		dns.NewServer,
		func() tun.TunRunner { return &mockTunRunner{} },
		discardLogger(),
	)

	helperDoneCh := make(chan error, 1)
	launcher := &funcHelperLauncher{
		launchFn: func(ctx context.Context) (io.ReadWriteCloser, func(), error) {
			guiConn, helperConn := net.Pipe()
			go func() {
				helperDoneCh <- RunHelperOnConn(context.Background(), helperConn, helperCtrl, discardLogger())
			}()
			return guiConn, func() { _ = guiConn.Close() }, nil
		},
	}

	guiCtrl := newHelperTUNController(
		TUNCapsDTO{Supported: true, RequiresElevation: true},
		launcher,
		&mockRouteManager{},
		discardLogger(),
	)

	snap := splitroute.NetworkSnapshot{
		VPSPeerIP:      "198.51.100.7",
		OrigGateway:    "10.0.0.1",
		OrigIfaceName:  "eth0",
		OrigIfaceIndex: 2,
		TUNIfaceName:   splitroute.TUNIfaceName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := guiCtrl.RestoreFromSnapshot(ctx, snap); err != nil {
		t.Fatalf("RestoreFromSnapshot failed: %v", err)
	}

	select {
	case err := <-helperDoneCh:
		if err != nil {
			t.Fatalf("one-shot helper exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for one-shot helper exit")
	}

	if launcher.Calls() != 1 {
		t.Fatalf("expected 1 launcher call, got %d", launcher.Calls())
	}
	if launcher.cleanups.Load() != 1 {
		t.Fatalf("expected 1 cleanup call, got %d", launcher.cleanups.Load())
	}

	routeMgr.mu.Lock()
	restoredCount := len(routeMgr.restoredSnaps)
	var restoredSnap splitroute.NetworkSnapshot
	if restoredCount > 0 {
		restoredSnap = routeMgr.restoredSnaps[0]
	}
	routeMgr.mu.Unlock()
	if restoredCount != 1 || restoredSnap.VPSPeerIP != "198.51.100.7" {
		t.Fatalf("unexpected restored snapshots: count=%d snap=%+v", restoredCount, restoredSnap)
	}
}

func TestHelperIPCIsActiveOnOSAvoidsElevationAndFallsBack(t *testing.T) {
	// Case 1: Local unprivileged check succeeds -> zero launcher calls.
	localMgr := &mockRouteManager{isActive: true}
	launcher := &funcHelperLauncher{
		launchFn: func(ctx context.Context) (io.ReadWriteCloser, func(), error) {
			return nil, nil, errors.New("launcher should not be called when local check succeeds")
		},
	}
	ctrl := newHelperTUNController(TUNCapsDTO{Supported: true}, launcher, localMgr, discardLogger())
	active, err := ctrl.IsActiveOnOS(context.Background())
	if err != nil || !active {
		t.Fatalf("expected active=true err=nil, got active=%v err=%v", active, err)
	}
	if launcher.Calls() != 0 {
		t.Fatalf("expected 0 launcher calls, got %d", launcher.Calls())
	}

	// Case 2: Local check errors -> falls back to helper.
	localMgrFail := &mockRouteManager{isActiveErr: errors.New("netlink unavailable")}
	helperRouteMgr := &mockRouteManager{isActive: true}
	helperCtrl := NewDirectTUNController(TUNCapsDTO{Supported: true}, helperRouteMgr, dns.NewServer, func() tun.TunRunner { return &mockTunRunner{} }, discardLogger())
	helperDone := make(chan error, 1)
	fallbackLauncher := &funcHelperLauncher{
		launchFn: func(ctx context.Context) (io.ReadWriteCloser, func(), error) {
			guiConn, helperConn := net.Pipe()
			go func() {
				helperDone <- RunHelperOnConn(context.Background(), helperConn, helperCtrl, discardLogger())
			}()
			return guiConn, func() { _ = guiConn.Close() }, nil
		},
	}
	ctrlFallback := newHelperTUNController(TUNCapsDTO{Supported: true}, fallbackLauncher, localMgrFail, discardLogger())
	active, err = ctrlFallback.IsActiveOnOS(context.Background())
	if err != nil || !active {
		t.Fatalf("expected fallback active=true err=nil, got active=%v err=%v", active, err)
	}
	if fallbackLauncher.Calls() != 1 || fallbackLauncher.cleanups.Load() != 1 {
		t.Fatalf("expected 1 fallback launch and 1 cleanup, got launches=%d cleanups=%d", fallbackLauncher.Calls(), fallbackLauncher.cleanups.Load())
	}
	select {
	case err := <-helperDone:
		if err != nil {
			t.Fatalf("fallback helper exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for fallback helper exit")
	}
}

func TestRunHelperModeArgValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "empty", args: nil},
		{name: "only_flag", args: []string{"--tun-helper"}},
		{name: "both_socket_and_pipe", args: []string{"--tun-helper", "--socket", "/tmp/a.sock", "--pipe", `\\.\pipe\tunssh-123`}},
		{name: "rejects_secret_flag", args: []string{"--tun-helper", "--socket", "/tmp/a.sock", "--password", "hunter2"}},
		{name: "rejects_positional", args: []string{"--tun-helper", "--socket", "/tmp/a.sock", "extra"}},
		{name: "invalid_socket_path", args: []string{"--tun-helper", "--socket", "/etc/passwd"}},
		{name: "invalid_pipe_name", args: []string{"--tun-helper", "--pipe", `\\.\pipe\other-123`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := RunHelperMode(tc.args, discardLogger()); err == nil {
				t.Fatalf("expected error for args %v, got nil", tc.args)
			}
		})
	}
}

func TestLinuxPeerCredAndUDS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only SO_PEERCRED and UDS test")
	}

	// 1. Unit tests for verifyLinuxPeerCred: Uid == 0 passes, Uid == 1000 & nil rejected.
	if err := testCheckLinuxPeerCred(0, false); err != nil {
		t.Fatalf("expected Uid 0 to pass verifyLinuxPeerCred, got: %v", err)
	}
	if err := testCheckLinuxPeerCred(1000, false); err == nil {
		t.Fatalf("expected Uid 1000 to be rejected by verifyLinuxPeerCred")
	}
	if err := testCheckLinuxPeerCred(0, true); err == nil {
		t.Fatalf("expected nil ucred to be rejected by verifyLinuxPeerCred")
	}

	// 2. Real UDS SO_PEERCRED end-to-end connection test in 0700 XDG_RUNTIME_DIR.
	rtDir := t.TempDir()
	// Keep path short enough for Linux 108-byte sun_path.
	if len(rtDir) > 70 {
		shortDir, err := os.MkdirTemp("/tmp", "tunssh-uds-")
		if err != nil {
			t.Fatalf("MkdirTemp: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(shortDir) })
		rtDir = shortDir
	}
	t.Setenv("XDG_RUNTIME_DIR", rtDir)

	sockDir := filepath.Join(rtDir, "tunssh")
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		t.Fatalf("mkdir sockDir: %v", err)
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sockPath := filepath.Join(sockDir, "tunssh-"+hex.EncodeToString(rnd[:])+".sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix(%s): %v", sockPath, err)
	}
	defer ln.Close()
	if err := os.Chmod(sockPath, 0o600); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}

	// 2a. Accept real UDS connection and verify SO_PEERCRED returns os.Getuid().
	acceptCh := make(chan struct {
		conn net.Conn
		uid  uint32
		err  error
	}, 1)
	go func() {
		c, uid, err := testAcceptUnixPeerCred(context.Background(), ln, false, uint32(os.Getuid()))
		acceptCh <- struct {
			conn net.Conn
			uid  uint32
			err  error
		}{c, uid, err}
	}()

	clientConn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	res := <-acceptCh
	if res.err != nil {
		_ = clientConn.Close()
		t.Fatalf("testAcceptUnixPeerCred failed: %v", res.err)
	}
	if res.uid != uint32(os.Getuid()) {
		t.Fatalf("expected peer uid %d, got %d", os.Getuid(), res.uid)
	}

	// Verify framing traffic works over the verified UDS connection.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 5)
	if _, err := clientConn.Write(append(hdr[:], []byte("hello")...)); err != nil {
		t.Fatalf("write UDS: %v", err)
	}
	buf := make([]byte, 9)
	if _, err := io.ReadFull(res.conn, buf); err != nil {
		t.Fatalf("read UDS: %v", err)
	}
	if string(buf[4:]) != "hello" {
		t.Fatalf("unexpected UDS payload: %q", string(buf[4:]))
	}
	_ = clientConn.Close()
	_ = res.conn.Close()

	// 2b. Verify verifyLinuxPeerCred rejects non-root SO_PEERCRED on real UDS when running unprivileged.
	if os.Getuid() != 0 {
		rejectCh := make(chan error, 1)
		go func() {
			c, _, err := testAcceptUnixPeerCred(context.Background(), ln, true, 0)
			if c != nil {
				_ = c.Close()
			}
			rejectCh <- err
		}()
		c2, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
		if err != nil {
			t.Fatalf("DialUnix 2: %v", err)
		}
		_ = c2.Close()
		if rejErr := <-rejectCh; rejErr == nil {
			t.Fatalf("expected verifyLinuxPeerCred to reject non-root peer uid %d on real UDS", os.Getuid())
		}
	}

	// 3. End-to-end RunHelperMode + RunHelperLinux over real UDS in $XDG_RUNTIME_DIR/tunssh.
	e2eSock := filepath.Join(sockDir, "tunssh-e2e-real.sock")
	e2eLn, err := net.ListenUnix("unix", &net.UnixAddr{Name: e2eSock, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix e2e: %v", err)
	}
	defer e2eLn.Close()
	if err := os.Chmod(e2eSock, 0o600); err != nil {
		t.Fatalf("chmod e2e socket: %v", err)
	}

	helperExitCh := make(chan error, 1)
	go func() {
		helperExitCh <- RunHelperMode([]string{"--tun-helper", "--socket", e2eSock}, discardLogger())
	}()

	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer acceptCancel()
	acceptedConn, gotUID, err := testAcceptUnixPeerCred(acceptCtx, e2eLn, false, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("accept e2e UDS: %v", err)
	}
	if gotUID != uint32(os.Getuid()) {
		_ = acceptedConn.Close()
		t.Fatalf("unexpected e2e peer uid %d", gotUID)
	}

	e2eLauncher := &funcHelperLauncher{
		launchFn: func(ctx context.Context) (io.ReadWriteCloser, func(), error) {
			return acceptedConn, func() { _ = acceptedConn.Close() }, nil
		},
	}
	// Force IsActiveOnOS to fall back to helper over the real UDS connection.
	e2eCtrl := newHelperTUNController(
		TUNCapsDTO{Supported: true},
		e2eLauncher,
		&mockRouteManager{isActiveErr: errors.New("force helper fallback")},
		discardLogger(),
	)
	if _, err := e2eCtrl.IsActiveOnOS(acceptCtx); err != nil {
		t.Fatalf("e2e IsActiveOnOS over real UDS failed: %v", err)
	}
	_ = acceptedConn.Close()

	select {
	case err := <-helperExitCh:
		if err != nil {
			t.Fatalf("RunHelperMode exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for RunHelperMode exit")
	}
}

func TestDirectTUNControllerTUNStartFailureRollsBackDNS(t *testing.T) {
	routeMgr := &mockRouteManager{}
	tunRunner := &mockTunRunner{startErr: errors.New("simulated tun device failure")}
	var createdDNS *dns.Server
	ctrl := NewDirectTUNController(
		TUNCapsDTO{Supported: true},
		routeMgr,
		func() *dns.Server {
			createdDNS = dns.NewServer()
			return createdDNS
		},
		func() tun.TunRunner { return tunRunner },
		discardLogger(),
	)

	req := TUNStartRequest{
		Snapshot: splitroute.NetworkSnapshot{
			VPSPeerIP:      "203.0.113.55",
			OrigGateway:    "192.168.1.1",
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 2,
		},
	}
	err := ctrl.StartTUN(context.Background(), req, &localEchoTunnelDialer{})
	if err == nil || !strings.Contains(err.Error(), "simulated tun device failure") {
		t.Fatalf("expected TUN start error, got %v", err)
	}
	if createdDNS == nil {
		t.Fatalf("expected DNS server to have been created")
	}
	if _, exErr := createdDNS.Exchange(context.Background(), new(mdns.Msg)); exErr == nil {
		t.Fatalf("expected DNS server to be stopped after TunRunner.Start failure")
	}
}

func TestHelperTUNControllerStartFailureClosesSessionAndStopIsIdempotent(t *testing.T) {
	routeMgr := &mockRouteManager{
		captureSnap: splitroute.NetworkSnapshot{
			OrigGateway:    "192.168.1.1",
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 2,
		},
		applyErr: errors.New("simulated apply error"),
	}
	helperCtrl := NewDirectTUNController(
		TUNCapsDTO{Supported: true},
		routeMgr,
		dns.NewServer,
		func() tun.TunRunner { return &mockTunRunner{} },
		discardLogger(),
	)

	helperDone := make(chan error, 1)
	launcher := &funcHelperLauncher{
		launchFn: func(ctx context.Context) (io.ReadWriteCloser, func(), error) {
			guiConn, helperConn := net.Pipe()
			go func() {
				helperDone <- RunHelperOnConn(context.Background(), helperConn, helperCtrl, discardLogger())
			}()
			return guiConn, func() { _ = guiConn.Close() }, nil
		},
	}
	guiCtrl := newHelperTUNController(TUNCapsDTO{Supported: true}, launcher, &mockRouteManager{}, discardLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	snap, err := guiCtrl.PrepareSession(ctx)
	if err != nil {
		t.Fatalf("PrepareSession failed: %v", err)
	}
	snap.VPSPeerIP = "203.0.113.77"
	if err := guiCtrl.StartTUN(ctx, TUNStartRequest{Snapshot: snap}, &localEchoTunnelDialer{}); err == nil {
		t.Fatalf("expected StartTUN error, got nil")
	}
	if err := guiCtrl.Stop(ctx); err != nil {
		t.Fatalf("idempotent Stop after StartTUN failure returned error: %v", err)
	}
	if launcher.cleanups.Load() != 1 {
		t.Fatalf("expected 1 cleanup call, got %d", launcher.cleanups.Load())
	}
	select {
	case err := <-helperDone:
		if err != nil {
			t.Fatalf("helper exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for helper exit")
	}
}

func TestHelperIPCSessionCloseCancelsInFlightStartTUNAndFallbackGatewayDNS(t *testing.T) {
	inStart := make(chan struct{})
	opCanceled := make(chan struct{})

	routeMgr := &mockRouteManager{
		captureSnap: splitroute.NetworkSnapshot{
			OrigGateway:    "192.168.50.1",
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 2,
		},
	}

	blockingTun := &blockingContextTunRunner{
		onStart: func(ctx context.Context, cfg tun.Config) error {
			close(inStart)
			<-ctx.Done()
			close(opCanceled)
			return ctx.Err()
		},
	}

	ctrl := NewDirectTUNController(
		TUNCapsDTO{Supported: true},
		routeMgr,
		func() *dns.Server {
			return dns.NewServer()
		},
		func() tun.TunRunner { return blockingTun },
		discardLogger(),
	)

	helperDone := make(chan error, 1)
	launcher := &funcHelperLauncher{
		launchFn: func(ctx context.Context) (io.ReadWriteCloser, func(), error) {
			guiConn, helperConn := net.Pipe()
			go func() {
				helperDone <- RunHelperOnConn(context.Background(), helperConn, ctrl, discardLogger())
			}()
			return guiConn, func() { _ = guiConn.Close() }, nil
		},
	}
	guiCtrl := newHelperTUNController(TUNCapsDTO{Supported: true, RequiresElevation: true}, launcher, &mockRouteManager{isActive: false}, discardLogger())

	snap, err := guiCtrl.PrepareSession(context.Background())
	if err != nil {
		t.Fatalf("PrepareSession failed: %v", err)
	}
	snap.VPSPeerIP = "203.0.113.88"

	startCtx, startCancel := context.WithCancel(context.Background())
	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- guiCtrl.StartTUN(startCtx, TUNStartRequest{Snapshot: snap, BypassIranLAN: true}, &localEchoTunnelDialer{})
	}()

	<-inStart
	startCancel()

	select {
	case <-opCanceled:
	case <-time.After(3 * time.Second):
		t.Fatalf("expected helper StartTUN opCtx canceled on client session close")
	}
	select {
	case err := <-startErrCh:
		if err == nil {
			t.Fatalf("expected canceled StartTUN error")
		}
		if errors.Is(err, ErrTUNRollbackIncomplete) {
			t.Fatalf("did not expect ErrTUNRollbackIncomplete when local OS check reports inactive: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for StartTUN cancellation")
	}
	select {
	case err := <-helperDone:
		if err != nil {
			t.Fatalf("helper exit error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for helper exit")
	}

	// Verify DirectTUNController private OrigGateway DNS fallback when OrigDNSServers is empty.
	var capturedDNS *dns.Server
	ctrl2 := NewDirectTUNController(
		TUNCapsDTO{Supported: true},
		&mockRouteManager{},
		func() *dns.Server {
			capturedDNS = dns.NewServer()
			return capturedDNS
		},
		func() tun.TunRunner { return &mockTunRunner{startIfIndex: 11} },
		discardLogger(),
	)
	if err := ctrl2.StartTUN(context.Background(), TUNStartRequest{
		Snapshot: splitroute.NetworkSnapshot{
			VPSPeerIP:      "203.0.113.88",
			OrigGateway:    "192.168.50.1",
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 2,
			// OrigDNSServers intentionally empty
		},
		BypassIranLAN: true,
	}, &localEchoTunnelDialer{}); err != nil {
		t.Fatalf("DirectTUNController.StartTUN fallback failed: %v", err)
	}
	if capturedDNS == nil || capturedDNS.UDPAddr() == "" {
		t.Fatalf("expected running DNS server with fallback upstream")
	}
	if err := ctrl2.Stop(context.Background()); err != nil {
		t.Fatalf("ctrl2.Stop failed: %v", err)
	}
}

type blockingContextTunRunner struct {
	onStart func(ctx context.Context, cfg tun.Config) error
}

func (b *blockingContextTunRunner) Start(ctx context.Context, cfg tun.Config) (int, error) {
	if b.onStart != nil {
		return 0, b.onStart(ctx, cfg)
	}
	return 1, nil
}

func (b *blockingContextTunRunner) Stop(context.Context) error { return nil }
func (b *blockingContextTunRunner) Stats() tun.Stats           { return tun.Stats{} }

func TestDirectTUNControllerWrapsErrTUNRollbackIncompleteOnlyWhenRollbackFails(t *testing.T) {
	// Case 1: clean rollback on ApplySplitTunnel error -> NO ErrTUNRollbackIncomplete.
	cleanCtrl := NewDirectTUNController(
		TUNCapsDTO{Supported: true},
		&mockRouteManager{applyErr: errors.New("apply failed")},
		dns.NewServer,
		func() tun.TunRunner { return &mockTunRunner{startIfIndex: 7} },
		discardLogger(),
	)
	req := TUNStartRequest{
		Snapshot: splitroute.NetworkSnapshot{
			VPSPeerIP:      "203.0.113.99",
			OrigGateway:    "192.168.1.1",
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 2,
		},
	}
	err := cleanCtrl.StartTUN(context.Background(), req, &localEchoTunnelDialer{})
	if err == nil || errors.Is(err, ErrTUNRollbackIncomplete) {
		t.Fatalf("expected clean rollback error without ErrTUNRollbackIncomplete, got %v", err)
	}

	// Case 2: rollback RestoreNetwork fails -> ErrTUNRollbackIncomplete wrapped.
	brokenCtrl := NewDirectTUNController(
		TUNCapsDTO{Supported: true},
		&mockRouteManager{
			applyErr:   errors.New("apply failed"),
			restoreErr: errors.New("restore failed"),
		},
		dns.NewServer,
		func() tun.TunRunner { return &mockTunRunner{startIfIndex: 7} },
		discardLogger(),
	)
	err = brokenCtrl.StartTUN(context.Background(), req, &localEchoTunnelDialer{})
	if !errors.Is(err, ErrTUNRollbackIncomplete) {
		t.Fatalf("expected ErrTUNRollbackIncomplete when rollback fails, got %v", err)
	}
}
