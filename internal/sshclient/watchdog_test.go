package sshclient

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func waitCondition(t *testing.T, timeout time.Duration, fn func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for: %s", timeout, msg)
}

func settleGoroutines(t *testing.T, baseline int, tolerance int) {
	t.Helper()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= baseline+tolerance {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: baseline=%d current=%d (tolerance=%d)", baseline, runtime.NumGoroutine(), tolerance)
}

func TestWatchdogSingleInFlightAndMissedProbesReconnect(t *testing.T) {
	hostSigner := generateTestSSHSigner(t)
	pin := &HostKeyPin{
		Algorithm: hostSigner.PublicKey().Type(),
		SHA256:    ssh.FingerprintSHA256(hostSigner.PublicKey()),
	}

	srv := startTestSSHServer(t, testServerOptions{
		hostSigner:       hostSigner,
		password:         "pw",
		ignoreKeepalives: true,
	})
	defer srv.Close()

	engine := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cfg := ConnectConfig{
		ProfileID: "wd-1",
		Host:      srv.Host(),
		Port:      srv.Port(),
		Username:  "ali",
		Auth: AuthConfig{
			Type:     AuthPassword,
			Password: "pw",
		},
		PinnedHostKey: pin,
		Watchdog: WatchdogConfig{
			Interval:  50 * time.Millisecond,
			Timeout:   25 * time.Millisecond,
			MaxMissed: 2,
		},
		BackoffBase: 20 * time.Millisecond,
		BackoffMax:  60 * time.Millisecond,
	}

	if err := engine.Connect(ctx, cfg); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if got := engine.epoch.Load(); got != 1 {
		t.Fatalf("initial epoch = %d, want 1", got)
	}

	// Switch server back to responding to keepalives AFTER at least 2 ignored keepalive requests
	// so the reconnect attempt succeeds and stays healthy!
	waitCondition(t, 2*time.Second, func() bool {
		return engine.epoch.Load() >= 2
	}, "watchdog should detect 2 missed keepalives and bump epoch")

	// Crucially: even though 2 ticks expired while the first keepalive probe was wedged,
	// at most 1 in-flight keepalive@openssh.com request should have been sent on that session!
	if got := srv.KeepaliveCountForConn(0); got != 1 {
		t.Fatalf("first session received %d keepalive requests while wedged, want exactly 1 (single in-flight probe invariant)", got)
	}

	// Now allow the server to reply to keepalives so reconnect stabilizes on epoch >= 2.
	srv.SetIgnoreKeepalives(false)

	waitCondition(t, 3*time.Second, func() bool {
		snap := engine.Snapshot()
		return snap.State == StateConnected && engine.epoch.Load() >= 2
	}, "engine should reconnect via backoff after watchdog drop")

	rtt, err := engine.MeasureRTT(ctx)
	if err != nil {
		t.Fatalf("MeasureRTT after reconnect failed: %v", err)
	}
	if rtt < 0 {
		t.Fatalf("unexpected negative RTT: %v", rtt)
	}

	if err := engine.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}
}

func TestWatchdogEpochGuardIgnoresStaleExit(t *testing.T) {
	hostSigner := generateTestSSHSigner(t)
	pin := &HostKeyPin{
		Algorithm: hostSigner.PublicKey().Type(),
		SHA256:    ssh.FingerprintSHA256(hostSigner.PublicKey()),
	}

	echoAddr := startEchoServer(t)
	srv := startTestSSHServer(t, testServerOptions{
		hostSigner: hostSigner,
		password:   "pw",
	})
	defer srv.Close()

	engine := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cfg := ConnectConfig{
		ProfileID: "epoch-race",
		Host:      srv.Host(),
		Port:      srv.Port(),
		Username:  "ali",
		Auth: AuthConfig{
			Type:     AuthPassword,
			Password: "pw",
		},
		PinnedHostKey: pin,
		Watchdog: WatchdogConfig{
			Interval:  200 * time.Millisecond,
			Timeout:   100 * time.Millisecond,
			MaxMissed: 2,
		},
	}

	// Epoch 1 connect.
	if err := engine.Connect(ctx, cfg); err != nil {
		t.Fatalf("first Connect failed: %v", err)
	}
	if got := engine.epoch.Load(); got != 1 {
		t.Fatalf("epoch after first connect = %d, want 1", got)
	}

	// Epoch 2 connect replaces epoch 1 cleanly.
	if err := engine.Connect(ctx, cfg); err != nil {
		t.Fatalf("second Connect failed: %v", err)
	}
	if got := engine.epoch.Load(); got != 2 {
		t.Fatalf("epoch after second connect = %d, want 2", got)
	}

	// Inject stale delayed exit signal from epoch=1 while epoch=2 is active.
	engine.handleSessionExit(1, errors.New("delayed epoch 1 failure"))

	if got := engine.epoch.Load(); got != 2 {
		t.Fatalf("epoch changed to %d after stale epoch 1 signal, want 2", got)
	}
	if got := engine.Snapshot().State; got != StateConnected {
		t.Fatalf("state = %q after stale epoch 1 signal, want %q", got, StateConnected)
	}

	// Verify epoch 2 tunnel still forwards real traffic cleanly.
	conn, err := engine.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext on epoch 2 failed: %v", err)
	}
	defer conn.Close()
	assertEchoPayload(t, conn, []byte("epoch-2-alive"))

	if err := engine.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}
}

func TestDisconnectMidDialAndMidBackoffZeroGoroutineLeak(t *testing.T) {
	// Warm up baseline after any prior stdlib background goroutines settle.
	runtime.GC()
	time.Sleep(30 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	t.Run("cancel_mid_dial_tcp", func(t *testing.T) {
		engine := NewClient()
		dialStarted := make(chan struct{})
		engine.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
			close(dialStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		}

		connectDone := make(chan error, 1)
		go func() {
			connectDone <- engine.Connect(context.Background(), ConnectConfig{
				ProfileID: "mid-dial",
				Host:      "127.0.0.1",
				Port:      443,
				Username:  "ali",
				Auth: AuthConfig{
					Type:     AuthPassword,
					Password: "pw",
				},
				DialTimeout: 5 * time.Second,
			})
		}()

		<-dialStarted
		start := time.Now()
		dCtx, dCancel := context.WithTimeout(context.Background(), time.Second)
		defer dCancel()
		if err := engine.Disconnect(dCtx); err != nil {
			t.Fatalf("Disconnect mid-dial failed: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Fatalf("Disconnect mid-dial took %v, expected fast return", elapsed)
		}
		<-connectDone
		if got := engine.Snapshot().State; got != StateDisconnected {
			t.Fatalf("state = %q, want %q", got, StateDisconnected)
		}
		settleGoroutines(t, baseline, 1)
	})

	t.Run("cancel_mid_handshake_ssh_stalled", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		accepted := make(chan net.Conn, 1)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				accepted <- c
			}
		}()

		engine := NewClient()
		addr := ln.Addr().(*net.TCPAddr)
		connectDone := make(chan error, 1)
		go func() {
			connectDone <- engine.Connect(context.Background(), ConnectConfig{
				ProfileID: "mid-handshake",
				Host:      "127.0.0.1",
				Port:      addr.Port,
				Username:  "ali",
				Auth: AuthConfig{
					Type:     AuthPassword,
					Password: "pw",
				},
				DialTimeout: 5 * time.Second,
			})
		}()

		srvConn := <-accepted
		defer srvConn.Close()

		start := time.Now()
		dCtx, dCancel := context.WithTimeout(context.Background(), time.Second)
		defer dCancel()
		if err := engine.Disconnect(dCtx); err != nil {
			t.Fatalf("Disconnect mid-handshake failed: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Fatalf("Disconnect mid-handshake took %v, expected fast return", elapsed)
		}
		<-connectDone
		settleGoroutines(t, baseline, 1)
	})

	t.Run("cancel_mid_backoff_via_Disconnect", func(t *testing.T) {
		hostSigner := generateTestSSHSigner(t)
		pin := &HostKeyPin{
			Algorithm: hostSigner.PublicKey().Type(),
			SHA256:    ssh.FingerprintSHA256(hostSigner.PublicKey()),
		}
		srv := startTestSSHServer(t, testServerOptions{
			hostSigner: hostSigner,
			password:   "pw",
		})

		engine := NewClient()
		var subMu sync.Mutex
		var states []ConnectionState
		reconnectingCh := make(chan struct{}, 1)
		unsub := engine.Subscribe(func(snap EngineSnapshot) {
			subMu.Lock()
			states = append(states, snap.State)
			subMu.Unlock()
			if snap.State == StateReconnecting {
				select {
				case reconnectingCh <- struct{}{}:
				default:
				}
			}
		})
		defer unsub()

		var dialAttempts atomic.Int32
		realDialer := &net.Dialer{}
		engine.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialAttempts.Add(1)
			return realDialer.DialContext(ctx, network, addr)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := engine.Connect(ctx, ConnectConfig{
			ProfileID: "mid-backoff",
			Host:      srv.Host(),
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:     AuthPassword,
				Password: "pw",
			},
			PinnedHostKey: pin,
			Watchdog: WatchdogConfig{
				Interval:  50 * time.Millisecond,
				Timeout:   25 * time.Millisecond,
				MaxMissed: 2,
			},
			// Long backoff so Disconnect definitely hits mid-backoff sleep.
			BackoffBase: 10 * time.Second,
			BackoffMax:  30 * time.Second,
		}); err != nil {
			t.Fatalf("Connect failed: %v", err)
		}

		// Force connection drop so engine enters StateReconnecting (10s backoff sleep).
		srv.Close()
		select {
		case <-reconnectingCh:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for StateReconnecting")
		}

		start := time.Now()
		dCtx, dCancel := context.WithTimeout(context.Background(), time.Second)
		defer dCancel()
		if err := engine.Disconnect(dCtx); err != nil {
			t.Fatalf("Disconnect mid-backoff failed: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Fatalf("Disconnect mid-backoff took %v, expected fast return", elapsed)
		}
		if got := engine.Snapshot().State; got != StateDisconnected {
			t.Fatalf("state = %q, want %q", got, StateDisconnected)
		}
		if dialAttempts.Load() != 1 {
			t.Fatalf("dialAttempts = %d, want 1 (should not have finished backoff sleep)", dialAttempts.Load())
		}
		subMu.Lock()
		sawReconnect := false
		sawDisconnected := false
		for _, st := range states {
			if st == StateReconnecting {
				sawReconnect = true
			}
			if st == StateDisconnected {
				sawDisconnected = true
			}
		}
		subMu.Unlock()
		if !sawReconnect || !sawDisconnected {
			t.Fatalf("expected StateReconnecting and StateDisconnected notifications, got %v", states)
		}
		settleGoroutines(t, baseline, 1)
	})
}

func TestWatchdogHealthyKeepalivesStayConnected(t *testing.T) {
	hostSigner := generateTestSSHSigner(t)
	pin := &HostKeyPin{
		Algorithm: hostSigner.PublicKey().Type(),
		SHA256:    ssh.FingerprintSHA256(hostSigner.PublicKey()),
	}
	srv := startTestSSHServer(t, testServerOptions{
		hostSigner: hostSigner,
		password:   "pw",
	})
	defer srv.Close()

	engine := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := engine.Connect(ctx, ConnectConfig{
		ProfileID: "healthy-wd",
		Host:      srv.Host(),
		Port:      srv.Port(),
		Username:  "ali",
		Auth: AuthConfig{
			Type:     AuthPassword,
			Password: "pw",
		},
		PinnedHostKey: pin,
		Watchdog: WatchdogConfig{
			Interval:  25 * time.Millisecond,
			Timeout:   200 * time.Millisecond,
			MaxMissed: 2,
		},
	}); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer engine.Disconnect(ctx)

	waitCondition(t, 2*time.Second, func() bool {
		return srv.KeepaliveCountForConn(0) >= 3
	}, "watchdog should issue multiple healthy keepalives")

	if got := engine.epoch.Load(); got != 1 {
		t.Fatalf("epoch = %d, want 1 during healthy session", got)
	}
	if got := engine.Snapshot().State; got != StateConnected {
		t.Fatalf("state = %q, want %q", got, StateConnected)
	}
}
