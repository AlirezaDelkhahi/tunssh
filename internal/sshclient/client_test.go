package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type testServerOptions struct {
	hostSigner         ssh.Signer
	password           string
	kbdInteractiveOnly bool
	pamWithPreBanner   bool
	pamLoopForever     bool
	allowedPubKey      ssh.PublicKey
	prohibitForwarding bool
	ignoreKeepalives   bool
}

type testSSHServer struct {
	mu               sync.Mutex
	opts             testServerOptions
	ln               net.Listener
	host             string
	port             int
	wg               sync.WaitGroup
	conns            []net.Conn
	keepalivePerConn []*atomic.Int32
	activeRawConns   atomic.Int32
	closed           atomic.Bool
}

func startTestSSHServer(t *testing.T, opts testServerOptions) *testSSHServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh test server: %v", err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	srv := &testSSHServer{
		opts: opts,
		ln:   ln,
		host: "127.0.0.1",
		port: tcpAddr.Port,
	}
	srv.wg.Add(1)
	go srv.serve()
	t.Cleanup(srv.Close)
	return srv
}

func (s *testSSHServer) Host() string { return s.host }
func (s *testSSHServer) Port() int    { return s.port }

func (s *testSSHServer) SetHostSigner(signer ssh.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opts.hostSigner = signer
}

func (s *testSSHServer) SetIgnoreKeepalives(ignore bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opts.ignoreKeepalives = ignore
}

func (s *testSSHServer) ActiveRawConns() int32 {
	return s.activeRawConns.Load()
}

func (s *testSSHServer) KeepaliveCountForConn(idx int) int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx < 0 || idx >= len(s.keepalivePerConn) {
		return 0
	}
	return s.keepalivePerConn[idx].Load()
}

func (s *testSSHServer) Close() {
	if s.closed.Swap(true) {
		return
	}
	_ = s.ln.Close()
	s.mu.Lock()
	conns := append([]net.Conn(nil), s.conns...)
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
}

func (s *testSSHServer) buildServerConfig() *ssh.ServerConfig {
	s.mu.Lock()
	opts := s.opts
	s.mu.Unlock()

	cfg := &ssh.ServerConfig{}
	cfg.AddHostKey(opts.hostSigner)

	if opts.allowedPubKey != nil {
		expected := opts.allowedPubKey.Marshal()
		cfg.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), expected) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("public key rejected")
		}
		return cfg
	}

	if opts.kbdInteractiveOnly || opts.pamLoopForever {
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if opts.pamLoopForever {
				for i := 0; i < 10; i++ {
					_, err := client("", "", []string{"Password: "}, []bool{false})
					if err != nil {
						return nil, err
					}
				}
				return nil, errors.New("pam loop failed")
			}
			if opts.pamWithPreBanner {
				ans, err := client("PAM Notice", "Authorized users only", nil, nil)
				if err != nil {
					return nil, err
				}
				if len(ans) != 0 {
					return nil, errors.New("expected 0 answers for empty pre-auth banner")
				}
			}
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != opts.password {
				return nil, errors.New("invalid keyboard-interactive password")
			}
			return &ssh.Permissions{}, nil
		}
		return cfg
	}

	cfg.PasswordCallback = func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if string(pass) == opts.password {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("invalid password")
	}
	return cfg
}

func (s *testSSHServer) serve() {
	defer s.wg.Done()
	for {
		rawConn, err := s.ln.Accept()
		if err != nil {
			return
		}
		kaCounter := &atomic.Int32{}
		s.mu.Lock()
		s.conns = append(s.conns, rawConn)
		s.keepalivePerConn = append(s.keepalivePerConn, kaCounter)
		s.mu.Unlock()

		s.activeRawConns.Add(1)
		s.wg.Add(1)
		go s.handleConn(rawConn, kaCounter)
	}
}

func (s *testSSHServer) handleConn(rawConn net.Conn, kaCounter *atomic.Int32) {
	defer s.wg.Done()
	defer func() {
		_ = rawConn.Close()
		s.activeRawConns.Add(-1)
	}()

	cfg := s.buildServerConfig()
	sConn, chans, reqs, err := ssh.NewServerConn(rawConn, cfg)
	if err != nil {
		return
	}
	defer sConn.Close()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				kaCounter.Add(1)
				s.mu.Lock()
				ignore := s.opts.ignoreKeepalives
				s.mu.Unlock()
				if ignore {
					continue
				}
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		s.mu.Lock()
		prohibit := s.opts.prohibitForwarding
		s.mu.Unlock()
		if prohibit {
			_ = newChan.Reject(ssh.Prohibited, "administratively prohibited")
			continue
		}

		var msg struct {
			DestAddr   string
			DestPort   uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(newChan.ExtraData(), &msg); err != nil {
			_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		target, err := net.DialTimeout("tcp", net.JoinHostPort(msg.DestAddr, strconv.Itoa(int(msg.DestPort))), 2*time.Second)
		if err != nil {
			_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			_ = target.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)

		s.wg.Add(1)
		go func(c ssh.Channel, t net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			defer t.Close()
			var copyWG sync.WaitGroup
			copyWG.Add(2)
			go func() {
				defer copyWG.Done()
				_, _ = io.Copy(t, c)
				if tc, ok := t.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}()
			go func() {
				defer copyWG.Done()
				_, _ = io.Copy(c, t)
				_ = c.CloseWrite()
			}()
			copyWG.Wait()
		}(ch, target)
	}
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
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
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return ln.Addr().String()
}

func assertEchoPayload(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write echo payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo payload: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, payload)
	}
}

func generateTestUserKeys(t *testing.T, passphrase string) (edUnencPEM, edEncPEM, rsaEncPEM string, edPub, rsaPub ssh.PublicKey) {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 user key: %v", err)
	}
	edSigner, err := ssh.NewSignerFromKey(edPriv)
	if err != nil {
		t.Fatalf("ed25519 signer: %v", err)
	}
	edPub = edSigner.PublicKey()

	blockUnenc, err := ssh.MarshalPrivateKey(edPriv, "test-ed")
	if err != nil {
		t.Fatalf("MarshalPrivateKey ed25519: %v", err)
	}
	edUnencPEM = string(pem.EncodeToMemory(blockUnenc))

	blockEncEd, err := ssh.MarshalPrivateKeyWithPassphrase(edPriv, "test-ed-enc", []byte(passphrase))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase ed25519: %v", err)
	}
	edEncPEM = string(pem.EncodeToMemory(blockEncEd))

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa user key: %v", err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaPriv)
	if err != nil {
		t.Fatalf("rsa signer: %v", err)
	}
	rsaPub = rsaSigner.PublicKey()

	blockEncRSA, err := ssh.MarshalPrivateKeyWithPassphrase(rsaPriv, "test-rsa-enc", []byte(passphrase))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase rsa: %v", err)
	}
	rsaEncPEM = string(pem.EncodeToMemory(blockEncRSA))

	return edUnencPEM, edEncPEM, rsaEncPEM, edPub, rsaPub
}

func TestBuildAuthMethods(t *testing.T) {
	_, edEncPEM, _, _, _ := generateTestUserKeys(t, "correct-passphrase")

	t.Run("password_and_keyboard_interactive_prompts", func(t *testing.T) {
		methods, err := BuildAuthMethods(AuthConfig{
			Type:     AuthPassword,
			Password: "my-secret-password",
		})
		if err != nil {
			t.Fatalf("BuildAuthMethods password failed: %v", err)
		}
		if len(methods) != 2 {
			t.Fatalf("expected 2 auth methods (password + kbd-interactive), got %d", len(methods))
		}

		kbd, ok := methods[1].(ssh.KeyboardInteractiveChallenge)
		if !ok {
			t.Fatalf("second method = %T, want ssh.KeyboardInteractiveChallenge", methods[1])
		}

		// Empty PAM banner returns empty slice cleanly.
		ans, err := kbd("banner", "instr", nil, nil)
		if err != nil || len(ans) != 0 {
			t.Fatalf("empty questions returned (%v, %v), want ([], nil)", ans, err)
		}

		// Non-echo prompt or case-insensitive password/passcode supplies password;
		// unrelated echo prompt does not leak password.
		ans, err = kbd("", "", []string{
			"Hidden prompt:",
			"Enter PASSCODE:",
			"Echo Username:",
		}, []bool{false, true, true})
		if err != nil {
			t.Fatalf("kbd round 2 failed: %v", err)
		}
		want := []string{"my-secret-password", "my-secret-password", ""}
		if len(ans) != len(want) {
			t.Fatalf("len(ans) = %d, want %d", len(ans), len(want))
		}
		for i := range want {
			if ans[i] != want[i] {
				t.Fatalf("ans[%d] = %q, want %q", i, ans[i], want[i])
			}
		}

		// Round 3 succeeds; round 4 exceeds maxKbdInteractiveRounds = 3.
		if _, err := kbd("", "", []string{"Password:"}, []bool{false}); err != nil {
			t.Fatalf("round 3 should succeed, got %v", err)
		}
		if _, err := kbd("", "", []string{"Password:"}, []bool{false}); err == nil {
			t.Fatal("round 4 should fail after maxKbdInteractiveRounds=3")
		}
	})

	t.Run("rejects_ppk_and_bad_or_missing_passphrases_before_dial", func(t *testing.T) {
		ppk := "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: test\n"
		for _, tc := range []struct {
			name string
			cfg  AuthConfig
			want string
		}{
			{"ppk", AuthConfig{Type: AuthKey, PrivateKey: ppk}, ERR_KEY_INVALID},
			{"missing_passphrase", AuthConfig{Type: AuthKey, PrivateKey: edEncPEM}, ERR_KEY_INVALID},
			{"wrong_passphrase", AuthConfig{Type: AuthKey, PrivateKey: edEncPEM, KeyPassphrase: "wrong"}, ERR_KEY_INVALID},
			{"garbage_pem", AuthConfig{Type: AuthKey, PrivateKey: "not a key"}, ERR_KEY_INVALID},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := BuildAuthMethods(tc.cfg)
				if err == nil {
					t.Fatal("expected key error")
				}
				mapped := ClassifyError(err, 443, PhaseAuth)
				if mapped.Code != tc.want || mapped.Retryable {
					t.Fatalf("mapped = %+v, want non-retryable %s", mapped, tc.want)
				}
			})
		}
	})
}

func TestClientAuthMatrixAndDialContextTraffic(t *testing.T) {
	hostSigner := generateTestSSHSigner(t)
	pin := &HostKeyPin{
		Algorithm: hostSigner.PublicKey().Type(),
		SHA256:    ssh.FingerprintSHA256(hostSigner.PublicKey()),
	}
	echoAddr := startEchoServer(t)

	edUnencPEM, edEncPEM, rsaEncPEM, edPub, rsaPub := generateTestUserKeys(t, "key-pass-123")

	t.Run("password_only_server_and_echo_byte_counters", func(t *testing.T) {
		srv := startTestSSHServer(t, testServerOptions{
			hostSigner: hostSigner,
			password:   "hunter2",
		})
		defer srv.Close()

		engine := NewClient()
		var subMu sync.Mutex
		var observedStates []ConnectionState
		unsub := engine.Subscribe(func(snap EngineSnapshot) {
			// Verify calling Snapshot() inside subscriber callback does NOT deadlock.
			_ = engine.Snapshot()
			subMu.Lock()
			observedStates = append(observedStates, snap.State)
			subMu.Unlock()
		})
		defer unsub()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := engine.Connect(ctx, ConnectConfig{
			ProfileID: "pw-only",
			Host:      srv.Host(),
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:     AuthPassword,
				Password: "hunter2",
			},
			PinnedHostKey: pin,
		})
		if err != nil {
			t.Fatalf("Connect password-only failed: %v", err)
		}

		conn, err := engine.DialContext(ctx, "tcp", echoAddr)
		if err != nil {
			t.Fatalf("DialContext failed: %v", err)
		}
		payload := []byte("hello-tunssh-direct-tcpip-payload-12345")
		assertEchoPayload(t, conn, payload)
		_ = conn.Close()

		snap := engine.Snapshot()
		if snap.State != StateConnected {
			t.Fatalf("state = %q, want %q", snap.State, StateConnected)
		}
		if snap.TxBytes != uint64(len(payload)) || snap.RxBytes != uint64(len(payload)) {
			t.Fatalf("byte counters = (tx=%d, rx=%d), want (%d, %d)",
				snap.TxBytes, snap.RxBytes, len(payload), len(payload))
		}

		if err := engine.Disconnect(ctx); err != nil {
			t.Fatalf("Disconnect failed: %v", err)
		}

		subMu.Lock()
		defer subMu.Unlock()
		if len(observedStates) < 3 ||
			observedStates[0] != StateConnecting ||
			observedStates[1] != StateConnected ||
			observedStates[len(observedStates)-1] != StateDisconnected {
			t.Fatalf("unexpected subscriber states: %v", observedStates)
		}
	})

	t.Run("keyboard_interactive_PAM_only_server_with_pre_banner", func(t *testing.T) {
		srv := startTestSSHServer(t, testServerOptions{
			hostSigner:         hostSigner,
			password:           "pam-secret",
			kbdInteractiveOnly: true,
			pamWithPreBanner:   true,
		})
		defer srv.Close()

		engine := NewClient()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := engine.Connect(ctx, ConnectConfig{
			ProfileID: "pam-only",
			Host:      srv.Host(),
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:     AuthPassword,
				Password: "pam-secret",
			},
			PinnedHostKey: pin,
		})
		if err != nil {
			t.Fatalf("Connect keyboard-interactive failed: %v", err)
		}
		conn, err := engine.DialContext(ctx, "tcp", echoAddr)
		if err != nil {
			t.Fatalf("DialContext via PAM session failed: %v", err)
		}
		assertEchoPayload(t, conn, []byte("pam-ok"))
		_ = conn.Close()
		_ = engine.Disconnect(ctx)
	})

	t.Run("pam_infinite_loop_stops_fast_as_non_retryable", func(t *testing.T) {
		srv := startTestSSHServer(t, testServerOptions{
			hostSigner:     hostSigner,
			pamLoopForever: true,
		})
		defer srv.Close()

		engine := NewClient()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := engine.Connect(ctx, ConnectConfig{
			ProfileID: "pam-loop",
			Host:      srv.Host(),
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:     AuthPassword,
				Password: "pw",
			},
			PinnedHostKey: pin,
		})
		var mapped *MappedError
		if !errors.As(err, &mapped) || mapped.Code != ERR_AUTH_FAILED || mapped.Retryable {
			t.Fatalf("expected non-retryable ERR_AUTH_FAILED, got %+v (%v)", mapped, err)
		}
	})

	t.Run("auth_key_unencrypted_ed25519_and_encrypted_ed25519_and_rsa", func(t *testing.T) {
		cases := []struct {
			name       string
			allowedPub ssh.PublicKey
			privPEM    string
			passphrase string
		}{
			{"ed25519_unencrypted", edPub, edUnencPEM, ""},
			{"ed25519_passphrase", edPub, edEncPEM, "key-pass-123"},
			{"rsa_passphrase", rsaPub, rsaEncPEM, "key-pass-123"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				srv := startTestSSHServer(t, testServerOptions{
					hostSigner:    hostSigner,
					allowedPubKey: tc.allowedPub,
				})
				defer srv.Close()

				engine := NewClient()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				err := engine.Connect(ctx, ConnectConfig{
					ProfileID: tc.name,
					Host:      srv.Host(),
					Port:      srv.Port(),
					Username:  "ali",
					Auth: AuthConfig{
						Type:          AuthKey,
						PrivateKey:    tc.privPEM,
						KeyPassphrase: tc.passphrase,
					},
					PinnedHostKey: pin,
				})
				if err != nil {
					t.Fatalf("Connect(%s) failed: %v", tc.name, err)
				}
				conn, err := engine.DialContext(ctx, "tcp", echoAddr)
				if err != nil {
					t.Fatalf("DialContext(%s) failed: %v", tc.name, err)
				}
				assertEchoPayload(t, conn, []byte("key-"+tc.name))
				_ = conn.Close()
				_ = engine.Disconnect(ctx)
			})
		}
	})

	t.Run("invalid_credentials_and_bad_passphrase_fail_fast_non_retryable", func(t *testing.T) {
		srv := startTestSSHServer(t, testServerOptions{
			hostSigner: hostSigner,
			password:   "correct-password",
		})
		defer srv.Close()

		engine := NewClient()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Wrong password -> ERR_AUTH_FAILED, Retryable == false, StateError.
		err := engine.Connect(ctx, ConnectConfig{
			ProfileID: "bad-pw",
			Host:      srv.Host(),
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:     AuthPassword,
				Password: "wrong-password",
			},
			PinnedHostKey: pin,
		})
		var mapped *MappedError
		if !errors.As(err, &mapped) || mapped.Code != ERR_AUTH_FAILED || mapped.Retryable {
			t.Fatalf("wrong password -> %+v (%v), want non-retryable ERR_AUTH_FAILED", mapped, err)
		}
		if got := engine.Snapshot().State; got != StateError {
			t.Fatalf("state = %q, want %q", got, StateError)
		}

		// Bad key passphrase MUST fail before dialing TCP!
		var dialCalled atomic.Bool
		engine.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCalled.Store(true)
			return nil, errors.New("should not dial TCP when key parse fails")
		}
		err = engine.Connect(ctx, ConnectConfig{
			ProfileID: "bad-passphrase",
			Host:      srv.Host(),
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:          AuthKey,
				PrivateKey:    edEncPEM,
				KeyPassphrase: "wrong-passphrase",
			},
			PinnedHostKey: pin,
		})
		if dialCalled.Load() {
			t.Fatal("dialTCP was called despite invalid key passphrase")
		}
		if !errors.As(err, &mapped) || mapped.Code != ERR_KEY_INVALID || mapped.Retryable {
			t.Fatalf("bad passphrase -> %+v (%v), want non-retryable ERR_KEY_INVALID", mapped, err)
		}
		if got := engine.Snapshot().State; got != StateError {
			t.Fatalf("state = %q, want %q", got, StateError)
		}
	})

	t.Run("prohibited_forwarding_channel_returns_ERR_FORWARD_DISABLED", func(t *testing.T) {
		srv := startTestSSHServer(t, testServerOptions{
			hostSigner:         hostSigner,
			password:           "pw",
			prohibitForwarding: true,
		})
		defer srv.Close()

		engine := NewClient()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := engine.Connect(ctx, ConnectConfig{
			ProfileID: "no-fwd",
			Host:      srv.Host(),
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:     AuthPassword,
				Password: "pw",
			},
			PinnedHostKey: pin,
		}); err != nil {
			t.Fatalf("Connect failed: %v", err)
		}
		defer engine.Disconnect(ctx)

		_, err := engine.DialContext(ctx, "tcp", echoAddr)
		var mapped *MappedError
		if !errors.As(err, &mapped) || mapped.Code != ERR_FORWARD_DISABLED || mapped.Retryable {
			t.Fatalf("DialContext -> %+v (%v), want non-retryable ERR_FORWARD_DISABLED", mapped, err)
		}
		if !strings.Contains(mapped.ActionHint, "AllowTcpForwarding") {
			t.Fatalf("ActionHint %q should mention AllowTcpForwarding", mapped.ActionHint)
		}
	})

	t.Run("disconnected_ops_and_connect_error_mappings", func(t *testing.T) {
		engine := NewClient()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		if _, err := engine.DialContext(ctx, "tcp", echoAddr); !errors.Is(err, ErrNotConnected) {
			t.Fatalf("DialContext when disconnected = %v, want ErrNotConnected", err)
		}
		if _, err := engine.MeasureRTT(ctx); !errors.Is(err, ErrNotConnected) {
			t.Fatalf("MeasureRTT when disconnected = %v, want ErrNotConnected", err)
		}

		// Closed local port -> ERR_CONN_REFUSED.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		closedPort := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()

		err = engine.Connect(ctx, ConnectConfig{
			ProfileID: "closed-port",
			Host:      "127.0.0.1",
			Port:      closedPort,
			Username:  "ali",
			Auth:      AuthConfig{Type: AuthPassword, Password: "pw"},
		})
		var mapped *MappedError
		if !errors.As(err, &mapped) || mapped.Code != ERR_CONN_REFUSED || !mapped.Retryable {
			t.Fatalf("closed port Connect -> %+v (%v), want retryable ERR_CONN_REFUSED", mapped, err)
		}

		// Immediate close before SSH banner -> mid-handshake EOF -> ERR_DPI_RESET.
		dropLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen drop: %v", err)
		}
		defer dropLn.Close()
		go func() {
			for {
				c, err := dropLn.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		dropPort := dropLn.Addr().(*net.TCPAddr).Port
		err = engine.Connect(ctx, ConnectConfig{
			ProfileID: "dpi-eof",
			Host:      "127.0.0.1",
			Port:      dropPort,
			Username:  "ali",
			Auth:      AuthConfig{Type: AuthPassword, Password: "pw"},
		})
		if !errors.As(err, &mapped) || mapped.Code != ERR_DPI_RESET || !mapped.Retryable {
			t.Fatalf("immediate handshake EOF Connect -> %+v (%v), want retryable ERR_DPI_RESET", mapped, err)
		}

		// Port 22 dial timeout -> ERR_PORT22_TIMEOUT.
		engine.dialTCP = func(dCtx context.Context, _, _ string) (net.Conn, error) {
			<-dCtx.Done()
			return nil, dCtx.Err()
		}
		err = engine.Connect(ctx, ConnectConfig{
			ProfileID:   "port22-timeout",
			Host:        "127.0.0.1",
			Port:        22,
			Username:    "ali",
			Auth:        AuthConfig{Type: AuthPassword, Password: "pw"},
			DialTimeout: 30 * time.Millisecond,
		})
		if !errors.As(err, &mapped) || mapped.Code != ERR_PORT22_TIMEOUT || !mapped.Retryable {
			t.Fatalf("port 22 timeout Connect -> %+v (%v), want retryable ERR_PORT22_TIMEOUT", mapped, err)
		}
	})
}

func TestClientDialHostPreservesLogicalHostForTOFUAndSnapshot(t *testing.T) {
	signerA := generateTestSSHSigner(t)
	signerB := generateTestSSHSigner(t)
	echoAddr := startEchoServer(t)

	srv := startTestSSHServer(t, testServerOptions{
		hostSigner: signerA,
		password:   "tun-secret",
	})
	defer srv.Close()

	const logicalHost = "pinned-vps.example.test"
	expectedDialAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.Port()))

	t.Run("dials_concrete_DialHost_while_TOFU_and_snapshot_use_logical_Host", func(t *testing.T) {
		engine := NewClient()
		realDialer := &net.Dialer{}

		var mu sync.Mutex
		var dialedAddrs []string
		engine.dialTCP = func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialedAddrs = append(dialedAddrs, addr)
			mu.Unlock()
			return realDialer.DialContext(ctx, network, addr)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Step 1: Unpinned connect fails with ERR_HOSTKEY_UNTRUSTED naming logicalHost.
		err := engine.Connect(ctx, ConnectConfig{
			ProfileID: "dialhost-tofu",
			Host:      logicalHost,
			DialHost:  "127.0.0.1",
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:     AuthPassword,
				Password: "tun-secret",
			},
		})
		var mapped *MappedError
		if !errors.As(err, &mapped) || mapped.Code != ERR_HOSTKEY_UNTRUSTED || mapped.Retryable {
			t.Fatalf("expected non-retryable ERR_HOSTKEY_UNTRUSTED, got %+v (%v)", mapped, err)
		}
		var untrusted *ErrHostKeyUntrusted
		if !errors.As(err, &untrusted) {
			t.Fatalf("expected *ErrHostKeyUntrusted in error chain, got %v", err)
		}
		if untrusted.Host != logicalHost || untrusted.Port != srv.Port() {
			t.Fatalf("ErrHostKeyUntrusted = (%q, %d), want (%q, %d)", untrusted.Host, untrusted.Port, logicalHost, srv.Port())
		}
		if !strings.Contains(mapped.Message, logicalHost) {
			t.Fatalf("MappedError.Message = %q, want logical host %q", mapped.Message, logicalHost)
		}

		snap := engine.Snapshot()
		if snap.Host != logicalHost || snap.Port != srv.Port() {
			t.Fatalf("Snapshot host/port = (%q, %d), want (%q, %d)", snap.Host, snap.Port, logicalHost, srv.Port())
		}
		if snap.HostKeyPrompt == nil || snap.HostKeyPrompt.Host != logicalHost {
			t.Fatalf("Snapshot.HostKeyPrompt = %+v, want Host=%q", snap.HostKeyPrompt, logicalHost)
		}

		// Step 2: Pin using the prompted host key and connect cleanly.
		pin := &HostKeyPin{
			Algorithm: snap.HostKeyPrompt.Algorithm,
			SHA256:    snap.HostKeyPrompt.SHA256,
		}
		if err := engine.Connect(ctx, ConnectConfig{
			ProfileID: "dialhost-tofu",
			Host:      logicalHost,
			DialHost:  "127.0.0.1",
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:     AuthPassword,
				Password: "tun-secret",
			},
			PinnedHostKey: pin,
		}); err != nil {
			t.Fatalf("Connect with DialHost + pinned key failed: %v", err)
		}

		snap = engine.Snapshot()
		if snap.State != StateConnected || snap.Host != logicalHost || snap.Port != srv.Port() {
			t.Fatalf("connected Snapshot = %+v, want StateConnected and Host=%q Port=%d", snap, logicalHost, srv.Port())
		}

		conn, err := engine.DialContext(ctx, "tcp", echoAddr)
		if err != nil {
			t.Fatalf("DialContext failed: %v", err)
		}
		assertEchoPayload(t, conn, []byte("dialhost-echo-ok"))
		_ = conn.Close()
		if err := engine.Disconnect(ctx); err != nil {
			t.Fatalf("Disconnect failed: %v", err)
		}

		// Step 3: Key rotation still reports ERR_HOSTKEY_MISMATCH for logicalHost.
		srv.SetHostSigner(signerB)
		err = engine.Connect(ctx, ConnectConfig{
			ProfileID: "dialhost-tofu",
			Host:      logicalHost,
			DialHost:  "127.0.0.1",
			Port:      srv.Port(),
			Username:  "ali",
			Auth: AuthConfig{
				Type:     AuthPassword,
				Password: "tun-secret",
			},
			PinnedHostKey: pin,
		})
		if !errors.As(err, &mapped) || mapped.Code != ERR_HOSTKEY_MISMATCH || mapped.Retryable {
			t.Fatalf("expected non-retryable ERR_HOSTKEY_MISMATCH, got %+v (%v)", mapped, err)
		}
		snap = engine.Snapshot()
		if snap.Host != logicalHost || snap.HostKeyMismatch == nil || snap.HostKeyMismatch.Host != logicalHost {
			t.Fatalf("mismatch Snapshot = %+v, want Host=%q", snap, logicalHost)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(dialedAddrs) != 3 {
			t.Fatalf("dialTCP call count = %d, want 3", len(dialedAddrs))
		}
		for i, addr := range dialedAddrs {
			if addr != expectedDialAddr {
				t.Fatalf("dialedAddrs[%d] = %q, want %q", i, addr, expectedDialAddr)
			}
		}
	})

	t.Run("validateConnectConfig_requires_Host_and_rejects_bad_DialHost_or_port", func(t *testing.T) {
		cases := []struct {
			name string
			cfg  ConnectConfig
		}{
			{
				name: "empty_host_with_dial_host",
				cfg: ConnectConfig{
					Host:     "",
					DialHost: "127.0.0.1",
					Port:     srv.Port(),
					Username: "ali",
					Auth:     AuthConfig{Type: AuthPassword, Password: "pw"},
				},
			},
			{
				name: "whitespace_only_dial_host",
				cfg: ConnectConfig{
					Host:     logicalHost,
					DialHost: "   ",
					Port:     srv.Port(),
					Username: "ali",
					Auth:     AuthConfig{Type: AuthPassword, Password: "pw"},
				},
			},
			{
				name: "leading_or_trailing_whitespace_dial_host",
				cfg: ConnectConfig{
					Host:     logicalHost,
					DialHost: "127.0.0.1 ",
					Port:     srv.Port(),
					Username: "ali",
					Auth:     AuthConfig{Type: AuthPassword, Password: "pw"},
				},
			},
			{
				name: "empty_port_suffix_in_dial_host",
				cfg: ConnectConfig{
					Host:     logicalHost,
					DialHost: "127.0.0.1:",
					Port:     srv.Port(),
					Username: "ali",
					Auth:     AuthConfig{Type: AuthPassword, Password: "pw"},
				},
			},
			{
				name: "embedded_port_in_dial_host",
				cfg: ConnectConfig{
					Host:     logicalHost,
					DialHost: "127.0.0.1:443",
					Port:     srv.Port(),
					Username: "ali",
					Auth:     AuthConfig{Type: AuthPassword, Password: "pw"},
				},
			},
			{
				name: "zero_port_with_dial_host",
				cfg: ConnectConfig{
					Host:     logicalHost,
					DialHost: "127.0.0.1",
					Port:     0,
					Username: "ali",
					Auth:     AuthConfig{Type: AuthPassword, Password: "pw"},
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				engine := NewClient()
				var dialCalled atomic.Bool
				engine.dialTCP = func(context.Context, string, string) (net.Conn, error) {
					dialCalled.Store(true)
					return nil, errors.New("should not dial on invalid config")
				}

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				err := engine.Connect(ctx, tc.cfg)
				if err == nil {
					t.Fatalf("expected validation error for %s", tc.name)
				}
				if dialCalled.Load() {
					t.Fatalf("dialTCP called despite invalid config %s", tc.name)
				}
				if got := engine.Snapshot().State; got != StateError {
					t.Fatalf("state = %q, want %q", got, StateError)
				}
			})
		}

		// Valid IPv6 DialHost (including :: shorthand) passes validation.
		if err := validateConnectConfig(ConnectConfig{
			Host:     logicalHost,
			DialHost: "2001:db8::",
			Port:     443,
			Username: "ali",
		}); err != nil {
			t.Fatalf("expected valid IPv6 DialHost to pass validation, got %v", err)
		}
	})
}

func TestClientDialControlInvokedAndFailureDoesNotLeak(t *testing.T) {
	hostSigner := generateTestSSHSigner(t)
	pin := &HostKeyPin{
		Algorithm: hostSigner.PublicKey().Type(),
		SHA256:    ssh.FingerprintSHA256(hostSigner.PublicKey()),
	}

	t.Run("invoked_with_tcp_and_target_address_before_ssh_handshake", func(t *testing.T) {
		srv := startTestSSHServer(t, testServerOptions{
			hostSigner: hostSigner,
			password:   "pw",
		})
		defer srv.Close()

		const logicalHost = "pinned-vps.example.test"
		wantTarget := net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.Port()))

		var controlCalls atomic.Int32
		var sawNetwork string
		var sawAddress string
		var sawRawConn atomic.Bool
		var sawServerIdleBeforeConnect atomic.Bool

		engine := NewClient()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := engine.Connect(ctx, ConnectConfig{
			ProfileID:     "dial-control-ok",
			Host:          logicalHost,
			DialHost:      "127.0.0.1",
			Port:          srv.Port(),
			Username:      "ali",
			Auth:          AuthConfig{Type: AuthPassword, Password: "pw"},
			PinnedHostKey: pin,
			DialControl: func(network, address string, c syscall.RawConn) error {
				controlCalls.Add(1)
				sawNetwork = network
				sawAddress = address
				sawRawConn.Store(c != nil)
				// net.Dialer invokes Control before connect(2), hence before SSH handshake.
				sawServerIdleBeforeConnect.Store(srv.ActiveRawConns() == 0)
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Connect with DialControl failed: %v", err)
		}
		defer engine.Disconnect(ctx)

		if got := controlCalls.Load(); got != 1 {
			t.Fatalf("DialControl calls = %d, want 1", got)
		}
		// net.Dialer normalizes "tcp" to "tcp4" (or "tcp6") when invoking Control.
		if sawNetwork != "tcp4" && sawNetwork != "tcp" {
			t.Fatalf("DialControl network = %q, want tcp4/tcp", sawNetwork)
		}
		if sawAddress != wantTarget {
			t.Fatalf("DialControl address = %q, want %q", sawAddress, wantTarget)
		}
		if !sawRawConn.Load() {
			t.Fatal("DialControl received nil syscall.RawConn")
		}
		if !sawServerIdleBeforeConnect.Load() {
			t.Fatal("expected DialControl to run before TCP connect / SSH handshake")
		}
		if got := engine.Snapshot().Host; got != logicalHost {
			t.Fatalf("Snapshot.Host = %q, want %q", got, logicalHost)
		}
	})

	t.Run("failing_DialControl_returns_mapped_error_without_goroutine_leak", func(t *testing.T) {
		srv := startTestSSHServer(t, testServerOptions{
			hostSigner: hostSigner,
			password:   "pw",
		})
		defer srv.Close()

		runtime.GC()
		time.Sleep(30 * time.Millisecond)
		baseline := runtime.NumGoroutine()

		controlErr := errors.New("mock socket bind error")
		var controlCalls atomic.Int32

		engine := NewClient()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := engine.Connect(ctx, ConnectConfig{
			ProfileID:     "dial-control-fail",
			Host:          "pinned-vps.example.test",
			DialHost:      "127.0.0.1",
			Port:          srv.Port(),
			Username:      "ali",
			Auth:          AuthConfig{Type: AuthPassword, Password: "pw"},
			PinnedHostKey: pin,
			DialControl: func(network, address string, c syscall.RawConn) error {
				controlCalls.Add(1)
				return controlErr
			},
		})
		var mapped *MappedError
		if !errors.As(err, &mapped) {
			t.Fatalf("expected *MappedError, got %T (%v)", err, err)
		}
		if mapped.Code != ERR_NETWORK || !mapped.Retryable {
			t.Fatalf("mapped = %+v, want retryable ERR_NETWORK", mapped)
		}
		if !errors.Is(err, controlErr) {
			t.Fatalf("expected error chain to contain %v, got %v", controlErr, err)
		}
		if got := controlCalls.Load(); got != 1 {
			t.Fatalf("DialControl calls = %d, want 1", got)
		}
		if got := srv.ActiveRawConns(); got != 0 {
			t.Fatalf("server ActiveRawConns = %d, want 0 when DialControl fails", got)
		}
		snap := engine.Snapshot()
		if snap.State != StateError || snap.LastError == nil {
			t.Fatalf("Snapshot = %+v, want StateError with LastError", snap)
		}

		settleGoroutines(t, baseline, 1)
	})
}
