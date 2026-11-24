package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/AlirezaDelkhahi/tunssh/internal/crypto"
	"github.com/AlirezaDelkhahi/tunssh/internal/profile"
	"github.com/AlirezaDelkhahi/tunssh/internal/proxy"
	"github.com/AlirezaDelkhahi/tunssh/internal/recovery"
	"github.com/AlirezaDelkhahi/tunssh/internal/splitroute"
	"github.com/AlirezaDelkhahi/tunssh/internal/sshclient"
	"github.com/AlirezaDelkhahi/tunssh/internal/sysproxy"
	"github.com/AlirezaDelkhahi/tunssh/internal/tun"
)

type recordedEvent struct {
	name string
	data any
}

type recordingEmitter struct {
	mu     sync.Mutex
	events []recordedEvent
}

func (e *recordingEmitter) Emit(eventName string, data any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, recordedEvent{name: eventName, data: data})
}

func (e *recordingEmitter) EventsNamed(name string) []recordedEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []recordedEvent
	for _, ev := range e.events {
		if ev.name == name {
			out = append(out, ev)
		}
	}
	return out
}

func (e *recordingEmitter) Count(name string) int {
	return len(e.EventsNamed(name))
}

func (e *recordingEmitter) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = nil
}

type mockSysProxy struct {
	mu             sync.Mutex
	caps           sysproxy.ProxyCapabilities
	snapshot       sysproxy.ProxySnapshot
	enableCalls    int
	restoreCalls   int
	enabledConfigs []sysproxy.ProxyApplyConfig
	restoredSnaps  []sysproxy.ProxySnapshot
	captureErr     error
	enableErr      error
	restoreErr     error
	onEnable       func()
}

func newMockSysProxy() *mockSysProxy {
	return &mockSysProxy{
		caps: sysproxy.ProxyCapabilities{
			AutoSupported: true,
			DesktopEnv:    "gnome",
		},
		snapshot: sysproxy.ProxySnapshot{
			Platform: "linux",
			LinuxDE:  "gnome",
			LinuxPrevValues: map[string]string{
				"org.gnome.system.proxy/mode": "'none'",
			},
		},
	}
}

func (m *mockSysProxy) Capabilities() sysproxy.ProxyCapabilities {
	return m.caps
}

func (m *mockSysProxy) CaptureSnapshot(ctx context.Context) (sysproxy.ProxySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return sysproxy.ProxySnapshot{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.captureErr != nil {
		return sysproxy.ProxySnapshot{}, m.captureErr
	}
	return m.snapshot, nil
}

func (m *mockSysProxy) Enable(ctx context.Context, cfg sysproxy.ProxyApplyConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	hook := m.onEnable
	err := m.enableErr
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.enableCalls++
	m.enabledConfigs = append(m.enabledConfigs, cfg)
	m.mu.Unlock()
	return nil
}

func (m *mockSysProxy) Restore(ctx context.Context, snap sysproxy.ProxySnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.restoreErr != nil {
		return m.restoreErr
	}
	m.restoreCalls++
	m.restoredSnaps = append(m.restoredSnaps, snap)
	return nil
}

func (m *mockSysProxy) EnvSnippet(socksPort, httpPort int) string {
	return sysproxy.FormatEnvSnippet(socksPort, httpPort)
}

func (m *mockSysProxy) Stats() (enableCalls int, restoreCalls int, enabled []sysproxy.ProxyApplyConfig, restored []sysproxy.ProxySnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enableCalls, m.restoreCalls, append([]sysproxy.ProxyApplyConfig(nil), m.enabledConfigs...), append([]sysproxy.ProxySnapshot(nil), m.restoredSnaps...)
}

type inMemorySSHServer struct {
	mu           sync.Mutex
	hostSigner   ssh.Signer
	expectedUser string
	password     string
	ln           net.Listener
	host         string
	port         int
	wg           sync.WaitGroup
	conns        []net.Conn
	closed       atomic.Bool
}

func generateTestEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer
}

func startInMemoryPAMSSHServer(t *testing.T, user, password string, signer ssh.Signer) *inMemorySSHServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen in-memory ssh server: %v", err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	srv := &inMemorySSHServer{
		hostSigner:   signer,
		expectedUser: user,
		password:     password,
		ln:           ln,
		host:         "127.0.0.1",
		port:         tcpAddr.Port,
	}
	srv.wg.Add(1)
	go srv.serve()
	t.Cleanup(srv.Close)
	return srv
}

func (s *inMemorySSHServer) SetHostSigner(signer ssh.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostSigner = signer
}

func (s *inMemorySSHServer) Close() {
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

func (s *inMemorySSHServer) serve() {
	defer s.wg.Done()
	for {
		rawConn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, rawConn)
		s.mu.Unlock()

		s.wg.Add(1)
		go s.handleConn(rawConn)
	}
}

func (s *inMemorySSHServer) handleConn(rawConn net.Conn) {
	defer s.wg.Done()
	defer rawConn.Close()

	s.mu.Lock()
	signer := s.hostSigner
	expectedUser := s.expectedUser
	password := s.password
	s.mu.Unlock()

	cfg := &ssh.ServerConfig{
		// Explicitly omit PasswordCallback so PAM keyboard-interactive is exercised end-to-end.
		KeyboardInteractiveCallback: func(meta ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if meta.User() != expectedUser {
				return nil, errors.New("unknown user")
			}
			// Pre-auth empty PAM banner followed by password prompt.
			preAns, err := client("PAM Banner", "Welcome", nil, nil)
			if err != nil || len(preAns) != 0 {
				return nil, errors.New("pam pre-auth banner failed")
			}
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != password {
				return nil, errors.New("invalid pam password")
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(signer)

	sConn, chans, reqs, err := ssh.NewServerConn(rawConn, cfg)
	if err != nil {
		return
	}
	defer sConn.Close()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(req.Type == "keepalive@openssh.com", nil)
			}
		}
	}()

	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel")
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

		dialHost := msg.DestAddr
		if dialHost == "remote-only.internal" {
			dialHost = "127.0.0.1"
		}
		targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(dialHost, strconv.Itoa(int(msg.DestPort))), 3*time.Second)
		if err != nil {
			_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}

		ch, chReqs, err := newChan.Accept()
		if err != nil {
			_ = targetConn.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer ch.Close()
			defer targetConn.Close()
			var relayWg sync.WaitGroup
			relayWg.Add(2)
			go func() {
				defer relayWg.Done()
				_, _ = io.Copy(targetConn, ch)
				if cw, ok := targetConn.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
			}()
			go func() {
				defer relayWg.Done()
				_, _ = io.Copy(ch, targetConn)
				_ = ch.CloseWrite()
			}()
			relayWg.Wait()
		}()
	}
}

func startLocalEchoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func socks5RoundTripDomain(t *testing.T, proxyAddr, domain string, port int, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting: VER=5, NMETHODS=1, NO-AUTH=0x00
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write socks5 greeting: %v", err)
	}
	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		t.Fatalf("read socks5 method reply: %v", err)
	}
	if methodResp != [2]byte{0x05, 0x00} {
		t.Fatalf("unexpected socks5 method reply: %v", methodResp)
	}

	// CONNECT ATYP=0x03 (domain)
	req := make([]byte, 0, 7+len(domain))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	req = append(req, domain...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	req = append(req, portBuf[:]...)

	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write socks5 connect: %v", err)
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read socks5 connect reply hdr: %v", err)
	}
	if hdr[1] != 0x00 {
		t.Fatalf("socks5 connect failed rep=%d", hdr[1])
	}
	switch hdr[3] {
	case 0x01:
		var rest [6]byte
		_, _ = io.ReadFull(conn, rest[:])
	case 0x04:
		var rest [18]byte
		_, _ = io.ReadFull(conn, rest[:])
	case 0x03:
		var ln [1]byte
		_, _ = io.ReadFull(conn, ln[:])
		rest := make([]byte, int(ln[0])+2)
		_, _ = io.ReadFull(conn, rest)
	}

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write socks5 payload: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read socks5 echoed payload: %v", err)
	}
	return got
}

func httpConnectRoundTrip(t *testing.T, proxyAddr, target string, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial HTTP proxy %s: %v", proxyAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	reqStr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write HTTP CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read HTTP CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP CONNECT status = %d, want 200", resp.StatusCode)
	}

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write HTTP CONNECT payload: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read HTTP CONNECT echoed payload: %v", err)
	}
	return got
}

type appHarness struct {
	dir        string
	profiles   *profile.FileStore
	secrets    *profile.EncryptedFileSecretStore
	engine     *sshclient.Client
	sysProxy   *mockSysProxy
	recStore   *recovery.FileRecoveryStore
	restorer   *recovery.Restorer
	emitter    *recordingEmitter
	scrubber   *SecretScrubber
	logBuf     *LogBuffer
	stderrBuf  *bytes.Buffer
	stderrMu   sync.Mutex
	logger     *slog.Logger
	svc        *AppService
	filePicker func(context.Context) (string, error)
}

type lockedBuffer struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newAppHarness(t *testing.T, statsInterval time.Duration) *appHarness {
	t.Helper()
	dir := t.TempDir()

	profStore, err := profile.NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	secStore := profile.NewEncryptedFileSecretStore(dir)
	recStore, err := recovery.NewFileRecoveryStore(dir)
	if err != nil {
		t.Fatalf("NewFileRecoveryStore: %v", err)
	}
	sysProx := newMockSysProxy()
	restorer := recovery.NewRestorer(recStore, sysProx)
	engine := sshclient.NewClient()
	emitter := &recordingEmitter{}
	scrubber := NewSecretScrubber()
	logBuf := NewLogBuffer(DefaultLogBufferCapacity)

	h := &appHarness{
		dir:       dir,
		profiles:  profStore,
		secrets:   secStore,
		engine:    engine,
		sysProxy:  sysProx,
		recStore:  recStore,
		restorer:  restorer,
		emitter:   emitter,
		scrubber:  scrubber,
		logBuf:    logBuf,
		stderrBuf: &bytes.Buffer{},
	}

	lw := &lockedBuffer{mu: &h.stderrMu, buf: h.stderrBuf}
	downstream := slog.NewTextHandler(lw, &slog.HandlerOptions{Level: slog.LevelDebug})
	handler := NewRedactingHandler(downstream, scrubber, logBuf, func(entry LogEntryDTO) {
		emitter.Emit("tunnel:log", entry)
	})
	h.logger = slog.New(handler)

	svc, err := NewAppService(Config{
		Profiles: profStore,
		Secrets:  secStore,
		Engine:   engine,
		ProxyConfig: proxy.Config{
			SOCKSAddr:        "127.0.0.1:0",
			HTTPAddr:         "127.0.0.1:0",
			HandshakeTimeout: 3 * time.Second,
		},
		SysProxy:      sysProx,
		Restorer:      restorer,
		Emitter:       emitter,
		Scrubber:      scrubber,
		LogBuffer:     logBuf,
		Logger:        h.logger,
		StatsInterval: statsInterval,
		FilePicker: func(ctx context.Context) (string, error) {
			if h.filePicker != nil {
				return h.filePicker(ctx)
			}
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("NewAppService: %v", err)
	}
	h.svc = svc
	t.Cleanup(func() {
		svc.Shutdown(context.Background())
	})
	return h
}

func TestAppService_Milestone1EndToEnd(t *testing.T) {
	h := newAppHarness(t, 50*time.Millisecond)
	ctx := context.Background()
	h.svc.Startup(ctx)

	const (
		vaultPass   = "VaultUnlock!Secret#1"
		sshUser     = "tunuser"
		sshPass     = "P@M-SSH-Secret-9911!"
		sharePass   = "ShareLink!Pass#443"
		echoPayload = "hello-through-real-ssh-socks5h-and-http-connect!"
	)

	echoPort := startLocalEchoServer(t)
	hostSigner := generateTestEd25519Signer(t)
	expectedAlg := hostSigner.PublicKey().Type()
	expectedFP := ssh.FingerprintSHA256(hostSigner.PublicKey())
	sshSrv := startInMemoryPAMSSHServer(t, sshUser, sshPass, hostSigner)

	// 1. Vault locked check -> UnlockVault succeeds.
	bootLocked, err := h.svc.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState (locked): %v", err)
	}
	if bootLocked.VaultBackend != "encrypted-file" || !bootLocked.VaultLocked {
		t.Fatalf("expected locked encrypted-file vault, got backend=%q locked=%v", bootLocked.VaultBackend, bootLocked.VaultLocked)
	}
	if bootLocked.Milestone != 1 || bootLocked.TUNEnabled {
		t.Fatalf("expected Milestone=1, TUNEnabled=false, got %+v", bootLocked)
	}

	if err := h.svc.UnlockVault(vaultPass); err != nil {
		t.Fatalf("UnlockVault: %v", err)
	}
	bootUnlocked, err := h.svc.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState (unlocked): %v", err)
	}
	if bootUnlocked.VaultLocked {
		t.Fatalf("expected VaultLocked == false after UnlockVault")
	}

	// Save password profile (tested before and after Connect).
	savedProf, err := h.svc.SaveProfile(SaveProfileRequest{
		Name:          "M1-PAM-VPS",
		Host:          sshSrv.host,
		Port:          sshSrv.port,
		Username:      sshUser,
		AuthType:      string(profile.AuthPassword),
		BypassIranLAN: true,
		PreferredMode: string(profile.ModeProxy),
		Password:      sshPass,
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	if !savedProf.HasSecret || savedProf.HasKeyPassphrase || savedProf.PinnedHostKey != nil {
		t.Fatalf("unexpected initial ProfileView: %+v", savedProf)
	}

	// Also verify Connect fails with ErrVaultLocked when locked on a fresh locked store.
	h.secrets.Lock()
	if err := h.svc.Connect(savedProf.ID, string(profile.ModeProxy)); !errors.Is(err, profile.ErrVaultLocked) {
		t.Fatalf("Connect while locked = %v, want ErrVaultLocked", err)
	}
	if err := h.svc.UnlockVault(vaultPass); err != nil {
		t.Fatalf("re-UnlockVault: %v", err)
	}

	// 2. First Connect triggers TOFU ErrHostKeyUntrusted + "tunnel:hostkey_prompt" with ZERO OS proxy mutation.
	err = h.svc.Connect(savedProf.ID, string(profile.ModeProxy))
	if err == nil {
		t.Fatalf("first Connect without pinned host key unexpectedly succeeded")
	}
	var untrusted *sshclient.ErrHostKeyUntrusted
	if !errors.As(err, &untrusted) {
		t.Fatalf("expected ErrHostKeyUntrusted, got %v", err)
	}

	prompts := h.emitter.EventsNamed("tunnel:hostkey_prompt")
	if len(prompts) != 1 {
		t.Fatalf("hostkey_prompt count = %d, want 1", len(prompts))
	}
	promptDTO := prompts[0].data.(HostKeyPromptDTO)
	if promptDTO.ProfileID != savedProf.ID || promptDTO.IsMismatch ||
		promptDTO.Algorithm != expectedAlg || promptDTO.SHA256 != expectedFP {
		t.Fatalf("unexpected HostKeyPromptDTO: %+v (want %s %s)", promptDTO, expectedAlg, expectedFP)
	}

	enableCalls, _, _, _ := h.sysProxy.Stats()
	if enableCalls != 0 {
		t.Fatalf("OS proxy Enable called %d times on TOFU error, want 0", enableCalls)
	}
	if st, err := h.recStore.Load(); err != nil {
		t.Fatalf("recStore.Load: %v", err)
	} else if st != nil && st.Dirty {
		t.Fatalf("recovery_state.json marked dirty on failed TOFU connect")
	}

	// 3. TrustHostKeyAndConnect persists PinnedHostKey, connects SSH via PAM, starts SOCKS5 + HTTP, writes dirty recovery, enables OS proxy.
	if err := h.svc.TrustHostKeyAndConnect(savedProf.ID, promptDTO.Algorithm, promptDTO.SHA256); err != nil {
		t.Fatalf("TrustHostKeyAndConnect: %v", err)
	}

	persistedProf, err := h.profiles.Get(ctx, savedProf.ID)
	if err != nil {
		t.Fatalf("profiles.Get: %v", err)
	}
	if persistedProf.PinnedHostKey == nil || persistedProf.PinnedHostKey.SHA256 != expectedFP {
		t.Fatalf("PinnedHostKey not persisted: %+v", persistedProf.PinnedHostKey)
	}

	recState, err := h.recStore.Load()
	if err != nil || recState == nil || !recState.Dirty || recState.Mode != recovery.RecoveryModeProxy {
		t.Fatalf("expected dirty proxy recovery_state.json, got %+v (err=%v)", recState, err)
	}

	enableCalls, _, enabledCfgs, _ := h.sysProxy.Stats()
	if enableCalls != 1 {
		t.Fatalf("OS proxy Enable calls = %d, want 1", enableCalls)
	}

	bootConn, err := h.svc.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState (connected): %v", err)
	}
	if bootConn.Status.State != string(sshclient.StateConnected) {
		t.Fatalf("status.State = %q, want connected", bootConn.Status.State)
	}
	if bootConn.Status.SOCKSPort <= 0 || bootConn.Status.HTTPPort <= 0 {
		t.Fatalf("expected bound ephemeral ports > 0, got socks=%d http=%d", bootConn.Status.SOCKSPort, bootConn.Status.HTTPPort)
	}
	if enabledCfgs[0].SOCKSPort != bootConn.Status.SOCKSPort || enabledCfgs[0].HTTPPort != bootConn.Status.HTTPPort || !enabledCfgs[0].BypassIranLAN {
		t.Fatalf("enabled OS proxy config mismatch: %+v vs ports (%d,%d)", enabledCfgs[0], bootConn.Status.SOCKSPort, bootConn.Status.HTTPPort)
	}

	// 4. Real payload round-trip through BOTH SOCKS5 (ATYP=0x03 remote-only.internal) AND HTTP CONNECT through SSH to local echo server.
	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(bootConn.Status.SOCKSPort))
	httpAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(bootConn.Status.HTTPPort))

	socksReply := socks5RoundTripDomain(t, socksAddr, "remote-only.internal", echoPort, []byte(echoPayload+"-socks5"))
	if string(socksReply) != echoPayload+"-socks5" {
		t.Fatalf("SOCKS5 round-trip = %q, want %q", string(socksReply), echoPayload+"-socks5")
	}

	httpTarget := net.JoinHostPort("remote-only.internal", strconv.Itoa(echoPort))
	httpReply := httpConnectRoundTrip(t, httpAddr, httpTarget, []byte(echoPayload+"-http"))
	if string(httpReply) != echoPayload+"-http" {
		t.Fatalf("HTTP CONNECT round-trip = %q, want %q", string(httpReply), echoPayload+"-http")
	}

	bootAfterIO, err := h.svc.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState after IO: %v", err)
	}
	if bootAfterIO.Status.RxBytes == 0 || bootAfterIO.Status.TxBytes == 0 {
		t.Fatalf("expected nonzero RxBytes/TxBytes, got rx=%d tx=%d", bootAfterIO.Status.RxBytes, bootAfterIO.Status.TxBytes)
	}

	// Wait briefly for stats ticker to emit tunnel:stats at least once.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if h.emitter.Count("tunnel:stats") > 0 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if h.emitter.Count("tunnel:stats") == 0 {
		t.Fatalf("expected at least one tunnel:stats emission")
	}

	// 5. Connect(id, "tun") rejected cleanly (Milestone 2 boundary).
	if err := h.svc.Connect(savedProf.ID, string(profile.ModeTUN)); err == nil || !strings.Contains(err.Error(), "Milestone 2") {
		t.Fatalf("Connect(tun) = %v, want Milestone 2 rejection error", err)
	}

	// Export encrypted share link now to test both zero-secret-leak & step 9 import.
	shareLink, err := h.svc.ExportShareLink(savedProf.ID, sharePass, false)
	if err != nil {
		t.Fatalf("ExportShareLink: %v", err)
	}
	if !strings.HasPrefix(shareLink, crypto.ShareLinkPrefix) {
		t.Fatalf("unexpected shareLink prefix: %q", shareLink)
	}

	// Log something intentionally containing share link and password to verify redaction end-to-end.
	h.logger.Warn("diagnostic leak check", "bad_link", shareLink, "bad_pw", sshPass)

	// 6. Verify profiles.json, recovery_state.json, LogBuffer, and stderr logs contain ZERO secrets.
	profilesRaw, err := os.ReadFile(filepath.Join(h.dir, "profiles.json"))
	if err != nil {
		t.Fatalf("read profiles.json: %v", err)
	}
	recRaw, err := os.ReadFile(h.recStore.Path())
	if err != nil {
		t.Fatalf("read recovery_state.json: %v", err)
	}
	allText := []string{
		string(profilesRaw),
		string(recRaw),
		h.svc.ExportRedactedLogs(),
		(&lockedBuffer{mu: &h.stderrMu, buf: h.stderrBuf}).String(),
	}
	for _, secret := range []string{sshPass, vaultPass, sharePass, shareLink, strings.TrimPrefix(shareLink, crypto.ShareLinkPrefix)} {
		for idx, txt := range allText {
			if strings.Contains(txt, secret) {
				t.Fatalf("artifact #%d leaked secret %q:\n%s", idx, secret, txt)
			}
		}
	}

	// 7. Disconnect stops proxy, restores OS proxy, marks recovery_state.json clean.
	if err := h.svc.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	_, restoreCalls, _, restoredSnaps := h.sysProxy.Stats()
	if restoreCalls != 1 {
		t.Fatalf("OS proxy Restore calls = %d, want 1", restoreCalls)
	}
	if restoredSnaps[0].LinuxPrevValues["org.gnome.system.proxy/mode"] != "'none'" {
		t.Fatalf("restored snapshot mismatch: %+v", restoredSnaps[0])
	}
	recAfterDisconn, err := h.recStore.Load()
	if err != nil || recAfterDisconn == nil || recAfterDisconn.Dirty {
		t.Fatalf("expected recovery_state.json dirty=false after Disconnect, got %+v (err=%v)", recAfterDisconn, err)
	}
	if st, _ := h.svc.GetBootstrapState(); st.Status.State != string(sshclient.StateDisconnected) {
		t.Fatalf("expected disconnected state, got %q", st.Status.State)
	}
	// Verify proxy listener ports actually stopped accepting connections.
	if conn, err := net.DialTimeout("tcp", socksAddr, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatalf("SOCKS5 port %s still listening after Disconnect", socksAddr)
	}

	// 8. Simulated crash (dirty: true with stale PID) auto-recovers OS proxy on Startup and emits "tunnel:recovery".
	h.emitter.Reset()
	crashSnap := h.sysProxy.snapshot
	if err := h.recStore.SaveDirty(recovery.RecoveryState{
		Mode:          recovery.RecoveryModeProxy,
		PID:           os.Getpid() + 50000,
		ProxySnapshot: &crashSnap,
	}); err != nil {
		t.Fatalf("SaveDirty simulated crash: %v", err)
	}

	h.svc.Startup(ctx)
	recEvents := h.emitter.EventsNamed("tunnel:recovery")
	if len(recEvents) != 1 {
		t.Fatalf("tunnel:recovery event count = %d, want 1", len(recEvents))
	}
	recDTO := recEvents[0].data.(StartupRecoveryDTO)
	if !recDTO.Recovered || recDTO.Mode != recovery.RecoveryModeProxy || recDTO.NeedsElevation {
		t.Fatalf("unexpected StartupRecoveryDTO: %+v", recDTO)
	}
	_, restoreCallsAfterBoot, _, _ := h.sysProxy.Stats()
	if restoreCallsAfterBoot != 2 {
		t.Fatalf("expected Restore called again on crash recovery, got %d", restoreCallsAfterBoot)
	}
	if recAfterBoot, err := h.recStore.Load(); err != nil || recAfterBoot.Dirty {
		t.Fatalf("expected recovery_state.json clean after startup recovery, got %+v (err=%v)", recAfterBoot, err)
	}

	// 9. Encrypted sshtun://v1/... export -> import creates profile with pinned host key and connects immediately without TOFU prompt!
	meta, err := h.svc.InspectShareLink(shareLink)
	if err != nil {
		t.Fatalf("InspectShareLink: %v", err)
	}
	if meta.Version != 1 || meta.Mode != crypto.ModeEncrypted || meta.HasHostKey {
		t.Fatalf("unexpected ShareInspectDTO: %+v", meta)
	}

	importedProf, err := h.svc.ImportShareLink(shareLink, sharePass, false)
	if err != nil {
		t.Fatalf("ImportShareLink: %v", err)
	}
	if importedProf.PinnedHostKey == nil || importedProf.PinnedHostKey.SHA256 != expectedFP {
		t.Fatalf("imported profile missing pinned host key: %+v", importedProf)
	}

	h.emitter.Reset()
	if err := h.svc.Connect(importedProf.ID, string(profile.ModeProxy)); err != nil {
		t.Fatalf("Connect imported profile without TOFU prompt failed: %v", err)
	}
	if h.emitter.Count("tunnel:hostkey_prompt") != 0 {
		t.Fatalf("expected zero TOFU prompts for imported profile with pinned host key")
	}
	if err := h.svc.Disconnect(); err != nil {
		t.Fatalf("Disconnect imported profile: %v", err)
	}
}

func TestAppService_KeepExistingSecretsHostKeyMismatchAndBypassToggle(t *testing.T) {
	h := newAppHarness(t, time.Second)
	ctx := context.Background()
	h.svc.Startup(ctx)
	if err := h.svc.UnlockVault("VaultPass!Test1"); err != nil {
		t.Fatalf("UnlockVault: %v", err)
	}

	signer1 := generateTestEd25519Signer(t)
	signer2 := generateTestEd25519Signer(t)
	sshSrv := startInMemoryPAMSSHServer(t, "alice", "SecretPass!42", signer1)

	created, err := h.svc.SaveProfile(SaveProfileRequest{
		Name:          "Alpha",
		Host:          sshSrv.host,
		Port:          sshSrv.port,
		Username:      "alice",
		AuthType:      string(profile.AuthPassword),
		BypassIranLAN: false,
		PreferredMode: string(profile.ModeProxy),
		Password:      "SecretPass!42",
	})
	if err != nil {
		t.Fatalf("SaveProfile create: %v", err)
	}

	// Edit profile keeping existing secrets.
	edited, err := h.svc.SaveProfile(SaveProfileRequest{
		ID:                  created.ID,
		Name:                "Alpha-Renamed",
		Host:                sshSrv.host,
		Port:                sshSrv.port,
		Username:            "alice",
		AuthType:            string(profile.AuthPassword),
		BypassIranLAN:       false,
		PreferredMode:       string(profile.ModeProxy),
		KeepExistingSecrets: true,
	})
	if err != nil {
		t.Fatalf("SaveProfile edit keep secrets: %v", err)
	}
	if !edited.HasSecret || edited.Name != "Alpha-Renamed" {
		t.Fatalf("expected preserved secret and updated name, got %+v", edited)
	}

	// Pin signer1 and connect.
	if err := h.svc.TrustHostKeyAndConnect(edited.ID, signer1.PublicKey().Type(), ssh.FingerprintSHA256(signer1.PublicKey())); err != nil {
		t.Fatalf("TrustHostKeyAndConnect: %v", err)
	}

	// Toggle BypassIranLAN while connected -> updates profile AND calls sysProxy.Enable without corrupting recovery snapshot.
	updatedBypass, err := h.svc.SetBypassIranLAN(edited.ID, true)
	if err != nil {
		t.Fatalf("SetBypassIranLAN while connected: %v", err)
	}
	if !updatedBypass.BypassIranLAN {
		t.Fatalf("expected BypassIranLAN == true")
	}
	_, _, enabledCfgs, _ := h.sysProxy.Stats()
	if len(enabledCfgs) != 2 || !enabledCfgs[1].BypassIranLAN {
		t.Fatalf("expected sysProxy.Enable called with BypassIranLAN=true, got %+v", enabledCfgs)
	}
	if rec, err := h.recStore.Load(); err != nil || rec.ProxySnapshot == nil || rec.ProxySnapshot.LinuxPrevValues["org.gnome.system.proxy/mode"] != "'none'" {
		t.Fatalf("SetBypassIranLAN overwrote original pre-tunnel recovery snapshot: %+v (err=%v)", rec, err)
	}

	if err := h.svc.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	// Rotate server host key -> triggers mismatch -> ForgetHostKey -> TrustHostKeyAndConnect succeeds.
	sshSrv.SetHostSigner(signer2)
	h.emitter.Reset()
	err = h.svc.Connect(edited.ID, string(profile.ModeProxy))
	var mismatch *sshclient.ErrHostKeyMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected ErrHostKeyMismatch after server key rotation, got %v", err)
	}
	prompts := h.emitter.EventsNamed("tunnel:hostkey_prompt")
	if len(prompts) != 1 {
		t.Fatalf("expected 1 mismatch hostkey_prompt, got %d", len(prompts))
	}
	pDTO := prompts[0].data.(HostKeyPromptDTO)
	if !pDTO.IsMismatch || pDTO.ExpectedSHA256 != ssh.FingerprintSHA256(signer1.PublicKey()) || pDTO.SHA256 != ssh.FingerprintSHA256(signer2.PublicKey()) {
		t.Fatalf("unexpected mismatch HostKeyPromptDTO: %+v", pDTO)
	}

	// ForgetHostKey clears pinned key, then TrustHostKeyAndConnect pins signer2 and connects.
	cleared, err := h.svc.ForgetHostKey(edited.ID)
	if err != nil {
		t.Fatalf("ForgetHostKey: %v", err)
	}
	if cleared.PinnedHostKey != nil {
		t.Fatalf("expected nil PinnedHostKey after ForgetHostKey")
	}
	if err := h.svc.TrustHostKeyAndConnect(edited.ID, signer2.PublicKey().Type(), ssh.FingerprintSHA256(signer2.PublicKey())); err != nil {
		t.Fatalf("TrustHostKeyAndConnect with new key: %v", err)
	}

	// Panic RestoreNetwork disconnects and marks recovery clean.
	if err := h.svc.RestoreNetwork(); err != nil {
		t.Fatalf("RestoreNetwork: %v", err)
	}
	if st, _ := h.svc.GetBootstrapState(); st.Status.State != string(sshclient.StateDisconnected) {
		t.Fatalf("expected disconnected after RestoreNetwork, got %q", st.Status.State)
	}
	if rec, _ := h.recStore.Load(); rec != nil && rec.Dirty {
		t.Fatalf("expected clean recovery state after RestoreNetwork")
	}
}

func TestAppService_ConcurrentDisconnectCancelsSlowConnect(t *testing.T) {
	h := newAppHarness(t, time.Second)
	ctx := context.Background()
	h.svc.Startup(ctx)
	if err := h.svc.UnlockVault("VaultPass!Test2"); err != nil {
		t.Fatalf("UnlockVault: %v", err)
	}

	// Listener that accepts TCP connections and stalls SSH banner forever so Connect blocks in handshake.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() {
		close(accepted)
		for c := range accepted {
			_ = c.Close()
		}
	})

	tcpAddr := ln.Addr().(*net.TCPAddr)
	prof, err := h.svc.SaveProfile(SaveProfileRequest{
		Name:          "SlowHost",
		Host:          "127.0.0.1",
		Port:          tcpAddr.Port,
		Username:      "u",
		AuthType:      string(profile.AuthPassword),
		PreferredMode: string(profile.ModeProxy),
		Password:      "pw123",
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}

	connectErrCh := make(chan error, 1)
	go func() {
		connectErrCh <- h.svc.Connect(prof.ID, string(profile.ModeProxy))
	}()

	// Wait for TCP connection to reach the blackhole listener.
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for Connect dial")
	}

	// Disconnect must cancel in-flight Connect promptly without deadlocking.
	disconnDone := make(chan error, 1)
	go func() {
		disconnDone <- h.svc.Disconnect()
	}()

	select {
	case err := <-disconnDone:
		if err != nil {
			t.Fatalf("Disconnect failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Disconnect hung waiting on slow Connect")
	}

	select {
	case err := <-connectErrCh:
		if err == nil {
			t.Fatalf("expected canceled Connect to return error")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Connect did not abort promptly on Disconnect")
	}

	enableCalls, _, _, _ := h.sysProxy.Stats()
	if enableCalls != 0 {
		t.Fatalf("OS proxy should not be enabled after canceled Connect, got %d", enableCalls)
	}
}

func TestAppService_UtilitiesAndShareLinkPlainGating(t *testing.T) {
	h := newAppHarness(t, time.Second)
	ctx := context.Background()
	h.svc.Startup(ctx)
	if err := h.svc.UnlockVault("VaultPass!Test3"); err != nil {
		t.Fatalf("UnlockVault: %v", err)
	}

	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	const samplePEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAtestkeydata\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(keyFile, []byte(samplePEM), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	h.filePicker = func(context.Context) (string, error) {
		return keyFile, nil
	}

	picked, err := h.svc.PickPrivateKeyFile()
	if err != nil {
		t.Fatalf("PickPrivateKeyFile: %v", err)
	}
	if picked != samplePEM {
		t.Fatalf("PickPrivateKeyFile = %q, want %q", picked, samplePEM)
	}

	prof, err := h.svc.SaveProfile(SaveProfileRequest{
		Name:          "PlainShareTest",
		Host:          "vps.example.com",
		Port:          443,
		Username:      "friend",
		AuthType:      string(profile.AuthKey),
		BypassIranLAN: true,
		PreferredMode: string(profile.ModeProxy),
		PrivateKey:    samplePEM,
		KeyPassphrase: "kp1",
	})
	if err != nil {
		t.Fatalf("SaveProfile key: %v", err)
	}
	if !prof.HasSecret || !prof.HasKeyPassphrase {
		t.Fatalf("expected HasSecret and HasKeyPassphrase true: %+v", prof)
	}

	plainLink, err := h.svc.ExportShareLink(prof.ID, "", true)
	if err != nil {
		t.Fatalf("ExportShareLink plain: %v", err)
	}
	if _, err := h.svc.ImportShareLink(plainLink, "", false); !errors.Is(err, crypto.ErrPlainShareNotAllowed) {
		t.Fatalf("ImportShareLink plain without allowPlain = %v, want ErrPlainShareNotAllowed", err)
	}
	imported, err := h.svc.ImportShareLink(plainLink, "", true)
	if err != nil {
		t.Fatalf("ImportShareLink plain allowed: %v", err)
	}
	if !imported.HasSecret || !imported.HasKeyPassphrase {
		t.Fatalf("expected imported key + passphrase flags true: %+v", imported)
	}

	if snippet := h.svc.GetEnvSnippet(); !strings.Contains(snippet, "socks5h://127.0.0.1:10808") {
		t.Fatalf("unexpected GetEnvSnippet: %q", snippet)
	}

	if logs := h.svc.GetLogs(); len(logs) == 0 {
		t.Fatalf("expected non-empty GetLogs")
	}
	h.svc.ClearLogs()
	if logs := h.svc.GetLogs(); len(logs) != 0 {
		t.Fatalf("expected empty logs after ClearLogs, got %d", len(logs))
	}

	if err := h.svc.DeleteProfile(prof.ID); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if _, err := h.profiles.Get(ctx, prof.ID); !errors.Is(err, profile.ErrProfileNotFound) {
		t.Fatalf("expected ErrProfileNotFound after DeleteProfile, got %v", err)
	}
}

func TestAppService_BeginProxySessionFailureRollbackAndBootstrapJSON(t *testing.T) {
	if _, err := NewAppService(Config{}); err == nil {
		t.Fatalf("expected NewAppService with empty Config to return error")
	}

	h := newAppHarness(t, time.Second)
	ctx := context.Background()
	h.svc.Startup(ctx)
	if err := h.svc.UnlockVault("VaultPass!Test4"); err != nil {
		t.Fatalf("UnlockVault: %v", err)
	}

	// Verify empty Profiles serializes as JSON [] (not null) matching frontend contract.
	boot, err := h.svc.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState: %v", err)
	}
	rawBoot, err := json.Marshal(boot)
	if err != nil {
		t.Fatalf("json.Marshal(BootstrapStateDTO): %v", err)
	}
	if !strings.Contains(string(rawBoot), `"profiles":[]`) {
		t.Fatalf("expected non-null empty profiles JSON array, got %s", string(rawBoot))
	}

	hostSigner := generateTestEd25519Signer(t)
	sshSrv := startInMemoryPAMSSHServer(t, "u", "pw-rollback", hostSigner)

	prof, err := h.svc.SaveProfile(SaveProfileRequest{
		Name:          "RollbackCheck",
		Host:          sshSrv.host,
		Port:          sshSrv.port,
		Username:      "u",
		AuthType:      string(profile.AuthPassword),
		BypassIranLAN: true,
		PreferredMode: string(profile.ModeProxy),
		Password:      "pw-rollback",
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}

	h.sysProxy.mu.Lock()
	h.sysProxy.enableErr = errors.New("gsettings permission failure")
	h.sysProxy.mu.Unlock()

	err = h.svc.TrustHostKeyAndConnect(prof.ID, hostSigner.PublicKey().Type(), ssh.FingerprintSHA256(hostSigner.PublicKey()))
	if err == nil {
		t.Fatalf("expected TrustHostKeyAndConnect to fail when sysProxy.Enable fails")
	}

	// SSH engine and proxy must be rolled back, and recovery_state.json must be clean.
	if st, err := h.svc.GetBootstrapState(); err != nil {
		t.Fatalf("GetBootstrapState: %v", err)
	} else if st.Status.State != string(sshclient.StateDisconnected) {
		t.Fatalf("expected disconnected after rollback, got %q", st.Status.State)
	}
	if rec, err := h.recStore.Load(); err != nil {
		t.Fatalf("recStore.Load: %v", err)
	} else if rec != nil && rec.Dirty {
		t.Fatalf("expected clean recovery_state.json after rollback, got %+v", rec)
	}
}

func TestAppService_StatsLoopGuardAndSetBypassRollback(t *testing.T) {
	h := newAppHarness(t, 15*time.Millisecond)
	ctx := context.Background()
	h.svc.Startup(ctx)
	if err := h.svc.UnlockVault("VaultPass!Test5"); err != nil {
		t.Fatalf("UnlockVault: %v", err)
	}

	hostSigner := generateTestEd25519Signer(t)
	sshSrv := startInMemoryPAMSSHServer(t, "u", "pw-stats", hostSigner)

	prof, err := h.svc.SaveProfile(SaveProfileRequest{
		Name:          "StatsGuard",
		Host:          sshSrv.host,
		Port:          sshSrv.port,
		Username:      "u",
		AuthType:      string(profile.AuthPassword),
		BypassIranLAN: false,
		PreferredMode: string(profile.ModeProxy),
		Password:      "pw-stats",
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}

	// Delay OS proxy enable across multiple 15ms statsLoop ticks and verify zero premature tunnel:stats.
	var statsBeforeProxy atomic.Int64
	h.sysProxy.mu.Lock()
	h.sysProxy.onEnable = func() {
		time.Sleep(80 * time.Millisecond)
		statsBeforeProxy.Store(int64(h.emitter.Count("tunnel:stats")))
	}
	h.sysProxy.mu.Unlock()

	if err := h.svc.TrustHostKeyAndConnect(prof.ID, hostSigner.PublicKey().Type(), ssh.FingerprintSHA256(hostSigner.PublicKey())); err != nil {
		t.Fatalf("TrustHostKeyAndConnect: %v", err)
	}
	if n := statsBeforeProxy.Load(); n != 0 {
		t.Fatalf("expected 0 tunnel:stats events before OS proxy enable completed, got %d", n)
	}

	// Clear delay and verify stats arrive once connected.
	h.sysProxy.mu.Lock()
	h.sysProxy.onEnable = nil
	h.sysProxy.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for h.emitter.Count("tunnel:stats") == 0 && time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
	}
	if h.emitter.Count("tunnel:stats") == 0 {
		t.Fatalf("expected tunnel:stats events while connected")
	}

	// Verify SetBypassIranLAN rolls back profile BypassIranLAN if live sysProxy.Enable fails.
	h.sysProxy.mu.Lock()
	h.sysProxy.enableErr = errors.New("live enable failed")
	h.sysProxy.mu.Unlock()
	if _, err := h.svc.SetBypassIranLAN(prof.ID, true); err == nil {
		t.Fatalf("expected SetBypassIranLAN error when sysProxy.Enable fails")
	}
	persisted, err := h.profiles.Get(ctx, prof.ID)
	if err != nil {
		t.Fatalf("profiles.Get: %v", err)
	}
	if persisted.BypassIranLAN {
		t.Fatalf("expected BypassIranLAN rolled back to false on live sysProxy.Enable failure")
	}

	// Verify Disconnect prevents any trailing tunnel:stats emissions.
	if err := h.svc.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	countAtDisconn := h.emitter.Count("tunnel:stats")
	time.Sleep(80 * time.Millisecond)
	if after := h.emitter.Count("tunnel:stats"); after != countAtDisconn {
		t.Fatalf("expected zero tunnel:stats after Disconnect (%d -> %d)", countAtDisconn, after)
	}
}

type mockTUNSessionController struct {
	mu sync.Mutex

	caps         TUNCapsDTO
	prepareSnap  splitroute.NetworkSnapshot
	prepareErr   error
	startErr     error
	setBypassErr error
	stopErr      error
	stats        tun.Stats
	isActiveOnOS bool
	isActiveErr  error
	restoreErr   error

	prepareCalls  int
	startCalls    int
	startReqs     []TUNStartRequest
	bypassCalls   []bool
	stopCalls     int
	restoreCalls  int
	restoredSnaps []splitroute.NetworkSnapshot
	isActiveCalls int

	onPrepare func(ctx context.Context)
	onStart   func(ctx context.Context, req TUNStartRequest, dialer sshclient.TunnelDialer)
	onStop    func(ctx context.Context)
}

var _ TUNSessionController = (*mockTUNSessionController)(nil)

func newMockTUNSessionController() *mockTUNSessionController {
	return &mockTUNSessionController{
		caps: TUNCapsDTO{
			Supported:              true,
			RequiresElevation:      true,
			HasPersistentCap:       false,
			CanEnablePersistentCap: true,
			IfaceName:              splitroute.TUNIfaceName,
			TUNIPv4:                splitroute.TUNIPv4Addr,
			TUNDNS:                 splitroute.TUNDNSServer,
		},
		prepareSnap: splitroute.NetworkSnapshot{
			OrigGateway:    "192.168.1.1",
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 2,
			OrigDNSServers: []string{"1.1.1.1"},
			DNSStrategy:    "resolv.conf",
			TUNIfaceName:   splitroute.TUNIfaceName,
		},
	}
}

func (m *mockTUNSessionController) Capabilities() TUNCapsDTO {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.caps
}

func (m *mockTUNSessionController) PrepareSession(ctx context.Context) (splitroute.NetworkSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return splitroute.NetworkSnapshot{}, err
	}
	m.mu.Lock()
	m.prepareCalls++
	cb := m.onPrepare
	snap := cloneNetworkSnapshot(m.prepareSnap)
	err := m.prepareErr
	m.mu.Unlock()
	if cb != nil {
		cb(ctx)
	}
	if err != nil {
		return splitroute.NetworkSnapshot{}, err
	}
	return snap, nil
}

func (m *mockTUNSessionController) StartTUN(ctx context.Context, req TUNStartRequest, dialer sshclient.TunnelDialer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	m.startCalls++
	reqCopy := req
	reqCopy.Snapshot = cloneNetworkSnapshot(req.Snapshot)
	m.startReqs = append(m.startReqs, reqCopy)
	cb := m.onStart
	err := m.startErr
	m.mu.Unlock()
	if cb != nil {
		cb(ctx, reqCopy, dialer)
	}
	return err
}

func (m *mockTUNSessionController) SetBypass(ctx context.Context, bypassIranLAN bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bypassCalls = append(m.bypassCalls, bypassIranLAN)
	return m.setBypassErr
}

func (m *mockTUNSessionController) Stop(ctx context.Context) error {
	m.mu.Lock()
	m.stopCalls++
	cb := m.onStop
	err := m.stopErr
	m.mu.Unlock()
	if cb != nil {
		cb(ctx)
	}
	return err
}

func (m *mockTUNSessionController) Stats() tun.Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

func (m *mockTUNSessionController) IsActiveOnOS(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.isActiveCalls++
	return m.isActiveOnOS, m.isActiveErr
}

func (m *mockTUNSessionController) RestoreFromSnapshot(ctx context.Context, snap splitroute.NetworkSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restoreCalls++
	m.restoredSnaps = append(m.restoredSnaps, cloneNetworkSnapshot(snap))
	return m.restoreErr
}

type tunRecoveryBridge struct {
	ctrl TUNSessionController
}

func (b tunRecoveryBridge) IsTUNStateActive(ctx context.Context) (bool, error) {
	return b.ctrl.IsActiveOnOS(ctx)
}

func (b tunRecoveryBridge) RestoreTUN(ctx context.Context, snap recovery.TUNSnapshot) error {
	return b.ctrl.RestoreFromSnapshot(ctx, RecoverySnapshotToNetwork(snap))
}

type faultRecoveryStore struct {
	inner        recovery.RecoveryStore
	saveDirtyErr error
}

func (f *faultRecoveryStore) Load() (*recovery.RecoveryState, error) {
	return f.inner.Load()
}

func (f *faultRecoveryStore) SaveDirty(state recovery.RecoveryState) error {
	if f.saveDirtyErr != nil {
		return f.saveDirtyErr
	}
	return f.inner.SaveDirty(state)
}

func (f *faultRecoveryStore) MarkClean() error {
	return f.inner.MarkClean()
}

type recordingSSHEngine struct {
	mu           sync.Mutex
	connectCfgs  []sshclient.ConnectConfig
	connectErr   error
	disconnCalls int
	snap         sshclient.EngineSnapshot
	subs         []func(sshclient.EngineSnapshot)
}

func (e *recordingSSHEngine) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (e *recordingSSHEngine) Connect(ctx context.Context, cfg sshclient.ConnectConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	e.connectCfgs = append(e.connectCfgs, cfg)
	err := e.connectErr
	if err == nil {
		e.snap = sshclient.EngineSnapshot{
			State:       sshclient.StateConnected,
			ProfileID:   cfg.ProfileID,
			Host:        cfg.Host,
			Port:        cfg.Port,
			ConnectedAt: time.Now(),
		}
	} else {
		e.snap = sshclient.EngineSnapshot{
			State:     sshclient.StateError,
			ProfileID: cfg.ProfileID,
			Host:      cfg.Host,
			Port:      cfg.Port,
		}
	}
	snap := e.snap
	subs := slices.Clone(e.subs)
	e.mu.Unlock()
	for _, fn := range subs {
		fn(snap)
	}
	return err
}

func (e *recordingSSHEngine) Disconnect(context.Context) error {
	e.mu.Lock()
	e.disconnCalls++
	e.snap.State = sshclient.StateDisconnected
	e.snap.LastError = nil
	snap := e.snap
	subs := slices.Clone(e.subs)
	e.mu.Unlock()
	for _, fn := range subs {
		fn(snap)
	}
	return nil
}

func (e *recordingSSHEngine) MeasureRTT(context.Context) (time.Duration, error) {
	return 5 * time.Millisecond, nil
}

func (e *recordingSSHEngine) Snapshot() sshclient.EngineSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snap
}

func (e *recordingSSHEngine) Subscribe(fn func(sshclient.EngineSnapshot)) func() {
	e.mu.Lock()
	e.subs = append(e.subs, fn)
	e.mu.Unlock()
	return func() {}
}

func (e *recordingSSHEngine) EmitSnapshot(snap sshclient.EngineSnapshot) {
	e.mu.Lock()
	e.snap = snap
	subs := slices.Clone(e.subs)
	e.mu.Unlock()
	for _, fn := range subs {
		fn(snap)
	}
}

func newTUNAppHarness(
	t *testing.T,
	statsInterval time.Duration,
	tunCtrl TUNSessionController,
	resolveFn func(ctx context.Context, host string) (netip.Addr, error),
	enableCapFn func(ctx context.Context) error,
	recStoreOverride recovery.RecoveryStore,
	engineOverride sshclient.Engine,
) *appHarness {
	t.Helper()
	dir := t.TempDir()

	profStore, err := profile.NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	secStore := profile.NewEncryptedFileSecretStore(dir)
	fileRecStore, err := recovery.NewFileRecoveryStore(dir)
	if err != nil {
		t.Fatalf("NewFileRecoveryStore: %v", err)
	}
	var recStore recovery.RecoveryStore = fileRecStore
	if recStoreOverride != nil {
		recStore = recStoreOverride
	}
	sysProx := newMockSysProxy()
	var restorerOpts []recovery.RestorerOption
	if tunCtrl != nil {
		restorerOpts = append(restorerOpts, recovery.WithTUNRecoveryOps(tunRecoveryBridge{ctrl: tunCtrl}))
	}
	restorer := recovery.NewRestorer(recStore, sysProx, restorerOpts...)

	var clientEngine *sshclient.Client
	var engine sshclient.Engine
	if engineOverride != nil {
		engine = engineOverride
	} else {
		clientEngine = sshclient.NewClient()
		engine = clientEngine
	}

	emitter := &recordingEmitter{}
	scrubber := NewSecretScrubber()
	logBuf := NewLogBuffer(DefaultLogBufferCapacity)

	h := &appHarness{
		dir:       dir,
		profiles:  profStore,
		secrets:   secStore,
		engine:    clientEngine,
		sysProxy:  sysProx,
		recStore:  fileRecStore,
		restorer:  restorer,
		emitter:   emitter,
		scrubber:  scrubber,
		logBuf:    logBuf,
		stderrBuf: &bytes.Buffer{},
	}

	lw := &lockedBuffer{mu: &h.stderrMu, buf: h.stderrBuf}
	downstream := slog.NewTextHandler(lw, &slog.HandlerOptions{Level: slog.LevelDebug})
	handler := NewRedactingHandler(downstream, scrubber, logBuf, func(entry LogEntryDTO) {
		emitter.Emit("tunnel:log", entry)
	})
	h.logger = slog.New(handler)

	svc, err := NewAppService(Config{
		Profiles: profStore,
		Secrets:  secStore,
		Engine:   engine,
		ProxyConfig: proxy.Config{
			SOCKSAddr:        "127.0.0.1:0",
			HTTPAddr:         "127.0.0.1:0",
			HandshakeTimeout: 3 * time.Second,
		},
		SysProxy:            sysProx,
		Restorer:            restorer,
		TUN:                 tunCtrl,
		ResolvePeerIP:       resolveFn,
		EnablePersistentTUN: enableCapFn,
		Emitter:             emitter,
		Scrubber:            scrubber,
		LogBuffer:           logBuf,
		Logger:              h.logger,
		StatsInterval:       statsInterval,
	})
	if err != nil {
		t.Fatalf("NewAppService: %v", err)
	}
	h.svc = svc
	t.Cleanup(func() {
		svc.Shutdown(context.Background())
	})
	return h
}

func TestAppService_Milestone2TUNBootstrapAndEnablePersistentAccess(t *testing.T) {
	ctx := context.Background()

	// 1. TUN == nil keeps Milestone 1 contract.
	m1 := newAppHarness(t, time.Second)
	m1.svc.Startup(ctx)
	if _, err := m1.svc.EnablePersistentTUNAccess(); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("EnablePersistentTUNAccess (tun=nil) = %v, want not enabled error", err)
	}

	// 2. TUN != nil with Supported=false reports Milestone 1 and TUNEnabled=false.
	unsupportedCtrl := newMockTUNSessionController()
	unsupportedCtrl.caps.Supported = false
	unsupportedCtrl.caps.CanEnablePersistentCap = false
	hUnsupported := newTUNAppHarness(t, time.Second, unsupportedCtrl, nil, nil, nil, nil)
	hUnsupported.svc.Startup(ctx)
	bootUnsupported, err := hUnsupported.svc.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState unsupported: %v", err)
	}
	if bootUnsupported.Milestone != 1 || bootUnsupported.TUNEnabled {
		t.Fatalf("expected Milestone=1, TUNEnabled=false for unsupported TUN, got %+v", bootUnsupported)
	}

	// 3. TUN supported reports Milestone 2, TUNEnabled=true, TUNCaps.
	tunCtrl := newMockTUNSessionController()
	var hookCalls atomic.Int32
	var hookHadDeadline atomic.Bool
	var hookErr error
	h := newTUNAppHarness(t, time.Second, tunCtrl, nil, func(callCtx context.Context) error {
		hookCalls.Add(1)
		if dl, ok := callCtx.Deadline(); ok && time.Until(dl) > 10*time.Second {
			hookHadDeadline.Store(true)
		}
		return hookErr
	}, nil, nil)
	h.svc.Startup(ctx)

	boot, err := h.svc.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState: %v", err)
	}
	if boot.Milestone != 2 || !boot.TUNEnabled {
		t.Fatalf("expected Milestone=2, TUNEnabled=true, got %+v", boot)
	}
	if !boot.TUNCaps.Supported || boot.TUNCaps.IfaceName != splitroute.TUNIfaceName || boot.TUNCaps.TUNDNS != splitroute.TUNDNSServer {
		t.Fatalf("unexpected TUNCaps: %+v", boot.TUNCaps)
	}

	// Success case invokes hook with bounded timeout (~30s).
	msg, err := h.svc.EnablePersistentTUNAccess()
	if err != nil {
		t.Fatalf("EnablePersistentTUNAccess success: %v", err)
	}
	if hookCalls.Load() != 1 || !hookHadDeadline.Load() {
		t.Fatalf("expected hook called once with >10s deadline (calls=%d, deadline=%v)", hookCalls.Load(), hookHadDeadline.Load())
	}
	if !strings.Contains(msg, "Restart tunssh") {
		t.Fatalf("unexpected success message: %q", msg)
	}

	// Hook failure propagates error.
	hookErr = errors.New("pkexec dismissed")
	if _, err := h.svc.EnablePersistentTUNAccess(); err == nil || !strings.Contains(err.Error(), "pkexec dismissed") {
		t.Fatalf("expected hook error, got %v", err)
	}

	// Already persistent skips hook.
	tunCtrl.mu.Lock()
	tunCtrl.caps.HasPersistentCap = true
	tunCtrl.mu.Unlock()
	alreadyMsg, err := h.svc.EnablePersistentTUNAccess()
	if err != nil || !strings.Contains(alreadyMsg, "already active") {
		t.Fatalf("HasPersistentCap = (%q, %v), want already active", alreadyMsg, err)
	}
	if hookCalls.Load() != 2 {
		t.Fatalf("expected hook not called when HasPersistentCap=true, calls=%d", hookCalls.Load())
	}

	// Platform without CanEnablePersistentCap returns error without invoking hook.
	tunCtrl.mu.Lock()
	tunCtrl.caps.HasPersistentCap = false
	tunCtrl.caps.CanEnablePersistentCap = false
	tunCtrl.mu.Unlock()
	if _, err := h.svc.EnablePersistentTUNAccess(); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("CanEnablePersistentCap=false = %v, want not available error", err)
	}
	if hookCalls.Load() != 2 {
		t.Fatalf("expected hook not called when CanEnablePersistentCap=false, calls=%d", hookCalls.Load())
	}
}

func TestAppService_Milestone2TUNEndToEndTOFUOrderingStatsBypassAndDisconnect(t *testing.T) {
	ctx := context.Background()
	const (
		vaultPass = "VaultPass!M2Test1"
		sshUser   = "tunm2"
		sshPass   = "SecretM2!Pass9"
	)

	hostSigner := generateTestEd25519Signer(t)
	sshSrv := startInMemoryPAMSSHServer(t, sshUser, sshPass, hostSigner)

	tunCtrl := newMockTUNSessionController()
	var resolvedHosts []string
	var resolveMu sync.Mutex
	resolveFn := func(_ context.Context, host string) (netip.Addr, error) {
		resolveMu.Lock()
		resolvedHosts = append(resolvedHosts, host)
		resolveMu.Unlock()
		return netip.MustParseAddr(sshSrv.host), nil
	}

	h := newTUNAppHarness(t, 20*time.Millisecond, tunCtrl, resolveFn, nil, nil, nil)
	h.svc.Startup(ctx)
	if err := h.svc.UnlockVault(vaultPass); err != nil {
		t.Fatalf("UnlockVault: %v", err)
	}

	// Save profile with logical hostname (different from DialHost 127.0.0.1) and PreferredMode="proxy"
	// so we also verify TrustHostKeyAndConnect preserves the explicit "tun" mode from failed Connect!
	prof, err := h.svc.SaveProfile(SaveProfileRequest{
		Name:          "M2-TUN-VPS",
		Host:          "vpn.example.test",
		Port:          sshSrv.port,
		Username:      sshUser,
		AuthType:      string(profile.AuthPassword),
		BypassIranLAN: true,
		PreferredMode: string(profile.ModeProxy),
		Password:      sshPass,
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}

	// 1. First Connect(id, "tun") hits TOFU using prof.Host while dialing vpsIP (127.0.0.1).
	err = h.svc.Connect(prof.ID, string(profile.ModeTUN))
	var untrusted *sshclient.ErrHostKeyUntrusted
	if !errors.As(err, &untrusted) {
		t.Fatalf("expected ErrHostKeyUntrusted, got %v", err)
	}
	prompts := h.emitter.EventsNamed("tunnel:hostkey_prompt")
	if len(prompts) != 1 {
		t.Fatalf("hostkey_prompt count = %d, want 1", len(prompts))
	}
	promptDTO := prompts[0].data.(HostKeyPromptDTO)
	if promptDTO.Host != "vpn.example.test" || promptDTO.Port != sshSrv.port {
		t.Fatalf("TOFU prompt host:port = %s:%d, want vpn.example.test:%d", promptDTO.Host, promptDTO.Port, sshSrv.port)
	}
	tunCtrl.mu.Lock()
	prepAfterTOFU := tunCtrl.prepareCalls
	startAfterTOFU := tunCtrl.startCalls
	stopAfterTOFU := tunCtrl.stopCalls
	tunCtrl.mu.Unlock()
	if prepAfterTOFU != 1 || startAfterTOFU != 0 || stopAfterTOFU != 1 {
		t.Fatalf("unexpected TUN calls after TOFU failure: prep=%d start=%d stop=%d", prepAfterTOFU, startAfterTOFU, stopAfterTOFU)
	}
	if rec, loadErr := h.recStore.Load(); loadErr != nil || (rec != nil && rec.Dirty) {
		t.Fatalf("expected clean recovery_state.json after TOFU failure, got %+v (err=%v)", rec, loadErr)
	}

	// 2. Verify ordering invariant: BeginTUNSession writes dirty:true, mode:"tun" strictly BEFORE StartTUN.
	var (
		recBeforeStart *recovery.RecoveryState
		recLoadErr     error
		dialerNonNil   bool
	)
	tunCtrl.mu.Lock()
	tunCtrl.onStart = func(_ context.Context, req TUNStartRequest, dialer sshclient.TunnelDialer) {
		recBeforeStart, recLoadErr = h.recStore.Load()
		dialerNonNil = dialer != nil
	}
	tunCtrl.stats = tun.Stats{
		Running:   true,
		IfaceName: splitroute.TUNIfaceName,
		RxBytes:   4096,
		TxBytes:   2048,
	}
	tunCtrl.mu.Unlock()

	if err := h.svc.TrustHostKeyAndConnect(prof.ID, promptDTO.Algorithm, promptDTO.SHA256); err != nil {
		t.Fatalf("TrustHostKeyAndConnect: %v", err)
	}
	if recLoadErr != nil || recBeforeStart == nil || !recBeforeStart.Dirty || recBeforeStart.Mode != recovery.RecoveryModeTUN || recBeforeStart.TUNSnapshot == nil {
		t.Fatalf("BeginTUNSession did not persist dirty TUN state before StartTUN: %+v (err=%v)", recBeforeStart, recLoadErr)
	}
	if recBeforeStart.TUNSnapshot.VPSPeerIP != "127.0.0.1" {
		t.Fatalf("expected VPSPeerIP=127.0.0.1 in recovery snapshot, got %+v", recBeforeStart.TUNSnapshot)
	}
	if !dialerNonNil {
		t.Fatalf("expected non-nil TunnelDialer passed to StartTUN")
	}

	resolveMu.Lock()
	if len(resolvedHosts) != 2 || resolvedHosts[0] != "vpn.example.test" || resolvedHosts[1] != "vpn.example.test" {
		t.Fatalf("resolvedHosts = %v, want [vpn.example.test vpn.example.test]", resolvedHosts)
	}
	resolveMu.Unlock()

	bootConn, err := h.svc.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState: %v", err)
	}
	if bootConn.Status.State != string(sshclient.StateConnected) || bootConn.Status.Mode != string(profile.ModeTUN) {
		t.Fatalf("expected connected/tun status, got state=%q mode=%q", bootConn.Status.State, bootConn.Status.Mode)
	}
	if enableCalls, _, _, _ := h.sysProxy.Stats(); enableCalls != 0 {
		t.Fatalf("expected 0 sysProxy.Enable calls in TUN mode, got %d", enableCalls)
	}

	// Verify connection summary log includes tunssh0 and 198.18.0.2.
	logsText := h.svc.ExportRedactedLogs()
	if !strings.Contains(logsText, splitroute.TUNIfaceName) || !strings.Contains(logsText, splitroute.TUNDNSServer) {
		t.Fatalf("expected TUN summary log containing %s and %s, got:\n%s", splitroute.TUNIfaceName, splitroute.TUNDNSServer, logsText)
	}

	// Wait for tunnel:stats and verify TUN stats are merged.
	deadline := time.Now().Add(2 * time.Second)
	for h.emitter.Count("tunnel:stats") == 0 && time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
	}
	statsEvs := h.emitter.EventsNamed("tunnel:stats")
	if len(statsEvs) == 0 {
		t.Fatalf("expected tunnel:stats emission in TUN mode")
	}
	lastStats := statsEvs[len(statsEvs)-1].data.(TunnelStatusDTO)
	if lastStats.Mode != string(profile.ModeTUN) || lastStats.RxBytes < 4096 || lastStats.TxBytes < 2048 {
		t.Fatalf("expected merged TUN stats in tunnel:stats, got %+v", lastStats)
	}

	// 3. SetBypassIranLAN updates live TUN bypass and rolls back profiles.json on failure.
	updatedView, err := h.svc.SetBypassIranLAN(prof.ID, false)
	if err != nil || updatedView.BypassIranLAN {
		t.Fatalf("SetBypassIranLAN(false) = (%+v, %v)", updatedView, err)
	}
	tunCtrl.mu.Lock()
	tunCtrl.setBypassErr = errors.New("netlink bypass update failed")
	tunCtrl.mu.Unlock()
	if _, err := h.svc.SetBypassIranLAN(prof.ID, true); err == nil {
		t.Fatalf("expected SetBypassIranLAN(true) failure")
	}
	persistedProf, err := h.profiles.Get(ctx, prof.ID)
	if err != nil {
		t.Fatalf("profiles.Get: %v", err)
	}
	if persistedProf.BypassIranLAN {
		t.Fatalf("expected BypassIranLAN rolled back to false on SetBypass failure")
	}

	// 4. Disconnect stops TUN, marks recovery clean, clears activeTUN, stops stats.
	if err := h.svc.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	tunCtrl.mu.Lock()
	stopsAfterDisconn := tunCtrl.stopCalls
	bypassCalls := append([]bool(nil), tunCtrl.bypassCalls...)
	tunCtrl.mu.Unlock()
	if stopsAfterDisconn != 2 {
		t.Fatalf("tun.Stop calls = %d, want 2 (1 TOFU failure + 1 Disconnect)", stopsAfterDisconn)
	}
	if len(bypassCalls) != 2 || bypassCalls[0] != false || bypassCalls[1] != true {
		t.Fatalf("bypassCalls = %v, want [false true]", bypassCalls)
	}
	if rec, loadErr := h.recStore.Load(); loadErr != nil || rec == nil || rec.Dirty {
		t.Fatalf("expected clean recovery_state.json after Disconnect, got %+v (err=%v)", rec, loadErr)
	}
	if st, _ := h.svc.GetBootstrapState(); st.Status.State != string(sshclient.StateDisconnected) {
		t.Fatalf("expected disconnected after Disconnect, got %q", st.Status.State)
	}
	countAtDisconn := h.emitter.Count("tunnel:stats")
	time.Sleep(70 * time.Millisecond)
	if h.emitter.Count("tunnel:stats") != countAtDisconn {
		t.Fatalf("expected zero trailing tunnel:stats after Disconnect")
	}

	// 5. Verify TrustHostKeyAndConnect on a fresh service with PreferredMode="tun" defaults to "tun" without prior Connect.
	tunCtrl2 := newMockTUNSessionController()
	h2 := newTUNAppHarness(t, time.Second, tunCtrl2, resolveFn, nil, nil, nil)
	h2.svc.Startup(ctx)
	if err := h2.svc.UnlockVault(vaultPass); err != nil {
		t.Fatalf("UnlockVault h2: %v", err)
	}
	profPrefTUN, err := h2.svc.SaveProfile(SaveProfileRequest{
		Name:          "Pref-TUN",
		Host:          "vpn.example.test",
		Port:          sshSrv.port,
		Username:      sshUser,
		AuthType:      string(profile.AuthPassword),
		BypassIranLAN: true,
		PreferredMode: string(profile.ModeTUN),
		Password:      sshPass,
	})
	if err != nil {
		t.Fatalf("SaveProfile h2: %v", err)
	}
	if err := h2.svc.TrustHostKeyAndConnect(profPrefTUN.ID, promptDTO.Algorithm, promptDTO.SHA256); err != nil {
		t.Fatalf("TrustHostKeyAndConnect PreferredMode=tun: %v", err)
	}
	if st, _ := h2.svc.GetBootstrapState(); st.Status.Mode != string(profile.ModeTUN) || st.Status.State != string(sshclient.StateConnected) {
		t.Fatalf("expected TrustHostKeyAndConnect to honor PreferredMode=tun, got %+v", st.Status)
	}

	// 6. Switching from active TUN -> Proxy stops TUN, restores TUN recovery, and activates proxy.
	profSwitch, err := h2.svc.SaveProfile(SaveProfileRequest{
		Name:          "Switch-TUN-Proxy",
		Host:          sshSrv.host,
		Port:          sshSrv.port,
		Username:      sshUser,
		AuthType:      string(profile.AuthPassword),
		BypassIranLAN: true,
		PreferredMode: string(profile.ModeTUN),
		Password:      sshPass,
	})
	if err != nil {
		t.Fatalf("SaveProfile switch: %v", err)
	}
	if err := h2.svc.TrustHostKeyAndConnect(profSwitch.ID, promptDTO.Algorithm, promptDTO.SHA256); err != nil {
		t.Fatalf("TrustHostKeyAndConnect switch profile (TUN): %v", err)
	}
	tunCtrl2.mu.Lock()
	tunStopsBeforeSwitch := tunCtrl2.stopCalls
	tunCtrl2.mu.Unlock()
	if tunStopsBeforeSwitch != 1 {
		t.Fatalf("expected tun.Stop called once on TUN -> TUN profile switch, got %d", tunStopsBeforeSwitch)
	}
	if err := h2.svc.Connect(profSwitch.ID, string(profile.ModeProxy)); err != nil {
		t.Fatalf("switch TUN -> Proxy: %v", err)
	}
	tunCtrl2.mu.Lock()
	tunStopsAfterSwitch := tunCtrl2.stopCalls
	tunCtrl2.mu.Unlock()
	if tunStopsAfterSwitch != 2 {
		t.Fatalf("expected tun.Stop called again on TUN -> Proxy switch, got %d", tunStopsAfterSwitch)
	}
	if st, _ := h2.svc.GetBootstrapState(); st.Status.Mode != string(profile.ModeProxy) || st.Status.State != string(sshclient.StateConnected) {
		t.Fatalf("expected connected/proxy after mode switch, got %+v", st.Status)
	}
	if rec, loadErr := h2.recStore.Load(); loadErr != nil || rec == nil || !rec.Dirty || rec.Mode != recovery.RecoveryModeProxy {
		t.Fatalf("expected dirty proxy recovery state after mode switch, got %+v (err=%v)", rec, loadErr)
	}
}

func TestAppService_Milestone2TUNConnectDialControlAndRollbacks(t *testing.T) {
	ctx := context.Background()

	// 1. Verify DialHost, DialControl attachment, and InstalledRoutes population with recordingSSHEngine.
	tunCtrl := newMockTUNSessionController()
	tunCtrl.caps.RequiresElevation = false
	var (
		recAtStart    *recovery.RecoveryState
		recAtStartErr error
	)
	recEng := &recordingSSHEngine{}
	resolveFn := func(context.Context, string) (netip.Addr, error) {
		return netip.MustParseAddr("203.0.113.10"), nil
	}
	h := newTUNAppHarness(t, 20*time.Millisecond, tunCtrl, resolveFn, nil, nil, recEng)
	tunCtrl.mu.Lock()
	tunCtrl.onStart = func(context.Context, TUNStartRequest, sshclient.TunnelDialer) {
		recAtStart, recAtStartErr = h.recStore.Load()
	}
	tunCtrl.mu.Unlock()
	h.svc.Startup(ctx)
	if err := h.svc.UnlockVault("VaultPass!M2Ctrl"); err != nil {
		t.Fatalf("UnlockVault: %v", err)
	}
	prof, err := h.svc.SaveProfile(SaveProfileRequest{
		Name:          "DialControl-Check",
		Host:          "edge.example.com",
		Port:          2222,
		Username:      "u",
		AuthType:      string(profile.AuthPassword),
		BypassIranLAN: true,
		PreferredMode: string(profile.ModeTUN),
		Password:      "pw",
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	if err := h.svc.Connect(prof.ID, string(profile.ModeTUN)); err != nil {
		t.Fatalf("Connect(tun) with recordingSSHEngine: %v", err)
	}
	if recAtStartErr != nil || recAtStart == nil || !recAtStart.Dirty || recAtStart.Mode != recovery.RecoveryModeTUN || recAtStart.TUNSnapshot == nil {
		t.Fatalf("expected dirty TUN recovery snapshot before StartTUN, got %+v (err=%v)", recAtStart, recAtStartErr)
	}
	if recAtStart.TUNSnapshot.VPSPeerIP != "203.0.113.10" || !slices.Contains(recAtStart.TUNSnapshot.InstalledRoutes, "203.0.113.10/32") || !slices.Contains(recAtStart.TUNSnapshot.InstalledRoutes, "0.0.0.0/1") {
		t.Fatalf("expected InstalledRoutes populated for 203.0.113.10, got %+v", recAtStart.TUNSnapshot)
	}
	recEng.mu.Lock()
	if len(recEng.connectCfgs) != 1 {
		recEng.mu.Unlock()
		t.Fatalf("expected 1 ConnectConfig, got %d", len(recEng.connectCfgs))
	}
	cfg1 := recEng.connectCfgs[0]
	recEng.mu.Unlock()
	if cfg1.Host != "edge.example.com" || cfg1.DialHost != "203.0.113.10" || cfg1.DialControl == nil {
		t.Fatalf("unexpected ConnectConfig for direct TUN: Host=%q DialHost=%q DialControl=%v", cfg1.Host, cfg1.DialHost, cfg1.DialControl != nil)
	}

	// Runtime StateError tears down active TUN and marks recovery clean.
	recEng.EmitSnapshot(sshclient.EngineSnapshot{
		State:     sshclient.StateError,
		ProfileID: prof.ID,
		Host:      prof.Host,
		Port:      prof.Port,
		LastError: &sshclient.MappedError{Code: "AUTH_FAILED", Message: "auth failed", Retryable: false},
	})
	tunCtrl.mu.Lock()
	stopsAfterErr := tunCtrl.stopCalls
	tunCtrl.mu.Unlock()
	if stopsAfterErr != 1 {
		t.Fatalf("expected tun.Stop called on runtime StateError, got %d", stopsAfterErr)
	}
	if rec, loadErr := h.recStore.Load(); loadErr != nil || rec == nil || rec.Dirty {
		t.Fatalf("expected clean recovery_state.json after StateError teardown, got %+v (err=%v)", rec, loadErr)
	}

	// 2. StartTUN failure rolls back TUN.Stop, marks recovery clean, and disconnects SSH.
	tunCtrl.mu.Lock()
	tunCtrl.caps.RequiresElevation = true
	tunCtrl.startErr = errors.New("wintun open failed")
	tunCtrl.mu.Unlock()
	if err := h.svc.Connect(prof.ID, string(profile.ModeTUN)); err == nil || !strings.Contains(err.Error(), "wintun open failed") {
		t.Fatalf("expected StartTUN failure, got %v", err)
	}
	recEng.mu.Lock()
	cfg2 := recEng.connectCfgs[1]
	disconnCallsAfterStartFail := recEng.disconnCalls
	recEng.mu.Unlock()
	if cfg2.DialControl != nil {
		t.Fatalf("expected nil DialControl when RequiresElevation=true")
	}
	if disconnCallsAfterStartFail == 0 {
		t.Fatalf("expected engine.Disconnect called on StartTUN failure")
	}
	if rec, loadErr := h.recStore.Load(); loadErr != nil || rec == nil || rec.Dirty {
		t.Fatalf("expected clean recovery_state.json after StartTUN rollback, got %+v (err=%v)", rec, loadErr)
	}
	if st, _ := h.svc.GetBootstrapState(); st.Status.State != string(sshclient.StateDisconnected) {
		t.Fatalf("expected disconnected after StartTUN failure, got %q", st.Status.State)
	}

	// 3. BeginTUNSession failure rolls back TUN.Stop and disconnects SSH without calling StartTUN.
	tunCtrlFailBegin := newMockTUNSessionController()
	recEngFailBegin := &recordingSSHEngine{}
	rawDir := t.TempDir()
	baseRec, err := recovery.NewFileRecoveryStore(rawDir)
	if err != nil {
		t.Fatalf("NewFileRecoveryStore: %v", err)
	}
	faultRec := &faultRecoveryStore{inner: baseRec, saveDirtyErr: errors.New("disk full")}
	hFailBegin := newTUNAppHarness(t, time.Second, tunCtrlFailBegin, resolveFn, nil, faultRec, recEngFailBegin)
	hFailBegin.svc.Startup(ctx)
	_ = hFailBegin.svc.UnlockVault("VaultPass!BeginFail")
	profFB, err := hFailBegin.svc.SaveProfile(SaveProfileRequest{
		Name:          "BeginFail",
		Host:          "edge.example.com",
		Port:          22,
		Username:      "u",
		AuthType:      string(profile.AuthPassword),
		PreferredMode: string(profile.ModeTUN),
		Password:      "pw",
	})
	if err != nil {
		t.Fatalf("SaveProfile failBegin: %v", err)
	}
	if err := hFailBegin.svc.Connect(profFB.ID, string(profile.ModeTUN)); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("expected BeginTUNSession failure, got %v", err)
	}
	tunCtrlFailBegin.mu.Lock()
	if tunCtrlFailBegin.startCalls != 0 || tunCtrlFailBegin.stopCalls != 1 {
		t.Fatalf("expected startCalls=0 stopCalls=1 on BeginTUNSession failure, got start=%d stop=%d", tunCtrlFailBegin.startCalls, tunCtrlFailBegin.stopCalls)
	}
	tunCtrlFailBegin.mu.Unlock()
	recEngFailBegin.mu.Lock()
	if recEngFailBegin.disconnCalls != 1 {
		t.Fatalf("expected engine.Disconnect on BeginTUNSession failure, got %d", recEngFailBegin.disconnCalls)
	}
	recEngFailBegin.mu.Unlock()

	// 4. Concurrent Disconnect cancels slow in-flight Connect(id, "tun").
	tunCtrlSlow := newMockTUNSessionController()
	prepStarted := make(chan struct{})
	tunCtrlSlow.onPrepare = func(prepCtx context.Context) {
		close(prepStarted)
		<-prepCtx.Done()
	}
	hSlow := newTUNAppHarness(t, time.Second, tunCtrlSlow, resolveFn, nil, nil, nil)
	hSlow.svc.Startup(ctx)
	_ = hSlow.svc.UnlockVault("VaultPass!SlowTUN")
	profSlow, err := hSlow.svc.SaveProfile(SaveProfileRequest{
		Name:          "SlowTUN",
		Host:          "127.0.0.1",
		Port:          22,
		Username:      "u",
		AuthType:      string(profile.AuthPassword),
		PreferredMode: string(profile.ModeTUN),
		Password:      "pw",
	})
	if err != nil {
		t.Fatalf("SaveProfile slowTUN: %v", err)
	}
	connErrCh := make(chan error, 1)
	go func() {
		connErrCh <- hSlow.svc.Connect(profSlow.ID, string(profile.ModeTUN))
	}()
	select {
	case <-prepStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for PrepareSession")
	}
	if err := hSlow.svc.Disconnect(); err != nil {
		t.Fatalf("Disconnect during PrepareSession: %v", err)
	}
	select {
	case err := <-connErrCh:
		if err == nil {
			t.Fatalf("expected canceled Connect(tun) error")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Connect(tun) hung after Disconnect")
	}
}

func TestAppService_Milestone2TUNStartupRecovery(t *testing.T) {
	ctx := context.Background()

	// Case (a): Dirty TUN state on startup when IsActiveOnOS returns false -> auto-cleaned.
	tunInactive := newMockTUNSessionController()
	tunInactive.isActiveOnOS = false
	h1 := newTUNAppHarness(t, time.Second, tunInactive, nil, nil, nil, nil)
	if err := h1.recStore.SaveDirty(recovery.RecoveryState{
		Mode: recovery.RecoveryModeTUN,
		PID:  os.Getpid() + 40000,
		TUNSnapshot: &recovery.TUNSnapshot{
			VPSPeerIP:     "203.0.113.10",
			OrigGateway:   "192.168.1.1",
			OrigIfaceName: "eth0",
			TUNIfaceName:  splitroute.TUNIfaceName,
		},
	}); err != nil {
		t.Fatalf("SaveDirty case a: %v", err)
	}

	h1.svc.Startup(ctx)
	ev1 := h1.emitter.EventsNamed("tunnel:recovery")
	if len(ev1) != 1 {
		t.Fatalf("expected 1 tunnel:recovery event in case a, got %d", len(ev1))
	}
	dto1 := ev1[0].data.(StartupRecoveryDTO)
	if !dto1.Recovered || dto1.NeedsElevation || dto1.Mode != recovery.RecoveryModeTUN {
		t.Fatalf("unexpected StartupRecoveryDTO for inactive OS TUN: %+v", dto1)
	}
	if rec, err := h1.recStore.Load(); err != nil || rec.Dirty {
		t.Fatalf("expected recovery_state.json marked clean automatically, got %+v (err=%v)", rec, err)
	}

	// Case (b): Dirty TUN state on startup when IsActiveOnOS returns true -> NeedsElevation, then RestoreNetwork restores + cleans.
	tunActive := newMockTUNSessionController()
	tunActive.isActiveOnOS = true
	h2 := newTUNAppHarness(t, time.Second, tunActive, nil, nil, nil, nil)
	if err := h2.recStore.SaveDirty(recovery.RecoveryState{
		Mode: recovery.RecoveryModeTUN,
		PID:  os.Getpid() + 40001,
		TUNSnapshot: &recovery.TUNSnapshot{
			VPSPeerIP:       "203.0.113.10",
			OrigGateway:     "192.168.1.1",
			OrigIfaceName:   "eth0",
			OrigIfaceIndex:  2,
			TUNIfaceName:    splitroute.TUNIfaceName,
			InstalledRoutes: []string{"203.0.113.10/32", "0.0.0.0/1", "128.0.0.0/1"},
		},
	}); err != nil {
		t.Fatalf("SaveDirty case b: %v", err)
	}

	h2.svc.Startup(ctx)
	ev2 := h2.emitter.EventsNamed("tunnel:recovery")
	if len(ev2) != 1 {
		t.Fatalf("expected 1 tunnel:recovery event in case b, got %d", len(ev2))
	}
	dto2 := ev2[0].data.(StartupRecoveryDTO)
	if dto2.Recovered || !dto2.NeedsElevation || dto2.Mode != recovery.RecoveryModeTUN {
		t.Fatalf("unexpected StartupRecoveryDTO for active OS TUN: %+v", dto2)
	}
	if rec, err := h2.recStore.Load(); err != nil || !rec.Dirty {
		t.Fatalf("expected recovery_state.json still dirty before RestoreNetwork, got %+v (err=%v)", rec, err)
	}

	if err := h2.svc.RestoreNetwork(); err != nil {
		t.Fatalf("RestoreNetwork: %v", err)
	}
	tunActive.mu.Lock()
	restoreCalls := tunActive.restoreCalls
	restoredSnaps := append([]splitroute.NetworkSnapshot(nil), tunActive.restoredSnaps...)
	tunActive.mu.Unlock()
	if restoreCalls != 1 || len(restoredSnaps) != 1 || restoredSnaps[0].VPSPeerIP != "203.0.113.10" {
		t.Fatalf("expected RestoreFromSnapshot called once with VPSPeerIP=203.0.113.10, got calls=%d snaps=%+v", restoreCalls, restoredSnaps)
	}
	if rec, err := h2.recStore.Load(); err != nil || rec.Dirty {
		t.Fatalf("expected recovery_state.json clean after RestoreNetwork, got %+v (err=%v)", rec, err)
	}
	bootAfterRestore, err := h2.svc.GetBootstrapState()
	if err != nil {
		t.Fatalf("GetBootstrapState after RestoreNetwork: %v", err)
	}
	if bootAfterRestore.Recovery == nil || !bootAfterRestore.Recovery.Recovered || bootAfterRestore.Recovery.NeedsElevation {
		t.Fatalf("expected updated Recovery banner state after RestoreNetwork, got %+v", bootAfterRestore.Recovery)
	}
}

func TestAppService_HelperSingleElevationPerSessionAndCleanRollback(t *testing.T) {
	ctx := context.Background()
	const (
		sshUser = "singleuac"
		sshPass = "SingleUAC!Pass1"
	)

	makePipeHelper := func(helperCtrl TUNSessionController) (*funcHelperLauncher, <-chan error) {
		helperDone := make(chan error, 4)
		launcher := &funcHelperLauncher{
			launchFn: func(_ context.Context) (io.ReadWriteCloser, func(), error) {
				guiConn, helperConn := net.Pipe()
				go func() {
					helperDone <- RunHelperOnConn(context.Background(), helperConn, helperCtrl, discardLogger())
				}()
				return guiConn, func() { _ = guiConn.Close() }, nil
			},
		}
		return launcher, helperDone
	}

	savePinnedTUNProfile := func(t *testing.T, h *appHarness, name, host string, port int, hostSigner ssh.Signer) ProfileView {
		t.Helper()
		view, err := h.svc.SaveProfile(SaveProfileRequest{
			Name:          name,
			Host:          host,
			Port:          port,
			Username:      sshUser,
			AuthType:      string(profile.AuthPassword),
			PreferredMode: string(profile.ModeTUN),
			Password:      sshPass,
		})
		if err != nil {
			t.Fatalf("SaveProfile: %v", err)
		}
		p, err := h.profiles.Get(ctx, view.ID)
		if err != nil {
			t.Fatalf("profiles.Get: %v", err)
		}
		p.PinnedHostKey = &profile.HostKeyPin{
			Algorithm: hostSigner.PublicKey().Type(),
			SHA256:    ssh.FingerprintSHA256(hostSigner.PublicKey()),
		}
		if _, err := h.profiles.Save(ctx, p); err != nil {
			t.Fatalf("profiles.Save pin: %v", err)
		}
		return view
	}

	t.Run("PrepareSession -> StartTUN -> Disconnect uses exactly 1 helper launch", func(t *testing.T) {
		hostSigner := generateTestEd25519Signer(t)
		sshSrv := startInMemoryPAMSSHServer(t, sshUser, sshPass, hostSigner)

		helperMock := newMockTUNSessionController()
		helperMock.stats = tun.Stats{Running: true, IfaceName: splitroute.TUNIfaceName}
		helperMock.onStop = func(context.Context) {
			helperMock.mu.Lock()
			helperMock.stats.Running = false
			helperMock.mu.Unlock()
		}
		launcher, helperDone := makePipeHelper(helperMock)
		guiCtrl := newHelperTUNController(
			TUNCapsDTO{Supported: true, RequiresElevation: true, IfaceName: splitroute.TUNIfaceName, TUNIPv4: splitroute.TUNIPv4Addr, TUNDNS: splitroute.TUNDNSServer},
			launcher,
			&mockRouteManager{isActive: false},
			discardLogger(),
		)

		resolveFn := func(context.Context, string) (netip.Addr, error) {
			return netip.MustParseAddr(sshSrv.host), nil
		}
		h := newTUNAppHarness(t, 50*time.Millisecond, guiCtrl, resolveFn, nil, nil, nil)
		h.svc.Startup(ctx)
		if err := h.svc.UnlockVault("VaultPass!Single1"); err != nil {
			t.Fatalf("UnlockVault: %v", err)
		}
		prof := savePinnedTUNProfile(t, h, "SingleLaunchHappy", sshSrv.host, sshSrv.port, hostSigner)

		if err := h.svc.Connect(prof.ID, string(profile.ModeTUN)); err != nil {
			t.Fatalf("Connect(tun) error = %v", err)
		}
		if launcher.Calls() != 1 {
			t.Fatalf("expected 1 helper launch after Connect, got %d", launcher.Calls())
		}
		if err := h.svc.Disconnect(); err != nil {
			t.Fatalf("Disconnect error = %v", err)
		}
		select {
		case err := <-helperDone:
			if err != nil {
				t.Fatalf("helper exited with error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for helper exit")
		}
		if launcher.Calls() != 1 {
			t.Fatalf("expected NO second helper launch on Disconnect, got %d", launcher.Calls())
		}
		if rec, err := h.recStore.Load(); err != nil || rec == nil || rec.Dirty {
			t.Fatalf("expected clean recovery_state.json after Disconnect, got %+v (err=%v)", rec, err)
		}
		helperMock.mu.Lock()
		gotStop, gotRestore := helperMock.stopCalls, helperMock.restoreCalls
		helperMock.mu.Unlock()
		if gotRestore != 0 || gotStop != 1 {
			t.Fatalf("expected helper Stop=1 Restore=0, got Stop=%d Restore=%d", gotStop, gotRestore)
		}
	})

	t.Run("PrepareSession -> StartTUN fail -> rollback uses exactly 1 helper launch and cleans recovery", func(t *testing.T) {
		hostSigner := generateTestEd25519Signer(t)
		sshSrv := startInMemoryPAMSSHServer(t, sshUser, sshPass, hostSigner)

		helperMock := newMockTUNSessionController()
		helperMock.startErr = errors.New("simulated start error with clean internal rollback")
		launcher, helperDone := makePipeHelper(helperMock)
		guiCtrl := newHelperTUNController(
			TUNCapsDTO{Supported: true, RequiresElevation: true, IfaceName: splitroute.TUNIfaceName, TUNIPv4: splitroute.TUNIPv4Addr, TUNDNS: splitroute.TUNDNSServer},
			launcher,
			&mockRouteManager{isActive: false},
			discardLogger(),
		)

		resolveFn := func(context.Context, string) (netip.Addr, error) {
			return netip.MustParseAddr(sshSrv.host), nil
		}
		h := newTUNAppHarness(t, 50*time.Millisecond, guiCtrl, resolveFn, nil, nil, nil)
		h.svc.Startup(ctx)
		if err := h.svc.UnlockVault("VaultPass!SingleFail"); err != nil {
			t.Fatalf("UnlockVault: %v", err)
		}
		prof := savePinnedTUNProfile(t, h, "SingleLaunchFail", sshSrv.host, sshSrv.port, hostSigner)

		err := h.svc.Connect(prof.ID, string(profile.ModeTUN))
		if err == nil || !strings.Contains(err.Error(), "simulated start error") {
			t.Fatalf("expected StartTUN error, got %v", err)
		}
		select {
		case err := <-helperDone:
			if err != nil {
				t.Fatalf("helper exited with error: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for helper exit")
		}
		if launcher.Calls() != 1 {
			t.Fatalf("expected NO second helper launch on StartTUN rollback, got %d", launcher.Calls())
		}
		if rec, err := h.recStore.Load(); err != nil || rec == nil || rec.Dirty {
			t.Fatalf("expected clean recovery_state.json after StartTUN rollback, got %+v (err=%v)", rec, err)
		}
		helperMock.mu.Lock()
		gotRestore := helperMock.restoreCalls
		helperMock.mu.Unlock()
		if gotRestore != 0 {
			t.Fatalf("expected helper RestoreFromSnapshot not called on clean rollback, got %d", gotRestore)
		}
	})

	t.Run("Stop error or ErrTUNRollbackIncomplete triggers fallback RestoreTUNSession", func(t *testing.T) {
		hostSigner := generateTestEd25519Signer(t)
		sshSrv := startInMemoryPAMSSHServer(t, sshUser, sshPass, hostSigner)

		// Case A: Stop returns error on Disconnect -> RestoreFromSnapshot runs via fallback launch.
		helperMockStopErr := newMockTUNSessionController()
		helperMockStopErr.stats = tun.Stats{Running: true, IfaceName: splitroute.TUNIfaceName}
		helperMockStopErr.stopErr = errors.New("rpc stop failed")
		helperMockStopErr.onStop = func(context.Context) {
			helperMockStopErr.mu.Lock()
			helperMockStopErr.stats.Running = false
			helperMockStopErr.mu.Unlock()
		}
		launcherA, helperDoneA := makePipeHelper(helperMockStopErr)
		guiCtrlA := newHelperTUNController(TUNCapsDTO{Supported: true, RequiresElevation: true}, launcherA, &mockRouteManager{}, discardLogger())

		resolveFn := func(context.Context, string) (netip.Addr, error) {
			return netip.MustParseAddr(sshSrv.host), nil
		}
		hA := newTUNAppHarness(t, 50*time.Millisecond, guiCtrlA, resolveFn, nil, nil, nil)
		hA.svc.Startup(ctx)
		_ = hA.svc.UnlockVault("VaultPass!FallbackA")
		profA := savePinnedTUNProfile(t, hA, "FallbackA", sshSrv.host, sshSrv.port, hostSigner)
		if err := hA.svc.Connect(profA.ID, string(profile.ModeTUN)); err != nil {
			t.Fatalf("Connect FallbackA: %v", err)
		}
		_ = hA.svc.Disconnect()
		for i := 0; i < 2; i++ {
			select {
			case <-helperDoneA:
			case <-time.After(3 * time.Second):
				t.Fatalf("timed out waiting for helperDoneA #%d", i)
			}
		}
		helperMockStopErr.mu.Lock()
		gotRestoreA := helperMockStopErr.restoreCalls
		helperMockStopErr.mu.Unlock()
		if launcherA.Calls() != 2 || gotRestoreA != 1 {
			t.Fatalf("expected fallback launch + RestoreFromSnapshot on Stop error, got launches=%d restore=%d", launcherA.Calls(), gotRestoreA)
		}
		if rec, err := hA.recStore.Load(); err != nil || rec == nil || rec.Dirty {
			t.Fatalf("expected clean recovery_state.json after fallback restore, got %+v (err=%v)", rec, err)
		}

		// Case B: StartTUN returns ErrTUNRollbackIncomplete -> RestoreFromSnapshot runs via fallback launch.
		helperMockIncomplete := newMockTUNSessionController()
		helperMockIncomplete.startErr = fmt.Errorf("apply fail: %w", ErrTUNRollbackIncomplete)
		launcherB, helperDoneB := makePipeHelper(helperMockIncomplete)
		guiCtrlB := newHelperTUNController(TUNCapsDTO{Supported: true, RequiresElevation: true}, launcherB, &mockRouteManager{}, discardLogger())

		hB := newTUNAppHarness(t, 50*time.Millisecond, guiCtrlB, resolveFn, nil, nil, nil)
		hB.svc.Startup(ctx)
		_ = hB.svc.UnlockVault("VaultPass!FallbackB")
		profB := savePinnedTUNProfile(t, hB, "FallbackB", sshSrv.host, sshSrv.port, hostSigner)
		if err := hB.svc.Connect(profB.ID, string(profile.ModeTUN)); err == nil {
			t.Fatalf("expected StartTUN error")
		}
		for i := 0; i < 2; i++ {
			select {
			case <-helperDoneB:
			case <-time.After(3 * time.Second):
				t.Fatalf("timed out waiting for helperDoneB #%d", i)
			}
		}
		helperMockIncomplete.mu.Lock()
		gotRestoreB := helperMockIncomplete.restoreCalls
		helperMockIncomplete.mu.Unlock()
		if launcherB.Calls() != 2 || gotRestoreB != 1 {
			t.Fatalf("expected fallback launch + RestoreFromSnapshot on ErrTUNRollbackIncomplete, got launches=%d restore=%d", launcherB.Calls(), gotRestoreB)
		}
		if rec, err := hB.recStore.Load(); err != nil || rec == nil || rec.Dirty {
			t.Fatalf("expected clean recovery_state.json after incomplete rollback restore, got %+v (err=%v)", rec, err)
		}
	})
}
