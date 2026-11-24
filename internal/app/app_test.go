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
	"os"
	"path/filepath"
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
	"github.com/AlirezaDelkhahi/tunssh/internal/sshclient"
	"github.com/AlirezaDelkhahi/tunssh/internal/sysproxy"
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
