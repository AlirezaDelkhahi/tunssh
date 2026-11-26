//go:build linux

package mobile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/AlirezaDelkhahi/tunssh/internal/crypto"
)

type recordingListener struct {
	mu       sync.Mutex
	statuses []statusDTO
	prompts  []hostKeyPromptDTO
	logs     []logEntryDTO
	onEvent  func()
}

func (l *recordingListener) OnStatusChanged(statusJSON string) {
	if l.onEvent != nil {
		l.onEvent()
	}
	var dto statusDTO
	if err := json.Unmarshal([]byte(statusJSON), &dto); err == nil {
		l.mu.Lock()
		l.statuses = append(l.statuses, dto)
		l.mu.Unlock()
	}
}

func (l *recordingListener) OnHostKeyPrompt(promptJSON string) {
	if l.onEvent != nil {
		l.onEvent()
	}
	var dto hostKeyPromptDTO
	if err := json.Unmarshal([]byte(promptJSON), &dto); err == nil {
		l.mu.Lock()
		l.prompts = append(l.prompts, dto)
		l.mu.Unlock()
	}
}

func (l *recordingListener) OnLog(entryJSON string) {
	if l.onEvent != nil {
		l.onEvent()
	}
	var dto logEntryDTO
	if err := json.Unmarshal([]byte(entryJSON), &dto); err == nil {
		l.mu.Lock()
		l.logs = append(l.logs, dto)
		l.mu.Unlock()
	}
}

func (l *recordingListener) Prompts() []hostKeyPromptDTO {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]hostKeyPromptDTO, len(l.prompts))
	copy(out, l.prompts)
	return out
}

func (l *recordingListener) Statuses() []statusDTO {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]statusDTO, len(l.statuses))
	copy(out, l.statuses)
	return out
}

type mockProtector struct {
	calls  atomic.Int32
	reject atomic.Bool
}

func (p *mockProtector) Protect(fd int32) bool {
	p.calls.Add(1)
	if p.reject.Load() {
		return false
	}
	return fd >= 0
}

type testSSHServer struct {
	ln        net.Listener
	host      string
	port      int
	signer    ssh.Signer
	allowAuth atomic.Bool
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     []net.Conn
	closed    atomic.Bool
}

func startTestSSHServer(t *testing.T, password string) *testSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new ssh signer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	srv := &testSSHServer{
		ln:     ln,
		host:   "127.0.0.1",
		port:   tcpAddr.Port,
		signer: signer,
	}
	srv.allowAuth.Store(true)

	srvCfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if srv.allowAuth.Load() && string(pass) == password {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("invalid password")
		},
	}
	srvCfg.AddHostKey(signer)

	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			srv.mu.Lock()
			srv.conns = append(srv.conns, raw)
			srv.mu.Unlock()

			srv.wg.Add(1)
			go func(c net.Conn) {
				defer srv.wg.Done()
				defer c.Close()
				sConn, chans, reqs, err := ssh.NewServerConn(c, srvCfg)
				if err != nil {
					return
				}
				defer sConn.Close()
				go func() {
					for req := range reqs {
						if req.WantReply {
							_ = req.Reply(true, nil)
						}
					}
				}()
				for newChan := range chans {
					_ = newChan.Reject(ssh.Prohibited, "unused")
				}
			}(raw)
		}
	}()

	t.Cleanup(srv.Close)
	return srv
}

func (s *testSSHServer) DropActiveConns() {
	s.mu.Lock()
	conns := append([]net.Conn(nil), s.conns...)
	s.conns = nil
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *testSSHServer) Close() {
	if s.closed.Swap(true) {
		return
	}
	_ = s.ln.Close()
	s.DropActiveConns()
	s.wg.Wait()
}

func assertFDClosed(t *testing.T, fd int) {
	t.Helper()
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("expected fd %d to be closed (EBADF), got err=%v", fd, err)
	}
}

func newSocketpairFD(t *testing.T) (int, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[1])
		if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			_ = unix.Close(fds[0])
		}
	})
	return fds[0], fds[1]
}

func TestGomobileExportSurface(t *testing.T) {
	allowedTopLevel := map[string]bool{
		"SocketProtector":  true,
		"EventListener":    true,
		"Engine":           true,
		"NewEngine":        true,
		"BuildVpnPlan":     true,
		"InspectShareLink": true,
		"DecodeShareLink":  true,
		"EncodeShareLink":  true,
	}
	allowedReceivers := map[string]bool{
		"Engine": true,
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("expected at least one non-test Go source file in mobile/")
	}

	var assertGobindSafeType func(ctx string, expr ast.Expr)
	assertGobindSafeType = func(ctx string, expr ast.Expr) {
		switch typ := expr.(type) {
		case nil:
		case *ast.Ident:
			switch typ.Name {
			case "uint64", "uint", "uint8", "uint16", "uint32", "uintptr", "int", "int8", "int16", "int64":
				if typ.Name == "int64" {
					return
				}
				t.Fatalf("%s uses unsupported gobind integer type %q", ctx, typ.Name)
			}
		case *ast.StarExpr:
			assertGobindSafeType(ctx, typ.X)
		case *ast.ArrayType:
			// Only []byte is allowed by gobind.
			if typ.Len == nil {
				if id, ok := typ.Elt.(*ast.Ident); ok && id.Name == "byte" {
					return
				}
			}
			t.Fatalf("%s uses unsupported gobind slice/array type", ctx)
		case *ast.MapType:
			t.Fatalf("%s uses unsupported gobind map type", ctx)
		case *ast.FuncType:
			t.Fatalf("%s uses unsupported gobind func type", ctx)
		case *ast.ChanType:
			t.Fatalf("%s uses unsupported gobind chan type", ctx)
		case *ast.SelectorExpr:
			if pkgID, ok := typ.X.(*ast.Ident); ok {
				if pkgID.Name == "context" || pkgID.Name == "slog" {
					t.Fatalf("%s uses forbidden gobind package selector %s.%s", ctx, pkgID.Name, typ.Sel.Name)
				}
			}
			t.Fatalf("%s uses external selector type in exported signature", ctx)
		case *ast.StructType:
			if typ.Fields != nil {
				for _, field := range typ.Fields.List {
					for _, fname := range field.Names {
						if fname.IsExported() {
							t.Fatalf("%s exports struct field %s", ctx, fname.Name)
						}
					}
					if len(field.Names) == 0 {
						// Embedded field
						assertGobindSafeType(ctx+" (embedded)", field.Type)
					}
				}
			}
		case *ast.InterfaceType:
			if typ.Methods != nil {
				for _, m := range typ.Methods.List {
					if fn, ok := m.Type.(*ast.FuncType); ok {
						mName := "<anon>"
						if len(m.Names) > 0 {
							mName = m.Names[0].Name
						}
						if fn.Params != nil {
							for _, p := range fn.Params.List {
								assertGobindSafeType(ctx+"."+mName+" param", p.Type)
							}
						}
						if fn.Results != nil {
							for _, r := range fn.Results.List {
								assertGobindSafeType(ctx+"."+mName+" result", r.Type)
							}
						}
					} else {
						assertGobindSafeType(ctx+" interface embed", m.Type)
					}
				}
			}
		}
	}

	seenExported := make(map[string]bool)
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							if !allowedTopLevel[s.Name.Name] {
								t.Fatalf("unexpected exported type %q in mobile/", s.Name.Name)
							}
							seenExported[s.Name.Name] = true
							assertGobindSafeType("type "+s.Name.Name, s.Type)
						}
					case *ast.ValueSpec:
						for _, id := range s.Names {
							if id.IsExported() {
								t.Fatalf("unexpected exported const/var %q in mobile/", id.Name)
							}
						}
					}
				}
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv == nil {
					if !allowedTopLevel[d.Name.Name] {
						t.Fatalf("unexpected exported function %q in mobile/", d.Name.Name)
					}
					seenExported[d.Name.Name] = true
				} else {
					var recvName string
					if len(d.Recv.List) > 0 {
						rt := d.Recv.List[0].Type
						if star, ok := rt.(*ast.StarExpr); ok {
							rt = star.X
						}
						if id, ok := rt.(*ast.Ident); ok {
							recvName = id.Name
						}
					}
					if !allowedReceivers[recvName] {
						// Unexported receiver types are ignored by gobind; only allow interface-required
						// methods on redactingHandler (slog.Handler) and protectedBypassDialer (dns.Dialer).
						if recvName != "redactingHandler" && recvName != "protectedBypassDialer" {
							t.Fatalf("unexpected exported method %s.%s in mobile/", recvName, d.Name.Name)
						}
						continue
					}
				}
				if d.Type.Params != nil {
					for _, p := range d.Type.Params.List {
						assertGobindSafeType(d.Name.Name+" param", p.Type)
					}
				}
				if d.Type.Results != nil {
					for _, r := range d.Type.Results.List {
						assertGobindSafeType(d.Name.Name+" result", r.Type)
					}
				}
			}
		}
	}

	for name := range allowedTopLevel {
		if !seenExported[name] {
			t.Fatalf("expected exported symbol %q in mobile/", name)
		}
	}
}

func TestBypassDNSNormalizationFiltersLinkLocal(t *testing.T) {
	norm := normalizeUpstreamDNSList([]string{
		"",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"224.0.0.251",
		"169.254.1.1",
		"fe80::1",
		"FE80::2",
		"[fe80::1]:53",
		"1.1.1.1",
		"8.8.8.8:5353",
		"1.1.1.1",
	})
	if len(norm) != 2 || norm[0] != "1.1.1.1" || norm[1] != "8.8.8.8:5353" {
		t.Fatalf("normalizeUpstreamDNSList() = %v, want [1.1.1.1 8.8.8.8:5353]", norm)
	}

	// Only link-local/loopback inputs -> falls back to defaultMobileBypassDNS.
	onlyLocal := normalizeUpstreamDNSList([]string{"fe80::1", "169.254.10.1", "127.0.0.1"})
	if len(onlyLocal) != 0 {
		t.Fatalf("expected empty normalized list for link-local/loopback inputs, got %v", onlyLocal)
	}
	bypass := normalizeBypassUpstreams(onlyLocal)
	if len(bypass) != 1 || bypass[0] != defaultMobileBypassDNS {
		t.Fatalf("normalizeBypassUpstreams() = %v, want [%s]", bypass, defaultMobileBypassDNS)
	}
}

func TestBuildVpnPlan(t *testing.T) {
	planV4OnlyJSON, err := BuildVpnPlan(true, false, 0)
	if err != nil {
		t.Fatalf("BuildVpnPlan(true, false, 0) failed: %v", err)
	}
	var planV4Only vpnPlanDTO
	if err := json.Unmarshal([]byte(planV4OnlyJSON), &planV4Only); err != nil {
		t.Fatalf("unmarshal planV4Only: %v", err)
	}
	if planV4Only.MTU != 1380 {
		t.Fatalf("default MTU = %d, want 1380", planV4Only.MTU)
	}
	if planV4Only.TunIPv4Addr != "198.18.0.1" || planV4Only.TunIPv4Prefix != 15 {
		t.Fatalf("unexpected tun ipv4: %s/%d", planV4Only.TunIPv4Addr, planV4Only.TunIPv4Prefix)
	}
	if planV4Only.DNSIPv4 != "198.18.0.2" {
		t.Fatalf("dns_ipv4 = %q, want 198.18.0.2", planV4Only.DNSIPv4)
	}
	if planV4Only.TunIPv6Addr != "" || planV4Only.TunIPv6Prefix != 0 {
		t.Fatalf("expected empty IPv6 config when enableIPv6=false, got %s/%d", planV4Only.TunIPv6Addr, planV4Only.TunIPv6Prefix)
	}
	for _, r := range planV4Only.Routes {
		addr, err := netip.ParseAddr(r.Address)
		if err != nil || !addr.Is4() {
			t.Fatalf("expected only IPv4 routes when enableIPv6=false, got %+v (err=%v)", r, err)
		}
	}

	planDualJSON, err := BuildVpnPlan(false, true, 1420)
	if err != nil {
		t.Fatalf("BuildVpnPlan(false, true, 1420) failed: %v", err)
	}
	var planDual vpnPlanDTO
	if err := json.Unmarshal([]byte(planDualJSON), &planDual); err != nil {
		t.Fatalf("unmarshal planDual: %v", err)
	}
	if planDual.MTU != 1420 {
		t.Fatalf("MTU = %d, want 1420", planDual.MTU)
	}
	if planDual.TunIPv6Addr != "fd98:18::1" || planDual.TunIPv6Prefix != 64 {
		t.Fatalf("unexpected tun ipv6: %s/%d", planDual.TunIPv6Addr, planDual.TunIPv6Prefix)
	}

	var hasV6Low, hasV6High bool
	for _, r := range planDual.Routes {
		if r.Address == "::" && r.Prefix == 1 {
			hasV6Low = true
		}
		if r.Address == "8000::" && r.Prefix == 1 {
			hasV6High = true
		}
	}
	if !hasV6Low || !hasV6High {
		t.Fatalf("expected ::/1 and 8000::/1 in IPv6-enabled plan routes; hasV6Low=%v hasV6High=%v", hasV6Low, hasV6High)
	}
}

func TestShareLinkBridge(t *testing.T) {
	payload := sharePayloadDTO{
		Name:     "Prod VPS",
		Host:     "example.com",
		Port:     22,
		User:     "root",
		AuthType: "password",
		Secret:   "super-secret-pass",
		HostKey: &shareHostKeyDTO{
			Alg:    "ssh-ed25519",
			SHA256: "SHA256:abc123",
		},
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	// Default plain without passphrase and allowPlain=false must fail.
	if _, err := EncodeShareLink(string(rawPayload), "", false); !errors.Is(err, crypto.ErrPlainShareNotAllowed) {
		t.Fatalf("expected ErrPlainShareNotAllowed, got %v", err)
	}

	// Encrypted encode -> inspect -> decode.
	encLink, err := EncodeShareLink(string(rawPayload), "my-passphrase", false)
	if err != nil {
		t.Fatalf("EncodeShareLink encrypted failed: %v", err)
	}
	metaJSON, err := InspectShareLink(encLink)
	if err != nil {
		t.Fatalf("InspectShareLink failed: %v", err)
	}
	var meta shareLinkMetaDTO
	if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if meta.Version != 1 || meta.Mode != crypto.ModeEncrypted {
		t.Fatalf("unexpected meta: %+v", meta)
	}

	if _, err := DecodeShareLink(encLink, "wrong-passphrase", false); err == nil {
		t.Fatal("expected DecodeShareLink with wrong passphrase to fail")
	}
	decJSON, err := DecodeShareLink(encLink, "my-passphrase", false)
	if err != nil {
		t.Fatalf("DecodeShareLink encrypted failed: %v", err)
	}
	var dec sharePayloadDTO
	if err := json.Unmarshal([]byte(decJSON), &dec); err != nil {
		t.Fatalf("unmarshal decoded: %v", err)
	}
	if dec.Mode != crypto.ModeEncrypted || dec.Secret != payload.Secret || dec.HostKey == nil || dec.HostKey.SHA256 != payload.HostKey.SHA256 {
		t.Fatalf("decoded payload mismatch: %+v", dec)
	}

	// Plain encode gated on allowPlain=true; decode gated on allowPlain=true.
	plainLink, err := EncodeShareLink(string(rawPayload), "", true)
	if err != nil {
		t.Fatalf("EncodeShareLink plain failed: %v", err)
	}
	plainMetaJSON, err := InspectShareLink(plainLink)
	if err != nil {
		t.Fatalf("InspectShareLink plain failed: %v", err)
	}
	var plainMeta shareLinkMetaDTO
	if err := json.Unmarshal([]byte(plainMetaJSON), &plainMeta); err != nil {
		t.Fatalf("unmarshal plainMeta: %v", err)
	}
	if plainMeta.Mode != crypto.ModePlain || !plainMeta.HasHostKey {
		t.Fatalf("unexpected plain meta: %+v", plainMeta)
	}
	if _, err := DecodeShareLink(plainLink, "", false); !errors.Is(err, crypto.ErrPlainShareNotAllowed) {
		t.Fatalf("expected ErrPlainShareNotAllowed on DecodeShareLink plain without allowPlain, got %v", err)
	}
	plainDecJSON, err := DecodeShareLink(plainLink, "", true)
	if err != nil {
		t.Fatalf("DecodeShareLink plain failed: %v", err)
	}
	var plainDec sharePayloadDTO
	if err := json.Unmarshal([]byte(plainDecJSON), &plainDec); err != nil {
		t.Fatalf("unmarshal plainDec: %v", err)
	}
	if plainDec.Mode != crypto.ModePlain || plainDec.Secret != payload.Secret {
		t.Fatalf("plain decoded payload mismatch: %+v", plainDec)
	}
}

func TestEngine_Lifecycle_TOFU_AttachReplaceNotifyStop_AndSecretScrubbing(t *testing.T) {
	const secretPass = "SuperSecretPassword-XYZ-987!"
	srv := startTestSSHServer(t, secretPass)

	var eng *Engine
	listener := &recordingListener{
		onEvent: func() {
			// Verify no mutex is held across EventListener callbacks by calling read methods re-entrantly.
			if eng != nil {
				_ = eng.StatusJson()
				_ = eng.LogsJson()
			}
		},
	}
	eng = NewEngine(listener)
	protector := &mockProtector{}

	// 1. Initial ConnectSsh without pinned host key -> TOFU OnHostKeyPrompt + error.
	cfgUntrusted := connectConfigDTO{
		ProfileID:     "p1",
		Host:          srv.host,
		Port:          srv.port,
		Username:      "tester",
		AuthType:      "password",
		Password:      secretPass,
		BypassIranLAN: true,
		EnableIPv6:    false,
		UpstreamDNS:   []string{"1.1.1.1"},
	}
	rawUntrusted, _ := json.Marshal(cfgUntrusted)
	if err := eng.ConnectSsh(string(rawUntrusted), protector); err == nil {
		t.Fatal("expected initial ConnectSsh without pinned host key to fail with TOFU untrusted error")
	}
	if protector.calls.Load() == 0 {
		t.Fatal("expected SocketProtector.Protect to be called during dial")
	}

	prompts := listener.Prompts()
	if len(prompts) == 0 {
		t.Fatal("expected OnHostKeyPrompt to be emitted on untrusted host key")
	}
	lastPrompt := prompts[len(prompts)-1]
	if lastPrompt.Mismatch {
		t.Fatalf("expected Mismatch=false on TOFU prompt, got %+v", lastPrompt)
	}
	expectedAlg := srv.signer.PublicKey().Type()
	expectedFP := ssh.FingerprintSHA256(srv.signer.PublicKey())
	if lastPrompt.Algorithm != expectedAlg || lastPrompt.SHA256 != expectedFP {
		t.Fatalf("unexpected prompt fingerprint: got (%s %s), want (%s %s)",
			lastPrompt.Algorithm, lastPrompt.SHA256, expectedAlg, expectedFP)
	}

	// 2. Mismatched pinned host key -> OnHostKeyPrompt with Mismatch=true + error.
	cfgMismatch := cfgUntrusted
	cfgMismatch.PinnedHostKey = &hostKeyPinDTO{
		Algorithm: lastPrompt.Algorithm,
		SHA256:    "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	rawMismatch, _ := json.Marshal(cfgMismatch)
	if err := eng.ConnectSsh(string(rawMismatch), protector); err == nil {
		t.Fatal("expected ConnectSsh with mismatched host key to fail")
	}
	promptsAfterMismatch := listener.Prompts()
	mismatchPrompt := promptsAfterMismatch[len(promptsAfterMismatch)-1]
	if !mismatchPrompt.Mismatch || mismatchPrompt.ExpectedSHA256 != cfgMismatch.PinnedHostKey.SHA256 {
		t.Fatalf("expected Mismatch=true with ExpectedSHA256=%q, got %+v", cfgMismatch.PinnedHostKey.SHA256, mismatchPrompt)
	}

	// 3. Re-connect with pinned host key -> succeeds.
	cfgPinned := cfgUntrusted
	cfgPinned.PinnedHostKey = &hostKeyPinDTO{
		Algorithm: lastPrompt.Algorithm,
		SHA256:    lastPrompt.SHA256,
	}
	rawPinned, _ := json.Marshal(cfgPinned)
	if err := eng.ConnectSsh(string(rawPinned), protector); err != nil {
		t.Fatalf("ConnectSsh with pinned host key failed: %v", err)
	}

	var st statusDTO
	if err := json.Unmarshal([]byte(eng.StatusJson()), &st); err != nil {
		t.Fatalf("unmarshal StatusJson: %v", err)
	}
	if st.State != "connected" || st.TunAttached || !st.BypassIranLAN || st.ProfileID != "p1" {
		t.Fatalf("unexpected connected status before AttachTun: %+v", st)
	}

	// 4. AttachTun(fd1) -> starts DNS + TUN.
	fd1, _ := newSocketpairFD(t)
	if err := eng.AttachTun(int32(fd1)); err != nil {
		t.Fatalf("AttachTun(fd1) failed: %v", err)
	}
	if err := json.Unmarshal([]byte(eng.StatusJson()), &st); err != nil {
		t.Fatalf("unmarshal StatusJson after AttachTun: %v", err)
	}
	if !st.TunAttached || st.State != "connected" {
		t.Fatalf("expected TunAttached=true and State=connected, got %+v", st)
	}

	// 5. SetBypass(false) -> updates status and DNS.
	if err := eng.SetBypass(false); err != nil {
		t.Fatalf("SetBypass(false) failed: %v", err)
	}
	if err := json.Unmarshal([]byte(eng.StatusJson()), &st); err != nil {
		t.Fatalf("unmarshal StatusJson after SetBypass: %v", err)
	}
	if st.BypassIranLAN {
		t.Fatalf("expected BypassIranLAN=false after SetBypass(false)")
	}

	// 6. ReplaceTun(fd2) -> swaps TUN runner without dropping SSH and closes fd1.
	fd2, _ := newSocketpairFD(t)
	if err := eng.ReplaceTun(int32(fd2)); err != nil {
		t.Fatalf("ReplaceTun(fd2) failed: %v", err)
	}
	assertFDClosed(t, fd1)

	if err := json.Unmarshal([]byte(eng.StatusJson()), &st); err != nil {
		t.Fatalf("unmarshal StatusJson after ReplaceTun: %v", err)
	}
	if st.State != "connected" || !st.TunAttached {
		t.Fatalf("expected SSH connected and TUN attached after ReplaceTun, got %+v", st)
	}

	// 7. NotifyNetworkChanged -> updates DNS upstreams + async RTT probe without blocking.
	if err := eng.NotifyNetworkChanged(`["8.8.8.8", "1.1.1.1"]`); err != nil {
		t.Fatalf("NotifyNetworkChanged failed: %v", err)
	}
	if err := eng.NotifyNetworkChanged(`not-json`); err == nil {
		t.Fatal("expected NotifyNetworkChanged with invalid JSON to return error")
	}

	// Log something mentioning the secret to verify scrubber catches it in LogsJson.
	eng.logger.Info("diagnostic check", "details", fmt.Sprintf("pass=%s", secretPass))

	// 8. Stop() -> closes fd2, disconnects SSH, scrubs secrets from logs.
	if err := eng.Stop(); err != nil {
		t.Fatalf("Engine.Stop failed: %v", err)
	}
	assertFDClosed(t, fd2)

	if err := json.Unmarshal([]byte(eng.StatusJson()), &st); err != nil {
		t.Fatalf("unmarshal StatusJson after Stop: %v", err)
	}
	if st.State != "disconnected" || st.TunAttached {
		t.Fatalf("expected disconnected and TunAttached=false after Stop, got %+v", st)
	}

	logsJSON := eng.LogsJson()
	if strings.Contains(logsJSON, secretPass) {
		t.Fatalf("LogsJson leaked secret password: %s", logsJSON)
	}
	if !strings.Contains(logsJSON, redactedPlaceholder) {
		t.Fatalf("expected redacted placeholder in LogsJson: %s", logsJSON)
	}

	eng.ClearLogs()
	if got := eng.LogsJson(); got != "[]" {
		t.Fatalf("LogsJson after ClearLogs = %q, want []", got)
	}

	// 9. AttachTun on disconnected engine must still close tunFD cleanly.
	fd3, _ := newSocketpairFD(t)
	if err := eng.AttachTun(int32(fd3)); err == nil {
		t.Fatal("expected AttachTun on disconnected engine to fail")
	}
	assertFDClosed(t, fd3)

	_ = io.EOF
}

func TestEngine_RuntimeStateErrorTearsDownTUN(t *testing.T) {
	const secretPass = "RuntimeDropPass-123"
	srv := startTestSSHServer(t, secretPass)
	listener := &recordingListener{}
	eng := NewEngine(listener)
	protector := &mockProtector{}

	cfg := connectConfigDTO{
		ProfileID: "p-err",
		Host:      srv.host,
		Port:      srv.port,
		Username:  "tester",
		AuthType:  "password",
		Password:  secretPass,
		PinnedHostKey: &hostKeyPinDTO{
			Algorithm: srv.signer.PublicKey().Type(),
			SHA256:    ssh.FingerprintSHA256(srv.signer.PublicKey()),
		},
		BypassIranLAN: true,
		UpstreamDNS:   []string{"1.1.1.1"},
	}
	rawCfg, _ := json.Marshal(cfg)
	if err := eng.ConnectSsh(string(rawCfg), protector); err != nil {
		t.Fatalf("ConnectSsh failed: %v", err)
	}

	fd, _ := newSocketpairFD(t)
	if err := eng.AttachTun(int32(fd)); err != nil {
		t.Fatalf("AttachTun failed: %v", err)
	}

	// Force non-retryable auth failure on reconnect, then drop active SSH connection.
	srv.allowAuth.Store(false)
	srv.DropActiveConns()

	deadline := time.Now().Add(5 * time.Second)
	var finalStatus statusDTO
	for time.Now().Before(deadline) {
		_ = json.Unmarshal([]byte(eng.StatusJson()), &finalStatus)
		if finalStatus.State == "error" && !finalStatus.TunAttached {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); errors.Is(err, unix.EBADF) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if finalStatus.State != "error" || finalStatus.TunAttached {
		t.Fatalf("expected runtime StateError to tear down TUN (state=error, tun_attached=false), got %+v", finalStatus)
	}
	if finalStatus.LastError == nil || finalStatus.LastError.Code == "" {
		t.Fatalf("expected LastError to be preserved after runtime StateError teardown, got %+v", finalStatus.LastError)
	}
	assertFDClosed(t, fd)

	if err := eng.Stop(); err != nil {
		t.Fatalf("Stop after runtime error teardown failed: %v", err)
	}
}

func TestResolvePeerIP_FallsBackPastBlackholeUDPServer(t *testing.T) {
	deadConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole udp: %v", err)
	}
	t.Cleanup(func() {
		_ = deadConn.Close()
	})

	liveConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen live udp: %v", err)
	}
	liveAddr := liveConn.LocalAddr().String()

	started := make(chan struct{})
	srv := &mdns.Server{
		PacketConn: liveConn,
		NotifyStartedFunc: func() {
			close(started)
		},
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
			resp := new(mdns.Msg)
			resp.SetReply(r)
			resp.RecursionAvailable = true
			if len(r.Question) > 0 && strings.EqualFold(r.Question[0].Name, "vps.example.test.") && r.Question[0].Qtype == mdns.TypeA {
				resp.Answer = []mdns.RR{
					&mdns.A{
						Hdr: mdns.RR_Header{
							Name:   r.Question[0].Name,
							Rrtype: mdns.TypeA,
							Class:  mdns.ClassINET,
							Ttl:    60,
						},
						A: net.ParseIP("203.0.113.42").To4(),
					},
				}
			}
			_ = w.WriteMsg(resp)
		}),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown()
	})

	select {
	case <-started:
	case serveErr := <-errCh:
		t.Fatalf("miekg/dns server exited early: %v", serveErr)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for live DNS server to start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	noopProtector := &mockProtector{}
	got, err := resolvePeerIP(ctx, "vps.example.test", []string{deadConn.LocalAddr().String(), liveAddr}, noopProtector)
	if err != nil {
		t.Fatalf("resolvePeerIP failed: %v", err)
	}
	if got != "203.0.113.42" {
		t.Fatalf("resolvePeerIP = %q, want %q", got, "203.0.113.42")
	}
	if noopProtector.calls.Load() < 2 {
		t.Fatalf("expected SocketProtector.Protect to be called for blackhole and live DNS attempts, got %d", noopProtector.calls.Load())
	}
}
