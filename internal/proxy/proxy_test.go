package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type dialCall struct {
	network string
	address string
}

type mockDialer struct {
	mu    sync.Mutex
	calls []dialCall
	fn    func(ctx context.Context, network, address string) (net.Conn, error)
}

func (m *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	m.mu.Lock()
	m.calls = append(m.calls, dialCall{network: network, address: address})
	fn := m.fn
	m.mu.Unlock()

	if fn != nil {
		return fn(ctx, network, address)
	}
	return nil, errors.New("mock dialer: no handler configured")
}

func (m *mockDialer) Calls() []dialCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]dialCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// startEchoTCPServer launches an in-memory local TCP echo server that supports half-close.
func startEchoTCPServer(t *testing.T) (addr string, closeFn func()) {
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

	return ln.Addr().String(), func() {
		_ = ln.Close()
		wg.Wait()
	}
}

func startTestServer(t *testing.T, dialer Dialer, cfg Config) *Server {
	t.Helper()
	if cfg.SOCKSAddr == "" {
		cfg.SOCKSAddr = "127.0.0.1:0"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = "127.0.0.1:0"
	}
	srv, err := NewServer(dialer, cfg)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Stop(ctx); err != nil {
			t.Errorf("Stop() cleanup error = %v", err)
		}
	})
	return srv
}

func socks5Handshake(t *testing.T, conn net.Conn, atyp byte, hostBytes []byte, port uint16) byte {
	t.Helper()
	// Greeting: VER=0x05, NMETHODS=1, METHOD=0x00 (NO AUTH)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		t.Fatalf("read SOCKS5 method selection: %v", err)
	}
	if methodResp != [2]byte{0x05, 0x00} {
		t.Fatalf("unexpected SOCKS5 method reply: %x", methodResp)
	}

	req := make([]byte, 0, 4+len(hostBytes)+2)
	req = append(req, 0x05, 0x01, 0x00, atyp)
	req = append(req, hostBytes...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	req = append(req, portBuf[:]...)

	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write SOCKS5 connect request: %v", err)
	}

	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read SOCKS5 reply header: %v", err)
	}
	if hdr[0] != 0x05 {
		t.Fatalf("unexpected SOCKS5 reply version: %x", hdr[0])
	}
	switch hdr[3] {
	case 0x01:
		var rest [6]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			t.Fatalf("read SOCKS5 IPv4 bind addr: %v", err)
		}
	case 0x04:
		var rest [18]byte
		if _, err := io.ReadFull(conn, rest[:]); err != nil {
			t.Fatalf("read SOCKS5 IPv6 bind addr: %v", err)
		}
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			t.Fatalf("read SOCKS5 domain len: %v", err)
		}
		rest := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(conn, rest); err != nil {
			t.Fatalf("read SOCKS5 domain bind addr: %v", err)
		}
	default:
		t.Fatalf("unexpected SOCKS5 reply ATYP: %x", hdr[3])
	}
	return hdr[1]
}

func TestNewServerValidationAndDefaults(t *testing.T) {
	if _, err := NewServer(nil, Config{}); err == nil {
		t.Fatal("NewServer(nil, ...) expected error, got nil")
	}

	srv, err := NewServer(&mockDialer{}, Config{})
	if err != nil {
		t.Fatalf("NewServer with defaults failed: %v", err)
	}
	if srv.SOCKSAddr() != DefaultSOCKSAddr {
		t.Fatalf("SOCKSAddr() = %q, want %q", srv.SOCKSAddr(), DefaultSOCKSAddr)
	}
	if srv.HTTPAddr() != DefaultHTTPAddr {
		t.Fatalf("HTTPAddr() = %q, want %q", srv.HTTPAddr(), DefaultHTTPAddr)
	}
}

func TestLoopbackAddrGuardRejectsNonLoopback(t *testing.T) {
	badAddrs := []string{
		"0.0.0.0:10808",
		"[::]:10808",
		":10808",
		"192.168.1.50:10808",
		"8.8.8.8:10809",
		"example.com:10808",
		"not-a-host-port",
		"127.0.0.1:",
	}
	for _, addr := range badAddrs {
		if isLoopbackAddr(addr) {
			t.Errorf("isLoopbackAddr(%q) = true, want false", addr)
		}
		if _, err := NewServer(&mockDialer{}, Config{SOCKSAddr: addr, HTTPAddr: "127.0.0.1:0"}); err == nil {
			t.Errorf("NewServer accepted non-loopback SOCKSAddr %q", addr)
		}
		if _, err := NewServer(&mockDialer{}, Config{SOCKSAddr: "127.0.0.1:0", HTTPAddr: addr}); err == nil {
			t.Errorf("NewServer accepted non-loopback HTTPAddr %q", addr)
		}
	}

	goodAddrs := []string{
		"127.0.0.1:10808",
		"127.0.0.2:10808",
		"[::1]:10808",
		"localhost:10809",
	}
	for _, addr := range goodAddrs {
		if !isLoopbackAddr(addr) {
			t.Errorf("isLoopbackAddr(%q) = false, want true", addr)
		}
	}
}

func TestSOCKS5DomainRemoteDNSAndBidirectionalRelay(t *testing.T) {
	echoAddr, stopEcho := startEchoTCPServer(t)
	defer stopEcho()

	dialer := &mockDialer{
		fn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", echoAddr)
		},
	}

	srv := startTestServer(t, dialer, Config{HandshakeTimeout: 2 * time.Second})

	conn, err := net.DialTimeout("tcp", srv.SOCKSAddr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	domain := "remote-only.internal"
	addrBytes := append([]byte{byte(len(domain))}, []byte(domain)...)
	rep := socks5Handshake(t, conn, 0x03, addrBytes, 8080)
	if rep != 0x00 {
		t.Fatalf("SOCKS5 reply = 0x%02x, want 0x00", rep)
	}

	calls := dialer.Calls()
	if len(calls) != 1 || calls[0].network != "tcp" || calls[0].address != "remote-only.internal:8080" {
		t.Fatalf("Dialer calls = %+v, want [{tcp remote-only.internal:8080}]", calls)
	}

	payload := []byte("hello-over-socks5h-tunnel-0123456789")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}

	echoed, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echoed = %q, want %q", echoed, payload)
	}

	// Wait briefly for relay goroutine to close and record stats.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		st := srv.Stats()
		if st.ActiveConns == 0 && st.TxBytes == uint64(len(payload)) && st.RxBytes == uint64(len(payload)) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	st := srv.Stats()
	t.Fatalf("unexpected Stats = %+v, want Tx=%d Rx=%d ActiveConns=0", st, len(payload), len(payload))
}

func TestSOCKS5AddressTypesAndErrorMapping(t *testing.T) {
	echoAddr, stopEcho := startEchoTCPServer(t)
	defer stopEcho()

	t.Run("ATYP_IPv4_and_IPv6", func(t *testing.T) {
		dialer := &mockDialer{
			fn: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", echoAddr)
			},
		}
		srv := startTestServer(t, dialer, Config{})

		// IPv4: 198.51.100.42:9000
		c4, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial SOCKS5: %v", err)
		}
		if rep := socks5Handshake(t, c4, 0x01, net.ParseIP("198.51.100.42").To4(), 9000); rep != 0x00 {
			t.Fatalf("IPv4 reply = 0x%02x, want 0x00", rep)
		}
		_ = c4.Close()

		// IPv6: [2001:db8::1]:443
		c6, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial SOCKS5: %v", err)
		}
		if rep := socks5Handshake(t, c6, 0x04, net.ParseIP("2001:db8::1").To16(), 443); rep != 0x00 {
			t.Fatalf("IPv6 reply = 0x%02x, want 0x00", rep)
		}
		_ = c6.Close()

		calls := dialer.Calls()
		if len(calls) != 2 {
			t.Fatalf("got %d dial calls, want 2", len(calls))
		}
		if calls[0].address != "198.51.100.42:9000" {
			t.Fatalf("calls[0] = %q, want 198.51.100.42:9000", calls[0].address)
		}
		if calls[1].address != "[2001:db8::1]:443" {
			t.Fatalf("calls[1] = %q, want [2001:db8::1]:443", calls[1].address)
		}
	})

	t.Run("AuthMethodRejected", func(t *testing.T) {
		srv := startTestServer(t, &mockDialer{}, Config{})
		conn, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial SOCKS5: %v", err)
		}
		defer conn.Close()

		// Only offer username/password auth (0x02)
		if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		var resp [2]byte
		if _, err := io.ReadFull(conn, resp[:]); err != nil {
			t.Fatalf("read method reply: %v", err)
		}
		if resp != [2]byte{0x05, 0xFF} {
			t.Fatalf("method reply = %x, want [05 ff]", resp)
		}
	})

	t.Run("UnsupportedCommandAndATYP", func(t *testing.T) {
		srv := startTestServer(t, &mockDialer{}, Config{})

		// CMD = 0x03 (UDP ASSOCIATE) -> REP = 0x07
		c1, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial SOCKS5: %v", err)
		}
		defer c1.Close()
		_, _ = c1.Write([]byte{0x05, 0x01, 0x00})
		var m [2]byte
		_, _ = io.ReadFull(c1, m[:])
		_, _ = c1.Write([]byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})
		var r1 [10]byte
		if _, err := io.ReadFull(c1, r1[:]); err != nil {
			t.Fatalf("read CMD unsupported reply: %v", err)
		}
		if r1[1] != 0x07 {
			t.Fatalf("CMD=0x03 reply = 0x%02x, want 0x07", r1[1])
		}

		// ATYP = 0x09 -> REP = 0x08
		c2, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial SOCKS5: %v", err)
		}
		defer c2.Close()
		_, _ = c2.Write([]byte{0x05, 0x01, 0x00})
		_, _ = io.ReadFull(c2, m[:])
		_, _ = c2.Write([]byte{0x05, 0x01, 0x00, 0x09, 0, 0, 0, 0, 0x00, 0x50})
		var r2 [10]byte
		if _, err := io.ReadFull(c2, r2[:]); err != nil {
			t.Fatalf("read ATYP unsupported reply: %v", err)
		}
		if r2[1] != 0x08 {
			t.Fatalf("ATYP=0x09 reply = 0x%02x, want 0x08", r2[1])
		}
	})

	t.Run("DialErrorMapping", func(t *testing.T) {
		cases := []struct {
			name    string
			dialErr error
			wantRep byte
		}{
			{"conn_refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, 0x05},
			{"host_unreach", &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, 0x04},
			{"general_failure", errors.New("ssh channel open failed"), 0x01},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				dialer := &mockDialer{
					fn: func(context.Context, string, string) (net.Conn, error) {
						return nil, tc.dialErr
					},
				}
				srv := startTestServer(t, dialer, Config{})
				conn, err := net.Dial("tcp", srv.SOCKSAddr())
				if err != nil {
					t.Fatalf("dial SOCKS5: %v", err)
				}
				defer conn.Close()

				domain := "target.internal"
				addrBytes := append([]byte{byte(len(domain))}, []byte(domain)...)
				rep := socks5Handshake(t, conn, 0x03, addrBytes, 443)
				if rep != tc.wantRep {
					t.Fatalf("SOCKS5 reply = 0x%02x, want 0x%02x", rep, tc.wantRep)
				}
			})
		}
	})
}

func TestSOCKS5HandshakeDeadlineClearedBeforeRelay(t *testing.T) {
	echoAddr, stopEcho := startEchoTCPServer(t)
	defer stopEcho()

	dialer := &mockDialer{
		fn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", echoAddr)
		},
	}
	srv := startTestServer(t, dialer, Config{HandshakeTimeout: 60 * time.Millisecond})

	// 1. Stalled handshake should be dropped shortly after HandshakeTimeout.
	stalled, err := net.Dial("tcp", srv.SOCKSAddr())
	if err != nil {
		t.Fatalf("dial SOCKS5: %v", err)
	}
	defer stalled.Close()
	_ = stalled.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := stalled.Read(b[:]); err == nil {
		t.Fatal("expected stalled handshake connection to close")
	}

	// 2. Established tunnel must survive longer than HandshakeTimeout.
	conn, err := net.Dial("tcp", srv.SOCKSAddr())
	if err != nil {
		t.Fatalf("dial SOCKS5: %v", err)
	}
	defer conn.Close()

	domain := "remote-only.internal"
	addrBytes := append([]byte{byte(len(domain))}, []byte(domain)...)
	if rep := socks5Handshake(t, conn, 0x03, addrBytes, 443); rep != 0x00 {
		t.Fatalf("SOCKS5 reply = 0x%02x, want 0x00", rep)
	}

	time.Sleep(100 * time.Millisecond)

	msg := []byte("after-handshake-timeout")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write after handshake timeout: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read after handshake timeout: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

func TestHTTPConnectBufferedBytesAndExactStats(t *testing.T) {
	echoAddr, stopEcho := startEchoTCPServer(t)
	defer stopEcho()

	dialer := &mockDialer{
		fn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", echoAddr)
		},
	}

	srv := startTestServer(t, dialer, Config{HandshakeTimeout: 2 * time.Second})

	conn, err := net.DialTimeout("tcp", srv.HTTPAddr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial HTTP proxy: %v", err)
	}
	defer conn.Close()

	pipelined := []byte("PIPELINED-TLS-CLIENT-HELLO")
	req := "CONNECT remote-only.internal:443 HTTP/1.1\r\nHost: remote-only.internal:443\r\n\r\n"
	if _, err := conn.Write(append([]byte(req), pipelined...)); err != nil {
		t.Fatalf("write CONNECT + pipelined bytes: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status line: %v", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 200 Connection Established") {
		t.Fatalf("status line = %q, want HTTP/1.1 200 Connection Established", statusLine)
	}
	// Drain remaining response headers until empty line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT response headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	calls := dialer.Calls()
	if len(calls) != 1 || calls[0].network != "tcp" || calls[0].address != "remote-only.internal:443" {
		t.Fatalf("Dialer calls = %+v, want [{tcp remote-only.internal:443}]", calls)
	}

	gotPipelined := make([]byte, len(pipelined))
	if _, err := io.ReadFull(br, gotPipelined); err != nil {
		t.Fatalf("read echoed pipelined bytes: %v", err)
	}
	if !bytes.Equal(gotPipelined, pipelined) {
		t.Fatalf("pipelined echo = %q, want %q", gotPipelined, pipelined)
	}

	secondMsg := []byte("-AND-SUBSEQUENT-PAYLOAD-BYTES")
	if _, err := conn.Write(secondMsg); err != nil {
		t.Fatalf("write second payload: %v", err)
	}
	gotSecond := make([]byte, len(secondMsg))
	if _, err := io.ReadFull(br, gotSecond); err != nil {
		t.Fatalf("read second echoed payload: %v", err)
	}
	if !bytes.Equal(gotSecond, secondMsg) {
		t.Fatalf("second echo = %q, want %q", gotSecond, secondMsg)
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	} else {
		_ = conn.Close()
	}

	wantBytes := uint64(len(pipelined) + len(secondMsg))
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		st := srv.Stats()
		if st.TxBytes == wantBytes && st.RxBytes == wantBytes && st.ActiveConns == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	st := srv.Stats()
	t.Fatalf("Stats() = %+v, want Tx=%d Rx=%d ActiveConns=0", st, wantBytes, wantBytes)
}

func TestHTTPConnectDialFailureReturns502(t *testing.T) {
	dialer := &mockDialer{
		fn: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("remote unreachable")
		},
	}
	srv := startTestServer(t, dialer, Config{})

	conn, err := net.Dial("tcp", srv.HTTPAddr())
	if err != nil {
		t.Fatalf("dial HTTP proxy: %v", err)
	}
	defer conn.Close()

	_, _ = io.WriteString(conn, "CONNECT remote-only.internal:443 HTTP/1.1\r\nHost: remote-only.internal:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read 502 response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestHTTPForwardProxyStripsHopByHopHeaders(t *testing.T) {
	var gotMu sync.Mutex
	var gotHeaders http.Header
	var gotPath string

	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin HTTP server: %v", err)
	}
	defer originLn.Close()

	originSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMu.Lock()
			gotHeaders = r.Header.Clone()
			gotPath = r.URL.RequestURI()
			gotMu.Unlock()

			w.Header().Set("X-Upstream", "ok")
			w.Header().Set("Proxy-Authenticate", "Basic realm=evil")
			w.Header().Set("Keep-Alive", "timeout=5")
			_, _ = io.WriteString(w, "proxied-body")
		}),
	}
	go func() {
		_ = originSrv.Serve(originLn)
	}()
	defer originSrv.Close()

	dialer := &mockDialer{
		fn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", originLn.Addr().String())
		},
	}
	srv := startTestServer(t, dialer, Config{})

	proxyURL, _ := url.Parse("http://" + srv.HTTPAddr())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}

	req, err := http.NewRequest(http.MethodGet, "http://remote-only.internal:8080/hello?x=1", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-End-To-End", "preserved")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Proxy-Authenticate", "Basic")
	req.Header.Set("Proxy-Authorization", "Basic secret-token")
	req.Header.Set("Keep-Alive", "timeout=10")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Trailers", "X-Trailer")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "X-Hop-Secret")
	req.Header.Set("X-Hop-Secret", "drop-me")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "proxied-body" {
		t.Fatalf("got status=%d body=%q, want 200 proxied-body", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Upstream") != "ok" {
		t.Fatalf("missing X-Upstream header: %+v", resp.Header)
	}
	if resp.Header.Get("Proxy-Authenticate") != "" || resp.Header.Get("Keep-Alive") != "" {
		t.Fatalf("hop-by-hop response headers leaked: %+v", resp.Header)
	}

	calls := dialer.Calls()
	if len(calls) != 1 || calls[0].address != "remote-only.internal:8080" {
		t.Fatalf("Dialer calls = %+v, want [{tcp remote-only.internal:8080}]", calls)
	}

	gotMu.Lock()
	defer gotMu.Unlock()
	if gotPath != "/hello?x=1" {
		t.Fatalf("origin path = %q, want /hello?x=1", gotPath)
	}
	if gotHeaders.Get("X-End-To-End") != "preserved" {
		t.Fatalf("X-End-To-End lost: %+v", gotHeaders)
	}
	stripped := []string{
		"Proxy-Connection",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Keep-Alive",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
		"Connection",
		"X-Hop-Secret",
	}
	for _, h := range stripped {
		if v := gotHeaders.Get(h); v != "" {
			t.Errorf("hop-by-hop header %s=%q reached origin server", h, v)
		}
	}

	st := srv.Stats()
	if st.TxBytes == 0 || st.RxBytes == 0 {
		t.Fatalf("expected non-zero TxBytes/RxBytes after HTTP forward, got %+v", st)
	}
}

func TestStopZeroGoroutineLeaks(t *testing.T) {
	// Let runtime settle any prior test goroutines before taking baseline.
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()

	dialStarted := make(chan struct{})
	dialer := &mockDialer{
		fn: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "blocked-dial.internal:443" {
				close(dialStarted)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			a, b := net.Pipe()
			// Hold remote side open until Server.Stop closes a.
			go func() {
				_, _ = io.Copy(io.Discard, b)
				_ = b.Close()
			}()
			return a, nil
		},
	}

	srv, err := NewServer(dialer, Config{
		SOCKSAddr:        "127.0.0.1:0",
		HTTPAddr:         "127.0.0.1:0",
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Open active SOCKS5 and HTTP CONNECT connections and leave them open while calling Stop.
	socksConn, err := net.Dial("tcp", srv.SOCKSAddr())
	if err != nil {
		t.Fatalf("dial SOCKS5: %v", err)
	}
	defer socksConn.Close()
	domain := "idle-stream.internal"
	if rep := socks5Handshake(t, socksConn, 0x03, append([]byte{byte(len(domain))}, []byte(domain)...), 443); rep != 0x00 {
		t.Fatalf("SOCKS5 reply = 0x%02x, want 0x00", rep)
	}

	httpConn, err := net.Dial("tcp", srv.HTTPAddr())
	if err != nil {
		t.Fatalf("dial HTTP: %v", err)
	}
	defer httpConn.Close()
	_, _ = io.WriteString(httpConn, "CONNECT idle-http.internal:443 HTTP/1.1\r\nHost: idle-http.internal:443\r\n\r\n")
	status, err := bufio.NewReader(httpConn).ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT status = %q err = %v", status, err)
	}

	// Also open a connection blocked mid-DialContext to verify Stop cancels in-flight dials.
	blockedConn, err := net.Dial("tcp", srv.HTTPAddr())
	if err != nil {
		t.Fatalf("dial HTTP blocked dial: %v", err)
	}
	defer blockedConn.Close()
	_, _ = io.WriteString(blockedConn, "CONNECT blocked-dial.internal:443 HTTP/1.1\r\nHost: blocked-dial.internal:443\r\n\r\n")
	<-dialStarted

	// Wait until ActiveConns reports all 3 active connections.
	waitActiveDeadline := time.Now().Add(time.Second)
	for time.Now().Before(waitActiveDeadline) {
		if srv.Stats().ActiveConns == 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := srv.Stats().ActiveConns; got != 3 {
		t.Fatalf("ActiveConns = %d, want 3", got)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	// Idempotent second Stop should also succeed cleanly.
	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}

	if got := srv.Stats().ActiveConns; got != 0 {
		t.Fatalf("ActiveConns after Stop = %d, want 0", got)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseGoroutines {
			return
		}
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine leak detected: baseline=%d after Stop=%d active=%d", baseGoroutines, runtime.NumGoroutine(), srv.Stats().ActiveConns)
}

func TestServerLifecycleAndContextCancel(t *testing.T) {
	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()

	srv0, err := NewServer(&mockDialer{}, Config{SOCKSAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv0.Start(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start(canceledCtx) = %v, want context.Canceled", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	srv := startTestServer(t, &mockDialer{}, Config{SOCKSAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0"})
	// Second Start while running must fail.
	if err := srv.Start(context.Background()); err == nil {
		t.Fatal("second Start() succeeded, want error")
	}

	srv2, err := NewServer(&mockDialer{}, Config{SOCKSAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("NewServer(srv2): %v", err)
	}
	if err := srv2.Start(runCtx); err != nil {
		t.Fatalf("Start(runCtx): %v", err)
	}
	socksAddr := srv2.SOCKSAddr()
	runCancel()

	// Listener should stop accepting shortly after runCtx cancellation.
	deadline := time.Now().Add(time.Second)
	closed := false
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", socksAddr, 50*time.Millisecond)
		if err != nil {
			closed = true
			break
		}
		_ = c.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if !closed {
		t.Fatal("listener remained open after Start(ctx) cancellation")
	}
	if err := srv2.Stop(context.Background()); err != nil {
		t.Fatalf("Stop after runCtx cancel: %v", err)
	}
}

func TestSOCKS5MalformedRequests(t *testing.T) {
	srv := startTestServer(t, &mockDialer{}, Config{HandshakeTimeout: time.Second})

	t.Run("InvalidVersion", func(t *testing.T) {
		c, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		_, _ = c.Write([]byte{0x04, 0x01, 0x00})
		var b [1]byte
		if _, err := c.Read(b[:]); err == nil {
			t.Fatal("expected EOF on SOCKS4 greeting")
		}
	})

	t.Run("ZeroMethods", func(t *testing.T) {
		c, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		_, _ = c.Write([]byte{0x05, 0x00})
		var resp [2]byte
		if _, err := io.ReadFull(c, resp[:]); err != nil {
			t.Fatalf("read reply: %v", err)
		}
		if resp != [2]byte{0x05, 0xFF} {
			t.Fatalf("reply = %x, want [05 ff]", resp)
		}
	})

	t.Run("EmptyDomainAndZeroPort", func(t *testing.T) {
		// Empty domain
		c1, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c1.Close()
		_, _ = c1.Write([]byte{0x05, 0x01, 0x00})
		var m [2]byte
		_, _ = io.ReadFull(c1, m[:])
		_, _ = c1.Write([]byte{0x05, 0x01, 0x00, 0x03, 0x00})
		var r1 [10]byte
		if _, err := io.ReadFull(c1, r1[:]); err != nil {
			t.Fatalf("read empty domain reply: %v", err)
		}
		if r1[1] != 0x01 {
			t.Fatalf("empty domain reply = 0x%02x, want 0x01", r1[1])
		}

		// Port 0
		c2, err := net.Dial("tcp", srv.SOCKSAddr())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c2.Close()
		_, _ = c2.Write([]byte{0x05, 0x01, 0x00})
		_, _ = io.ReadFull(c2, m[:])
		_, _ = c2.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00})
		var r2 [10]byte
		if _, err := io.ReadFull(c2, r2[:]); err != nil {
			t.Fatalf("read port 0 reply: %v", err)
		}
		if r2[1] != 0x01 {
			t.Fatalf("port 0 reply = 0x%02x, want 0x01", r2[1])
		}
	})
}

func TestHTTPBadConnectAndForwardErrors(t *testing.T) {
	dialer := &mockDialer{
		fn: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("tunnel disconnected")
		},
	}
	srv := startTestServer(t, dialer, Config{})

	// CONNECT without port -> 400 Bad Request
	c1, err := net.Dial("tcp", srv.HTTPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c1.Close()
	_, _ = io.WriteString(c1, "CONNECT missing-port HTTP/1.1\r\nHost: missing-port\r\n\r\n")
	resp1, err := http.ReadResponse(bufio.NewReader(c1), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read 400 response: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp1.StatusCode)
	}

	// Non-CONNECT GET when dialer fails -> 502 Bad Gateway
	proxyURL, _ := url.Parse("http://" + srv.HTTPAddr())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp2, err := client.Get("http://remote-only.internal:8080/fail")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadGateway {
		t.Fatalf("forward error status = %d, want 502", resp2.StatusCode)
	}
}
