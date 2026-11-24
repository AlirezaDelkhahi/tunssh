package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
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

func (m *mockDialer) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// serveTCPPipe serves one or more RFC 7766 DNS-over-TCP messages over an in-memory pipe.
func serveTCPPipe(handler func(*mdns.Msg) *mdns.Msg) net.Conn {
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		var lenBuf [2]byte
		for {
			if _, err := io.ReadFull(serverConn, lenBuf[:]); err != nil {
				return
			}
			msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			payload := make([]byte, msgLen)
			if _, err := io.ReadFull(serverConn, payload); err != nil {
				return
			}
			req := new(mdns.Msg)
			if err := req.Unpack(payload); err != nil {
				return
			}
			resp := handler(req)
			if resp == nil {
				return
			}
			wire, err := resp.Pack()
			if err != nil {
				return
			}
			frame := make([]byte, 2+len(wire))
			binary.BigEndian.PutUint16(frame, uint16(len(wire)))
			copy(frame[2:], wire)
			if _, err := serverConn.Write(frame); err != nil {
				return
			}
		}
	}()
	return clientConn
}

// serveUDPPipe serves a single raw DNS packet exchange over an in-memory pipe.
func serveUDPPipe(handler func(*mdns.Msg) *mdns.Msg) net.Conn {
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 4096)
		n, err := serverConn.Read(buf)
		if err != nil {
			return
		}
		req := new(mdns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			return
		}
		resp := handler(req)
		if resp == nil {
			return
		}
		wire, err := resp.Pack()
		if err != nil {
			return
		}
		_, _ = serverConn.Write(wire)
	}()
	return clientConn
}

func makeAReply(req *mdns.Msg, ip string, ttl uint32) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	if len(req.Question) > 0 {
		resp.Answer = []mdns.RR{
			&mdns.A{
				Hdr: mdns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: mdns.TypeA,
					Class:  mdns.ClassINET,
					Ttl:    ttl,
				},
				A: net.ParseIP(ip).To4(),
			},
		}
	}
	return resp
}

func queryUDPAndTCP(t *testing.T, srv *Server, qname string) (*mdns.Msg, *mdns.Msg) {
	t.Helper()
	udpClient := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
	tcpClient := &mdns.Client{Net: "tcp", Timeout: 2 * time.Second}

	reqUDP := new(mdns.Msg)
	reqUDP.SetQuestion(qname, mdns.TypeA)
	udpResp, _, err := udpClient.Exchange(reqUDP, srv.UDPAddr())
	if err != nil {
		t.Fatalf("UDP Exchange(%s): %v", qname, err)
	}

	reqTCP := new(mdns.Msg)
	reqTCP.SetQuestion(qname, mdns.TypeA)
	tcpResp, _, err := tcpClient.Exchange(reqTCP, srv.TCPAddr())
	if err != nil {
		t.Fatalf("TCP Exchange(%s): %v", qname, err)
	}
	return udpResp, tcpResp
}

func extractFirstA(t *testing.T, msg *mdns.Msg) (string, uint32) {
	t.Helper()
	if len(msg.Answer) == 0 {
		t.Fatalf("expected at least 1 Answer RR, got 0 (rcode=%s)", mdns.RcodeToString[msg.Rcode])
	}
	a, ok := msg.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("expected *dns.A answer, got %T", msg.Answer[0])
	}
	return a.A.String(), a.Hdr.Ttl
}

func TestShouldBypassDomain(t *testing.T) {
	tests := []struct {
		name          string
		qname         string
		bypassIranLAN bool
		want          bool
	}{
		// Bypass enabled
		{name: "exact ir root", qname: "ir.", bypassIranLAN: true, want: true},
		{name: "exact ir uppercase", qname: "IR.", bypassIranLAN: true, want: true},
		{name: "exact ir no dot", qname: "ir", bypassIranLAN: true, want: true},
		{name: "ir domain", qname: "bankmellat.ir.", bypassIranLAN: true, want: true},
		{name: "ir subdomain mixed case", qname: "Sub.BankMellat.IR.", bypassIranLAN: true, want: true},
		{name: "ir domain no trailing dot", qname: "shaparak.ir", bypassIranLAN: true, want: true},
		{name: "local domain", qname: "printer.local.", bypassIranLAN: true, want: true},
		{name: "local uppercase", qname: "NAS.LOCAL.", bypassIranLAN: true, want: true},
		{name: "lan domain", qname: "router.lan.", bypassIranLAN: true, want: true},
		{name: "home.arpa domain", qname: "gateway.home.arpa.", bypassIranLAN: true, want: true},
		{name: "reverse ipv4", qname: "1.168.192.in-addr.arpa.", bypassIranLAN: true, want: true},
		{name: "reverse ipv6", qname: "1.0.0.0.0.0.0.0.ip6.arpa.", bypassIranLAN: true, want: true},
		{name: "non-ir com", qname: "example.com.", bypassIranLAN: true, want: false},
		{name: "suffix trap evil-ir", qname: "evil-ir.", bypassIranLAN: true, want: false},
		{name: "substring trap myir.com", qname: "myir.com.", bypassIranLAN: true, want: false},
		{name: "label trap ir.example.com", qname: "ir.example.com.", bypassIranLAN: true, want: false},
		{name: "empty", qname: "", bypassIranLAN: true, want: false},
		{name: "root dot", qname: ".", bypassIranLAN: true, want: false},
		// Bypass disabled -> always false
		{name: "disabled exact ir", qname: "ir.", bypassIranLAN: false, want: false},
		{name: "disabled bankmellat.ir", qname: "bankmellat.ir.", bypassIranLAN: false, want: false},
		{name: "disabled printer.local", qname: "printer.local.", bypassIranLAN: false, want: false},
		{name: "disabled router.lan", qname: "router.lan.", bypassIranLAN: false, want: false},
		{name: "disabled home.arpa", qname: "gateway.home.arpa.", bypassIranLAN: false, want: false},
		{name: "disabled in-addr.arpa", qname: "1.168.192.in-addr.arpa.", bypassIranLAN: false, want: false},
		{name: "disabled ip6.arpa", qname: "1.0.ip6.arpa.", bypassIranLAN: false, want: false},
		{name: "disabled example.com", qname: "example.com.", bypassIranLAN: false, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldBypassDomain(tc.qname, tc.bypassIranLAN); got != tc.want {
				t.Fatalf("ShouldBypassDomain(%q, %v) = %v, want %v", tc.qname, tc.bypassIranLAN, got, tc.want)
			}
		})
	}
}

func TestServerRoutingAndToggle(t *testing.T) {
	var tunnelUpstreamQueries atomic.Int32
	var bypassUpstreamQueries atomic.Int32

	tunnelDialer := &mockDialer{
		fn: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, errors.New("tunnel dialer expected tcp")
			}
			return serveTCPPipe(func(req *mdns.Msg) *mdns.Msg {
				tunnelUpstreamQueries.Add(1)
				qname := strings.ToLower(req.Question[0].Name)
				switch qname {
				case "example.com.":
					return makeAReply(req, "198.51.100.10", 60)
				case "bankmellat.ir.":
					return makeAReply(req, "198.51.100.99", 60)
				default:
					return makeAReply(req, "198.51.100.1", 60)
				}
			}), nil
		},
	}
	bypassDialer := &mockDialer{
		fn: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "udp" {
				return nil, errors.New("bypass dialer expected udp")
			}
			return serveUDPPipe(func(req *mdns.Msg) *mdns.Msg {
				bypassUpstreamQueries.Add(1)
				qname := strings.ToLower(req.Question[0].Name)
				switch qname {
				case "bankmellat.ir.":
					return makeAReply(req, "185.1.2.3", 60)
				case "printer.local.":
					return makeAReply(req, "192.168.1.50", 60)
				default:
					return makeAReply(req, "10.0.0.1", 60)
				}
			}), nil
		},
	}

	srv := NewServer()
	var _ DNSResolver = srv

	err := srv.Start(context.Background(), DNSConfig{
		ListenAddr:      "127.0.0.1:0",
		TunnelDialer:    tunnelDialer,
		BypassDialer:    bypassDialer,
		BypassUpstreams: []string{"192.168.1.1:53"},
		BypassIranLAN:   true,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Stop(ctx); err != nil {
			t.Errorf("Stop() cleanup error = %v", err)
		}
	})

	if srv.UDPAddr() == "" || srv.TCPAddr() == "" {
		t.Fatalf("expected non-empty UDPAddr and TCPAddr, got udp=%q tcp=%q", srv.UDPAddr(), srv.TCPAddr())
	}

	// 1. example.com. must dial TunnelDialer exclusively (BypassDialer == 0).
	udpResp, tcpResp := queryUDPAndTCP(t, srv, "example.com.")
	if ip, _ := extractFirstA(t, udpResp); ip != "198.51.100.10" {
		t.Fatalf("example.com. UDP IP = %s, want 198.51.100.10", ip)
	}
	if ip, _ := extractFirstA(t, tcpResp); ip != "198.51.100.10" {
		t.Fatalf("example.com. TCP IP = %s, want 198.51.100.10", ip)
	}
	if got := bypassDialer.CallCount(); got != 0 {
		t.Fatalf("BypassDialer calls after example.com. = %d, want 0", got)
	}
	if got := tunnelDialer.CallCount(); got != 1 {
		t.Fatalf("TunnelDialer calls after example.com. (UDP+TCP with cache) = %d, want 1", got)
	}
	if got := tunnelUpstreamQueries.Load(); got != 1 {
		t.Fatalf("tunnelUpstreamQueries after example.com. = %d, want 1", got)
	}

	// 2. bankmellat.ir. & printer.local. with BypassIranLAN == true must dial BypassDialer exclusively.
	udpIR, tcpIR := queryUDPAndTCP(t, srv, "bankmellat.ir.")
	if ip, _ := extractFirstA(t, udpIR); ip != "185.1.2.3" {
		t.Fatalf("bankmellat.ir. UDP IP = %s, want 185.1.2.3", ip)
	}
	if ip, _ := extractFirstA(t, tcpIR); ip != "185.1.2.3" {
		t.Fatalf("bankmellat.ir. TCP IP = %s, want 185.1.2.3", ip)
	}

	udpLocal, _ := queryUDPAndTCP(t, srv, "printer.local.")
	if ip, _ := extractFirstA(t, udpLocal); ip != "192.168.1.50" {
		t.Fatalf("printer.local. UDP IP = %s, want 192.168.1.50", ip)
	}

	if got := tunnelDialer.CallCount(); got != 1 {
		t.Fatalf("TunnelDialer calls increased during bypass queries: got %d, want 1", got)
	}
	if got := tunnelUpstreamQueries.Load(); got != 1 {
		t.Fatalf("tunnelUpstreamQueries increased during bypass queries: got %d, want 1", got)
	}
	bypassCallsBeforeToggle := bypassDialer.CallCount()
	if bypassCallsBeforeToggle != 2 || bypassUpstreamQueries.Load() != 2 {
		t.Fatalf("BypassDialer calls/queries = %d/%d, want 2/2", bypassCallsBeforeToggle, bypassUpstreamQueries.Load())
	}

	// 3. Toggle SetBypassIranLAN(false): flushes cache and routes bankmellat.ir. through TunnelDialer immediately.
	srv.SetBypassIranLAN(false)
	if entries := srv.Stats().CacheEntries; entries != 0 {
		t.Fatalf("CacheEntries after SetBypassIranLAN toggle = %d, want 0", entries)
	}

	udpIRAfter, _ := queryUDPAndTCP(t, srv, "bankmellat.ir.")
	if ip, _ := extractFirstA(t, udpIRAfter); ip != "198.51.100.99" {
		t.Fatalf("bankmellat.ir. after SetBypassIranLAN(false) = %s, want 198.51.100.99", ip)
	}
	if got := bypassDialer.CallCount(); got != bypassCallsBeforeToggle {
		t.Fatalf("BypassDialer calls increased after SetBypassIranLAN(false): got %d, want %d", got, bypassCallsBeforeToggle)
	}
	if got := tunnelUpstreamQueries.Load(); got != 2 {
		t.Fatalf("expected tunnelUpstreamQueries=2 after SetBypassIranLAN(false), got %d", got)
	}

	stats := srv.Stats()
	if stats.TotalQueries != 8 || stats.TunnelQueries != 4 || stats.BypassQueries != 4 || stats.CacheHits < 4 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestServerCacheHitTTLClampingAndEviction(t *testing.T) {
	nowMu := sync.Mutex{}
	nowTime := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	advance := func(d time.Duration) {
		nowMu.Lock()
		nowTime = nowTime.Add(d)
		nowMu.Unlock()
	}

	var upstreamQueries atomic.Int32
	tunnelDialer := &mockDialer{
		fn: func(_ context.Context, _, _ string) (net.Conn, error) {
			return serveTCPPipe(func(req *mdns.Msg) *mdns.Msg {
				n := upstreamQueries.Add(1)
				qname := strings.ToLower(req.Question[0].Name)
				switch qname {
				case "short.example.":
					resp := makeAReply(req, "203.0.113.1", 2) // below 10s -> clamped to 10s
					resp.Extra = []mdns.RR{
						&mdns.OPT{
							Hdr: mdns.RR_Header{Name: ".", Rrtype: mdns.TypeOPT, Class: 4096, Ttl: 0},
						},
					}
					return resp
				case "long.example.":
					return makeAReply(req, "203.0.113.2", 3600) // above 300s -> clamped to 300s
				case "nxdomain.example.":
					resp := new(mdns.Msg)
					resp.SetRcode(req, mdns.RcodeNameError)
					resp.Ns = []mdns.RR{
						&mdns.SOA{
							Hdr: mdns.RR_Header{
								Name:   "example.",
								Rrtype: mdns.TypeSOA,
								Class:  mdns.ClassINET,
								Ttl:    30,
							},
							Ns:      "ns1.example.",
							Mbox:    "hostmaster.example.",
							Serial:  1,
							Refresh: 60,
							Retry:   60,
							Expire:  60,
							Minttl:  30,
						},
					}
					return resp
				case "fail.example.":
					resp := new(mdns.Msg)
					resp.SetRcode(req, mdns.RcodeServerFailure)
					return resp
				default:
					return makeAReply(req, "203.0.113."+string(rune('0'+n)), 60)
				}
			}), nil
		},
	}

	srv := NewServer()
	srv.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return nowTime
	}

	err := srv.Start(context.Background(), DNSConfig{
		ListenAddr:      "127.0.0.1:0",
		TunnelDialer:    tunnelDialer,
		CacheMaxEntries: 2,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	// 1. Short TTL (2s) is clamped up to 10s (even with EDNS0 OPT Ttl=0 in Extra!).
	req1 := new(mdns.Msg)
	req1.SetQuestion("short.example.", mdns.TypeA)
	req1.Id = 101
	resp1, err := srv.Exchange(context.Background(), req1)
	if err != nil {
		t.Fatalf("Exchange(short) 1: %v", err)
	}
	if resp1.Id != 101 {
		t.Fatalf("resp1.Id = %d, want 101", resp1.Id)
	}
	if upstreamQueries.Load() != 1 {
		t.Fatalf("upstreamQueries = %d, want 1", upstreamQueries.Load())
	}

	// Advance 4s: still valid (10s min TTL), cache hit rewrites Id and remaining TTL (6s).
	advance(4 * time.Second)
	req2 := new(mdns.Msg)
	req2.SetQuestion("SHORT.EXAMPLE.", mdns.TypeA)
	req2.Id = 202
	resp2, err := srv.Exchange(context.Background(), req2)
	if err != nil {
		t.Fatalf("Exchange(short) 2: %v", err)
	}
	if resp2.Id != 202 {
		t.Fatalf("cached resp2.Id = %d, want 202", resp2.Id)
	}
	if resp2.Question[0].Name != "SHORT.EXAMPLE." {
		t.Fatalf("cached Question.Name = %q, want SHORT.EXAMPLE.", resp2.Question[0].Name)
	}
	if _, ttl := extractFirstA(t, resp2); ttl != 6 {
		t.Fatalf("cached remaining TTL = %d, want 6", ttl)
	}
	if upstreamQueries.Load() != 1 {
		t.Fatalf("expected cache hit with upstreamQueries=1, got %d", upstreamQueries.Load())
	}

	// Advance another 6s (total 10s): expired, must evict and re-query upstream.
	advance(6 * time.Second)
	req3 := new(mdns.Msg)
	req3.SetQuestion("short.example.", mdns.TypeA)
	req3.Id = 303
	if _, err := srv.Exchange(context.Background(), req3); err != nil {
		t.Fatalf("Exchange(short) 3: %v", err)
	}
	if upstreamQueries.Load() != 2 {
		t.Fatalf("expected re-query after 10s expiry, upstreamQueries = %d, want 2", upstreamQueries.Load())
	}

	// 2. Long TTL (3600s) is clamped down to 300s.
	reqLong := new(mdns.Msg)
	reqLong.SetQuestion("long.example.", mdns.TypeA)
	reqLong.Id = 404
	if _, err := srv.Exchange(context.Background(), reqLong); err != nil {
		t.Fatalf("Exchange(long) 1: %v", err)
	}
	queriesAfterLong := upstreamQueries.Load()

	advance(299 * time.Second)
	reqLong2 := new(mdns.Msg)
	reqLong2.SetQuestion("long.example.", mdns.TypeA)
	reqLong2.Id = 405
	respLong2, err := srv.Exchange(context.Background(), reqLong2)
	if err != nil {
		t.Fatalf("Exchange(long) 2: %v", err)
	}
	if _, ttl := extractFirstA(t, respLong2); ttl != 1 {
		t.Fatalf("clamped long TTL at +299s = %d, want 1", ttl)
	}
	if upstreamQueries.Load() != queriesAfterLong {
		t.Fatalf("expected cache hit at +299s")
	}

	advance(1 * time.Second)
	if _, err := srv.Exchange(context.Background(), reqLong2); err != nil {
		t.Fatalf("Exchange(long) 3: %v", err)
	}
	if upstreamQueries.Load() != queriesAfterLong+1 {
		t.Fatalf("expected expiry at +300s (clamped from 3600s)")
	}

	// 3. Capacity eviction (CacheMaxEntries = 2) with LRU promotion.
	srv.FlushCache()
	beforeLRU := upstreamQueries.Load()

	queryName := func(name string) *mdns.Msg {
		r := new(mdns.Msg)
		r.SetQuestion(name, mdns.TypeA)
		resp, err := srv.Exchange(context.Background(), r)
		if err != nil {
			t.Fatalf("Exchange(%s): %v", name, err)
		}
		return resp
	}

	queryName("a.example.") // cache: [a]
	queryName("b.example.") // cache: [b, a]
	queryName("a.example.") // hit! promotes a -> cache: [a, b]
	if got := upstreamQueries.Load(); got != beforeLRU+2 {
		t.Fatalf("expected 2 upstream queries after hitting a.example., got %d", got-beforeLRU)
	}
	queryName("c.example.") // evicts LRU (b) -> cache: [c, a]
	if entries := srv.Stats().CacheEntries; entries != 2 {
		t.Fatalf("CacheEntries = %d, want 2", entries)
	}

	queriesBeforeCheck := upstreamQueries.Load()
	queryName("a.example.") // must still be cached!
	if upstreamQueries.Load() != queriesBeforeCheck {
		t.Fatalf("expected a.example. to remain in cache")
	}
	queryName("b.example.") // was evicted -> must hit upstream!
	if upstreamQueries.Load() != queriesBeforeCheck+1 {
		t.Fatalf("expected b.example. to be evicted from LRU cache")
	}

	// 4. NXDOMAIN IS cached using Ns SOA TTL, while SERVFAIL must NOT be cached.
	srv.FlushCache()
	beforeNX := upstreamQueries.Load()
	nx1 := queryName("nxdomain.example.")
	if nx1.Rcode != mdns.RcodeNameError {
		t.Fatalf("nx1.Rcode = %s, want NXDOMAIN", mdns.RcodeToString[nx1.Rcode])
	}
	advance(5 * time.Second)
	nx2 := queryName("nxdomain.example.")
	if nx2.Rcode != mdns.RcodeNameError || nx2.Ns[0].Header().Ttl != 25 {
		t.Fatalf("expected cached NXDOMAIN with Ns TTL=25, got rcode=%d ttl=%d", nx2.Rcode, nx2.Ns[0].Header().Ttl)
	}
	if upstreamQueries.Load() != beforeNX+1 {
		t.Fatalf("expected NXDOMAIN cache hit")
	}

	queriesBeforeFail := upstreamQueries.Load()
	queryName("fail.example.")
	queryName("fail.example.")
	if upstreamQueries.Load() != queriesBeforeFail+2 {
		t.Fatalf("expected SERVFAIL not to be cached; queries = %d, want 2", upstreamQueries.Load()-queriesBeforeFail)
	}

	// 5. Namespace partitioning isolates bypass vs tunnel entries.
	cache := newDNSCache(4, srv.now)
	bypassReply := makeAReply(&mdns.Msg{Question: []mdns.Question{{Name: "bankmellat.ir.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET}}}, "185.1.2.3", 60)
	cache.setAtEpoch(cacheKey{namespace: namespaceBypass, qname: "bankmellat.ir.", qtype: mdns.TypeA, qclass: mdns.ClassINET}, bypassReply, cache.currentEpoch())
	if _, _, ok := cache.get(cacheKey{namespace: namespaceTunnel, qname: "bankmellat.ir.", qtype: mdns.TypeA, qclass: mdns.ClassINET}); ok {
		t.Fatalf("expected bypass cache entry not to be visible in tunnel namespace")
	}

	// 6. Stop() flushes cache.
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop(): %v", err)
	}
	if entries := srv.Stats().CacheEntries; entries != 0 {
		t.Fatalf("CacheEntries after Stop() = %d, want 0", entries)
	}
}

func TestServerTimeoutSERVFAILAndNoGoroutineLeak(t *testing.T) {
	// Stalled upstream responder that blocks on read until deadline or context cancellation.
	stalledDialer := &mockDialer{
		fn: func(ctx context.Context, _, _ string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				<-ctx.Done()
			}()
			return clientConn, nil
		},
	}

	srv := NewServer()
	err := srv.Start(context.Background(), DNSConfig{
		ListenAddr:   "127.0.0.1:0",
		TunnelDialer: stalledDialer,
		QueryTimeout: 60 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Capture goroutine baseline after server start settles.
	runtime.Gosched()
	time.Sleep(20 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	const workers = 6
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			netMode := "udp"
			addr := srv.UDPAddr()
			if idx%2 == 1 {
				netMode = "tcp"
				addr = srv.TCPAddr()
			}
			c := &mdns.Client{Net: netMode, Timeout: 2 * time.Second}
			req := new(mdns.Msg)
			req.SetQuestion("stalled.example.", mdns.TypeA)
			resp, _, err := c.Exchange(req, addr)
			if err != nil {
				t.Errorf("%s Exchange error = %v, want SERVFAIL reply", netMode, err)
				return
			}
			if resp.Rcode != mdns.RcodeServerFailure {
				t.Errorf("%s Rcode = %s, want SERVFAIL", netMode, mdns.RcodeToString[resp.Rcode])
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("stalled queries took %v, expected <= 500ms (~60ms QueryTimeout)", elapsed)
	}

	stats := srv.Stats()
	if stats.UpstreamErrors != workers {
		t.Fatalf("UpstreamErrors = %d, want %d", stats.UpstreamErrors, workers)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Allow up to +1 variance for runtime background goroutines, though normally <= baseline.
	if after := runtime.NumGoroutine(); after > baseline+1 {
		t.Fatalf("goroutine leak detected: baseline=%d after=%d", baseline, after)
	}
}

func TestPooledTCPStaleEOFRetryAndUpstreamFallback(t *testing.T) {
	t.Run("pooled reuse and stale EOF single retry", func(t *testing.T) {
		var dialCount atomic.Int32
		var queryCount atomic.Int32
		var firstServerConn net.Conn
		var connMu sync.Mutex

		dialer := &mockDialer{
			fn: func(_ context.Context, _, address string) (net.Conn, error) {
				n := dialCount.Add(1)
				clientConn, serverConn := net.Pipe()
				if n == 1 {
					connMu.Lock()
					firstServerConn = serverConn
					connMu.Unlock()
				}
				go func(connID int32, sc net.Conn) {
					defer sc.Close()
					var lenBuf [2]byte
					for {
						if _, err := io.ReadFull(sc, lenBuf[:]); err != nil {
							return
						}
						msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
						payload := make([]byte, msgLen)
						if _, err := io.ReadFull(sc, payload); err != nil {
							return
						}
						req := new(mdns.Msg)
						if err := req.Unpack(payload); err != nil {
							return
						}
						q := queryCount.Add(1)
						resp := makeAReply(req, "198.51.100."+string(rune('0'+q)), 30)
						wire, _ := resp.Pack()
						frame := make([]byte, 2+len(wire))
						binary.BigEndian.PutUint16(frame, uint16(len(wire)))
						copy(frame[2:], wire)
						if _, err := sc.Write(frame); err != nil {
							return
						}
					}
				}(n, serverConn)
				return clientConn, nil
			},
		}

		fwd := newTunnelTCPForwarder(dialer, []string{"1.1.1.1:53", "8.8.8.8:53"}, 2*time.Second)
		defer fwd.Close()

		// Query 1: dials conn 1 and returns it to pool.
		req1 := new(mdns.Msg)
		req1.SetQuestion("one.example.", mdns.TypeA)
		resp1, err := fwd.Exchange(context.Background(), req1)
		if err != nil {
			t.Fatalf("Exchange 1: %v", err)
		}
		if ip, _ := extractFirstA(t, resp1); ip != "198.51.100.1" {
			t.Fatalf("resp1 IP = %s, want 198.51.100.1", ip)
		}

		// Query 2: reuses pooled conn 1 without new dial.
		req2 := new(mdns.Msg)
		req2.SetQuestion("two.example.", mdns.TypeA)
		resp2, err := fwd.Exchange(context.Background(), req2)
		if err != nil {
			t.Fatalf("Exchange 2: %v", err)
		}
		if ip, _ := extractFirstA(t, resp2); ip != "198.51.100.2" {
			t.Fatalf("resp2 IP = %s, want 198.51.100.2", ip)
		}
		if dialCount.Load() != 1 {
			t.Fatalf("expected pooled connection reuse (dialCount=1), got %d", dialCount.Load())
		}

		// Force server-side close of pooled conn 1 -> next query hits stale EOF and retries once with fresh dial!
		connMu.Lock()
		_ = firstServerConn.Close()
		connMu.Unlock()

		req3 := new(mdns.Msg)
		req3.SetQuestion("three.example.", mdns.TypeA)
		resp3, err := fwd.Exchange(context.Background(), req3)
		if err != nil {
			t.Fatalf("Exchange 3 (stale EOF retry): %v", err)
		}
		if ip, _ := extractFirstA(t, resp3); ip != "198.51.100.3" {
			t.Fatalf("resp3 IP = %s, want 198.51.100.3", ip)
		}
		if dialCount.Load() != 2 {
			t.Fatalf("expected fresh retry dial (dialCount=2), got %d", dialCount.Load())
		}
		calls := dialer.Calls()
		if calls[1].address != "1.1.1.1:53" {
			t.Fatalf("expected stale-EOF retry on primary 1.1.1.1:53, got %s", calls[1].address)
		}
	})

	t.Run("cycles to fallback resolver when primary fails", func(t *testing.T) {
		dialer := &mockDialer{
			fn: func(_ context.Context, _, address string) (net.Conn, error) {
				if address == "1.1.1.1:53" {
					return nil, errors.New("primary unreachable")
				}
				return serveTCPPipe(func(req *mdns.Msg) *mdns.Msg {
					return makeAReply(req, "8.8.4.4", 60)
				}), nil
			},
		}

		fwd := newTunnelTCPForwarder(dialer, []string{"1.1.1.1:53", "8.8.8.8:53"}, 2*time.Second)
		defer fwd.Close()

		req := new(mdns.Msg)
		req.SetQuestion("fallback.example.", mdns.TypeA)
		resp, err := fwd.Exchange(context.Background(), req)
		if err != nil {
			t.Fatalf("Exchange fallback: %v", err)
		}
		if ip, _ := extractFirstA(t, resp); ip != "8.8.4.4" {
			t.Fatalf("fallback IP = %s, want 8.8.4.4", ip)
		}
		calls := dialer.Calls()
		if len(calls) != 2 || calls[0].address != "1.1.1.1:53" || calls[1].address != "8.8.8.8:53" {
			t.Fatalf("unexpected dial sequence: %+v", calls)
		}
	})
}

func TestBypassUDPTCFallbackToTCP(t *testing.T) {
	dialer := &mockDialer{
		fn: func(_ context.Context, network, address string) (net.Conn, error) {
			if network == "udp" {
				return serveUDPPipe(func(req *mdns.Msg) *mdns.Msg {
					resp := new(mdns.Msg)
					resp.SetReply(req)
					resp.Truncated = true
					return resp
				}), nil
			}
			if network == "tcp" {
				return serveTCPPipe(func(req *mdns.Msg) *mdns.Msg {
					return makeAReply(req, "185.10.20.30", 45)
				}), nil
			}
			return nil, errors.New("unexpected network")
		},
	}

	fwd := newBypassForwarder(dialer, []string{"192.168.1.1:53"}, 2*time.Second)
	defer fwd.Close()

	req := new(mdns.Msg)
	req.SetQuestion("big.ir.", mdns.TypeA)
	resp, err := fwd.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("bypass Exchange with TC fallback: %v", err)
	}
	if resp.Truncated {
		t.Fatalf("expected non-truncated TCP fallback response")
	}
	if ip, _ := extractFirstA(t, resp); ip != "185.10.20.30" {
		t.Fatalf("TCP fallback IP = %s, want 185.10.20.30", ip)
	}
	calls := dialer.Calls()
	if len(calls) != 2 || calls[0] != (dialCall{network: "udp", address: "192.168.1.1:53"}) || calls[1] != (dialCall{network: "tcp", address: "192.168.1.1:53"}) {
		t.Fatalf("unexpected dial calls: %+v", calls)
	}
}

func TestDoHTransportOverTunnelDialer(t *testing.T) {
	t.Run("default DoH endpoint targets 1.1.1.1:443 via TunnelDialer", func(t *testing.T) {
		tunnelDialer := &mockDialer{
			fn: func(_ context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("stop dial")
			},
		}
		srv := NewServer()
		if err := srv.Start(context.Background(), DNSConfig{
			ListenAddr:   "127.0.0.1:0",
			TunnelDialer: tunnelDialer,
			Transport:    string(UpstreamTransportDoH),
		}); err != nil {
			t.Fatalf("Start DoH: %v", err)
		}
		defer srv.Stop(context.Background())

		req := new(mdns.Msg)
		req.SetQuestion("doh.example.", mdns.TypeA)
		resp, err := srv.Exchange(context.Background(), req)
		if err == nil {
			t.Fatalf("expected error from stopped dial")
		}
		if resp == nil || resp.Rcode != mdns.RcodeServerFailure {
			t.Fatalf("expected SERVFAIL response on DoH dial failure, got %+v", resp)
		}
		calls := tunnelDialer.Calls()
		if len(calls) == 0 || calls[0].address != "1.1.1.1:443" {
			t.Fatalf("expected DoH default dial to 1.1.1.1:443 via TunnelDialer, got %+v", calls)
		}
	})

	t.Run("forwards RFC 8484 POST via TunnelDialer", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen DoH test server: %v", err)
		}
		defer ln.Close()

		httpSrv := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					http.Error(w, "method", http.StatusMethodNotAllowed)
					return
				}
				if r.Header.Get("Content-Type") != "application/dns-message" {
					http.Error(w, "content-type", http.StatusUnsupportedMediaType)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "read", http.StatusBadRequest)
					return
				}
				req := new(mdns.Msg)
				if err := req.Unpack(body); err != nil {
					http.Error(w, "unpack", http.StatusBadRequest)
					return
				}
				resp := makeAReply(req, "198.51.100.77", 120)
				wire, err := resp.Pack()
				if err != nil {
					http.Error(w, "pack", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(wire)
			}),
		}
		go func() { _ = httpSrv.Serve(ln) }()
		defer httpSrv.Close()

		tunnelDialer := &mockDialer{
			fn: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			},
		}

		srv := NewServer()
		if err := srv.Start(context.Background(), DNSConfig{
			ListenAddr:      "127.0.0.1:0",
			TunnelDialer:    tunnelDialer,
			TunnelUpstreams: []string{"http://" + ln.Addr().String() + "/dns-query"},
			Transport:       string(UpstreamTransportDoH),
		}); err != nil {
			t.Fatalf("Start DoH custom endpoint: %v", err)
		}
		defer srv.Stop(context.Background())

		req := new(mdns.Msg)
		req.SetQuestion("doh-ok.example.", mdns.TypeA)
		resp, err := srv.Exchange(context.Background(), req)
		if err != nil {
			t.Fatalf("DoH Exchange: %v", err)
		}
		if ip, _ := extractFirstA(t, resp); ip != "198.51.100.77" {
			t.Fatalf("DoH IP = %s, want 198.51.100.77", ip)
		}
		if got := tunnelDialer.CallCount(); got != 1 {
			t.Fatalf("TunnelDialer CallCount = %d, want 1", got)
		}
	})
}

func TestServerLifecycleAndNoLockAcrossIO(t *testing.T) {
	dialBlocked := make(chan struct{})
	releaseDial := make(chan struct{})

	tunnelDialer := &mockDialer{
		fn: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(dialBlocked)
			select {
			case <-releaseDial:
				return serveTCPPipe(func(req *mdns.Msg) *mdns.Msg {
					return makeAReply(req, "198.51.100.1", 60)
				}), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	bypassDialer := &mockDialer{
		fn: func(_ context.Context, _, _ string) (net.Conn, error) {
			return serveUDPPipe(func(req *mdns.Msg) *mdns.Msg {
				return makeAReply(req, "185.5.5.5", 60)
			}), nil
		},
	}

	srv := NewServer()

	// Validation errors.
	if err := srv.Start(context.Background(), DNSConfig{}); err == nil {
		t.Fatal("expected error when TunnelDialer is nil")
	}
	if err := srv.Start(context.Background(), DNSConfig{TunnelDialer: tunnelDialer, Transport: "quic"}); err == nil {
		t.Fatal("expected error for unsupported transport")
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := srv.Start(canceledCtx, DNSConfig{TunnelDialer: tunnelDialer}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start(canceledCtx) = %v, want context.Canceled", err)
	}
	// Stop before Start is a safe no-op.
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	if err := srv.Start(runCtx, DNSConfig{
		ListenAddr:      "127.0.0.1:0",
		TunnelDialer:    tunnelDialer,
		BypassDialer:    bypassDialer,
		BypassUpstreams: []string{"192.168.1.1:53"},
		BypassIranLAN:   true,
		QueryTimeout:    2 * time.Second,
	}); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	if err := srv.Start(context.Background(), DNSConfig{TunnelDialer: tunnelDialer}); err == nil {
		t.Fatal("expected second Start() to fail")
	}

	// Start a slow tunnel query that blocks inside DialContext.
	slowDone := make(chan error, 1)
	go func() {
		req := new(mdns.Msg)
		req.SetQuestion("slow.example.", mdns.TypeA)
		_, err := srv.Exchange(context.Background(), req)
		slowDone <- err
	}()

	<-dialBlocked

	// While tunnel query is blocked in DialContext, Stats, FlushCache, and bypass queries must NOT block!
	fastDone := make(chan struct{})
	go func() {
		defer close(fastDone)
		_ = srv.Stats()
		reqIR := new(mdns.Msg)
		reqIR.SetQuestion("fast.ir.", mdns.TypeA)
		resp, err := srv.Exchange(context.Background(), reqIR)
		if err != nil {
			t.Errorf("concurrent bypass Exchange error = %v", err)
			return
		}
		if ip, _ := extractFirstA(t, resp); ip != "185.5.5.5" {
			t.Errorf("concurrent bypass IP = %s, want 185.5.5.5", ip)
		}
	}()

	select {
	case <-fastDone:
	case <-time.After(300 * time.Millisecond):
		close(releaseDial)
		t.Fatal("Stats()/bypass Exchange blocked while tunnel DialContext was in-flight (mutex held across I/O!)")
	}

	close(releaseDial)
	if err := <-slowDone; err != nil {
		t.Fatalf("slow Exchange error = %v", err)
	}

	// Cancelling runCtx should trigger server shutdown cleanly, and Stop() remains idempotent.
	runCancel()
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() after runCancel: %v", err)
	}
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop(): %v", err)
	}

	// Nil and empty-question request validation.
	if _, err := srv.Exchange(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil request")
	}
	emptyResp, err := srv.Exchange(context.Background(), new(mdns.Msg))
	if err == nil || emptyResp == nil || emptyResp.Rcode != mdns.RcodeFormatError {
		t.Fatalf("expected FORMERR for empty question, got resp=%+v err=%v", emptyResp, err)
	}
}

func TestBypassFallbackUpstreamCyclingAndIdlePoolExpiry(t *testing.T) {
	t.Run("bypass cycles to secondary upstream when primary fails", func(t *testing.T) {
		dialer := &mockDialer{
			fn: func(_ context.Context, network, address string) (net.Conn, error) {
				if address == "192.168.1.1:53" {
					return nil, errors.New("primary ISP DNS unreachable")
				}
				return serveUDPPipe(func(req *mdns.Msg) *mdns.Msg {
					return makeAReply(req, "185.2.3.4", 60)
				}), nil
			},
		}

		fwd := newBypassForwarder(dialer, []string{"192.168.1.1:53", "192.168.1.2:53"}, 2*time.Second)
		defer fwd.Close()

		req := new(mdns.Msg)
		req.SetQuestion("bank.ir.", mdns.TypeA)
		resp, err := fwd.Exchange(context.Background(), req)
		if err != nil {
			t.Fatalf("bypass Exchange fallback: %v", err)
		}
		if ip, _ := extractFirstA(t, resp); ip != "185.2.3.4" {
			t.Fatalf("bypass fallback IP = %s, want 185.2.3.4", ip)
		}
		calls := dialer.Calls()
		if len(calls) != 2 || calls[0].address != "192.168.1.1:53" || calls[1].address != "192.168.1.2:53" {
			t.Fatalf("unexpected bypass dial calls: %+v", calls)
		}
	})

	t.Run("idle pooled TCP connection expires past idleTTL", func(t *testing.T) {
		nowMu := sync.Mutex{}
		nowTime := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
		dialer := &mockDialer{
			fn: func(_ context.Context, _, _ string) (net.Conn, error) {
				return serveTCPPipe(func(req *mdns.Msg) *mdns.Msg {
					return makeAReply(req, "1.2.3.4", 60)
				}), nil
			},
		}

		fwd := newTunnelTCPForwarder(dialer, []string{"1.1.1.1:53"}, 2*time.Second)
		fwd.now = func() time.Time {
			nowMu.Lock()
			defer nowMu.Unlock()
			return nowTime
		}
		defer fwd.Close()

		req := new(mdns.Msg)
		req.SetQuestion("pool.example.", mdns.TypeA)
		if _, err := fwd.Exchange(context.Background(), req); err != nil {
			t.Fatalf("Exchange 1: %v", err)
		}
		if dialer.CallCount() != 1 {
			t.Fatalf("CallCount 1 = %d, want 1", dialer.CallCount())
		}

		nowMu.Lock()
		nowTime = nowTime.Add(defaultIdleTCPConnTTL + time.Second)
		nowMu.Unlock()

		if _, err := fwd.Exchange(context.Background(), req); err != nil {
			t.Fatalf("Exchange 2: %v", err)
		}
		if dialer.CallCount() != 2 {
			t.Fatalf("expected fresh dial after idleTTL expiry, got CallCount=%d", dialer.CallCount())
		}
	})
}

func TestServerConcreteSharedPort(t *testing.T) {
	// Find a port free for TCP and UDP simultaneously to verify same host:port binding.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe tcp port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	tunnelDialer := &mockDialer{
		fn: func(_ context.Context, _, _ string) (net.Conn, error) {
			return serveTCPPipe(func(req *mdns.Msg) *mdns.Msg {
				return makeAReply(req, "198.51.100.55", 60)
			}), nil
		},
	}

	srv := NewServer()
	if err := srv.Start(context.Background(), DNSConfig{
		ListenAddr:   addr,
		TunnelDialer: tunnelDialer,
	}); err != nil {
		t.Skipf("port %s raced with OS before Start(): %v", addr, err)
	}
	defer srv.Stop(context.Background())

	if srv.UDPAddr() != addr || srv.TCPAddr() != addr {
		t.Fatalf("expected shared concrete addr %q, got udp=%q tcp=%q", addr, srv.UDPAddr(), srv.TCPAddr())
	}
	udpResp, tcpResp := queryUDPAndTCP(t, srv, "shared-port.example.")
	if ip, _ := extractFirstA(t, udpResp); ip != "198.51.100.55" {
		t.Fatalf("UDP IP = %s, want 198.51.100.55", ip)
	}
	if ip, _ := extractFirstA(t, tcpResp); ip != "198.51.100.55" {
		t.Fatalf("TCP IP = %s, want 198.51.100.55", ip)
	}
}

func TestNormalizeDNSAddrAndScopedIPv6Upstreams(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{raw: "fe80::1%eth0", want: "[fe80::1%eth0]:53"},
		{raw: "[fe80::1%eth0]:53", want: "[fe80::1%eth0]:53"},
		{raw: "2001:4860:4860::8888", want: "[2001:4860:4860::8888]:53"},
		{raw: "192.168.1.1", want: "192.168.1.1:53"},
		{raw: "192.168.1.1:5353", want: "192.168.1.1:5353"},
	}
	for _, tc := range cases {
		got, err := normalizeDNSAddr(tc.raw)
		if err != nil {
			t.Fatalf("normalizeDNSAddr(%q) unexpected error: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeDNSAddr(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	bypassDialer := &mockDialer{
		fn: func(_ context.Context, _, _ string) (net.Conn, error) {
			return serveUDPPipe(func(req *mdns.Msg) *mdns.Msg {
				return makeAReply(req, "185.7.7.7", 60)
			}), nil
		},
	}
	tunnelDialer := &mockDialer{
		fn: func(_ context.Context, _, _ string) (net.Conn, error) {
			return serveTCPPipe(func(req *mdns.Msg) *mdns.Msg {
				return makeAReply(req, "93.184.216.34", 60)
			}), nil
		},
	}

	srv := NewServer()
	if err := srv.Start(context.Background(), DNSConfig{
		ListenAddr:      "127.0.0.1:0",
		TunnelDialer:    tunnelDialer,
		BypassDialer:    bypassDialer,
		BypassUpstreams: []string{"fe80::1%eth0"},
		BypassIranLAN:   true,
	}); err != nil {
		t.Fatalf("Start with scoped IPv6 upstream failed: %v", err)
	}
	defer srv.Stop(context.Background())

	req := new(mdns.Msg)
	req.SetQuestion("scoped.ir.", mdns.TypeA)
	resp, err := srv.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange(scoped.ir.) error = %v", err)
	}
	if ip, _ := extractFirstA(t, resp); ip != "185.7.7.7" {
		t.Fatalf("scoped bypass IP = %s, want 185.7.7.7", ip)
	}
	calls := bypassDialer.Calls()
	if len(calls) != 1 || calls[0].address != "[fe80::1%eth0]:53" {
		t.Fatalf("expected dial to [fe80::1%%eth0]:53, got %+v", calls)
	}
}

func TestEmptyBypassUpstreamsFallsBackToTunnelForwarder(t *testing.T) {
	tunnelDialer := &mockDialer{
		fn: func(_ context.Context, _, _ string) (net.Conn, error) {
			return serveTCPPipe(func(req *mdns.Msg) *mdns.Msg {
				return makeAReply(req, "185.10.20.30", 60)
			}), nil
		},
	}

	srv := NewServer()
	if err := srv.Start(context.Background(), DNSConfig{
		ListenAddr:    "127.0.0.1:0",
		TunnelDialer:  tunnelDialer,
		BypassIranLAN: true,
	}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer srv.Stop(context.Background())

	req := new(mdns.Msg)
	req.SetQuestion("fallback.ir.", mdns.TypeA)
	resp, err := srv.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("Exchange(fallback.ir.) error = %v", err)
	}
	if ip, _ := extractFirstA(t, resp); ip != "185.10.20.30" {
		t.Fatalf("fallback.ir. IP = %s, want 185.10.20.30", ip)
	}
	if tunnelDialer.CallCount() != 1 {
		t.Fatalf("expected tunnelDialer call count 1, got %d", tunnelDialer.CallCount())
	}
}

func TestStartCancellationDoesNotDeadlock(t *testing.T) {
	tunnelDialer := &mockDialer{
		fn: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New("unused")
		},
	}

	for i := 0; i < 5; i++ {
		srv := NewServer()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Microsecond)
		err := srv.Start(ctx, DNSConfig{
			ListenAddr:   "127.0.0.1:0",
			TunnelDialer: tunnelDialer,
		})
		cancel()
		if err == nil {
			_ = srv.Stop(context.Background())
		}
	}
}
