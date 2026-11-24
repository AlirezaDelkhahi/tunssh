package dns

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	// DefaultListenAddr is the default unprivileged loopback bind address.
	DefaultListenAddr = "127.0.0.1:0"
	// DefaultTUNListenAddr is the standard TUN DNS intercept address in Full TUN mode.
	DefaultTUNListenAddr = "198.18.0.2:53"
	// DefaultCacheMaxEntries bounds the in-memory DNS LRU cache.
	DefaultCacheMaxEntries = 2048
	// MinCacheTTL is the lower bound for cached DNS record TTLs.
	MinCacheTTL = 10 * time.Second
	// MaxCacheTTL is the upper bound for cached DNS record TTLs.
	MaxCacheTTL = 300 * time.Second

	namespaceTunnel = "tunnel"
	namespaceBypass = "bypass"
)

// DNSConfig configures the embedded DNS server, upstreams, cache, and split bypass rules.
type DNSConfig struct {
	ListenAddr      string
	TunnelDialer    Dialer
	BypassDialer    Dialer
	TunnelUpstreams []string
	BypassUpstreams []string
	BypassIranLAN   bool
	QueryTimeout    time.Duration
	CacheMaxEntries int
	Transport       string
}

// DNSStats holds point-in-time DNS query, cache, and error counters.
type DNSStats struct {
	TotalQueries   uint64
	TunnelQueries  uint64
	BypassQueries  uint64
	CacheHits      uint64
	UpstreamErrors uint64
	CacheEntries   int
}

// DNSResolver runs the embedded miekg/dns interceptor.
type DNSResolver interface {
	Start(ctx context.Context, cfg DNSConfig) error
	Stop(ctx context.Context) error
	Stats() DNSStats
}

var _ DNSResolver = (*Server)(nil)

// ShouldBypassDomain reports whether qname should bypass the SSH tunnel when bypassIranLAN is enabled.
func ShouldBypassDomain(qname string, bypassIranLAN bool) bool {
	if !bypassIranLAN {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(qname))
	if name == "" || name == "." {
		return false
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	if name == "ir." || strings.HasSuffix(name, ".ir.") {
		return true
	}
	for _, suffix := range []string{
		".local.",
		".lan.",
		".home.arpa.",
		".in-addr.arpa.",
		".ip6.arpa.",
	} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

type cacheKey struct {
	namespace string
	qname     string
	qtype     uint16
	qclass    uint16
}

type cacheEntry struct {
	key       cacheKey
	msg       *dns.Msg
	expiresAt time.Time
}

type dnsCache struct {
	mu         sync.Mutex
	maxEntries int
	ll         *list.List
	items      map[cacheKey]*list.Element
	now        func() time.Time
	epoch      uint64
}

func newDNSCache(maxEntries int, nowFn func() time.Time) *dnsCache {
	if maxEntries <= 0 {
		maxEntries = DefaultCacheMaxEntries
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	return &dnsCache{
		maxEntries: maxEntries,
		ll:         list.New(),
		items:      make(map[cacheKey]*list.Element, maxEntries),
		now:        nowFn,
	}
}

func (c *dnsCache) currentEpoch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}

func (c *dnsCache) get(key cacheKey) (*dns.Msg, time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return nil, 0, false
	}
	entry := elem.Value.(*cacheEntry)
	now := c.now()
	if !now.Before(entry.expiresAt) {
		c.ll.Remove(elem)
		delete(c.items, key)
		return nil, 0, false
	}
	c.ll.MoveToFront(elem)
	remaining := entry.expiresAt.Sub(now)
	return entry.msg.Copy(), remaining, true
}

func (c *dnsCache) setAtEpoch(key cacheKey, msg *dns.Msg, expectedEpoch uint64) {
	if !isCacheableMsg(msg) {
		return
	}
	ttl := extractClampedTTL(msg)
	clone := msg.Copy()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.epoch != expectedEpoch {
		return
	}
	expiresAt := c.now().Add(ttl)

	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.msg = clone
		entry.expiresAt = expiresAt
		c.ll.MoveToFront(elem)
		return
	}

	if c.ll.Len() >= c.maxEntries {
		if tail := c.ll.Back(); tail != nil {
			c.ll.Remove(tail)
			evicted := tail.Value.(*cacheEntry)
			delete(c.items, evicted.key)
		}
	}

	entry := &cacheEntry{
		key:       key,
		msg:       clone,
		expiresAt: expiresAt,
	}
	elem := c.ll.PushFront(entry)
	c.items[key] = elem
}

func (c *dnsCache) flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	c.ll.Init()
	clear(c.items)
}

func (c *dnsCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func isCacheableMsg(msg *dns.Msg) bool {
	if msg == nil || msg.Truncated {
		return false
	}
	return msg.Rcode == dns.RcodeSuccess || msg.Rcode == dns.RcodeNameError
}

func extractClampedTTL(msg *dns.Msg) time.Duration {
	minSec, found := minRRTTL(msg.Answer)
	if !found {
		minSec, found = minRRTTL(msg.Ns)
	}
	if !found {
		minSec = 0
	}
	ttl := time.Duration(minSec) * time.Second
	if ttl < MinCacheTTL {
		ttl = MinCacheTTL
	}
	if ttl > MaxCacheTTL {
		ttl = MaxCacheTTL
	}
	return ttl
}

func minRRTTL(rrs []dns.RR) (uint32, bool) {
	var minTTL uint32
	found := false
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		hdr := rr.Header()
		if hdr.Rrtype == dns.TypeOPT {
			continue
		}
		if !found || hdr.Ttl < minTTL {
			minTTL = hdr.Ttl
			found = true
		}
	}
	return minTTL, found
}

func rewriteReplyTTL(msg *dns.Msg, remaining time.Duration) {
	sec := uint32((remaining + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	maxSec := uint32(MaxCacheTTL / time.Second)
	if sec > maxSec {
		sec = maxSec
	}
	rewriteRRListTTL(msg.Answer, sec)
	rewriteRRListTTL(msg.Ns, sec)
	rewriteRRListTTL(msg.Extra, sec)
}

func rewriteRRListTTL(rrs []dns.RR, ttl uint32) {
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		hdr := rr.Header()
		if hdr.Rrtype == dns.TypeOPT {
			continue
		}
		hdr.Ttl = ttl
	}
}

func rcodeReply(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	if req != nil {
		resp.SetRcode(req, rcode)
	} else {
		resp.Response = true
		resp.Rcode = rcode
	}
	resp.RecursionAvailable = true
	return resp
}

// Server serves embedded UDP and TCP DNS queries with split .ir/LAN forwarding and bounded LRU caching.
type Server struct {
	now func() time.Time // optional clock override for deterministic unit testing

	mu           sync.Mutex
	starting     bool
	running      bool
	stopping     bool
	udpServer    *dns.Server
	tcpServer    *dns.Server
	udpAddr      string
	tcpAddr      string
	tunnelFwd    forwarder
	bypassFwd    forwarder
	cache        *dnsCache
	queryTimeout time.Duration
	runCancel    context.CancelFunc
	wg           sync.WaitGroup

	bypassIranLAN  atomic.Bool
	totalQueries   atomic.Uint64
	tunnelQueries  atomic.Uint64
	bypassQueries  atomic.Uint64
	cacheHits      atomic.Uint64
	upstreamErrors atomic.Uint64
}

// NewServer constructs an unstarted DNS Server.
func NewServer() *Server {
	return &Server{}
}

func (s *Server) nowFunc() func() time.Time {
	if s.now != nil {
		return s.now
	}
	return time.Now
}

// Start validates cfg, binds UDP and TCP listeners, and launches the embedded miekg/dns servers.
func (s *Server) Start(ctx context.Context, cfg DNSConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if cfg.TunnelDialer == nil {
		return errors.New("dns: TunnelDialer must not be nil")
	}

	transport := UpstreamTransport(strings.ToLower(strings.TrimSpace(cfg.Transport)))
	if transport == "" {
		transport = UpstreamTransportTCP
	}
	if transport != UpstreamTransportTCP && transport != UpstreamTransportDoH {
		return fmt.Errorf("dns: unsupported transport %q", cfg.Transport)
	}

	listenAddr := strings.TrimSpace(cfg.ListenAddr)
	if listenAddr == "" {
		listenAddr = DefaultListenAddr
	}
	if _, _, err := net.SplitHostPort(listenAddr); err != nil {
		return fmt.Errorf("dns: invalid ListenAddr %q: %w", listenAddr, err)
	}

	queryTimeout := cfg.QueryTimeout
	if queryTimeout <= 0 {
		queryTimeout = DefaultQueryTimeout
	}
	cacheMax := cfg.CacheMaxEntries
	if cacheMax <= 0 {
		cacheMax = DefaultCacheMaxEntries
	}

	tunnelUpstreams, err := prepareTunnelUpstreams(transport, cfg.TunnelUpstreams)
	if err != nil {
		return err
	}
	bypassUpstreams, err := prepareBypassUpstreams(cfg.BypassUpstreams)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.running || s.starting {
		s.mu.Unlock()
		return errors.New("dns: server already started")
	}
	s.starting = true
	s.mu.Unlock()

	resetStarting := func() {
		s.mu.Lock()
		s.starting = false
		s.mu.Unlock()
	}

	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		resetStarting()
		return fmt.Errorf("dns: listen UDP %q: %w", listenAddr, err)
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		_ = pc.Close()
		resetStarting()
		return fmt.Errorf("dns: listen TCP %q: %w", listenAddr, err)
	}
	if err := ctx.Err(); err != nil {
		_ = pc.Close()
		_ = ln.Close()
		resetStarting()
		return err
	}

	var tunnelFwd forwarder
	if transport == UpstreamTransportDoH {
		tunnelFwd = newTunnelDoHForwarder(cfg.TunnelDialer, tunnelUpstreams, queryTimeout)
	} else {
		tunnelFwd = newTunnelTCPForwarder(cfg.TunnelDialer, tunnelUpstreams, queryTimeout)
	}
	var bypassFwd forwarder
	if cfg.BypassDialer != nil && len(bypassUpstreams) > 0 {
		bypassFwd = newBypassForwarder(cfg.BypassDialer, bypassUpstreams, queryTimeout)
	}
	cache := newDNSCache(cacheMax, s.nowFunc())

	runCtx, runCancel := context.WithCancel(ctx)
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.serveDNS(runCtx, w, r)
	})

	udpStarted := make(chan struct{})
	tcpStarted := make(chan struct{})
	var udpStartOnce sync.Once
	var tcpStartOnce sync.Once

	ioTimeout := queryTimeout + time.Second
	if ioTimeout < 2*time.Second {
		ioTimeout = 2 * time.Second
	}

	udpSrv := &dns.Server{
		PacketConn:   pc,
		Handler:      handler,
		UDPSize:      dns.DefaultMsgSize,
		ReadTimeout:  ioTimeout,
		WriteTimeout: ioTimeout,
		NotifyStartedFunc: func() {
			udpStartOnce.Do(func() { close(udpStarted) })
		},
	}
	tcpSrv := &dns.Server{
		Listener:     ln,
		Handler:      handler,
		ReadTimeout:  ioTimeout,
		WriteTimeout: ioTimeout,
		NotifyStartedFunc: func() {
			tcpStartOnce.Do(func() { close(tcpStarted) })
		},
	}

	s.mu.Lock()
	s.bypassIranLAN.Store(cfg.BypassIranLAN)
	s.udpServer = udpSrv
	s.tcpServer = tcpSrv
	s.udpAddr = pc.LocalAddr().String()
	s.tcpAddr = ln.Addr().String()
	s.tunnelFwd = tunnelFwd
	s.bypassFwd = bypassFwd
	s.cache = cache
	s.queryTimeout = queryTimeout
	s.runCancel = runCancel
	s.stopping = false
	s.running = true
	s.starting = false
	s.wg.Add(3)
	s.mu.Unlock()

	udpErrCh := make(chan error, 1)
	tcpErrCh := make(chan error, 1)

	go s.watchShutdown(runCtx)
	go func() {
		defer s.wg.Done()
		udpErrCh <- udpSrv.ActivateAndServe()
	}()
	go func() {
		defer s.wg.Done()
		tcpErrCh <- tcpSrv.ActivateAndServe()
	}()

	if err := waitStarted(ctx, udpStarted, udpErrCh); err != nil {
		_ = pc.Close()
		_ = ln.Close()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = s.Stop(stopCtx)
		stopCancel()
		return fmt.Errorf("dns: start UDP server: %w", err)
	}
	if err := waitStarted(ctx, tcpStarted, tcpErrCh); err != nil {
		_ = pc.Close()
		_ = ln.Close()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = s.Stop(stopCtx)
		stopCancel()
		return fmt.Errorf("dns: start TCP server: %w", err)
	}
	return nil
}

func prepareTunnelUpstreams(transport UpstreamTransport, raw []string) ([]string, error) {
	if transport == UpstreamTransportDoH {
		var out []string
		for _, item := range raw {
			u := strings.TrimSpace(item)
			if u == "" {
				continue
			}
			if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
				return nil, fmt.Errorf("dns: invalid DoH upstream URL %q", item)
			}
			out = append(out, u)
		}
		if len(out) == 0 {
			return []string{DefaultDoHUpstream}, nil
		}
		return out, nil
	}

	var out []string
	for _, item := range raw {
		if strings.TrimSpace(item) == "" {
			continue
		}
		norm, err := normalizeDNSAddr(item)
		if err != nil {
			return nil, err
		}
		out = append(out, norm)
	}
	if len(out) == 0 {
		return defaultTunnelTCPUpstreams(), nil
	}
	return out, nil
}

func prepareBypassUpstreams(raw []string) ([]string, error) {
	var out []string
	for _, item := range raw {
		if strings.TrimSpace(item) == "" {
			continue
		}
		norm, err := normalizeDNSAddr(item)
		if err != nil {
			return nil, err
		}
		out = append(out, norm)
	}
	return out, nil
}

func waitStarted(ctx context.Context, started <-chan struct{}, errCh <-chan error) error {
	select {
	case <-started:
		return nil
	case err := <-errCh:
		if err != nil {
			return err
		}
		return errors.New("server exited before listening")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) watchShutdown(runCtx context.Context) {
	defer s.wg.Done()
	<-runCtx.Done()
	s.shutdown(context.Background())
}

func (s *Server) shutdown(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if !s.running || s.stopping {
		s.mu.Unlock()
		return
	}
	s.stopping = true
	runCancel := s.runCancel
	udpSrv := s.udpServer
	tcpSrv := s.tcpServer
	tunnelFwd := s.tunnelFwd
	bypassFwd := s.bypassFwd
	cache := s.cache
	s.mu.Unlock()

	if runCancel != nil {
		runCancel()
	}
	if udpSrv != nil {
		_ = udpSrv.ShutdownContext(ctx)
	}
	if tcpSrv != nil {
		_ = tcpSrv.ShutdownContext(ctx)
	}
	if tunnelFwd != nil {
		_ = tunnelFwd.Close()
	}
	if bypassFwd != nil {
		_ = bypassFwd.Close()
	}
	if cache != nil {
		cache.flush()
	}
}

// Stop shuts down both UDP and TCP DNS servers, closes pooled upstream connections, and flushes the cache.
func (s *Server) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	s.shutdown(ctx)

	waitDone := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		s.mu.Lock()
		cache := s.cache
		s.running = false
		s.stopping = false
		s.udpServer = nil
		s.tcpServer = nil
		s.tunnelFwd = nil
		s.bypassFwd = nil
		s.runCancel = nil
		s.mu.Unlock()
		if cache != nil {
			cache.flush()
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetBypassIranLAN dynamically updates Iran/LAN bypass routing and flushes the cache when toggled.
func (s *Server) SetBypassIranLAN(bypass bool) {
	prev := s.bypassIranLAN.Swap(bypass)
	if prev != bypass {
		s.FlushCache()
	}
}

// FlushCache removes all entries from the DNS response cache.
func (s *Server) FlushCache() {
	s.mu.Lock()
	cache := s.cache
	s.mu.Unlock()
	if cache != nil {
		cache.flush()
	}
}

// UDPAddr returns the bound UDP listener address.
func (s *Server) UDPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpAddr
}

// TCPAddr returns the bound TCP listener address.
func (s *Server) TCPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpAddr
}

// Stats returns a point-in-time snapshot of DNS query, cache, and error statistics.
func (s *Server) Stats() DNSStats {
	s.mu.Lock()
	cache := s.cache
	s.mu.Unlock()

	entries := 0
	if cache != nil {
		entries = cache.len()
	}
	return DNSStats{
		TotalQueries:   s.totalQueries.Load(),
		TunnelQueries:  s.tunnelQueries.Load(),
		BypassQueries:  s.bypassQueries.Load(),
		CacheHits:      s.cacheHits.Load(),
		UpstreamErrors: s.upstreamErrors.Load(),
		CacheEntries:   entries,
	}
}

func (s *Server) serveDNS(runCtx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	resp, _ := s.Exchange(runCtx, req)
	if resp != nil {
		_ = w.WriteMsg(resp)
	}
}

// Exchange resolves a single DNS request through the LRU cache or split tunnel/bypass upstream forwarders.
func (s *Server) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if req == nil {
		return nil, errors.New("dns: request must not be nil")
	}
	s.totalQueries.Add(1)

	if len(req.Question) == 0 {
		return rcodeReply(req, dns.RcodeFormatError), errors.New("dns: empty question section")
	}

	s.mu.Lock()
	if !s.running || s.stopping {
		s.mu.Unlock()
		s.upstreamErrors.Add(1)
		return rcodeReply(req, dns.RcodeServerFailure), errors.New("dns: server not started")
	}
	tunnelFwd := s.tunnelFwd
	bypassFwd := s.bypassFwd
	cache := s.cache
	queryTimeout := s.queryTimeout
	s.mu.Unlock()

	q := req.Question[0]
	bypass := ShouldBypassDomain(q.Name, s.bypassIranLAN.Load())
	namespace := namespaceTunnel
	fwd := tunnelFwd
	if bypass && bypassFwd != nil {
		namespace = namespaceBypass
		fwd = bypassFwd
		s.bypassQueries.Add(1)
	} else {
		s.tunnelQueries.Add(1)
	}

	key := cacheKey{
		namespace: namespace,
		qname:     strings.ToLower(dns.Fqdn(q.Name)),
		qtype:     q.Qtype,
		qclass:    q.Qclass,
	}

	if cache != nil {
		if cached, remaining, ok := cache.get(key); ok {
			s.cacheHits.Add(1)
			cached.Id = req.Id
			if len(cached.Question) > 0 {
				cached.Question[0].Name = q.Name
			}
			rewriteReplyTTL(cached, remaining)
			return cached, nil
		}
	}

	var epoch uint64
	if cache != nil {
		epoch = cache.currentEpoch()
	}

	qCtx, cancel := withQueryTimeout(ctx, queryTimeout)
	defer cancel()

	resp, err := fwd.Exchange(qCtx, req)
	if err != nil {
		s.upstreamErrors.Add(1)
		return rcodeReply(req, dns.RcodeServerFailure), err
	}
	if resp == nil {
		s.upstreamErrors.Add(1)
		return rcodeReply(req, dns.RcodeServerFailure), errors.New("dns: empty upstream response")
	}

	if cache != nil {
		cache.setAtEpoch(key, resp, epoch)
	}
	return resp, nil
}
