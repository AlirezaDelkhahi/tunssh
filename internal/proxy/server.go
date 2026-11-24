// Package proxy implements loopback-only SOCKS5 (socks5h) and HTTP CONNECT proxy servers.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultSOCKSAddr is the default loopback bind address for the SOCKS5 proxy.
	DefaultSOCKSAddr = "127.0.0.1:10808"
	// DefaultHTTPAddr is the default loopback bind address for the HTTP CONNECT proxy.
	DefaultHTTPAddr = "127.0.0.1:10809"
	// DefaultHandshakeTimeout bounds SOCKS5 and HTTP proxy handshake/dial completion.
	DefaultHandshakeTimeout = 10 * time.Second
)

// Dialer establishes outbound tunnel connections without performing local DNS lookups.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Config configures the local SOCKS5 and HTTP proxy listeners.
type Config struct {
	SOCKSAddr        string
	HTTPAddr         string
	HandshakeTimeout time.Duration
}

// Stats holds a point-in-time snapshot of proxy traffic and active listener addresses.
type Stats struct {
	RxBytes     uint64
	TxBytes     uint64
	ActiveConns int64
	SOCKSAddr   string
	HTTPAddr    string
}

// Server serves local SOCKS5 (socks5h) and HTTP proxy traffic over a Dialer.
type Server struct {
	dialer        Dialer
	cfg           Config
	httpTransport *http.Transport

	mu        sync.Mutex
	starting  bool
	running   bool
	stopping  bool
	socksLn   net.Listener
	httpLn    net.Listener
	socksAddr string
	httpAddr  string
	runCancel context.CancelFunc
	conns     map[*trackedConn]struct{}
	wg        sync.WaitGroup

	rxBytes     atomic.Uint64
	txBytes     atomic.Uint64
	activeConns atomic.Int64
}

type trackedConn struct {
	mu     sync.Mutex
	closed bool
	local  net.Conn
	remote net.Conn
}

func (tc *trackedConn) setRemote(remote net.Conn) bool {
	tc.mu.Lock()
	if tc.closed {
		tc.mu.Unlock()
		if remote != nil {
			_ = remote.Close()
		}
		return false
	}
	tc.remote = remote
	tc.mu.Unlock()
	return true
}

func (tc *trackedConn) closeAll() {
	tc.mu.Lock()
	if tc.closed {
		tc.mu.Unlock()
		return
	}
	tc.closed = true
	local := tc.local
	remote := tc.remote
	tc.remote = nil
	tc.mu.Unlock()

	if local != nil {
		_ = local.Close()
	}
	if remote != nil {
		_ = remote.Close()
	}
}

type countingWriter struct {
	w       io.Writer
	counter *atomic.Uint64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	if n > 0 {
		cw.counter.Add(uint64(n))
	}
	return n, err
}

type countingConn struct {
	net.Conn
	rxBytes *atomic.Uint64
	txBytes *atomic.Uint64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.rxBytes.Add(uint64(n))
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.txBytes.Add(uint64(n))
	}
	return n, err
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// isLoopbackAddr validates that addr has a valid port and binds strictly to a loopback host.
func isLoopbackAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return false
	}
	if host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewServer constructs a loopback-only proxy Server using dialer and cfg.
func NewServer(dialer Dialer, cfg Config) (*Server, error) {
	if dialer == nil {
		return nil, errors.New("proxy: dialer must not be nil")
	}
	if cfg.SOCKSAddr == "" {
		cfg.SOCKSAddr = DefaultSOCKSAddr
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = DefaultHTTPAddr
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if !isLoopbackAddr(cfg.SOCKSAddr) {
		return nil, fmt.Errorf("proxy: SOCKSAddr %q must be a loopback address", cfg.SOCKSAddr)
	}
	if !isLoopbackAddr(cfg.HTTPAddr) {
		return nil, fmt.Errorf("proxy: HTTPAddr %q must be a loopback address", cfg.HTTPAddr)
	}

	s := &Server{
		dialer:    dialer,
		cfg:       cfg,
		socksAddr: cfg.SOCKSAddr,
		httpAddr:  cfg.HTTPAddr,
		conns:     make(map[*trackedConn]struct{}),
	}
	s.httpTransport = &http.Transport{
		// Explicitly nil to avoid looping back into HTTP_PROXY environment variables.
		Proxy:              nil,
		DisableCompression: true,
		IdleConnTimeout:    30 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := s.dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &countingConn{
				Conn:    conn,
				rxBytes: &s.rxBytes,
				txBytes: &s.txBytes,
			}, nil
		},
	}
	return s, nil
}

// Start binds both loopback listeners and begins serving SOCKS5 and HTTP proxy connections.
func (s *Server) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !isLoopbackAddr(s.cfg.SOCKSAddr) {
		return fmt.Errorf("proxy: SOCKSAddr %q must be a loopback address", s.cfg.SOCKSAddr)
	}
	if !isLoopbackAddr(s.cfg.HTTPAddr) {
		return fmt.Errorf("proxy: HTTPAddr %q must be a loopback address", s.cfg.HTTPAddr)
	}

	s.mu.Lock()
	if s.running || s.starting {
		s.mu.Unlock()
		return errors.New("proxy: server already started")
	}
	s.starting = true
	s.mu.Unlock()

	resetStarting := func() {
		s.mu.Lock()
		s.starting = false
		s.mu.Unlock()
	}

	socksLn, err := net.Listen("tcp", s.cfg.SOCKSAddr)
	if err != nil {
		resetStarting()
		return fmt.Errorf("proxy: listen SOCKS5 %q: %w", s.cfg.SOCKSAddr, err)
	}
	httpLn, err := net.Listen("tcp", s.cfg.HTTPAddr)
	if err != nil {
		_ = socksLn.Close()
		resetStarting()
		return fmt.Errorf("proxy: listen HTTP %q: %w", s.cfg.HTTPAddr, err)
	}
	if err := ctx.Err(); err != nil {
		_ = socksLn.Close()
		_ = httpLn.Close()
		resetStarting()
		return err
	}

	runCtx, runCancel := context.WithCancel(ctx)

	s.mu.Lock()
	s.socksLn = socksLn
	s.httpLn = httpLn
	s.socksAddr = socksLn.Addr().String()
	s.httpAddr = httpLn.Addr().String()
	s.runCancel = runCancel
	s.conns = make(map[*trackedConn]struct{})
	s.stopping = false
	s.running = true
	s.starting = false
	s.wg.Add(3)
	s.mu.Unlock()

	go s.watchShutdown(runCtx)
	go s.acceptLoop(runCtx, socksLn, s.handleSOCKS5)
	go s.acceptLoop(runCtx, httpLn, s.handleHTTP)

	return nil
}

// Stop shuts down listeners first, closes active connections, and waits for all goroutines to exit.
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

	s.shutdown()

	waitDone := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		s.mu.Lock()
		s.running = false
		s.socksLn = nil
		s.httpLn = nil
		s.runCancel = nil
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SOCKSAddr returns the configured or bound SOCKS5 listener address.
func (s *Server) SOCKSAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.socksAddr
}

// HTTPAddr returns the configured or bound HTTP proxy listener address.
func (s *Server) HTTPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpAddr
}

// Stats returns a thread-safe snapshot of transferred byte counts, active connections, and addresses.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	socksAddr := s.socksAddr
	httpAddr := s.httpAddr
	s.mu.Unlock()

	return Stats{
		RxBytes:     s.rxBytes.Load(),
		TxBytes:     s.txBytes.Load(),
		ActiveConns: s.activeConns.Load(),
		SOCKSAddr:   socksAddr,
		HTTPAddr:    httpAddr,
	}
}

func (s *Server) watchShutdown(runCtx context.Context) {
	defer s.wg.Done()
	<-runCtx.Done()
	s.shutdown()
}

func (s *Server) shutdown() {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	s.stopping = true
	socksLn := s.socksLn
	httpLn := s.httpLn
	cancel := s.runCancel
	conns := make([]*trackedConn, 0, len(s.conns))
	for tc := range s.conns {
		conns = append(conns, tc)
	}
	s.mu.Unlock()

	if socksLn != nil {
		_ = socksLn.Close()
	}
	if httpLn != nil {
		_ = httpLn.Close()
	}
	if cancel != nil {
		cancel()
	}
	for _, tc := range conns {
		tc.closeAll()
	}
	if s.httpTransport != nil {
		s.httpTransport.CloseIdleConnections()
	}
}

func (s *Server) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

func (s *Server) acceptLoop(runCtx context.Context, ln net.Listener, handler func(context.Context, *trackedConn)) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || runCtx.Err() != nil || s.isStopping() {
				return
			}
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-runCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		if !s.spawnConn(runCtx, conn, handler) {
			_ = conn.Close()
			return
		}
	}
}

func (s *Server) spawnConn(runCtx context.Context, conn net.Conn, handler func(context.Context, *trackedConn)) bool {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return false
	}
	tc := &trackedConn{local: conn}
	s.conns[tc] = struct{}{}
	s.activeConns.Add(1)
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.wg.Done()
		defer s.untrackConn(tc)
		defer tc.closeAll()
		handler(runCtx, tc)
	}()
	return true
}

func (s *Server) untrackConn(tc *trackedConn) {
	s.mu.Lock()
	if _, ok := s.conns[tc]; ok {
		delete(s.conns, tc)
		s.activeConns.Add(-1)
	}
	s.mu.Unlock()
}

func (s *Server) relay(client, remote net.Conn) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(&countingWriter{w: remote, counter: &s.txBytes}, client)
		if err == nil {
			closeWrite(remote)
		} else {
			_ = remote.Close()
			_ = client.Close()
		}
		errCh <- err
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(&countingWriter{w: client, counter: &s.rxBytes}, remote)
		if err == nil {
			closeWrite(client)
		} else {
			_ = client.Close()
			_ = remote.Close()
		}
		errCh <- err
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
