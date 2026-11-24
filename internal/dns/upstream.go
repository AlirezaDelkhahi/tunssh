// Package dns implements the embedded DNS interceptor, bounded LRU TTL cache, and split .ir/LAN forwarding.
package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// DefaultQueryTimeout bounds upstream DNS forwarding operations.
	DefaultQueryTimeout = 4 * time.Second
	// DefaultDoHUpstream is the default DNS-over-HTTPS endpoint used over TunnelDialer.
	DefaultDoHUpstream = "https://1.1.1.1/dns-query"

	defaultMaxIdleTCPConnsPerAddr = 4
	defaultIdleTCPConnTTL         = 60 * time.Second
	maxDNSWireSize                = 65535
	minDNSWireSize                = 12
)

// UpstreamTransport selects the DNS forwarding transport used over TunnelDialer.
type UpstreamTransport string

const (
	// UpstreamTransportTCP forwards queries using DNS-over-TCP (RFC 7766).
	UpstreamTransportTCP UpstreamTransport = "tcp"
	// UpstreamTransportDoH forwards queries using DNS-over-HTTPS (RFC 8484).
	UpstreamTransportDoH UpstreamTransport = "doh"
)

// Dialer establishes outbound tunnel or bypass connections.
// Implementations must be safe for concurrent use and hold zero locks across I/O.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type forwarder interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	Close() error
}

func defaultTunnelTCPUpstreams() []string {
	return []string{"1.1.1.1:53", "8.8.8.8:53"}
}

func normalizeDNSAddr(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return "", errors.New("dns: empty upstream address")
	}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("dns: invalid upstream address %q", raw)
		}
		return net.JoinHostPort(host, port), nil
	}
	// Accept bare IPv4/IPv6 (including scoped link-local like fe80::1%eth0) or hostname and default to port 53.
	if ip, err := netip.ParseAddr(addr); err == nil && ip.IsValid() {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if strings.Contains(addr, ":") {
		return "", fmt.Errorf("dns: invalid upstream address %q", raw)
	}
	return net.JoinHostPort(addr, "53"), nil
}

func withQueryTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = DefaultQueryTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func applyConnDeadline(ctx context.Context, conn net.Conn) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func packTCPFrame(req *dns.Msg) ([]byte, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("dns: pack query: %w", err)
	}
	if len(wire) > maxDNSWireSize {
		return nil, fmt.Errorf("dns: query wire length %d exceeds %d", len(wire), maxDNSWireSize)
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	return frame, nil
}

func exchangeTCPConn(ctx context.Context, conn net.Conn, reqID uint16, frame []byte) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	applyConnDeadline(ctx, conn)
	stopWatch := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer func() {
		// Reclaim cancellation watcher cleanly when I/O finishes normally.
		_ = stopWatch()
	}()

	if err := writeAll(conn, frame); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if msgLen < minDNSWireSize {
		return nil, fmt.Errorf("dns: invalid TCP response length %d", msgLen)
	}

	payload := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	if !stopWatch() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, context.Canceled
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(payload); err != nil {
		return nil, fmt.Errorf("dns: unpack TCP response: %w", err)
	}
	if resp.Id != reqID {
		return nil, fmt.Errorf("dns: TCP response ID mismatch: got %d want %d", resp.Id, reqID)
	}
	return resp, nil
}

type pooledTCPConn struct {
	conn     net.Conn
	lastUsed time.Time
}

type tunnelTCPForwarder struct {
	dialer         Dialer
	upstreams      []string
	queryTimeout   time.Duration
	idleTTL        time.Duration
	maxIdlePerAddr int
	now            func() time.Time

	mu     sync.Mutex
	closed bool
	idle   map[string][]*pooledTCPConn
}

func newTunnelTCPForwarder(dialer Dialer, upstreams []string, queryTimeout time.Duration) *tunnelTCPForwarder {
	if len(upstreams) == 0 {
		upstreams = defaultTunnelTCPUpstreams()
	}
	if queryTimeout <= 0 {
		queryTimeout = DefaultQueryTimeout
	}
	copied := make([]string, len(upstreams))
	copy(copied, upstreams)
	return &tunnelTCPForwarder{
		dialer:         dialer,
		upstreams:      copied,
		queryTimeout:   queryTimeout,
		idleTTL:        defaultIdleTCPConnTTL,
		maxIdlePerAddr: defaultMaxIdleTCPConnsPerAddr,
		now:            time.Now,
		idle:           make(map[string][]*pooledTCPConn, len(copied)),
	}
}

func (f *tunnelTCPForwarder) getIdleConn(addr string) net.Conn {
	var expired []net.Conn
	var picked net.Conn

	now := f.now()
	f.mu.Lock()
	if !f.closed {
		list := f.idle[addr]
		for len(list) > 0 {
			n := len(list) - 1
			entry := list[n]
			list[n] = nil
			list = list[:n]
			if f.idleTTL > 0 && now.Sub(entry.lastUsed) > f.idleTTL {
				expired = append(expired, entry.conn)
				continue
			}
			picked = entry.conn
			break
		}
		if len(list) == 0 {
			delete(f.idle, addr)
		} else {
			f.idle[addr] = list
		}
	}
	f.mu.Unlock()

	for _, c := range expired {
		_ = c.Close()
	}
	return picked
}

func (f *tunnelTCPForwarder) putIdleConn(addr string, conn net.Conn) {
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	f.mu.Lock()
	if f.closed || len(f.idle[addr]) >= f.maxIdlePerAddr {
		f.mu.Unlock()
		_ = conn.Close()
		return
	}
	f.idle[addr] = append(f.idle[addr], &pooledTCPConn{
		conn:     conn,
		lastUsed: f.now(),
	})
	f.mu.Unlock()
}

func (f *tunnelTCPForwarder) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if f.dialer == nil {
		return nil, errors.New("dns: TunnelDialer must not be nil")
	}
	frame, err := packTCPFrame(req)
	if err != nil {
		return nil, err
	}

	qCtx, cancel := withQueryTimeout(ctx, f.queryTimeout)
	defer cancel()

	var lastErr error
	for _, addr := range f.upstreams {
		if err := qCtx.Err(); err != nil {
			return nil, err
		}

		// Try pooled idle connection first; on stale EOF/failure, close and retry once with a fresh dial.
		if pooled := f.getIdleConn(addr); pooled != nil {
			resp, err := exchangeTCPConn(qCtx, pooled, req.Id, frame)
			if err == nil {
				if qCtx.Err() == nil {
					f.putIdleConn(addr, pooled)
				} else {
					_ = pooled.Close()
				}
				return resp, nil
			}
			_ = pooled.Close()
			if qCtxErr := qCtx.Err(); qCtxErr != nil {
				return nil, qCtxErr
			}
		}

		conn, err := f.dialer.DialContext(qCtx, "tcp", addr)
		if err != nil {
			lastErr = err
			if qCtxErr := qCtx.Err(); qCtxErr != nil {
				return nil, qCtxErr
			}
			continue
		}
		if qCtxErr := qCtx.Err(); qCtxErr != nil {
			_ = conn.Close()
			return nil, qCtxErr
		}

		resp, err := exchangeTCPConn(qCtx, conn, req.Id, frame)
		if err == nil {
			if qCtx.Err() == nil {
				f.putIdleConn(addr, conn)
			} else {
				_ = conn.Close()
			}
			return resp, nil
		}
		_ = conn.Close()
		lastErr = err
		if qCtxErr := qCtx.Err(); qCtxErr != nil {
			return nil, qCtxErr
		}
	}

	if lastErr == nil {
		if err := qCtx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("dns: no tunnel upstreams configured")
	}
	return nil, lastErr
}

func (f *tunnelTCPForwarder) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	var toClose []net.Conn
	for _, list := range f.idle {
		for _, entry := range list {
			if entry != nil && entry.conn != nil {
				toClose = append(toClose, entry.conn)
			}
		}
	}
	f.idle = nil
	f.mu.Unlock()

	for _, c := range toClose {
		_ = c.Close()
	}
	return nil
}

type tunnelDoHForwarder struct {
	upstreams    []string
	queryTimeout time.Duration
	transport    *http.Transport
	client       *http.Client
}

func newTunnelDoHForwarder(dialer Dialer, upstreams []string, queryTimeout time.Duration) *tunnelDoHForwarder {
	if len(upstreams) == 0 {
		upstreams = []string{DefaultDoHUpstream}
	}
	if queryTimeout <= 0 {
		queryTimeout = DefaultQueryTimeout
	}
	copied := make([]string, len(upstreams))
	copy(copied, upstreams)

	tr := &http.Transport{
		// Explicitly disable OS HTTP_PROXY env vars so DoH never loops into system proxy.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       defaultIdleTCPConnTTL,
		TLSHandshakeTimeout:   queryTimeout,
		ExpectContinueTimeout: time.Second,
	}
	return &tunnelDoHForwarder{
		upstreams:    copied,
		queryTimeout: queryTimeout,
		transport:    tr,
		client:       &http.Client{Transport: tr},
	}
}

func (f *tunnelDoHForwarder) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("dns: pack DoH query: %w", err)
	}
	qCtx, cancel := withQueryTimeout(ctx, f.queryTimeout)
	defer cancel()

	var lastErr error
	for _, endpoint := range f.upstreams {
		if err := qCtx.Err(); err != nil {
			return nil, err
		}

		httpReq, err := http.NewRequestWithContext(qCtx, http.MethodPost, endpoint, bytes.NewReader(wire))
		if err != nil {
			lastErr = err
			continue
		}
		httpReq.Header.Set("Content-Type", "application/dns-message")
		httpReq.Header.Set("Accept", "application/dns-message")

		httpResp, err := f.client.Do(httpReq)
		if err != nil {
			lastErr = err
			if qCtxErr := qCtx.Err(); qCtxErr != nil {
				return nil, qCtxErr
			}
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(httpResp.Body, maxDNSWireSize+1))
		_ = httpResp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if httpResp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("dns: DoH endpoint %s returned HTTP %d", endpoint, httpResp.StatusCode)
			continue
		}
		if len(body) < minDNSWireSize || len(body) > maxDNSWireSize {
			lastErr = fmt.Errorf("dns: DoH response size %d out of range", len(body))
			continue
		}

		resp := new(dns.Msg)
		if err := resp.Unpack(body); err != nil {
			lastErr = fmt.Errorf("dns: unpack DoH response: %w", err)
			continue
		}
		if resp.Id != req.Id {
			lastErr = fmt.Errorf("dns: DoH response ID mismatch: got %d want %d", resp.Id, req.Id)
			continue
		}
		return resp, nil
	}

	if lastErr == nil {
		if err := qCtx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("dns: no DoH upstreams configured")
	}
	return nil, lastErr
}

func (f *tunnelDoHForwarder) Close() error {
	if f.transport != nil {
		f.transport.CloseIdleConnections()
	}
	return nil
}

type bypassForwarder struct {
	dialer       Dialer
	upstreams    []string
	queryTimeout time.Duration
}

func newBypassForwarder(dialer Dialer, upstreams []string, queryTimeout time.Duration) *bypassForwarder {
	if queryTimeout <= 0 {
		queryTimeout = DefaultQueryTimeout
	}
	copied := make([]string, len(upstreams))
	copy(copied, upstreams)
	return &bypassForwarder{
		dialer:       dialer,
		upstreams:    copied,
		queryTimeout: queryTimeout,
	}
}

func (f *bypassForwarder) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if f.dialer == nil {
		return nil, errors.New("dns: BypassDialer must not be nil")
	}
	if len(f.upstreams) == 0 {
		return nil, errors.New("dns: no bypass upstreams configured")
	}

	wire, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("dns: pack bypass query: %w", err)
	}

	qCtx, cancel := withQueryTimeout(ctx, f.queryTimeout)
	defer cancel()

	var tcpFrame []byte
	var lastErr error
	for _, addr := range f.upstreams {
		if err := qCtx.Err(); err != nil {
			return nil, err
		}

		resp, err := f.exchangeUDP(qCtx, addr, req.Id, wire)
		if err != nil {
			lastErr = err
			if qCtxErr := qCtx.Err(); qCtxErr != nil {
				return nil, qCtxErr
			}
			continue
		}

		if resp.Truncated {
			if tcpFrame == nil {
				tcpFrame, err = packTCPFrame(req)
				if err != nil {
					return nil, err
				}
			}
			tcpResp, tcpErr := f.exchangeTCPOnce(qCtx, addr, req.Id, tcpFrame)
			if tcpErr == nil {
				return tcpResp, nil
			}
			lastErr = tcpErr
			if qCtxErr := qCtx.Err(); qCtxErr != nil {
				return nil, qCtxErr
			}
			continue
		}
		return resp, nil
	}

	if lastErr == nil {
		if err := qCtx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("dns: bypass query failed")
	}
	return nil, lastErr
}

func (f *bypassForwarder) exchangeUDP(ctx context.Context, addr string, reqID uint16, wire []byte) (*dns.Msg, error) {
	conn, err := f.dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	applyConnDeadline(ctx, conn)
	stopWatch := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer func() {
		_ = stopWatch()
	}()

	n, err := conn.Write(wire)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if n != len(wire) {
		return nil, io.ErrShortWrite
	}

	buf := make([]byte, maxDNSWireSize)
	rn, err := conn.Read(buf)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	if !stopWatch() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, context.Canceled
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:rn]); err != nil {
		return nil, fmt.Errorf("dns: unpack bypass UDP response: %w", err)
	}
	if resp.Id != reqID {
		return nil, fmt.Errorf("dns: bypass UDP response ID mismatch: got %d want %d", resp.Id, reqID)
	}
	return resp, nil
}

func (f *bypassForwarder) exchangeTCPOnce(ctx context.Context, addr string, reqID uint16, frame []byte) (*dns.Msg, error) {
	conn, err := f.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return exchangeTCPConn(ctx, conn, reqID, frame)
}

func (f *bypassForwarder) Close() error {
	return nil
}
