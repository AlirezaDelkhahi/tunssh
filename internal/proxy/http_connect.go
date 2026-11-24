package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Keep-Alive",
	"TE",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func newBufferedConn(conn net.Conn, br *bufio.Reader) net.Conn {
	if br != nil && br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, br: br}
	}
	return conn
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.br != nil {
		n, err := c.br.Read(p)
		if c.br.Buffered() == 0 {
			c.br = nil
		}
		return n, err
	}
	return c.Conn.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (s *Server) handleHTTP(ctx context.Context, tc *trackedConn) {
	conn := tc.local
	br := bufio.NewReader(conn)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			var netErr net.Error
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && (!errors.As(err, &netErr) || !netErr.Timeout()) {
				_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
				_ = writeHTTPError(conn, http.StatusBadRequest, "Bad Request")
			}
			return
		}

		if req.Method == http.MethodConnect {
			s.handleHTTPConnect(ctx, tc, conn, br, req)
			return
		}

		_ = conn.SetReadDeadline(time.Time{})
		if !s.handleHTTPForward(ctx, conn, req) {
			return
		}
	}
}

func (s *Server) handleHTTPConnect(ctx context.Context, tc *trackedConn, conn net.Conn, br *bufio.Reader, req *http.Request) {
	_ = req.Body.Close()

	target := req.Host
	if target == "" && req.URL != nil {
		target = req.URL.Host
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		_ = writeHTTPError(conn, http.StatusBadRequest, "Bad Request")
		return
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
	remote, err := s.dialer.DialContext(dialCtx, "tcp", target)
	dialCancel()
	if err != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		_ = writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway")
		return
	}

	if !tc.setRemote(remote) {
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	if err := writeAll(conn, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Clear handshake deadline before entering long-lived bidirectional tunnel relay.
	_ = conn.SetDeadline(time.Time{})
	clientConn := newBufferedConn(conn, br)
	_ = s.relay(clientConn, remote)
}

func (s *Server) handleHTTPForward(ctx context.Context, conn net.Conn, req *http.Request) bool {
	defer req.Body.Close()

	closeAfter := req.Close || strings.EqualFold(req.Header.Get("Proxy-Connection"), "close")

	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()

	outReq := req.Clone(reqCtx)
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = req.Host
	}
	if outReq.URL.Host == "" {
		_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		_ = writeHTTPError(conn, http.StatusBadRequest, "Bad Request")
		return false
	}

	stripHopByHopHeaders(outReq.Header)

	resp, err := s.httpTransport.RoundTrip(outReq)
	if err != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		_ = writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway")
		return false
	}
	defer resp.Body.Close()

	stripHopByHopHeaders(resp.Header)
	if closeAfter {
		resp.Close = true
	}

	_ = conn.SetDeadline(time.Time{})
	if err := resp.Write(conn); err != nil {
		return false
	}

	if closeAfter || resp.Close || req.ProtoMajor < 1 || (req.ProtoMajor == 1 && req.ProtoMinor == 0) {
		return false
	}
	return true
}

func stripHopByHopHeaders(h http.Header) {
	if h == nil {
		return
	}
	for _, connVal := range h.Values("Connection") {
		for field := range strings.SplitSeq(connVal, ",") {
			if trimmed := strings.TrimSpace(field); trimmed != "" {
				h.Del(trimmed)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func writeHTTPError(w io.Writer, statusCode int, text string) error {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", statusCode, text)
	return writeAll(w, []byte(resp))
}
