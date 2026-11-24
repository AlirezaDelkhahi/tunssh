package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	socks5Version = 0x05

	socks5AuthNone         = 0x00
	socks5AuthNoAcceptable = 0xFF

	socks5CmdConnect = 0x01

	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04

	socks5RepSuccess          = 0x00
	socks5RepGeneralFailure   = 0x01
	socks5RepHostUnreachable  = 0x04
	socks5RepConnRefused      = 0x05
	socks5RepCmdNotSupported  = 0x07
	socks5RepAddrNotSupported = 0x08
)

func (s *Server) handleSOCKS5(ctx context.Context, tc *trackedConn) {
	conn := tc.local
	_ = conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))

	if !negotiateSOCKS5Method(conn) {
		return
	}

	target, ok := readSOCKS5Target(conn)
	if !ok {
		return
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
	remote, err := s.dialer.DialContext(dialCtx, "tcp", target)
	dialCancel()
	if err != nil {
		_ = writeSOCKS5Reply(conn, mapSOCKS5DialError(err), nil)
		return
	}

	if !tc.setRemote(remote) {
		return
	}

	if err := writeSOCKS5Reply(conn, socks5RepSuccess, remote.LocalAddr()); err != nil {
		return
	}

	// Clear handshake deadline before entering long-lived bidirectional tunnel relay.
	_ = conn.SetDeadline(time.Time{})
	_ = s.relay(conn, remote)
}

func negotiateSOCKS5Method(conn net.Conn) bool {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return false
	}
	if hdr[0] != socks5Version {
		return false
	}
	nMethods := int(hdr[1])
	if nMethods == 0 {
		_ = writeAll(conn, []byte{socks5Version, socks5AuthNoAcceptable})
		return false
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return false
	}
	if !bytes.Contains(methods, []byte{socks5AuthNone}) {
		_ = writeAll(conn, []byte{socks5Version, socks5AuthNoAcceptable})
		return false
	}
	return writeAll(conn, []byte{socks5Version, socks5AuthNone}) == nil
}

func readSOCKS5Target(conn net.Conn) (string, bool) {
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return "", false
	}
	if req[0] != socks5Version || req[2] != 0x00 {
		_ = writeSOCKS5Reply(conn, socks5RepGeneralFailure, nil)
		return "", false
	}
	if req[1] != socks5CmdConnect {
		_ = writeSOCKS5Reply(conn, socks5RepCmdNotSupported, nil)
		return "", false
	}

	var host string
	var port uint16

	switch req[3] {
	case socks5AddrIPv4:
		var buf [6]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return "", false
		}
		host = net.IP(buf[:4]).String()
		port = binary.BigEndian.Uint16(buf[4:6])

	case socks5AddrDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", false
		}
		domainLen := int(lenBuf[0])
		if domainLen == 0 {
			_ = writeSOCKS5Reply(conn, socks5RepGeneralFailure, nil)
			return "", false
		}
		buf := make([]byte, domainLen+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", false
		}
		host = string(buf[:domainLen])
		if strings.ContainsRune(host, 0) {
			_ = writeSOCKS5Reply(conn, socks5RepGeneralFailure, nil)
			return "", false
		}
		port = binary.BigEndian.Uint16(buf[domainLen : domainLen+2])

	case socks5AddrIPv6:
		var buf [18]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return "", false
		}
		host = net.IP(buf[:16]).String()
		port = binary.BigEndian.Uint16(buf[16:18])

	default:
		_ = writeSOCKS5Reply(conn, socks5RepAddrNotSupported, nil)
		return "", false
	}

	if port == 0 {
		_ = writeSOCKS5Reply(conn, socks5RepGeneralFailure, nil)
		return "", false
	}

	// Pass host:port verbatim so SSH performs remote DNS resolution (socks5h).
	return net.JoinHostPort(host, strconv.Itoa(int(port))), true
}

func writeSOCKS5Reply(w io.Writer, rep byte, bindAddr net.Addr) error {
	if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok && tcpAddr != nil && tcpAddr.IP != nil {
		if ip4 := tcpAddr.IP.To4(); ip4 != nil {
			reply := [10]byte{socks5Version, rep, 0x00, socks5AddrIPv4}
			copy(reply[4:8], ip4)
			binary.BigEndian.PutUint16(reply[8:10], uint16(tcpAddr.Port))
			return writeAll(w, reply[:])
		}
		if ip16 := tcpAddr.IP.To16(); ip16 != nil {
			reply := [22]byte{socks5Version, rep, 0x00, socks5AddrIPv6}
			copy(reply[4:20], ip16)
			binary.BigEndian.PutUint16(reply[20:22], uint16(tcpAddr.Port))
			return writeAll(w, reply[:])
		}
	}

	reply := [10]byte{socks5Version, rep, 0x00, socks5AddrIPv4}
	return writeAll(w, reply[:])
}

func mapSOCKS5DialError(err error) byte {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return socks5RepConnRefused
	}
	var dnsErr *net.DNSError
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTDOWN) || errors.As(err, &dnsErr) {
		return socks5RepHostUnreachable
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"):
		return socks5RepConnRefused
	case strings.Contains(msg, "host unreachable"), strings.Contains(msg, "no route to host"), strings.Contains(msg, "network is unreachable"):
		return socks5RepHostUnreachable
	default:
		return socks5RepGeneralFailure
	}
}
