// Package tun integrates tun2socks v2 (gVisor netstack) over OS TUN devices
// for Milestone 2 full-TUN tunneling and local DNS interception.
package tun

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// DefaultIfaceName is the default TUN interface name used across Linux and Windows.
	DefaultIfaceName = "tunssh0"
	// DefaultMTU is the default TUN MTU chosen to avoid PPPoE/LTE fragmentation.
	DefaultMTU = 1380
	// DefaultIPv4CIDR is the default RFC 2544 TUN interface IPv4 address/prefix.
	DefaultIPv4CIDR = "198.18.0.1/15"
	// DefaultIPv6CIDR is the default ULA IPv6 address/prefix assigned for IPv6 leak prevention.
	DefaultIPv6CIDR = "fd98:18::1/64"
	// DefaultDNSPort is the standard DNS port intercepted on TUN TCP and UDP traffic.
	DefaultDNSPort uint16 = 53

	// WintunSHA256AMD64 is the pinned official Wintun 0.14.1 amd64 DLL SHA-256 digest.
	WintunSHA256AMD64 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
	// WintunSHA256ARM64 is the pinned official Wintun 0.14.1 arm64 DLL SHA-256 digest.
	WintunSHA256ARM64 = "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"

	capNetAdminBit      = 12
	defaultDialTimeout  = 5 * time.Second
	minTunnelMTU        = 68
	maxTunnelMTU        = 65535
	maxIfaceNamePreview = 64

	defaultTCPWndSize    = 0
	maxTCPConnAttempts   = 2 << 10
	tcpKeepaliveCount    = 9
	tcpKeepaliveIdle     = 60 * time.Second
	tcpKeepaliveInterval = 30 * time.Second
)

// ErrUDPDropped is returned by CustomProxy.DialUDP for non-DNS UDP packets so
// QUIC/UDP flows fast-fail and browsers cleanly fall back to TCP.
var ErrUDPDropped = errors.New("tun: non-DNS UDP packet dropped")

// ErrLocalTUNRejected is returned when non-DNS TCP traffic targets the local TUN subnet
// (for example, Android Private DNS DoT probes to 198.18.0.2:853).
var ErrLocalTUNRejected = errors.New("tun: non-DNS traffic to local TUN subnet rejected")

// ErrIPv6Blocked is returned when BlockIPv6Data is enabled and a non-DNS IPv6 TCP
// connection is attempted on an IPv4-only SSH tunnel.
var ErrIPv6Blocked = errors.New("tun: IPv6 data connection blocked for IPv4-only tunnel")

var (
	_ t2sproxy.Proxy  = (*CustomProxy)(nil)
	_ TunRunner       = (*Runner)(nil)
	_ adapter.TCPConn = (*tunTCPConn)(nil)
	_ adapter.UDPConn = (*tunUDPConn)(nil)
)

// Dialer establishes outbound TCP connections through the upstream SSH tunnel.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Config configures the TUN interface, upstream dialer, and local DNS redirect targets.
type Config struct {
	IfaceName     string
	MTU           int
	IPv4CIDR      string
	IPv6CIDR      string
	EnableIPv6    bool
	BlockIPv6Data bool
	TunnelDialer  Dialer
	DNSUDPAddr    string
	DNSTCPAddr    string
}

// Stats holds a thread-safe snapshot of TUN runner state and tunnel byte counters.
type Stats struct {
	Running    bool
	IfaceName  string
	IfaceIndex int
	RxBytes    uint64
	TxBytes    uint64
}

// TunRunner manages the lifecycle of the OS TUN device, gVisor stack, and tun2socks tunnel.
type TunRunner interface {
	Start(ctx context.Context, cfg Config) (int, error)
	Stop(ctx context.Context) error
	Stats() Stats
}

type deviceOpener func(name string, mtu int, ipv4CIDR, ipv6CIDR string, enableIPv6 bool) (device.Device, int, error)

// ExpectedWintunSHA256 returns the pinned official Wintun 0.14.1 SHA-256 hex digest for arch.
func ExpectedWintunSHA256(arch string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "amd64":
		return WintunSHA256AMD64, nil
	case "arm64":
		return WintunSHA256ARM64, nil
	default:
		return "", fmt.Errorf("tun: unsupported Windows architecture %q for wintun.dll", arch)
	}
}

// VerifyDLLSHA256 verifies that the file at path matches expectedSHA256 using constant-time comparison.
func VerifyDLLSHA256(path, expectedSHA256 string) error {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return errors.New("tun: DLL path must not be empty")
	}
	expectedBytes, err := hex.DecodeString(strings.TrimSpace(expectedSHA256))
	if err != nil || len(expectedBytes) != sha256.Size {
		return errors.New("tun: expected SHA-256 digest must be a valid 64-character hex string")
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return fmt.Errorf("tun: open %q for SHA-256 verification: %w", cleanPath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("tun: stat %q for SHA-256 verification: %w", cleanPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("tun: %q is a directory, expected DLL file", cleanPath)
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("tun: hash %q: %w", cleanPath, err)
	}
	actualBytes := h.Sum(nil)
	if subtle.ConstantTimeCompare(actualBytes, expectedBytes) != 1 {
		return fmt.Errorf("tun: SHA-256 mismatch for %q: got %x, want %x", cleanPath, actualBytes, expectedBytes)
	}
	return nil
}

// parseCapEffHasNetAdmin parses Linux /proc/self/status text and reports whether CapEff includes CAP_NET_ADMIN (bit 12).
func parseCapEffHasNetAdmin(statusText string) bool {
	for _, line := range strings.Split(statusText, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "CapEff:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "CapEff:"))
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return false
		}
		hexMask := strings.TrimPrefix(strings.TrimPrefix(fields[0], "0x"), "0X")
		capEff, err := strconv.ParseUint(hexMask, 16, 64)
		if err != nil {
			return false
		}
		return (capEff & (uint64(1) << capNetAdminBit)) != 0
	}
	return false
}

func normalizeDeviceConfig(name string, mtu int, ipv4CIDR, ipv6CIDR string, enableIPv6 bool) (string, int, netip.Prefix, netip.Prefix, error) {
	if name == "" {
		name = DefaultIfaceName
	}
	if err := validateIfaceName(name); err != nil {
		return "", 0, netip.Prefix{}, netip.Prefix{}, err
	}

	if mtu == 0 {
		mtu = DefaultMTU
	} else if mtu < minTunnelMTU || mtu > maxTunnelMTU {
		return "", 0, netip.Prefix{}, netip.Prefix{}, fmt.Errorf("tun: invalid MTU %d (must be between %d and %d)", mtu, minTunnelMTU, maxTunnelMTU)
	}

	if ipv4CIDR == "" {
		ipv4CIDR = DefaultIPv4CIDR
	}
	p4, err := netip.ParsePrefix(ipv4CIDR)
	if err != nil || !p4.IsValid() || !p4.Addr().Is4() {
		return "", 0, netip.Prefix{}, netip.Prefix{}, fmt.Errorf("tun: invalid IPv4 CIDR %q", ipv4CIDR)
	}

	var p6 netip.Prefix
	if enableIPv6 {
		if ipv6CIDR == "" {
			ipv6CIDR = DefaultIPv6CIDR
		}
		p6, err = netip.ParsePrefix(ipv6CIDR)
		if err != nil || !p6.IsValid() || !p6.Addr().Is6() {
			return "", 0, netip.Prefix{}, netip.Prefix{}, fmt.Errorf("tun: invalid IPv6 CIDR %q", ipv6CIDR)
		}
	} else if ipv6CIDR != "" {
		p6, err = netip.ParsePrefix(ipv6CIDR)
		if err != nil || !p6.IsValid() || !p6.Addr().Is6() {
			return "", 0, netip.Prefix{}, netip.Prefix{}, fmt.Errorf("tun: invalid IPv6 CIDR %q", ipv6CIDR)
		}
	}

	return name, mtu, p4, p6, nil
}

func validateIfaceName(name string) error {
	if name == "" || len(name) > maxIfaceNamePreview {
		return fmt.Errorf("tun: invalid interface name %q", name)
	}
	if strings.ContainsAny(name, "/\\\"\x00\r\n\t") || strings.Contains(name, "..") {
		return fmt.Errorf("tun: unsafe characters in interface name %q", name)
	}
	return nil
}

func normalizeRunnerConfig(cfg Config) (Config, error) {
	if cfg.TunnelDialer == nil {
		return Config{}, errors.New("tun: TunnelDialer must not be nil")
	}

	name, mtu, p4, p6, err := normalizeDeviceConfig(cfg.IfaceName, cfg.MTU, cfg.IPv4CIDR, cfg.IPv6CIDR, cfg.EnableIPv6)
	if err != nil {
		return Config{}, err
	}
	cfg.IfaceName = name
	cfg.MTU = mtu
	cfg.IPv4CIDR = p4.String()
	if p6.IsValid() {
		cfg.IPv6CIDR = p6.String()
	}

	if cfg.DNSUDPAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", cfg.DNSUDPAddr)
		if err != nil || addr == nil || addr.Port <= 0 {
			return Config{}, fmt.Errorf("tun: invalid DNSUDPAddr %q", cfg.DNSUDPAddr)
		}
	}
	if cfg.DNSTCPAddr != "" {
		host, port, err := net.SplitHostPort(cfg.DNSTCPAddr)
		if err != nil || host == "" || port == "" {
			return Config{}, fmt.Errorf("tun: invalid DNSTCPAddr %q", cfg.DNSTCPAddr)
		}
	}

	return cfg, nil
}

func parseTUNPrefixes(cfg Config) (netip.Prefix, netip.Prefix) {
	var v4, v6 netip.Prefix

	rawV4 := strings.TrimSpace(cfg.IPv4CIDR)
	if rawV4 == "" {
		rawV4 = DefaultIPv4CIDR
	}
	if p4, err := netip.ParsePrefix(rawV4); err == nil && p4.IsValid() && p4.Addr().Is4() {
		v4 = p4.Masked()
	}

	rawV6 := strings.TrimSpace(cfg.IPv6CIDR)
	if rawV6 == "" && cfg.EnableIPv6 {
		rawV6 = DefaultIPv6CIDR
	}
	if rawV6 != "" {
		if p6, err := netip.ParsePrefix(rawV6); err == nil && p6.IsValid() && p6.Addr().Is6() {
			v6 = p6.Masked()
		}
	}

	return v4, v6
}

func isLocalTUNAddr(dstIP netip.Addr, v4, v6 netip.Prefix) bool {
	if !dstIP.IsValid() {
		return false
	}
	ip := dstIP.Unmap()
	return (v4.IsValid() && v4.Contains(ip)) || (v6.IsValid() && v6.Contains(ip))
}

// CustomProxy implements tun2socks v2 proxy.Proxy by routing TCP traffic through TunnelDialer,
// redirecting TCP/UDP :53 to local embedded DNS listeners, and fast-rejecting non-DNS UDP,
// non-DNS local TUN subnet probes, and (optionally) IPv6 data connections.
type CustomProxy struct {
	tunnelDialer  Dialer
	dnsUDPAddr    string
	dnsTCPAddr    string
	tunIPv4Prefix netip.Prefix
	tunIPv6Prefix netip.Prefix
	blockIPv6Data bool

	baseCtx context.Context
	cancel  context.CancelFunc

	mu     sync.Mutex
	closed bool
	active map[io.Closer]struct{}

	rxBytes atomic.Uint64
	txBytes atomic.Uint64
}

// NewCustomProxy constructs a CustomProxy for the given Config.
func NewCustomProxy(cfg Config) *CustomProxy {
	baseCtx, cancel := context.WithCancel(context.Background())
	tunV4, tunV6 := parseTUNPrefixes(cfg)
	return &CustomProxy{
		tunnelDialer:  cfg.TunnelDialer,
		dnsUDPAddr:    cfg.DNSUDPAddr,
		dnsTCPAddr:    cfg.DNSTCPAddr,
		tunIPv4Prefix: tunV4,
		tunIPv6Prefix: tunV6,
		blockIPv6Data: cfg.BlockIPv6Data,
		baseCtx:       baseCtx,
		cancel:        cancel,
		active:        make(map[io.Closer]struct{}),
	}
}

// Close cancels in-flight proxy dials and closes all active TCP/UDP proxy connections
// so tun2socks worker goroutines unblock immediately during shutdown.
func (p *CustomProxy) Close() error {
	if p.cancel != nil {
		p.cancel()
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conns := make([]io.Closer, 0, len(p.active))
	for c := range p.active {
		conns = append(conns, c)
	}
	clear(p.active)
	p.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}

func (p *CustomProxy) isClosed() bool {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	return closed
}

func (p *CustomProxy) track(c io.Closer) bool {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return false
	}
	if p.active == nil {
		p.active = make(map[io.Closer]struct{})
	}
	p.active[c] = struct{}{}
	p.mu.Unlock()
	return true
}

func (p *CustomProxy) untrack(c io.Closer) {
	p.mu.Lock()
	if !p.closed {
		delete(p.active, c)
	}
	p.mu.Unlock()
}

// RxBytes returns total bytes read from outbound tunneled TCP connections.
func (p *CustomProxy) RxBytes() uint64 {
	return p.rxBytes.Load()
}

// TxBytes returns total bytes written to outbound tunneled TCP connections.
func (p *CustomProxy) TxBytes() uint64 {
	return p.txBytes.Load()
}

// DialContext routes TCP :53 directly to the local DNS TCP listener (when configured)
// and forwards all other TCP streams through TunnelDialer with atomic Rx/Tx accounting.
func (p *CustomProxy) DialContext(ctx context.Context, md *M.Metadata) (net.Conn, error) {
	if md == nil {
		return nil, errors.New("tun: nil metadata")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if p.isClosed() {
		return nil, net.ErrClosed
	}

	if md.DstPort != DefaultDNSPort && md.DstIP.IsValid() {
		dstIP := md.DstIP.Unmap()
		if isLocalTUNAddr(dstIP, p.tunIPv4Prefix, p.tunIPv6Prefix) {
			return nil, ErrLocalTUNRejected
		}
		if p.blockIPv6Data && dstIP.Is6() {
			return nil, ErrIPv6Blocked
		}
	}

	dialCtx, dialCancel := context.WithCancel(ctx)
	defer dialCancel()
	if p.baseCtx != nil {
		stopAfter := context.AfterFunc(p.baseCtx, dialCancel)
		defer stopAfter()
	}

	var (
		conn net.Conn
		err  error
		rx   *atomic.Uint64
		tx   *atomic.Uint64
	)
	if md.DstPort == DefaultDNSPort && p.dnsTCPAddr != "" {
		d := &net.Dialer{Timeout: defaultDialTimeout}
		conn, err = d.DialContext(dialCtx, "tcp", p.dnsTCPAddr)
	} else {
		if p.tunnelDialer == nil {
			return nil, errors.New("tun: tunnel dialer must not be nil")
		}
		conn, err = p.tunnelDialer.DialContext(dialCtx, "tcp", md.DestinationAddress())
		rx = &p.rxBytes
		tx = &p.txBytes
	}
	if err != nil {
		return nil, err
	}

	tc := &trackedProxyConn{
		Conn:    conn,
		owner:   p,
		rxBytes: rx,
		txBytes: tx,
	}
	if !p.track(tc) {
		_ = tc.Close()
		return nil, net.ErrClosed
	}
	return tc, nil
}

// DialUDP fast-rejects non-:53 UDP packets with ErrUDPDropped and redirects UDP :53
// packets to the local embedded DNS UDP listener while rewriting reply source addresses
// back to the originally queried destination so tun2socks symmetricNATPacketConn accepts them.
func (p *CustomProxy) DialUDP(md *M.Metadata) (net.PacketConn, error) {
	if md == nil || md.DstPort != DefaultDNSPort || p.dnsUDPAddr == "" {
		return nil, ErrUDPDropped
	}
	if p.isClosed() {
		return nil, net.ErrClosed
	}

	targetAddr, err := net.ResolveUDPAddr("udp", p.dnsUDPAddr)
	if err != nil {
		return nil, fmt.Errorf("tun: resolve DNSUDPAddr %q: %w", p.dnsUDPAddr, err)
	}

	network := "udp6"
	bindAddr := &net.UDPAddr{IP: net.IPv6loopback, Port: 0}
	if targetAddr.IP.To4() != nil {
		network = "udp4"
		bindAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	}

	pc, err := net.ListenUDP(network, bindAddr)
	if err != nil {
		return nil, fmt.Errorf("tun: bind local UDP socket for DNS redirect: %w", err)
	}

	origDst := resolveOriginalUDPDst(md)
	rpc := &dnsRedirectPacketConn{
		PacketConn:  pc,
		targetAddr:  targetAddr,
		origDstAddr: origDst,
		owner:       p,
	}
	if !p.track(rpc) {
		_ = rpc.Close()
		return nil, net.ErrClosed
	}
	return rpc, nil
}

func resolveOriginalUDPDst(md *M.Metadata) net.Addr {
	if udpAddr := md.UDPAddr(); udpAddr != nil {
		return udpAddr
	}
	if md.DstIP.IsValid() {
		return net.UDPAddrFromAddrPort(md.DestinationAddrPort())
	}
	return md.Addr()
}

type trackedProxyConn struct {
	net.Conn
	owner     *CustomProxy
	rxBytes   *atomic.Uint64
	txBytes   *atomic.Uint64
	closeOnce sync.Once
	closeErr  error
}

func (c *trackedProxyConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.rxBytes != nil {
		c.rxBytes.Add(uint64(n))
	}
	return n, err
}

func (c *trackedProxyConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && c.txBytes != nil {
		c.txBytes.Add(uint64(n))
	}
	return n, err
}

func (c *trackedProxyConn) Close() error {
	c.closeOnce.Do(func() {
		if c.owner != nil {
			c.owner.untrack(c)
		}
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *trackedProxyConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return errors.ErrUnsupported
}

func (c *trackedProxyConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

type dnsRedirectPacketConn struct {
	net.PacketConn
	targetAddr  *net.UDPAddr
	origDstAddr net.Addr
	owner       *CustomProxy
	closeOnce   sync.Once
	closeErr    error
}

func (r *dnsRedirectPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return r.PacketConn.WriteTo(p, r.targetAddr)
}

func (r *dnsRedirectPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := r.PacketConn.ReadFrom(p)
		if err != nil {
			return n, nil, err
		}
		// Ignore unrelated packets arriving on the ephemeral loopback socket so
		// only responses from the embedded DNS listener are returned to tun2socks.
		if udpFrom, ok := from.(*net.UDPAddr); ok {
			if !udpFrom.IP.Equal(r.targetAddr.IP) || udpFrom.Port != r.targetAddr.Port {
				continue
			}
		}
		return n, r.origDstAddr, nil
	}
}

func (r *dnsRedirectPacketConn) Close() error {
	r.closeOnce.Do(func() {
		if r.owner != nil {
			r.owner.untrack(r)
		}
		r.closeErr = r.PacketConn.Close()
	})
	return r.closeErr
}

type postWaitCloser interface {
	CloseBeforeWait()
	CloseAfterWait()
}

// onceCloseDevice guards device.Device.Close() with sync.Once because both Runner.Stop
// and gVisor stack.Wait (via removeNICLocked) invoke Close() during teardown; double-closing
// an OS TUN file descriptor would introduce an fd-reuse race. It also supports deferring
// LinkEndpoint.Attach until custom gVisor transport handlers are installed so inbound packet
// dispatch never races with SetTransportProtocolHandler.
type onceCloseDevice struct {
	device.Device
	closeOnce  sync.Once
	beforeOnce sync.Once
	afterOnce  sync.Once

	attachMu        sync.Mutex
	deferAttach     bool
	attachClosed    bool
	pendingDispatch stack.NetworkDispatcher
}

func (d *onceCloseDevice) Attach(dispatcher stack.NetworkDispatcher) {
	d.attachMu.Lock()
	if dispatcher == nil {
		d.attachClosed = true
		d.pendingDispatch = nil
		d.attachMu.Unlock()
		d.Device.Attach(nil)
		return
	}
	if d.attachClosed {
		d.attachMu.Unlock()
		return
	}
	if d.deferAttach {
		d.pendingDispatch = dispatcher
		d.attachMu.Unlock()
		return
	}
	d.attachMu.Unlock()
	d.Device.Attach(dispatcher)
}

func (d *onceCloseDevice) ActivateAttach() {
	d.attachMu.Lock()
	d.deferAttach = false
	disp := d.pendingDispatch
	d.pendingDispatch = nil
	closed := d.attachClosed
	d.attachMu.Unlock()
	if !closed && disp != nil {
		d.Device.Attach(disp)
	}
}

func (d *onceCloseDevice) markAttachClosed() {
	d.attachMu.Lock()
	d.attachClosed = true
	d.pendingDispatch = nil
	d.attachMu.Unlock()
}

func (d *onceCloseDevice) Close() {
	d.markAttachClosed()
	d.closeOnce.Do(func() {
		if pwc, ok := d.Device.(postWaitCloser); ok {
			pwc.CloseBeforeWait()
			pwc.CloseAfterWait()
			return
		}
		d.Device.Close()
	})
}

func (d *onceCloseDevice) CloseBeforeWait() {
	d.markAttachClosed()
	d.beforeOnce.Do(func() {
		if pwc, ok := d.Device.(postWaitCloser); ok {
			pwc.CloseBeforeWait()
			return
		}
		d.Close()
	})
}

func (d *onceCloseDevice) CloseAfterWait() {
	d.afterOnce.Do(func() {
		if pwc, ok := d.Device.(postWaitCloser); ok {
			pwc.CloseAfterWait()
			return
		}
		d.Close()
	})
}

type tunTCPConn struct {
	*gonet.TCPConn
	id stack.TransportEndpointID
}

func (c *tunTCPConn) ID() stack.TransportEndpointID {
	return c.id
}

type tunUDPConn struct {
	*gonet.UDPConn
	id stack.TransportEndpointID
}

func (c *tunUDPConn) ID() stack.TransportEndpointID {
	return c.id
}

func setTCPSocketOptions(s *stack.Stack, ep tcpip.Endpoint) tcpip.Error {
	ep.SocketOptions().SetKeepAlive(true)

	idle := tcpip.KeepaliveIdleOption(tcpKeepaliveIdle)
	if err := ep.SetSockOpt(&idle); err != nil {
		return err
	}

	interval := tcpip.KeepaliveIntervalOption(tcpKeepaliveInterval)
	if err := ep.SetSockOpt(&interval); err != nil {
		return err
	}

	if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, tcpKeepaliveCount); err != nil {
		return err
	}

	var ss tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &ss); err == nil {
		ep.SocketOptions().SetSendBufferSize(int64(ss.Default), false)
	}

	var rs tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &rs); err == nil {
		ep.SocketOptions().SetReceiveBufferSize(int64(rs.Default), false)
	}
	return nil
}

// installFastRejectHandlers installs custom gVisor TCP and UDP transport forwarders that:
//   - immediately TCP-RST non-DNS traffic targeting the local TUN IPv4/IPv6 subnet (e.g., Android Private DNS :853),
//   - immediately TCP-RST non-DNS IPv6 traffic when cfg.BlockIPv6Data is enabled (fast Happy Eyeballs fallback), and
//   - immediately reject non-DNS UDP packets (e.g., QUIC :443) before creating a gVisor UDP endpoint.
func installFastRejectHandlers(st *stack.Stack, handler adapter.TransportHandler, cfg Config) {
	tunIPv4Prefix, tunIPv6Prefix := parseTUNPrefixes(cfg)

	tcpFwd := tcp.NewForwarder(st, defaultTCPWndSize, maxTCPConnAttempts, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		if id.LocalPort != DefaultDNSPort {
			if dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice()); ok && dstIP.IsValid() {
				ip := dstIP.Unmap()
				if isLocalTUNAddr(ip, tunIPv4Prefix, tunIPv6Prefix) || (cfg.BlockIPv6Data && ip.Is6()) {
					r.Complete(true)
					return
				}
			}
		}

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		defer r.Complete(false)

		_ = setTCPSocketOptions(st, ep)

		handler.HandleTCP(&tunTCPConn{
			TCPConn: gonet.NewTCPConn(&wq, ep),
			id:      id,
		})
	})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(st, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		if id.LocalPort != DefaultDNSPort {
			return false
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		handler.HandleUDP(&tunUDPConn{
			UDPConn: gonet.NewUDPConn(&wq, ep),
			id:      id,
		})
		return true
	})
	st.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if id.LocalPort != DefaultDNSPort {
			return false
		}
		return udpFwd.HandlePacket(id, pkt)
	})
}

// Runner owns the active TUN device, tun2socks Tunnel, and gVisor netstack lifecycle.
type Runner struct {
	openDevice    deviceOpener
	cleanupUnused func()

	mu         sync.Mutex
	starting   bool
	running    bool
	stopping   bool
	stopDone   chan struct{}
	ifaceName  string
	ifaceIndex int
	proxy      *CustomProxy
	tun        *tunnel.Tunnel
	dev        device.Device
	stack      *stack.Stack
}

// NewRunner returns a TunRunner backed by the OS-native TUN opener.
func NewRunner() *Runner {
	return newRunnerWithOpener(OpenAndConfigureDevice)
}

func newRunnerWithOpener(opener deviceOpener) *Runner {
	return &Runner{openDevice: opener}
}

func (r *Runner) consumeCleanupUnused() {
	r.mu.Lock()
	if r.starting || r.running || r.stopping {
		r.mu.Unlock()
		return
	}
	cleanup := r.cleanupUnused
	r.cleanupUnused = nil
	r.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
}

// Start validates cfg, opens and configures the OS TUN device, starts the tun2socks tunnel,
// attaches the gVisor stack, and returns the resulting OS interface index.
func (r *Runner) Start(ctx context.Context, cfg Config) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		r.consumeCleanupUnused()
		return 0, err
	}

	normCfg, err := normalizeRunnerConfig(cfg)
	if err != nil {
		r.consumeCleanupUnused()
		return 0, err
	}

	r.mu.Lock()
	if r.starting || r.running || r.stopping {
		r.mu.Unlock()
		return 0, errors.New("tun: runner is already active or stopping")
	}
	if r.openDevice == nil {
		cleanup := r.cleanupUnused
		r.cleanupUnused = nil
		r.mu.Unlock()
		if cleanup != nil {
			cleanup()
		}
		return 0, errors.New("tun: device opener must not be nil")
	}
	r.starting = true
	opener := r.openDevice
	cleanup := r.cleanupUnused
	r.cleanupUnused = nil
	r.mu.Unlock()

	var (
		wrappedDev  device.Device
		customProxy *CustomProxy
		tunInst     *tunnel.Tunnel
		st          *stack.Stack
		committed   bool
	)
	defer func() {
		if committed {
			return
		}
		var pwc postWaitCloser
		if wrappedDev != nil {
			if p, ok := wrappedDev.(postWaitCloser); ok && st != nil {
				pwc = p
				pwc.CloseBeforeWait()
			} else {
				wrappedDev.Close()
			}
		} else if cleanup != nil {
			cleanup()
		}
		if st != nil {
			st.Close()
		}
		if customProxy != nil {
			_ = customProxy.Close()
		}
		if st != nil {
			st.Wait()
		}
		if pwc != nil {
			pwc.CloseAfterWait()
		}
		if tunInst != nil {
			tunInst.Close()
		}
		r.mu.Lock()
		r.starting = false
		r.mu.Unlock()
	}()

	rawDev, ifIndex, err := opener(normCfg.IfaceName, normCfg.MTU, normCfg.IPv4CIDR, normCfg.IPv6CIDR, normCfg.EnableIPv6)
	if err != nil {
		return 0, err
	}
	ocd := &onceCloseDevice{Device: rawDev, deferAttach: true}
	wrappedDev = ocd

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	customProxy = NewCustomProxy(normCfg)
	tunInst = tunnel.New(customProxy, statistic.DefaultManager)
	tunInst.ProcessAsync()

	st, err = core.CreateStack(&core.Config{
		LinkEndpoint:     wrappedDev,
		TransportHandler: tunInst,
	})
	if err != nil {
		return 0, fmt.Errorf("tun: create gVisor stack: %w", err)
	}
	installFastRejectHandlers(st, tunInst, normCfg)

	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ocd.ActivateAttach()

	ifaceName := rawDev.Name()
	if ifaceName == "" {
		ifaceName = normCfg.IfaceName
	}

	r.mu.Lock()
	r.starting = false
	r.running = true
	r.ifaceName = ifaceName
	r.ifaceIndex = ifIndex
	r.proxy = customProxy
	r.tun = tunInst
	r.dev = wrappedDev
	r.stack = st
	committed = true
	r.mu.Unlock()

	return ifIndex, nil
}

// Stop closes the TUN device, closes and waits on the gVisor stack (bounded by ctx),
// and closes the tun2socks Tunnel cleanly. Repeated calls to Stop are idempotent.
func (r *Runner) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	r.mu.Lock()
	if r.stopping {
		stopDone := r.stopDone
		r.mu.Unlock()
		if stopDone != nil {
			select {
			case <-stopDone:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	if !r.running {
		if r.starting {
			r.mu.Unlock()
			return errors.New("tun: cannot stop while start is in progress")
		}
		r.mu.Unlock()
		r.consumeCleanupUnused()
		return nil
	}

	r.running = false
	r.stopping = true
	stopDone := make(chan struct{})
	r.stopDone = stopDone
	dev := r.dev
	st := r.stack
	tunInst := r.tun
	customProxy := r.proxy
	r.dev = nil
	r.stack = nil
	r.tun = nil
	r.proxy = nil
	r.ifaceName = ""
	r.ifaceIndex = 0
	r.mu.Unlock()

	// Close the link device, stack, and active proxy sockets before stopping
	// tunnel.ProcessAsync() so active sessions unblock and queued handlers drain cleanly.
	// For postWaitCloser devices (e.g., fdDevice), defer closing the underlying FD strictly
	// until after st.Wait() finishes so st.Close() and stack teardown never touch a closed FD.
	var pwc postWaitCloser
	if dev != nil {
		if p, ok := dev.(postWaitCloser); ok && st != nil {
			pwc = p
			pwc.CloseBeforeWait()
		} else {
			dev.Close()
		}
	}
	if st != nil {
		st.Close()
	}
	if customProxy != nil {
		_ = customProxy.Close()
	}

	waitDone := make(chan struct{})
	go func() {
		if st != nil {
			st.Wait()
		}
		if pwc != nil {
			pwc.CloseAfterWait()
		}
		close(waitDone)
	}()

	var stopErr error
	select {
	case <-waitDone:
	case <-ctx.Done():
		stopErr = ctx.Err()
	}

	if tunInst != nil {
		tunInst.Close()
	}

	r.mu.Lock()
	r.stopping = false
	r.stopDone = nil
	close(stopDone)
	r.mu.Unlock()

	return stopErr
}

// Stats returns a thread-safe snapshot of TUN runner status and traffic byte counters.
func (r *Runner) Stats() Stats {
	r.mu.Lock()
	running := r.running
	ifaceName := r.ifaceName
	ifaceIndex := r.ifaceIndex
	p := r.proxy
	r.mu.Unlock()

	var rx, tx uint64
	if p != nil {
		rx = p.RxBytes()
		tx = p.TxBytes()
	}

	return Stats{
		Running:    running,
		IfaceName:  ifaceName,
		IfaceIndex: ifaceIndex,
		RxBytes:    rx,
		TxBytes:    tx,
	}
}
