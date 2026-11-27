package tun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type recordedDial struct {
	network string
	address string
}

type mockDialer struct {
	mu    sync.Mutex
	calls []recordedDial
	fn    func(ctx context.Context, network, address string) (net.Conn, error)
}

func (m *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	m.mu.Lock()
	m.calls = append(m.calls, recordedDial{network: network, address: address})
	m.mu.Unlock()
	if m.fn != nil {
		return m.fn(ctx, network, address)
	}
	return nil, errors.New("mockDialer: no dial function configured")
}

func (m *mockDialer) Calls() []recordedDial {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]recordedDial, len(m.calls))
	copy(out, m.calls)
	return out
}

type mockChannelDevice struct {
	*channel.Endpoint
	name      string
	closeOnce sync.Once
	closed    atomic.Bool
}

func newMockChannelDevice(name string, mtu uint32) *mockChannelDevice {
	return &mockChannelDevice{
		Endpoint: channel.New(256, mtu, ""),
		name:     name,
	}
}

func (d *mockChannelDevice) Name() string {
	return d.name
}

func (d *mockChannelDevice) Type() string {
	return "mock-tun"
}

func (d *mockChannelDevice) Close() {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		d.Endpoint.Close()
	})
}

func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close()
		wg.Wait()
	}
}

func startUDPDNSResponder(t *testing.T, replyPayload []byte) (string, <-chan []byte, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	receivedCh := make(chan []byte, 4)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pktCopy := append([]byte(nil), buf[:n]...)
			select {
			case receivedCh <- pktCopy:
			default:
			}
			_, _ = pc.WriteTo(replyPayload, addr)
		}
	}()

	return pc.LocalAddr().String(), receivedCh, func() {
		_ = pc.Close()
		wg.Wait()
	}
}

func TestCustomProxy_DialContext_RoutesTCP53ToLocalDNS(t *testing.T) {
	dnsAddr, stopDNS := startTCPEchoServer(t)
	defer stopDNS()

	dialer := &mockDialer{}
	p := NewCustomProxy(Config{
		TunnelDialer: dialer,
		DNSTCPAddr:   dnsAddr,
	})

	md := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("198.18.0.1"),
		SrcPort: 50001,
		DstIP:   netip.MustParseAddr("198.18.0.2"),
		DstPort: 53,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := p.DialContext(ctx, md)
	if err != nil {
		t.Fatalf("DialContext TCP:53 failed: %v", err)
	}
	defer conn.Close()

	want := []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write dns tcp conn: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read dns tcp conn: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("dns tcp echo = %x, want %x", got, want)
	}

	if calls := dialer.Calls(); len(calls) != 0 {
		t.Fatalf("expected 0 TunnelDialer calls for TCP:53, got %v", calls)
	}
	if p.RxBytes() != 0 || p.TxBytes() != 0 {
		t.Fatalf("expected 0 tunnel byte counters for local TCP:53, got rx=%d tx=%d", p.RxBytes(), p.TxBytes())
	}
}

func TestCustomProxy_DialContext_RoutesOtherPortsThroughTunnelDialerAndCountsBytes(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoServer(t)
	defer stopEcho()

	dialer := &mockDialer{
		fn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, echoAddr)
		},
	}
	p := NewCustomProxy(Config{
		TunnelDialer: dialer,
		DNSTCPAddr:   "127.0.0.1:1",
	})

	md := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("198.18.0.1"),
		SrcPort: 50002,
		DstIP:   netip.MustParseAddr("93.184.216.34"),
		DstPort: 443,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := p.DialContext(ctx, md)
	if err != nil {
		t.Fatalf("DialContext TCP:443 failed: %v", err)
	}
	defer conn.Close()

	calls := dialer.Calls()
	if len(calls) != 1 || calls[0].network != "tcp" || calls[0].address != "93.184.216.34:443" {
		t.Fatalf("unexpected TunnelDialer calls: %+v", calls)
	}

	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatalf("reply = %q, want %q", reply, payload)
	}

	wantCount := uint64(len(payload))
	if gotTx := p.TxBytes(); gotTx != wantCount {
		t.Fatalf("TxBytes() = %d, want %d", gotTx, wantCount)
	}
	if gotRx := p.RxBytes(); gotRx != wantCount {
		t.Fatalf("RxBytes() = %d, want %d", gotRx, wantCount)
	}

	// Empty DNSTCPAddr should fall back to TunnelDialer even on port 53.
	pNoDNS := NewCustomProxy(Config{TunnelDialer: dialer})
	dnsMD := &M.Metadata{
		Network: M.TCP,
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 53,
	}
	c2, err := pNoDNS.DialContext(ctx, dnsMD)
	if err != nil {
		t.Fatalf("DialContext TCP:53 fallback failed: %v", err)
	}
	_ = c2.Close()
	calls = dialer.Calls()
	if len(calls) != 2 || calls[1].address != "1.1.1.1:53" {
		t.Fatalf("expected fallback dial to 1.1.1.1:53, got %+v", calls)
	}
}

func TestCustomProxy_DialUDP_FastRejectsNonDNS(t *testing.T) {
	p := NewCustomProxy(Config{
		TunnelDialer: &mockDialer{},
		DNSUDPAddr:   "127.0.0.1:5353",
	})

	for _, port := range []uint16{443, 5353, 123, 0} {
		md := &M.Metadata{
			Network: M.UDP,
			SrcIP:   netip.MustParseAddr("198.18.0.1"),
			SrcPort: 40000,
			DstIP:   netip.MustParseAddr("1.1.1.1"),
			DstPort: port,
		}
		pc, err := p.DialUDP(md)
		if !errors.Is(err, ErrUDPDropped) {
			if pc != nil {
				_ = pc.Close()
			}
			t.Fatalf("port %d: err = %v, want ErrUDPDropped", port, err)
		}
	}

	// Port 53 with empty DNSUDPAddr must also fast-reject.
	pNoDNS := NewCustomProxy(Config{TunnelDialer: &mockDialer{}})
	pc, err := pNoDNS.DialUDP(&M.Metadata{
		Network: M.UDP,
		DstIP:   netip.MustParseAddr("198.18.0.2"),
		DstPort: 53,
	})
	if !errors.Is(err, ErrUDPDropped) {
		if pc != nil {
			_ = pc.Close()
		}
		t.Fatalf("empty DNSUDPAddr port 53: err = %v, want ErrUDPDropped", err)
	}
}

func TestCustomProxy_DialUDP_RedirectsDNS53AndRewritesSourceAddr(t *testing.T) {
	wantReply := []byte("dns-udp-response-payload")
	dnsAddr, receivedCh, stopDNS := startUDPDNSResponder(t, wantReply)
	defer stopDNS()

	p := NewCustomProxy(Config{
		TunnelDialer: &mockDialer{},
		DNSUDPAddr:   dnsAddr,
	})

	for _, dstIP := range []string{"198.18.0.2", "8.8.8.8"} {
		md := &M.Metadata{
			Network: M.UDP,
			SrcIP:   netip.MustParseAddr("198.18.0.1"),
			SrcPort: 51234,
			DstIP:   netip.MustParseAddr(dstIP),
			DstPort: 53,
		}

		pc, err := p.DialUDP(md)
		if err != nil {
			t.Fatalf("DialUDP(%s:53) failed: %v", dstIP, err)
		}

		query := []byte("dns-query-" + dstIP)
		n, err := pc.WriteTo(query, md.UDPAddr())
		if err != nil || n != len(query) {
			_ = pc.Close()
			t.Fatalf("WriteTo failed: n=%d err=%v", n, err)
		}

		select {
		case gotQuery := <-receivedCh:
			if !bytes.Equal(gotQuery, query) {
				_ = pc.Close()
				t.Fatalf("local DNS server got %q, want %q", gotQuery, query)
			}
		case <-time.After(2 * time.Second):
			_ = pc.Close()
			t.Fatalf("timed out waiting for local UDP DNS packet for %s", dstIP)
		}

		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		rn, from, err := pc.ReadFrom(buf)
		_ = pc.Close()
		if err != nil {
			t.Fatalf("ReadFrom failed: %v", err)
		}
		if !bytes.Equal(buf[:rn], wantReply) {
			t.Fatalf("ReadFrom payload = %q, want %q", buf[:rn], wantReply)
		}
		if from == nil || from.String() != md.DestinationAddress() {
			t.Fatalf("ReadFrom addr = %v, want %s (symmetricNATPacketConn compatibility)", from, md.DestinationAddress())
		}
	}
}

func TestVerifyDLLSHA256(t *testing.T) {
	dir := t.TempDir()
	dllPath := filepath.Join(dir, "wintun.dll")
	content := []byte("simulated wintun binary payload v0.14.1")
	if err := os.WriteFile(dllPath, content, 0o600); err != nil {
		t.Fatalf("write temp dll: %v", err)
	}

	sum := sha256.Sum256(content)
	hexLower := hex.EncodeToString(sum[:])
	hexUpper := strings.ToUpper(hexLower)

	if err := VerifyDLLSHA256(dllPath, hexLower); err != nil {
		t.Fatalf("VerifyDLLSHA256 lowercase failed: %v", err)
	}
	if err := VerifyDLLSHA256(dllPath, hexUpper); err != nil {
		t.Fatalf("VerifyDLLSHA256 uppercase failed: %v", err)
	}

	// Single-byte tamper must be rejected.
	tampered := append([]byte(nil), content...)
	tampered[len(tampered)/2] ^= 0x01
	if err := os.WriteFile(dllPath, tampered, 0o600); err != nil {
		t.Fatalf("overwrite tampered dll: %v", err)
	}
	if err := VerifyDLLSHA256(dllPath, hexLower); err == nil {
		t.Fatal("expected VerifyDLLSHA256 to reject single-byte-modified file")
	}

	// Missing file must be rejected.
	if err := VerifyDLLSHA256(filepath.Join(dir, "missing.dll"), hexLower); err == nil {
		t.Fatal("expected VerifyDLLSHA256 to reject missing file")
	}

	// Invalid digest formats must be rejected.
	for _, bad := range []string{"", "deadbeef", strings.Repeat("z", 64)} {
		if err := VerifyDLLSHA256(dllPath, bad); err == nil {
			t.Fatalf("expected VerifyDLLSHA256 to reject bad digest %q", bad)
		}
	}

	// Pinned Wintun 0.14.1 digest lookup checks.
	amd64Sum, err := ExpectedWintunSHA256("amd64")
	if err != nil || amd64Sum != WintunSHA256AMD64 {
		t.Fatalf("ExpectedWintunSHA256(amd64) = (%q, %v), want %q", amd64Sum, err, WintunSHA256AMD64)
	}
	arm64Sum, err := ExpectedWintunSHA256("arm64")
	if err != nil || arm64Sum != WintunSHA256ARM64 {
		t.Fatalf("ExpectedWintunSHA256(arm64) = (%q, %v), want %q", arm64Sum, err, WintunSHA256ARM64)
	}
	if _, err := ExpectedWintunSHA256("386"); err == nil {
		t.Fatal("expected unsupported arch error for 386")
	}
}

func TestParseCapEffHasNetAdmin(t *testing.T) {
	if !parseCapEffHasNetAdmin("Name:\ttunssh\nCapInh:\t0000000000000000\nCapPrm:\t0000000000001000\nCapEff:\t0000000000001000\n") {
		t.Fatal("expected CapEff=0000000000001000 to report CAP_NET_ADMIN=true")
	}
	if parseCapEffHasNetAdmin("Name:\ttunssh\nCapEff:\t0000000000000000\n") {
		t.Fatal("expected CapEff=0000000000000000 to report CAP_NET_ADMIN=false")
	}
	if !parseCapEffHasNetAdmin("CapEff: 000001FFFFFFFFFF\n") {
		t.Fatal("expected full capability mask to include CAP_NET_ADMIN")
	}
	if parseCapEffHasNetAdmin("CapEff:\t0000000000002000\n") {
		t.Fatal("expected bit 13 only (CAP_NET_RAW) to report CAP_NET_ADMIN=false")
	}
	if parseCapEffHasNetAdmin("Name:\ttunssh\n") {
		t.Fatal("expected missing CapEff line to report false")
	}
	if parseCapEffHasNetAdmin("CapEff:\tnot-hex\n") {
		t.Fatal("expected malformed CapEff hex to report false")
	}

	if runtime.GOOS == "linux" {
		// Unprivileged test run must not panic and should return a boolean matching current process privileges.
		_ = HasEffectiveCAPNetAdmin()
	}
}

func buildIPv4UDPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := header.UDPMinimumSize + len(payload)
	totalLen := header.IPv4MinimumSize + udpLen
	pkt := make([]byte, totalLen)

	ipHdr := header.IPv4(pkt[:header.IPv4MinimumSize])
	srcAddr := tcpip.AddrFrom4(srcIP.As4())
	dstAddr := tcpip.AddrFrom4(dstIP.As4())
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	udpHdr := header.UDP(pkt[header.IPv4MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	copy(pkt[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	xsum := checksum.Checksum(payload, header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcAddr, dstAddr, uint16(udpLen)))
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))
	return pkt
}

func TestRunner_StartStopLifecycleAndNoGoroutineLeak(t *testing.T) {
	wantDNSReply := []byte("ok-dns-reply")
	dnsUDPAddr, dnsReceivedCh, stopDNS := startUDPDNSResponder(t, wantDNSReply)
	defer stopDNS()

	mockDev := newMockChannelDevice("tunssh-test0", 1380)

	// Allow runtime goroutines from test setup to settle before capturing baseline.
	runtime.GC()
	time.Sleep(30 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	runner := newRunnerWithOpener(func(name string, mtu int, ipv4CIDR, ipv6CIDR string, enableIPv6 bool) (device.Device, int, error) {
		return mockDev, 42, nil
	})

	if st := runner.Stats(); st.Running {
		t.Fatalf("expected initial Stats().Running=false, got %+v", st)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ifIdx, err := runner.Start(ctx, Config{
		IfaceName:    "tunssh-test0",
		MTU:          1380,
		IPv4CIDR:     DefaultIPv4CIDR,
		IPv6CIDR:     DefaultIPv6CIDR,
		EnableIPv6:   true,
		TunnelDialer: &mockDialer{},
		DNSUDPAddr:   dnsUDPAddr,
	})
	if err != nil {
		t.Fatalf("Runner.Start failed: %v", err)
	}
	if ifIdx != 42 {
		t.Fatalf("Runner.Start ifIndex = %d, want 42", ifIdx)
	}

	st := runner.Stats()
	if !st.Running || st.IfaceName != "tunssh-test0" || st.IfaceIndex != 42 {
		t.Fatalf("unexpected running stats: %+v", st)
	}

	// Duplicate Start must fail cleanly without disrupting running tunnel.
	if _, err := runner.Start(ctx, Config{TunnelDialer: &mockDialer{}}); err == nil {
		t.Fatal("expected duplicate Runner.Start to return an error")
	}

	// End-to-end check through gVisor stack -> tunnel.Tunnel -> symmetricNATPacketConn -> CustomProxy.DialUDP!
	rawQuery := buildIPv4UDPPacket(
		netip.MustParseAddr("198.18.0.1"),
		netip.MustParseAddr("198.18.0.2"),
		45678,
		53,
		[]byte("dns-wire-query"),
	)
	pktBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(rawQuery),
	})
	mockDev.InjectInbound(header.IPv4ProtocolNumber, pktBuf)
	pktBuf.DecRef()

	select {
	case got := <-dnsReceivedCh:
		if string(got) != "dns-wire-query" {
			t.Fatalf("DNS listener received %q, want %q", got, "dns-wire-query")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for DNS query through gVisor + tunnel stack")
	}

	readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel()
	outPkt := mockDev.ReadContext(readCtx)
	if outPkt == nil {
		t.Fatal("expected DNS reply packet back from gVisor stack (symmetricNATPacketConn)")
	}
	outBytes := outPkt.ToView().AsSlice()
	outPkt.DecRef()

	ipOut := header.IPv4(outBytes)
	if ipOut.SourceAddress() != tcpip.AddrFrom4(netip.MustParseAddr("198.18.0.2").As4()) {
		t.Fatalf("reply source IP = %v, want 198.18.0.2", ipOut.SourceAddress())
	}
	udpOut := header.UDP(ipOut.Payload())
	if udpOut.SourcePort() != 53 || udpOut.DestinationPort() != 45678 {
		t.Fatalf("reply UDP ports = %d->%d, want 53->45678", udpOut.SourcePort(), udpOut.DestinationPort())
	}
	if !bytes.Equal(udpOut.Payload(), wantDNSReply) {
		t.Fatalf("reply UDP payload = %q, want %q", udpOut.Payload(), wantDNSReply)
	}

	// Clean Stop and idempotent second Stop.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	if err := runner.Stop(stopCtx); err != nil {
		t.Fatalf("Runner.Stop failed: %v", err)
	}
	if err := runner.Stop(stopCtx); err != nil {
		t.Fatalf("second Runner.Stop failed: %v", err)
	}

	if !mockDev.closed.Load() {
		t.Fatal("expected mock TUN device to be closed on Stop")
	}
	if st := runner.Stats(); st.Running || st.IfaceIndex != 0 {
		t.Fatalf("expected stopped stats, got %+v", st)
	}

	// Verify zero leaked goroutines after Stop.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline {
		buf := make([]byte, 64*1024)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutine leak: got %d, baseline %d\n%s", got, baseline, buf[:n])
	}
}

func TestRunner_StartValidationAndFailureRollback(t *testing.T) {
	openErr := errors.New("boom open device")
	runner := newRunnerWithOpener(func(name string, mtu int, ipv4CIDR, ipv6CIDR string, enableIPv6 bool) (device.Device, int, error) {
		return nil, 0, openErr
	})

	if _, err := runner.Start(context.Background(), Config{}); err == nil {
		t.Fatal("expected error for nil TunnelDialer")
	}
	if _, err := runner.Start(context.Background(), Config{
		TunnelDialer: &mockDialer{},
		IPv4CIDR:     "not-a-cidr",
	}); err == nil {
		t.Fatal("expected error for invalid IPv4CIDR")
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runner.Start(cancelledCtx, Config{TunnelDialer: &mockDialer{}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	if _, err := runner.Start(context.Background(), Config{TunnelDialer: &mockDialer{}}); !errors.Is(err, openErr) {
		t.Fatalf("expected openErr, got %v", err)
	}
	if st := runner.Stats(); st.Running {
		t.Fatalf("expected Running=false after Start failure, got %+v", st)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline {
		t.Fatalf("goroutine leak after Start failure: got %d, baseline %d", got, baseline)
	}
}

func TestCustomProxy_CloseCancelsInFlightDialAndActiveConns(t *testing.T) {
	dialStarted := make(chan struct{})
	dialErrCh := make(chan error, 1)

	blockingDialer := &mockDialer{
		fn: func(ctx context.Context, network, address string) (net.Conn, error) {
			close(dialStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	p := NewCustomProxy(Config{TunnelDialer: blockingDialer})
	if _, err := p.DialContext(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil metadata")
	}

	go func() {
		_, err := p.DialContext(context.Background(), &M.Metadata{
			Network: M.TCP,
			DstIP:   netip.MustParseAddr("1.1.1.1"),
			DstPort: 443,
		})
		dialErrCh <- err
	}()

	select {
	case <-dialStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for in-flight dial to start")
	}

	if err := p.Close(); err != nil {
		t.Fatalf("CustomProxy.Close failed: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("idempotent CustomProxy.Close failed: %v", err)
	}

	select {
	case err := <-dialErrCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled from aborted dial, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight dial did not unblock after CustomProxy.Close")
	}

	if _, err := p.DialContext(context.Background(), &M.Metadata{
		Network: M.TCP,
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 443,
	}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close, got %v", err)
	}
}

func TestRunner_ConcurrentStopIsIdempotent(t *testing.T) {
	runner := newRunnerWithOpener(func(name string, mtu int, ipv4CIDR, ipv6CIDR string, enableIPv6 bool) (device.Device, int, error) {
		return newMockChannelDevice(name, uint32(mtu)), 7, nil
	})

	if _, err := runner.Start(context.Background(), Config{TunnelDialer: &mockDialer{}}); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			errs <- runner.Stop(ctx)
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Stop failed: %v", err)
		}
	}
}

func TestCustomProxy_DialContext_RejectsLocalTUNNonDNS(t *testing.T) {
	dnsAddr, stopDNS := startTCPEchoServer(t)
	defer stopDNS()

	dialer := &mockDialer{}
	p := NewCustomProxy(Config{
		IPv4CIDR:     DefaultIPv4CIDR,
		IPv6CIDR:     DefaultIPv6CIDR,
		EnableIPv6:   true,
		TunnelDialer: dialer,
		DNSTCPAddr:   dnsAddr,
	})
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. 198.18.0.2:853 (Android Private DNS DoT probe) must be rejected immediately without dialing SSH.
	if conn, err := p.DialContext(ctx, &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("198.18.0.1"),
		SrcPort: 50001,
		DstIP:   netip.MustParseAddr("198.18.0.2"),
		DstPort: 853,
	}); !errors.Is(err, ErrLocalTUNRejected) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("198.18.0.2:853 err = %v, want ErrLocalTUNRejected", err)
	}

	// 2. fd98:18::2:853 (IPv6 TUN subnet non-DNS) must also be rejected immediately.
	if conn, err := p.DialContext(ctx, &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("fd98:18::1"),
		SrcPort: 50002,
		DstIP:   netip.MustParseAddr("fd98:18::2"),
		DstPort: 853,
	}); !errors.Is(err, ErrLocalTUNRejected) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("fd98:18::2:853 err = %v, want ErrLocalTUNRejected", err)
	}

	if calls := dialer.Calls(); len(calls) != 0 {
		t.Fatalf("expected 0 TunnelDialer calls for rejected local TUN destinations, got %+v", calls)
	}

	// 3. 198.18.0.2:53 must still route to the local DNS TCP listener.
	conn, err := p.DialContext(ctx, &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("198.18.0.1"),
		SrcPort: 50003,
		DstIP:   netip.MustParseAddr("198.18.0.2"),
		DstPort: 53,
	})
	if err != nil {
		t.Fatalf("198.18.0.2:53 failed: %v", err)
	}
	_ = conn.Close()
	if calls := dialer.Calls(); len(calls) != 0 {
		t.Fatalf("expected 0 TunnelDialer calls for TCP:53, got %+v", calls)
	}
}

func TestCustomProxy_DialContext_BlockIPv6Data(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoServer(t)
	defer stopEcho()

	dialer := &mockDialer{
		fn: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, echoAddr)
		},
	}

	p := NewCustomProxy(Config{
		IPv4CIDR:      DefaultIPv4CIDR,
		IPv6CIDR:      DefaultIPv6CIDR,
		EnableIPv6:    true,
		BlockIPv6Data: true,
		TunnelDialer:  dialer,
	})
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// IPv6 data connection must be rejected immediately without calling TunnelDialer.
	if conn, err := p.DialContext(ctx, &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("fd98:18::1"),
		SrcPort: 51000,
		DstIP:   netip.MustParseAddr("2606:4700:4700::1111"),
		DstPort: 443,
	}); !errors.Is(err, ErrIPv6Blocked) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("[2606:4700:4700::1111]:443 err = %v, want ErrIPv6Blocked", err)
	}
	if calls := dialer.Calls(); len(calls) != 0 {
		t.Fatalf("expected 0 TunnelDialer calls when IPv6 blocked, got %+v", calls)
	}

	// IPv4 data connection must still dial TunnelDialer normally.
	conn, err := p.DialContext(ctx, &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("198.18.0.1"),
		SrcPort: 51001,
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 443,
	})
	if err != nil {
		t.Fatalf("1.1.1.1:443 failed: %v", err)
	}
	_ = conn.Close()

	calls := dialer.Calls()
	if len(calls) != 1 || calls[0].address != "1.1.1.1:443" {
		t.Fatalf("unexpected TunnelDialer calls: %+v", calls)
	}

	// Zero-value default (BlockIPv6Data: false) preserves IPv6 forwarding.
	pAllowV6 := NewCustomProxy(Config{
		TunnelDialer: dialer,
	})
	defer pAllowV6.Close()
	c2, err := pAllowV6.DialContext(ctx, &M.Metadata{
		Network: M.TCP,
		DstIP:   netip.MustParseAddr("2606:4700:4700::1111"),
		DstPort: 443,
	})
	if err != nil {
		t.Fatalf("IPv6 with BlockIPv6Data=false failed: %v", err)
	}
	_ = c2.Close()
	if calls := dialer.Calls(); len(calls) != 2 || calls[1].address != "[2606:4700:4700::1111]:443" {
		t.Fatalf("expected IPv6 dial when BlockIPv6Data=false, got %+v", calls)
	}
}

func buildIPv4TCPSynPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq uint32) []byte {
	totalLen := header.IPv4MinimumSize + header.TCPMinimumSize
	pkt := make([]byte, totalLen)

	srcAddr := tcpip.AddrFrom4(srcIP.As4())
	dstAddr := tcpip.AddrFrom4(dstIP.As4())

	ipHdr := header.IPv4(pkt[:header.IPv4MinimumSize])
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	tcpHdr := header.TCP(pkt[header.IPv4MinimumSize:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, header.TCPMinimumSize)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(xsum))
	return pkt
}

func buildIPv6TCPSynPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq uint32) []byte {
	totalLen := header.IPv6MinimumSize + header.TCPMinimumSize
	pkt := make([]byte, totalLen)

	srcAddr := tcpip.AddrFrom16(srcIP.As16())
	dstAddr := tcpip.AddrFrom16(dstIP.As16())

	ipHdr := header.IPv6(pkt[:header.IPv6MinimumSize])
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     header.TCPMinimumSize,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})

	tcpHdr := header.TCP(pkt[header.IPv6MinimumSize:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, header.TCPMinimumSize)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(xsum))
	return pkt
}

func TestRunner_FastRejectHandlers_TCPResetAndUDPDrop(t *testing.T) {
	wantDNSReply := []byte("dns-ok-with-fast-reject")
	dnsUDPAddr, dnsReceivedCh, stopDNS := startUDPDNSResponder(t, wantDNSReply)
	defer stopDNS()

	mockDev := newMockChannelDevice("tunssh-fast0", 1380)
	dialer := &mockDialer{}

	runner := newRunnerWithOpener(func(name string, mtu int, ipv4CIDR, ipv6CIDR string, enableIPv6 bool) (device.Device, int, error) {
		return mockDev, 43, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := runner.Start(ctx, Config{
		IfaceName:     "tunssh-fast0",
		MTU:           1380,
		IPv4CIDR:      DefaultIPv4CIDR,
		IPv6CIDR:      DefaultIPv6CIDR,
		EnableIPv6:    true,
		BlockIPv6Data: true,
		TunnelDialer:  dialer,
		DNSUDPAddr:    dnsUDPAddr,
	}); err != nil {
		t.Fatalf("Runner.Start failed: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stopCancel()
		if err := runner.Stop(stopCtx); err != nil {
			t.Errorf("Runner.Stop failed: %v", err)
		}
	}()

	// 1. TCP SYN to 198.18.0.2:853 (Android Private DNS DoT) must get immediate TCP RST before CreateEndpoint.
	syn853 := buildIPv4TCPSynPacket(
		netip.MustParseAddr("198.18.0.1"),
		netip.MustParseAddr("198.18.0.2"),
		54321,
		853,
		1000,
	)
	pkt853 := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(syn853)})
	mockDev.InjectInbound(header.IPv4ProtocolNumber, pkt853)
	pkt853.DecRef()

	readCtx1, readCancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel1()
	rstPkt1 := mockDev.ReadContext(readCtx1)
	if rstPkt1 == nil {
		t.Fatal("expected immediate TCP RST for 198.18.0.2:853, got nil")
	}
	rstBytes1 := rstPkt1.ToView().AsSlice()
	rstPkt1.DecRef()
	ipOut1 := header.IPv4(rstBytes1)
	tcpOut1 := header.TCP(ipOut1.Payload())
	if !tcpOut1.Flags().Contains(header.TCPFlagRst) {
		t.Fatalf("198.18.0.2:853 reply flags = %v, want RST", tcpOut1.Flags())
	}
	if tcpOut1.SourcePort() != 853 || tcpOut1.DestinationPort() != 54321 {
		t.Fatalf("198.18.0.2:853 RST ports = %d->%d, want 853->54321", tcpOut1.SourcePort(), tcpOut1.DestinationPort())
	}

	// 2. IPv6 TCP SYN to [2606:4700:4700::1111]:443 with BlockIPv6Data=true must get immediate TCP RST.
	synV6 := buildIPv6TCPSynPacket(
		netip.MustParseAddr("fd98:18::1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
		54322,
		443,
		2000,
	)
	pktV6 := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(synV6)})
	mockDev.InjectInbound(header.IPv6ProtocolNumber, pktV6)
	pktV6.DecRef()

	readCtx2, readCancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel2()
	rstPkt2 := mockDev.ReadContext(readCtx2)
	if rstPkt2 == nil {
		t.Fatal("expected immediate IPv6 TCP RST for [2606:4700:4700::1111]:443, got nil")
	}
	rstBytes2 := rstPkt2.ToView().AsSlice()
	rstPkt2.DecRef()
	ipOut2 := header.IPv6(rstBytes2)
	tcpOut2 := header.TCP(ipOut2.Payload())
	if !tcpOut2.Flags().Contains(header.TCPFlagRst) {
		t.Fatalf("IPv6 :443 reply flags = %v, want RST", tcpOut2.Flags())
	}
	if tcpOut2.SourcePort() != 443 || tcpOut2.DestinationPort() != 54322 {
		t.Fatalf("IPv6 :443 RST ports = %d->%d, want 443->54322", tcpOut2.SourcePort(), tcpOut2.DestinationPort())
	}

	// 3. Non-DNS UDP (QUIC :443) must be rejected at gVisor forwarder without touching DNS or TunnelDialer.
	quicPkt := buildIPv4UDPPacket(
		netip.MustParseAddr("198.18.0.1"),
		netip.MustParseAddr("1.1.1.1"),
		54323,
		443,
		[]byte("quic-client-hello"),
	)
	pktQUIC := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(quicPkt)})
	mockDev.InjectInbound(header.IPv4ProtocolNumber, pktQUIC)
	pktQUIC.DecRef()

	// Drain any ICMP port unreachable packet emitted by gVisor for unhandled UDP :443, then verify UDP :53 still works.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if p := mockDev.ReadContext(drainCtx); p != nil {
		p.DecRef()
	}
	drainCancel()

	dnsQuery := buildIPv4UDPPacket(
		netip.MustParseAddr("198.18.0.1"),
		netip.MustParseAddr("198.18.0.2"),
		54324,
		53,
		[]byte("dns-after-quic"),
	)
	pktDNS := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(dnsQuery)})
	mockDev.InjectInbound(header.IPv4ProtocolNumber, pktDNS)
	pktDNS.DecRef()

	select {
	case got := <-dnsReceivedCh:
		if string(got) != "dns-after-quic" {
			t.Fatalf("DNS listener got %q, want %q", got, "dns-after-quic")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP :53 DNS packet after QUIC rejection")
	}

	if calls := dialer.Calls(); len(calls) != 0 {
		t.Fatalf("expected 0 TunnelDialer calls across all fast-rejected packets, got %+v", calls)
	}

	// 4. Normal IPv4 TCP SYN to a public address (93.184.216.34:443) must complete handshake (SYN+ACK)
	// through our custom TCP forwarder and invoke TunnelDialer.
	synOK := buildIPv4TCPSynPacket(
		netip.MustParseAddr("198.18.0.1"),
		netip.MustParseAddr("93.184.216.34"),
		54325,
		443,
		3000,
	)
	pktOK := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(synOK)})
	mockDev.InjectInbound(header.IPv4ProtocolNumber, pktOK)
	pktOK.DecRef()

	readCtx3, readCancel3 := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel3()
	gotSynAck := false
	for !gotSynAck {
		p := mockDev.ReadContext(readCtx3)
		if p == nil {
			t.Fatal("timed out waiting for TCP SYN+ACK from custom TCP forwarder for 93.184.216.34:443")
		}
		b := p.ToView().AsSlice()
		p.DecRef()
		if len(b) < header.IPv4MinimumSize {
			continue
		}
		ipOut := header.IPv4(b)
		if ipOut.TransportProtocol() != header.TCPProtocolNumber {
			continue
		}
		tcpOut := header.TCP(ipOut.Payload())
		if tcpOut.SourcePort() == 443 && tcpOut.DestinationPort() == 54325 &&
			tcpOut.Flags().Contains(header.TCPFlagSyn|header.TCPFlagAck) {
			gotSynAck = true
		}
	}
}
