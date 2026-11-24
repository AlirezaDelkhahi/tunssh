package splitroute

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
)

type opCall struct {
	kind  string // "add_route", "del_route", "capture_route", "is_active", "capture_dns", "apply_dns", "restore_dns"
	route RouteSpec
}

type mockRouteAndDNS struct {
	mu sync.Mutex

	gw4        netip.Addr
	gw6        netip.Addr
	ifaceName  string
	ifaceIndex int
	captureErr error

	tunActive    bool
	tunActiveErr error
	dnsActive    bool
	dnsActiveErr error

	dnsStrategy   string
	origDNS       []netip.Addr
	winBackups    []WinAdapterDNSBackup
	linuxBackups  []LinuxDNSBackup
	resolvBackup  string
	captureDNSErr error

	failAddDst     netip.Prefix
	failAddErr     error
	failDelDst     netip.Prefix
	failDelErr     error
	failApplyDNS   error
	failRestoreDNS error

	installed  map[netip.Prefix]RouteSpec
	dnsApplied bool
	calls      []opCall
}

func newMockRouteAndDNS() *mockRouteAndDNS {
	return &mockRouteAndDNS{
		gw4:         netip.MustParseAddr("192.168.1.1"),
		ifaceName:   "eth0",
		ifaceIndex:  3,
		dnsStrategy: "systemd-resolved",
		origDNS:     []netip.Addr{netip.MustParseAddr("192.168.1.1")},
		linuxBackups: []LinuxDNSBackup{
			{
				IfIndex:      3,
				IfName:       "eth0",
				DNSServers:   []string{"192.168.1.1"},
				DefaultRoute: true,
			},
		},
		installed: make(map[netip.Prefix]RouteSpec),
	}
}

func (m *mockRouteAndDNS) CaptureDefaultRoute(ctx context.Context) (netip.Addr, netip.Addr, string, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, opCall{kind: "capture_route"})
	if m.captureErr != nil {
		return netip.Addr{}, netip.Addr{}, "", 0, m.captureErr
	}
	return m.gw4, m.gw6, m.ifaceName, m.ifaceIndex, nil
}

func (m *mockRouteAndDNS) AddRoute(ctx context.Context, r RouteSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, opCall{kind: "add_route", route: r})
	if m.failAddErr != nil && m.failAddDst == r.Dst {
		return m.failAddErr
	}
	m.installed[r.Dst] = r
	return nil
}

func (m *mockRouteAndDNS) DeleteRoute(ctx context.Context, r RouteSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, opCall{kind: "del_route", route: r})
	if m.failDelErr != nil && m.failDelDst == r.Dst {
		return m.failDelErr
	}
	// Idempotent delete: missing route succeeds cleanly.
	delete(m.installed, r.Dst)
	return nil
}

func (m *mockRouteAndDNS) IsTUNRouteOrIfaceActive(ctx context.Context, tunIface string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, opCall{kind: "is_active"})
	return m.tunActive, m.tunActiveErr
}

func (m *mockRouteAndDNS) IsTUNDNSActive(ctx context.Context, tunIface string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, opCall{kind: "is_dns_active"})
	return m.dnsActive, m.dnsActiveErr
}

func (m *mockRouteAndDNS) CaptureDNS(ctx context.Context, origIfaceName string, origIfaceIndex int) (string, []netip.Addr, []WinAdapterDNSBackup, []LinuxDNSBackup, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, opCall{kind: "capture_dns"})
	if m.captureDNSErr != nil {
		return "", nil, nil, nil, "", m.captureDNSErr
	}
	return m.dnsStrategy, slices.Clone(m.origDNS), slices.Clone(m.winBackups), slices.Clone(m.linuxBackups), m.resolvBackup, nil
}

func (m *mockRouteAndDNS) ApplyTUNDNS(ctx context.Context, snap NetworkSnapshot, tunDNS netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, opCall{kind: "apply_dns"})
	if m.failApplyDNS != nil {
		return m.failApplyDNS
	}
	m.dnsApplied = true
	return nil
}

func (m *mockRouteAndDNS) RestoreDNS(ctx context.Context, snap NetworkSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, opCall{kind: "restore_dns"})
	if m.failRestoreDNS != nil {
		return m.failRestoreDNS
	}
	m.dnsApplied = false
	return nil
}

func (m *mockRouteAndDNS) findCallIndex(kind string, dstPrefix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, c := range m.calls {
		if c.kind != kind {
			continue
		}
		if dstPrefix == "" || c.route.Dst.String() == dstPrefix {
			return i
		}
	}
	return -1
}

func (m *mockRouteAndDNS) resetCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

func TestConstantsAndIranCIDRsValidNonOverlapping(t *testing.T) {
	if TUNIfaceName != "tunssh0" {
		t.Fatalf("TUNIfaceName = %q, want tunssh0", TUNIfaceName)
	}
	if TUNIPv4CIDR != "198.18.0.1/15" {
		t.Fatalf("TUNIPv4CIDR = %q, want 198.18.0.1/15", TUNIPv4CIDR)
	}
	if TUNIPv4Addr != "198.18.0.1" {
		t.Fatalf("TUNIPv4Addr = %q, want 198.18.0.1", TUNIPv4Addr)
	}
	if TUNDNSServer != "198.18.0.2" {
		t.Fatalf("TUNDNSServer = %q, want 198.18.0.2", TUNDNSServer)
	}
	if TUNIPv6CIDR != "fd98:18::1/64" {
		t.Fatalf("TUNIPv6CIDR = %q, want fd98:18::1/64", TUNIPv6CIDR)
	}
	if TUNMTU != 1380 {
		t.Fatalf("TUNMTU = %d, want 1380", TUNMTU)
	}

	if len(RFC1918AndLocalBypassCIDRs) != 5 {
		t.Fatalf("len(RFC1918AndLocalBypassCIDRs) = %d, want 5", len(RFC1918AndLocalBypassCIDRs))
	}
	if len(IranBypassCIDRs) == 0 {
		t.Fatal("IranBypassCIDRs must not be empty")
	}

	forbidden := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
	}
	forbidden = append(forbidden, RFC1918AndLocalBypassCIDRs...)

	for i, p := range IranBypassCIDRs {
		if !p.IsValid() {
			t.Fatalf("IranBypassCIDRs[%d] is invalid", i)
		}
		if !p.Addr().Is4() {
			t.Fatalf("IranBypassCIDRs[%d] (%s) must be IPv4", i, p)
		}
		if p != p.Masked() {
			t.Fatalf("IranBypassCIDRs[%d] (%s) is not canonical masked form %s", i, p, p.Masked())
		}
		for _, f := range forbidden {
			if p.Overlaps(f) {
				t.Fatalf("IranBypassCIDRs[%d] (%s) overlaps forbidden range %s", i, p, f)
			}
		}
		for j := i + 1; j < len(IranBypassCIDRs); j++ {
			if p.Overlaps(IranBypassCIDRs[j]) {
				t.Fatalf("IranBypassCIDRs[%d] (%s) overlaps IranBypassCIDRs[%d] (%s)", i, p, j, IranBypassCIDRs[j])
			}
		}
	}
}

func TestIsBypassIP(t *testing.T) {
	cases := []struct {
		name        string
		addr        netip.Addr
		includeIran bool
		want        bool
	}{
		{name: "rfc1918_10", addr: netip.MustParseAddr("10.1.2.3"), includeIran: false, want: true},
		{name: "rfc1918_172", addr: netip.MustParseAddr("172.16.5.4"), includeIran: false, want: true},
		{name: "rfc1918_192", addr: netip.MustParseAddr("192.168.1.1"), includeIran: false, want: true},
		{name: "link_local_169", addr: netip.MustParseAddr("169.254.10.20"), includeIran: false, want: true},
		{name: "multicast_224", addr: netip.MustParseAddr("224.0.0.251"), includeIran: false, want: true},
		{name: "v4_mapped_192", addr: netip.MustParseAddr("::ffff:192.168.1.1"), includeIran: false, want: true},
		{name: "public_8888", addr: netip.MustParseAddr("8.8.8.8"), includeIran: true, want: false},
		{name: "public_1111", addr: netip.MustParseAddr("1.1.1.1"), includeIran: true, want: false},
		{name: "loopback", addr: netip.MustParseAddr("127.0.0.1"), includeIran: true, want: false},
		{name: "tun_dns", addr: netip.MustParseAddr("198.18.0.2"), includeIran: true, want: false},
		{name: "iran_tic_bypass_off", addr: netip.MustParseAddr("217.218.155.155"), includeIran: false, want: false},
		{name: "iran_tic_bypass_on", addr: netip.MustParseAddr("217.218.155.155"), includeIran: true, want: true},
		{name: "iran_mci_bypass_on", addr: netip.MustParseAddr("5.112.10.10"), includeIran: true, want: true},
		{name: "ipv6_public", addr: netip.MustParseAddr("2001:4860:4860::8888"), includeIran: true, want: false},
		{name: "invalid", addr: netip.Addr{}, includeIran: true, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBypassIP(tc.addr, tc.includeIran); got != tc.want {
				t.Fatalf("IsBypassIP(%v, %v) = %v, want %v", tc.addr, tc.includeIran, got, tc.want)
			}
		})
	}
}

func TestApplySplitTunnelStrictOrderingAndBypassFlags(t *testing.T) {
	ctx := context.Background()

	t.Run("bypass_iran_true_pins_public_dns_and_installs_vps_first", func(t *testing.T) {
		mock := newMockRouteAndDNS()
		mgr := NewManagerWithDeps(mock, mock, nil)

		plan := RoutePlan{
			VPSPeerIP:      netip.MustParseAddr("203.0.113.10"),
			OrigGateway:    netip.MustParseAddr("192.168.1.1"),
			OrigGateway6:   netip.MustParseAddr("fe80::1"),
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 3,
			OrigDNSServers: []netip.Addr{
				netip.MustParseAddr("127.0.0.53"),           // loopback -> skipped
				netip.MustParseAddr("192.168.1.1"),          // RFC1918 -> covered by step 3
				netip.MustParseAddr("217.218.155.155"),      // Iran CIDR -> covered by step 4 when BypassIranLAN=true
				netip.MustParseAddr("8.8.8.8"),              // public -> pinned /32 in step 2
				netip.MustParseAddr("2001:4860:4860::8888"), // public IPv6 -> pinned /128 in step 2
				netip.MustParseAddr("fe80::1"),              // link-local -> skipped
			},
			TUNIfaceName:  TUNIfaceName,
			TUNIfaceIndex: 99,
			BypassIranLAN: true,
			EnableIPv6:    true,
		}

		if err := mgr.ApplySplitTunnel(ctx, plan); err != nil {
			t.Fatalf("ApplySplitTunnel failed: %v", err)
		}

		vpsIdx := mock.findCallIndex("add_route", "203.0.113.10/32")
		dnsIdx := mock.findCallIndex("add_route", "8.8.8.8/32")
		dns6Idx := mock.findCallIndex("add_route", "2001:4860:4860::8888/128")
		rfcIdx := mock.findCallIndex("add_route", "192.168.0.0/16")
		iranIdx := mock.findCallIndex("add_route", IranBypassCIDRs[0].String())
		splitV4LowIdx := mock.findCallIndex("add_route", "0.0.0.0/1")
		splitV4HighIdx := mock.findCallIndex("add_route", "128.0.0.0/1")
		splitV6LowIdx := mock.findCallIndex("add_route", "::/1")
		splitV6HighIdx := mock.findCallIndex("add_route", "8000::/1")
		applyDNSIdx := mock.findCallIndex("apply_dns", "")

		if vpsIdx != 0 {
			t.Fatalf("expected VPSPeerIP/32 to be strictly first call (index 0), got %d", vpsIdx)
		}
		if dnsIdx < 0 || dns6Idx < 0 {
			t.Fatalf("expected public OrigDNS routes to be pinned; dnsIdx=%d dns6Idx=%d", dnsIdx, dns6Idx)
		}
		if mock.findCallIndex("add_route", "192.168.1.1/32") >= 0 {
			t.Fatal("LAN OrigDNS 192.168.1.1 must not be given a redundant /32 route")
		}
		if mock.findCallIndex("add_route", "127.0.0.53/32") >= 0 {
			t.Fatal("loopback OrigDNS 127.0.0.53 must not be pinned")
		}
		if mock.findCallIndex("add_route", "217.218.155.155/32") >= 0 {
			t.Fatal("Iran OrigDNS 217.218.155.155 must not get redundant /32 when BypassIranLAN=true")
		}
		if !(vpsIdx < dnsIdx && dnsIdx < rfcIdx && rfcIdx < iranIdx && iranIdx < splitV4LowIdx && splitV4LowIdx < splitV4HighIdx && splitV4HighIdx < splitV6LowIdx && splitV6LowIdx < splitV6HighIdx && splitV6HighIdx < applyDNSIdx) {
			t.Fatalf("unexpected ordering indices: vps=%d dns=%d rfc=%d iran=%d 0/1=%d 128/1=%d ::/1=%d 8000::/1=%d applyDNS=%d",
				vpsIdx, dnsIdx, rfcIdx, iranIdx, splitV4LowIdx, splitV4HighIdx, splitV6LowIdx, splitV6HighIdx, applyDNSIdx)
		}

		// Verify Iran CIDRs all installed and routed via OrigGateway.
		for _, cidr := range IranBypassCIDRs {
			spec, ok := mock.installed[cidr]
			if !ok {
				t.Fatalf("missing Iran bypass CIDR %s", cidr)
			}
			if spec.Gateway != plan.OrigGateway || spec.IfaceName != plan.OrigIfaceName {
				t.Fatalf("Iran CIDR %s routed via %v/%s, want %v/%s", cidr, spec.Gateway, spec.IfaceName, plan.OrigGateway, plan.OrigIfaceName)
			}
		}

		// Verify TUN routes use TUN interface.
		if spec := mock.installed[netip.MustParsePrefix("0.0.0.0/1")]; spec.IfaceName != TUNIfaceName || spec.IfaceIndex != 99 {
			t.Fatalf("0.0.0.0/1 route spec mismatch: %+v", spec)
		}
	})

	t.Run("bypass_iran_false_omits_iran_cidrs", func(t *testing.T) {
		mock := newMockRouteAndDNS()
		mgr := NewManagerWithDeps(mock, mock, nil)

		plan := RoutePlan{
			VPSPeerIP:      netip.MustParseAddr("203.0.113.10"),
			OrigGateway:    netip.MustParseAddr("192.168.1.1"),
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 3,
			OrigDNSServers: []netip.Addr{
				netip.MustParseAddr("217.218.155.155"), // Not covered when BypassIranLAN=false -> gets /32 pin
			},
			TUNIfaceName:  TUNIfaceName,
			TUNIfaceIndex: 99,
			BypassIranLAN: false,
			EnableIPv6:    false,
		}

		if err := mgr.ApplySplitTunnel(ctx, plan); err != nil {
			t.Fatalf("ApplySplitTunnel failed: %v", err)
		}

		for _, cidr := range RFC1918AndLocalBypassCIDRs {
			if _, ok := mock.installed[cidr]; !ok {
				t.Fatalf("expected RFC1918/local CIDR %s to still be installed", cidr)
			}
		}
		for _, cidr := range IranBypassCIDRs {
			if _, ok := mock.installed[cidr]; ok {
				t.Fatalf("did not expect Iran CIDR %s when BypassIranLAN=false", cidr)
			}
		}
		if _, ok := mock.installed[netip.MustParsePrefix("217.218.155.155/32")]; !ok {
			t.Fatal("expected public/non-bypassed DNS 217.218.155.155/32 to be pinned when BypassIranLAN=false")
		}
		if _, ok := mock.installed[netip.MustParsePrefix("::/1")]; ok {
			t.Fatal("did not expect IPv6 ::/1 when EnableIPv6=false")
		}
	})

	t.Run("ipv6_disabled_gracefully_skips_v6_split_routes", func(t *testing.T) {
		mock := newMockRouteAndDNS()
		mock.failAddDst = netip.MustParsePrefix("::/1")
		mock.failAddErr = ErrIPv6Disabled
		mgr := NewManagerWithDeps(mock, mock, nil)

		plan := RoutePlan{
			VPSPeerIP:      netip.MustParseAddr("203.0.113.10"),
			OrigGateway:    netip.MustParseAddr("192.168.1.1"),
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 3,
			TUNIfaceName:   TUNIfaceName,
			TUNIfaceIndex:  99,
			BypassIranLAN:  false,
			EnableIPv6:     true,
		}

		if err := mgr.ApplySplitTunnel(ctx, plan); err != nil {
			t.Fatalf("expected graceful skip on ErrIPv6Disabled, got error: %v", err)
		}
		if _, ok := mock.installed[netip.MustParsePrefix("0.0.0.0/1")]; !ok {
			t.Fatal("expected IPv4 split route 0.0.0.0/1 to remain installed")
		}
		if !mock.dnsApplied {
			t.Fatal("expected TUN DNS to still be applied when IPv6 is disabled")
		}
	})
}

func TestRestoreNetworkReverseOrderAndIdempotency(t *testing.T) {
	ctx := context.Background()
	mock := newMockRouteAndDNS()
	mgr := NewManagerWithDeps(mock, mock, nil)

	snap, err := mgr.CaptureNetworkSnapshot(ctx)
	if err != nil {
		t.Fatalf("CaptureNetworkSnapshot failed: %v", err)
	}

	plan := RoutePlan{
		VPSPeerIP:      netip.MustParseAddr("203.0.113.10"),
		OrigGateway:    netip.MustParseAddr("192.168.1.1"),
		OrigIfaceName:  "eth0",
		OrigIfaceIndex: 3,
		OrigDNSServers: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("192.168.1.1")},
		TUNIfaceName:   TUNIfaceName,
		TUNIfaceIndex:  99,
		BypassIranLAN:  true,
		EnableIPv6:     true,
	}
	if err := mgr.ApplySplitTunnel(ctx, plan); err != nil {
		t.Fatalf("ApplySplitTunnel failed: %v", err)
	}

	snap.VPSPeerIP = plan.VPSPeerIP.String()
	snap.OrigDNSServers = []string{"8.8.8.8", "192.168.1.1"}
	snap.InstalledRoutes, err = BuildInstalledRoutes(plan)
	if err != nil {
		t.Fatalf("BuildInstalledRoutes failed: %v", err)
	}

	mock.resetCalls()
	if err := mgr.RestoreNetwork(ctx, snap); err != nil {
		t.Fatalf("RestoreNetwork (1st) failed: %v", err)
	}

	del0Idx := mock.findCallIndex("del_route", "0.0.0.0/1")
	del128Idx := mock.findCallIndex("del_route", "128.0.0.0/1")
	delV6LowIdx := mock.findCallIndex("del_route", "::/1")
	delV6HighIdx := mock.findCallIndex("del_route", "8000::/1")
	restoreDNSIdx := mock.findCallIndex("restore_dns", "")
	delRFCIdx := mock.findCallIndex("del_route", "10.0.0.0/8")
	delIranIdx := mock.findCallIndex("del_route", IranBypassCIDRs[0].String())
	delOrigDNSIdx := mock.findCallIndex("del_route", "8.8.8.8/32")
	delVPSIdx := mock.findCallIndex("del_route", "203.0.113.10/32")

	if del0Idx < 0 || del128Idx < 0 || restoreDNSIdx < 0 || delRFCIdx < 0 || delIranIdx < 0 || delOrigDNSIdx < 0 || delVPSIdx < 0 {
		t.Fatalf("missing expected teardown calls: 0/1=%d 128/1=%d dns=%d rfc=%d iran=%d origDNS=%d vps=%d",
			del0Idx, del128Idx, restoreDNSIdx, delRFCIdx, delIranIdx, delOrigDNSIdx, delVPSIdx)
	}
	if !(delV6HighIdx < restoreDNSIdx && delV6LowIdx < restoreDNSIdx && del0Idx < restoreDNSIdx && del128Idx < restoreDNSIdx) {
		t.Fatalf("split routes must be deleted BEFORE RestoreDNS: v6=%d,%d v4=%d,%d dns=%d",
			delV6LowIdx, delV6HighIdx, del0Idx, del128Idx, restoreDNSIdx)
	}
	if !(restoreDNSIdx < delIranIdx && restoreDNSIdx < delRFCIdx && restoreDNSIdx < delOrigDNSIdx) {
		t.Fatalf("RestoreDNS must execute BEFORE deleting bypass/OrigDNS routes: dns=%d iran=%d rfc=%d origDNS=%d",
			restoreDNSIdx, delIranIdx, delRFCIdx, delOrigDNSIdx)
	}
	lastCallIdx := len(mock.calls) - 1
	if delVPSIdx != lastCallIdx {
		t.Fatalf("expected <VPSPeerIP>/32 delete to be STRICTLY LAST call (%d), got %d (%+v)", lastCallIdx, delVPSIdx, mock.calls[lastCallIdx])
	}
	if len(mock.installed) != 0 {
		t.Fatalf("expected all installed routes to be removed, remaining: %v", mock.installed)
	}
	if mock.dnsApplied {
		t.Fatal("expected DNS to be restored")
	}

	// Verify second RestoreNetwork call is completely idempotent.
	mock.resetCalls()
	if err := mgr.RestoreNetwork(ctx, snap); err != nil {
		t.Fatalf("RestoreNetwork (2nd idempotent call) failed: %v", err)
	}
	if len(mock.installed) != 0 || mock.dnsApplied {
		t.Fatal("expected clean state after idempotent 2nd RestoreNetwork")
	}
}

func TestApplySplitTunnelMidApplyFailureTriggersStrictReverseRollback(t *testing.T) {
	ctx := context.Background()

	t.Run("fail_on_128_0_0_0_1", func(t *testing.T) {
		mock := newMockRouteAndDNS()
		mock.failAddDst = netip.MustParsePrefix("128.0.0.0/1")
		mock.failAddErr = errors.New("netlink EPERM simulated")
		mgr := NewManagerWithDeps(mock, mock, nil)

		plan := RoutePlan{
			VPSPeerIP:      netip.MustParseAddr("203.0.113.10"),
			OrigGateway:    netip.MustParseAddr("192.168.1.1"),
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 3,
			OrigDNSServers: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
			TUNIfaceName:   TUNIfaceName,
			TUNIfaceIndex:  99,
			BypassIranLAN:  true,
		}

		err := mgr.ApplySplitTunnel(ctx, plan)
		if err == nil {
			t.Fatal("expected ApplySplitTunnel to fail on 128.0.0.0/1")
		}
		if len(mock.installed) != 0 {
			t.Fatalf("expected full rollback leaving 0 routes installed, remaining: %d", len(mock.installed))
		}
		if mock.findCallIndex("restore_dns", "") >= 0 {
			t.Fatal("did not expect RestoreDNS when ApplyTUNDNS was never called")
		}

		// Verify strict reverse order of all deleted routes relative to their add order.
		var added, deleted []string
		for _, c := range mock.calls {
			if c.kind == "add_route" && c.route.Dst != mock.failAddDst {
				added = append(added, c.route.Dst.String())
			}
			if c.kind == "del_route" {
				deleted = append(deleted, c.route.Dst.String())
			}
		}
		slices.Reverse(added)
		if !slices.Equal(added, deleted) {
			t.Fatalf("rollback delete order mismatch:\nwant reverse: %v\ngot:          %v", added[:min(5, len(added))], deleted[:min(5, len(deleted))])
		}
	})

	t.Run("fail_on_apply_tun_dns", func(t *testing.T) {
		mock := newMockRouteAndDNS()
		mock.failApplyDNS = errors.New("resolvectl failed")
		mgr := NewManagerWithDeps(mock, mock, nil)

		plan := RoutePlan{
			VPSPeerIP:      netip.MustParseAddr("203.0.113.10"),
			OrigGateway:    netip.MustParseAddr("192.168.1.1"),
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 3,
			OrigDNSServers: []netip.Addr{netip.MustParseAddr("8.8.8.8")},
			TUNIfaceName:   TUNIfaceName,
			TUNIfaceIndex:  99,
			BypassIranLAN:  false,
			EnableIPv6:     true,
		}

		err := mgr.ApplySplitTunnel(ctx, plan)
		if err == nil {
			t.Fatal("expected ApplySplitTunnel to fail on ApplyTUNDNS")
		}
		if len(mock.installed) != 0 {
			t.Fatalf("expected full rollback leaving 0 routes installed, remaining: %v", mock.installed)
		}

		del0Idx := mock.findCallIndex("del_route", "0.0.0.0/1")
		del128Idx := mock.findCallIndex("del_route", "128.0.0.0/1")
		restoreDNSIdx := mock.findCallIndex("restore_dns", "")
		delRFCIdx := mock.findCallIndex("del_route", "10.0.0.0/8")
		delVPSIdx := mock.findCallIndex("del_route", "203.0.113.10/32")

		if restoreDNSIdx < 0 {
			t.Fatal("expected RestoreDNS to be called when rolling back ApplyTUNDNS failure")
		}
		if !(del128Idx < restoreDNSIdx && del0Idx < restoreDNSIdx && restoreDNSIdx < delRFCIdx && delRFCIdx < delVPSIdx) {
			t.Fatalf("unexpected rollback order on ApplyTUNDNS failure: 128/1=%d 0/1=%d restoreDNS=%d rfc=%d vps=%d",
				del128Idx, del0Idx, restoreDNSIdx, delRFCIdx, delVPSIdx)
		}
		if delVPSIdx != len(mock.calls)-1 {
			t.Fatalf("expected <VPSPeerIP>/32 delete last (%d), got %d", len(mock.calls)-1, delVPSIdx)
		}
	})
}

func TestResolveVPSPeerIP(t *testing.T) {
	ctx := context.Background()

	ip, err := ResolveVPSPeerIP(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("ResolveVPSPeerIP(127.0.0.1) failed: %v", err)
	}
	if ip != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("got %v, want 127.0.0.1", ip)
	}

	ip6, err := ResolveVPSPeerIP(ctx, "[::1]")
	if err != nil {
		t.Fatalf("ResolveVPSPeerIP([::1]) failed: %v", err)
	}
	if ip6 != netip.MustParseAddr("::1") {
		t.Fatalf("got %v, want ::1", ip6)
	}

	localIP, err := ResolveVPSPeerIP(ctx, "localhost")
	if err != nil {
		t.Fatalf("ResolveVPSPeerIP(localhost) failed: %v", err)
	}
	if !localIP.IsValid() || !localIP.IsLoopback() {
		t.Fatalf("expected valid loopback IP for localhost, got %v", localIP)
	}

	if _, err := ResolveVPSPeerIP(ctx, "   "); err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestIsTUNStateActiveAndBindControl(t *testing.T) {
	ctx := context.Background()
	mock := newMockRouteAndDNS()
	mgr := NewManagerWithDeps(mock, mock, nil)

	active, err := mgr.IsTUNStateActive(ctx)
	if err != nil || active {
		t.Fatalf("got (%v, %v), want (false, nil)", active, err)
	}

	mock.tunActive = true
	active, err = mgr.IsTUNStateActive(ctx)
	if err != nil || !active {
		t.Fatalf("got (%v, %v), want (true, nil)", active, err)
	}

	ctrl := BindToInterfaceControl("lo", 1, false)
	if ctrl == nil {
		t.Fatal("BindToInterfaceControl must return a non-nil callback")
	}
	if !strings.HasPrefix(TUNIfaceName, "tunssh") {
		t.Fatalf("unexpected TUNIfaceName: %q", TUNIfaceName)
	}
}

func TestApplySplitTunnelIPv6PeerAndEdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("ipv6_vps_peer_pins_slash128_first_and_deletes_last", func(t *testing.T) {
		mock := newMockRouteAndDNS()
		mgr := NewManagerWithDeps(mock, mock, nil)

		plan := RoutePlan{
			VPSPeerIP:      netip.MustParseAddr("2001:db8::10"),
			OrigGateway:    netip.MustParseAddr("192.168.1.1"),
			OrigGateway6:   netip.MustParseAddr("fe80::1"),
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 3,
			TUNIfaceName:   TUNIfaceName,
			TUNIfaceIndex:  99,
			EnableIPv6:     true,
		}

		if err := mgr.ApplySplitTunnel(ctx, plan); err != nil {
			t.Fatalf("ApplySplitTunnel failed: %v", err)
		}
		if idx := mock.findCallIndex("add_route", "2001:db8::10/128"); idx != 0 {
			t.Fatalf("expected IPv6 VPS peer /128 at index 0, got %d", idx)
		}
		if spec := mock.installed[netip.MustParsePrefix("2001:db8::10/128")]; spec.Gateway != plan.OrigGateway6 {
			t.Fatalf("expected IPv6 VPS route gateway %v, got %v", plan.OrigGateway6, spec.Gateway)
		}

		mock.resetCalls()
		snap := NetworkSnapshot{
			VPSPeerIP:      "2001:db8::10",
			OrigGateway:    "192.168.1.1",
			OrigGateway6:   "fe80::1",
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 3,
			TUNIfaceName:   TUNIfaceName,
		}
		if err := mgr.RestoreNetwork(ctx, snap); err != nil {
			t.Fatalf("RestoreNetwork failed: %v", err)
		}
		if idx := mock.findCallIndex("del_route", "2001:db8::10/128"); idx != len(mock.calls)-1 {
			t.Fatalf("expected IPv6 VPS /128 delete strictly last (%d), got %d", len(mock.calls)-1, idx)
		}
	})

	t.Run("ipv6_disabled_on_8000_cleans_up_partial_::1_without_failing", func(t *testing.T) {
		mock := newMockRouteAndDNS()
		mock.failAddDst = netip.MustParsePrefix("8000::/1")
		mock.failAddErr = ErrIPv6Disabled
		mgr := NewManagerWithDeps(mock, mock, nil)

		plan := RoutePlan{
			VPSPeerIP:      netip.MustParseAddr("203.0.113.10"),
			OrigGateway:    netip.MustParseAddr("192.168.1.1"),
			OrigIfaceName:  "eth0",
			OrigIfaceIndex: 3,
			TUNIfaceName:   TUNIfaceName,
			TUNIfaceIndex:  99,
			EnableIPv6:     true,
		}

		if err := mgr.ApplySplitTunnel(ctx, plan); err != nil {
			t.Fatalf("expected graceful skip, got: %v", err)
		}
		if _, ok := mock.installed[netip.MustParsePrefix("::/1")]; ok {
			t.Fatal("expected partial ::/1 route to be cleaned up when 8000::/1 reports IPv6 disabled")
		}
		if _, ok := mock.installed[netip.MustParsePrefix("0.0.0.0/1")]; !ok {
			t.Fatal("expected IPv4 split tunnel to stay active")
		}
	})

	t.Run("validation_rejects_missing_peer_gateway_or_interface", func(t *testing.T) {
		mock := newMockRouteAndDNS()
		mgr := NewManagerWithDeps(mock, mock, nil)

		invalidPlans := []RoutePlan{
			{OrigGateway: netip.MustParseAddr("192.168.1.1"), OrigIfaceName: "eth0"},
			{VPSPeerIP: netip.MustParseAddr("203.0.113.10"), OrigIfaceName: "eth0"},
			{VPSPeerIP: netip.MustParseAddr("203.0.113.10"), OrigGateway: netip.MustParseAddr("192.168.1.1")},
			{VPSPeerIP: netip.MustParseAddr("2001:db8::1"), OrigGateway: netip.MustParseAddr("192.168.1.1"), OrigIfaceName: "eth0"},
		}
		for i, p := range invalidPlans {
			if err := mgr.ApplySplitTunnel(ctx, p); err == nil {
				t.Fatalf("case %d: expected validation error", i)
			}
		}
	})
}

func TestNetworkSnapshotJSONParityAndFreshManagerCrashRestore(t *testing.T) {
	rawJSON := `{
		"vps_peer_ip": "203.0.113.10",
		"orig_gateway": "192.168.1.1",
		"orig_iface_name": "wlan0",
		"orig_iface_index": 3,
		"orig_dns_servers": ["8.8.8.8", "192.168.1.1"],
		"win_adapter_dns_backups": [{"iface_index": 3, "iface_name": "Wi-Fi", "ipv4_dns": ["192.168.1.1"], "ipv6_dns": ["fe80::1"]}],
		"linux_dns_backups": [{"ifindex": 3, "ifname": "wlan0", "dns_servers": ["192.168.1.1"], "default_route": true}],
		"dns_strategy": "systemd-resolved",
		"resolv_conf_backup": "",
		"tun_iface_name": "tunssh0",
		"installed_routes": ["203.0.113.10/32", "0.0.0.0/1", "128.0.0.0/1"]
	}`

	var snap NetworkSnapshot
	if err := json.Unmarshal([]byte(rawJSON), &snap); err != nil {
		t.Fatalf("unmarshal crash snapshot failed: %v", err)
	}
	if snap.VPSPeerIP != "203.0.113.10" || snap.OrigIfaceName != "wlan0" || snap.DNSStrategy != "systemd-resolved" {
		t.Fatalf("unexpected decoded snapshot: %+v", snap)
	}

	// Simulate fresh Manager in new process after crash with pre-existing routes + DNS.
	mock := newMockRouteAndDNS()
	mock.installed[netip.MustParsePrefix("203.0.113.10/32")] = RouteSpec{Dst: netip.MustParsePrefix("203.0.113.10/32")}
	mock.installed[netip.MustParsePrefix("8.8.8.8/32")] = RouteSpec{Dst: netip.MustParsePrefix("8.8.8.8/32")}
	mock.installed[netip.MustParsePrefix("192.168.0.0/16")] = RouteSpec{Dst: netip.MustParsePrefix("192.168.0.0/16")}
	mock.installed[netip.MustParsePrefix("0.0.0.0/1")] = RouteSpec{Dst: netip.MustParsePrefix("0.0.0.0/1")}
	mock.installed[netip.MustParsePrefix("128.0.0.0/1")] = RouteSpec{Dst: netip.MustParsePrefix("128.0.0.0/1")}
	mock.dnsApplied = true

	freshMgr := NewManagerWithDeps(mock, mock, nil)
	if err := freshMgr.RestoreNetwork(context.Background(), snap); err != nil {
		t.Fatalf("fresh crash RestoreNetwork failed: %v", err)
	}

	if _, ok := mock.installed[netip.MustParsePrefix("8.8.8.8/32")]; ok {
		t.Fatal("expected public OrigDNS 8.8.8.8/32 to be removed even when InstalledRoutes was minimal")
	}
	if _, ok := mock.installed[netip.MustParsePrefix("192.168.0.0/16")]; ok {
		t.Fatal("expected RFC1918 route to be removed even when InstalledRoutes was minimal")
	}
	if len(mock.installed) != 0 || mock.dnsApplied {
		t.Fatalf("expected completely clean state after crash recovery, remaining routes=%v dnsApplied=%v", mock.installed, mock.dnsApplied)
	}

	del0 := mock.findCallIndex("del_route", "0.0.0.0/1")
	del128 := mock.findCallIndex("del_route", "128.0.0.0/1")
	restoreDNS := mock.findCallIndex("restore_dns", "")
	delDNS := mock.findCallIndex("del_route", "8.8.8.8/32")
	delVPS := mock.findCallIndex("del_route", "203.0.113.10/32")
	if !(del0 < restoreDNS && del128 < restoreDNS && restoreDNS < delDNS && delDNS < delVPS) || delVPS != len(mock.calls)-1 {
		t.Fatalf("unexpected crash-restore ordering: 0/1=%d 128/1=%d dns=%d dnsPin=%d vps=%d total=%d",
			del0, del128, restoreDNS, delDNS, delVPS, len(mock.calls))
	}
}

func TestSetBypassIranLANTogglesOnlyIranRoutes(t *testing.T) {
	mock := newMockRouteAndDNS()
	mgr := NewManagerWithDeps(mock, mock, nil)
	snap, err := mgr.CaptureNetworkSnapshot(context.Background())
	if err != nil {
		t.Fatalf("CaptureNetworkSnapshot: %v", err)
	}

	plan := RoutePlan{
		VPSPeerIP:      netip.MustParseAddr("203.0.113.10"),
		OrigGateway:    netip.MustParseAddr("192.168.1.1"),
		OrigIfaceName:  "wlan0",
		OrigIfaceIndex: 3,
		TUNIfaceName:   TUNIfaceName,
		TUNIfaceIndex:  9,
		BypassIranLAN:  false,
		EnableIPv6:     false,
	}
	if err := mgr.ApplySplitTunnel(context.Background(), plan); err != nil {
		t.Fatalf("ApplySplitTunnel: %v", err)
	}
	for _, p := range IranBypassCIDRs {
		if _, ok := mock.installed[p]; ok {
			t.Fatalf("expected Iran CIDR %s absent when BypassIranLAN=false", p)
		}
	}

	if err := mgr.SetBypassIranLAN(context.Background(), snap, true); err != nil {
		t.Fatalf("SetBypassIranLAN(true): %v", err)
	}
	for _, p := range IranBypassCIDRs {
		if _, ok := mock.installed[p]; !ok {
			t.Fatalf("expected Iran CIDR %s installed after SetBypassIranLAN(true)", p)
		}
	}
	if _, ok := mock.installed[netip.MustParsePrefix("0.0.0.0/1")]; !ok {
		t.Fatal("expected split default route 0.0.0.0/1 preserved")
	}

	if err := mgr.SetBypassIranLAN(context.Background(), snap, false); err != nil {
		t.Fatalf("SetBypassIranLAN(false): %v", err)
	}
	for _, p := range IranBypassCIDRs {
		if _, ok := mock.installed[p]; ok {
			t.Fatalf("expected Iran CIDR %s removed after SetBypassIranLAN(false)", p)
		}
	}
	if _, ok := mock.installed[netip.MustParsePrefix("192.168.0.0/16")]; !ok {
		t.Fatal("expected RFC1918 route preserved after disabling Iran bypass")
	}
}

func TestIsTUNStateActiveChecksDNSFallback(t *testing.T) {
	ctx := context.Background()

	// Interface/routes gone after reboot, but DNS still dirty -> must return active=true!
	mock := newMockRouteAndDNS()
	mock.tunActive = false
	mock.dnsActive = true
	mgr := NewManagerWithDeps(mock, mock, nil)

	active, err := mgr.IsTUNStateActive(ctx)
	if err != nil || !active {
		t.Fatalf("IsTUNStateActive = (%v, %v), want (true, nil) when DNS is still dirty", active, err)
	}

	// Both inactive -> clean false.
	mock.dnsActive = false
	active, err = mgr.IsTUNStateActive(ctx)
	if err != nil || active {
		t.Fatalf("IsTUNStateActive = (%v, %v), want (false, nil) when routes and DNS are clean", active, err)
	}

	// RouteOps errored, but DNS check confirms dirty -> still report active=true.
	mock.tunActiveErr = errors.New("route lookup failed")
	mock.dnsActive = true
	active, err = mgr.IsTUNStateActive(ctx)
	if err != nil || !active {
		t.Fatalf("IsTUNStateActive = (%v, %v), want (true, nil) when DNS is active despite route error", active, err)
	}
}
