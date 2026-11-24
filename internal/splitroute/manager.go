package splitroute

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
)

const defaultRouteMetric = 5

// ErrIPv6Disabled indicates the host operating system has IPv6 disabled, so IPv6 split
// routes should be skipped cleanly while keeping IPv4 split tunneling active.
var ErrIPv6Disabled = errors.New("splitroute: IPv6 disabled on host OS")

var (
	tunIPv4AddrParsed = netip.MustParseAddr(TUNIPv4Addr)
	tunIPv6AddrParsed = netip.MustParseAddr(tunIPv6Addr)
	tunDNSAddrParsed  = netip.MustParseAddr(TUNDNSServer)

	ipv4SplitPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	ipv6SplitPrefixes = []netip.Prefix{
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
)

// WinAdapterDNSBackup stores pre-tunnel DNS settings for a Windows network adapter
// (JSON-compatible with recovery.WinAdapterDNSBackup).
type WinAdapterDNSBackup struct {
	IfaceIndex int      `json:"iface_index"`
	IfaceName  string   `json:"iface_name"`
	IPv4DNS    []string `json:"ipv4_dns,omitempty"`
	IPv6DNS    []string `json:"ipv6_dns,omitempty"`
}

// LinuxDNSBackup stores pre-tunnel systemd-resolved link settings for a Linux interface
// (JSON-compatible with recovery.LinuxDNSBackup).
type LinuxDNSBackup struct {
	IfIndex      int      `json:"ifindex"`
	IfName       string   `json:"ifname"`
	DNSServers   []string `json:"dns_servers,omitempty"`
	DefaultRoute bool     `json:"default_route"`
}

// NetworkSnapshot captures pre-tunnel OS route and DNS state for crash-safe restoration
// (JSON-compatible with recovery.TUNSnapshot).
type NetworkSnapshot struct {
	VPSPeerIP            string                `json:"vps_peer_ip"`
	OrigGateway          string                `json:"orig_gateway"`
	OrigGateway6         string                `json:"orig_gateway6,omitempty"`
	OrigIfaceName        string                `json:"orig_iface_name"`
	OrigIfaceIndex       int                   `json:"orig_iface_index"`
	OrigDNSServers       []string              `json:"orig_dns_servers,omitempty"`
	WinAdapterDNSBackups []WinAdapterDNSBackup `json:"win_adapter_dns_backups,omitempty"`
	LinuxDNSBackups      []LinuxDNSBackup      `json:"linux_dns_backups,omitempty"`
	DNSStrategy          string                `json:"dns_strategy"`
	ResolvConfBackup     string                `json:"resolv_conf_backup"`
	TUNIfaceName         string                `json:"tun_iface_name"`
	InstalledRoutes      []string              `json:"installed_routes,omitempty"`
}

// RoutePlan specifies the resolved peer, pre-tunnel gateway/interface, and policy options
// used to program split-tunnel routing.
type RoutePlan struct {
	VPSPeerIP      netip.Addr
	OrigGateway    netip.Addr
	OrigGateway6   netip.Addr
	OrigIfaceName  string
	OrigIfaceIndex int
	OrigDNSServers []netip.Addr
	TUNIfaceName   string
	TUNIfaceIndex  int
	BypassIranLAN  bool
	EnableIPv6     bool
}

// RouteSpec describes a single OS routing table entry to add or remove.
type RouteSpec struct {
	Dst        netip.Prefix
	Gateway    netip.Addr
	IfaceName  string
	IfaceIndex int
	Metric     int
}

// RouteOps abstracts OS-level routing table inspection and mutation for unit testing.
type RouteOps interface {
	CaptureDefaultRoute(ctx context.Context) (gw4 netip.Addr, gw6 netip.Addr, ifaceName string, ifaceIndex int, err error)
	AddRoute(ctx context.Context, r RouteSpec) error
	DeleteRoute(ctx context.Context, r RouteSpec) error
	IsTUNRouteOrIfaceActive(ctx context.Context, tunIface string) (bool, error)
}

// DNSConfigurator abstracts OS-level DNS backup, TUN DNS activation, and restoration.
type DNSConfigurator interface {
	CaptureDNS(ctx context.Context, origIfaceName string, origIfaceIndex int) (strategy string, origDNS []netip.Addr, winBackups []WinAdapterDNSBackup, linuxBackups []LinuxDNSBackup, resolvBackup string, err error)
	ApplyTUNDNS(ctx context.Context, snap NetworkSnapshot, tunDNS netip.Addr) error
	RestoreDNS(ctx context.Context, snap NetworkSnapshot) error
}

type tunDNSActivityChecker interface {
	IsTUNDNSActive(ctx context.Context, tunIface string) (bool, error)
}

// RouteManager manages split-tunnel routes and OS DNS in strict ordering (Milestone 2).
type RouteManager interface {
	CaptureNetworkSnapshot(ctx context.Context) (NetworkSnapshot, error)
	ApplySplitTunnel(ctx context.Context, plan RoutePlan) error
	SetBypassIranLAN(ctx context.Context, snap NetworkSnapshot, enable bool) error
	RestoreNetwork(ctx context.Context, snap NetworkSnapshot) error
	IsTUNStateActive(ctx context.Context) (bool, error)
}

// Manager implements RouteManager using pluggable RouteOps and DNSConfigurator backends.
type Manager struct {
	ops RouteOps
	dns DNSConfigurator
	log *slog.Logger

	mu          sync.Mutex
	lastSnap    *NetworkSnapshot
	lastApplied []RouteSpec
}

var _ RouteManager = (*Manager)(nil)

// NewManagerWithDeps constructs a Manager with explicit RouteOps, DNSConfigurator, and logger.
func NewManagerWithDeps(ops RouteOps, dns DNSConfigurator, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		ops: ops,
		dns: dns,
		log: logger,
	}
}

// CaptureNetworkSnapshot captures the current default route and OS DNS configuration prior to mutation.
func (m *Manager) CaptureNetworkSnapshot(ctx context.Context) (NetworkSnapshot, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return NetworkSnapshot{}, err
	}
	if err := m.requireDeps(); err != nil {
		return NetworkSnapshot{}, err
	}

	gw4, gw6, ifaceName, ifaceIndex, err := m.ops.CaptureDefaultRoute(ctx)
	if err != nil {
		return NetworkSnapshot{}, fmt.Errorf("splitroute: capture default route: %w", err)
	}

	strategy, origDNS, winBackups, linuxBackups, resolvBackup, err := m.dns.CaptureDNS(ctx, ifaceName, ifaceIndex)
	if err != nil {
		return NetworkSnapshot{}, fmt.Errorf("splitroute: capture DNS: %w", err)
	}

	snap := NetworkSnapshot{
		OrigIfaceName:        ifaceName,
		OrigIfaceIndex:       ifaceIndex,
		OrigDNSServers:       addrsToStrings(origDNS),
		WinAdapterDNSBackups: slices.Clone(winBackups),
		LinuxDNSBackups:      slices.Clone(linuxBackups),
		DNSStrategy:          strategy,
		ResolvConfBackup:     resolvBackup,
		TUNIfaceName:         TUNIfaceName,
	}
	if gw4.IsValid() {
		snap.OrigGateway = gw4.Unmap().String()
	}
	if gw6.IsValid() {
		snap.OrigGateway6 = gw6.String()
	}

	snapCopy := cloneSnapshot(snap)
	m.mu.Lock()
	m.lastSnap = &snapCopy
	m.mu.Unlock()

	return snap, nil
}

// ApplySplitTunnel installs host-pinned, bypass, and split default routes plus OS DNS in strict order,
// automatically rolling back already-applied changes in reverse order if any step fails.
func (m *Manager) ApplySplitTunnel(ctx context.Context, plan RoutePlan) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.requireDeps(); err != nil {
		return err
	}

	m.mu.Lock()
	var baseSnap NetworkSnapshot
	if m.lastSnap != nil {
		baseSnap = cloneSnapshot(*m.lastSnap)
	}
	m.mu.Unlock()

	return m.applyWithSnapshot(ctx, plan, baseSnap)
}

// ApplySplitTunnelWithSnapshot applies split-tunnel routes and OS DNS using an explicit pre-captured snapshot.
func (m *Manager) ApplySplitTunnelWithSnapshot(ctx context.Context, plan RoutePlan, snap NetworkSnapshot) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.requireDeps(); err != nil {
		return err
	}
	return m.applyWithSnapshot(ctx, plan, cloneSnapshot(snap))
}

type validatedPlan struct {
	vpsIP      netip.Addr
	origGW4    netip.Addr
	origGW6    netip.Addr
	origIface  string
	origIdx    int
	tunIface   string
	tunIdx     int
	origDNS    []netip.Addr
	bypassIran bool
	enableIPv6 bool
}

func validatePlan(plan RoutePlan) (validatedPlan, error) {
	if !plan.VPSPeerIP.IsValid() {
		return validatedPlan{}, errors.New("splitroute: VPSPeerIP must be valid")
	}
	vpsIP := plan.VPSPeerIP.Unmap()
	if vpsIP.IsUnspecified() || vpsIP.IsLoopback() || vpsIP.IsMulticast() {
		return validatedPlan{}, fmt.Errorf("splitroute: invalid VPSPeerIP %q", plan.VPSPeerIP)
	}

	var origGW4 netip.Addr
	if plan.OrigGateway.IsValid() {
		origGW4 = plan.OrigGateway.Unmap()
		if !origGW4.Is4() || origGW4.IsUnspecified() {
			return validatedPlan{}, fmt.Errorf("splitroute: invalid IPv4 OrigGateway %q", plan.OrigGateway)
		}
	}

	var origGW6 netip.Addr
	if plan.OrigGateway6.IsValid() {
		origGW6 = plan.OrigGateway6
		if !origGW6.Is6() || origGW6.IsUnspecified() {
			return validatedPlan{}, fmt.Errorf("splitroute: invalid IPv6 OrigGateway6 %q", plan.OrigGateway6)
		}
	}

	origIface := strings.TrimSpace(plan.OrigIfaceName)
	if origIface == "" && plan.OrigIfaceIndex <= 0 {
		return validatedPlan{}, errors.New("splitroute: OrigIfaceName or OrigIfaceIndex is required")
	}

	if vpsIP.Is4() && !origGW4.IsValid() {
		return validatedPlan{}, errors.New("splitroute: OrigGateway is required for IPv4 VPSPeerIP")
	}
	if vpsIP.Is6() && !origGW6.IsValid() {
		return validatedPlan{}, errors.New("splitroute: OrigGateway6 is required for IPv6 VPSPeerIP")
	}

	tunIface := strings.TrimSpace(plan.TUNIfaceName)
	if tunIface == "" {
		tunIface = TUNIfaceName
	}

	return validatedPlan{
		vpsIP:      vpsIP,
		origGW4:    origGW4,
		origGW6:    origGW6,
		origIface:  origIface,
		origIdx:    plan.OrigIfaceIndex,
		tunIface:   tunIface,
		tunIdx:     plan.TUNIfaceIndex,
		origDNS:    dedupValidAddrs(plan.OrigDNSServers),
		bypassIran: plan.BypassIranLAN,
		enableIPv6: plan.EnableIPv6,
	}, nil
}

func (m *Manager) applyWithSnapshot(ctx context.Context, plan RoutePlan, baseSnap NetworkSnapshot) error {
	vp, err := validatePlan(plan)
	if err != nil {
		return err
	}

	applied := make([]RouteSpec, 0, 12+len(IranBypassCIDRs))
	addStep := func(spec RouteSpec) error {
		if err := m.ops.AddRoute(ctx, spec); err != nil {
			return err
		}
		applied = append(applied, spec)
		return nil
	}

	// 1. Pin <VPSPeerIP>/32 (or /128) via <OrigGateway> (or <OrigGateway6>) STRICTLY FIRST.
	vpsSpec := vp.vpsRouteSpec()
	if err := addStep(vpsSpec); err != nil {
		return m.rollbackApplyError(ctx, fmt.Errorf("splitroute: pin VPS peer route %s: %w", vpsSpec.Dst, err), applied, baseSnap, false)
	}

	// 2. Pin any non-loopback OrigDNSServers not covered by IsBypassIP(..., BypassIranLAN).
	for _, spec := range vp.dnsPinSpecs() {
		if err := addStep(spec); err != nil {
			return m.rollbackApplyError(ctx, fmt.Errorf("splitroute: pin DNS route %s: %w", spec.Dst, err), applied, baseSnap, false)
		}
	}

	// 3. Install RFC1918 and local bypass CIDRs via OrigGateway.
	for _, spec := range vp.rfc1918Specs() {
		if err := addStep(spec); err != nil {
			return m.rollbackApplyError(ctx, fmt.Errorf("splitroute: install RFC1918 bypass route %s: %w", spec.Dst, err), applied, baseSnap, false)
		}
	}

	// 4. When BypassIranLAN is enabled, install IranBypassCIDRs via OrigGateway.
	if vp.bypassIran {
		for _, spec := range vp.iranSpecs() {
			if err := addStep(spec); err != nil {
				return m.rollbackApplyError(ctx, fmt.Errorf("splitroute: install Iran bypass route %s: %w", spec.Dst, err), applied, baseSnap, false)
			}
		}
	}

	// 5. Install 0.0.0.0/1 and 128.0.0.0/1 via TUNIface.
	for _, spec := range vp.tunV4Specs() {
		if err := addStep(spec); err != nil {
			return m.rollbackApplyError(ctx, fmt.Errorf("splitroute: install TUN IPv4 split route %s: %w", spec.Dst, err), applied, baseSnap, false)
		}
	}

	// 6. When EnableIPv6 is enabled, install ::/1 and 8000::/1 via TUNIface (skip if host disables IPv6).
	if vp.enableIPv6 {
		if err := m.applyIPv6SplitRoutes(ctx, vp, &applied); err != nil {
			return m.rollbackApplyError(ctx, err, applied, baseSnap, false)
		}
	}

	// 7. Apply OS DNS (198.18.0.2). Capture DNS first if no snapshot backup was captured yet.
	if baseSnap.DNSStrategy == "" {
		strategy, origDNS, winBackups, linuxBackups, resolvBackup, capErr := m.dns.CaptureDNS(ctx, vp.origIface, vp.origIdx)
		if capErr != nil {
			return m.rollbackApplyError(ctx, fmt.Errorf("splitroute: capture DNS before apply: %w", capErr), applied, baseSnap, false)
		}
		baseSnap.DNSStrategy = strategy
		baseSnap.WinAdapterDNSBackups = winBackups
		baseSnap.LinuxDNSBackups = linuxBackups
		baseSnap.ResolvConfBackup = resolvBackup
		if len(baseSnap.OrigDNSServers) == 0 {
			baseSnap.OrigDNSServers = addrsToStrings(origDNS)
		}
	}

	baseSnap = populateSnapshotFromPlan(baseSnap, vp, applied)
	if err := m.dns.ApplyTUNDNS(ctx, baseSnap, tunDNSAddrParsed); err != nil {
		return m.rollbackApplyError(ctx, fmt.Errorf("splitroute: apply TUN DNS: %w", err), applied, baseSnap, true)
	}

	snapCopy := cloneSnapshot(baseSnap)
	appliedCopy := slices.Clone(applied)
	m.mu.Lock()
	m.lastSnap = &snapCopy
	m.lastApplied = appliedCopy
	m.mu.Unlock()

	return nil
}

func (m *Manager) applyIPv6SplitRoutes(ctx context.Context, vp validatedPlan, applied *[]RouteSpec) error {
	var addedV6 []RouteSpec
	for _, spec := range vp.tunV6Specs() {
		err := m.ops.AddRoute(ctx, spec)
		if err == nil {
			*applied = append(*applied, spec)
			addedV6 = append(addedV6, spec)
			continue
		}
		if errors.Is(err, ErrIPv6Disabled) {
			m.log.Warn("host OS has IPv6 disabled; skipping IPv6 leak-prevention split routes", "error", err)
			for i := len(addedV6) - 1; i >= 0; i-- {
				_ = m.ops.DeleteRoute(context.WithoutCancel(ctx), addedV6[i])
				if len(*applied) > 0 && (*applied)[len(*applied)-1].Dst == addedV6[i].Dst {
					*applied = (*applied)[:len(*applied)-1]
				}
			}
			return nil
		}
		return fmt.Errorf("splitroute: install TUN IPv6 split route %s: %w", spec.Dst, err)
	}
	return nil
}

func (m *Manager) rollbackApplyError(ctx context.Context, applyErr error, applied []RouteSpec, snap NetworkSnapshot, restoreDNS bool) error {
	rollbackCtx := context.WithoutCancel(ctx)
	var rbErrs []error

	splitIdx := len(applied)
	if restoreDNS {
		// Delete TUN split default routes first (reverse order) before restoring OS DNS.
		for splitIdx > 0 && isSplitDefaultPrefix(applied[splitIdx-1].Dst) {
			splitIdx--
			if err := m.ops.DeleteRoute(rollbackCtx, applied[splitIdx]); err != nil {
				rbErrs = append(rbErrs, fmt.Errorf("delete split route %s: %w", applied[splitIdx].Dst, err))
			}
		}
		if err := m.dns.RestoreDNS(rollbackCtx, snap); err != nil {
			rbErrs = append(rbErrs, fmt.Errorf("restore DNS: %w", err))
		}
	}

	for i := splitIdx - 1; i >= 0; i-- {
		if err := m.ops.DeleteRoute(rollbackCtx, applied[i]); err != nil {
			rbErrs = append(rbErrs, fmt.Errorf("delete route %s: %w", applied[i].Dst, err))
		}
	}

	if len(rbErrs) > 0 {
		return fmt.Errorf("%w (rollback errors: %w)", applyErr, errors.Join(rbErrs...))
	}
	return applyErr
}

// RestoreNetwork restores split default routes, OS DNS, bypass/pinned DNS routes, and finally
// the VPS peer host route in strict reverse order. It is safe and idempotent across retries.
func (m *Manager) RestoreNetwork(ctx context.Context, snap NetworkSnapshot) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.requireDeps(); err != nil {
		return err
	}

	m.mu.Lock()
	var prevSnap *NetworkSnapshot
	if m.lastSnap != nil {
		c := cloneSnapshot(*m.lastSnap)
		prevSnap = &c
	}
	prevApplied := slices.Clone(m.lastApplied)
	m.mu.Unlock()

	effSnap := mergeSnapshots(snap, prevSnap)
	tunIface := strings.TrimSpace(effSnap.TUNIfaceName)
	if tunIface == "" {
		tunIface = TUNIfaceName
	}
	origIface := strings.TrimSpace(effSnap.OrigIfaceName)
	origIdx := effSnap.OrigIfaceIndex
	origGW4, _ := parseOptionalAddr(effSnap.OrigGateway)
	origGW6, _ := parseOptionalAddr(effSnap.OrigGateway6)
	vpsIP, _ := parseOptionalAddr(effSnap.VPSPeerIP)

	var tunIdx int
	for _, spec := range prevApplied {
		if isSplitDefaultPrefix(spec.Dst) && spec.IfaceIndex > 0 {
			tunIdx = spec.IfaceIndex
			break
		}
	}

	var errs []error

	// 1. Delete ::/1, 8000::/1, 0.0.0.0/1, 128.0.0.0/1 FIRST.
	splitRoutes := []RouteSpec{
		{Dst: ipv6SplitPrefixes[1], Gateway: tunIPv6AddrParsed, IfaceName: tunIface, IfaceIndex: tunIdx, Metric: defaultRouteMetric},
		{Dst: ipv6SplitPrefixes[0], Gateway: tunIPv6AddrParsed, IfaceName: tunIface, IfaceIndex: tunIdx, Metric: defaultRouteMetric},
		{Dst: ipv4SplitPrefixes[1], Gateway: tunIPv4AddrParsed, IfaceName: tunIface, IfaceIndex: tunIdx, Metric: defaultRouteMetric},
		{Dst: ipv4SplitPrefixes[0], Gateway: tunIPv4AddrParsed, IfaceName: tunIface, IfaceIndex: tunIdx, Metric: defaultRouteMetric},
	}
	for _, spec := range splitRoutes {
		if err := m.ops.DeleteRoute(ctx, spec); err != nil && !errors.Is(err, ErrIPv6Disabled) {
			errs = append(errs, fmt.Errorf("splitroute: delete split route %s: %w", spec.Dst, err))
		}
	}

	// 2. Restore OS DNS SECOND.
	if err := m.dns.RestoreDNS(ctx, effSnap); err != nil {
		errs = append(errs, fmt.Errorf("splitroute: restore DNS: %w", err))
	}

	// 3. Delete bypass CIDRs & pinned public OrigDNS routes THIRD (strictly before VPSPeerIP).
	var vpsPrefix netip.Prefix
	if vpsIP.IsValid() {
		vpsPrefix = netip.PrefixFrom(vpsIP, vpsIP.BitLen())
	}
	middleRoutes := buildMiddleTeardownRoutes(effSnap, prevApplied, origGW4, origGW6, origIface, origIdx, vpsIP, vpsPrefix)
	for _, spec := range middleRoutes {
		if err := m.ops.DeleteRoute(ctx, spec); err != nil {
			errs = append(errs, fmt.Errorf("splitroute: delete bypass/DNS route %s: %w", spec.Dst, err))
		}
	}

	// 4. Delete <VPSPeerIP>/32 (or /128) LAST.
	if vpsPrefix.IsValid() {
		gw := origGW4
		if vpsIP.Is6() {
			gw = origGW6
		}
		vpsSpec := RouteSpec{
			Dst:        vpsPrefix,
			Gateway:    gw,
			IfaceName:  origIface,
			IfaceIndex: origIdx,
			Metric:     defaultRouteMetric,
		}
		if err := m.ops.DeleteRoute(ctx, vpsSpec); err != nil {
			errs = append(errs, fmt.Errorf("splitroute: delete VPS peer route %s: %w", vpsSpec.Dst, err))
		}
	}

	if len(errs) == 0 {
		m.mu.Lock()
		m.lastApplied = nil
		m.mu.Unlock()
		return nil
	}
	return errors.Join(errs...)
}

// IsTUNStateActive checks whether the TUN interface, split routes, or TUN DNS settings are
// currently active on the OS.
func (m *Manager) IsTUNStateActive(ctx context.Context) (bool, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if m == nil || m.ops == nil {
		return false, errors.New("splitroute: RouteOps must not be nil")
	}

	tunIface := TUNIfaceName
	m.mu.Lock()
	if m.lastSnap != nil && strings.TrimSpace(m.lastSnap.TUNIfaceName) != "" {
		tunIface = strings.TrimSpace(m.lastSnap.TUNIfaceName)
	}
	m.mu.Unlock()

	active, opsErr := m.ops.IsTUNRouteOrIfaceActive(ctx, tunIface)
	if opsErr == nil && active {
		return true, nil
	}
	if checker, ok := m.dns.(tunDNSActivityChecker); ok {
		dnsActive, dnsErr := checker.IsTUNDNSActive(ctx, tunIface)
		if dnsErr == nil && dnsActive {
			return true, nil
		}
		if opsErr != nil {
			return false, opsErr
		}
		if dnsErr != nil {
			return false, dnsErr
		}
		return false, nil
	}
	return active, opsErr
}

// SetBypassIranLAN dynamically installs or removes Iranian CIDR bypass routes on an active
// split-tunnel session without interrupting split default routes or OS DNS configuration.
func (m *Manager) SetBypassIranLAN(ctx context.Context, snap NetworkSnapshot, enable bool) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.requireDeps(); err != nil {
		return err
	}

	m.mu.Lock()
	var prevSnap *NetworkSnapshot
	if m.lastSnap != nil {
		c := cloneSnapshot(*m.lastSnap)
		prevSnap = &c
	}
	m.mu.Unlock()

	effSnap := mergeSnapshots(snap, prevSnap)
	origGW4, ok := parseOptionalAddr(effSnap.OrigGateway)
	if !ok {
		if strings.TrimSpace(effSnap.OrigGateway) != "" {
			return fmt.Errorf("splitroute: invalid orig_gateway %q", effSnap.OrigGateway)
		}
		return nil
	}
	if !origGW4.IsValid() {
		return nil
	}
	origIface := strings.TrimSpace(effSnap.OrigIfaceName)
	origIdx := effSnap.OrigIfaceIndex

	specs := make([]RouteSpec, 0, len(IranBypassCIDRs))
	for _, p := range IranBypassCIDRs {
		specs = append(specs, RouteSpec{
			Dst:        p,
			Gateway:    origGW4,
			IfaceName:  origIface,
			IfaceIndex: origIdx,
			Metric:     defaultRouteMetric,
		})
	}

	if enable {
		var added []RouteSpec
		for _, spec := range specs {
			if err := m.ops.AddRoute(ctx, spec); err != nil {
				rbCtx := context.WithoutCancel(ctx)
				for i := len(added) - 1; i >= 0; i-- {
					_ = m.ops.DeleteRoute(rbCtx, added[i])
				}
				return fmt.Errorf("splitroute: add Iran bypass route %s: %w", spec.Dst, err)
			}
			added = append(added, spec)
		}
	} else {
		for i := len(specs) - 1; i >= 0; i-- {
			if err := m.ops.DeleteRoute(ctx, specs[i]); err != nil {
				return fmt.Errorf("splitroute: delete Iran bypass route %s: %w", specs[i].Dst, err)
			}
		}
	}

	iranSet := make(map[netip.Prefix]struct{}, len(IranBypassCIDRs))
	for _, p := range IranBypassCIDRs {
		iranSet[p] = struct{}{}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastApplied != nil {
		filtered := make([]RouteSpec, 0, len(m.lastApplied)+len(specs))
		for _, spec := range m.lastApplied {
			if _, isIran := iranSet[spec.Dst]; !isIran {
				filtered = append(filtered, spec)
			}
		}
		if enable {
			filtered = append(filtered, specs...)
		}
		m.lastApplied = filtered
		if m.lastSnap != nil {
			routes := make([]string, 0, len(filtered))
			for _, spec := range filtered {
				routes = append(routes, spec.Dst.String())
			}
			m.lastSnap.InstalledRoutes = routes
		}
	}
	return nil
}

// BuildInstalledRoutes returns the ordered list of CIDR strings that ApplySplitTunnel installs for plan.
func BuildInstalledRoutes(plan RoutePlan) ([]string, error) {
	vp, err := validatePlan(plan)
	if err != nil {
		return nil, err
	}

	var out []string
	out = append(out, vp.vpsRouteSpec().Dst.String())
	for _, spec := range vp.dnsPinSpecs() {
		out = append(out, spec.Dst.String())
	}
	for _, spec := range vp.rfc1918Specs() {
		out = append(out, spec.Dst.String())
	}
	if vp.bypassIran {
		for _, spec := range vp.iranSpecs() {
			out = append(out, spec.Dst.String())
		}
	}
	for _, spec := range vp.tunV4Specs() {
		out = append(out, spec.Dst.String())
	}
	if vp.enableIPv6 {
		for _, spec := range vp.tunV6Specs() {
			out = append(out, spec.Dst.String())
		}
	}
	return out, nil
}

// ResolveVPSPeerIP resolves host to a concrete IPv4 address via net.DefaultResolver
// (falling back to IPv6 when host is an IPv6 literal or IPv4 resolution yields no address).
func ResolveVPSPeerIP(ctx context.Context, host string) (netip.Addr, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}

	trimmed := strings.TrimSpace(host)
	trimmed = strings.TrimPrefix(trimmed, "[")
	trimmed = strings.TrimSuffix(trimmed, "]")
	if trimmed == "" {
		return netip.Addr{}, errors.New("splitroute: host must not be empty")
	}

	if addr, err := netip.ParseAddr(trimmed); err == nil {
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
			return netip.Addr{}, fmt.Errorf("splitroute: unsupported VPS peer IP literal %q", host)
		}
		return addr, nil
	}

	ips4, err4 := net.DefaultResolver.LookupNetIP(ctx, "ip4", trimmed)
	if err4 == nil {
		for _, ip := range ips4 {
			u := ip.Unmap()
			if u.IsValid() && u.Is4() && !u.IsUnspecified() && !u.IsMulticast() {
				return u, nil
			}
		}
	}

	ips6, err6 := net.DefaultResolver.LookupNetIP(ctx, "ip6", trimmed)
	if err6 == nil {
		for _, ip := range ips6 {
			if ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() {
				return ip, nil
			}
		}
	}

	if err4 != nil && err6 != nil {
		return netip.Addr{}, fmt.Errorf("splitroute: resolve %q: ipv4=%v; ipv6=%w", host, err4, err6)
	}
	if err4 != nil {
		return netip.Addr{}, fmt.Errorf("splitroute: resolve %q: %w", host, err4)
	}
	if err6 != nil {
		return netip.Addr{}, fmt.Errorf("splitroute: resolve %q: %w", host, err6)
	}
	return netip.Addr{}, fmt.Errorf("splitroute: resolve %q: no usable IP address returned", host)
}

// BindToInterfaceControl returns a net.Dialer.Control callback that pins outbound sockets
// to the pre-tunnel physical egress interface on Windows and Linux.
func BindToInterfaceControl(ifaceName string, ifaceIndex int, isIPv6 bool) func(network, address string, c syscall.RawConn) error {
	return bindToInterfaceControl(ifaceName, ifaceIndex, isIPv6)
}

func (m *Manager) requireDeps() error {
	if m == nil || m.ops == nil || m.dns == nil {
		return errors.New("splitroute: RouteOps and DNSConfigurator must not be nil")
	}
	return nil
}

func (vp validatedPlan) vpsRouteSpec() RouteSpec {
	gw := vp.origGW4
	if vp.vpsIP.Is6() {
		gw = vp.origGW6
	}
	return RouteSpec{
		Dst:        netip.PrefixFrom(vp.vpsIP, vp.vpsIP.BitLen()),
		Gateway:    gw,
		IfaceName:  vp.origIface,
		IfaceIndex: vp.origIdx,
		Metric:     defaultRouteMetric,
	}
}

func (vp validatedPlan) dnsPinSpecs() []RouteSpec {
	var specs []RouteSpec
	for _, dnsIP := range vp.origDNS {
		if !dnsIP.IsValid() {
			continue
		}
		dnsIP = dnsIP.Unmap()
		if dnsIP.IsUnspecified() || dnsIP.IsLoopback() || dnsIP.IsMulticast() || dnsIP.IsLinkLocalUnicast() {
			continue
		}
		if dnsIP == vp.vpsIP || IsBypassIP(dnsIP, vp.bypassIran) {
			continue
		}
		if dnsIP.Is4() && vp.origGW4.IsValid() {
			specs = append(specs, RouteSpec{
				Dst:        netip.PrefixFrom(dnsIP, 32),
				Gateway:    vp.origGW4,
				IfaceName:  vp.origIface,
				IfaceIndex: vp.origIdx,
				Metric:     defaultRouteMetric,
			})
		} else if dnsIP.Is6() && vp.origGW6.IsValid() {
			specs = append(specs, RouteSpec{
				Dst:        netip.PrefixFrom(dnsIP, 128),
				Gateway:    vp.origGW6,
				IfaceName:  vp.origIface,
				IfaceIndex: vp.origIdx,
				Metric:     defaultRouteMetric,
			})
		}
	}
	return specs
}

func (vp validatedPlan) rfc1918Specs() []RouteSpec {
	if !vp.origGW4.IsValid() {
		return nil
	}
	specs := make([]RouteSpec, 0, len(RFC1918AndLocalBypassCIDRs))
	for _, p := range RFC1918AndLocalBypassCIDRs {
		specs = append(specs, RouteSpec{
			Dst:        p,
			Gateway:    vp.origGW4,
			IfaceName:  vp.origIface,
			IfaceIndex: vp.origIdx,
			Metric:     defaultRouteMetric,
		})
	}
	return specs
}

func (vp validatedPlan) iranSpecs() []RouteSpec {
	if !vp.origGW4.IsValid() {
		return nil
	}
	specs := make([]RouteSpec, 0, len(IranBypassCIDRs))
	for _, p := range IranBypassCIDRs {
		specs = append(specs, RouteSpec{
			Dst:        p,
			Gateway:    vp.origGW4,
			IfaceName:  vp.origIface,
			IfaceIndex: vp.origIdx,
			Metric:     defaultRouteMetric,
		})
	}
	return specs
}

func (vp validatedPlan) tunV4Specs() []RouteSpec {
	return []RouteSpec{
		{
			Dst:        ipv4SplitPrefixes[0],
			Gateway:    tunIPv4AddrParsed,
			IfaceName:  vp.tunIface,
			IfaceIndex: vp.tunIdx,
			Metric:     defaultRouteMetric,
		},
		{
			Dst:        ipv4SplitPrefixes[1],
			Gateway:    tunIPv4AddrParsed,
			IfaceName:  vp.tunIface,
			IfaceIndex: vp.tunIdx,
			Metric:     defaultRouteMetric,
		},
	}
}

func (vp validatedPlan) tunV6Specs() []RouteSpec {
	return []RouteSpec{
		{
			Dst:        ipv6SplitPrefixes[0],
			Gateway:    tunIPv6AddrParsed,
			IfaceName:  vp.tunIface,
			IfaceIndex: vp.tunIdx,
			Metric:     defaultRouteMetric,
		},
		{
			Dst:        ipv6SplitPrefixes[1],
			Gateway:    tunIPv6AddrParsed,
			IfaceName:  vp.tunIface,
			IfaceIndex: vp.tunIdx,
			Metric:     defaultRouteMetric,
		},
	}
}

func buildMiddleTeardownRoutes(
	snap NetworkSnapshot,
	prevApplied []RouteSpec,
	origGW4, origGW6 netip.Addr,
	origIface string,
	origIdx int,
	vpsIP netip.Addr,
	vpsPrefix netip.Prefix,
) []RouteSpec {
	seen := make(map[netip.Prefix]struct{})
	var out []RouteSpec

	addUnique := func(spec RouteSpec) {
		if !spec.Dst.IsValid() || isSplitDefaultPrefix(spec.Dst) {
			return
		}
		if vpsPrefix.IsValid() && spec.Dst == vpsPrefix {
			return
		}
		if _, ok := seen[spec.Dst]; ok {
			return
		}
		seen[spec.Dst] = struct{}{}
		out = append(out, spec)
	}

	// First prefer exact routes recorded by this Manager in reverse order.
	for i := len(prevApplied) - 1; i >= 0; i-- {
		addUnique(prevApplied[i])
	}

	// Next process snap.InstalledRoutes in reverse order (for crash recovery).
	for i := len(snap.InstalledRoutes) - 1; i >= 0; i-- {
		p, err := netip.ParsePrefix(strings.TrimSpace(snap.InstalledRoutes[i]))
		if err != nil || !p.IsValid() {
			continue
		}
		p = p.Masked()
		gw := origGW4
		if p.Addr().Is6() {
			gw = origGW6
		}
		addUnique(RouteSpec{
			Dst:        p,
			Gateway:    gw,
			IfaceName:  origIface,
			IfaceIndex: origIdx,
			Metric:     defaultRouteMetric,
		})
	}

	// Ensure RFC1918/local bypass routes are cleaned even if InstalledRoutes was minimal/empty.
	if origGW4.IsValid() {
		for i := len(RFC1918AndLocalBypassCIDRs) - 1; i >= 0; i-- {
			addUnique(RouteSpec{
				Dst:        RFC1918AndLocalBypassCIDRs[i],
				Gateway:    origGW4,
				IfaceName:  origIface,
				IfaceIndex: origIdx,
				Metric:     defaultRouteMetric,
			})
		}
	}

	// Ensure any public OrigDNS pins are cleaned even if InstalledRoutes was minimal/empty.
	for _, raw := range snap.OrigDNSServers {
		addr, ok := parseOptionalAddr(raw)
		if !ok || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			continue
		}
		if vpsIP.IsValid() && addr == vpsIP {
			continue
		}
		if IsBypassIP(addr, false) {
			continue
		}
		if addr.Is4() && origGW4.IsValid() {
			addUnique(RouteSpec{
				Dst:        netip.PrefixFrom(addr, 32),
				Gateway:    origGW4,
				IfaceName:  origIface,
				IfaceIndex: origIdx,
				Metric:     defaultRouteMetric,
			})
		} else if addr.Is6() && origGW6.IsValid() {
			addUnique(RouteSpec{
				Dst:        netip.PrefixFrom(addr, 128),
				Gateway:    origGW6,
				IfaceName:  origIface,
				IfaceIndex: origIdx,
				Metric:     defaultRouteMetric,
			})
		}
	}

	return out
}

func populateSnapshotFromPlan(snap NetworkSnapshot, vp validatedPlan, applied []RouteSpec) NetworkSnapshot {
	snap.VPSPeerIP = vp.vpsIP.String()
	if vp.origGW4.IsValid() && snap.OrigGateway == "" {
		snap.OrigGateway = vp.origGW4.String()
	}
	if vp.origGW6.IsValid() && snap.OrigGateway6 == "" {
		snap.OrigGateway6 = vp.origGW6.String()
	}
	if snap.OrigIfaceName == "" {
		snap.OrigIfaceName = vp.origIface
	}
	if snap.OrigIfaceIndex == 0 {
		snap.OrigIfaceIndex = vp.origIdx
	}
	if snap.TUNIfaceName == "" {
		snap.TUNIfaceName = vp.tunIface
	}
	if len(snap.OrigDNSServers) == 0 && len(vp.origDNS) > 0 {
		snap.OrigDNSServers = addrsToStrings(vp.origDNS)
	}
	routes := make([]string, 0, len(applied))
	for _, spec := range applied {
		routes = append(routes, spec.Dst.String())
	}
	snap.InstalledRoutes = routes
	return snap
}

func mergeSnapshots(primary NetworkSnapshot, fallback *NetworkSnapshot) NetworkSnapshot {
	out := cloneSnapshot(primary)
	if fallback == nil {
		return out
	}
	if out.VPSPeerIP == "" {
		out.VPSPeerIP = fallback.VPSPeerIP
	}
	if out.OrigGateway == "" {
		out.OrigGateway = fallback.OrigGateway
	}
	if out.OrigGateway6 == "" {
		out.OrigGateway6 = fallback.OrigGateway6
	}
	if out.OrigIfaceName == "" {
		out.OrigIfaceName = fallback.OrigIfaceName
	}
	if out.OrigIfaceIndex == 0 {
		out.OrigIfaceIndex = fallback.OrigIfaceIndex
	}
	if len(out.OrigDNSServers) == 0 && len(fallback.OrigDNSServers) > 0 {
		out.OrigDNSServers = slices.Clone(fallback.OrigDNSServers)
	}
	if len(out.WinAdapterDNSBackups) == 0 && len(fallback.WinAdapterDNSBackups) > 0 {
		out.WinAdapterDNSBackups = slices.Clone(fallback.WinAdapterDNSBackups)
	}
	if len(out.LinuxDNSBackups) == 0 && len(fallback.LinuxDNSBackups) > 0 {
		out.LinuxDNSBackups = slices.Clone(fallback.LinuxDNSBackups)
	}
	if out.DNSStrategy == "" {
		out.DNSStrategy = fallback.DNSStrategy
	}
	if out.ResolvConfBackup == "" {
		out.ResolvConfBackup = fallback.ResolvConfBackup
	}
	if out.TUNIfaceName == "" {
		out.TUNIfaceName = fallback.TUNIfaceName
	}
	if len(out.InstalledRoutes) == 0 && len(fallback.InstalledRoutes) > 0 {
		out.InstalledRoutes = slices.Clone(fallback.InstalledRoutes)
	}
	return out
}

func cloneSnapshot(s NetworkSnapshot) NetworkSnapshot {
	out := s
	out.OrigDNSServers = slices.Clone(s.OrigDNSServers)
	if s.WinAdapterDNSBackups != nil {
		out.WinAdapterDNSBackups = make([]WinAdapterDNSBackup, len(s.WinAdapterDNSBackups))
		for i, b := range s.WinAdapterDNSBackups {
			out.WinAdapterDNSBackups[i] = WinAdapterDNSBackup{
				IfaceIndex: b.IfaceIndex,
				IfaceName:  b.IfaceName,
				IPv4DNS:    slices.Clone(b.IPv4DNS),
				IPv6DNS:    slices.Clone(b.IPv6DNS),
			}
		}
	}
	if s.LinuxDNSBackups != nil {
		out.LinuxDNSBackups = make([]LinuxDNSBackup, len(s.LinuxDNSBackups))
		for i, b := range s.LinuxDNSBackups {
			out.LinuxDNSBackups[i] = LinuxDNSBackup{
				IfIndex:      b.IfIndex,
				IfName:       b.IfName,
				DNSServers:   slices.Clone(b.DNSServers),
				DefaultRoute: b.DefaultRoute,
			}
		}
	}
	out.InstalledRoutes = slices.Clone(s.InstalledRoutes)
	return out
}

func isSplitDefaultPrefix(p netip.Prefix) bool {
	return p == ipv4SplitPrefixes[0] || p == ipv4SplitPrefixes[1] ||
		p == ipv6SplitPrefixes[0] || p == ipv6SplitPrefixes[1]
}

func isTUNLocalAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	u := addr.Unmap()
	return u == tunIPv4AddrParsed || u == tunIPv6AddrParsed
}

func dedupValidAddrs(addrs []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		u := a.Unmap()
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}

func addrsToStrings(addrs []netip.Addr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.Unmap().String()
	}
	return out
}

func parseOptionalAddr(raw string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || !addr.IsValid() {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
