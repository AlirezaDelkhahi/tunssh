//go:build linux && !android

package splitroute

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	dnsStrategySystemdResolved = "systemd-resolved"
	dnsStrategyResolvConf      = "resolv.conf"

	defaultResolvConfPath     = "/etc/resolv.conf"
	defaultResolvBackupPath   = "/etc/resolv.conf.tunssh.bak"
	defaultResolvedResolvPath = "/run/systemd/resolve/resolv.conf"
	defaultIPv6DisablePath    = "/proc/sys/net/ipv6/conf/all/disable_ipv6"

	resolvConfMode os.FileMode = 0o644
)

// LinuxOptions injects OS command and filesystem hooks for deterministic testing on Linux.
type LinuxOptions struct {
	RunCmd             func(ctx context.Context, name string, args ...string) (string, error)
	LookPath           func(file string) (string, error)
	ReadFile           func(path string) ([]byte, error)
	WriteFileAtomic    func(path string, data []byte, perm os.FileMode) error
	RemoveFile         func(path string) error
	StatFile           func(path string) (os.FileInfo, error)
	ResolvConfPath     string
	ResolvBackupPath   string
	ResolvedResolvPath string
	IPv6DisablePath    string
	Logger             *slog.Logger
}

// NewManager returns the Linux RouteManager backed by netlink and systemd-resolved / /etc/resolv.conf.
func NewManager() RouteManager {
	return NewLinuxManager(LinuxOptions{})
}

// NewLinuxManager constructs a Linux RouteManager using the supplied dependency overrides.
func NewLinuxManager(opts LinuxOptions) RouteManager {
	opts = normalizeLinuxOptions(opts)
	ops := &netlinkRouteOps{
		ipv6DisablePath: opts.IPv6DisablePath,
	}
	dns := newLinuxDNSConfigurator(opts)
	return NewManagerWithDeps(ops, dns, opts.Logger)
}

func normalizeLinuxOptions(opts LinuxOptions) LinuxOptions {
	if opts.RunCmd == nil {
		opts.RunCmd = defaultLinuxRunCmd
	}
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	if opts.ReadFile == nil {
		opts.ReadFile = os.ReadFile
	}
	if opts.WriteFileAtomic == nil {
		opts.WriteFileAtomic = writeFileAtomicLinux
	}
	if opts.RemoveFile == nil {
		opts.RemoveFile = os.Remove
	}
	if opts.StatFile == nil {
		opts.StatFile = os.Stat
	}
	if opts.ResolvConfPath == "" {
		opts.ResolvConfPath = defaultResolvConfPath
	}
	if opts.ResolvBackupPath == "" {
		opts.ResolvBackupPath = defaultResolvBackupPath
	}
	if opts.ResolvedResolvPath == "" {
		opts.ResolvedResolvPath = defaultResolvedResolvPath
	}
	if opts.IPv6DisablePath == "" {
		opts.IPv6DisablePath = defaultIPv6DisablePath
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return opts
}

func defaultLinuxRunCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg != "" {
			return "", fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, errMsg)
		}
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func writeFileAtomicLinux(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tunssh.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, path, err)
	}
	cleanup = false

	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// bindToInterfaceControl binds outbound sockets to ifaceName via SO_BINDTODEVICE when permitted,
// gracefully falling back to a no-op when unprivileged (EPERM/EACCES) because the /32 route protects egress.
func bindToInterfaceControl(ifaceName string, ifaceIndex int, _ bool) func(network, address string, c syscall.RawConn) error {
	resolvedName := strings.TrimSpace(ifaceName)
	if resolvedName == "" && ifaceIndex > 0 {
		if iface, err := net.InterfaceByIndex(ifaceIndex); err == nil {
			resolvedName = iface.Name
		}
	}
	return func(_, _ string, c syscall.RawConn) error {
		if resolvedName == "" || c == nil {
			return nil
		}
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, resolvedName)
		}); err != nil {
			return err
		}
		if errors.Is(sockErr, unix.EPERM) || errors.Is(sockErr, unix.EACCES) {
			return nil
		}
		return sockErr
	}
}

type netlinkRouteOps struct {
	ipv6DisablePath string
}

var _ RouteOps = (*netlinkRouteOps)(nil)

func (o *netlinkRouteOps) CaptureDefaultRoute(ctx context.Context) (netip.Addr, netip.Addr, string, int, error) {
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, netip.Addr{}, "", 0, err
	}

	links, err := netlink.LinkList()
	if err != nil {
		return netip.Addr{}, netip.Addr{}, "", 0, fmt.Errorf("list links: %w", err)
	}
	linkNames := make(map[int]string, len(links))
	skipIdx := make(map[int]bool, len(links))
	for _, l := range links {
		attrs := l.Attrs()
		linkNames[attrs.Index] = attrs.Name
		if attrs.Name == "lo" || attrs.Name == TUNIfaceName || attrs.Flags&net.FlagLoopback != 0 {
			skipIdx[attrs.Index] = true
		}
	}

	v4Routes, err := listDefaultRoutes(netlink.FAMILY_V4)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, "", 0, fmt.Errorf("list IPv4 default routes: %w", err)
	}

	bestV4, okV4 := pickBestDefaultRoute(v4Routes, skipIdx, 0)

	var v6Routes []netlink.Route
	v6Routes, err = listDefaultRoutes(netlink.FAMILY_V6)
	if err != nil && !isLinuxIPv6DisabledErr(err, o.ipv6DisablePath) {
		return netip.Addr{}, netip.Addr{}, "", 0, fmt.Errorf("list IPv6 default routes: %w", err)
	}

	preferredIdx := 0
	if okV4 {
		preferredIdx = bestV4.linkIndex
	}
	bestV6, okV6 := pickBestDefaultRoute(v6Routes, skipIdx, preferredIdx)

	if !okV4 && !okV6 {
		return netip.Addr{}, netip.Addr{}, "", 0, errors.New("no active default route found")
	}

	ifaceIndex := bestV4.linkIndex
	if !okV4 {
		ifaceIndex = bestV6.linkIndex
	}
	ifaceName := linkNames[ifaceIndex]
	if ifaceName == "" {
		if link, err := netlink.LinkByIndex(ifaceIndex); err == nil {
			ifaceName = link.Attrs().Name
		}
	}
	if ifaceName == "" {
		return netip.Addr{}, netip.Addr{}, "", 0, fmt.Errorf("resolve interface name for index %d", ifaceIndex)
	}

	return bestV4.gw, bestV6.gw, ifaceName, ifaceIndex, nil
}

type defaultRouteCandidate struct {
	gw        netip.Addr
	linkIndex int
	priority  int
}

func listDefaultRoutes(family int) ([]netlink.Route, error) {
	filter := &netlink.Route{Table: unix.RT_TABLE_MAIN}
	var lastErr error
	for range 3 {
		routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
		if err == nil {
			return routes, nil
		}
		lastErr = err
		if !errors.Is(err, netlink.ErrDumpInterrupted) {
			return nil, err
		}
	}
	return nil, lastErr
}

func pickBestDefaultRoute(routes []netlink.Route, skipIdx map[int]bool, preferIdx int) (defaultRouteCandidate, bool) {
	var best defaultRouteCandidate
	found := false

	for _, r := range routes {
		if r.Type != 0 && r.Type != unix.RTN_UNICAST {
			continue
		}
		if !isZeroPrefixRoute(r.Dst) {
			continue
		}

		linkIdx := r.LinkIndex
		gwIP := r.Gw
		if len(r.MultiPath) > 0 && (linkIdx == 0 || len(gwIP) == 0) {
			linkIdx = r.MultiPath[0].LinkIndex
			gwIP = r.MultiPath[0].Gw
		}
		if linkIdx <= 0 || skipIdx[linkIdx] {
			continue
		}

		var gw netip.Addr
		if len(gwIP) > 0 {
			parsed, ok := netip.AddrFromSlice(gwIP)
			if !ok {
				continue
			}
			gw = parsed.Unmap()
		}

		cand := defaultRouteCandidate{
			gw:        gw,
			linkIndex: linkIdx,
			priority:  r.Priority,
		}
		if !found || isBetterDefaultCandidate(cand, best, preferIdx) {
			best = cand
			found = true
		}
	}
	return best, found
}

func isBetterDefaultCandidate(cand, cur defaultRouteCandidate, preferIdx int) bool {
	if preferIdx > 0 {
		candPref := cand.linkIndex == preferIdx
		curPref := cur.linkIndex == preferIdx
		if candPref != curPref {
			return candPref
		}
	}
	if cand.priority != cur.priority {
		return cand.priority < cur.priority
	}
	return cand.gw.IsValid() && !cur.gw.IsValid()
}

func isZeroPrefixRoute(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, bits := dst.Mask.Size()
	return ones == 0 && (bits == 32 || bits == 128)
}

func (o *netlinkRouteOps) AddRoute(ctx context.Context, r RouteSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	nlRoute, err := o.toNetlinkRoute(r, false)
	if err != nil {
		return err
	}
	if err := netlink.RouteReplace(nlRoute); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		if r.Dst.Addr().Is6() && isLinuxIPv6DisabledErr(err, o.ipv6DisablePath) {
			return fmt.Errorf("%w: %v", ErrIPv6Disabled, err)
		}
		return err
	}
	return nil
}

func (o *netlinkRouteOps) DeleteRoute(ctx context.Context, r RouteSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	nlRoute, err := o.toNetlinkRoute(r, true)
	if err != nil {
		var lnf netlink.LinkNotFoundError
		if errors.As(err, &lnf) {
			return nil
		}
		return err
	}
	if nlRoute == nil {
		return nil
	}
	err = netlink.RouteDel(nlRoute)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		return nil
	}
	if r.Dst.Addr().Is6() && isLinuxIPv6DisabledErr(err, o.ipv6DisablePath) {
		return nil
	}
	return err
}

func (o *netlinkRouteOps) IsTUNRouteOrIfaceActive(ctx context.Context, tunIface string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if strings.TrimSpace(tunIface) == "" {
		tunIface = TUNIfaceName
	}

	var firstErr error
	link, err := netlink.LinkByName(tunIface)
	if err == nil && link != nil {
		return true, nil
	}
	if err != nil {
		var lnf netlink.LinkNotFoundError
		if !errors.As(err, &lnf) {
			firstErr = err
		}
	}

	v4Routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		if firstErr == nil {
			firstErr = err
		}
	} else {
		for _, r := range v4Routes {
			if ipNetMatchesSplitPrefix(r.Dst) {
				return true, nil
			}
		}
	}

	v6Routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		if !isLinuxIPv6DisabledErr(err, o.ipv6DisablePath) && firstErr == nil {
			firstErr = err
		}
	} else {
		for _, r := range v6Routes {
			if ipNetMatchesSplitPrefix(r.Dst) {
				return true, nil
			}
		}
	}

	return false, firstErr
}

func ipNetMatchesSplitPrefix(dst *net.IPNet) bool {
	if dst == nil || len(dst.IP) == 0 {
		return false
	}
	addr, ok := netip.AddrFromSlice(dst.IP)
	if !ok || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	ones, bits := dst.Mask.Size()
	if (addr.Is4() && bits != 32) || (addr.Is6() && bits != 128) {
		return false
	}
	pfx := netip.PrefixFrom(addr, ones).Masked()
	return isSplitDefaultPrefix(pfx)
}

func (o *netlinkRouteOps) toNetlinkRoute(r RouteSpec, forDelete bool) (*netlink.Route, error) {
	if !r.Dst.IsValid() {
		return nil, errors.New("splitroute: route destination prefix is invalid")
	}

	linkIdx := r.IfaceIndex
	if linkIdx <= 0 && strings.TrimSpace(r.IfaceName) != "" {
		link, err := netlink.LinkByName(strings.TrimSpace(r.IfaceName))
		if err != nil {
			var lnf netlink.LinkNotFoundError
			if forDelete && errors.As(err, &lnf) {
				return nil, nil
			}
			return nil, fmt.Errorf("lookup link %q: %w", r.IfaceName, err)
		}
		linkIdx = link.Attrs().Index
	}

	dst := r.Dst.Masked()
	nlRoute := &netlink.Route{
		LinkIndex: linkIdx,
		Dst:       prefixToIPNet(dst),
		Priority:  r.Metric,
	}

	if r.Gateway.IsValid() && !isTUNLocalAddr(r.Gateway) && strings.TrimSpace(r.IfaceName) != TUNIfaceName {
		gw := r.Gateway.Unmap()
		if gw.Is4() {
			a := gw.As4()
			nlRoute.Gw = net.IP(a[:])
		} else {
			a := gw.As16()
			nlRoute.Gw = net.IP(a[:])
		}
	}

	return nlRoute, nil
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	p = p.Masked()
	addr := p.Addr()
	if addr.Is4() {
		a := addr.As4()
		return &net.IPNet{
			IP:   net.IP(a[:]),
			Mask: net.CIDRMask(p.Bits(), 32),
		}
	}
	a := addr.As16()
	return &net.IPNet{
		IP:   net.IP(a[:]),
		Mask: net.CIDRMask(p.Bits(), 128),
	}
}

func isLinuxIPv6DisabledErr(err error, procPath string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unix.EAFNOSUPPORT) ||
		errors.Is(err, unix.EPROTONOSUPPORT) ||
		errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EADDRNOTAVAIL) {
		return true
	}
	if procPath != "" {
		if data, readErr := os.ReadFile(procPath); readErr == nil {
			if strings.TrimSpace(string(data)) == "1" && (errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EINVAL)) {
				return true
			}
		}
	}
	return false
}

type linuxDNSConfigurator struct {
	runCmd             func(ctx context.Context, name string, args ...string) (string, error)
	lookPath           func(file string) (string, error)
	readFile           func(path string) ([]byte, error)
	writeFileAtomic    func(path string, data []byte, perm os.FileMode) error
	removeFile         func(path string) error
	statFile           func(path string) (os.FileInfo, error)
	resolvConfPath     string
	resolvBackupPath   string
	resolvedResolvPath string
}

var _ DNSConfigurator = (*linuxDNSConfigurator)(nil)

func newLinuxDNSConfigurator(opts LinuxOptions) *linuxDNSConfigurator {
	opts = normalizeLinuxOptions(opts)
	return &linuxDNSConfigurator{
		runCmd:             opts.RunCmd,
		lookPath:           opts.LookPath,
		readFile:           opts.ReadFile,
		writeFileAtomic:    opts.WriteFileAtomic,
		removeFile:         opts.RemoveFile,
		statFile:           opts.StatFile,
		resolvConfPath:     opts.ResolvConfPath,
		resolvBackupPath:   opts.ResolvBackupPath,
		resolvedResolvPath: opts.ResolvedResolvPath,
	}
}

func (d *linuxDNSConfigurator) isSystemdResolvedActive(ctx context.Context) bool {
	if _, err := d.lookPath("resolvectl"); err != nil {
		return false
	}
	if _, err := d.lookPath("systemctl"); err == nil {
		out, err := d.runCmd(ctx, "systemctl", "is-active", "systemd-resolved")
		return err == nil && strings.TrimSpace(out) == "active"
	}
	_, err := d.runCmd(ctx, "resolvectl", "status")
	return err == nil
}

func (d *linuxDNSConfigurator) CaptureDNS(ctx context.Context, origIfaceName string, origIfaceIndex int) (string, []netip.Addr, []WinAdapterDNSBackup, []LinuxDNSBackup, string, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, nil, nil, "", err
	}

	if d.isSystemdResolvedActive(ctx) {
		return d.captureSystemdResolved(ctx, origIfaceName, origIfaceIndex)
	}
	return d.captureResolvConf()
}

func (d *linuxDNSConfigurator) captureSystemdResolved(ctx context.Context, origIfaceName string, origIfaceIndex int) (string, []netip.Addr, []WinAdapterDNSBackup, []LinuxDNSBackup, string, error) {
	dnsOut, err := d.runCmd(ctx, "resolvectl", "dns")
	if err != nil {
		return "", nil, nil, nil, "", fmt.Errorf("query resolvectl dns: %w", err)
	}
	linkDNS := parseResolvectlLinkMap(dnsOut)

	drOut, err := d.runCmd(ctx, "resolvectl", "default-route")
	if err != nil {
		return "", nil, nil, nil, "", fmt.Errorf("query resolvectl default-route: %w", err)
	}
	linkDefaultRoute := parseResolvectlDefaultRouteMap(drOut)

	// Ensure origIfaceName is queried explicitly if missing from global dump.
	if strings.TrimSpace(origIfaceName) != "" && !hasResolvectlLink(linkDNS, origIfaceName, origIfaceIndex) {
		if singleOut, singleErr := d.runCmd(ctx, "resolvectl", "dns", origIfaceName); singleErr == nil {
			for k, v := range parseResolvectlLinkMap(singleOut) {
				linkDNS[k] = v
			}
		}
		if singleDR, drErr := d.runCmd(ctx, "resolvectl", "default-route", origIfaceName); drErr == nil {
			for k, v := range parseResolvectlDefaultRouteMap(singleDR) {
				linkDefaultRoute[k] = v
			}
		}
	}

	var indices []int
	seenIdx := make(map[int]bool)
	for idx := range linkDNS {
		seenIdx[idx] = true
		indices = append(indices, idx)
	}
	for idx := range linkDefaultRoute {
		if !seenIdx[idx] {
			seenIdx[idx] = true
			indices = append(indices, idx)
		}
	}
	slices.Sort(indices)

	backups := make([]LinuxDNSBackup, 0, len(indices))
	var primaryDNS []netip.Addr
	var fallbackDNS []netip.Addr

	for _, idx := range indices {
		entry := linkDNS[idx]
		name := entry.ifName
		if name == "" {
			name = linkDefaultRoute[idx].ifName
		}
		if name == "" || name == "lo" || name == TUNIfaceName {
			continue
		}

		dr := true
		if drEntry, ok := linkDefaultRoute[idx]; ok {
			dr = drEntry.defaultRoute
		}

		nonLoopback := filterUpstreamDNS(entry.servers)
		backups = append(backups, LinuxDNSBackup{
			IfIndex:      idx,
			IfName:       name,
			DNSServers:   addrsToStrings(nonLoopback),
			DefaultRoute: dr,
		})

		if (origIfaceIndex > 0 && idx == origIfaceIndex) || (origIfaceName != "" && name == origIfaceName) {
			primaryDNS = append(primaryDNS, nonLoopback...)
		} else {
			fallbackDNS = append(fallbackDNS, nonLoopback...)
		}
	}

	origDNS := dedupValidAddrs(primaryDNS)
	if len(origDNS) == 0 {
		origDNS = dedupValidAddrs(fallbackDNS)
	}
	if len(origDNS) == 0 {
		if data, err := d.readFile(d.resolvedResolvPath); err == nil {
			origDNS = parseResolvConfNameservers(string(data))
		}
	}
	if len(origDNS) == 0 {
		if data, err := d.readFile(d.resolvConfPath); err == nil {
			origDNS = parseResolvConfNameservers(string(data))
		}
	}

	return dnsStrategySystemdResolved, origDNS, nil, backups, "", nil
}

func (d *linuxDNSConfigurator) captureResolvConf() (string, []netip.Addr, []WinAdapterDNSBackup, []LinuxDNSBackup, string, error) {
	var backupContent string
	data, err := d.readFile(d.resolvConfPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", nil, nil, nil, "", fmt.Errorf("read %s: %w", d.resolvConfPath, err)
	}
	if err == nil {
		backupContent = string(data)
	}

	// If a previous crashed session already replaced /etc/resolv.conf with 198.18.0.2,
	// prefer the preserved .tunssh.bak file if present.
	if isOnlyTUNDNSResolvConf(backupContent) {
		if bakData, bakErr := d.readFile(d.resolvBackupPath); bakErr == nil && len(bakData) > 0 {
			backupContent = string(bakData)
		}
	}

	origDNS := parseResolvConfNameservers(backupContent)
	return dnsStrategyResolvConf, origDNS, nil, nil, backupContent, nil
}

func (d *linuxDNSConfigurator) ApplyTUNDNS(ctx context.Context, snap NetworkSnapshot, tunDNS netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !tunDNS.IsValid() {
		return errors.New("splitroute: invalid TUN DNS address")
	}

	strategy := snap.DNSStrategy
	if strategy == "" {
		if d.isSystemdResolvedActive(ctx) {
			strategy = dnsStrategySystemdResolved
		} else {
			strategy = dnsStrategyResolvConf
		}
	}

	tunIface := strings.TrimSpace(snap.TUNIfaceName)
	if tunIface == "" {
		tunIface = TUNIfaceName
	}

	if strategy == dnsStrategySystemdResolved {
		seen := make(map[string]bool)
		for _, b := range snap.LinuxDNSBackups {
			name := strings.TrimSpace(b.IfName)
			if name == "" || name == "lo" || name == tunIface || seen[name] {
				continue
			}
			seen[name] = true
			if _, err := d.runCmd(ctx, "resolvectl", "default-route", name, "false"); err != nil {
				return fmt.Errorf("disable default-route on %s: %w", name, err)
			}
		}
		if orig := strings.TrimSpace(snap.OrigIfaceName); orig != "" && orig != "lo" && orig != tunIface && !seen[orig] {
			if _, err := d.runCmd(ctx, "resolvectl", "default-route", orig, "false"); err != nil {
				return fmt.Errorf("disable default-route on %s: %w", orig, err)
			}
		}

		if _, err := d.runCmd(ctx, "resolvectl", "dns", tunIface, tunDNS.String()); err != nil {
			return fmt.Errorf("set resolvectl dns on %s: %w", tunIface, err)
		}
		if _, err := d.runCmd(ctx, "resolvectl", "domain", tunIface, "~."); err != nil {
			return fmt.Errorf("set resolvectl domain on %s: %w", tunIface, err)
		}
		if _, err := d.runCmd(ctx, "resolvectl", "default-route", tunIface, "true"); err != nil {
			return fmt.Errorf("set resolvectl default-route on %s: %w", tunIface, err)
		}
		return nil
	}

	// Fallback: atomic /etc/resolv.conf backup + overwrite.
	if _, statErr := d.statFile(d.resolvBackupPath); errors.Is(statErr, os.ErrNotExist) {
		bakContent := snap.ResolvConfBackup
		if bakContent == "" {
			if existing, readErr := d.readFile(d.resolvConfPath); readErr == nil && !isOnlyTUNDNSResolvConf(string(existing)) {
				bakContent = string(existing)
			}
		}
		if bakContent != "" {
			if err := d.writeFileAtomic(d.resolvBackupPath, []byte(bakContent), resolvConfMode); err != nil {
				return fmt.Errorf("write %s: %w", d.resolvBackupPath, err)
			}
		}
	}

	content := fmt.Sprintf("nameserver %s\n", tunDNS.String())
	if err := d.writeFileAtomic(d.resolvConfPath, []byte(content), resolvConfMode); err != nil {
		return fmt.Errorf("write %s: %w", d.resolvConfPath, err)
	}
	return nil
}

func (d *linuxDNSConfigurator) RestoreDNS(ctx context.Context, snap NetworkSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	strategy := snap.DNSStrategy
	if strategy == "" {
		switch {
		case len(snap.LinuxDNSBackups) > 0:
			strategy = dnsStrategySystemdResolved
		case snap.ResolvConfBackup != "":
			strategy = dnsStrategyResolvConf
		default:
			if _, err := d.statFile(d.resolvBackupPath); err == nil {
				strategy = dnsStrategyResolvConf
			} else if d.isSystemdResolvedActive(ctx) {
				strategy = dnsStrategySystemdResolved
			} else {
				strategy = dnsStrategyResolvConf
			}
		}
	}

	tunIface := strings.TrimSpace(snap.TUNIfaceName)
	if tunIface == "" {
		tunIface = TUNIfaceName
	}

	if strategy == dnsStrategySystemdResolved {
		var errs []error
		if _, err := d.runCmd(ctx, "resolvectl", "revert", tunIface); err != nil && !isUnknownLinkCmdErr(err) {
			errs = append(errs, fmt.Errorf("revert resolvectl on %s: %w", tunIface, err))
		}
		seen := make(map[string]bool)
		for _, b := range snap.LinuxDNSBackups {
			name := strings.TrimSpace(b.IfName)
			if name == "" || name == "lo" || name == tunIface || seen[name] {
				continue
			}
			seen[name] = true
			val := "false"
			if b.DefaultRoute {
				val = "true"
			}
			if _, err := d.runCmd(ctx, "resolvectl", "default-route", name, val); err != nil && !isUnknownLinkCmdErr(err) {
				errs = append(errs, fmt.Errorf("restore default-route on %s: %w", name, err))
			}
		}
		if len(snap.LinuxDNSBackups) == 0 {
			if orig := strings.TrimSpace(snap.OrigIfaceName); orig != "" && orig != "lo" && orig != tunIface {
				if _, err := d.runCmd(ctx, "resolvectl", "default-route", orig, "true"); err != nil && !isUnknownLinkCmdErr(err) {
					errs = append(errs, fmt.Errorf("restore default-route on %s: %w", orig, err))
				}
			}
		}
		return errors.Join(errs...)
	}

	// Fallback: restore /etc/resolv.conf from snapshot string or .tunssh.bak.
	restoreContent := snap.ResolvConfBackup
	if restoreContent == "" {
		if bakData, err := d.readFile(d.resolvBackupPath); err == nil {
			restoreContent = string(bakData)
		}
	}

	if restoreContent != "" {
		if err := d.writeFileAtomic(d.resolvConfPath, []byte(restoreContent), resolvConfMode); err != nil {
			return fmt.Errorf("restore %s: %w", d.resolvConfPath, err)
		}
		if err := d.removeFile(d.resolvBackupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", d.resolvBackupPath, err)
		}
		return nil
	}

	// No backup content left: check if /etc/resolv.conf still contains only TUN DNS.
	cur, err := d.readFile(d.resolvConfPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s during restore: %w", d.resolvConfPath, err)
	}
	if isOnlyTUNDNSResolvConf(string(cur)) && len(snap.OrigDNSServers) > 0 {
		var buf strings.Builder
		for _, raw := range snap.OrigDNSServers {
			if addr, ok := parseOptionalAddr(raw); ok && !addr.IsLoopback() && addr != tunDNSAddrParsed {
				buf.WriteString("nameserver ")
				buf.WriteString(addr.String())
				buf.WriteByte('\n')
			}
		}
		if buf.Len() > 0 {
			if err := d.writeFileAtomic(d.resolvConfPath, []byte(buf.String()), resolvConfMode); err != nil {
				return fmt.Errorf("write fallback %s: %w", d.resolvConfPath, err)
			}
		}
	}
	return nil
}

func (d *linuxDNSConfigurator) IsTUNDNSActive(ctx context.Context, tunIface string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if strings.TrimSpace(tunIface) == "" {
		tunIface = TUNIfaceName
	}

	if _, err := d.statFile(d.resolvBackupPath); err == nil {
		return true, nil
	}
	if data, err := d.readFile(d.resolvConfPath); err == nil && isOnlyTUNDNSResolvConf(string(data)) {
		return true, nil
	}

	if d.isSystemdResolvedActive(ctx) {
		if dnsOut, err := d.runCmd(ctx, "resolvectl", "dns"); err == nil {
			for _, entry := range parseResolvectlLinkMap(dnsOut) {
				if strings.EqualFold(strings.TrimSpace(entry.ifName), tunIface) || containsDNSAddrToken(entry.servers, tunDNSAddrParsed) {
					return true, nil
				}
			}
		}
		if drOut, err := d.runCmd(ctx, "resolvectl", "default-route"); err == nil {
			for _, entry := range parseResolvectlDefaultRouteMap(drOut) {
				if strings.EqualFold(strings.TrimSpace(entry.ifName), tunIface) {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

type parsedLinkDNS struct {
	ifName  string
	servers []string
}

type parsedLinkDefaultRoute struct {
	ifName       string
	defaultRoute bool
}

func parseResolvectlLinkMap(output string) map[int]parsedLinkDNS {
	res := make(map[int]parsedLinkDNS)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		idx, ifName, rest, ok := parseResolvectlLinkLine(line)
		if !ok {
			continue
		}
		res[idx] = parsedLinkDNS{
			ifName:  ifName,
			servers: strings.Fields(rest),
		}
	}
	return res
}

func parseResolvectlDefaultRouteMap(output string) map[int]parsedLinkDefaultRoute {
	res := make(map[int]parsedLinkDefaultRoute)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		idx, ifName, rest, ok := parseResolvectlLinkLine(line)
		if !ok {
			continue
		}
		val := strings.ToLower(strings.TrimSpace(rest))
		res[idx] = parsedLinkDefaultRoute{
			ifName:       ifName,
			defaultRoute: val == "yes" || val == "true" || val == "1",
		}
	}
	return res
}

func parseResolvectlLinkLine(line string) (idx int, ifName string, rest string, ok bool) {
	if !strings.HasPrefix(line, "Link ") {
		return 0, "", "", false
	}
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return 0, "", "", false
	}
	header := strings.TrimSpace(line[len("Link "):colon])
	rest = strings.TrimSpace(line[colon+1:])

	openParen := strings.IndexByte(header, '(')
	closeParen := strings.LastIndexByte(header, ')')
	if openParen <= 0 || closeParen <= openParen {
		return 0, "", "", false
	}
	parsedIdx, err := strconv.Atoi(strings.TrimSpace(header[:openParen]))
	if err != nil || parsedIdx <= 0 {
		return 0, "", "", false
	}
	ifName = strings.TrimSpace(header[openParen+1 : closeParen])
	return parsedIdx, ifName, rest, true
}

func hasResolvectlLink(m map[int]parsedLinkDNS, ifName string, ifIndex int) bool {
	if ifIndex > 0 {
		if _, ok := m[ifIndex]; ok {
			return true
		}
	}
	for _, v := range m {
		if v.ifName == ifName {
			return true
		}
	}
	return false
}

func parseDNSTokenAddr(tok string) (netip.Addr, bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return netip.Addr{}, false
	}
	if hash := strings.IndexByte(tok, '#'); hash >= 0 {
		tok = tok[:hash]
	}
	if host, _, err := net.SplitHostPort(tok); err == nil {
		tok = host
	}
	addr, err := netip.ParseAddr(tok)
	if err != nil || !addr.IsValid() {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func containsDNSAddrToken(tokens []string, target netip.Addr) bool {
	for _, tok := range tokens {
		if addr, ok := parseDNSTokenAddr(tok); ok && addr == target {
			return true
		}
	}
	return false
}

func filterUpstreamDNS(tokens []string) []netip.Addr {
	var out []netip.Addr
	for _, tok := range tokens {
		addr, ok := parseDNSTokenAddr(tok)
		if !ok || addr.IsUnspecified() || addr.IsLoopback() || addr == tunDNSAddrParsed {
			continue
		}
		out = append(out, addr)
	}
	return dedupValidAddrs(out)
}

func parseResolvConfNameservers(content string) []netip.Addr {
	var out []netip.Addr
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || !addr.IsValid() {
			continue
		}
		addr = addr.Unmap()
		if addr.IsUnspecified() || addr.IsLoopback() || addr == tunDNSAddrParsed {
			continue
		}
		out = append(out, addr)
	}
	return dedupValidAddrs(out)
}

func isOnlyTUNDNSResolvConf(content string) bool {
	var servers []netip.Addr
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if addr, err := netip.ParseAddr(fields[1]); err == nil {
			servers = append(servers, addr.Unmap())
		}
	}
	return len(servers) == 1 && servers[0] == tunDNSAddrParsed
}

func isUnknownLinkCmdErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unknown interface") ||
		strings.Contains(msg, "no such device") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "invalid argument") ||
		strings.Contains(msg, "link not found")
}
