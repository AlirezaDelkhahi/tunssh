//go:build windows

package splitroute

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	dnsStrategyWindowsNetsh = "windows-netsh"

	tcpipInterfacesKeyPath  = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`
	tcpip6InterfacesKeyPath = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\`

	ipUnicastIfOpt   = 31
	ipv6UnicastIfOpt = 31

	routeLifetimeInfinite = 0xffffffff
)

var (
	modiphlpapi                  = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeIpForwardEntry = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2    = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2    = modiphlpapi.NewProc("DeleteIpForwardEntry2")

	moddnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = moddnsapi.NewProc("DnsFlushResolverCache")

	errWinAdapterNotFound = errors.New("windows adapter not found")
)

// WindowsOptions injects command and logging hooks for deterministic testing on Windows.
type WindowsOptions struct {
	RunCmd func(ctx context.Context, name string, args ...string) (string, error)
	Logger *slog.Logger
}

// NewManager returns the Windows RouteManager backed by iphlpapi.dll and multi-adapter netsh DNS management.
func NewManager() RouteManager {
	return NewWindowsManager(WindowsOptions{})
}

// NewWindowsManager constructs a Windows RouteManager with optional dependency overrides.
func NewWindowsManager(opts WindowsOptions) RouteManager {
	if opts.RunCmd == nil {
		opts.RunCmd = defaultWindowsRunCmd
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return NewManagerWithDeps(&windowsRouteOps{}, &windowsDNSConfigurator{runCmd: opts.RunCmd}, opts.Logger)
}

func defaultWindowsRunCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = strings.TrimSpace(stdout.String())
		}
		if errMsg != "" {
			return "", fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, errMsg)
		}
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// bindToInterfaceControl binds outbound sockets on Windows to ifaceIndex/ifaceName via
// IP_UNICAST_IF (network byte order htonl) for IPv4 and IPV6_UNICAST_IF (host byte order) for IPv6.
func bindToInterfaceControl(ifaceName string, ifaceIndex int, isIPv6 bool) func(network, address string, c syscall.RawConn) error {
	idx := ifaceIndex
	if idx <= 0 && strings.TrimSpace(ifaceName) != "" {
		if iface, err := net.InterfaceByName(strings.TrimSpace(ifaceName)); err == nil {
			idx = iface.Index
		}
	}

	return func(network, _ string, c syscall.RawConn) error {
		if idx <= 0 || c == nil {
			return nil
		}

		useV6 := isIPv6
		if strings.HasSuffix(network, "4") {
			useV6 = false
		} else if strings.HasSuffix(network, "6") {
			useV6 = true
		}

		var sockErr error
		if err := c.Control(func(fd uintptr) {
			if useV6 {
				sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIfOpt, idx)
				return
			}
			var netOrder [4]byte
			binary.BigEndian.PutUint32(netOrder[:], uint32(idx))
			sockErr = windows.Setsockopt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIfOpt, &netOrder[0], int32(len(netOrder)))
		}); err != nil {
			return err
		}
		return sockErr
	}
}

type windowsAdapterInfo struct {
	ifIndex      uint32
	ipv6IfIndex  uint32
	luid         uint64
	friendlyName string
	adapterGUID  string
	ifType       uint32
	operStatus   uint32
	ipv4Metric   uint32
	ipv6Metric   uint32
	dnsServers   []netip.Addr
}

func listWindowsAdapters() ([]windowsAdapterInfo, error) {
	bufLen := uint32(16 * 1024)
	var buf []byte
	for attempt := 0; attempt < 5; attempt++ {
		buf = make([]byte, bufLen)
		err := windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			0,
			0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])),
			&bufLen,
		)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
		if attempt == 4 {
			return nil, fmt.Errorf("GetAdaptersAddresses buffer overflow after retries: %w", err)
		}
	}

	var adapters []windowsAdapterInfo
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		info := windowsAdapterInfo{
			ifIndex:      aa.IfIndex,
			ipv6IfIndex:  aa.Ipv6IfIndex,
			luid:         aa.Luid,
			friendlyName: windows.UTF16PtrToString(aa.FriendlyName),
			adapterGUID:  windows.BytePtrToString(aa.AdapterName),
			ifType:       aa.IfType,
			operStatus:   aa.OperStatus,
			ipv4Metric:   aa.Ipv4Metric,
			ipv6Metric:   aa.Ipv6Metric,
		}
		for dns := aa.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if len(ip) == 0 {
				continue
			}
			if addr, ok := netip.AddrFromSlice(ip); ok {
				addr = addr.Unmap()
				if addr.IsValid() && !addr.IsUnspecified() {
					info.dnsServers = append(info.dnsServers, addr)
				}
			}
		}
		adapters = append(adapters, info)
	}
	return adapters, nil
}

func findWindowsAdapter(adapters []windowsAdapterInfo, name string, index int) (windowsAdapterInfo, error) {
	trimmed := strings.TrimSpace(name)
	if index > 0 {
		idx32 := uint32(index)
		for _, a := range adapters {
			if a.ifIndex == idx32 || a.ipv6IfIndex == idx32 {
				return a, nil
			}
		}
	}
	if trimmed != "" {
		for _, a := range adapters {
			if strings.EqualFold(a.friendlyName, trimmed) {
				return a, nil
			}
		}
	}
	return windowsAdapterInfo{}, fmt.Errorf("%w: name=%q index=%d", errWinAdapterNotFound, name, index)
}

type windowsRouteOps struct{}

var _ RouteOps = (*windowsRouteOps)(nil)

func (o *windowsRouteOps) CaptureDefaultRoute(ctx context.Context) (netip.Addr, netip.Addr, string, int, error) {
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, netip.Addr{}, "", 0, err
	}

	adapters, err := listWindowsAdapters()
	if err != nil {
		return netip.Addr{}, netip.Addr{}, "", 0, err
	}
	byLuid := make(map[uint64]windowsAdapterInfo, len(adapters))
	byIdx := make(map[uint32]windowsAdapterInfo, len(adapters))
	for _, a := range adapters {
		if a.luid != 0 {
			byLuid[a.luid] = a
		}
		if a.ifIndex != 0 {
			byIdx[a.ifIndex] = a
		}
		if a.ipv6IfIndex != 0 {
			byIdx[a.ipv6IfIndex] = a
		}
	}

	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return netip.Addr{}, netip.Addr{}, "", 0, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	if table != nil {
		defer windows.FreeMibTable(unsafe.Pointer(table))
	}

	type cand struct {
		gw     netip.Addr
		ifIdx  uint32
		luid   uint64
		metric uint64
		name   string
	}

	var bestV4, bestV6 *cand
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}

		adapter, hasAdapter := byLuid[row.InterfaceLuid]
		if !hasAdapter {
			adapter, hasAdapter = byIdx[row.InterfaceIndex]
		}
		if hasAdapter {
			if adapter.ifType == windows.IF_TYPE_SOFTWARE_LOOPBACK ||
				adapter.operStatus != windows.IfOperStatusUp ||
				strings.EqualFold(adapter.friendlyName, TUNIfaceName) {
				continue
			}
		}

		nextHop := rawSockaddrToAddr(&row.NextHop).Unmap()
		if !nextHop.IsValid() || nextHop.IsUnspecified() {
			continue
		}

		totalMetric := uint64(row.Metric)
		switch row.DestinationPrefix.Prefix.Family {
		case windows.AF_INET:
			if !nextHop.Is4() {
				continue
			}
			if hasAdapter {
				totalMetric += uint64(adapter.ipv4Metric)
			}
			c := cand{
				gw:     nextHop,
				ifIdx:  row.InterfaceIndex,
				luid:   row.InterfaceLuid,
				metric: totalMetric,
				name:   adapter.friendlyName,
			}
			if bestV4 == nil || c.metric < bestV4.metric {
				bestV4 = &c
			}
		case windows.AF_INET6:
			if !nextHop.Is6() {
				continue
			}
			if hasAdapter {
				totalMetric += uint64(adapter.ipv6Metric)
			}
			c := cand{
				gw:     nextHop,
				ifIdx:  row.InterfaceIndex,
				luid:   row.InterfaceLuid,
				metric: totalMetric,
				name:   adapter.friendlyName,
			}
			if bestV6 == nil ||
				(bestV4 != nil && c.luid == bestV4.luid && bestV6.luid != bestV4.luid) ||
				(((bestV4 == nil) || (c.luid == bestV4.luid) == (bestV6.luid == bestV4.luid)) && c.metric < bestV6.metric) {
				bestV6 = &c
			}
		}
	}

	if bestV4 == nil && bestV6 == nil {
		return netip.Addr{}, netip.Addr{}, "", 0, errors.New("no active Windows default route found")
	}

	var gw4, gw6 netip.Addr
	var ifaceName string
	var ifaceIndex int

	if bestV4 != nil {
		gw4 = bestV4.gw
		ifaceName = bestV4.name
		ifaceIndex = int(bestV4.ifIdx)
	}
	if bestV6 != nil {
		gw6 = bestV6.gw
		if ifaceName == "" {
			ifaceName = bestV6.name
			ifaceIndex = int(bestV6.ifIdx)
		}
	}

	if ifaceName == "" && ifaceIndex > 0 {
		if iface, err := net.InterfaceByIndex(ifaceIndex); err == nil {
			ifaceName = iface.Name
		}
	}

	return gw4, gw6, ifaceName, ifaceIndex, nil
}

func (o *windowsRouteOps) AddRoute(ctx context.Context, r RouteSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	row, err := o.buildForwardRow(r)
	if err != nil {
		return err
	}
	if err := callCreateIpForwardEntry2(&row); err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return nil
		}
		if r.Dst.Addr().Is6() && isWindowsIPv6DisabledErr(err) {
			return fmt.Errorf("%w: %v", ErrIPv6Disabled, err)
		}
		return fmt.Errorf("CreateIpForwardEntry2(%s): %w", r.Dst, err)
	}
	return nil
}

func (o *windowsRouteOps) DeleteRoute(ctx context.Context, r RouteSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	row, err := o.buildForwardRow(r)
	if err != nil {
		if errors.Is(err, errWinAdapterNotFound) || errors.Is(err, ErrIPv6Disabled) {
			return nil
		}
		return err
	}
	if err := callDeleteIpForwardEntry2(&row); err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		if r.Dst.Addr().Is6() && isWindowsIPv6DisabledErr(err) {
			return nil
		}
		return fmt.Errorf("DeleteIpForwardEntry2(%s): %w", r.Dst, err)
	}
	return nil
}

func (o *windowsRouteOps) IsTUNRouteOrIfaceActive(ctx context.Context, tunIface string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if strings.TrimSpace(tunIface) == "" {
		tunIface = TUNIfaceName
	}

	var firstErr error
	adapters, err := listWindowsAdapters()
	if err != nil {
		firstErr = err
	} else {
		for _, a := range adapters {
			if strings.EqualFold(a.friendlyName, tunIface) {
				return true, nil
			}
		}
	}

	var table *windows.MibIpForwardTable2
	if tblErr := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); tblErr != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("GetIpForwardTable2: %w", tblErr)
		}
	} else if table != nil {
		defer windows.FreeMibTable(unsafe.Pointer(table))
		for _, row := range table.Rows() {
			if row.DestinationPrefix.PrefixLength != 1 {
				continue
			}
			addr := rawSockaddrToAddr(&row.DestinationPrefix.Prefix).Unmap()
			if !addr.IsValid() {
				continue
			}
			pfx := netip.PrefixFrom(addr, int(row.DestinationPrefix.PrefixLength)).Masked()
			if isSplitDefaultPrefix(pfx) {
				return true, nil
			}
		}
	}

	return false, firstErr
}

func (o *windowsRouteOps) buildForwardRow(r RouteSpec) (windows.MibIpForwardRow2, error) {
	if !r.Dst.IsValid() {
		return windows.MibIpForwardRow2{}, errors.New("splitroute: route destination prefix is invalid")
	}

	var row windows.MibIpForwardRow2
	if err := procInitializeIpForwardEntry.Find(); err == nil {
		_, _, _ = procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	}

	dst := r.Dst.Masked()
	isV6 := dst.Addr().Is6()

	adapters, err := listWindowsAdapters()
	if err != nil {
		return windows.MibIpForwardRow2{}, err
	}
	adapter, err := findWindowsAdapter(adapters, r.IfaceName, r.IfaceIndex)
	if err != nil {
		return windows.MibIpForwardRow2{}, err
	}

	if isV6 {
		if adapter.ipv6IfIndex == 0 {
			return windows.MibIpForwardRow2{}, fmt.Errorf("%w: adapter %q has no IPv6 interface", ErrIPv6Disabled, adapter.friendlyName)
		}
		row.InterfaceIndex = adapter.ipv6IfIndex
	} else {
		if adapter.ifIndex != 0 {
			row.InterfaceIndex = adapter.ifIndex
		} else {
			row.InterfaceIndex = uint32(max(0, r.IfaceIndex))
		}
	}
	row.InterfaceLuid = adapter.luid

	row.DestinationPrefix.Prefix = addrToRawSockaddr(dst.Addr(), isV6)
	row.DestinationPrefix.PrefixLength = uint8(dst.Bits())

	if r.Gateway.IsValid() && !isTUNLocalAddr(r.Gateway) && !strings.EqualFold(strings.TrimSpace(r.IfaceName), TUNIfaceName) {
		row.NextHop = addrToRawSockaddr(r.Gateway.Unmap(), isV6)
	} else {
		row.NextHop = addrToRawSockaddr(netip.Addr{}, isV6)
	}

	row.ValidLifetime = routeLifetimeInfinite
	row.PreferredLifetime = routeLifetimeInfinite
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	row.Origin = windows.NlroManual
	if r.Metric > 0 {
		row.Metric = uint32(r.Metric)
	}
	return row, nil
}

func callCreateIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	if err := procCreateIpForwardEntry2.Find(); err != nil {
		return fmt.Errorf("load CreateIpForwardEntry2: %w", err)
	}
	r0, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

func callDeleteIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	if err := procDeleteIpForwardEntry2.Find(); err != nil {
		return fmt.Errorf("load DeleteIpForwardEntry2: %w", err)
	}
	r0, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if r0 != 0 {
		return syscall.Errno(r0)
	}
	return nil
}

func addrToRawSockaddr(addr netip.Addr, isV6 bool) windows.RawSockaddrInet {
	var sa windows.RawSockaddrInet
	if isV6 {
		sa6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&sa))
		sa6.Family = windows.AF_INET6
		if addr.IsValid() {
			sa6.Addr = addr.As16()
		}
		return sa
	}
	sa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&sa))
	sa4.Family = windows.AF_INET
	if addr.IsValid() {
		sa4.Addr = addr.Unmap().As4()
	}
	return sa
}

func rawSockaddrToAddr(sa *windows.RawSockaddrInet) netip.Addr {
	if sa == nil {
		return netip.Addr{}
	}
	switch sa.Family {
	case windows.AF_INET:
		sa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrFrom4(sa4.Addr)
	case windows.AF_INET6:
		sa6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa))
		return netip.AddrFrom16(sa6.Addr)
	default:
		return netip.Addr{}
	}
}

func isWindowsIPv6DisabledErr(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.WSAEAFNOSUPPORT) ||
		errors.Is(err, windows.WSAENETUNREACH)
}

type windowsDNSConfigurator struct {
	runCmd func(ctx context.Context, name string, args ...string) (string, error)
}

var _ DNSConfigurator = (*windowsDNSConfigurator)(nil)

func (d *windowsDNSConfigurator) CaptureDNS(ctx context.Context, origIfaceName string, origIfaceIndex int) (string, []netip.Addr, []WinAdapterDNSBackup, []LinuxDNSBackup, string, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, nil, nil, "", err
	}

	adapters, err := listWindowsAdapters()
	if err != nil {
		return "", nil, nil, nil, "", err
	}

	var backups []WinAdapterDNSBackup
	var primaryDNS []netip.Addr
	var secondaryDNS []netip.Addr

	for _, a := range adapters {
		if a.operStatus != windows.IfOperStatusUp ||
			a.ifType == windows.IF_TYPE_SOFTWARE_LOOPBACK ||
			strings.EqualFold(a.friendlyName, TUNIfaceName) {
			continue
		}
		isOrig := (origIfaceIndex > 0 && (int(a.ifIndex) == origIfaceIndex || int(a.ipv6IfIndex) == origIfaceIndex)) ||
			(origIfaceName != "" && strings.EqualFold(a.friendlyName, origIfaceName))
		if a.ifType == windows.IF_TYPE_TUNNEL && !isOrig {
			continue
		}
		if strings.TrimSpace(a.friendlyName) == "" {
			continue
		}

		// Record statically configured DNS servers from registry; empty slice preserves DHCP state on RestoreDNS.
		staticV4 := readStaticNameServers(tcpipInterfacesKeyPath + a.adapterGUID)
		staticV6 := readStaticNameServers(tcpip6InterfacesKeyPath + a.adapterGUID)

		backups = append(backups, WinAdapterDNSBackup{
			IfaceIndex: int(a.ifIndex),
			IfaceName:  a.friendlyName,
			IPv4DNS:    staticV4,
			IPv6DNS:    staticV6,
		})

		for _, addr := range a.dnsServers {
			if addr.IsLoopback() || addr == tunDNSAddrParsed || addr.IsLinkLocalUnicast() {
				continue
			}
			if isOrig {
				primaryDNS = append(primaryDNS, addr)
			} else {
				secondaryDNS = append(secondaryDNS, addr)
			}
		}
	}

	origDNS := dedupValidAddrs(primaryDNS)
	if len(origDNS) == 0 {
		origDNS = dedupValidAddrs(secondaryDNS)
	}

	return dnsStrategyWindowsNetsh, origDNS, backups, nil, "", nil
}

func (d *windowsDNSConfigurator) ApplyTUNDNS(ctx context.Context, snap NetworkSnapshot, tunDNS netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !tunDNS.IsValid() {
		return errors.New("splitroute: invalid TUN DNS address")
	}

	tunIface := strings.TrimSpace(snap.TUNIfaceName)
	if tunIface == "" {
		tunIface = TUNIfaceName
	}

	seen := make(map[string]bool)
	for _, b := range snap.WinAdapterDNSBackups {
		name := strings.TrimSpace(b.IfaceName)
		if name == "" || strings.EqualFold(name, tunIface) || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true

		if _, err := d.runCmd(ctx, "netsh", "interface", "ipv4", "set", "dnsservers",
			"name="+name, "source=static", "address="+tunDNS.String(), "register=none", "validate=no"); err != nil {
			return fmt.Errorf("set IPv4 DNS on %q: %w", name, err)
		}
		// Prevent Windows SMHNR leaks over physical IPv6 DNS servers.
		_, _ = d.runCmd(ctx, "netsh", "interface", "ipv6", "delete", "dnsservers", "name="+name, "all")
	}

	if len(seen) == 0 {
		if orig := strings.TrimSpace(snap.OrigIfaceName); orig != "" && !strings.EqualFold(orig, tunIface) {
			if _, err := d.runCmd(ctx, "netsh", "interface", "ipv4", "set", "dnsservers",
				"name="+orig, "source=static", "address="+tunDNS.String(), "register=none", "validate=no"); err != nil {
				return fmt.Errorf("set IPv4 DNS on %q: %w", orig, err)
			}
			_, _ = d.runCmd(ctx, "netsh", "interface", "ipv6", "delete", "dnsservers", "name="+orig, "all")
		}
	}

	if adapters, err := listWindowsAdapters(); err == nil {
		if _, err := findWindowsAdapter(adapters, tunIface, 0); err == nil {
			if _, err := d.runCmd(ctx, "netsh", "interface", "ipv4", "set", "dnsservers",
				"name="+tunIface, "source=static", "address="+tunDNS.String(), "register=none", "validate=no"); err != nil {
				return fmt.Errorf("set IPv4 DNS on TUN %q: %w", tunIface, err)
			}
			_, _ = d.runCmd(ctx, "netsh", "interface", "ipv6", "delete", "dnsservers", "name="+tunIface, "all")
		}
	}

	flushWindowsDNSCache()
	return nil
}

func (d *windowsDNSConfigurator) RestoreDNS(ctx context.Context, snap NetworkSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	tunIface := strings.TrimSpace(snap.TUNIfaceName)
	if tunIface == "" {
		tunIface = TUNIfaceName
	}

	var errs []error
	seen := make(map[string]bool)

	for _, b := range snap.WinAdapterDNSBackups {
		name := strings.TrimSpace(b.IfaceName)
		if name == "" || strings.EqualFold(name, tunIface) || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true

		if err := d.restoreAdapterFamilyDNS(ctx, "ipv4", name, b.IPv4DNS); err != nil {
			errs = append(errs, err)
		}
		if err := d.restoreAdapterFamilyDNS(ctx, "ipv6", name, b.IPv6DNS); err != nil && !isIgnorableNetshV6Err(err) {
			errs = append(errs, err)
		}
	}

	if len(seen) == 0 {
		if orig := strings.TrimSpace(snap.OrigIfaceName); orig != "" && !strings.EqualFold(orig, tunIface) {
			if err := d.restoreAdapterFamilyDNS(ctx, "ipv4", orig, nil); err != nil {
				errs = append(errs, err)
			}
			if err := d.restoreAdapterFamilyDNS(ctx, "ipv6", orig, nil); err != nil && !isIgnorableNetshV6Err(err) {
				errs = append(errs, err)
			}
		}
	}

	flushWindowsDNSCache()
	return errors.Join(errs...)
}

func (d *windowsDNSConfigurator) restoreAdapterFamilyDNS(ctx context.Context, family, ifaceName string, servers []string) error {
	if len(servers) == 0 {
		if _, err := d.runCmd(ctx, "netsh", "interface", family, "set", "dnsservers", "name="+ifaceName, "source=dhcp"); err != nil && !isNetshNotFoundErr(err) {
			return fmt.Errorf("restore %s DHCP DNS on %q: %w", family, ifaceName, err)
		}
		return nil
	}

	if _, err := d.runCmd(ctx, "netsh", "interface", family, "set", "dnsservers",
		"name="+ifaceName, "source=static", "address="+servers[0], "register=none", "validate=no"); err != nil {
		if isNetshNotFoundErr(err) {
			return nil
		}
		return fmt.Errorf("restore %s static DNS on %q: %w", family, ifaceName, err)
	}
	for i := 1; i < len(servers); i++ {
		if _, err := d.runCmd(ctx, "netsh", "interface", family, "add", "dnsservers",
			"name="+ifaceName, "address="+servers[i], "index="+strconv.Itoa(i+1), "validate=no"); err != nil {
			if isNetshNotFoundErr(err) {
				return nil
			}
			return fmt.Errorf("add %s static DNS #%d on %q: %w", family, i+1, ifaceName, err)
		}
	}
	return nil
}

func (d *windowsDNSConfigurator) IsTUNDNSActive(ctx context.Context, tunIface string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if strings.TrimSpace(tunIface) == "" {
		tunIface = TUNIfaceName
	}

	adapters, err := listWindowsAdapters()
	if err == nil {
		for _, a := range adapters {
			if strings.EqualFold(a.friendlyName, tunIface) {
				return true, nil
			}
			for _, dnsIP := range a.dnsServers {
				if dnsIP.Unmap() == tunDNSAddrParsed {
					return true, nil
				}
			}
			if a.adapterGUID != "" {
				if hasStaticNameServer(tcpipInterfacesKeyPath+a.adapterGUID, tunDNSAddrParsed) ||
					hasStaticNameServer(tcpip6InterfacesKeyPath+a.adapterGUID, tunDNSAddrParsed) {
					return true, nil
				}
			}
		}
	}

	if registryTreeContainsNameServer(tcpipInterfacesKeyPath, tunDNSAddrParsed) ||
		registryTreeContainsNameServer(tcpip6InterfacesKeyPath, tunDNSAddrParsed) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

func readRegistryNameServerAddrs(regKeyPath string) []netip.Addr {
	if strings.HasSuffix(regKeyPath, `\`) {
		return nil
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()

	raw, _, err := k.GetStringValue("NameServer")
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	var out []netip.Addr
	for _, f := range fields {
		if addr, ok := parseOptionalAddr(f); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

func readStaticNameServers(regKeyPath string) []string {
	addrs := readRegistryNameServerAddrs(regKeyPath)
	var out []string
	for _, addr := range addrs {
		if !addr.IsUnspecified() && !addr.IsLoopback() && addr != tunDNSAddrParsed {
			out = append(out, addr.String())
		}
	}
	return out
}

func hasStaticNameServer(regKeyPath string, target netip.Addr) bool {
	return slices.Contains(readRegistryNameServerAddrs(regKeyPath), target)
}

func registryTreeContainsNameServer(parentPathWithSlash string, target netip.Addr) bool {
	parentKeyPath := strings.TrimSuffix(parentPathWithSlash, `\`)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, parentKeyPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}
	for _, sub := range names {
		if hasStaticNameServer(parentPathWithSlash+sub, target) {
			return true
		}
	}
	return false
}

func flushWindowsDNSCache() {
	if err := procDnsFlushResolverCache.Find(); err == nil {
		_, _, _ = procDnsFlushResolverCache.Call()
	}
}

func isNetshNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "element not found") ||
		strings.Contains(msg, "cannot find") ||
		strings.Contains(msg, "is not configured") ||
		strings.Contains(msg, "does not exist")
}

func isIgnorableNetshV6Err(err error) bool {
	if isNetshNotFoundErr(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "not installed") ||
		strings.Contains(msg, "already")
}
