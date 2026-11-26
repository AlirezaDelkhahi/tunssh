//go:build linux && !android

package tun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"golang.org/x/sys/unix"
)

const procSelfStatusPath = "/proc/self/status"

// HasEffectiveCAPNetAdmin reports whether the current process has effective root
// privileges or CAP_NET_ADMIN in /proc/self/status CapEff.
func HasEffectiveCAPNetAdmin() bool {
	if os.Geteuid() == 0 {
		return true
	}
	data, err := os.ReadFile(procSelfStatusPath)
	if err != nil {
		return false
	}
	return parseCapEffHasNetAdmin(string(data))
}

// OpenAndConfigureDevice creates a Linux /dev/net/tun interface, assigns its MTU,
// IPv4 CIDR, optional ULA IPv6 CIDR (skipping IPv6 gracefully if disabled globally),
// brings the link UP, and returns the device alongside its OS interface index.
func OpenAndConfigureDevice(name string, mtu int, ipv4CIDR string, ipv6CIDR string, enableIPv6 bool) (device.Device, int, error) {
	normName, normMTU, p4, p6, err := normalizeDeviceConfig(name, mtu, ipv4CIDR, ipv6CIDR, enableIPv6)
	if err != nil {
		return nil, 0, err
	}
	if len(normName) >= unix.IFNAMSIZ {
		return nil, 0, fmt.Errorf("tun: Linux interface name %q exceeds IFNAMSIZ (%d)", normName, unix.IFNAMSIZ-1)
	}

	addr4, err := netlink.ParseAddr(p4.String())
	if err != nil {
		return nil, 0, fmt.Errorf("tun: parse IPv4 CIDR %q: %w", p4.String(), err)
	}

	var addr6 *netlink.Addr
	if enableIPv6 && p6.IsValid() {
		addr6, err = netlink.ParseAddr(p6.String())
		if err != nil {
			return nil, 0, fmt.Errorf("tun: parse IPv6 CIDR %q: %w", p6.String(), err)
		}
	}

	dev, err := tun.Open(normName, uint32(normMTU))
	if err != nil {
		return nil, 0, fmt.Errorf("tun: open device %q: %w", normName, err)
	}

	closeOnErr := true
	defer func() {
		if closeOnErr {
			dev.Close()
		}
	}()

	actualName := dev.Name()
	if actualName == "" {
		actualName = normName
	}
	if err := validateIfaceName(actualName); err != nil {
		return nil, 0, err
	}

	link, err := netlink.LinkByName(actualName)
	if err != nil {
		return nil, 0, fmt.Errorf("tun: lookup link %q: %w", actualName, err)
	}

	if err := netlink.LinkSetMTU(link, normMTU); err != nil {
		return nil, 0, fmt.Errorf("tun: set MTU %d on %q: %w", normMTU, actualName, err)
	}

	if err := netlink.AddrAdd(link, addr4); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, 0, fmt.Errorf("tun: add IPv4 %s to %q: %w", p4.String(), actualName, err)
	}

	if enableIPv6 && addr6 != nil {
		configureLinuxIPv6(link, actualName, addr6)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, 0, fmt.Errorf("tun: set link %q up: %w", actualName, err)
	}

	ifIndex := link.Attrs().Index
	if ifIndex <= 0 {
		return nil, 0, fmt.Errorf("tun: invalid interface index %d for %q", ifIndex, actualName)
	}

	closeOnErr = false
	return dev, ifIndex, nil
}

func configureLinuxIPv6(link netlink.Link, ifaceName string, addr6 *netlink.Addr) {
	if isLinuxIPv6GloballyDisabled() {
		return
	}

	disableIPv6Path := filepath.Join("/proc/sys/net/ipv6/conf", ifaceName, "disable_ipv6")
	if err := writeSysctlIfWritable(disableIPv6Path, "0\n"); err != nil && errors.Is(err, os.ErrNotExist) {
		// Kernel has IPv6 disabled globally (e.g., ipv6.disable=1).
		return
	}

	if err := netlink.AddrAdd(link, addr6); err != nil {
		if isIPv6DisabledLinuxErr(err) || errors.Is(err, unix.EEXIST) {
			return
		}
	}
}

func isLinuxIPv6GloballyDisabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if err != nil {
		// If procfs IPv6 sysctls do not exist, IPv6 stack is disabled in kernel.
		return errors.Is(err, os.ErrNotExist)
	}
	return strings.TrimSpace(string(data)) == "1"
}

func writeSysctlIfWritable(path, val string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(val)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func isIPv6DisabledLinuxErr(err error) bool {
	return errors.Is(err, unix.EAFNOSUPPORT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.EADDRNOTAVAIL)
}
