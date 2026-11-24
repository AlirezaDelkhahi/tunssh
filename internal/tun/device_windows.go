//go:build windows

package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"golang.org/x/sys/windows"
)

const (
	wintunDLLName          = "wintun.dll"
	netshCommandTimeout    = 10 * time.Second
	ifaceLookupPollTimeout = 2 * time.Second
	ifaceLookupPollStep    = 50 * time.Millisecond
)

var (
	modIphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceAliasToLuid = modIphlpapi.NewProc("ConvertInterfaceAliasToLuid")
	procConvertInterfaceLuidToIndex = modIphlpapi.NewProc("ConvertInterfaceLuidToIndex")
)

// HasEffectiveCAPNetAdmin reports whether the current Windows process holds an elevated token.
func HasEffectiveCAPNetAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// VerifyWintunDLL verifies wintun.dll at path against expectedHex using constant-time SHA-256 comparison.
func VerifyWintunDLL(path, expectedHex string) error {
	return VerifyDLLSHA256(path, expectedHex)
}

// OpenAndConfigureDevice locates and SHA-256-verifies wintun.dll before opening the Wintun
// adapter, configures IPv4, optional ULA IPv6 (gracefully skipped if IPv6 is disabled on the host),
// and MTU, and returns the opened device and its Windows interface index.
func OpenAndConfigureDevice(name string, mtu int, ipv4CIDR string, ipv6CIDR string, enableIPv6 bool) (device.Device, int, error) {
	normName, normMTU, p4, p6, err := normalizeDeviceConfig(name, mtu, ipv4CIDR, ipv6CIDR, enableIPv6)
	if err != nil {
		return nil, 0, err
	}

	expectedSHA, err := ExpectedWintunSHA256(runtime.GOARCH)
	if err != nil {
		return nil, 0, err
	}

	dllPath, sysDir, err := locateWintunDLL()
	if err != nil {
		return nil, 0, err
	}
	if err := VerifyWintunDLL(dllPath, expectedSHA); err != nil {
		return nil, 0, err
	}

	dev, err := tun.Open(normName, uint32(normMTU))
	if err != nil {
		return nil, 0, fmt.Errorf("tun: open Wintun device %q: %w", normName, err)
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

	ifIndex, err := waitForWindowsInterfaceIndex(actualName, ifaceLookupPollTimeout)
	if err != nil {
		return nil, 0, err
	}

	netshPath := filepath.Join(sysDir, "netsh.exe")
	if err := configureWindowsIPv4(netshPath, actualName, p4, normMTU); err != nil {
		return nil, 0, err
	}

	if enableIPv6 && p6.IsValid() {
		// Gracefully skip IPv6 configuration if IPv6 is disabled globally on Windows.
		_ = configureWindowsIPv6(netshPath, actualName, p6, normMTU)
	}

	closeOnErr = false
	return dev, ifIndex, nil
}

func locateWintunDLL() (dllPath string, sysDir string, err error) {
	sysDir, err = windows.GetSystemDirectory()
	if err != nil {
		return "", "", fmt.Errorf("tun: resolve Windows System32 directory: %w", err)
	}

	// Match golang.zx2c4.com/wintun's LoadLibraryEx search order:
	// LOAD_LIBRARY_SEARCH_APPLICATION_DIR first, LOAD_LIBRARY_SEARCH_SYSTEM32 second.
	if exePath, exeErr := os.Executable(); exeErr == nil && exePath != "" {
		appDLL := filepath.Join(filepath.Dir(exePath), wintunDLLName)
		info, statErr := os.Stat(appDLL)
		if statErr == nil {
			if info.IsDir() {
				return "", "", fmt.Errorf("tun: %q is a directory, expected %s", appDLL, wintunDLLName)
			}
			return appDLL, sysDir, nil
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return "", "", fmt.Errorf("tun: stat %q: %w", appDLL, statErr)
		}
	}

	sysDLL := filepath.Join(sysDir, wintunDLLName)
	info, statErr := os.Stat(sysDLL)
	if statErr != nil {
		return "", "", fmt.Errorf("tun: locate %s next to executable or in %s: %w", wintunDLLName, sysDir, statErr)
	}
	if info.IsDir() {
		return "", "", fmt.Errorf("tun: %q is a directory, expected %s", sysDLL, wintunDLLName)
	}
	return sysDLL, sysDir, nil
}

func waitForWindowsInterfaceIndex(ifaceName string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		ifIndex, err := lookupWindowsInterfaceIndex(ifaceName)
		if err == nil && ifIndex > 0 {
			return ifIndex, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(ifaceLookupPollStep)
	}
	return 0, fmt.Errorf("tun: resolve interface index for %q: %w", ifaceName, lastErr)
}

func lookupWindowsInterfaceIndex(ifaceName string) (int, error) {
	aliasPtr, err := windows.UTF16PtrFromString(ifaceName)
	if err != nil {
		return 0, err
	}

	var luid uint64
	r0, _, _ := procConvertInterfaceAliasToLuid.Call(
		uintptr(unsafe.Pointer(aliasPtr)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if r0 == 0 {
		var idx uint32
		r1, _, _ := procConvertInterfaceLuidToIndex.Call(
			uintptr(unsafe.Pointer(&luid)),
			uintptr(unsafe.Pointer(&idx)),
		)
		if r1 == 0 && idx > 0 {
			return int(idx), nil
		}
		if r1 != 0 {
			return 0, windows.Errno(r1)
		}
	}

	iface, ifaceErr := net.InterfaceByName(ifaceName)
	if ifaceErr == nil && iface.Index > 0 {
		return iface.Index, nil
	}
	if r0 != 0 {
		return 0, windows.Errno(r0)
	}
	return 0, ifaceErr
}

func configureWindowsIPv4(netshPath, ifaceName string, p4 netip.Prefix, mtu int) error {
	ipStr := p4.Addr().String()
	maskIP := net.IP(net.CIDRMask(p4.Bits(), 32))
	if len(maskIP) != 4 {
		return fmt.Errorf("tun: compute IPv4 mask for %q", p4.String())
	}

	if err := runNetshHidden(
		netshPath,
		"interface", "ipv4", "set", "address",
		"name="+ifaceName,
		"source=static",
		"address="+ipStr,
		"mask="+maskIP.String(),
		"store=active",
	); err != nil {
		return fmt.Errorf("tun: configure IPv4 address %s on %q: %w", p4.String(), ifaceName, err)
	}

	if err := runNetshHidden(
		netshPath,
		"interface", "ipv4", "set", "subinterface",
		"interface="+ifaceName,
		"mtu="+strconv.Itoa(mtu),
		"store=active",
	); err != nil {
		return fmt.Errorf("tun: set IPv4 MTU %d on %q: %w", mtu, ifaceName, err)
	}

	return nil
}

func configureWindowsIPv6(netshPath, ifaceName string, p6 netip.Prefix, mtu int) error {
	if err := runNetshHidden(
		netshPath,
		"interface", "ipv6", "set", "subinterface",
		"interface="+ifaceName,
		"mtu="+strconv.Itoa(mtu),
		"store=active",
	); err != nil {
		return err
	}

	return runNetshHidden(
		netshPath,
		"interface", "ipv6", "set", "address",
		"interface="+ifaceName,
		"address="+p6.String(),
		"store=active",
	)
}

func runNetshHidden(netshPath string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), netshCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, netshPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}
