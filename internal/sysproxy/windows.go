//go:build windows

package sysproxy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	internetSettingsKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	regValProxyEnable   = "ProxyEnable"
	regValProxyServer   = "ProxyServer"
	regValProxyOverride = "ProxyOverride"
	regValAutoConfigURL = "AutoConfigURL"

	internetOptionRefresh         uintptr = 37
	internetOptionSettingsChanged uintptr = 39
)

var (
	wininetDLL             = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOptionW = wininetDLL.NewProc("InternetSetOptionW")
)

type windowsManager struct{}

// NewManager returns the Windows SystemProxyManager backed by HKCU Internet Settings and WinINet.
func NewManager() SystemProxyManager {
	return &windowsManager{}
}

func (m *windowsManager) Capabilities() ProxyCapabilities {
	return ProxyCapabilities{
		AutoSupported: true,
		DesktopEnv:    DesktopEnvWindows,
	}
}

func (m *windowsManager) EnvSnippet(socksPort, httpPort int) string {
	return FormatEnvSnippet(socksPort, httpPort)
}

func (m *windowsManager) CaptureSnapshot(ctx context.Context) (ProxySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ProxySnapshot{}, err
	}

	snap := ProxySnapshot{
		Platform:        "windows",
		LinuxPrevValues: map[string]string{},
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return snap, nil
	}
	if err != nil {
		return ProxySnapshot{}, fmt.Errorf("sysproxy: open %s: %w", internetSettingsKeyPath, err)
	}
	defer key.Close()

	enableVal, _, err := key.GetIntegerValue(regValProxyEnable)
	if err == nil {
		if enableVal > math.MaxUint32 {
			return ProxySnapshot{}, fmt.Errorf("sysproxy: %s value %d overflows uint32", regValProxyEnable, enableVal)
		}
		snap.WinProxyEnable = uint32(enableVal)
		snap.WinProxyEnableSet = true
	} else if !errors.Is(err, registry.ErrNotExist) {
		return ProxySnapshot{}, fmt.Errorf("sysproxy: read %s: %w", regValProxyEnable, err)
	}

	if snap.WinProxyServer, snap.WinProxyServerSet, err = readRegistryString(key, regValProxyServer); err != nil {
		return ProxySnapshot{}, err
	}
	if snap.WinProxyOverride, snap.WinProxyOverrideSet, err = readRegistryString(key, regValProxyOverride); err != nil {
		return ProxySnapshot{}, err
	}
	if snap.WinAutoConfigURL, snap.WinAutoConfigURLSet, err = readRegistryString(key, regValAutoConfigURL); err != nil {
		return ProxySnapshot{}, err
	}

	return snap, nil
}

func (m *windowsManager) Enable(ctx context.Context, cfg ProxyApplyConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	norm, err := normalizeApplyConfig(cfg)
	if err != nil {
		return err
	}

	key, _, err := registry.CreateKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("sysproxy: create/open %s: %w", internetSettingsKeyPath, err)
	}

	proxyServer := net.JoinHostPort(norm.HTTPHost, strconv.Itoa(norm.HTTPPort))
	proxyOverride := WindowsProxyOverride(norm.BypassIranLAN)

	writeErr := errors.Join(
		setRegistryDWord(key, regValProxyEnable, 1),
		setRegistryString(key, regValProxyServer, proxyServer),
		setRegistryString(key, regValProxyOverride, proxyOverride),
		deleteRegistryValue(key, regValAutoConfigURL),
	)
	if err := key.Close(); err != nil && writeErr == nil {
		writeErr = fmt.Errorf("sysproxy: close registry key: %w", err)
	}
	if writeErr != nil {
		return writeErr
	}

	return notifyWinINet()
}

func (m *windowsManager) Restore(ctx context.Context, snap ProxySnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if snap.Platform != "" && snap.Platform != "windows" {
		return fmt.Errorf("sysproxy: cannot restore %q snapshot on windows", snap.Platform)
	}

	hasValuesToRestore := snap.WinProxyEnableSet ||
		snap.WinProxyServerSet ||
		snap.WinProxyOverrideSet ||
		snap.WinAutoConfigURLSet

	var (
		key registry.Key
		err error
	)
	if hasValuesToRestore {
		key, _, err = registry.CreateKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.SET_VALUE)
	} else {
		key, err = registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.SET_VALUE)
		if errors.Is(err, registry.ErrNotExist) {
			return notifyWinINet()
		}
	}
	if err != nil {
		return fmt.Errorf("sysproxy: open %s for restore: %w", internetSettingsKeyPath, err)
	}

	var restoreErrs []error
	if snap.WinProxyEnableSet {
		restoreErrs = append(restoreErrs, setRegistryDWord(key, regValProxyEnable, snap.WinProxyEnable))
	} else {
		restoreErrs = append(restoreErrs, deleteRegistryValue(key, regValProxyEnable))
	}

	restoreErrs = append(restoreErrs,
		restoreRegistryString(key, regValProxyServer, snap.WinProxyServer, snap.WinProxyServerSet),
		restoreRegistryString(key, regValProxyOverride, snap.WinProxyOverride, snap.WinProxyOverrideSet),
		restoreRegistryString(key, regValAutoConfigURL, snap.WinAutoConfigURL, snap.WinAutoConfigURLSet),
	)

	if err := key.Close(); err != nil {
		restoreErrs = append(restoreErrs, fmt.Errorf("sysproxy: close registry key: %w", err))
	}
	restoreErrs = append(restoreErrs, notifyWinINet())

	return errors.Join(restoreErrs...)
}

func readRegistryString(key registry.Key, name string) (val string, present bool, err error) {
	v, _, err := key.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("sysproxy: read %s: %w", name, err)
	}
	return v, true, nil
}

func setRegistryDWord(key registry.Key, name string, val uint32) error {
	if err := key.SetDWordValue(name, val); err != nil {
		return fmt.Errorf("sysproxy: set %s: %w", name, err)
	}
	return nil
}

func setRegistryString(key registry.Key, name, val string) error {
	if err := key.SetStringValue(name, val); err != nil {
		return fmt.Errorf("sysproxy: set %s: %w", name, err)
	}
	return nil
}

func restoreRegistryString(key registry.Key, name, val string, present bool) error {
	if present {
		return setRegistryString(key, name, val)
	}
	return deleteRegistryValue(key, name)
}

func deleteRegistryValue(key registry.Key, name string) error {
	err := key.DeleteValue(name)
	if err == nil || errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("sysproxy: delete %s: %w", name, err)
}

func notifyWinINet() error {
	if err := procInternetSetOptionW.Find(); err != nil {
		return fmt.Errorf("sysproxy: load wininet InternetSetOptionW: %w", err)
	}
	if err := callInternetSetOption(internetOptionSettingsChanged); err != nil {
		return err
	}
	return callInternetSetOption(internetOptionRefresh)
}

func callInternetSetOption(option uintptr) error {
	// Win32 BOOL functions return 0 on failure; LazyProc.Call always returns a non-nil lastErr wrapping GetLastError().
	r1, _, lastErr := procInternetSetOptionW.Call(0, option, 0, 0)
	if r1 == 0 {
		return fmt.Errorf("sysproxy: InternetSetOptionW(%d): %w", option, lastErr)
	}
	return nil
}
