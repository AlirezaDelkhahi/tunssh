// Package sysproxy manages OS system proxy configuration and shell environment snippets.
package sysproxy

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
)

const (
	// DefaultLoopbackHost is the default local proxy bind host.
	DefaultLoopbackHost = "127.0.0.1"
	// DefaultSOCKSPort is the default local SOCKS5 (socks5h) listener port.
	DefaultSOCKSPort = 10808
	// DefaultHTTPPort is the default local HTTP CONNECT listener port.
	DefaultHTTPPort = 10809

	// IranSuffix is the wildcard suffix bypassed when Iran/LAN bypass is enabled.
	IranSuffix = "*.ir"

	// WindowsLocalBypassToken bypasses single-label local hostnames in WinINet ProxyOverride.
	WindowsLocalBypassToken = "<local>"

	// DesktopEnvManual identifies tiling WMs, headless sessions, or missing proxy CLI tools.
	DesktopEnvManual = "manual-env"
	// DesktopEnvWindows identifies the native Windows WinINet/registry proxy backend.
	DesktopEnvWindows = "windows"

	maxTCPPort = 65535
)

var (
	// DefaultLoopbackBypassHosts are always bypassed for loopback traffic on Linux desktops.
	DefaultLoopbackBypassHosts = []string{"localhost", "127.0.0.0/8", "::1"}

	// DefaultBypassCIDRs are the private RFC1918 LAN CIDR ranges bypassed when BypassIranLAN is enabled.
	DefaultBypassCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	// WindowsLoopbackBypassPatterns are always bypassed in Windows Internet Settings ProxyOverride.
	WindowsLoopbackBypassPatterns = []string{"localhost", "127.*"}

	// WindowsLANBypassPatterns are the RFC1918 wildcard patterns for Windows Internet Settings ProxyOverride.
	WindowsLANBypassPatterns = []string{
		"10.*",
		"172.16.*", "172.17.*", "172.18.*", "172.19.*",
		"172.20.*", "172.21.*", "172.22.*", "172.23.*",
		"172.24.*", "172.25.*", "172.26.*", "172.27.*",
		"172.28.*", "172.29.*", "172.30.*", "172.31.*",
		"192.168.*",
	}
)

// ProxyCapabilities describes whether automatic OS system proxy management is available.
type ProxyCapabilities struct {
	AutoSupported bool   `json:"auto_supported"`
	DesktopEnv    string `json:"desktop_env"`
}

// ProxyApplyConfig specifies the local SOCKS5/HTTP proxy endpoints and bypass policy to apply.
type ProxyApplyConfig struct {
	SOCKSHost     string
	SOCKSPort     int
	HTTPHost      string
	HTTPPort      int
	BypassIranLAN bool
}

// ProxySnapshot captures pre-tunnel OS system proxy settings for crash-safe idempotent restoration.
type ProxySnapshot struct {
	Platform            string            `json:"platform"`
	WinProxyEnable      uint32            `json:"win_proxy_enable"`
	WinProxyEnableSet   bool              `json:"win_proxy_enable_set,omitempty"`
	WinProxyServer      string            `json:"win_proxy_server"`
	WinProxyServerSet   bool              `json:"win_proxy_server_set,omitempty"`
	WinProxyOverride    string            `json:"win_proxy_override"`
	WinProxyOverrideSet bool              `json:"win_proxy_override_set,omitempty"`
	WinAutoConfigURL    string            `json:"win_auto_config_url"`
	WinAutoConfigURLSet bool              `json:"win_auto_config_url_set,omitempty"`
	LinuxDE             string            `json:"linux_de"`
	LinuxPrevValues     map[string]string `json:"linux_prev_values"`
}

// SystemProxyManager snapshots, enables, and restores OS proxy configuration (Milestone 1).
type SystemProxyManager interface {
	Capabilities() ProxyCapabilities
	CaptureSnapshot(ctx context.Context) (ProxySnapshot, error)
	Enable(ctx context.Context, cfg ProxyApplyConfig) error
	Restore(ctx context.Context, snap ProxySnapshot) error
	EnvSnippet(socksPort, httpPort int) string
}

// FormatEnvSnippet formats a shell export command for CLI tools and tiling WMs.
func FormatEnvSnippet(socksPort, httpPort int) string {
	if socksPort < 1 || socksPort > maxTCPPort {
		socksPort = DefaultSOCKSPort
	}
	if httpPort < 1 || httpPort > maxTCPPort {
		httpPort = DefaultHTTPPort
	}
	return fmt.Sprintf(
		"export ALL_PROXY=socks5h://%s:%d HTTP_PROXY=http://%s:%d HTTPS_PROXY=http://%s:%d",
		DefaultLoopbackHost, socksPort,
		DefaultLoopbackHost, httpPort,
		DefaultLoopbackHost, httpPort,
	)
}

// LinuxBypassHosts returns a fresh bypass host/CIDR slice for Linux desktop proxy settings.
func LinuxBypassHosts(bypassIranLAN bool) []string {
	out := slices.Clone(DefaultLoopbackBypassHosts)
	if bypassIranLAN {
		out = append(out, DefaultBypassCIDRs...)
		out = append(out, IranSuffix)
	}
	return out
}

// WindowsProxyOverride builds the semicolon-delimited ProxyOverride value for Windows Internet Settings.
func WindowsProxyOverride(bypassIranLAN bool) string {
	entries := slices.Clone(WindowsLoopbackBypassPatterns)
	if bypassIranLAN {
		entries = append(entries, WindowsLANBypassPatterns...)
		entries = append(entries, IranSuffix)
	}
	entries = append(entries, WindowsLocalBypassToken)
	return strings.Join(entries, ";")
}

func normalizeApplyConfig(cfg ProxyApplyConfig) (ProxyApplyConfig, error) {
	if cfg.SOCKSHost == "" {
		cfg.SOCKSHost = DefaultLoopbackHost
	} else if err := validateProxyHost(cfg.SOCKSHost); err != nil {
		return ProxyApplyConfig{}, fmt.Errorf("sysproxy: invalid SOCKS host: %w", err)
	}

	if cfg.HTTPHost == "" {
		cfg.HTTPHost = DefaultLoopbackHost
	} else if err := validateProxyHost(cfg.HTTPHost); err != nil {
		return ProxyApplyConfig{}, fmt.Errorf("sysproxy: invalid HTTP host: %w", err)
	}

	if cfg.SOCKSPort == 0 {
		cfg.SOCKSPort = DefaultSOCKSPort
	} else if cfg.SOCKSPort < 1 || cfg.SOCKSPort > maxTCPPort {
		return ProxyApplyConfig{}, fmt.Errorf("sysproxy: invalid SOCKS port %d", cfg.SOCKSPort)
	}

	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = DefaultHTTPPort
	} else if cfg.HTTPPort < 1 || cfg.HTTPPort > maxTCPPort {
		return ProxyApplyConfig{}, fmt.Errorf("sysproxy: invalid HTTP port %d", cfg.HTTPPort)
	}

	return cfg, nil
}

func validateProxyHost(host string) error {
	if host == "" {
		return fmt.Errorf("host must not be empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '.' && c != '-' {
			return fmt.Errorf("unsupported character %q in host %q", c, host)
		}
	}
	return nil
}
