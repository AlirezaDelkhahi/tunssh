//go:build linux

package sysproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	kdeConfigFile  = "kioslaverc"
	kdeProxyGroup  = "Proxy Settings"
	kdeKeyPrefix   = kdeConfigFile + "/" + kdeProxyGroup + "/"
	gsettingsBin   = "gsettings"
	dbusSendBin    = "dbus-send"
	kread6Bin      = "kreadconfig6"
	kwrite6Bin     = "kwriteconfig6"
	kread5Bin      = "kreadconfig5"
	kwrite5Bin     = "kwriteconfig5"
	kdeScheduler   = "/KIO/Scheduler"
	kdeReparseSign = "org.kde.KIO.Scheduler.reparseConfiguration"
)

type linuxBackend uint8

const (
	backendManual linuxBackend = iota
	backendGNOME
	backendKDE
)

type gsettingsKeySpec struct {
	schema string
	key    string
}

var gnomeProxyKeys = []gsettingsKeySpec{
	{schema: "org.gnome.system.proxy", key: "mode"},
	{schema: "org.gnome.system.proxy", key: "autoconfig-url"},
	{schema: "org.gnome.system.proxy", key: "ignore-hosts"},
	{schema: "org.gnome.system.proxy.http", key: "host"},
	{schema: "org.gnome.system.proxy.http", key: "port"},
	{schema: "org.gnome.system.proxy.http", key: "enabled"},
	{schema: "org.gnome.system.proxy.https", key: "host"},
	{schema: "org.gnome.system.proxy.https", key: "port"},
	{schema: "org.gnome.system.proxy.socks", key: "host"},
	{schema: "org.gnome.system.proxy.socks", key: "port"},
}

var kdeProxyKeys = []string{
	"ProxyType",
	"httpProxy",
	"httpsProxy",
	"socksProxy",
	"NoProxyFor",
}

// LinuxOptions injects OS command and environment lookups for testing Linux desktop integrations.
type LinuxOptions struct {
	RunCmd   func(ctx context.Context, name string, args ...string) (string, error)
	LookPath func(file string) (string, error)
	Getenv   func(key string) string
}

type linuxManager struct {
	runCmd    func(ctx context.Context, name string, args ...string) (string, error)
	lookPath  func(file string) (string, error)
	getenv    func(key string) string
	caps      ProxyCapabilities
	backend   linuxBackend
	kreadBin  string
	kwriteBin string
}

// NewManager returns the Linux SystemProxyManager configured from the process environment.
func NewManager() SystemProxyManager {
	return NewLinuxManager(LinuxOptions{})
}

// NewLinuxManager returns a Linux SystemProxyManager using the provided dependency overrides.
func NewLinuxManager(opts LinuxOptions) SystemProxyManager {
	if opts.RunCmd == nil {
		opts.RunCmd = defaultRunCmd
	}
	if opts.LookPath == nil {
		opts.LookPath = exec.LookPath
	}
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}

	m := &linuxManager{
		runCmd:   opts.RunCmd,
		lookPath: opts.LookPath,
		getenv:   opts.Getenv,
	}
	m.detectBackend()
	return m
}

func defaultRunCmd(ctx context.Context, name string, args ...string) (string, error) {
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

func (m *linuxManager) detectBackend() {
	deName, family := classifyDesktopEnv(
		m.getenv("XDG_CURRENT_DESKTOP"),
		m.getenv("DESKTOP_SESSION"),
		m.getenv("KDE_FULL_SESSION"),
	)

	switch family {
	case backendKDE:
		kread, kwrite, ok := detectKDEBinaries(m.lookPath, 6)
		if ok {
			m.backend = backendKDE
			m.kreadBin = kread
			m.kwriteBin = kwrite
			m.caps = ProxyCapabilities{AutoSupported: true, DesktopEnv: "kde"}
			return
		}
	case backendGNOME:
		if _, err := m.lookPath(gsettingsBin); err == nil {
			m.backend = backendGNOME
			m.caps = ProxyCapabilities{AutoSupported: true, DesktopEnv: deName}
			return
		}
	}

	m.backend = backendManual
	m.caps = ProxyCapabilities{AutoSupported: false, DesktopEnv: DesktopEnvManual}
}

func classifyDesktopEnv(xdgDesktop, desktopSession, kdeFullSession string) (string, linuxBackend) {
	var xdgTokens []string
	for _, part := range strings.Split(xdgDesktop, ":") {
		token := strings.ToLower(strings.TrimSpace(part))
		if token != "" {
			xdgTokens = append(xdgTokens, token)
		}
	}

	if len(xdgTokens) > 0 {
		if hasAnyToken(xdgTokens, "kde", "plasma") {
			return "kde", backendKDE
		}
		if hasAnyToken(xdgTokens, "cinnamon", "x-cinnamon") {
			return "cinnamon", backendGNOME
		}
		if hasAnyToken(xdgTokens, "budgie", "budgie-desktop") {
			return "budgie", backendGNOME
		}
		if hasAnyToken(xdgTokens, "gnome", "ubuntu") {
			return "gnome", backendGNOME
		}
		return DesktopEnvManual, backendManual
	}

	session := strings.ToLower(strings.TrimSpace(desktopSession))
	if session != "" {
		switch {
		case session == "kde" || session == "kde-plasma" || strings.HasPrefix(session, "plasma"):
			return "kde", backendKDE
		case strings.HasPrefix(session, "cinnamon"):
			return "cinnamon", backendGNOME
		case strings.HasPrefix(session, "budgie"):
			return "budgie", backendGNOME
		case strings.HasPrefix(session, "gnome") || strings.HasPrefix(session, "ubuntu"):
			return "gnome", backendGNOME
		default:
			return DesktopEnvManual, backendManual
		}
	}

	kdeFull := strings.ToLower(strings.TrimSpace(kdeFullSession))
	if kdeFull == "true" || kdeFull == "1" {
		return "kde", backendKDE
	}

	return DesktopEnvManual, backendManual
}

func hasAnyToken(tokens []string, candidates ...string) bool {
	for _, token := range tokens {
		for _, cand := range candidates {
			if token == cand {
				return true
			}
		}
	}
	return false
}

func detectKDEBinaries(lookPath func(string) (string, error), preferMajor int) (readBin, writeBin string, ok bool) {
	checkPair := func(r, w string) bool {
		if _, err := lookPath(r); err != nil {
			return false
		}
		if _, err := lookPath(w); err != nil {
			return false
		}
		return true
	}

	if preferMajor == 5 {
		if checkPair(kread5Bin, kwrite5Bin) {
			return kread5Bin, kwrite5Bin, true
		}
		if checkPair(kread6Bin, kwrite6Bin) {
			return kread6Bin, kwrite6Bin, true
		}
		return "", "", false
	}

	if checkPair(kread6Bin, kwrite6Bin) {
		return kread6Bin, kwrite6Bin, true
	}
	if checkPair(kread5Bin, kwrite5Bin) {
		return kread5Bin, kwrite5Bin, true
	}
	return "", "", false
}

func (m *linuxManager) Capabilities() ProxyCapabilities {
	return m.caps
}

func (m *linuxManager) EnvSnippet(socksPort, httpPort int) string {
	return FormatEnvSnippet(socksPort, httpPort)
}

func (m *linuxManager) CaptureSnapshot(ctx context.Context) (ProxySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ProxySnapshot{}, err
	}

	snap := ProxySnapshot{
		Platform:        "linux",
		LinuxDE:         m.caps.DesktopEnv,
		LinuxPrevValues: make(map[string]string),
	}

	switch m.backend {
	case backendGNOME:
		for _, spec := range gnomeProxyKeys {
			val, err := m.runCmd(ctx, gsettingsBin, "get", spec.schema, spec.key)
			if err != nil {
				return ProxySnapshot{}, fmt.Errorf("sysproxy: capture %s %s: %w", spec.schema, spec.key, err)
			}
			snap.LinuxPrevValues[gnomeMapKey(spec)] = val
		}
		return snap, nil

	case backendKDE:
		for _, key := range kdeProxyKeys {
			val, err := m.runCmd(ctx, m.kreadBin, "--file", kdeConfigFile, "--group", kdeProxyGroup, "--key", key)
			if err != nil {
				return ProxySnapshot{}, fmt.Errorf("sysproxy: capture kde key %s: %w", key, err)
			}
			snap.LinuxPrevValues[kdeKeyPrefix+key] = val
		}
		return snap, nil

	default:
		return snap, nil
	}
}

func (m *linuxManager) Enable(ctx context.Context, cfg ProxyApplyConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	norm, err := normalizeApplyConfig(cfg)
	if err != nil {
		return err
	}

	switch m.backend {
	case backendGNOME:
		return m.enableGNOME(ctx, norm)
	case backendKDE:
		return m.enableKDE(ctx, norm)
	default:
		return nil
	}
}

func (m *linuxManager) enableGNOME(ctx context.Context, cfg ProxyApplyConfig) error {
	ignoreHosts := formatGSettingsStringArray(LinuxBypassHosts(cfg.BypassIranLAN))
	updates := [][3]string{
		{"org.gnome.system.proxy", "mode", "'manual'"},
		{"org.gnome.system.proxy.http", "host", formatGSettingsString(cfg.HTTPHost)},
		{"org.gnome.system.proxy.http", "port", strconv.Itoa(cfg.HTTPPort)},
		{"org.gnome.system.proxy.http", "enabled", "true"},
		{"org.gnome.system.proxy.https", "host", formatGSettingsString(cfg.HTTPHost)},
		{"org.gnome.system.proxy.https", "port", strconv.Itoa(cfg.HTTPPort)},
		{"org.gnome.system.proxy.socks", "host", formatGSettingsString(cfg.SOCKSHost)},
		{"org.gnome.system.proxy.socks", "port", strconv.Itoa(cfg.SOCKSPort)},
		{"org.gnome.system.proxy", "ignore-hosts", ignoreHosts},
	}

	for _, u := range updates {
		if _, err := m.runCmd(ctx, gsettingsBin, "set", u[0], u[1], u[2]); err != nil {
			return fmt.Errorf("sysproxy: set %s %s: %w", u[0], u[1], err)
		}
	}
	return nil
}

func (m *linuxManager) enableKDE(ctx context.Context, cfg ProxyApplyConfig) error {
	httpAddr := "http://" + net.JoinHostPort(cfg.HTTPHost, strconv.Itoa(cfg.HTTPPort))
	socksAddr := "socks://" + net.JoinHostPort(cfg.SOCKSHost, strconv.Itoa(cfg.SOCKSPort))
	noProxyFor := strings.Join(LinuxBypassHosts(cfg.BypassIranLAN), ",")

	entries := [][2]string{
		{"ProxyType", "1"},
		{"httpProxy", httpAddr},
		{"httpsProxy", httpAddr},
		{"socksProxy", socksAddr},
		{"NoProxyFor", noProxyFor},
	}

	for _, e := range entries {
		if _, err := m.runCmd(ctx, m.kwriteBin, "--file", kdeConfigFile, "--group", kdeProxyGroup, "--key", e[0], e[1]); err != nil {
			return fmt.Errorf("sysproxy: set kde key %s: %w", e[0], err)
		}
	}

	m.notifyKIO(ctx)
	return nil
}

func (m *linuxManager) Restore(ctx context.Context, snap ProxySnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if snap.Platform != "" && snap.Platform != "linux" {
		return fmt.Errorf("sysproxy: cannot restore %q snapshot on linux", snap.Platform)
	}

	targetDE := strings.ToLower(strings.TrimSpace(snap.LinuxDE))
	if targetDE == "" {
		targetDE = m.caps.DesktopEnv
	}

	switch targetDE {
	case DesktopEnvManual:
		return nil
	case "gnome", "cinnamon", "budgie":
		return m.restoreGNOME(ctx, snap.LinuxPrevValues)
	case "kde", "kde5", "kde6":
		return m.restoreKDE(ctx, targetDE, snap.LinuxPrevValues)
	default:
		return fmt.Errorf("sysproxy: unsupported linux desktop environment %q", snap.LinuxDE)
	}
}

func (m *linuxManager) restoreGNOME(ctx context.Context, prev map[string]string) error {
	if m.backend != backendGNOME {
		if _, err := m.lookPath(gsettingsBin); err != nil {
			return fmt.Errorf("sysproxy: gsettings unavailable for restore: %w", err)
		}
	}

	var errs []error
	for _, spec := range gnomeProxyKeys {
		val := ""
		if prev != nil {
			val = strings.TrimSpace(prev[gnomeMapKey(spec)])
		}
		if val == "" {
			if _, err := m.runCmd(ctx, gsettingsBin, "reset", spec.schema, spec.key); err != nil {
				errs = append(errs, fmt.Errorf("sysproxy: reset %s %s: %w", spec.schema, spec.key, err))
			}
			continue
		}
		if _, err := m.runCmd(ctx, gsettingsBin, "set", spec.schema, spec.key, val); err != nil {
			errs = append(errs, fmt.Errorf("sysproxy: restore %s %s: %w", spec.schema, spec.key, err))
		}
	}
	return errors.Join(errs...)
}

func (m *linuxManager) restoreKDE(ctx context.Context, targetDE string, prev map[string]string) error {
	kwriteBin := m.kwriteBin
	if kwriteBin == "" {
		preferMajor := 6
		if targetDE == "kde5" {
			preferMajor = 5
		}
		_, detectedWrite, ok := detectKDEBinaries(m.lookPath, preferMajor)
		if !ok {
			return errors.New("sysproxy: kwriteconfig unavailable for KDE restore")
		}
		kwriteBin = detectedWrite
	}

	var errs []error
	for _, key := range kdeProxyKeys {
		val := lookupKDEPrevValue(prev, key)
		if val == "" {
			if _, err := m.runCmd(ctx, kwriteBin, "--file", kdeConfigFile, "--group", kdeProxyGroup, "--key", key, "--delete"); err != nil {
				errs = append(errs, fmt.Errorf("sysproxy: delete kde key %s: %w", key, err))
			}
			continue
		}
		if _, err := m.runCmd(ctx, kwriteBin, "--file", kdeConfigFile, "--group", kdeProxyGroup, "--key", key, val); err != nil {
			errs = append(errs, fmt.Errorf("sysproxy: restore kde key %s: %w", key, err))
		}
	}

	m.notifyKIO(ctx)
	return errors.Join(errs...)
}

func (m *linuxManager) notifyKIO(ctx context.Context) {
	if _, err := m.lookPath(dbusSendBin); err != nil {
		return
	}
	// KIO reparse notification is best-effort because headless/test sessions may lack a D-Bus daemon.
	_, _ = m.runCmd(ctx, dbusSendBin, "--type=signal", kdeScheduler, kdeReparseSign, "string:")
}

func gnomeMapKey(spec gsettingsKeySpec) string {
	return spec.schema + "/" + spec.key
}

func lookupKDEPrevValue(prev map[string]string, key string) string {
	if prev == nil {
		return ""
	}
	if v, ok := prev[kdeKeyPrefix+key]; ok {
		return strings.TrimSpace(v)
	}
	if v, ok := prev[key]; ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func formatGSettingsString(s string) string {
	return "'" + s + "'"
}

func formatGSettingsStringArray(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = formatGSettingsString(item)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
