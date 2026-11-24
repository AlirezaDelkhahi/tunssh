//go:build linux

package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type recordedCmd struct {
	name string
	args []string
}

func (c recordedCmd) String() string {
	return c.name + " " + strings.Join(c.args, " ")
}

type fakeDesktopEnv struct {
	env           map[string]string
	bins          map[string]bool
	gsettingsData map[string]string
	gsettingsDefs map[string]string
	kdeData       map[string]string
	calls         []recordedCmd
	failCmd       func(name string, args ...string) error
}

func newFakeDesktopEnv() *fakeDesktopEnv {
	return &fakeDesktopEnv{
		env:  make(map[string]string),
		bins: make(map[string]bool),
		gsettingsData: map[string]string{
			"org.gnome.system.proxy/mode":           "'none'",
			"org.gnome.system.proxy/autoconfig-url": "''",
			"org.gnome.system.proxy/ignore-hosts":   "['localhost', '127.0.0.0/8', '::1']",
			"org.gnome.system.proxy.http/host":      "''",
			"org.gnome.system.proxy.http/port":      "0",
			"org.gnome.system.proxy.http/enabled":   "false",
			"org.gnome.system.proxy.https/host":     "''",
			"org.gnome.system.proxy.https/port":     "0",
			"org.gnome.system.proxy.socks/host":     "''",
			"org.gnome.system.proxy.socks/port":     "0",
		},
		gsettingsDefs: map[string]string{
			"org.gnome.system.proxy/mode":           "'none'",
			"org.gnome.system.proxy/autoconfig-url": "''",
			"org.gnome.system.proxy/ignore-hosts":   "['localhost', '127.0.0.0/8', '::1']",
			"org.gnome.system.proxy.http/host":      "''",
			"org.gnome.system.proxy.http/port":      "0",
			"org.gnome.system.proxy.http/enabled":   "false",
			"org.gnome.system.proxy.https/host":     "''",
			"org.gnome.system.proxy.https/port":     "0",
			"org.gnome.system.proxy.socks/host":     "''",
			"org.gnome.system.proxy.socks/port":     "0",
		},
		kdeData: make(map[string]string),
	}
}

func (f *fakeDesktopEnv) opts() LinuxOptions {
	return LinuxOptions{
		Getenv: func(key string) string {
			return f.env[key]
		},
		LookPath: func(file string) (string, error) {
			if f.bins[file] {
				return "/usr/bin/" + file, nil
			}
			return "", errors.New("executable file not found in $PATH")
		},
		RunCmd: func(_ context.Context, name string, args ...string) (string, error) {
			f.calls = append(f.calls, recordedCmd{
				name: name,
				args: slices.Clone(args),
			})
			if f.failCmd != nil {
				if err := f.failCmd(name, args...); err != nil {
					return "", err
				}
			}

			switch name {
			case "gsettings":
				return f.handleGSettings(args...)
			case "kreadconfig6", "kreadconfig5":
				return f.handleKReadConfig(args...)
			case "kwriteconfig6", "kwriteconfig5":
				return "", f.handleKWriteConfig(args...)
			case "dbus-send":
				return "", nil
			default:
				return "", errors.New("unexpected command: " + name)
			}
		},
	}
}

func (f *fakeDesktopEnv) handleGSettings(args ...string) (string, error) {
	if len(args) < 3 {
		return "", errors.New("invalid gsettings args")
	}
	sub := args[0]
	key := args[1] + "/" + args[2]
	switch sub {
	case "get":
		v, ok := f.gsettingsData[key]
		if !ok {
			return "", errors.New("unknown gsettings key: " + key)
		}
		return v, nil
	case "set":
		if len(args) != 4 {
			return "", errors.New("gsettings set requires 4 args")
		}
		if args[3] == "" {
			return "", errors.New("gsettings set received empty GVariant string")
		}
		f.gsettingsData[key] = args[3]
		return "", nil
	case "reset":
		def, ok := f.gsettingsDefs[key]
		if !ok {
			return "", errors.New("unknown gsettings key: " + key)
		}
		f.gsettingsData[key] = def
		return "", nil
	default:
		return "", errors.New("unknown gsettings subcommand: " + sub)
	}
}

func (f *fakeDesktopEnv) handleKReadConfig(args ...string) (string, error) {
	key, _, _, err := parseKConfigArgs(args, false)
	if err != nil {
		return "", err
	}
	return f.kdeData[key], nil
}

func (f *fakeDesktopEnv) handleKWriteConfig(args ...string) error {
	key, val, del, err := parseKConfigArgs(args, true)
	if err != nil {
		return err
	}
	if del {
		delete(f.kdeData, key)
		return nil
	}
	f.kdeData[key] = val
	return nil
}

func parseKConfigArgs(args []string, isWrite bool) (key, val string, del bool, err error) {
	var file, group string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--file":
			i++
			if i >= len(args) {
				return "", "", false, errors.New("missing --file value")
			}
			file = args[i]
		case "--group":
			i++
			if i >= len(args) {
				return "", "", false, errors.New("missing --group value")
			}
			group = args[i]
		case "--key":
			i++
			if i >= len(args) {
				return "", "", false, errors.New("missing --key value")
			}
			key = args[i]
		case "--delete":
			del = true
		default:
			if !isWrite || strings.HasPrefix(args[i], "--") || i != len(args)-1 {
				return "", "", false, errors.New("unexpected kconfig arg: " + args[i])
			}
			val = args[i]
		}
	}
	if file != "kioslaverc" || group != "Proxy Settings" || key == "" {
		return "", "", false, errors.New("unexpected file/group/key in kconfig call")
	}
	if isWrite && !del && val == "" {
		return "", "", false, errors.New("kwriteconfig missing value")
	}
	return key, val, del, nil
}

func cloneStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestFormatEnvSnippet(t *testing.T) {
	gotDefault := FormatEnvSnippet(10808, 10809)
	wantDefault := "export ALL_PROXY=socks5h://127.0.0.1:10808 HTTP_PROXY=http://127.0.0.1:10809 HTTPS_PROXY=http://127.0.0.1:10809"
	if gotDefault != wantDefault {
		t.Fatalf("FormatEnvSnippet(10808, 10809) = %q, want %q", gotDefault, wantDefault)
	}

	gotCustom := FormatEnvSnippet(20808, 20809)
	wantCustom := "export ALL_PROXY=socks5h://127.0.0.1:20808 HTTP_PROXY=http://127.0.0.1:20809 HTTPS_PROXY=http://127.0.0.1:20809"
	if gotCustom != wantCustom {
		t.Fatalf("FormatEnvSnippet(20808, 20809) = %q, want %q", gotCustom, wantCustom)
	}

	// Zero / invalid ports fall back safely to standard loopback ports.
	if gotZero := FormatEnvSnippet(0, 0); gotZero != wantDefault {
		t.Fatalf("FormatEnvSnippet(0, 0) = %q, want %q", gotZero, wantDefault)
	}
	if gotInvalid := FormatEnvSnippet(-1, 70000); gotInvalid != wantDefault {
		t.Fatalf("FormatEnvSnippet(-1, 70000) = %q, want %q", gotInvalid, wantDefault)
	}

	// Verify manager EnvSnippet delegates cleanly.
	mgr := NewLinuxManager(newFakeDesktopEnv().opts())
	if gotMgr := mgr.EnvSnippet(10808, 10809); gotMgr != wantDefault {
		t.Fatalf("mgr.EnvSnippet(10808, 10809) = %q, want %q", gotMgr, wantDefault)
	}
}

func TestBypassHelpersAndSnapshotJSON(t *testing.T) {
	if IranSuffix != "*.ir" {
		t.Fatalf("IranSuffix = %q, want %q", IranSuffix, "*.ir")
	}
	wantCIDRs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if !reflect.DeepEqual(DefaultBypassCIDRs, wantCIDRs) {
		t.Fatalf("DefaultBypassCIDRs = %v, want %v", DefaultBypassCIDRs, wantCIDRs)
	}

	winNoBypass := WindowsProxyOverride(false)
	wantWinNoBypass := "localhost;127.*;<local>"
	if winNoBypass != wantWinNoBypass {
		t.Fatalf("WindowsProxyOverride(false) = %q, want %q", winNoBypass, wantWinNoBypass)
	}

	winBypass := WindowsProxyOverride(true)
	wantWinBypass := "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;*.ir;<local>"
	if winBypass != wantWinBypass {
		t.Fatalf("WindowsProxyOverride(true) = %q, want %q", winBypass, wantWinBypass)
	}

	snap := ProxySnapshot{
		Platform:         "windows",
		WinProxyEnable:   1,
		WinProxyServer:   "127.0.0.1:10809",
		WinProxyOverride: wantWinBypass,
		WinAutoConfigURL: "",
		LinuxDE:          "gnome",
		LinuxPrevValues:  map[string]string{},
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal ProxySnapshot: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal ProxySnapshot: %v", err)
	}
	for _, requiredKey := range []string{
		"platform",
		"win_proxy_enable",
		"win_proxy_server",
		"win_proxy_override",
		"win_auto_config_url",
		"linux_de",
		"linux_prev_values",
	} {
		if _, ok := m[requiredKey]; !ok {
			t.Fatalf("ProxySnapshot JSON missing key %q in %s", requiredKey, string(raw))
		}
	}
	for _, omittedKey := range []string{
		"win_proxy_enable_set",
		"win_proxy_server_set",
		"win_proxy_override_set",
		"win_auto_config_url_set",
	} {
		if _, ok := m[omittedKey]; ok {
			t.Fatalf("ProxySnapshot JSON expected omitempty key %q to be omitted when false", omittedKey)
		}
	}
}

func TestGNOMESnapshotEnableAndIdempotentRestore(t *testing.T) {
	ctx := context.Background()

	t.Run("gnome_cinnamon_budgie_detection", func(t *testing.T) {
		cases := []struct {
			name    string
			xdg     string
			session string
			wantDE  string
		}{
			{name: "ubuntu_gnome", xdg: "ubuntu:GNOME", wantDE: "gnome"},
			{name: "cinnamon", xdg: "X-Cinnamon", wantDE: "cinnamon"},
			{name: "budgie", xdg: "Budgie:GNOME", wantDE: "budgie"},
			{name: "session_only_gnome", session: "gnome-xorg", wantDE: "gnome"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fake := newFakeDesktopEnv()
				fake.bins["gsettings"] = true
				fake.env["XDG_CURRENT_DESKTOP"] = tc.xdg
				fake.env["DESKTOP_SESSION"] = tc.session

				mgr := NewLinuxManager(fake.opts())
				caps := mgr.Capabilities()
				if !caps.AutoSupported {
					t.Fatalf("expected AutoSupported=true, got false (caps=%+v)", caps)
				}
				if caps.DesktopEnv != tc.wantDE {
					t.Fatalf("DesktopEnv = %q, want %q", caps.DesktopEnv, tc.wantDE)
				}
			})
		}
	})

	t.Run("snapshot_enable_with_and_without_bypass_and_idempotent_restore", func(t *testing.T) {
		fake := newFakeDesktopEnv()
		fake.bins["gsettings"] = true
		fake.env["XDG_CURRENT_DESKTOP"] = "ubuntu:GNOME"
		// Pre-existing custom settings to verify non-default restore fidelity.
		fake.gsettingsData["org.gnome.system.proxy/mode"] = "'auto'"
		fake.gsettingsData["org.gnome.system.proxy/autoconfig-url"] = "'http://pac.corp.local/proxy.pac'"
		fake.gsettingsData["org.gnome.system.proxy/ignore-hosts"] = "['localhost', '127.0.0.0/8']"
		fake.gsettingsData["org.gnome.system.proxy.http/host"] = "'old-http.local'"
		fake.gsettingsData["org.gnome.system.proxy.http/port"] = "3128"
		fake.gsettingsData["org.gnome.system.proxy.http/enabled"] = "false"
		fake.gsettingsData["org.gnome.system.proxy.https/host"] = "'old-https.local'"
		fake.gsettingsData["org.gnome.system.proxy.https/port"] = "3129"
		fake.gsettingsData["org.gnome.system.proxy.socks/host"] = "'old-socks.local'"
		fake.gsettingsData["org.gnome.system.proxy.socks/port"] = "1080"
		origState := cloneStringMap(fake.gsettingsData)

		mgr := NewLinuxManager(fake.opts())
		snap, err := mgr.CaptureSnapshot(ctx)
		if err != nil {
			t.Fatalf("CaptureSnapshot failed: %v", err)
		}
		if snap.Platform != "linux" || snap.LinuxDE != "gnome" {
			t.Fatalf("unexpected snapshot metadata: %+v", snap)
		}

		// Enable with BypassIranLAN == false.
		err = mgr.Enable(ctx, ProxyApplyConfig{
			SOCKSHost:     "127.0.0.1",
			SOCKSPort:     10808,
			HTTPHost:      "127.0.0.1",
			HTTPPort:      10809,
			BypassIranLAN: false,
		})
		if err != nil {
			t.Fatalf("Enable(BypassIranLAN=false) failed: %v", err)
		}

		wantNoBypass := map[string]string{
			"org.gnome.system.proxy/mode":           "'manual'",
			"org.gnome.system.proxy/autoconfig-url": "'http://pac.corp.local/proxy.pac'",
			"org.gnome.system.proxy/ignore-hosts":   "['localhost', '127.0.0.0/8', '::1']",
			"org.gnome.system.proxy.http/host":      "'127.0.0.1'",
			"org.gnome.system.proxy.http/port":      "10809",
			"org.gnome.system.proxy.http/enabled":   "true",
			"org.gnome.system.proxy.https/host":     "'127.0.0.1'",
			"org.gnome.system.proxy.https/port":     "10809",
			"org.gnome.system.proxy.socks/host":     "'127.0.0.1'",
			"org.gnome.system.proxy.socks/port":     "10808",
		}
		if !reflect.DeepEqual(fake.gsettingsData, wantNoBypass) {
			t.Fatalf("gsettings state after Enable(false):\ngot:  %v\nwant: %v", fake.gsettingsData, wantNoBypass)
		}

		// Enable with BypassIranLAN == true.
		err = mgr.Enable(ctx, ProxyApplyConfig{
			SOCKSHost:     "127.0.0.1",
			SOCKSPort:     10808,
			HTTPHost:      "127.0.0.1",
			HTTPPort:      10809,
			BypassIranLAN: true,
		})
		if err != nil {
			t.Fatalf("Enable(BypassIranLAN=true) failed: %v", err)
		}
		wantIgnoreBypass := "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '*.ir']"
		if fake.gsettingsData["org.gnome.system.proxy/ignore-hosts"] != wantIgnoreBypass {
			t.Fatalf("ignore-hosts with BypassIranLAN=true = %q, want %q",
				fake.gsettingsData["org.gnome.system.proxy/ignore-hosts"], wantIgnoreBypass)
		}

		// Restore first time.
		if err := mgr.Restore(ctx, snap); err != nil {
			t.Fatalf("first Restore failed: %v", err)
		}
		if !reflect.DeepEqual(fake.gsettingsData, origState) {
			t.Fatalf("gsettings state after first Restore:\ngot:  %v\nwant: %v", fake.gsettingsData, origState)
		}

		// Restore second time (idempotency check).
		if err := mgr.Restore(ctx, snap); err != nil {
			t.Fatalf("second Restore failed: %v", err)
		}
		if !reflect.DeepEqual(fake.gsettingsData, origState) {
			t.Fatalf("gsettings state after second Restore:\ngot:  %v\nwant: %v", fake.gsettingsData, origState)
		}
	})

	t.Run("restore_resets_empty_and_missing_values_safely", func(t *testing.T) {
		fake := newFakeDesktopEnv()
		fake.bins["gsettings"] = true
		fake.env["XDG_CURRENT_DESKTOP"] = "GNOME"
		// Simulate dirty proxy state before restore.
		fake.gsettingsData["org.gnome.system.proxy/mode"] = "'manual'"
		fake.gsettingsData["org.gnome.system.proxy/ignore-hosts"] = "['localhost', '*.ir']"
		fake.gsettingsData["org.gnome.system.proxy.http/host"] = "'127.0.0.1'"
		fake.gsettingsData["org.gnome.system.proxy.http/port"] = "10809"
		fake.gsettingsData["org.gnome.system.proxy.http/enabled"] = "true"

		mgr := NewLinuxManager(fake.opts())
		// Snapshot containing empty strings and missing keys (e.g. from partial/empty recovery state).
		emptySnap := ProxySnapshot{
			Platform: "linux",
			LinuxDE:  "gnome",
			LinuxPrevValues: map[string]string{
				"org.gnome.system.proxy/mode":      "",
				"org.gnome.system.proxy.http/host": "",
			},
		}
		if err := mgr.Restore(ctx, emptySnap); err != nil {
			t.Fatalf("Restore(emptySnap) failed: %v", err)
		}
		if !reflect.DeepEqual(fake.gsettingsData, fake.gsettingsDefs) {
			t.Fatalf("expected all keys reset to schema defaults:\ngot:  %v\nwant: %v", fake.gsettingsData, fake.gsettingsDefs)
		}

		// Verify `gsettings reset` was actually used instead of invalid `gsettings set ... ""`.
		var sawReset bool
		for _, c := range fake.calls {
			if c.name == "gsettings" && len(c.args) > 0 && c.args[0] == "reset" {
				sawReset = true
			}
		}
		if !sawReset {
			t.Fatal("expected Restore on empty/missing keys to invoke `gsettings reset`")
		}
	})
}

func TestKDEPlasma6AndPlasma5SnapshotEnableRestore(t *testing.T) {
	ctx := context.Background()

	t.Run("plasma6_preferred_over_plasma5_and_reparse_signal", func(t *testing.T) {
		fake := newFakeDesktopEnv()
		fake.bins["kwriteconfig6"] = true
		fake.bins["kreadconfig6"] = true
		fake.bins["kwriteconfig5"] = true
		fake.bins["kreadconfig5"] = true
		fake.bins["dbus-send"] = true
		fake.env["XDG_CURRENT_DESKTOP"] = "KDE"

		// Pre-existing ProxyType=0; other keys unset (missing in kioslaverc).
		fake.kdeData["ProxyType"] = "0"

		mgr := NewLinuxManager(fake.opts())
		caps := mgr.Capabilities()
		if !caps.AutoSupported || caps.DesktopEnv != "kde" {
			t.Fatalf("unexpected KDE caps: %+v", caps)
		}

		snap, err := mgr.CaptureSnapshot(ctx)
		if err != nil {
			t.Fatalf("CaptureSnapshot failed: %v", err)
		}
		if snap.Platform != "linux" || snap.LinuxDE != "kde" {
			t.Fatalf("unexpected KDE snapshot: %+v", snap)
		}

		// Verify kreadconfig6 was used, not kreadconfig5.
		for _, c := range fake.calls {
			if c.name == "kreadconfig5" {
				t.Fatalf("unexpected call to kreadconfig5 when Plasma 6 tools exist: %s", c.String())
			}
		}

		// Enable without Iran/LAN bypass.
		fake.calls = nil
		err = mgr.Enable(ctx, ProxyApplyConfig{
			SOCKSHost:     "127.0.0.1",
			SOCKSPort:     10808,
			HTTPHost:      "127.0.0.1",
			HTTPPort:      10809,
			BypassIranLAN: false,
		})
		if err != nil {
			t.Fatalf("Enable(false) failed: %v", err)
		}
		wantKDE := map[string]string{
			"ProxyType":  "1",
			"httpProxy":  "http://127.0.0.1:10809",
			"httpsProxy": "http://127.0.0.1:10809",
			"socksProxy": "socks://127.0.0.1:10808",
			"NoProxyFor": "localhost,127.0.0.0/8,::1",
		}
		if !reflect.DeepEqual(fake.kdeData, wantKDE) {
			t.Fatalf("kdeData after Enable(false):\ngot:  %v\nwant: %v", fake.kdeData, wantKDE)
		}

		// Verify kwriteconfig6 and dbus-send reparseConfiguration were called.
		var sawWrite6, sawDBus bool
		for _, c := range fake.calls {
			if c.name == "kwriteconfig6" {
				sawWrite6 = true
			}
			if c.name == "kwriteconfig5" {
				t.Fatalf("unexpected kwriteconfig5 call when Plasma 6 exists: %s", c.String())
			}
			if c.name == "dbus-send" {
				wantArgs := []string{
					"--type=signal",
					"/KIO/Scheduler",
					"org.kde.KIO.Scheduler.reparseConfiguration",
					"string:",
				}
				if !reflect.DeepEqual(c.args, wantArgs) {
					t.Fatalf("dbus-send args = %v, want %v", c.args, wantArgs)
				}
				sawDBus = true
			}
		}
		if !sawWrite6 || !sawDBus {
			t.Fatalf("expected kwriteconfig6 (%v) and dbus-send (%v) calls", sawWrite6, sawDBus)
		}

		// Enable with BypassIranLAN == true.
		err = mgr.Enable(ctx, ProxyApplyConfig{
			SOCKSHost:     "127.0.0.1",
			SOCKSPort:     10808,
			HTTPHost:      "127.0.0.1",
			HTTPPort:      10809,
			BypassIranLAN: true,
		})
		if err != nil {
			t.Fatalf("Enable(true) failed: %v", err)
		}
		wantNoProxy := "localhost,127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,*.ir"
		if fake.kdeData["NoProxyFor"] != wantNoProxy {
			t.Fatalf("NoProxyFor = %q, want %q", fake.kdeData["NoProxyFor"], wantNoProxy)
		}

		// Restore: ProxyType should be 0, unset keys deleted via --delete, and dbus-send invoked.
		fake.calls = nil
		if err := mgr.Restore(ctx, snap); err != nil {
			t.Fatalf("Restore failed: %v", err)
		}
		wantRestored := map[string]string{"ProxyType": "0"}
		if !reflect.DeepEqual(fake.kdeData, wantRestored) {
			t.Fatalf("kdeData after Restore:\ngot:  %v\nwant: %v", fake.kdeData, wantRestored)
		}
		var deleteCount int
		var sawRestoreDBus bool
		for _, c := range fake.calls {
			if c.name == "kwriteconfig6" && slices.Contains(c.args, "--delete") {
				deleteCount++
			}
			if c.name == "dbus-send" {
				sawRestoreDBus = true
			}
		}
		if deleteCount != 4 {
			t.Fatalf("expected 4 --delete calls for unset KDE keys, got %d", deleteCount)
		}
		if !sawRestoreDBus {
			t.Fatal("expected dbus-send reparseConfiguration after Restore")
		}

		// Idempotent second restore.
		if err := mgr.Restore(ctx, snap); err != nil {
			t.Fatalf("second Restore failed: %v", err)
		}
		if !reflect.DeepEqual(fake.kdeData, wantRestored) {
			t.Fatalf("kdeData after second Restore = %v, want %v", fake.kdeData, wantRestored)
		}
	})

	t.Run("plasma5_fallback_when_plasma6_missing", func(t *testing.T) {
		fake := newFakeDesktopEnv()
		fake.bins["kwriteconfig5"] = true
		fake.bins["kreadconfig5"] = true
		// Even without dbus-send, KDE Enable/Restore succeeds cleanly.
		fake.env["KDE_FULL_SESSION"] = "true"
		fake.env["DESKTOP_SESSION"] = "plasma"
		fake.kdeData["ProxyType"] = "2"
		fake.kdeData["httpProxy"] = "http://10.0.0.2:8080"
		orig := cloneStringMap(fake.kdeData)

		mgr := NewLinuxManager(fake.opts())
		caps := mgr.Capabilities()
		if !caps.AutoSupported || caps.DesktopEnv != "kde" {
			t.Fatalf("unexpected Plasma 5 caps: %+v", caps)
		}

		snap, err := mgr.CaptureSnapshot(ctx)
		if err != nil {
			t.Fatalf("CaptureSnapshot failed: %v", err)
		}
		if err := mgr.Enable(ctx, ProxyApplyConfig{
			SOCKSPort:     10808,
			HTTPPort:      10809,
			BypassIranLAN: true,
		}); err != nil {
			t.Fatalf("Enable failed: %v", err)
		}

		var sawRead5, sawWrite5 bool
		for _, c := range fake.calls {
			if c.name == "kreadconfig5" {
				sawRead5 = true
			}
			if c.name == "kwriteconfig5" {
				sawWrite5 = true
			}
			if c.name == "dbus-send" {
				t.Fatal("did not expect dbus-send call when dbus-send binary is absent")
			}
		}
		if !sawRead5 || !sawWrite5 {
			t.Fatalf("expected kreadconfig5 (%v) and kwriteconfig5 (%v) calls", sawRead5, sawWrite5)
		}

		if err := mgr.Restore(ctx, snap); err != nil {
			t.Fatalf("Restore failed: %v", err)
		}
		if !reflect.DeepEqual(fake.kdeData, orig) {
			t.Fatalf("Plasma 5 restore mismatch:\ngot:  %v\nwant: %v", fake.kdeData, orig)
		}
	})

	t.Run("dbus_send_failure_is_best_effort", func(t *testing.T) {
		fake := newFakeDesktopEnv()
		fake.bins["kwriteconfig6"] = true
		fake.bins["kreadconfig6"] = true
		fake.bins["dbus-send"] = true
		fake.env["XDG_CURRENT_DESKTOP"] = "KDE"
		fake.failCmd = func(name string, _ ...string) error {
			if name == "dbus-send" {
				return errors.New("no dbus session")
			}
			return nil
		}

		mgr := NewLinuxManager(fake.opts())
		snap, err := mgr.CaptureSnapshot(ctx)
		if err != nil {
			t.Fatalf("CaptureSnapshot failed: %v", err)
		}
		if err := mgr.Enable(ctx, ProxyApplyConfig{SOCKSPort: 10808, HTTPPort: 10809}); err != nil {
			t.Fatalf("Enable should ignore dbus-send failure, got: %v", err)
		}
		if err := mgr.Restore(ctx, snap); err != nil {
			t.Fatalf("Restore should ignore dbus-send failure, got: %v", err)
		}
	})
}

func TestTilingWMAndHeadlessFallback(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name      string
		xdg       string
		session   string
		kdeFull   string
		withTools bool
	}{
		{name: "sway_with_gsettings_installed", xdg: "sway", withTools: true},
		{name: "hyprland_with_tools_installed", xdg: "Hyprland", withTools: true},
		{name: "i3_session", session: "i3", withTools: true},
		{name: "xfce", xdg: "XFCE", withTools: true},
		{name: "headless_empty_env", withTools: false},
		{name: "gnome_missing_gsettings", xdg: "GNOME", withTools: false},
		{name: "kde_missing_kwriteconfig", xdg: "KDE", kdeFull: "true", withTools: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDesktopEnv()
			fake.env["XDG_CURRENT_DESKTOP"] = tc.xdg
			fake.env["DESKTOP_SESSION"] = tc.session
			fake.env["KDE_FULL_SESSION"] = tc.kdeFull
			if tc.withTools {
				fake.bins["gsettings"] = true
				fake.bins["kwriteconfig6"] = true
				fake.bins["kreadconfig6"] = true
			}

			mgr := NewLinuxManager(fake.opts())
			caps := mgr.Capabilities()
			if caps.AutoSupported {
				t.Fatalf("expected AutoSupported=false, got true (caps=%+v)", caps)
			}
			if caps.DesktopEnv != "manual-env" {
				t.Fatalf("DesktopEnv = %q, want %q", caps.DesktopEnv, "manual-env")
			}

			snap, err := mgr.CaptureSnapshot(ctx)
			if err != nil {
				t.Fatalf("CaptureSnapshot failed: %v", err)
			}
			if snap.Platform != "linux" || snap.LinuxDE != "manual-env" {
				t.Fatalf("unexpected manual-env snapshot: %+v", snap)
			}
			if err := mgr.Enable(ctx, ProxyApplyConfig{SOCKSPort: 10808, HTTPPort: 10809, BypassIranLAN: true}); err != nil {
				t.Fatalf("Enable should be clean no-op, got: %v", err)
			}
			if err := mgr.Restore(ctx, snap); err != nil {
				t.Fatalf("Restore should be clean no-op, got: %v", err)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("expected zero external command calls in manual-env mode, got: %v", fake.calls)
			}
		})
	}
}

func TestValidationAndErrorPropagation(t *testing.T) {
	ctx := context.Background()

	fake := newFakeDesktopEnv()
	fake.bins["gsettings"] = true
	fake.env["XDG_CURRENT_DESKTOP"] = "GNOME"
	mgr := NewLinuxManager(fake.opts())

	// Reject out-of-range ports and unsafe host strings.
	invalidConfigs := []ProxyApplyConfig{
		{SOCKSPort: -1, HTTPPort: 10809},
		{SOCKSPort: 70000, HTTPPort: 10809},
		{SOCKSPort: 10808, HTTPPort: -1},
		{SOCKSPort: 10808, HTTPPort: 65536},
		{HTTPHost: "127.0.0.1'", HTTPPort: 10809, SOCKSPort: 10808},
		{SOCKSHost: "127.0.0.1\n", HTTPPort: 10809, SOCKSPort: 10808},
		{HTTPHost: "127.0.0.1;rm -rf /", HTTPPort: 10809, SOCKSPort: 10808},
	}
	for _, cfg := range invalidConfigs {
		if err := mgr.Enable(ctx, cfg); err == nil {
			t.Fatalf("expected error for invalid config %+v", cfg)
		}
	}

	// Reject restoring a Windows snapshot on Linux.
	if err := mgr.Restore(ctx, ProxySnapshot{Platform: "windows"}); err == nil {
		t.Fatal("expected error when restoring windows snapshot on linux")
	}

	// Propagate canceled context.
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := mgr.CaptureSnapshot(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from CaptureSnapshot, got %v", err)
	}
	if err := mgr.Enable(canceledCtx, ProxyApplyConfig{SOCKSPort: 10808, HTTPPort: 10809}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from Enable, got %v", err)
	}
	if err := mgr.Restore(canceledCtx, ProxySnapshot{Platform: "linux", LinuxDE: "gnome"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from Restore, got %v", err)
	}

	// Propagate command failure on gsettings get.
	fake.failCmd = func(name string, args ...string) error {
		if name == "gsettings" && len(args) > 0 && args[0] == "get" {
			return errors.New("dconf unavailable")
		}
		return nil
	}
	if _, err := mgr.CaptureSnapshot(ctx); err == nil {
		t.Fatal("expected CaptureSnapshot to propagate gsettings error")
	}

	// Propagate KDE kreadconfig/kwriteconfig failures.
	kdeFake := newFakeDesktopEnv()
	kdeFake.bins["kreadconfig6"] = true
	kdeFake.bins["kwriteconfig6"] = true
	kdeFake.env["XDG_CURRENT_DESKTOP"] = "KDE"
	kdeFake.failCmd = func(name string, _ ...string) error {
		if name == "kreadconfig6" || name == "kwriteconfig6" {
			return errors.New("kconfig IO error")
		}
		return nil
	}
	kdeMgr := NewLinuxManager(kdeFake.opts())
	if _, err := kdeMgr.CaptureSnapshot(ctx); err == nil {
		t.Fatal("expected CaptureSnapshot to propagate kreadconfig6 error")
	}
	if err := kdeMgr.Enable(ctx, ProxyApplyConfig{}); err == nil {
		t.Fatal("expected Enable to propagate kwriteconfig6 error")
	}
	if err := kdeMgr.Restore(ctx, ProxySnapshot{Platform: "linux", LinuxDE: "kde"}); err == nil {
		t.Fatal("expected Restore to propagate kwriteconfig6 error")
	}
}

func TestDefaultConfigAndZeroSnapshotBehavior(t *testing.T) {
	ctx := context.Background()

	// Verify NewManager returns a valid implementation on Linux without panicking.
	realMgr := NewManager()
	if realMgr == nil {
		t.Fatal("NewManager() returned nil")
	}
	if realMgr.EnvSnippet(10808, 10809) == "" {
		t.Fatal("NewManager().EnvSnippet returned empty string")
	}

	// Zero host/port in ProxyApplyConfig should apply 127.0.0.1:10808 / 127.0.0.1:10809 defaults.
	fake := newFakeDesktopEnv()
	fake.bins["kreadconfig6"] = true
	fake.bins["kwriteconfig6"] = true
	fake.env["XDG_CURRENT_DESKTOP"] = "KDE"
	mgr := NewLinuxManager(fake.opts())

	if err := mgr.Enable(ctx, ProxyApplyConfig{BypassIranLAN: true}); err != nil {
		t.Fatalf("Enable with default config failed: %v", err)
	}
	if fake.kdeData["httpProxy"] != "http://127.0.0.1:10809" {
		t.Fatalf("httpProxy = %q, want http://127.0.0.1:10809", fake.kdeData["httpProxy"])
	}
	if fake.kdeData["socksProxy"] != "socks://127.0.0.1:10808" {
		t.Fatalf("socksProxy = %q, want socks://127.0.0.1:10808", fake.kdeData["socksProxy"])
	}

	// Restoring an empty ProxySnapshot{} on KDE safely deletes all proxy keys.
	if err := mgr.Restore(ctx, ProxySnapshot{}); err != nil {
		t.Fatalf("Restore(ProxySnapshot{}) failed: %v", err)
	}
	if len(fake.kdeData) != 0 {
		t.Fatalf("expected empty kdeData after zero-snapshot restore, got: %v", fake.kdeData)
	}

	// Verify ProxySnapshot JSON round-trip preserves Windows *Set flags when true.
	orig := ProxySnapshot{
		Platform:            "windows",
		WinProxyEnable:      1,
		WinProxyEnableSet:   true,
		WinProxyServer:      "127.0.0.1:8080",
		WinProxyServerSet:   true,
		WinProxyOverride:    "localhost;<local>",
		WinProxyOverrideSet: true,
		WinAutoConfigURL:    "http://pac.local/wpad.dat",
		WinAutoConfigURLSet: true,
		LinuxDE:             "",
		LinuxPrevValues:     map[string]string{},
	}
	encoded, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var decoded ProxySnapshot
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if !reflect.DeepEqual(decoded, orig) {
		t.Fatalf("ProxySnapshot JSON round-trip mismatch:\ngot:  %+v\nwant: %+v", decoded, orig)
	}
}
