//go:build linux && !android

package splitroute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxDNSConfiguratorSystemdResolved(t *testing.T) {
	ctx := context.Background()
	var cmds []string
	tunGoneOnSecondRestore := false

	dns := newLinuxDNSConfigurator(LinuxOptions{
		LookPath: func(file string) (string, error) {
			if file == "resolvectl" || file == "systemctl" {
				return "/usr/bin/" + file, nil
			}
			return "", errors.New("not found")
		},
		RunCmd: func(_ context.Context, name string, args ...string) (string, error) {
			cmd := name + " " + strings.Join(args, " ")
			cmds = append(cmds, cmd)
			switch {
			case cmd == "systemctl is-active systemd-resolved":
				return "active", nil
			case cmd == "resolvectl dns":
				return "Global:\nLink 2 (eth0): 127.0.0.53 192.168.1.1 8.8.8.8#dns.google\nLink 3 (wlan0): 10.0.0.2\n", nil
			case cmd == "resolvectl default-route":
				return "Global: no\nLink 2 (eth0): yes\nLink 3 (wlan0): no\n", nil
			case cmd == "resolvectl revert tunssh0":
				if tunGoneOnSecondRestore {
					return "", errors.New("resolvectl revert tunssh0: exit status 1 (Unknown interface tunssh0)")
				}
				return "", nil
			default:
				return "", nil
			}
		},
	})

	strategy, origDNS, winBackups, linuxBackups, resolvBak, err := dns.CaptureDNS(ctx, "eth0", 2)
	if err != nil {
		t.Fatalf("CaptureDNS failed: %v", err)
	}
	if strategy != dnsStrategySystemdResolved {
		t.Fatalf("strategy = %q, want %q", strategy, dnsStrategySystemdResolved)
	}
	if len(winBackups) != 0 || resolvBak != "" {
		t.Fatalf("expected empty winBackups/resolvBak, got %v / %q", winBackups, resolvBak)
	}
	wantOrig := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("8.8.8.8")}
	if !slices.Equal(origDNS, wantOrig) {
		t.Fatalf("origDNS = %v, want %v", origDNS, wantOrig)
	}
	if len(linuxBackups) != 2 || linuxBackups[0].IfName != "eth0" || !linuxBackups[0].DefaultRoute || linuxBackups[1].IfName != "wlan0" || linuxBackups[1].DefaultRoute {
		t.Fatalf("unexpected linuxBackups: %+v", linuxBackups)
	}

	snap := NetworkSnapshot{
		OrigIfaceName:   "eth0",
		OrigIfaceIndex:  2,
		TUNIfaceName:    TUNIfaceName,
		DNSStrategy:     strategy,
		LinuxDNSBackups: linuxBackups,
	}

	cmds = nil
	if err := dns.ApplyTUNDNS(ctx, snap, netip.MustParseAddr(TUNDNSServer)); err != nil {
		t.Fatalf("ApplyTUNDNS failed: %v", err)
	}
	wantApply := []string{
		"resolvectl default-route eth0 false",
		"resolvectl default-route wlan0 false",
		"resolvectl dns tunssh0 198.18.0.2",
		"resolvectl domain tunssh0 ~.",
		"resolvectl default-route tunssh0 true",
	}
	if !slices.Equal(cmds, wantApply) {
		t.Fatalf("ApplyTUNDNS commands mismatch:\ngot:  %v\nwant: %v", cmds, wantApply)
	}

	cmds = nil
	if err := dns.RestoreDNS(ctx, snap); err != nil {
		t.Fatalf("RestoreDNS (1st) failed: %v", err)
	}
	wantRestore := []string{
		"resolvectl revert tunssh0",
		"resolvectl default-route eth0 true",
		"resolvectl default-route wlan0 false",
	}
	if !slices.Equal(cmds, wantRestore) {
		t.Fatalf("RestoreDNS commands mismatch:\ngot:  %v\nwant: %v", cmds, wantRestore)
	}

	// Second idempotent restore when tunssh0 is already gone must still succeed.
	tunGoneOnSecondRestore = true
	if err := dns.RestoreDNS(ctx, snap); err != nil {
		t.Fatalf("RestoreDNS (2nd idempotent) failed: %v", err)
	}
}

func TestLinuxDNSConfiguratorResolvConfFallback(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	resolvPath := filepath.Join(tmpDir, "resolv.conf")
	backupPath := filepath.Join(tmpDir, "resolv.conf.tunssh.bak")

	origContent := "# DHCP DNS\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 1.1.1.1\n"
	if err := os.WriteFile(resolvPath, []byte(origContent), 0o644); err != nil {
		t.Fatalf("write fixture resolv.conf: %v", err)
	}

	dns := newLinuxDNSConfigurator(LinuxOptions{
		LookPath: func(string) (string, error) {
			return "", errors.New("not found")
		},
		ResolvConfPath:   resolvPath,
		ResolvBackupPath: backupPath,
	})

	strategy, origDNS, _, _, resolvBak, err := dns.CaptureDNS(ctx, "eth0", 2)
	if err != nil {
		t.Fatalf("CaptureDNS failed: %v", err)
	}
	if strategy != dnsStrategyResolvConf {
		t.Fatalf("strategy = %q, want %q", strategy, dnsStrategyResolvConf)
	}
	if resolvBak != origContent {
		t.Fatalf("resolvBak = %q, want %q", resolvBak, origContent)
	}
	wantOrig := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("1.1.1.1")}
	if !slices.Equal(origDNS, wantOrig) {
		t.Fatalf("origDNS = %v, want %v", origDNS, wantOrig)
	}

	snap := NetworkSnapshot{
		DNSStrategy:      strategy,
		ResolvConfBackup: resolvBak,
		OrigDNSServers:   []string{"192.168.1.1", "1.1.1.1"},
	}
	if err := dns.ApplyTUNDNS(ctx, snap, netip.MustParseAddr(TUNDNSServer)); err != nil {
		t.Fatalf("ApplyTUNDNS failed: %v", err)
	}

	gotResolv, err := os.ReadFile(resolvPath)
	if err != nil {
		t.Fatalf("read updated resolv.conf: %v", err)
	}
	if string(gotResolv) != "nameserver 198.18.0.2\n" {
		t.Fatalf("resolv.conf = %q, want %q", string(gotResolv), "nameserver 198.18.0.2\n")
	}
	gotBak, err := os.ReadFile(backupPath)
	if err != nil || string(gotBak) != origContent {
		t.Fatalf("backup file mismatch: err=%v content=%q", err, string(gotBak))
	}

	// Verify re-capturing while TUN DNS is active preserves the original .bak content instead of overwriting with 198.18.0.2.
	_, _, _, _, recapturedBak, err := dns.CaptureDNS(ctx, "eth0", 2)
	if err != nil || recapturedBak != origContent {
		t.Fatalf("re-capture while active should preserve backup: err=%v got=%q", err, recapturedBak)
	}

	// Restore and verify .bak is cleaned up and no .tmp files remain.
	if err := dns.RestoreDNS(ctx, snap); err != nil {
		t.Fatalf("RestoreDNS (1st) failed: %v", err)
	}
	restoredData, err := os.ReadFile(resolvPath)
	if err != nil || string(restoredData) != origContent {
		t.Fatalf("restored resolv.conf mismatch: err=%v got=%q", err, string(restoredData))
	}
	if _, err := os.Stat(backupPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected backup file removed, stat err=%v", err)
	}

	// Second restore is idempotent.
	if err := dns.RestoreDNS(ctx, snap); err != nil {
		t.Fatalf("RestoreDNS (2nd idempotent) failed: %v", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("readdir failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "resolv.conf" {
		t.Fatalf("unexpected leftover files in temp dir: %v", entries)
	}
}

func TestLinuxBindToInterfaceControlAndIPv6DisabledDetection(t *testing.T) {
	// Smoke-test BindToInterfaceControl with a real UDP socket on loopback (unprivileged EPERM must not fail).
	lc := net.ListenConfig{
		Control: BindToInterfaceControl("lo", 1, false),
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket with BindToInterfaceControl failed: %v", err)
	}
	_ = pc.Close()

	// Verify procfs disable_ipv6 detection.
	procFile := filepath.Join(t.TempDir(), "disable_ipv6")
	if err := os.WriteFile(procFile, []byte("1\n"), 0o644); err != nil {
		t.Fatalf("write proc fixture: %v", err)
	}
	if !isLinuxIPv6DisabledErr(unix.ENETUNREACH, procFile) {
		t.Fatal("expected ENETUNREACH with disable_ipv6=1 to be classified as IPv6 disabled")
	}
	if !isLinuxIPv6DisabledErr(unix.EAFNOSUPPORT, "") {
		t.Fatal("expected EAFNOSUPPORT to be classified as IPv6 disabled")
	}
	if isLinuxIPv6DisabledErr(unix.EPERM, procFile) {
		t.Fatal("EPERM must not be misclassified as IPv6 disabled")
	}
}

func TestLinuxIsTUNDNSActiveAndSplitPrefixDetection(t *testing.T) {
	ctx := context.Background()

	t.Run("detects resolv.conf.tunssh.bak backup file", func(t *testing.T) {
		tmpDir := t.TempDir()
		resolvPath := filepath.Join(tmpDir, "resolv.conf")
		bakPath := filepath.Join(tmpDir, "resolv.conf.tunssh.bak")
		if err := os.WriteFile(resolvPath, []byte("nameserver 1.1.1.1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bakPath, []byte("nameserver 192.168.1.1\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		d := newLinuxDNSConfigurator(LinuxOptions{
			LookPath:         func(string) (string, error) { return "", errors.New("not found") },
			ResolvConfPath:   resolvPath,
			ResolvBackupPath: bakPath,
		})
		active, err := d.IsTUNDNSActive(ctx, TUNIfaceName)
		if err != nil || !active {
			t.Fatalf("IsTUNDNSActive with .tunssh.bak = (%v, %v), want (true, nil)", active, err)
		}
	})

	t.Run("detects resolv.conf pointing only to 198.18.0.2 and clean state when restored", func(t *testing.T) {
		tmpDir := t.TempDir()
		resolvPath := filepath.Join(tmpDir, "resolv.conf")
		bakPath := filepath.Join(tmpDir, "resolv.conf.tunssh.bak")
		if err := os.WriteFile(resolvPath, []byte("nameserver 198.18.0.2\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		d := newLinuxDNSConfigurator(LinuxOptions{
			LookPath:         func(string) (string, error) { return "", errors.New("not found") },
			ResolvConfPath:   resolvPath,
			ResolvBackupPath: bakPath,
		})
		active, err := d.IsTUNDNSActive(ctx, TUNIfaceName)
		if err != nil || !active {
			t.Fatalf("IsTUNDNSActive with 198.18.0.2 = (%v, %v), want (true, nil)", active, err)
		}

		if err := os.WriteFile(resolvPath, []byte("nameserver 192.168.1.1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		active, err = d.IsTUNDNSActive(ctx, TUNIfaceName)
		if err != nil || active {
			t.Fatalf("IsTUNDNSActive clean resolv.conf = (%v, %v), want (false, nil)", active, err)
		}
	})

	t.Run("detects systemd-resolved 198.18.0.2 or tunssh0", func(t *testing.T) {
		dnsOut := "Global:\nLink 2 (eth0): 192.168.1.1\nLink 9 (wlan0): 198.18.0.2\n"
		d := newLinuxDNSConfigurator(LinuxOptions{
			LookPath: func(file string) (string, error) {
				if file == "resolvectl" || file == "systemctl" {
					return "/usr/bin/" + file, nil
				}
				return "", errors.New("not found")
			},
			RunCmd: func(_ context.Context, name string, args ...string) (string, error) {
				if name == "systemctl" {
					return "active", nil
				}
				if name == "resolvectl" && len(args) > 0 && args[0] == "dns" {
					return dnsOut, nil
				}
				return "", nil
			},
			ResolvConfPath:   filepath.Join(t.TempDir(), "resolv.conf"),
			ResolvBackupPath: filepath.Join(t.TempDir(), "resolv.conf.bak"),
		})
		active, err := d.IsTUNDNSActive(ctx, TUNIfaceName)
		if err != nil || !active {
			t.Fatalf("IsTUNDNSActive with 198.18.0.2 in resolvectl dns = (%v, %v), want (true, nil)", active, err)
		}

		dnsOut = "Global:\nLink 2 (eth0): 192.168.1.1\nLink 42 (tunssh0): 1.1.1.1\n"
		active, err = d.IsTUNDNSActive(ctx, TUNIfaceName)
		if err != nil || !active {
			t.Fatalf("IsTUNDNSActive with tunssh0 in resolvectl dns = (%v, %v), want (true, nil)", active, err)
		}

		dnsOut = "Global:\nLink 2 (eth0): 192.168.1.1\n"
		active, err = d.IsTUNDNSActive(ctx, TUNIfaceName)
		if err != nil || active {
			t.Fatalf("IsTUNDNSActive clean systemd-resolved = (%v, %v), want (false, nil)", active, err)
		}
	})

	t.Run("ipNetMatchesSplitPrefix", func(t *testing.T) {
		yes := []*net.IPNet{
			{IP: net.IPv4(0, 0, 0, 0).To4(), Mask: net.CIDRMask(1, 32)},
			{IP: net.IPv4(128, 0, 0, 0), Mask: net.CIDRMask(1, 32)}, // 16-byte v4-in-v6 slice
			{IP: net.ParseIP("::"), Mask: net.CIDRMask(1, 128)},
			{IP: net.ParseIP("8000::"), Mask: net.CIDRMask(1, 128)},
		}
		for _, ipnet := range yes {
			if !ipNetMatchesSplitPrefix(ipnet) {
				t.Fatalf("expected ipNetMatchesSplitPrefix(%v) == true", ipnet)
			}
		}
		no := []*net.IPNet{
			nil,
			{IP: net.IPv4(0, 0, 0, 0).To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
		}
		for _, ipnet := range no {
			if ipNetMatchesSplitPrefix(ipnet) {
				t.Fatalf("expected ipNetMatchesSplitPrefix(%v) == false", ipnet)
			}
		}
	})
}
