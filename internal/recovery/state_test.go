package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AlirezaDelkhahi/tunssh/internal/sysproxy"
)

type mockSysProxyManager struct {
	mu           sync.Mutex
	calls        []string
	snapshot     sysproxy.ProxySnapshot
	captureErr   error
	enableErr    error
	restoreErr   error
	enabledCfgs  []sysproxy.ProxyApplyConfig
	restoredSnap []sysproxy.ProxySnapshot
}

func (m *mockSysProxyManager) Capabilities() sysproxy.ProxyCapabilities {
	return sysproxy.ProxyCapabilities{AutoSupported: true, DesktopEnv: "gnome"}
}

func (m *mockSysProxyManager) CaptureSnapshot(ctx context.Context) (sysproxy.ProxySnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "CaptureSnapshot")
	if m.captureErr != nil {
		return sysproxy.ProxySnapshot{}, m.captureErr
	}
	return m.snapshot, nil
}

func (m *mockSysProxyManager) Enable(ctx context.Context, cfg sysproxy.ProxyApplyConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "Enable")
	m.enabledCfgs = append(m.enabledCfgs, cfg)
	return m.enableErr
}

func (m *mockSysProxyManager) Restore(ctx context.Context, snap sysproxy.ProxySnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "Restore")
	m.restoredSnap = append(m.restoredSnap, snap)
	return m.restoreErr
}

func (m *mockSysProxyManager) EnvSnippet(socksPort, httpPort int) string {
	return sysproxy.FormatEnvSnippet(socksPort, httpPort)
}

func (m *mockSysProxyManager) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *mockSysProxyManager) RestoredSnapshots() []sysproxy.ProxySnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sysproxy.ProxySnapshot, len(m.restoredSnap))
	copy(out, m.restoredSnap)
	return out
}

type failingRecoveryStore struct {
	inner        RecoveryStore
	loadErr      error
	saveDirtyErr error
	markCleanErr error
	calls        []string
}

func (f *failingRecoveryStore) Load() (*RecoveryState, error) {
	f.calls = append(f.calls, "Load")
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	if f.inner == nil {
		return nil, nil
	}
	return f.inner.Load()
}

func (f *failingRecoveryStore) SaveDirty(state RecoveryState) error {
	f.calls = append(f.calls, "SaveDirty")
	if f.saveDirtyErr != nil {
		return f.saveDirtyErr
	}
	if f.inner == nil {
		return nil
	}
	return f.inner.SaveDirty(state)
}

func (f *failingRecoveryStore) MarkClean() error {
	f.calls = append(f.calls, "MarkClean")
	if f.markCleanErr != nil {
		return f.markCleanErr
	}
	if f.inner == nil {
		return nil
	}
	return f.inner.MarkClean()
}

func sampleProxySnapshot() sysproxy.ProxySnapshot {
	return sysproxy.ProxySnapshot{
		Platform: "linux",
		LinuxDE:  "gnome",
		LinuxPrevValues: map[string]string{
			"org.gnome.system.proxy/mode": "'none'",
			"org.gnome.system.proxy/host": "''",
		},
	}
}

func mustNewStore(t *testing.T, configDir string) *FileRecoveryStore {
	t.Helper()
	store, err := NewFileRecoveryStore(configDir)
	if err != nil {
		t.Fatalf("NewFileRecoveryStore(%q): %v", configDir, err)
	}
	return store
}

func assertZeroTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("unexpected temporary file left in %q: %s", dir, entry.Name())
		}
	}
}

func TestFileRecoveryStoreAtomicPersistenceAndPerms(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "tunssh-cfg")
	store := mustNewStore(t, configDir)

	// Missing file returns (nil, nil).
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() on missing file returned error: %v", err)
	}
	if loaded != nil {
		t.Fatalf("Load() on missing file = %+v, want nil", loaded)
	}

	snap := sampleProxySnapshot()
	wantState := RecoveryState{
		Mode:          RecoveryModeProxy,
		PID:           48210,
		ProxySnapshot: &snap,
	}
	if err := store.SaveDirty(wantState); err != nil {
		t.Fatalf("SaveDirty() error: %v", err)
	}

	statePath := filepath.Join(configDir, StateFileName)
	if runtime.GOOS != "windows" {
		dirInfo, err := os.Stat(configDir)
		if err != nil {
			t.Fatalf("Stat(%q): %v", configDir, err)
		}
		if got := dirInfo.Mode().Perm(); got != 0o700 {
			t.Fatalf("configDir perm = %04o, want 0700", got)
		}

		fileInfo, err := os.Stat(statePath)
		if err != nil {
			t.Fatalf("Stat(%q): %v", statePath, err)
		}
		if got := fileInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("state file perm = %04o, want 0600", got)
		}
	}
	assertZeroTempFiles(t, configDir)

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after SaveDirty error: %v", err)
	}
	if got == nil {
		t.Fatal("Load() after SaveDirty returned nil")
	}
	if got.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, SchemaVersion)
	}
	if !got.Dirty {
		t.Error("Dirty = false, want true")
	}
	if got.Mode != RecoveryModeProxy {
		t.Errorf("Mode = %q, want %q", got.Mode, RecoveryModeProxy)
	}
	if got.PID != 48210 {
		t.Errorf("PID = %d, want 48210", got.PID)
	}
	if got.UpdatedAtUTC.IsZero() {
		t.Error("UpdatedAtUTC is zero, want defaulted UTC timestamp")
	}
	if got.UpdatedAtUTC.Location() != time.UTC {
		t.Errorf("UpdatedAtUTC location = %v, want UTC", got.UpdatedAtUTC.Location())
	}
	if !reflect.DeepEqual(got.ProxySnapshot, &snap) {
		t.Errorf("ProxySnapshot = %+v, want %+v", got.ProxySnapshot, &snap)
	}

	if err := store.MarkClean(); err != nil {
		t.Fatalf("MarkClean() error: %v", err)
	}
	assertZeroTempFiles(t, configDir)
	if runtime.GOOS != "windows" {
		fileInfo, err := os.Stat(statePath)
		if err != nil {
			t.Fatalf("Stat(%q) after MarkClean: %v", statePath, err)
		}
		if got := fileInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("state file perm after MarkClean = %04o, want 0600", got)
		}
	}

	clean, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after MarkClean error: %v", err)
	}
	if clean == nil {
		t.Fatal("Load() after MarkClean returned nil")
	}
	if clean.SchemaVersion != SchemaVersion {
		t.Errorf("clean.SchemaVersion = %d, want %d", clean.SchemaVersion, SchemaVersion)
	}
	if clean.Dirty {
		t.Error("clean.Dirty = true, want false")
	}
	if clean.UpdatedAtUTC.IsZero() {
		t.Error("clean.UpdatedAtUTC is zero")
	}
}

func TestFileRecoveryStoreMarkCleanOnMissingFile(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "fresh-cfg")
	store := mustNewStore(t, configDir)

	if err := store.MarkClean(); err != nil {
		t.Fatalf("MarkClean() on missing file error: %v", err)
	}
	assertZeroTempFiles(t, configDir)

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after MarkClean error: %v", err)
	}
	if got == nil || got.Dirty {
		t.Fatalf("Load() = %+v, want non-nil clean state", got)
	}
}

func TestBeginProxySessionAbortsIfSaveDirtyFails(t *testing.T) {
	saveErr := errors.New("disk full")
	store := &failingRecoveryStore{saveDirtyErr: saveErr}
	sysProxy := &mockSysProxyManager{snapshot: sampleProxySnapshot()}

	restorer := NewRestorer(
		store,
		sysProxy,
		WithPIDFunc(func() int { return 4242 }),
		WithNowFunc(func() time.Time { return time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC) }),
	)

	err := restorer.BeginProxySession(context.Background(), sysproxy.ProxyApplyConfig{
		SOCKSPort: 10808,
		HTTPPort:  10809,
	})
	if !errors.Is(err, saveErr) {
		t.Fatalf("BeginProxySession() error = %v, want wrapped %v", err, saveErr)
	}

	calls := sysProxy.Calls()
	if !reflect.DeepEqual(calls, []string{"CaptureSnapshot"}) {
		t.Fatalf("sysProxy calls = %v, want [CaptureSnapshot] (Enable MUST NOT be called)", calls)
	}
}

func TestBeginProxySessionRollsBackWhenEnableFails(t *testing.T) {
	configDir := t.TempDir()
	store := mustNewStore(t, configDir)
	snap := sampleProxySnapshot()
	enableErr := errors.New("gsettings exited with status 1")
	sysProxy := &mockSysProxyManager{
		snapshot:  snap,
		enableErr: enableErr,
	}

	restorer := NewRestorer(
		store,
		sysProxy,
		WithPIDFunc(func() int { return 5151 }),
		WithNowFunc(func() time.Time { return time.Date(2026, 11, 24, 8, 15, 0, 0, time.UTC) }),
	)

	err := restorer.BeginProxySession(context.Background(), sysproxy.ProxyApplyConfig{
		SOCKSPort:     10808,
		HTTPPort:      10809,
		BypassIranLAN: true,
	})
	if !errors.Is(err, enableErr) {
		t.Fatalf("BeginProxySession() error = %v, want wrapped %v", err, enableErr)
	}

	wantCalls := []string{"CaptureSnapshot", "Enable", "Restore"}
	if got := sysProxy.Calls(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("sysProxy calls = %v, want %v", got, wantCalls)
	}
	restored := sysProxy.RestoredSnapshots()
	if len(restored) != 1 || !reflect.DeepEqual(restored[0], snap) {
		t.Fatalf("restored snapshots = %+v, want [%+v]", restored, snap)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}
	if state == nil || state.Dirty {
		t.Fatalf("state after Enable failure rollback = %+v, want dirty=false", state)
	}
}

func TestBeginProxySessionHappyPathPersistsBeforeEnable(t *testing.T) {
	configDir := t.TempDir()
	store := mustNewStore(t, configDir)
	snap := sampleProxySnapshot()
	sysProxy := &mockSysProxyManager{snapshot: snap}
	fixedNow := time.Date(2026, 11, 24, 8, 30, 0, 0, time.UTC)

	restorer := NewRestorer(
		store,
		sysProxy,
		WithPIDFunc(func() int { return 7777 }),
		WithNowFunc(func() time.Time { return fixedNow }),
	)

	if err := restorer.BeginProxySession(context.Background(), sysproxy.ProxyApplyConfig{
		SOCKSPort:     10808,
		HTTPPort:      10809,
		BypassIranLAN: true,
	}); err != nil {
		t.Fatalf("BeginProxySession() error: %v", err)
	}

	if got := sysProxy.Calls(); !reflect.DeepEqual(got, []string{"CaptureSnapshot", "Enable"}) {
		t.Fatalf("sysProxy calls = %v, want [CaptureSnapshot Enable]", got)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load() error: %v", err)
	}
	if state == nil || !state.Dirty || state.Mode != RecoveryModeProxy || state.PID != 7777 {
		t.Fatalf("state = %+v, want dirty=true mode=proxy pid=7777", state)
	}
	if !state.UpdatedAtUTC.Equal(fixedNow) {
		t.Errorf("UpdatedAtUTC = %v, want %v", state.UpdatedAtUTC, fixedNow)
	}
	if !reflect.DeepEqual(state.ProxySnapshot, &snap) {
		t.Errorf("ProxySnapshot = %+v, want %+v", state.ProxySnapshot, &snap)
	}
}

func TestCheckAndRecoverOnStartupRestoresDirtyProxySession(t *testing.T) {
	configDir := t.TempDir()
	store := mustNewStore(t, configDir)
	snap := sampleProxySnapshot()

	if err := store.SaveDirty(RecoveryState{
		Mode:          RecoveryModeProxy,
		PID:           999999,
		UpdatedAtUTC:  time.Date(2026, 11, 24, 7, 45, 0, 0, time.UTC),
		ProxySnapshot: &snap,
	}); err != nil {
		t.Fatalf("seed SaveDirty error: %v", err)
	}

	sysProxy := &mockSysProxyManager{}
	restorer := NewRestorer(store, sysProxy, WithPIDFunc(func() int { return 12345 }))

	res, err := restorer.CheckAndRecoverOnStartup(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRecoverOnStartup() error: %v", err)
	}
	if !res.Recovered {
		t.Errorf("Recovered = false, want true")
	}
	if res.Mode != RecoveryModeProxy {
		t.Errorf("Mode = %q, want %q", res.Mode, RecoveryModeProxy)
	}
	if res.NeedsElevation {
		t.Errorf("NeedsElevation = true, want false")
	}
	if res.Message == "" {
		t.Error("Message is empty, want descriptive recovery message")
	}

	restored := sysProxy.RestoredSnapshots()
	if len(restored) != 1 || !reflect.DeepEqual(restored[0], snap) {
		t.Fatalf("Restore snapshots = %+v, want [%+v]", restored, snap)
	}

	after, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after startup recovery error: %v", err)
	}
	if after == nil || after.Dirty {
		t.Fatalf("state after startup recovery = %+v, want dirty=false", after)
	}
	assertZeroTempFiles(t, configDir)
}

func TestRestoreProxySessionIdempotency(t *testing.T) {
	configDir := t.TempDir()
	store := mustNewStore(t, configDir)
	snap := sampleProxySnapshot()

	if err := store.SaveDirty(RecoveryState{
		Mode:          RecoveryModeProxy,
		PID:           88888,
		ProxySnapshot: &snap,
	}); err != nil {
		t.Fatalf("SaveDirty() error: %v", err)
	}

	sysProxy := &mockSysProxyManager{}
	restorer := NewRestorer(store, sysProxy)

	if err := restorer.RestoreProxySession(context.Background()); err != nil {
		t.Fatalf("first RestoreProxySession() error: %v", err)
	}
	if err := restorer.RestoreProxySession(context.Background()); err != nil {
		t.Fatalf("second RestoreProxySession() error: %v", err)
	}

	if got := sysProxy.Calls(); !reflect.DeepEqual(got, []string{"Restore"}) {
		t.Fatalf("sysProxy calls = %v, want single [Restore] across two calls", got)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if state == nil || state.Dirty {
		t.Fatalf("state = %+v, want dirty=false", state)
	}
}

func TestRestoreProxySessionDoesNotMarkCleanOnRestoreFailure(t *testing.T) {
	configDir := t.TempDir()
	store := mustNewStore(t, configDir)
	snap := sampleProxySnapshot()

	if err := store.SaveDirty(RecoveryState{
		Mode:          RecoveryModeProxy,
		PID:           88888,
		ProxySnapshot: &snap,
	}); err != nil {
		t.Fatalf("SaveDirty() error: %v", err)
	}

	restoreErr := errors.New("dbus unavailable")
	sysProxy := &mockSysProxyManager{restoreErr: restoreErr}
	restorer := NewRestorer(store, sysProxy)

	err := restorer.RestoreProxySession(context.Background())
	if !errors.Is(err, restoreErr) {
		t.Fatalf("RestoreProxySession() error = %v, want wrapped %v", err, restoreErr)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if state == nil || !state.Dirty {
		t.Fatalf("state after failed restore = %+v, want dirty=true preserved", state)
	}
}

func TestCheckAndRecoverOnStartupSkipsSamePID(t *testing.T) {
	configDir := t.TempDir()
	store := mustNewStore(t, configDir)
	snap := sampleProxySnapshot()

	const livePID = 54321
	if err := store.SaveDirty(RecoveryState{
		Mode:          RecoveryModeProxy,
		PID:           livePID,
		ProxySnapshot: &snap,
	}); err != nil {
		t.Fatalf("SaveDirty() error: %v", err)
	}

	sysProxy := &mockSysProxyManager{}
	restorer := NewRestorer(store, sysProxy, WithPIDFunc(func() int { return livePID }))

	res, err := restorer.CheckAndRecoverOnStartup(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRecoverOnStartup() error: %v", err)
	}
	if res != (StartupRecoveryResult{}) {
		t.Fatalf("result = %+v, want zero StartupRecoveryResult", res)
	}
	if got := sysProxy.Calls(); len(got) != 0 {
		t.Fatalf("sysProxy calls = %v, want none", got)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if state == nil || !state.Dirty {
		t.Fatalf("state = %+v, want dirty=true untouched for live PID", state)
	}
}

func TestCheckAndRecoverOnStartupDirtyTUNNeedsElevation(t *testing.T) {
	configDir := t.TempDir()
	store := mustNewStore(t, configDir)

	if err := store.SaveDirty(RecoveryState{
		Mode: RecoveryModeTUN,
		PID:  999999,
		TUNSnapshot: &TUNSnapshot{
			VPSPeerIP:       "203.0.113.10",
			OrigGateway:     "192.168.1.1",
			OrigIfaceName:   "wlan0",
			OrigIfaceIndex:  3,
			OrigDNSServers:  []string{"192.168.1.1"},
			DNSStrategy:     "systemd-resolved",
			TUNIfaceName:    "tunssh0",
			InstalledRoutes: []string{"203.0.113.10/32", "0.0.0.0/1", "128.0.0.0/1"},
		},
	}); err != nil {
		t.Fatalf("SaveDirty() error: %v", err)
	}

	sysProxy := &mockSysProxyManager{}
	restorer := NewRestorer(store, sysProxy, WithPIDFunc(func() int { return 11111 }))

	res, err := restorer.CheckAndRecoverOnStartup(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRecoverOnStartup() error: %v", err)
	}
	if res.Recovered {
		t.Error("Recovered = true, want false")
	}
	if res.Mode != RecoveryModeTUN {
		t.Errorf("Mode = %q, want %q", res.Mode, RecoveryModeTUN)
	}
	if !res.NeedsElevation {
		t.Error("NeedsElevation = false, want true")
	}
	if res.Message == "" {
		t.Error("Message is empty, want elevation notice")
	}
	if got := sysProxy.Calls(); len(got) != 0 {
		t.Fatalf("sysProxy calls = %v, want none", got)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if state == nil || !state.Dirty {
		t.Fatalf("state = %+v, want dirty=true preserved until elevated TUN restore", state)
	}
}

func TestRestoreNetworkPanicButton(t *testing.T) {
	t.Run("dirty proxy restores idempotently", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleProxySnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:          RecoveryModeProxy,
			PID:           44444,
			ProxySnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		sysProxy := &mockSysProxyManager{}
		restorer := NewRestorer(store, sysProxy)

		if err := restorer.RestoreNetwork(context.Background()); err != nil {
			t.Fatalf("RestoreNetwork() error: %v", err)
		}
		if err := restorer.RestoreNetwork(context.Background()); err != nil {
			t.Fatalf("second RestoreNetwork() error: %v", err)
		}
		if got := sysProxy.Calls(); !reflect.DeepEqual(got, []string{"Restore"}) {
			t.Fatalf("sysProxy calls = %v, want [Restore]", got)
		}
		state, err := store.Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if state == nil || state.Dirty {
			t.Fatalf("state = %+v, want dirty=false", state)
		}
	})

	t.Run("dirty tun returns M2 not enabled error", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         44444,
			TUNSnapshot: &TUNSnapshot{TUNIfaceName: "tunssh0"},
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		sysProxy := &mockSysProxyManager{}
		restorer := NewRestorer(store, sysProxy)

		err := restorer.RestoreNetwork(context.Background())
		if !errors.Is(err, ErrTUNRestoreNotSupported) {
			t.Fatalf("RestoreNetwork() error = %v, want ErrTUNRestoreNotSupported", err)
		}
		if got := sysProxy.Calls(); len(got) != 0 {
			t.Fatalf("sysProxy calls = %v, want none", got)
		}
		state, err := store.Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if state == nil || !state.Dirty {
			t.Fatalf("state = %+v, want dirty=true preserved", state)
		}
	})
}

func TestSection25JSONSchemaCompatibility(t *testing.T) {
	raw := `{
		"schema_version": 1,
		"dirty": true,
		"mode": "proxy",
		"pid": 48210,
		"updated_at_utc": "2026-11-24T08:00:00Z",
		"proxy_snapshot": {
			"platform": "windows",
			"win_proxy_enable": 0,
			"win_proxy_server": "",
			"win_proxy_override": "",
			"win_auto_config_url": "",
			"linux_de": "gnome",
			"linux_prev_values": {}
		},
		"tun_snapshot": {
			"vps_peer_ip": "203.0.113.10",
			"orig_gateway": "192.168.1.1",
			"orig_iface_name": "wlan0",
			"orig_iface_index": 3,
			"orig_dns_servers": ["192.168.1.1"],
			"win_adapter_dns_backups": [
				{
					"iface_index": 3,
					"iface_name": "Wi-Fi",
					"ipv4_dns": ["192.168.1.1"],
					"ipv6_dns": ["fe80::1"]
				}
			],
			"linux_dns_backups": [
				{
					"ifindex": 3,
					"ifname": "wlan0",
					"dns_servers": ["192.168.1.1"],
					"default_route": true
				}
			],
			"dns_strategy": "systemd-resolved",
			"resolv_conf_backup": "",
			"tun_iface_name": "tunssh0",
			"installed_routes": ["203.0.113.10/32", "0.0.0.0/1", "128.0.0.0/1"]
		}
	}`

	var state RecoveryState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	if state.SchemaVersion != 1 || !state.Dirty || state.Mode != RecoveryModeProxy || state.PID != 48210 {
		t.Fatalf("unexpected top-level decoded fields: %+v", state)
	}
	if state.TUNSnapshot == nil {
		t.Fatal("TUNSnapshot is nil")
	}
	if state.TUNSnapshot.VPSPeerIP != "203.0.113.10" ||
		state.TUNSnapshot.OrigGateway != "192.168.1.1" ||
		state.TUNSnapshot.OrigIfaceName != "wlan0" ||
		state.TUNSnapshot.OrigIfaceIndex != 3 ||
		state.TUNSnapshot.DNSStrategy != "systemd-resolved" ||
		state.TUNSnapshot.TUNIfaceName != "tunssh0" {
		t.Fatalf("unexpected TUNSnapshot scalar fields: %+v", state.TUNSnapshot)
	}
	if len(state.TUNSnapshot.WinAdapterDNSBackups) != 1 || state.TUNSnapshot.WinAdapterDNSBackups[0].IfaceName != "Wi-Fi" {
		t.Fatalf("unexpected WinAdapterDNSBackups: %+v", state.TUNSnapshot.WinAdapterDNSBackups)
	}
	if len(state.TUNSnapshot.LinuxDNSBackups) != 1 || !state.TUNSnapshot.LinuxDNSBackups[0].DefaultRoute {
		t.Fatalf("unexpected LinuxDNSBackups: %+v", state.TUNSnapshot.LinuxDNSBackups)
	}
	if !reflect.DeepEqual(state.TUNSnapshot.InstalledRoutes, []string{"203.0.113.10/32", "0.0.0.0/1", "128.0.0.0/1"}) {
		t.Fatalf("unexpected InstalledRoutes: %v", state.TUNSnapshot.InstalledRoutes)
	}
}

func TestFileRecoveryStoreConcurrency(t *testing.T) {
	configDir := t.TempDir()
	store := mustNewStore(t, configDir)
	snap := sampleProxySnapshot()

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := range 10 {
				if (worker+j)%2 == 0 {
					if err := store.SaveDirty(RecoveryState{
						Mode:          RecoveryModeProxy,
						PID:           1000 + worker,
						ProxySnapshot: &snap,
					}); err != nil {
						t.Errorf("SaveDirty error: %v", err)
					}
				} else {
					if err := store.MarkClean(); err != nil {
						t.Errorf("MarkClean error: %v", err)
					}
				}
				if _, err := store.Load(); err != nil {
					t.Errorf("Load error: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()
	assertZeroTempFiles(t, configDir)
}

func TestFileRecoveryStoreEdgeCases(t *testing.T) {
	t.Run("empty configDir rejected", func(t *testing.T) {
		if _, err := NewFileRecoveryStore("   "); err == nil {
			t.Fatal("NewFileRecoveryStore empty dir succeeded, want error")
		}
	})

	t.Run("tightens overly permissive existing dir and file modes", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX permission bits are not applicable on Windows")
		}
		configDir := filepath.Join(t.TempDir(), "permissive")
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.Chmod(configDir, 0o755); err != nil {
			t.Fatalf("Chmod dir: %v", err)
		}
		statePath := filepath.Join(configDir, StateFileName)
		if err := os.WriteFile(statePath, []byte("{}"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		store := mustNewStore(t, configDir)
		if err := store.SaveDirty(RecoveryState{Mode: RecoveryModeProxy, PID: 12}); err != nil {
			t.Fatalf("SaveDirty: %v", err)
		}

		dirInfo, err := os.Stat(configDir)
		if err != nil {
			t.Fatalf("Stat dir: %v", err)
		}
		if got := dirInfo.Mode().Perm(); got != 0o700 {
			t.Fatalf("dir perm = %04o, want 0700", got)
		}
		fileInfo, err := os.Stat(statePath)
		if err != nil {
			t.Fatalf("Stat file: %v", err)
		}
		if got := fileInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("file perm = %04o, want 0600", got)
		}
	})

	t.Run("cleans up temp file when rename fails", func(t *testing.T) {
		configDir := t.TempDir()
		// Create a directory at the target path so os.Rename(file, dir) fails.
		blockingDir := filepath.Join(configDir, StateFileName)
		if err := os.Mkdir(blockingDir, 0o700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}

		store := mustNewStore(t, configDir)
		if err := store.SaveDirty(RecoveryState{Mode: RecoveryModeProxy, PID: 99}); err == nil {
			t.Fatal("SaveDirty succeeded despite blocking directory, want error")
		}
		assertZeroTempFiles(t, configDir)
	})

	t.Run("rejects unsupported schema version and corrupt JSON", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)

		if err := os.WriteFile(store.Path(), []byte(`{"schema_version": 99, "dirty": true}`), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := store.Load(); !errors.Is(err, ErrUnsupportedSchemaVersion) {
			t.Fatalf("Load() error = %v, want ErrUnsupportedSchemaVersion", err)
		}

		if err := os.WriteFile(store.Path(), []byte(`{not-json`), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("Load() on corrupt JSON succeeded, want error")
		}
	})
}

func TestRestorerEdgeCases(t *testing.T) {
	t.Run("BeginProxySession leaves state dirty when both Enable and rollback Restore fail", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		enableErr := errors.New("enable failed")
		restoreErr := errors.New("rollback restore failed")
		sysProxy := &mockSysProxyManager{
			snapshot:   sampleProxySnapshot(),
			enableErr:  enableErr,
			restoreErr: restoreErr,
		}
		restorer := NewRestorer(store, sysProxy, WithPIDFunc(func() int { return 3030 }))

		err := restorer.BeginProxySession(context.Background(), sysproxy.ProxyApplyConfig{SOCKSPort: 10808, HTTPPort: 10809})
		if !errors.Is(err, enableErr) || !errors.Is(err, restoreErr) {
			t.Fatalf("BeginProxySession() error = %v, want wrapped enableErr and restoreErr", err)
		}

		state, loadErr := store.Load()
		if loadErr != nil {
			t.Fatalf("Load() error: %v", loadErr)
		}
		if state == nil || !state.Dirty {
			t.Fatalf("state = %+v, want dirty=true preserved when rollback fails", state)
		}
	})

	t.Run("same PID can RestoreProxySession on shutdown while startup check skips live PID", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleProxySnapshot()
		sysProxy := &mockSysProxyManager{snapshot: snap}
		const currentPID = 42420
		restorer := NewRestorer(store, sysProxy, WithPIDFunc(func() int { return currentPID }))

		if err := restorer.BeginProxySession(context.Background(), sysproxy.ProxyApplyConfig{SOCKSPort: 10808, HTTPPort: 10809}); err != nil {
			t.Fatalf("BeginProxySession() error: %v", err)
		}

		startupRes, err := restorer.CheckAndRecoverOnStartup(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRecoverOnStartup() error: %v", err)
		}
		if startupRes != (StartupRecoveryResult{}) {
			t.Fatalf("CheckAndRecoverOnStartup() = %+v, want zero result for live PID", startupRes)
		}

		if err := restorer.RestoreProxySession(context.Background()); err != nil {
			t.Fatalf("RestoreProxySession() error: %v", err)
		}
		if got := sysProxy.Calls(); !reflect.DeepEqual(got, []string{"CaptureSnapshot", "Enable", "Restore"}) {
			t.Fatalf("sysProxy calls = %v, want [CaptureSnapshot Enable Restore]", got)
		}
		state, err := store.Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if state == nil || state.Dirty {
			t.Fatalf("state = %+v, want dirty=false", state)
		}
	})

	t.Run("CheckAndRecoverOnStartup returns zero result when missing or clean", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		sysProxy := &mockSysProxyManager{}
		restorer := NewRestorer(store, sysProxy)

		res, err := restorer.CheckAndRecoverOnStartup(context.Background())
		if err != nil || res != (StartupRecoveryResult{}) {
			t.Fatalf("missing file CheckAndRecoverOnStartup() = (%+v, %v), want zero nil", res, err)
		}

		if err := store.MarkClean(); err != nil {
			t.Fatalf("MarkClean() error: %v", err)
		}
		res, err = restorer.CheckAndRecoverOnStartup(context.Background())
		if err != nil || res != (StartupRecoveryResult{}) {
			t.Fatalf("clean state CheckAndRecoverOnStartup() = (%+v, %v), want zero nil", res, err)
		}
		if got := sysProxy.Calls(); len(got) != 0 {
			t.Fatalf("sysProxy calls = %v, want none", got)
		}
	})

	t.Run("CheckAndRecoverOnStartup rejects unknown dirty mode without clearing state", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		if err := store.SaveDirty(RecoveryState{Mode: "bogus", PID: 999999}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		sysProxy := &mockSysProxyManager{}
		restorer := NewRestorer(store, sysProxy, WithPIDFunc(func() int { return 100 }))

		_, err := restorer.CheckAndRecoverOnStartup(context.Background())
		if !errors.Is(err, ErrUnsupportedMode) {
			t.Fatalf("CheckAndRecoverOnStartup() error = %v, want ErrUnsupportedMode", err)
		}
		state, loadErr := store.Load()
		if loadErr != nil || state == nil || !state.Dirty {
			t.Fatalf("state = (%+v, %v), want dirty=true preserved", state, loadErr)
		}
	})

	t.Run("RestoreNetwork on clean or missing state marks clean without touching sysproxy", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		sysProxy := &mockSysProxyManager{}
		restorer := NewRestorer(store, sysProxy)

		if err := restorer.RestoreNetwork(context.Background()); err != nil {
			t.Fatalf("RestoreNetwork() error: %v", err)
		}
		if got := sysProxy.Calls(); len(got) != 0 {
			t.Fatalf("sysProxy calls = %v, want none", got)
		}
		state, err := store.Load()
		if err != nil || state == nil || state.Dirty {
			t.Fatalf("state = (%+v, %v), want clean state persisted", state, err)
		}
	})
}

type mockTUNRecoveryOps struct {
	mu           sync.Mutex
	calls        []string
	active       bool
	activeErr    error
	restoreErr   error
	restoredSnap []TUNSnapshot
}

func (m *mockTUNRecoveryOps) IsTUNStateActive(ctx context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "IsTUNStateActive")
	if m.activeErr != nil {
		return m.active, m.activeErr
	}
	return m.active, nil
}

func (m *mockTUNRecoveryOps) RestoreTUN(ctx context.Context, snap TUNSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "RestoreTUN")
	m.restoredSnap = append(m.restoredSnap, snap)
	return m.restoreErr
}

func (m *mockTUNRecoveryOps) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *mockTUNRecoveryOps) RestoredSnapshots() []TUNSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TUNSnapshot, len(m.restoredSnap))
	copy(out, m.restoredSnap)
	return out
}

func (m *mockTUNRecoveryOps) SetRestoreErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restoreErr = err
}

func sampleTUNSnapshot() TUNSnapshot {
	return TUNSnapshot{
		VPSPeerIP:      "203.0.113.10",
		OrigGateway:    "192.168.1.1",
		OrigIfaceName:  "wlan0",
		OrigIfaceIndex: 3,
		OrigDNSServers: []string{"192.168.1.1", "9.9.9.9"},
		WinAdapterDNSBackups: []WinAdapterDNSBackup{
			{
				IfaceIndex: 3,
				IfaceName:  "Wi-Fi",
				IPv4DNS:    []string{"192.168.1.1"},
				IPv6DNS:    []string{"fe80::1"},
			},
		},
		LinuxDNSBackups: []LinuxDNSBackup{
			{
				IfIndex:      3,
				IfName:       "wlan0",
				DNSServers:   []string{"192.168.1.1"},
				DefaultRoute: true,
			},
		},
		DNSStrategy:      "systemd-resolved",
		ResolvConfBackup: "nameserver 192.168.1.1\n",
		TUNIfaceName:     "tunssh0",
		InstalledRoutes:  []string{"203.0.113.10/32", "0.0.0.0/1", "128.0.0.0/1"},
	}
}

func TestBeginTUNSessionAtomicPersistenceAndPerms(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "tunssh-cfg")
	store := mustNewStore(t, configDir)
	fixedNow := time.Date(2026, 11, 24, 15, 30, 0, 0, time.UTC)

	restorer := NewRestorer(
		store,
		nil,
		WithPIDFunc(func() int { return 7788 }),
		WithNowFunc(func() time.Time { return fixedNow }),
	)

	snap := sampleTUNSnapshot()
	expectedSnap := sampleTUNSnapshot()
	if err := restorer.BeginTUNSession(context.Background(), snap); err != nil {
		t.Fatalf("BeginTUNSession() error: %v", err)
	}

	// Mutate caller slices after BeginTUNSession to ensure a defensive copy was persisted.
	snap.OrigDNSServers[0] = "mutated"
	snap.WinAdapterDNSBackups[0].IPv4DNS[0] = "mutated"
	snap.LinuxDNSBackups[0].DNSServers[0] = "mutated"
	snap.InstalledRoutes[0] = "mutated"

	statePath := filepath.Join(configDir, StateFileName)
	if runtime.GOOS != "windows" {
		dirInfo, err := os.Stat(configDir)
		if err != nil {
			t.Fatalf("Stat(%q): %v", configDir, err)
		}
		if got := dirInfo.Mode().Perm(); got != 0o700 {
			t.Fatalf("configDir perm = %04o, want 0700", got)
		}

		fileInfo, err := os.Stat(statePath)
		if err != nil {
			t.Fatalf("Stat(%q): %v", statePath, err)
		}
		if got := fileInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("state file perm = %04o, want 0600", got)
		}
	}
	assertZeroTempFiles(t, configDir)

	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after BeginTUNSession error: %v", err)
	}
	if got == nil {
		t.Fatal("Load() after BeginTUNSession returned nil")
	}
	if got.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, SchemaVersion)
	}
	if !got.Dirty {
		t.Error("Dirty = false, want true")
	}
	if got.Mode != RecoveryModeTUN {
		t.Errorf("Mode = %q, want %q", got.Mode, RecoveryModeTUN)
	}
	if got.PID != 7788 {
		t.Errorf("PID = %d, want 7788", got.PID)
	}
	if !got.UpdatedAtUTC.Equal(fixedNow) {
		t.Errorf("UpdatedAtUTC = %v, want %v", got.UpdatedAtUTC, fixedNow)
	}
	if got.ProxySnapshot != nil {
		t.Errorf("ProxySnapshot = %+v, want nil", got.ProxySnapshot)
	}
	if !reflect.DeepEqual(got.TUNSnapshot, &expectedSnap) {
		t.Errorf("TUNSnapshot = %+v, want %+v", got.TUNSnapshot, &expectedSnap)
	}
}

func TestBeginTUNSessionValidationAndErrors(t *testing.T) {
	t.Run("rejects nil store", func(t *testing.T) {
		restorer := NewRestorer(nil, nil)
		if err := restorer.BeginTUNSession(context.Background(), sampleTUNSnapshot()); err == nil {
			t.Fatal("BeginTUNSession() with nil store succeeded, want error")
		}
	})

	t.Run("propagates SaveDirty error", func(t *testing.T) {
		saveErr := errors.New("disk full")
		store := &failingRecoveryStore{saveDirtyErr: saveErr}
		restorer := NewRestorer(store, nil)

		err := restorer.BeginTUNSession(context.Background(), sampleTUNSnapshot())
		if !errors.Is(err, saveErr) {
			t.Fatalf("BeginTUNSession() error = %v, want wrapped %v", err, saveErr)
		}
	})

	t.Run("respects canceled context", func(t *testing.T) {
		store := &failingRecoveryStore{}
		restorer := NewRestorer(store, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := restorer.BeginTUNSession(ctx, sampleTUNSnapshot())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("BeginTUNSession() error = %v, want context.Canceled", err)
		}
		if len(store.calls) != 0 {
			t.Fatalf("store calls = %v, want none on canceled context", store.calls)
		}
	})
}

func TestCheckAndRecoverOnStartupTUNMode(t *testing.T) {
	t.Run("IsTUNStateActive false marks clean and reports recovered", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         999999,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		sysProxy := &mockSysProxyManager{}
		tunOps := &mockTUNRecoveryOps{active: false}
		restorer := NewRestorer(
			store,
			sysProxy,
			WithPIDFunc(func() int { return 12345 }),
			WithTUNRecoveryOps(tunOps),
		)

		res, err := restorer.CheckAndRecoverOnStartup(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRecoverOnStartup() error: %v", err)
		}
		if !res.Recovered {
			t.Error("Recovered = false, want true")
		}
		if res.Mode != RecoveryModeTUN {
			t.Errorf("Mode = %q, want %q", res.Mode, RecoveryModeTUN)
		}
		if res.NeedsElevation {
			t.Error("NeedsElevation = true, want false")
		}
		const wantMsg = "Previous TUN session ended unexpectedly; OS network routes were already cleanly restored."
		if res.Message != wantMsg {
			t.Errorf("Message = %q, want %q", res.Message, wantMsg)
		}
		if got := tunOps.Calls(); !reflect.DeepEqual(got, []string{"IsTUNStateActive"}) {
			t.Fatalf("tunOps calls = %v, want [IsTUNStateActive]", got)
		}
		if got := sysProxy.Calls(); len(got) != 0 {
			t.Fatalf("sysProxy calls = %v, want none", got)
		}

		after, err := store.Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if after == nil || after.Dirty {
			t.Fatalf("state after clean TUN startup check = %+v, want dirty=false", after)
		}
		assertZeroTempFiles(t, configDir)
	})

	t.Run("IsTUNStateActive false returns error if MarkClean fails", func(t *testing.T) {
		configDir := t.TempDir()
		inner := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := inner.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         999999,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		markErr := errors.New("read-only filesystem")
		store := &failingRecoveryStore{inner: inner, markCleanErr: markErr}
		tunOps := &mockTUNRecoveryOps{active: false}
		restorer := NewRestorer(
			store,
			nil,
			WithPIDFunc(func() int { return 12345 }),
			WithTUNRecoveryOps(tunOps),
		)

		_, err := restorer.CheckAndRecoverOnStartup(context.Background())
		if !errors.Is(err, markErr) {
			t.Fatalf("CheckAndRecoverOnStartup() error = %v, want wrapped %v", err, markErr)
		}
		after, loadErr := inner.Load()
		if loadErr != nil || after == nil || !after.Dirty {
			t.Fatalf("state = (%+v, %v), want dirty=true preserved on MarkClean error", after, loadErr)
		}
	})

	t.Run("IsTUNStateActive true leaves dirty and requires elevation", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         999999,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		tunOps := &mockTUNRecoveryOps{active: true}
		restorer := NewRestorer(
			store,
			nil,
			WithPIDFunc(func() int { return 12345 }),
			WithTUNRecoveryOps(tunOps),
		)

		res, err := restorer.CheckAndRecoverOnStartup(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRecoverOnStartup() error: %v", err)
		}
		if res.Recovered {
			t.Error("Recovered = true, want false")
		}
		if res.Mode != RecoveryModeTUN {
			t.Errorf("Mode = %q, want %q", res.Mode, RecoveryModeTUN)
		}
		if !res.NeedsElevation {
			t.Error("NeedsElevation = false, want true")
		}
		const wantMsg = "Previous TUN session ended unexpectedly. Click Restore Network to clean up remaining TUN routes and DNS."
		if res.Message != wantMsg {
			t.Errorf("Message = %q, want %q", res.Message, wantMsg)
		}
		if got := tunOps.Calls(); !reflect.DeepEqual(got, []string{"IsTUNStateActive"}) {
			t.Fatalf("tunOps calls = %v, want [IsTUNStateActive]", got)
		}

		after, err := store.Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if after == nil || !after.Dirty {
			t.Fatalf("state = %+v, want dirty=true preserved", after)
		}
		if !reflect.DeepEqual(after.TUNSnapshot, &snap) {
			t.Fatalf("TUNSnapshot = %+v, want %+v", after.TUNSnapshot, &snap)
		}
	})

	t.Run("IsTUNStateActive error leaves dirty and requires elevation", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         999999,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		tunOps := &mockTUNRecoveryOps{
			active:    false,
			activeErr: errors.New("netlink probe failed"),
		}
		restorer := NewRestorer(
			store,
			nil,
			WithPIDFunc(func() int { return 12345 }),
			WithTUNRecoveryOps(tunOps),
		)

		res, err := restorer.CheckAndRecoverOnStartup(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRecoverOnStartup() error: %v, want nil with NeedsElevation=true", err)
		}
		if res.Recovered {
			t.Error("Recovered = true, want false")
		}
		if res.Mode != RecoveryModeTUN {
			t.Errorf("Mode = %q, want %q", res.Mode, RecoveryModeTUN)
		}
		if !res.NeedsElevation {
			t.Error("NeedsElevation = false, want true")
		}
		const wantMsg = "Previous TUN session ended unexpectedly. Click Restore Network to clean up remaining TUN routes and DNS."
		if res.Message != wantMsg {
			t.Errorf("Message = %q, want %q", res.Message, wantMsg)
		}

		after, err := store.Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if after == nil || !after.Dirty {
			t.Fatalf("state = %+v, want dirty=true preserved", after)
		}
	})

	t.Run("same PID skips IsTUNStateActive and preserves dirty state", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		const livePID = 65432
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         livePID,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		tunOps := &mockTUNRecoveryOps{active: false}
		restorer := NewRestorer(
			store,
			nil,
			WithPIDFunc(func() int { return livePID }),
			WithTUNRecoveryOps(tunOps),
		)

		res, err := restorer.CheckAndRecoverOnStartup(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRecoverOnStartup() error: %v", err)
		}
		if res != (StartupRecoveryResult{}) {
			t.Fatalf("result = %+v, want zero StartupRecoveryResult", res)
		}
		if got := tunOps.Calls(); len(got) != 0 {
			t.Fatalf("tunOps calls = %v, want none for same PID", got)
		}
		after, err := store.Load()
		if err != nil || after == nil || !after.Dirty {
			t.Fatalf("state = (%+v, %v), want dirty=true preserved", after, err)
		}
	})
}

func TestRestoreTUNSessionAndRestoreNetworkWithMockTUNOps(t *testing.T) {
	t.Run("RestoreTUNSession invokes RestoreTUN with exact snapshot idempotently", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         77777,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		sysProxy := &mockSysProxyManager{}
		tunOps := &mockTUNRecoveryOps{}
		restorer := NewRestorer(store, sysProxy, WithTUNRecoveryOps(tunOps))

		if err := restorer.RestoreTUNSession(context.Background()); err != nil {
			t.Fatalf("first RestoreTUNSession() error: %v", err)
		}
		if err := restorer.RestoreTUNSession(context.Background()); err != nil {
			t.Fatalf("second RestoreTUNSession() error: %v", err)
		}

		if got := tunOps.Calls(); !reflect.DeepEqual(got, []string{"RestoreTUN"}) {
			t.Fatalf("tunOps calls = %v, want single [RestoreTUN] across two calls", got)
		}
		restored := tunOps.RestoredSnapshots()
		if len(restored) != 1 || !reflect.DeepEqual(restored[0], snap) {
			t.Fatalf("restored snapshots = %+v, want [%+v]", restored, snap)
		}
		if got := sysProxy.Calls(); len(got) != 0 {
			t.Fatalf("sysProxy calls = %v, want none", got)
		}

		after, err := store.Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if after == nil || after.Dirty {
			t.Fatalf("state = %+v, want dirty=false", after)
		}
		assertZeroTempFiles(t, configDir)
	})

	t.Run("RestoreNetwork restores dirty TUN session with exact snapshot idempotently", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         77777,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		sysProxy := &mockSysProxyManager{}
		tunOps := &mockTUNRecoveryOps{}
		restorer := NewRestorer(store, sysProxy, WithTUNRecoveryOps(tunOps))

		if err := restorer.RestoreNetwork(context.Background()); err != nil {
			t.Fatalf("first RestoreNetwork() error: %v", err)
		}
		if err := restorer.RestoreNetwork(context.Background()); err != nil {
			t.Fatalf("second RestoreNetwork() error: %v", err)
		}

		if got := tunOps.Calls(); !reflect.DeepEqual(got, []string{"RestoreTUN"}) {
			t.Fatalf("tunOps calls = %v, want single [RestoreTUN] across two calls", got)
		}
		restored := tunOps.RestoredSnapshots()
		if len(restored) != 1 || !reflect.DeepEqual(restored[0], snap) {
			t.Fatalf("restored snapshots = %+v, want [%+v]", restored, snap)
		}
		if got := sysProxy.Calls(); len(got) != 0 {
			t.Fatalf("sysProxy calls = %v, want none", got)
		}

		after, err := store.Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if after == nil || after.Dirty {
			t.Fatalf("state = %+v, want dirty=false", after)
		}
	})

	t.Run("RestoreTUNSession preserves dirty state on failure and recovers on retry", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         77777,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		restoreErr := errors.New("helper elevation canceled")
		tunOps := &mockTUNRecoveryOps{restoreErr: restoreErr}
		restorer := NewRestorer(store, nil, WithTUNRecoveryOps(tunOps))

		err := restorer.RestoreTUNSession(context.Background())
		if !errors.Is(err, restoreErr) {
			t.Fatalf("RestoreTUNSession() error = %v, want wrapped %v", err, restoreErr)
		}

		afterFail, err := store.Load()
		if err != nil {
			t.Fatalf("Load() after failure error: %v", err)
		}
		if afterFail == nil || !afterFail.Dirty {
			t.Fatalf("state after failed restore = %+v, want dirty=true preserved", afterFail)
		}
		if !reflect.DeepEqual(afterFail.TUNSnapshot, &snap) {
			t.Fatalf("TUNSnapshot after failed restore = %+v, want %+v", afterFail.TUNSnapshot, &snap)
		}

		tunOps.SetRestoreErr(nil)
		if err := restorer.RestoreTUNSession(context.Background()); err != nil {
			t.Fatalf("retry RestoreTUNSession() error: %v", err)
		}
		if got := tunOps.Calls(); !reflect.DeepEqual(got, []string{"RestoreTUN", "RestoreTUN"}) {
			t.Fatalf("tunOps calls = %v, want two RestoreTUN calls", got)
		}
		afterRetry, err := store.Load()
		if err != nil {
			t.Fatalf("Load() after retry error: %v", err)
		}
		if afterRetry == nil || afterRetry.Dirty {
			t.Fatalf("state after retry = %+v, want dirty=false", afterRetry)
		}
	})

	t.Run("RestoreNetwork preserves dirty state when RestoreTUN fails", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         77777,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		restoreErr := errors.New("pkexec dismissed")
		tunOps := &mockTUNRecoveryOps{restoreErr: restoreErr}
		restorer := NewRestorer(store, nil, WithTUNRecoveryOps(tunOps))

		err := restorer.RestoreNetwork(context.Background())
		if !errors.Is(err, restoreErr) {
			t.Fatalf("RestoreNetwork() error = %v, want wrapped %v", err, restoreErr)
		}

		after, loadErr := store.Load()
		if loadErr != nil {
			t.Fatalf("Load() error: %v", loadErr)
		}
		if after == nil || !after.Dirty {
			t.Fatalf("state = %+v, want dirty=true preserved", after)
		}
	})

	t.Run("RestoreTUNSession on missing or clean state marks clean without calling RestoreTUN", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		tunOps := &mockTUNRecoveryOps{}
		sysProxy := &mockSysProxyManager{}
		restorer := NewRestorer(store, sysProxy, WithTUNRecoveryOps(tunOps))

		if err := restorer.RestoreTUNSession(context.Background()); err != nil {
			t.Fatalf("RestoreTUNSession() on missing state error: %v", err)
		}
		if err := restorer.RestoreTUNSession(context.Background()); err != nil {
			t.Fatalf("RestoreTUNSession() on clean state error: %v", err)
		}
		if got := tunOps.Calls(); len(got) != 0 {
			t.Fatalf("tunOps calls = %v, want none", got)
		}
		if got := sysProxy.Calls(); len(got) != 0 {
			t.Fatalf("sysProxy calls = %v, want none", got)
		}
		state, err := store.Load()
		if err != nil || state == nil || state.Dirty {
			t.Fatalf("state = (%+v, %v), want clean state persisted", state, err)
		}
	})

	t.Run("RestoreTUNSession delegates proxy mode to proxy restore", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleProxySnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:          RecoveryModeProxy,
			PID:           88888,
			ProxySnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		sysProxy := &mockSysProxyManager{}
		tunOps := &mockTUNRecoveryOps{}
		restorer := NewRestorer(store, sysProxy, WithTUNRecoveryOps(tunOps))

		if err := restorer.RestoreTUNSession(context.Background()); err != nil {
			t.Fatalf("RestoreTUNSession() error: %v", err)
		}
		if got := sysProxy.Calls(); !reflect.DeepEqual(got, []string{"Restore"}) {
			t.Fatalf("sysProxy calls = %v, want [Restore]", got)
		}
		if got := tunOps.Calls(); len(got) != 0 {
			t.Fatalf("tunOps calls = %v, want none", got)
		}
		after, err := store.Load()
		if err != nil || after == nil || after.Dirty {
			t.Fatalf("state = (%+v, %v), want dirty=false", after, err)
		}
	})

	t.Run("RestoreTUNSession with nil TUNSnapshot passes empty snapshot", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		if err := store.SaveDirty(RecoveryState{
			Mode: RecoveryModeTUN,
			PID:  88888,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		tunOps := &mockTUNRecoveryOps{}
		restorer := NewRestorer(store, nil, WithTUNRecoveryOps(tunOps))

		if err := restorer.RestoreTUNSession(context.Background()); err != nil {
			t.Fatalf("RestoreTUNSession() error: %v", err)
		}
		restored := tunOps.RestoredSnapshots()
		if len(restored) != 1 || !reflect.DeepEqual(restored[0], TUNSnapshot{}) {
			t.Fatalf("restored snapshots = %+v, want [empty TUNSnapshot]", restored)
		}
		after, err := store.Load()
		if err != nil || after == nil || after.Dirty {
			t.Fatalf("state = (%+v, %v), want dirty=false", after, err)
		}
	})

	t.Run("RestoreTUNSession returns ErrTUNRestoreNotSupported when tunOps is nil", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         88888,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		restorer := NewRestorer(store, nil, WithTUNRecoveryOps(nil))
		err := restorer.RestoreTUNSession(context.Background())
		if !errors.Is(err, ErrTUNRestoreNotSupported) {
			t.Fatalf("RestoreTUNSession() error = %v, want ErrTUNRestoreNotSupported", err)
		}
		after, loadErr := store.Load()
		if loadErr != nil || after == nil || !after.Dirty {
			t.Fatalf("state = (%+v, %v), want dirty=true preserved", after, loadErr)
		}
	})

	t.Run("RestoreTUNSession rejects unknown dirty mode without clearing state", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		if err := store.SaveDirty(RecoveryState{
			Mode: "bogus",
			PID:  88888,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		tunOps := &mockTUNRecoveryOps{}
		restorer := NewRestorer(store, nil, WithTUNRecoveryOps(tunOps))
		err := restorer.RestoreTUNSession(context.Background())
		if !errors.Is(err, ErrUnsupportedMode) {
			t.Fatalf("RestoreTUNSession() error = %v, want ErrUnsupportedMode", err)
		}
		after, loadErr := store.Load()
		if loadErr != nil || after == nil || !after.Dirty {
			t.Fatalf("state = (%+v, %v), want dirty=true preserved", after, loadErr)
		}
	})
}

func TestCompleteTUNSession(t *testing.T) {
	t.Run("marks dirty TUN state clean without calling tunOps.RestoreTUN", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleTUNSnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:        RecoveryModeTUN,
			PID:         88888,
			TUNSnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		sysProxy := &mockSysProxyManager{}
		tunOps := &mockTUNRecoveryOps{}
		restorer := NewRestorer(store, sysProxy, WithTUNRecoveryOps(tunOps))

		if err := restorer.CompleteTUNSession(context.Background()); err != nil {
			t.Fatalf("CompleteTUNSession() error: %v", err)
		}
		if err := restorer.CompleteTUNSession(context.Background()); err != nil {
			t.Fatalf("second CompleteTUNSession() error: %v", err)
		}
		if got := tunOps.Calls(); len(got) != 0 {
			t.Fatalf("tunOps calls = %v, want none", got)
		}
		if got := sysProxy.Calls(); len(got) != 0 {
			t.Fatalf("sysProxy calls = %v, want none", got)
		}
		after, err := store.Load()
		if err != nil || after == nil || after.Dirty {
			t.Fatalf("state = (%+v, %v), want dirty=false", after, err)
		}
	})

	t.Run("delegates dirty proxy state to sysProxy.Restore", func(t *testing.T) {
		configDir := t.TempDir()
		store := mustNewStore(t, configDir)
		snap := sampleProxySnapshot()
		if err := store.SaveDirty(RecoveryState{
			Mode:          RecoveryModeProxy,
			PID:           88888,
			ProxySnapshot: &snap,
		}); err != nil {
			t.Fatalf("SaveDirty() error: %v", err)
		}

		sysProxy := &mockSysProxyManager{}
		tunOps := &mockTUNRecoveryOps{}
		restorer := NewRestorer(store, sysProxy, WithTUNRecoveryOps(tunOps))

		if err := restorer.CompleteTUNSession(context.Background()); err != nil {
			t.Fatalf("CompleteTUNSession() error: %v", err)
		}
		if got := sysProxy.Calls(); !reflect.DeepEqual(got, []string{"Restore"}) {
			t.Fatalf("sysProxy calls = %v, want [Restore]", got)
		}
		if got := tunOps.Calls(); len(got) != 0 {
			t.Fatalf("tunOps calls = %v, want none", got)
		}
		after, err := store.Load()
		if err != nil || after == nil || after.Dirty {
			t.Fatalf("state = (%+v, %v), want dirty=false", after, err)
		}
	})
}
