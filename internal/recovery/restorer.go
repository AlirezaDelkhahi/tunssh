package recovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/AlirezaDelkhahi/tunssh/internal/sysproxy"
)

var (
	// ErrTUNRestoreNotSupported is returned when TUN recovery is requested before Milestone 2 support is enabled.
	ErrTUNRestoreNotSupported = errors.New("recovery: Milestone 2 TUN network restore is not enabled yet")
	// ErrUnsupportedMode is returned when recovery_state.json holds an unknown session mode.
	ErrUnsupportedMode = errors.New("recovery: unsupported recovery mode")
)

// StartupRecoveryResult describes the outcome of boot/startup dirty-state inspection.
type StartupRecoveryResult struct {
	Recovered      bool   `json:"recovered"`
	Mode           string `json:"mode,omitempty"`
	NeedsElevation bool   `json:"needs_elevation,omitempty"`
	Message        string `json:"message,omitempty"`
}

// TUNRecoveryOps abstracts OS-level Milestone 2 TUN state inspection and network restoration.
type TUNRecoveryOps interface {
	IsTUNStateActive(ctx context.Context) (bool, error)
	RestoreTUN(ctx context.Context, snap TUNSnapshot) error
}

// RestorerOption configures optional Restorer dependencies for deterministic testing.
type RestorerOption func(*Restorer)

// WithPIDFunc overrides the process ID lookup used for dirty-state ownership checks.
func WithPIDFunc(fn func() int) RestorerOption {
	return func(r *Restorer) {
		if fn != nil {
			r.pidFn = fn
		}
	}
}

// WithNowFunc overrides the clock used to stamp dirty recovery records.
func WithNowFunc(fn func() time.Time) RestorerOption {
	return func(r *Restorer) {
		if fn != nil {
			r.nowFn = fn
		}
	}
}

// WithTUNRecoveryOps configures optional Milestone 2 TUN inspection and restore callbacks.
func WithTUNRecoveryOps(ops TUNRecoveryOps) RestorerOption {
	return func(r *Restorer) {
		r.tunOps = ops
	}
}

// Restorer coordinates crash-safe state persistence with OS network mutations and startup recovery.
type Restorer struct {
	store    RecoveryStore
	sysProxy sysproxy.SystemProxyManager
	tunOps   TUNRecoveryOps
	pidFn    func() int
	nowFn    func() time.Time
}

// NewRestorer constructs a Restorer coordinating store and sysProxy.
func NewRestorer(store RecoveryStore, sysProxy sysproxy.SystemProxyManager, opts ...RestorerOption) *Restorer {
	r := &Restorer{
		store:    store,
		sysProxy: sysProxy,
		pidFn:    os.Getpid,
		nowFn:    func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}

// BeginProxySession snapshots the OS proxy, persists dirty state first, and only then enables the proxy.
func (r *Restorer) BeginProxySession(ctx context.Context, cfg sysproxy.ProxyApplyConfig) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.requireStore(); err != nil {
		return err
	}
	if err := r.requireSysProxy(); err != nil {
		return err
	}

	snap, err := r.sysProxy.CaptureSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("recovery: capture proxy snapshot: %w", err)
	}

	state := RecoveryState{
		SchemaVersion: SchemaVersion,
		Dirty:         true,
		Mode:          RecoveryModeProxy,
		PID:           r.currentPID(),
		UpdatedAtUTC:  r.nowUTC(),
		ProxySnapshot: &snap,
	}
	if err := r.store.SaveDirty(state); err != nil {
		return fmt.Errorf("recovery: save dirty state: %w", err)
	}

	if enableErr := r.sysProxy.Enable(ctx, cfg); enableErr != nil {
		restoreCtx := context.WithoutCancel(ctx)
		if restoreErr := r.sysProxy.Restore(restoreCtx, snap); restoreErr != nil {
			return fmt.Errorf("recovery: enable system proxy: %w (rollback restore failed: %w)", enableErr, restoreErr)
		}
		if cleanErr := r.store.MarkClean(); cleanErr != nil {
			return fmt.Errorf("recovery: enable system proxy: %w (mark clean failed: %w)", enableErr, cleanErr)
		}
		return fmt.Errorf("recovery: enable system proxy: %w", enableErr)
	}

	return nil
}

// BeginTUNSession persists dirty TUN recovery state strictly prior to any OS route or DNS mutation.
func (r *Restorer) BeginTUNSession(ctx context.Context, snap TUNSnapshot) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.requireStore(); err != nil {
		return err
	}

	snapCopy := cloneTUNSnapshot(snap)
	state := RecoveryState{
		SchemaVersion: SchemaVersion,
		Dirty:         true,
		Mode:          RecoveryModeTUN,
		PID:           r.currentPID(),
		UpdatedAtUTC:  r.nowUTC(),
		TUNSnapshot:   &snapCopy,
	}
	if err := r.store.SaveDirty(state); err != nil {
		return fmt.Errorf("recovery: save dirty state: %w", err)
	}
	return nil
}

// RestoreProxySession idempotently restores a dirty proxy session and marks recovery_state.json clean.
func (r *Restorer) RestoreProxySession(ctx context.Context) error {
	ctx, state, err := r.loadForOperation(ctx)
	if err != nil {
		return err
	}
	return r.restoreProxyWithState(ctx, state)
}

// RestoreTUNSession idempotently restores a dirty TUN session (or delegates proxy mode) and marks recovery_state.json clean.
func (r *Restorer) RestoreTUNSession(ctx context.Context) error {
	ctx, state, err := r.loadForOperation(ctx)
	if err != nil {
		return err
	}
	return r.restoreTUNWithState(ctx, state)
}

// CompleteTUNSession idempotently marks recovery_state.json clean after an active TUN session or
// failed StartTUN attempt has already cleanly rolled back OS routes and DNS in-band.
func (r *Restorer) CompleteTUNSession(ctx context.Context) error {
	ctx, state, err := r.loadForOperation(ctx)
	if err != nil {
		return err
	}
	if state == nil || !state.Dirty || state.Mode == RecoveryModeTUN {
		if err := r.store.MarkClean(); err != nil {
			return fmt.Errorf("recovery: mark clean: %w", err)
		}
		return nil
	}
	if state.Mode == RecoveryModeProxy {
		return r.restoreProxyWithState(ctx, state)
	}
	return fmt.Errorf("%w: %q", ErrUnsupportedMode, state.Mode)
}

// RestoreNetwork is the panic-button entry point that restores OS network state idempotently.
func (r *Restorer) RestoreNetwork(ctx context.Context) error {
	ctx, state, err := r.loadForOperation(ctx)
	if err != nil {
		return err
	}
	if state != nil && state.Dirty && state.Mode == RecoveryModeTUN {
		return r.restoreTUNWithState(ctx, state)
	}
	return r.restoreProxyWithState(ctx, state)
}

// CheckAndRecoverOnStartup inspects recovery_state.json on launch and recovers dirty sessions from dead PIDs.
func (r *Restorer) CheckAndRecoverOnStartup(ctx context.Context) (StartupRecoveryResult, error) {
	ctx, state, err := r.loadForOperation(ctx)
	if err != nil {
		return StartupRecoveryResult{}, err
	}
	if state == nil || !state.Dirty {
		return StartupRecoveryResult{}, nil
	}
	if state.PID == r.currentPID() {
		return StartupRecoveryResult{}, nil
	}

	switch state.Mode {
	case RecoveryModeProxy:
		if err := r.restoreProxyWithState(ctx, state); err != nil {
			return StartupRecoveryResult{}, err
		}
		return StartupRecoveryResult{
			Recovered: true,
			Mode:      RecoveryModeProxy,
			Message:   "Previous session ended unexpectedly. OS proxy settings were automatically restored.",
		}, nil
	case RecoveryModeTUN:
		if r.tunOps != nil {
			active, activeErr := r.tunOps.IsTUNStateActive(ctx)
			if activeErr == nil && !active {
				if err := r.store.MarkClean(); err != nil {
					return StartupRecoveryResult{}, fmt.Errorf("recovery: mark clean: %w", err)
				}
				return StartupRecoveryResult{
					Recovered:      true,
					Mode:           RecoveryModeTUN,
					NeedsElevation: false,
					Message:        "Previous TUN session ended unexpectedly; OS network routes were already cleanly restored.",
				}, nil
			}
		}
		return StartupRecoveryResult{
			Recovered:      false,
			Mode:           RecoveryModeTUN,
			NeedsElevation: true,
			Message:        "Previous TUN session ended unexpectedly. Click Restore Network to clean up remaining TUN routes and DNS.",
		}, nil
	default:
		return StartupRecoveryResult{}, fmt.Errorf("%w: %q", ErrUnsupportedMode, state.Mode)
	}
}

func (r *Restorer) loadForOperation(ctx context.Context) (context.Context, *RecoveryState, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := r.requireStore(); err != nil {
		return nil, nil, err
	}
	state, err := r.store.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("recovery: load state: %w", err)
	}
	return ctx, state, nil
}

func (r *Restorer) restoreProxyWithState(ctx context.Context, state *RecoveryState) error {
	if state == nil || !state.Dirty {
		if err := r.store.MarkClean(); err != nil {
			return fmt.Errorf("recovery: mark clean: %w", err)
		}
		return nil
	}

	switch state.Mode {
	case RecoveryModeTUN:
		return ErrTUNRestoreNotSupported
	case "", RecoveryModeProxy:
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedMode, state.Mode)
	}

	if state.ProxySnapshot != nil {
		if err := r.requireSysProxy(); err != nil {
			return err
		}
		if err := r.sysProxy.Restore(ctx, *state.ProxySnapshot); err != nil {
			return fmt.Errorf("recovery: restore system proxy: %w", err)
		}
	}

	if err := r.store.MarkClean(); err != nil {
		return fmt.Errorf("recovery: mark clean: %w", err)
	}
	return nil
}

func (r *Restorer) restoreTUNWithState(ctx context.Context, state *RecoveryState) error {
	if state == nil || !state.Dirty {
		if err := r.store.MarkClean(); err != nil {
			return fmt.Errorf("recovery: mark clean: %w", err)
		}
		return nil
	}

	switch state.Mode {
	case RecoveryModeProxy:
		return r.restoreProxyWithState(ctx, state)
	case RecoveryModeTUN:
		if r.tunOps == nil {
			return ErrTUNRestoreNotSupported
		}
		var snap TUNSnapshot
		if state.TUNSnapshot != nil {
			snap = cloneTUNSnapshot(*state.TUNSnapshot)
		}
		if err := r.tunOps.RestoreTUN(ctx, snap); err != nil {
			return fmt.Errorf("recovery: restore TUN: %w", err)
		}
		if err := r.store.MarkClean(); err != nil {
			return fmt.Errorf("recovery: mark clean: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedMode, state.Mode)
	}
}

func (r *Restorer) requireStore() error {
	if r == nil || r.store == nil {
		return errors.New("recovery: recovery store must not be nil")
	}
	return nil
}

func (r *Restorer) requireSysProxy() error {
	if r == nil || r.sysProxy == nil {
		return errors.New("recovery: system proxy manager must not be nil")
	}
	return nil
}

func (r *Restorer) currentPID() int {
	if r != nil && r.pidFn != nil {
		return r.pidFn()
	}
	return os.Getpid()
}

func (r *Restorer) nowUTC() time.Time {
	if r != nil && r.nowFn != nil {
		return r.nowFn().UTC()
	}
	return time.Now().UTC()
}

func cloneTUNSnapshot(snap TUNSnapshot) TUNSnapshot {
	snap.OrigDNSServers = slices.Clone(snap.OrigDNSServers)
	if snap.WinAdapterDNSBackups != nil {
		winBackups := make([]WinAdapterDNSBackup, len(snap.WinAdapterDNSBackups))
		for i, b := range snap.WinAdapterDNSBackups {
			b.IPv4DNS = slices.Clone(b.IPv4DNS)
			b.IPv6DNS = slices.Clone(b.IPv6DNS)
			winBackups[i] = b
		}
		snap.WinAdapterDNSBackups = winBackups
	}
	if snap.LinuxDNSBackups != nil {
		linuxBackups := make([]LinuxDNSBackup, len(snap.LinuxDNSBackups))
		for i, b := range snap.LinuxDNSBackups {
			b.DNSServers = slices.Clone(b.DNSServers)
			linuxBackups[i] = b
		}
		snap.LinuxDNSBackups = linuxBackups
	}
	snap.InstalledRoutes = slices.Clone(snap.InstalledRoutes)
	return snap
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
