package recovery

import (
	"context"
	"errors"
	"fmt"
	"os"
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

// Restorer coordinates crash-safe state persistence with OS system proxy mutations and startup recovery.
type Restorer struct {
	store    RecoveryStore
	sysProxy sysproxy.SystemProxyManager
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
		PID:           r.pidFn(),
		UpdatedAtUTC:  r.nowFn().UTC(),
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

// RestoreProxySession idempotently restores a dirty proxy session and marks recovery_state.json clean.
func (r *Restorer) RestoreProxySession(ctx context.Context) error {
	ctx, state, err := r.loadForOperation(ctx)
	if err != nil {
		return err
	}
	return r.restoreProxyWithState(ctx, state)
}

// RestoreNetwork is the panic-button entry point that restores OS network state idempotently.
func (r *Restorer) RestoreNetwork(ctx context.Context) error {
	ctx, state, err := r.loadForOperation(ctx)
	if err != nil {
		return err
	}
	if state != nil && state.Dirty && state.Mode == RecoveryModeTUN {
		return ErrTUNRestoreNotSupported
	}
	return r.restoreProxyWithState(ctx, state)
}

// CheckAndRecoverOnStartup inspects recovery_state.json on launch and recovers dirty proxy sessions from dead PIDs.
func (r *Restorer) CheckAndRecoverOnStartup(ctx context.Context) (StartupRecoveryResult, error) {
	ctx, state, err := r.loadForOperation(ctx)
	if err != nil {
		return StartupRecoveryResult{}, err
	}
	if state == nil || !state.Dirty {
		return StartupRecoveryResult{}, nil
	}
	if state.PID == r.pidFn() {
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
		return StartupRecoveryResult{
			Recovered:      false,
			Mode:           RecoveryModeTUN,
			NeedsElevation: true,
			Message:        "Previous TUN session ended unexpectedly (Milestone 2 elevation required to restore routes).",
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

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
