// Package app orchestrates SSH tunnel lifecycle, profiles, secrets,
// crash recovery, share links, redacted logging, and frontend DTO contracts.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AlirezaDelkhahi/tunssh/internal/crypto"
	"github.com/AlirezaDelkhahi/tunssh/internal/profile"
	"github.com/AlirezaDelkhahi/tunssh/internal/proxy"
	"github.com/AlirezaDelkhahi/tunssh/internal/recovery"
	"github.com/AlirezaDelkhahi/tunssh/internal/splitroute"
	"github.com/AlirezaDelkhahi/tunssh/internal/sshclient"
	"github.com/AlirezaDelkhahi/tunssh/internal/sysproxy"
)

const (
	defaultStatsInterval      = 1 * time.Second
	defaultOpTimeout          = 5 * time.Second
	persistentTUNSetupTimeout = 30 * time.Second
	maxPrivateKeyFileBytes    = 256 * 1024
)

// ProxyController abstracts the local SOCKS5/HTTP CONNECT proxy server lifecycle.
type ProxyController interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	SOCKSAddr() string
	HTTPAddr() string
	Stats() proxy.Stats
}

// EventEmitter delivers typed backend events to the UI or test harness.
type EventEmitter interface {
	Emit(eventName string, data any)
}

// NopEventEmitter discards emitted events when no UI listener is attached.
type NopEventEmitter struct{}

// Emit implements EventEmitter as a no-op.
func (NopEventEmitter) Emit(string, any) {}

// HostKeyPinDTO represents a TOFU-pinned SSH server fingerprint in JSON payloads.
type HostKeyPinDTO struct {
	Algorithm string `json:"algorithm"`
	SHA256    string `json:"sha256"`
}

// ProfileView exposes non-secret profile metadata and secret presence flags to the UI.
type ProfileView struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Host             string         `json:"host"`
	Port             int            `json:"port"`
	Username         string         `json:"username"`
	AuthType         string         `json:"auth_type"`
	PinnedHostKey    *HostKeyPinDTO `json:"pinned_host_key"`
	BypassIranLAN    bool           `json:"bypass_iran_lan"`
	PreferredMode    string         `json:"preferred_mode"`
	HasSecret        bool           `json:"has_secret"`
	HasKeyPassphrase bool           `json:"has_key_passphrase"`
	CreatedAt        string         `json:"created_at"`
	UpdatedAt        string         `json:"updated_at"`
}

// SaveProfileRequest carries create/update profile parameters from the UI modal.
type SaveProfileRequest struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	Username            string `json:"username"`
	AuthType            string `json:"auth_type"`
	BypassIranLAN       bool   `json:"bypass_iran_lan"`
	PreferredMode       string `json:"preferred_mode"`
	Password            string `json:"password"`
	PrivateKey          string `json:"private_key"`
	KeyPassphrase       string `json:"key_passphrase"`
	KeepExistingSecrets bool   `json:"keep_existing_secrets"`
}

// MappedErrorDTO describes an actionable Iran-aware error banner for the UI.
type MappedErrorDTO struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	ActionHint string `json:"action_hint"`
	Retryable  bool   `json:"retryable"`
}

// TunnelStatusDTO represents live tunnel connection state, ports, counters, and rates.
type TunnelStatusDTO struct {
	State           string          `json:"state"`
	ProfileID       string          `json:"profile_id"`
	Mode            string          `json:"mode"`
	Attempt         int             `json:"attempt"`
	RTTMs           int64           `json:"rtt_ms"`
	RxBytes         uint64          `json:"rx_bytes"`
	TxBytes         uint64          `json:"tx_bytes"`
	RxRateBPS       uint64          `json:"rx_rate_bps"`
	TxRateBPS       uint64          `json:"tx_rate_bps"`
	ConnectedAtUnix int64           `json:"connected_at_unix"`
	SOCKSPort       int             `json:"socks_port"`
	HTTPPort        int             `json:"http_port"`
	EnvSnippet      string          `json:"env_snippet"`
	LastError       *MappedErrorDTO `json:"last_error"`
}

// HostKeyPromptDTO triggers the TOFU verification or MITM mismatch modal.
type HostKeyPromptDTO struct {
	ProfileID         string `json:"profile_id"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	IsMismatch        bool   `json:"is_mismatch"`
	Algorithm         string `json:"algorithm"`
	SHA256            string `json:"sha256"`
	ExpectedAlgorithm string `json:"expected_algorithm,omitempty"`
	ExpectedSHA256    string `json:"expected_sha256,omitempty"`
}

// StartupRecoveryDTO reports startup crash-recovery outcomes to the recovery banner.
type StartupRecoveryDTO struct {
	Recovered      bool   `json:"recovered"`
	Mode           string `json:"mode,omitempty"`
	NeedsElevation bool   `json:"needs_elevation,omitempty"`
	Message        string `json:"message,omitempty"`
}

// ProxyCapabilitiesDTO describes OS automatic system proxy capabilities.
type ProxyCapabilitiesDTO struct {
	AutoSupported bool   `json:"auto_supported"`
	DesktopEnv    string `json:"desktop_env"`
}

// ShareInspectDTO returns unencrypted envelope metadata for an sshtun://v1/ share link.
type ShareInspectDTO struct {
	Version    int    `json:"version"`
	Mode       string `json:"mode"`
	HasHostKey bool   `json:"has_host_key"`
}

// BootstrapStateDTO holds the initial application state loaded by the UI on mount.
type BootstrapStateDTO struct {
	VaultBackend string               `json:"vault_backend"`
	VaultLocked  bool                 `json:"vault_locked"`
	ProxyCaps    ProxyCapabilitiesDTO `json:"proxy_caps"`
	TUNCaps      TUNCapsDTO           `json:"tun_caps"`
	Status       TunnelStatusDTO      `json:"status"`
	Profiles     []ProfileView        `json:"profiles"`
	Recovery     *StartupRecoveryDTO  `json:"recovery"`
	Milestone    int                  `json:"milestone"`
	TUNEnabled   bool                 `json:"tun_enabled"`
}

// Config injects all dependencies required by AppService without coupling to Wails or systray.
type Config struct {
	Profiles            profile.ProfileStore
	Secrets             profile.SecretStore
	Engine              sshclient.Engine
	NewProxy            func(dialer proxy.Dialer, cfg proxy.Config) (ProxyController, error)
	ProxyConfig         proxy.Config
	SysProxy            sysproxy.SystemProxyManager
	Restorer            *recovery.Restorer
	TUN                 TUNSessionController
	ResolvePeerIP       func(ctx context.Context, host string) (netip.Addr, error)
	EnablePersistentTUN func(ctx context.Context) error
	Emitter             EventEmitter
	Scrubber            *SecretScrubber
	LogBuffer           *LogBuffer
	Logger              *slog.Logger
	FilePicker          func(ctx context.Context) (string, error)
	StatsInterval       time.Duration
	DialTimeout         time.Duration
	Watchdog            sshclient.WatchdogConfig
	BackoffBase         time.Duration
	BackoffMax          time.Duration
}

// AppService provides the headless application facade bound by Wails and tests.
type AppService struct {
	profiles            profile.ProfileStore
	secrets             profile.SecretStore
	engine              sshclient.Engine
	newProxy            func(dialer proxy.Dialer, cfg proxy.Config) (ProxyController, error)
	proxyConfig         proxy.Config
	sysProxy            sysproxy.SystemProxyManager
	restorer            *recovery.Restorer
	tun                 TUNSessionController
	resolvePeerIP       func(ctx context.Context, host string) (netip.Addr, error)
	enablePersistentTUN func(ctx context.Context) error
	emitter             EventEmitter
	scrubber            *SecretScrubber
	logBuffer           *LogBuffer
	logger              *slog.Logger
	filePicker          func(ctx context.Context) (string, error)
	statsInterval       time.Duration
	dialTimeout         time.Duration
	watchdog            sshclient.WatchdogConfig
	backoffBase         time.Duration
	backoffMax          time.Duration

	mu              sync.Mutex
	lifecycleCtx    context.Context
	unsubEngine     func()
	statsStop       chan struct{}
	statsDone       chan struct{}
	connectSeq      uint64
	disconnectedSeq uint64
	inDialSeq       uint64
	dialCancel      context.CancelFunc
	activeProfileID string
	activeMode      string
	activeBypass    bool
	activeProxy     ProxyController
	activeTUN       bool
	socksPort       int
	httpPort        int
	lastRecovery    *StartupRecoveryDTO
	lastStatsTime   time.Time
	lastRxBytes     uint64
	lastTxBytes     uint64
}

// NewAppService validates dependencies and constructs an AppService.
func NewAppService(cfg Config) (*AppService, error) {
	if cfg.Profiles == nil {
		return nil, errors.New("app: Profiles store must not be nil")
	}
	if cfg.Secrets == nil {
		return nil, errors.New("app: Secrets store must not be nil")
	}
	if cfg.Engine == nil {
		return nil, errors.New("app: Engine must not be nil")
	}
	if cfg.SysProxy == nil {
		return nil, errors.New("app: SysProxy must not be nil")
	}
	if cfg.Restorer == nil {
		return nil, errors.New("app: Restorer must not be nil")
	}

	newProxy := cfg.NewProxy
	if newProxy == nil {
		newProxy = func(dialer proxy.Dialer, pcfg proxy.Config) (ProxyController, error) {
			return proxy.NewServer(dialer, pcfg)
		}
	}

	proxyCfg := cfg.ProxyConfig
	if proxyCfg.SOCKSAddr == "" {
		proxyCfg.SOCKSAddr = proxy.DefaultSOCKSAddr
	}
	if proxyCfg.HTTPAddr == "" {
		proxyCfg.HTTPAddr = proxy.DefaultHTTPAddr
	}

	emitter := cfg.Emitter
	if emitter == nil {
		emitter = NopEventEmitter{}
	}

	scrubber := cfg.Scrubber
	if scrubber == nil {
		scrubber = NewSecretScrubber()
	}

	logBuffer := cfg.LogBuffer
	if logBuffer == nil {
		logBuffer = NewLogBuffer(DefaultLogBufferCapacity)
	}

	logger := cfg.Logger
	if logger == nil {
		handler := NewRedactingHandler(
			slog.NewTextHandler(io.Discard, nil),
			scrubber,
			logBuffer,
			func(entry LogEntryDTO) {
				emitter.Emit("tunnel:log", entry)
			},
		)
		logger = slog.New(handler)
	}

	statsInterval := cfg.StatsInterval
	if statsInterval <= 0 {
		statsInterval = defaultStatsInterval
	}

	resolvePeerIP := cfg.ResolvePeerIP
	if resolvePeerIP == nil {
		resolvePeerIP = splitroute.ResolveVPSPeerIP
	}

	enablePersistentTUN := cfg.EnablePersistentTUN
	if enablePersistentTUN == nil && cfg.TUN != nil {
		enablePersistentTUN = EnablePersistentTUNAccess
	}

	return &AppService{
		profiles:            cfg.Profiles,
		secrets:             cfg.Secrets,
		engine:              cfg.Engine,
		newProxy:            newProxy,
		proxyConfig:         proxyCfg,
		sysProxy:            cfg.SysProxy,
		restorer:            cfg.Restorer,
		tun:                 cfg.TUN,
		resolvePeerIP:       resolvePeerIP,
		enablePersistentTUN: enablePersistentTUN,
		emitter:             emitter,
		scrubber:            scrubber,
		logBuffer:           logBuffer,
		logger:              logger,
		filePicker:          cfg.FilePicker,
		statsInterval:       statsInterval,
		dialTimeout:         cfg.DialTimeout,
		watchdog:            cfg.Watchdog,
		backoffBase:         cfg.BackoffBase,
		backoffMax:          cfg.BackoffMax,
		lifecycleCtx:        context.Background(),
	}, nil
}

// Startup runs boot-time crash recovery, refreshes active secret scrubbing when unlocked,
// subscribes to SSH engine state events, and starts the periodic stats ticker.
func (s *AppService) Startup(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	stopCtx, stopCancel := boundedCleanupCtx(defaultOpTimeout)
	s.stopRuntimeLoops(stopCtx)
	stopCancel()

	statsStop := make(chan struct{})
	statsDone := make(chan struct{})

	s.mu.Lock()
	s.lifecycleCtx = ctx
	s.statsStop = statsStop
	s.statsDone = statsDone
	s.mu.Unlock()

	unsub := s.engine.Subscribe(s.handleEngineSnapshot)

	s.mu.Lock()
	if s.statsStop == statsStop {
		s.unsubEngine = unsub
	} else {
		s.mu.Unlock()
		unsub()
		return
	}
	s.mu.Unlock()

	go s.statsLoop(statsStop, statsDone)

	if !s.secrets.IsLocked() {
		if err := s.refreshScrubberSecrets(ctx); err != nil {
			s.logger.Warn("Failed to preload credential scrubber", "err", err)
		}
	}

	res, err := s.restorer.CheckAndRecoverOnStartup(ctx)
	if err != nil {
		s.logger.Error("Startup recovery check failed", "err", err)
		return
	}
	if res.Recovered || res.NeedsElevation {
		dto := StartupRecoveryDTO{
			Recovered:      res.Recovered,
			Mode:           res.Mode,
			NeedsElevation: res.NeedsElevation,
			Message:        s.scrubber.Scrub(res.Message),
		}
		s.mu.Lock()
		copyDTO := dto
		s.lastRecovery = &copyDTO
		s.mu.Unlock()

		s.logger.Warn("Startup crash recovery status", "mode", res.Mode, "recovered", res.Recovered, "needs_elevation", res.NeedsElevation)
		s.emitter.Emit("tunnel:recovery", dto)
	}
}

// Shutdown cleanly disconnects any active tunnel/proxy, restores OS proxy state, and stops background loops.
func (s *AppService) Shutdown(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.stopRuntimeLoops(ctx)
	timeout := s.cleanupTimeout()
	if deadline, ok := ctx.Deadline(); ok {
		if rem := time.Until(deadline); rem > timeout {
			timeout = rem
		}
	}
	disconnCtx, cancel := boundedCleanupCtx(timeout)
	defer cancel()
	_ = s.disconnect(disconnCtx)
}

func (s *AppService) stopRuntimeLoops(ctx context.Context) {
	s.mu.Lock()
	unsub := s.unsubEngine
	s.unsubEngine = nil
	statsStop := s.statsStop
	statsDone := s.statsDone
	s.statsStop = nil
	s.statsDone = nil
	s.mu.Unlock()

	if unsub != nil {
		unsub()
	}
	if statsStop != nil {
		close(statsStop)
		select {
		case <-statsDone:
		case <-ctx.Done():
		}
	}
}

// GetBootstrapState returns the initial state snapshot required to render the UI.
func (s *AppService) GetBootstrapState() (BootstrapStateDTO, error) {
	profiles, err := s.ListProfiles()
	if err != nil {
		return BootstrapStateDTO{}, err
	}
	caps := s.sysProxy.Capabilities()

	milestone := 1
	tunEnabled := false
	var tunCaps TUNCapsDTO
	if s.tun != nil {
		tunCaps = s.tun.Capabilities()
		if tunCaps.Supported {
			milestone = 2
			tunEnabled = true
		}
	}

	s.mu.Lock()
	var recCopy *StartupRecoveryDTO
	if s.lastRecovery != nil {
		c := *s.lastRecovery
		recCopy = &c
	}
	s.mu.Unlock()

	return BootstrapStateDTO{
		VaultBackend: s.secrets.BackendName(),
		VaultLocked:  s.secrets.IsLocked(),
		ProxyCaps: ProxyCapabilitiesDTO{
			AutoSupported: caps.AutoSupported,
			DesktopEnv:    caps.DesktopEnv,
		},
		TUNCaps:    tunCaps,
		Status:     s.buildStatusDTO(),
		Profiles:   profiles,
		Recovery:   recCopy,
		Milestone:  milestone,
		TUNEnabled: tunEnabled,
	}, nil
}

// EnablePersistentTUNAccess grants persistent Linux capabilities (when supported) so Full TUN runs without elevation prompts.
func (s *AppService) EnablePersistentTUNAccess() (string, error) {
	if s.tun == nil {
		return "", errors.New("Full TUN mode is not enabled")
	}
	caps := s.tun.Capabilities()
	if caps.HasPersistentCap {
		return "Persistent TUN capability is already active.", nil
	}
	if !caps.CanEnablePersistentCap || s.enablePersistentTUN == nil {
		return "", errors.New("persistent TUN capability setup is not available on this platform")
	}

	ctx, cancel := boundedOpCtx(s.currentLifecycleCtx(), persistentTUNSetupTimeout)
	defer cancel()
	if err := s.enablePersistentTUN(ctx); err != nil {
		s.logger.Warn("Failed to enable persistent TUN capability", "err", err)
		return "", err
	}
	s.logger.Info("Persistent TUN capability enabled for current executable.")
	return "Persistent TUN capability enabled. Restart tunssh to run Full TUN without elevation prompts.", nil
}

// UnlockVault unlocks the encrypted credential vault and loads active secrets into the log scrubber.
func (s *AppService) UnlockVault(passphrase string) error {
	if err := s.secrets.Unlock(passphrase); err != nil {
		return err
	}
	if err := s.refreshScrubberSecrets(s.currentLifecycleCtx()); err != nil {
		s.logger.Warn("Vault unlocked, but failed to refresh scrubber secrets", "err", err)
	}
	s.logger.Info("Local credential vault unlocked.")
	return nil
}

// ListProfiles returns UI views for all stored profiles without exposing secrets.
func (s *AppService) ListProfiles() ([]ProfileView, error) {
	ctx := s.currentLifecycleCtx()
	list, err := s.profiles.List(ctx)
	if err != nil {
		return nil, err
	}
	locked := s.secrets.IsLocked()
	out := make([]ProfileView, 0, len(list))
	for _, p := range list {
		var sec profile.ProfileSecrets
		if !locked {
			loaded, getErr := s.secrets.Get(ctx, p.ID)
			if getErr == nil {
				sec = loaded
			} else if !errors.Is(getErr, profile.ErrVaultLocked) {
				return nil, getErr
			}
		}
		out = append(out, toProfileView(p, sec))
	}
	return out, nil
}

// SaveProfile creates or updates a profile and its isolated secrets in SecretStore.
func (s *AppService) SaveProfile(req SaveProfileRequest) (ProfileView, error) {
	ctx := s.currentLifecycleCtx()
	if s.secrets.IsLocked() {
		return ProfileView{}, profile.ErrVaultLocked
	}

	reqID := strings.TrimSpace(req.ID)
	authType := profile.AuthType(strings.TrimSpace(req.AuthType))
	prefMode := profile.TunnelMode(strings.TrimSpace(req.PreferredMode))
	if prefMode == "" {
		prefMode = profile.ModeProxy
	}

	var (
		hasExisting bool
		existing    profile.Profile
		existingSec profile.ProfileSecrets
	)
	if reqID != "" {
		var err error
		existing, err = s.profiles.Get(ctx, reqID)
		if err != nil {
			return ProfileView{}, err
		}
		hasExisting = true
		existingSec, err = s.secrets.Get(ctx, reqID)
		if err != nil {
			return ProfileView{}, err
		}
	}

	var finalSecrets profile.ProfileSecrets
	if req.KeepExistingSecrets {
		if !hasExisting {
			return ProfileView{}, fmt.Errorf("%w: cannot keep existing secrets for a new profile", profile.ErrInvalidProfile)
		}
		switch authType {
		case profile.AuthPassword:
			if existingSec.Password == "" {
				return ProfileView{}, fmt.Errorf("%w: password is required", profile.ErrInvalidProfile)
			}
		case profile.AuthKey:
			if strings.TrimSpace(existingSec.PrivateKey) == "" {
				return ProfileView{}, fmt.Errorf("%w: private key is required", profile.ErrInvalidProfile)
			}
		default:
			return ProfileView{}, fmt.Errorf("%w: unsupported auth_type %q", profile.ErrInvalidProfile, req.AuthType)
		}
		finalSecrets = existingSec
	} else {
		switch authType {
		case profile.AuthPassword:
			if req.Password == "" {
				return ProfileView{}, fmt.Errorf("%w: password is required", profile.ErrInvalidProfile)
			}
			finalSecrets = profile.ProfileSecrets{Password: req.Password}
		case profile.AuthKey:
			trimmedKey := strings.TrimSpace(req.PrivateKey)
			if trimmedKey == "" {
				return ProfileView{}, fmt.Errorf("%w: private key is required", profile.ErrInvalidProfile)
			}
			finalSecrets = profile.ProfileSecrets{
				PrivateKey:    trimmedKey,
				KeyPassphrase: req.KeyPassphrase,
			}
		default:
			return ProfileView{}, fmt.Errorf("%w: unsupported auth_type %q", profile.ErrInvalidProfile, req.AuthType)
		}
	}

	toSave := profile.Profile{
		ID:            reqID,
		Name:          strings.TrimSpace(req.Name),
		Host:          strings.TrimSpace(req.Host),
		Port:          req.Port,
		Username:      strings.TrimSpace(req.Username),
		AuthType:      authType,
		BypassIranLAN: req.BypassIranLAN,
		PreferredMode: prefMode,
	}
	if hasExisting {
		toSave.PinnedHostKey = existing.Clone().PinnedHostKey
	}

	saved, err := s.profiles.Save(ctx, toSave)
	if err != nil {
		return ProfileView{}, err
	}

	if !req.KeepExistingSecrets {
		if err := s.secrets.Put(ctx, saved.ID, finalSecrets); err != nil {
			if hasExisting {
				_, _ = s.profiles.Save(ctx, existing)
			} else {
				_ = s.profiles.Delete(ctx, saved.ID)
			}
			return ProfileView{}, err
		}
	}

	if err := s.refreshScrubberSecrets(ctx); err != nil {
		s.logger.Warn("Failed to refresh scrubber after saving profile", "profile_id", saved.ID, "err", err)
	}
	s.logger.Info("Saved SSH profile", "profile_id", saved.ID, "name", saved.Name, "host", saved.Host, "port", saved.Port)
	return toProfileView(saved, finalSecrets), nil
}

// DeleteProfile deletes both isolated secrets and metadata for profileID.
func (s *AppService) DeleteProfile(profileID string) error {
	ctx := s.currentLifecycleCtx()
	if s.secrets.IsLocked() {
		return profile.ErrVaultLocked
	}
	if _, err := s.profiles.Get(ctx, profileID); err != nil {
		return err
	}

	s.mu.Lock()
	isActive := s.activeProfileID == profileID && (s.activeProxy != nil || s.activeTUN || s.dialCancel != nil)
	s.mu.Unlock()
	if isActive {
		_ = s.Disconnect()
	}

	if err := s.secrets.Delete(ctx, profileID); err != nil {
		return err
	}
	if err := s.profiles.Delete(ctx, profileID); err != nil {
		return err
	}
	s.mu.Lock()
	if s.activeProfileID == profileID {
		s.activeProfileID = ""
	}
	s.mu.Unlock()
	if err := s.refreshScrubberSecrets(ctx); err != nil {
		s.logger.Warn("Failed to refresh scrubber after deleting profile", "profile_id", profileID, "err", err)
	}
	s.logger.Info("Deleted SSH profile", "profile_id", profileID)
	return nil
}

// ClearHostKey removes the pinned SSH host key from a profile.
func (s *AppService) ClearHostKey(profileID string) (ProfileView, error) {
	ctx := s.currentLifecycleCtx()
	p, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return ProfileView{}, err
	}
	p.PinnedHostKey = nil
	saved, err := s.profiles.Save(ctx, p)
	if err != nil {
		return ProfileView{}, err
	}

	var sec profile.ProfileSecrets
	if !s.secrets.IsLocked() {
		if loaded, getErr := s.secrets.Get(ctx, saved.ID); getErr == nil {
			sec = loaded
		}
	}
	s.logger.Warn("Cleared pinned host key", "profile_id", saved.ID, "host", saved.Host, "port", saved.Port)
	return toProfileView(saved, sec), nil
}

// ForgetHostKey clears the pinned host key so the next connection performs fresh TOFU verification.
func (s *AppService) ForgetHostKey(profileID string) (ProfileView, error) {
	return s.ClearHostKey(profileID)
}

// TrustHostKeyAndConnect pins algorithm and sha256 onto profileID and reconnects using the active or preferred mode.
func (s *AppService) TrustHostKeyAndConnect(profileID string, algorithm string, sha256 string) error {
	alg := strings.TrimSpace(algorithm)
	fp := strings.TrimSpace(sha256)
	if alg == "" || fp == "" {
		return fmt.Errorf("%w: host key algorithm and sha256 must not be empty", profile.ErrInvalidProfile)
	}

	ctx := s.currentLifecycleCtx()
	p, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return err
	}
	p.PinnedHostKey = &profile.HostKeyPin{
		Algorithm: alg,
		SHA256:    fp,
	}
	if _, err := s.profiles.Save(ctx, p); err != nil {
		return err
	}

	s.mu.Lock()
	targetMode := s.activeMode
	if s.activeProfileID != "" && s.activeProfileID != profileID {
		targetMode = ""
	}
	s.mu.Unlock()

	if targetMode == "" {
		if s.tun != nil && s.tun.Capabilities().Supported && p.PreferredMode == profile.ModeTUN {
			targetMode = string(profile.ModeTUN)
		} else {
			targetMode = string(profile.ModeProxy)
		}
	} else if targetMode == string(profile.ModeTUN) && (s.tun == nil || !s.tun.Capabilities().Supported) {
		targetMode = string(profile.ModeProxy)
	}

	s.logger.Info("Pinned server host key", "profile_id", profileID, "algorithm", alg, "sha256", fp)
	return s.Connect(profileID, targetMode)
}

// Connect establishes the SSH tunnel in System Proxy ("proxy") or Full TUN ("tun") mode.
func (s *AppService) Connect(profileID string, mode string) error {
	trimmedMode := strings.TrimSpace(strings.ToLower(mode))
	targetMode := string(profile.ModeProxy)
	switch trimmedMode {
	case "", string(profile.ModeProxy):
		targetMode = string(profile.ModeProxy)
	case string(profile.ModeTUN):
		if s.tun == nil || !s.tun.Capabilities().Supported {
			return errors.New("Full TUN mode is Milestone 2; unavailable in current configuration")
		}
		targetMode = string(profile.ModeTUN)
	default:
		return fmt.Errorf("unsupported tunnel mode %q", mode)
	}
	if s.secrets.IsLocked() {
		return profile.ErrVaultLocked
	}

	baseCtx := s.currentLifecycleCtx()
	prof, err := s.profiles.Get(baseCtx, profileID)
	if err != nil {
		return err
	}
	sec, err := s.secrets.Get(baseCtx, profileID)
	if err != nil {
		return err
	}

	if refreshErr := s.refreshScrubberSecrets(baseCtx, sec.Password, sec.PrivateKey, sec.KeyPassphrase); refreshErr != nil {
		s.logger.Warn("Failed to refresh all scrubber secrets prior to connect", "profile_id", prof.ID, "err", refreshErr)
	}

	s.mu.Lock()
	s.connectSeq++
	mySeq := s.connectSeq
	prevCancel := s.dialCancel
	prevProxy := s.activeProxy
	s.activeProxy = nil
	prevTUN := s.activeTUN
	s.activeTUN = false
	dialCtx, dialCancel := context.WithCancel(baseCtx)
	s.dialCancel = dialCancel
	s.inDialSeq = mySeq
	s.activeProfileID = prof.ID
	s.activeMode = targetMode
	s.activeBypass = prof.BypassIranLAN
	s.socksPort = 0
	s.httpPort = 0
	s.lastRxBytes = 0
	s.lastTxBytes = 0
	s.lastStatsTime = time.Time{}
	s.mu.Unlock()

	defer func() {
		dialCancel()
		s.mu.Lock()
		if s.inDialSeq == mySeq {
			s.inDialSeq = 0
		}
		if s.connectSeq == mySeq {
			s.dialCancel = nil
		}
		s.mu.Unlock()
	}()

	if prevCancel != nil {
		prevCancel()
	}
	if prevProxy != nil {
		stopCtx, stopCancel := boundedCleanupCtx(defaultOpTimeout)
		_ = prevProxy.Stop(stopCtx)
		_ = s.restorer.RestoreProxySession(stopCtx)
		stopCancel()
	}
	if prevTUN && s.tun != nil {
		stopCtx, stopCancel := boundedCleanupCtx(s.cleanupTimeout())
		_ = s.stopAndCompleteTUN(stopCtx)
		stopCancel()
	}

	if err := dialCtx.Err(); err != nil || !s.isConnectSeqCurrent(mySeq) {
		return context.Canceled
	}

	if targetMode == string(profile.ModeTUN) {
		return s.connectTUN(prof, sec, mySeq, dialCtx)
	}
	return s.connectProxy(prof, sec, mySeq, dialCtx, baseCtx)
}

func (s *AppService) buildSSHConnectConfig(prof profile.Profile, sec profile.ProfileSecrets) sshclient.ConnectConfig {
	connectCfg := sshclient.ConnectConfig{
		ProfileID: prof.ID,
		Host:      prof.Host,
		Port:      prof.Port,
		Username:  prof.Username,
		Auth: sshclient.AuthConfig{
			Type:          sshclient.AuthType(prof.AuthType),
			Password:      sec.Password,
			PrivateKey:    sec.PrivateKey,
			KeyPassphrase: sec.KeyPassphrase,
		},
		DialTimeout: s.dialTimeout,
		Watchdog:    s.watchdog,
		BackoffBase: s.backoffBase,
		BackoffMax:  s.backoffMax,
	}
	if prof.PinnedHostKey != nil {
		connectCfg.PinnedHostKey = &sshclient.HostKeyPin{
			Algorithm: prof.PinnedHostKey.Algorithm,
			SHA256:    prof.PinnedHostKey.SHA256,
		}
	}
	return connectCfg
}

func (s *AppService) connectProxy(
	prof profile.Profile,
	sec profile.ProfileSecrets,
	mySeq uint64,
	dialCtx context.Context,
	baseCtx context.Context,
) error {
	connectCfg := s.buildSSHConnectConfig(prof, sec)
	s.logger.Info("Connecting to SSH server...", "profile_id", prof.ID, "host", prof.Host, "port", prof.Port, "mode", profile.ModeProxy)

	if err := s.engine.Connect(dialCtx, connectCfg); err != nil {
		s.clearInDial(mySeq)
		if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
			return context.Canceled
		}
		snap := s.engine.Snapshot()
		s.emitHostKeyPromptIfPresent(prof, snap, err)
		s.logMappedError("SSH connection failed", prof, snap, err)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return err
	}

	if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
		return context.Canceled
	}

	proxyCtrl, err := s.newProxy(s.engine, s.proxyConfig)
	if err != nil {
		s.clearInDial(mySeq)
		s.rollbackFailedProxyStart(mySeq, nil)
		s.logger.Error("Failed to initialize local proxy server", "profile_id", prof.ID, "err", err)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return err
	}
	if err := proxyCtrl.Start(baseCtx); err != nil {
		s.clearInDial(mySeq)
		if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
			return context.Canceled
		}
		s.rollbackFailedProxyStart(mySeq, nil)
		s.logger.Error("Failed to start local proxy server", "profile_id", prof.ID, "err", err)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return err
	}

	if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
		stopCtx, stopCancel := boundedCleanupCtx(defaultOpTimeout)
		_ = proxyCtrl.Stop(stopCtx)
		stopCancel()
		return context.Canceled
	}

	socksHost, socksPort, err := parseBoundAddr(proxyCtrl.SOCKSAddr(), sysproxy.DefaultLoopbackHost)
	if err != nil {
		s.clearInDial(mySeq)
		s.rollbackFailedProxyStart(mySeq, proxyCtrl)
		s.logger.Error("Invalid bound SOCKS5 listener address", "profile_id", prof.ID, "err", err)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return err
	}
	httpHost, httpPort, err := parseBoundAddr(proxyCtrl.HTTPAddr(), sysproxy.DefaultLoopbackHost)
	if err != nil {
		s.clearInDial(mySeq)
		s.rollbackFailedProxyStart(mySeq, proxyCtrl)
		s.logger.Error("Invalid bound HTTP listener address", "profile_id", prof.ID, "err", err)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return err
	}

	applyCfg := sysproxy.ProxyApplyConfig{
		SOCKSHost:     socksHost,
		SOCKSPort:     socksPort,
		HTTPHost:      httpHost,
		HTTPPort:      httpPort,
		BypassIranLAN: prof.BypassIranLAN,
	}
	beginCtx, beginCancel := boundedOpCtx(dialCtx, defaultOpTimeout)
	beginErr := s.restorer.BeginProxySession(beginCtx, applyCfg)
	beginCancel()
	if beginErr != nil {
		s.clearInDial(mySeq)
		if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
			stopCtx, stopCancel := boundedCleanupCtx(defaultOpTimeout)
			_ = proxyCtrl.Stop(stopCtx)
			stopCancel()
			s.cleanupIfStale(mySeq)
			return context.Canceled
		}
		cleanCtx, cleanCancel := boundedCleanupCtx(defaultOpTimeout)
		_ = proxyCtrl.Stop(cleanCtx)
		_ = s.restorer.RestoreProxySession(cleanCtx)
		if s.isConnectSeqCurrent(mySeq) {
			_ = s.engine.Disconnect(cleanCtx)
		}
		cleanCancel()
		s.logger.Error("Failed to apply OS system proxy", "profile_id", prof.ID, "err", beginErr)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return beginErr
	}

	s.mu.Lock()
	if s.connectSeq != mySeq || dialCtx.Err() != nil {
		if s.inDialSeq == mySeq {
			s.inDialSeq = 0
		}
		disconnAfter := s.disconnectedSeq > mySeq
		noNewProxy := s.activeProxy == nil
		s.mu.Unlock()
		cleanCtx, cleanCancel := boundedCleanupCtx(defaultOpTimeout)
		_ = proxyCtrl.Stop(cleanCtx)
		if noNewProxy {
			_ = s.restorer.RestoreProxySession(cleanCtx)
		}
		if disconnAfter {
			_ = s.engine.Disconnect(cleanCtx)
		}
		cleanCancel()
		return context.Canceled
	}
	s.activeProxy = proxyCtrl
	s.socksPort = socksPort
	s.httpPort = httpPort
	s.activeProfileID = prof.ID
	s.activeMode = string(profile.ModeProxy)
	s.activeBypass = prof.BypassIranLAN
	s.inDialSeq = 0
	s.dialCancel = nil
	s.mu.Unlock()

	s.logger.Info(
		fmt.Sprintf("Connected to %s:%d (SOCKS5 :%d, HTTP :%d).", prof.Host, prof.Port, socksPort, httpPort),
		"profile_id", prof.ID,
	)
	s.emitter.Emit("tunnel:status", s.buildStatusDTO())
	return nil
}

func (s *AppService) connectTUN(
	prof profile.Profile,
	sec profile.ProfileSecrets,
	mySeq uint64,
	dialCtx context.Context,
) error {
	s.logger.Info("Connecting to SSH server...", "profile_id", prof.ID, "host", prof.Host, "port", prof.Port, "mode", profile.ModeTUN)

	vpsIP, err := s.resolvePeerIP(dialCtx, prof.Host)
	if err == nil && !vpsIP.IsValid() {
		err = fmt.Errorf("resolved invalid IP address for host %q", prof.Host)
	}
	if err != nil {
		s.clearInDial(mySeq)
		if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
			return context.Canceled
		}
		s.logMappedError("Failed to resolve VPS peer IP for Full TUN mode", prof, s.engine.Snapshot(), err)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return err
	}
	vpsIP = vpsIP.Unmap()

	if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
		return context.Canceled
	}

	snap, err := s.tun.PrepareSession(dialCtx)
	if err != nil {
		s.clearInDial(mySeq)
		if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
			return context.Canceled
		}
		s.logger.Error("Failed to prepare Full TUN session", "profile_id", prof.ID, "err", err)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return err
	}
	if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
		s.cleanupStaleTUNBeforeCommit(mySeq, false)
		return context.Canceled
	}

	caps := s.tun.Capabilities()
	snap.VPSPeerIP = vpsIP.String()
	if strings.TrimSpace(snap.TUNIfaceName) == "" {
		if iface := strings.TrimSpace(caps.IfaceName); iface != "" {
			snap.TUNIfaceName = iface
		} else {
			snap.TUNIfaceName = splitroute.TUNIfaceName
		}
	}
	populateSnapshotInstalledRoutes(&snap, vpsIP, prof.BypassIranLAN)

	connectCfg := s.buildSSHConnectConfig(prof, sec)
	connectCfg.DialHost = vpsIP.String()
	if !caps.RequiresElevation && snap.OrigIfaceName != "" {
		connectCfg.DialControl = splitroute.BindToInterfaceControl(snap.OrigIfaceName, snap.OrigIfaceIndex, vpsIP.Is6())
	}

	if err := s.engine.Connect(dialCtx, connectCfg); err != nil {
		s.clearInDial(mySeq)
		s.cleanupStaleTUNBeforeCommit(mySeq, false)
		if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
			return context.Canceled
		}
		engSnap := s.engine.Snapshot()
		s.emitHostKeyPromptIfPresent(prof, engSnap, err)
		s.logMappedError("SSH connection failed", prof, engSnap, err)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return err
	}

	if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
		s.cleanupStaleTUNBeforeCommit(mySeq, true)
		return context.Canceled
	}

	// Persist dirty TUN recovery state strictly before calling StartTUN (OS route/DNS mutations).
	beginCtx, beginCancel := boundedOpCtx(dialCtx, defaultOpTimeout)
	beginErr := s.restorer.BeginTUNSession(beginCtx, NetworkSnapshotToRecovery(snap))
	beginCancel()
	if beginErr != nil {
		s.clearInDial(mySeq)
		if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
			s.cleanupStaleTUNBeforeCommit(mySeq, true)
			return context.Canceled
		}
		cleanCtx, cleanCancel := boundedCleanupCtx(s.cleanupTimeout())
		_ = s.tun.Stop(cleanCtx)
		if s.isConnectSeqCurrent(mySeq) {
			_ = s.engine.Disconnect(cleanCtx)
		}
		cleanCancel()
		s.logger.Error("Failed to persist Full TUN recovery state", "profile_id", prof.ID, "err", beginErr)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return beginErr
	}

	if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
		s.cleanupStaleTUNAfterBegin(mySeq, nil)
		return context.Canceled
	}

	tunReq := TUNStartRequest{
		Snapshot:      snap,
		BypassIranLAN: prof.BypassIranLAN,
		EnableIPv6:    true,
	}
	if err := s.tun.StartTUN(dialCtx, tunReq, s.engine); err != nil {
		s.clearInDial(mySeq)
		if !s.isConnectSeqCurrent(mySeq) || dialCtx.Err() != nil {
			s.cleanupStaleTUNAfterBegin(mySeq, err)
			return context.Canceled
		}
		cleanCtx, cleanCancel := boundedCleanupCtx(s.cleanupTimeout())
		_ = s.rollbackFailedTUNStart(cleanCtx, err)
		if s.isConnectSeqCurrent(mySeq) {
			_ = s.engine.Disconnect(cleanCtx)
		}
		cleanCancel()
		s.logger.Error("Failed to start Full TUN session", "profile_id", prof.ID, "err", err)
		s.emitter.Emit("tunnel:status", s.buildStatusDTO())
		return err
	}

	s.mu.Lock()
	if s.connectSeq != mySeq || dialCtx.Err() != nil {
		if s.inDialSeq == mySeq {
			s.inDialSeq = 0
		}
		disconnAfter := s.disconnectedSeq > mySeq
		shouldCleanTUN := !s.activeTUN && (s.connectSeq == mySeq || disconnAfter || s.activeMode != string(profile.ModeTUN))
		shouldDisconnEngine := disconnAfter || s.connectSeq == mySeq
		s.mu.Unlock()
		cleanCtx, cleanCancel := boundedCleanupCtx(s.cleanupTimeout())
		if shouldCleanTUN {
			_ = s.stopAndCompleteTUN(cleanCtx)
		}
		if shouldDisconnEngine {
			_ = s.engine.Disconnect(cleanCtx)
		}
		cleanCancel()
		return context.Canceled
	}
	s.activeTUN = true
	s.activeProfileID = prof.ID
	s.activeMode = string(profile.ModeTUN)
	s.activeBypass = prof.BypassIranLAN
	s.inDialSeq = 0
	s.dialCancel = nil
	s.mu.Unlock()

	ifaceName := strings.TrimSpace(caps.IfaceName)
	if ifaceName == "" {
		ifaceName = strings.TrimSpace(snap.TUNIfaceName)
	}
	if ifaceName == "" {
		ifaceName = splitroute.TUNIfaceName
	}
	tunDNS := strings.TrimSpace(caps.TUNDNS)
	if tunDNS == "" {
		tunDNS = splitroute.TUNDNSServer
	}

	s.logger.Info(
		fmt.Sprintf("Connected to %s:%d via Full TUN (%s, DNS %s).", prof.Host, prof.Port, ifaceName, tunDNS),
		"profile_id", prof.ID,
		"iface", ifaceName,
		"dns", tunDNS,
	)
	s.emitter.Emit("tunnel:status", s.buildStatusDTO())
	return nil
}

func populateSnapshotInstalledRoutes(snap *splitroute.NetworkSnapshot, vpsIP netip.Addr, bypassIranLAN bool) {
	if snap == nil {
		return
	}
	origGW4, gwErr := parseOptionalIP(snap.OrigGateway, "orig_gateway")
	if gwErr != nil || !origGW4.IsValid() {
		return
	}
	origGW6, _ := parseOptionalIP(snap.OrigGateway6, "orig_gateway6")
	origDNS := make([]netip.Addr, 0, len(snap.OrigDNSServers))
	for _, rawDNS := range snap.OrigDNSServers {
		trimmed := strings.TrimSpace(rawDNS)
		if trimmed == "" {
			continue
		}
		if host, _, splitErr := net.SplitHostPort(trimmed); splitErr == nil {
			trimmed = host
		}
		if addr, parseErr := netip.ParseAddr(trimmed); parseErr == nil && addr.IsValid() {
			origDNS = append(origDNS, addr.Unmap())
		}
	}
	plan := splitroute.RoutePlan{
		VPSPeerIP:      vpsIP,
		OrigGateway:    origGW4,
		OrigGateway6:   origGW6,
		OrigIfaceName:  strings.TrimSpace(snap.OrigIfaceName),
		OrigIfaceIndex: snap.OrigIfaceIndex,
		OrigDNSServers: origDNS,
		TUNIfaceName:   snap.TUNIfaceName,
		BypassIranLAN:  bypassIranLAN,
		EnableIPv6:     true,
	}
	if routes, routeErr := splitroute.BuildInstalledRoutes(plan); routeErr == nil {
		snap.InstalledRoutes = routes
	}
}

func (s *AppService) cleanupStaleTUNBeforeCommit(mySeq uint64, disconnectEngine bool) {
	s.mu.Lock()
	disconnAfter := s.disconnectedSeq > mySeq
	shouldStopTUN := !s.activeTUN && (s.connectSeq == mySeq || disconnAfter || s.activeMode != string(profile.ModeTUN))
	s.mu.Unlock()

	ctx, cancel := boundedCleanupCtx(s.cleanupTimeout())
	defer cancel()
	if shouldStopTUN && s.tun != nil {
		_ = s.tun.Stop(ctx)
	}
	if disconnectEngine && disconnAfter {
		_ = s.engine.Disconnect(ctx)
	}
}

func (s *AppService) cleanupStaleTUNAfterBegin(mySeq uint64, startErr error) {
	s.mu.Lock()
	disconnAfter := s.disconnectedSeq > mySeq
	shouldCleanTUN := !s.activeTUN && (s.connectSeq == mySeq || disconnAfter || s.activeMode != string(profile.ModeTUN))
	shouldDisconnEngine := disconnAfter || s.connectSeq == mySeq
	s.mu.Unlock()

	ctx, cancel := boundedCleanupCtx(s.cleanupTimeout())
	defer cancel()
	if shouldCleanTUN && s.tun != nil {
		_ = s.rollbackFailedTUNStart(ctx, startErr)
	}
	if shouldDisconnEngine {
		_ = s.engine.Disconnect(ctx)
	}
}

func (s *AppService) rollbackFailedProxyStart(mySeq uint64, proxyCtrl ProxyController) {
	ctx, cancel := boundedCleanupCtx(defaultOpTimeout)
	defer cancel()
	if proxyCtrl != nil {
		_ = proxyCtrl.Stop(ctx)
	}
	if s.isConnectSeqCurrent(mySeq) {
		_ = s.engine.Disconnect(ctx)
	}
}

func (s *AppService) cleanupIfStale(mySeq uint64) {
	s.mu.Lock()
	disconnAfter := s.disconnectedSeq > mySeq
	noNewProxy := s.activeProxy == nil
	s.mu.Unlock()
	ctx, cancel := boundedCleanupCtx(defaultOpTimeout)
	defer cancel()
	if noNewProxy {
		_ = s.restorer.RestoreProxySession(ctx)
	}
	if disconnAfter {
		_ = s.engine.Disconnect(ctx)
	}
}

func (s *AppService) clearInDial(mySeq uint64) {
	s.mu.Lock()
	if s.inDialSeq == mySeq {
		s.inDialSeq = 0
	}
	s.mu.Unlock()
}

func (s *AppService) isConnectSeqCurrent(seq uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectSeq == seq
}

// Disconnect cancels any active dial, stops the proxy or TUN session, restores OS network state, and closes SSH.
func (s *AppService) Disconnect() error {
	ctx, cancel := boundedCleanupCtx(s.cleanupTimeout())
	defer cancel()
	return s.disconnect(ctx)
}

func (s *AppService) disconnect(ctx context.Context) error {
	s.mu.Lock()
	s.connectSeq++
	s.disconnectedSeq = s.connectSeq
	dialCancel := s.dialCancel
	s.dialCancel = nil
	proxyCtrl := s.activeProxy
	s.activeProxy = nil
	wasTUN := s.activeTUN
	s.activeTUN = false
	s.activeMode = ""
	s.socksPort = 0
	s.httpPort = 0
	s.lastRxBytes = 0
	s.lastTxBytes = 0
	s.lastStatsTime = time.Time{}
	s.mu.Unlock()

	if dialCancel != nil {
		dialCancel()
	}

	var errs []error
	if proxyCtrl != nil {
		if err := proxyCtrl.Stop(ctx); err != nil {
			errs = append(errs, err)
			s.logger.Warn("Error stopping local proxy server", "err", err)
		}
		if err := s.restorer.RestoreProxySession(ctx); err != nil {
			errs = append(errs, err)
			s.logger.Warn("Error restoring OS proxy settings", "err", err)
		}
	}
	if wasTUN && s.tun != nil {
		if err := s.tun.Stop(ctx); err != nil {
			errs = append(errs, err)
			s.logger.Warn("Error stopping Full TUN session", "err", err)
			if restoreErr := s.restorer.RestoreTUNSession(ctx); restoreErr != nil {
				errs = append(errs, restoreErr)
				s.logger.Warn("Error restoring Full TUN network settings", "err", restoreErr)
			}
		} else if err := s.restorer.CompleteTUNSession(ctx); err != nil {
			errs = append(errs, err)
			s.logger.Warn("Error marking Full TUN recovery state clean", "err", err)
		}
	}
	if err := s.engine.Disconnect(ctx); err != nil {
		errs = append(errs, err)
		s.logger.Warn("Error disconnecting SSH engine", "err", err)
	}

	s.emitter.Emit("tunnel:status", s.buildStatusDTO())
	s.logger.Info("Tunnel disconnected.")
	return errors.Join(errs...)
}

// RestoreNetwork executes the panic-button flow: disconnects active tunnel state and restores OS network state.
func (s *AppService) RestoreNetwork() error {
	timeout := defaultOpTimeout
	if s.tun != nil {
		timeout = persistentTUNSetupTimeout
	}
	ctx, cancel := boundedCleanupCtx(timeout)
	defer cancel()
	disconnErr := s.disconnect(ctx)
	restoreErr := s.restorer.RestoreNetwork(ctx)
	if restoreErr == nil {
		s.mu.Lock()
		if s.lastRecovery != nil {
			s.lastRecovery.NeedsElevation = false
			s.lastRecovery.Recovered = true
		}
		s.mu.Unlock()
		s.logger.Info("OS network settings verified and restored.")
	} else {
		s.logger.Error("Failed to restore OS network settings", "err", restoreErr)
	}
	return errors.Join(disconnErr, restoreErr)
}

// SetBypassIranLAN updates BypassIranLAN on profileID and re-applies live OS proxy or TUN bypass rules if connected.
func (s *AppService) SetBypassIranLAN(profileID string, bypass bool) (ProfileView, error) {
	ctx := s.currentLifecycleCtx()
	p, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return ProfileView{}, err
	}
	prevBypass := p.BypassIranLAN
	p.BypassIranLAN = bypass
	saved, err := s.profiles.Save(ctx, p)
	if err != nil {
		return ProfileView{}, err
	}

	s.mu.Lock()
	activeProxyOnProfile := s.activeProxy != nil && s.activeProfileID == saved.ID && s.activeMode == string(profile.ModeProxy)
	activeTUNOnProfile := s.activeTUN && s.tun != nil && s.activeProfileID == saved.ID && s.activeMode == string(profile.ModeTUN)
	proxyCtrl := s.activeProxy
	socksPort := s.socksPort
	httpPort := s.httpPort
	if activeProxyOnProfile || activeTUNOnProfile {
		s.activeBypass = bypass
	}
	s.mu.Unlock()

	rollbackBypass := func() {
		saved.BypassIranLAN = prevBypass
		_, _ = s.profiles.Save(ctx, saved)
		s.mu.Lock()
		if s.activeProfileID == saved.ID {
			s.activeBypass = prevBypass
		}
		s.mu.Unlock()
	}

	if activeProxyOnProfile && proxyCtrl != nil {
		socksHost, parsedSOCKS, errSOCKS := parseBoundAddr(proxyCtrl.SOCKSAddr(), sysproxy.DefaultLoopbackHost)
		httpHost, parsedHTTP, errHTTP := parseBoundAddr(proxyCtrl.HTTPAddr(), sysproxy.DefaultLoopbackHost)
		if errSOCKS == nil && errHTTP == nil {
			socksPort = parsedSOCKS
			httpPort = parsedHTTP
		} else {
			socksHost = sysproxy.DefaultLoopbackHost
			httpHost = sysproxy.DefaultLoopbackHost
		}
		enableCtx, enableCancel := boundedOpCtx(ctx, defaultOpTimeout)
		enableErr := s.sysProxy.Enable(enableCtx, sysproxy.ProxyApplyConfig{
			SOCKSHost:     socksHost,
			SOCKSPort:     socksPort,
			HTTPHost:      httpHost,
			HTTPPort:      httpPort,
			BypassIranLAN: bypass,
		})
		enableCancel()
		if enableErr != nil {
			rollbackBypass()
			s.logger.Warn("Failed to update live OS proxy bypass rules", "profile_id", saved.ID, "err", enableErr)
			return ProfileView{}, enableErr
		}
	}

	if activeTUNOnProfile {
		enableCtx, enableCancel := boundedOpCtx(ctx, s.cleanupTimeout())
		setErr := s.tun.SetBypass(enableCtx, bypass)
		enableCancel()
		if setErr != nil {
			rollbackBypass()
			s.logger.Warn("Failed to update live TUN bypass rules", "profile_id", saved.ID, "err", setErr)
			return ProfileView{}, setErr
		}
	}

	var sec profile.ProfileSecrets
	if !s.secrets.IsLocked() {
		if loaded, getErr := s.secrets.Get(ctx, saved.ID); getErr == nil {
			sec = loaded
		}
	}
	s.logger.Info("Updated Bypass Iran & LAN setting", "profile_id", saved.ID, "bypass_iran_lan", bypass)
	return toProfileView(saved, sec), nil
}

// ExportShareLink encodes profileID and its isolated secrets into an sshtun://v1/ share link.
func (s *AppService) ExportShareLink(profileID string, passphrase string, unsafePlain bool) (string, error) {
	if s.secrets.IsLocked() {
		return "", profile.ErrVaultLocked
	}
	ctx := s.currentLifecycleCtx()
	p, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return "", err
	}
	sec, err := s.secrets.Get(ctx, profileID)
	if err != nil {
		return "", err
	}

	secretVal := sec.Password
	if p.AuthType == profile.AuthKey {
		secretVal = sec.PrivateKey
	}
	payload := crypto.SharePayload{
		Name:          p.Name,
		Host:          p.Host,
		Port:          p.Port,
		User:          p.Username,
		AuthType:      string(p.AuthType),
		Secret:        secretVal,
		KeyPassphrase: sec.KeyPassphrase,
	}
	if p.PinnedHostKey != nil {
		payload.HostKey = &crypto.ShareHostKey{
			Alg:    p.PinnedHostKey.Algorithm,
			SHA256: p.PinnedHostKey.SHA256,
		}
	}

	var (
		link string
		mode string
	)
	if unsafePlain {
		mode = crypto.ModePlain
		link, err = crypto.EncodePlainShareLink(payload, true)
	} else {
		mode = crypto.ModeEncrypted
		link, err = crypto.EncodeEncryptedShareLink(payload, passphrase)
	}
	if err != nil {
		return "", err
	}

	s.logger.Info("Exported share link", "profile_id", p.ID, "mode", mode)
	return link, nil
}

// InspectShareLink inspects an sshtun://v1/ envelope without decrypting its payload.
func (s *AppService) InspectShareLink(link string) (ShareInspectDTO, error) {
	meta, err := crypto.InspectShareLink(strings.TrimSpace(link))
	if err != nil {
		return ShareInspectDTO{}, err
	}
	return ShareInspectDTO{
		Version:    meta.Version,
		Mode:       meta.Mode,
		HasHostKey: meta.HasHostKey,
	}, nil
}

// ImportShareLink decodes/decrypts an sshtun://v1/ share link and stores the profile and secrets.
func (s *AppService) ImportShareLink(link string, passphrase string, allowPlain bool) (ProfileView, error) {
	if s.secrets.IsLocked() {
		return ProfileView{}, profile.ErrVaultLocked
	}
	ctx := s.currentLifecycleCtx()

	payload, mode, err := crypto.DecodeShareLink(strings.TrimSpace(link), crypto.DecodeOptions{
		Passphrase:       passphrase,
		AllowPlainImport: allowPlain,
	})
	if err != nil {
		return ProfileView{}, err
	}

	authType := profile.AuthType(strings.TrimSpace(payload.AuthType))
	var sec profile.ProfileSecrets
	switch authType {
	case profile.AuthPassword:
		sec = profile.ProfileSecrets{Password: payload.Secret}
	case profile.AuthKey:
		sec = profile.ProfileSecrets{
			PrivateKey:    strings.TrimSpace(payload.Secret),
			KeyPassphrase: payload.KeyPassphrase,
		}
	default:
		return ProfileView{}, fmt.Errorf("%w: unsupported auth_type %q", crypto.ErrInvalidShareLink, payload.AuthType)
	}

	name := strings.TrimSpace(payload.Name)
	if name == "" {
		name = net.JoinHostPort(strings.TrimSpace(payload.Host), strconv.Itoa(payload.Port))
	}

	toSave := profile.Profile{
		Name:          name,
		Host:          strings.TrimSpace(payload.Host),
		Port:          payload.Port,
		Username:      strings.TrimSpace(payload.User),
		AuthType:      authType,
		BypassIranLAN: true,
		PreferredMode: profile.ModeProxy,
	}
	if payload.HostKey != nil {
		toSave.PinnedHostKey = &profile.HostKeyPin{
			Algorithm: strings.TrimSpace(payload.HostKey.Alg),
			SHA256:    strings.TrimSpace(payload.HostKey.SHA256),
		}
	}

	saved, err := s.profiles.Save(ctx, toSave)
	if err != nil {
		return ProfileView{}, err
	}
	if err := s.secrets.Put(ctx, saved.ID, sec); err != nil {
		_ = s.profiles.Delete(ctx, saved.ID)
		return ProfileView{}, err
	}

	if err := s.refreshScrubberSecrets(ctx); err != nil {
		s.logger.Warn("Failed to refresh scrubber after importing profile", "profile_id", saved.ID, "err", err)
	}
	s.logger.Info("Imported shared profile", "profile_id", saved.ID, "mode", mode, "has_host_key", saved.PinnedHostKey != nil)
	return toProfileView(saved, sec), nil
}

// GetLogs returns all redacted log entries currently held in the 500-entry ring buffer.
func (s *AppService) GetLogs() []LogEntryDTO {
	return s.logBuffer.Entries()
}

// ClearLogs clears the in-memory diagnostic log buffer.
func (s *AppService) ClearLogs() {
	s.logBuffer.Clear()
}

// ExportRedactedLogs renders all buffered redacted log entries as plain text.
func (s *AppService) ExportRedactedLogs() string {
	return s.logBuffer.ExportText()
}

// PickPrivateKeyFile invokes the injected file picker and returns the selected PEM/OpenSSH private key contents.
func (s *AppService) PickPrivateKeyFile() (string, error) {
	if s.filePicker == nil {
		return "", errors.New("file picker is not available")
	}
	selected, err := s.filePicker(s.currentLifecycleCtx())
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(selected) == "" {
		return "", nil
	}
	if strings.Contains(selected, "-----BEGIN ") {
		return selected, nil
	}

	info, err := os.Stat(selected)
	if err != nil {
		return "", fmt.Errorf("read private key file: %w", err)
	}
	if info.IsDir() {
		return "", errors.New("selected path is a directory, not a private key file")
	}
	if info.Size() > maxPrivateKeyFileBytes {
		return "", fmt.Errorf("private key file exceeds %d bytes limit", maxPrivateKeyFileBytes)
	}
	raw, err := os.ReadFile(selected)
	if err != nil {
		return "", fmt.Errorf("read private key file: %w", err)
	}
	return string(raw), nil
}

// GetEnvSnippet returns the copyable shell environment export snippet for the current proxy ports.
func (s *AppService) GetEnvSnippet() string {
	socksPort, httpPort := s.currentPorts()
	return s.sysProxy.EnvSnippet(socksPort, httpPort)
}

func (s *AppService) handleEngineSnapshot(snap sshclient.EngineSnapshot) {
	s.mu.Lock()
	inDial := s.inDialSeq != 0
	var (
		proxyCtrl ProxyController
		wasTUN    bool
	)
	profileID := s.activeProfileID
	if snap.State == sshclient.StateError && !inDial {
		proxyCtrl = s.activeProxy
		s.activeProxy = nil
		wasTUN = s.activeTUN
		s.activeTUN = false
		s.socksPort = 0
		s.httpPort = 0
	}
	s.mu.Unlock()

	if proxyCtrl != nil {
		cleanCtx, cleanCancel := boundedCleanupCtx(defaultOpTimeout)
		_ = proxyCtrl.Stop(cleanCtx)
		_ = s.restorer.RestoreProxySession(cleanCtx)
		cleanCancel()
	}
	if wasTUN && s.tun != nil {
		cleanCtx, cleanCancel := boundedCleanupCtx(s.cleanupTimeout())
		_ = s.stopAndCompleteTUN(cleanCtx)
		cleanCancel()
	}

	if snap.State == sshclient.StateError && !inDial {
		prof := profile.Profile{ID: profileID, Host: snap.Host, Port: snap.Port}
		if prof.ID == "" {
			prof.ID = snap.ProfileID
		}
		s.emitHostKeyPromptIfPresent(prof, snap, snap.LastError)
		if snap.LastError != nil {
			s.logMappedError("SSH tunnel entered error state", prof, snap, snap.LastError)
		}
	}

	if inDial && snap.State == sshclient.StateConnected {
		// Connect() emits the authoritative connected status once proxy/TUN + OS config are up.
		return
	}

	s.emitter.Emit("tunnel:status", s.buildStatusDTOFromSnap(snap, false))
}

func (s *AppService) statsLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(s.statsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.mu.Lock()
			ready := (s.activeProxy != nil || s.activeTUN) && s.inDialSeq == 0
			seq := s.connectSeq
			s.mu.Unlock()
			if !ready {
				continue
			}

			snap := s.engine.Snapshot()
			if snap.State != sshclient.StateConnected {
				continue
			}
			dto := s.buildStatusDTOFromSnap(snap, true)

			s.mu.Lock()
			stillSame := s.connectSeq == seq && (s.activeProxy != nil || s.activeTUN) && s.inDialSeq == 0
			s.mu.Unlock()
			if !stillSame || dto.State != string(sshclient.StateConnected) {
				continue
			}
			s.emitter.Emit("tunnel:stats", dto)
		}
	}
}

func (s *AppService) buildStatusDTO() TunnelStatusDTO {
	return s.buildStatusDTOFromSnap(s.engine.Snapshot(), false)
}

func (s *AppService) buildStatusDTOFromSnap(snap sshclient.EngineSnapshot, updateRates bool) TunnelStatusDTO {
	s.mu.Lock()
	proxyCtrl := s.activeProxy
	activeTUN := s.activeTUN
	activeProfileID := s.activeProfileID
	activeMode := s.activeMode
	boundSOCKS := s.socksPort
	boundHTTP := s.httpPort
	s.mu.Unlock()

	var proxyStats proxy.Stats
	if proxyCtrl != nil {
		proxyStats = proxyCtrl.Stats()
	}

	rxBytes := snap.RxBytes
	if proxyStats.RxBytes > rxBytes {
		rxBytes = proxyStats.RxBytes
	}
	txBytes := snap.TxBytes
	if proxyStats.TxBytes > txBytes {
		txBytes = proxyStats.TxBytes
	}

	if activeTUN && s.tun != nil {
		tunStats := s.tun.Stats()
		if tunStats.RxBytes > rxBytes {
			rxBytes = tunStats.RxBytes
		}
		if tunStats.TxBytes > txBytes {
			txBytes = tunStats.TxBytes
		}
	}

	var rxRate, txRate uint64
	if updateRates && snap.State == sshclient.StateConnected {
		now := time.Now()
		s.mu.Lock()
		if !s.lastStatsTime.IsZero() {
			dt := now.Sub(s.lastStatsTime).Seconds()
			if dt > 0 {
				if rxBytes >= s.lastRxBytes {
					rxRate = uint64(float64(rxBytes-s.lastRxBytes) / dt)
				}
				if txBytes >= s.lastTxBytes {
					txRate = uint64(float64(txBytes-s.lastTxBytes) / dt)
				}
			}
		}
		s.lastStatsTime = now
		s.lastRxBytes = rxBytes
		s.lastTxBytes = txBytes
		s.mu.Unlock()
	}

	socksPort, httpPort := resolveDisplayPorts(boundSOCKS, boundHTTP, s.proxyConfig)
	profileID := snap.ProfileID
	if profileID == "" {
		profileID = activeProfileID
	}
	mode := activeMode
	if mode == "" {
		mode = string(profile.ModeProxy)
	}

	var connectedAtUnix int64
	if snap.State == sshclient.StateConnected && !snap.ConnectedAt.IsZero() {
		connectedAtUnix = snap.ConnectedAt.Unix()
	}

	var lastErrDTO *MappedErrorDTO
	if snap.LastError != nil {
		lastErrDTO = &MappedErrorDTO{
			Code:       snap.LastError.Code,
			Message:    s.scrubber.Scrub(snap.LastError.Message),
			ActionHint: s.scrubber.Scrub(snap.LastError.ActionHint),
			Retryable:  snap.LastError.Retryable,
		}
	}

	return TunnelStatusDTO{
		State:           string(snap.State),
		ProfileID:       profileID,
		Mode:            mode,
		Attempt:         snap.Attempt,
		RTTMs:           snap.RTTMs,
		RxBytes:         rxBytes,
		TxBytes:         txBytes,
		RxRateBPS:       rxRate,
		TxRateBPS:       txRate,
		ConnectedAtUnix: connectedAtUnix,
		SOCKSPort:       socksPort,
		HTTPPort:        httpPort,
		EnvSnippet:      s.sysProxy.EnvSnippet(socksPort, httpPort),
		LastError:       lastErrDTO,
	}
}

func (s *AppService) emitHostKeyPromptIfPresent(prof profile.Profile, snap sshclient.EngineSnapshot, err error) {
	if mismatch := extractHostKeyMismatch(snap, err); mismatch != nil {
		host := mismatch.Host
		if host == "" {
			host = prof.Host
		}
		port := mismatch.Port
		if port == 0 {
			port = prof.Port
		}
		s.emitter.Emit("tunnel:hostkey_prompt", HostKeyPromptDTO{
			ProfileID:         prof.ID,
			Host:              host,
			Port:              port,
			IsMismatch:        true,
			Algorithm:         mismatch.ActualAlg,
			SHA256:            mismatch.ActualSHA256,
			ExpectedAlgorithm: mismatch.ExpectedAlg,
			ExpectedSHA256:    mismatch.ExpectedSHA256,
		})
		return
	}

	if untrusted := extractHostKeyUntrusted(snap, err); untrusted != nil {
		host := untrusted.Host
		if host == "" {
			host = prof.Host
		}
		port := untrusted.Port
		if port == 0 {
			port = prof.Port
		}
		s.emitter.Emit("tunnel:hostkey_prompt", HostKeyPromptDTO{
			ProfileID:  prof.ID,
			Host:       host,
			Port:       port,
			IsMismatch: false,
			Algorithm:  untrusted.Algorithm,
			SHA256:     untrusted.SHA256,
		})
	}
}

func extractHostKeyMismatch(snap sshclient.EngineSnapshot, err error) *sshclient.ErrHostKeyMismatch {
	if snap.HostKeyMismatch != nil {
		return snap.HostKeyMismatch
	}
	var mismatch *sshclient.ErrHostKeyMismatch
	if errors.As(err, &mismatch) {
		return mismatch
	}
	return nil
}

func extractHostKeyUntrusted(snap sshclient.EngineSnapshot, err error) *sshclient.ErrHostKeyUntrusted {
	if snap.HostKeyPrompt != nil {
		return snap.HostKeyPrompt
	}
	var untrusted *sshclient.ErrHostKeyUntrusted
	if errors.As(err, &untrusted) {
		return untrusted
	}
	return nil
}

func (s *AppService) logMappedError(prefix string, prof profile.Profile, snap sshclient.EngineSnapshot, err error) {
	mapped := snap.LastError
	if mapped == nil {
		var fromErr *sshclient.MappedError
		if errors.As(err, &fromErr) {
			mapped = fromErr
		} else if err != nil {
			mapped = sshclient.ClassifyError(err, prof.Port, sshclient.PhaseDial)
		}
	}
	if mapped != nil {
		s.logger.Error(
			mapped.Message,
			"code", mapped.Code,
			"action_hint", mapped.ActionHint,
			"profile_id", prof.ID,
			"host", prof.Host,
			"port", prof.Port,
			"err", err,
		)
		return
	}
	s.logger.Error(prefix, "profile_id", prof.ID, "host", prof.Host, "port", prof.Port, "err", err)
}

func (s *AppService) refreshScrubberSecrets(ctx context.Context, extra ...string) error {
	collected := make([]string, 0, len(extra)+8)
	collected = append(collected, extra...)

	list, err := s.profiles.List(ctx)
	if err != nil {
		if len(collected) > 0 {
			s.scrubber.SetSecrets(collected)
		}
		return err
	}
	if !s.secrets.IsLocked() {
		for _, p := range list {
			sec, getErr := s.secrets.Get(ctx, p.ID)
			if getErr != nil {
				if errors.Is(getErr, profile.ErrVaultLocked) {
					continue
				}
				if len(collected) > 0 {
					s.scrubber.SetSecrets(collected)
				}
				return getErr
			}
			collected = append(collected, sec.Password, sec.PrivateKey, sec.KeyPassphrase)
		}
	}

	s.scrubber.SetSecrets(collected)
	return nil
}

func (s *AppService) currentLifecycleCtx() context.Context {
	s.mu.Lock()
	ctx := s.lifecycleCtx
	s.mu.Unlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (s *AppService) lifecycleCtxLocked() context.Context {
	if s.lifecycleCtx == nil {
		return context.Background()
	}
	return s.lifecycleCtx
}

func (s *AppService) currentPorts() (int, int) {
	s.mu.Lock()
	socksPort := s.socksPort
	httpPort := s.httpPort
	s.mu.Unlock()
	return resolveDisplayPorts(socksPort, httpPort, s.proxyConfig)
}

func resolveDisplayPorts(boundSOCKS, boundHTTP int, cfg proxy.Config) (int, int) {
	socksPort := boundSOCKS
	if socksPort <= 0 {
		socksPort = parseConfigPort(cfg.SOCKSAddr, sysproxy.DefaultSOCKSPort)
	}
	httpPort := boundHTTP
	if httpPort <= 0 {
		httpPort = parseConfigPort(cfg.HTTPAddr, sysproxy.DefaultHTTPPort)
	}
	return socksPort, httpPort
}

func parseConfigPort(addr string, fallback int) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fallback
	}
	return port
}

func parseBoundAddr(addr string, defaultHost string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("parse bound proxy address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid bound proxy port in %q", addr)
	}
	if host == "" {
		host = defaultHost
	}
	return host, port, nil
}

func toProfileView(p profile.Profile, sec profile.ProfileSecrets) ProfileView {
	var pin *HostKeyPinDTO
	if p.PinnedHostKey != nil {
		pin = &HostKeyPinDTO{
			Algorithm: p.PinnedHostKey.Algorithm,
			SHA256:    p.PinnedHostKey.SHA256,
		}
	}
	var createdAt, updatedAt string
	if !p.CreatedAt.IsZero() {
		createdAt = p.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !p.UpdatedAt.IsZero() {
		updatedAt = p.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	prefMode := string(p.PreferredMode)
	if prefMode == "" {
		prefMode = string(profile.ModeProxy)
	}
	return ProfileView{
		ID:               p.ID,
		Name:             p.Name,
		Host:             p.Host,
		Port:             p.Port,
		Username:         p.Username,
		AuthType:         string(p.AuthType),
		PinnedHostKey:    pin,
		BypassIranLAN:    p.BypassIranLAN,
		PreferredMode:    prefMode,
		HasSecret:        sec.Password != "" || sec.PrivateKey != "",
		HasKeyPassphrase: sec.KeyPassphrase != "",
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	}
}

func boundedOpCtx(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, timeout)
}

func (s *AppService) cleanupTimeout() time.Duration {
	if s.tun != nil {
		return persistentTUNSetupTimeout
	}
	return defaultOpTimeout
}

func (s *AppService) stopAndCompleteTUN(ctx context.Context) error {
	if err := s.tun.Stop(ctx); err != nil {
		return errors.Join(err, s.restorer.RestoreTUNSession(ctx))
	}
	return s.restorer.CompleteTUNSession(ctx)
}

func (s *AppService) rollbackFailedTUNStart(ctx context.Context, startErr error) error {
	stopErr := s.tun.Stop(ctx)
	if stopErr != nil || errors.Is(startErr, ErrTUNRollbackIncomplete) {
		return errors.Join(stopErr, s.restorer.RestoreTUNSession(ctx))
	}
	return s.restorer.CompleteTUNSession(ctx)
}

func boundedCleanupCtx(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
