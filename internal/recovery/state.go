// Package recovery implements crash-safe recovery_state.json persistence and idempotent OS network restoration.
package recovery

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AlirezaDelkhahi/tunssh/internal/sysproxy"
)

const (
	// RecoveryModeProxy identifies an active or interrupted system proxy session.
	RecoveryModeProxy = "proxy"
	// RecoveryModeTUN identifies an active or interrupted Milestone 2 full-TUN session.
	RecoveryModeTUN = "tun"
	// SchemaVersion is the supported recovery_state.json schema version.
	SchemaVersion = 1
	// StateFileName is the recovery file name inside the configuration directory.
	StateFileName = "recovery_state.json"

	configDirMode os.FileMode = 0o700
	stateFileMode os.FileMode = 0o600
	appDirName                = "tunssh"
)

// ErrUnsupportedSchemaVersion is returned when recovery_state.json carries an unknown schema version.
var ErrUnsupportedSchemaVersion = errors.New("recovery: unsupported schema version")

// WinAdapterDNSBackup stores pre-tunnel DNS settings for a Windows network adapter (Milestone 2 schema compatibility).
type WinAdapterDNSBackup struct {
	IfaceIndex int      `json:"iface_index"`
	IfaceName  string   `json:"iface_name"`
	IPv4DNS    []string `json:"ipv4_dns,omitempty"`
	IPv6DNS    []string `json:"ipv6_dns,omitempty"`
}

// LinuxDNSBackup stores pre-tunnel systemd-resolved link settings for a Linux interface (Milestone 2 schema compatibility).
type LinuxDNSBackup struct {
	IfIndex      int      `json:"ifindex"`
	IfName       string   `json:"ifname"`
	DNSServers   []string `json:"dns_servers,omitempty"`
	DefaultRoute bool     `json:"default_route"`
}

// TUNSnapshot captures pre-tunnel OS route and DNS state for Milestone 2 schema compatibility.
type TUNSnapshot struct {
	VPSPeerIP            string                `json:"vps_peer_ip"`
	OrigGateway          string                `json:"orig_gateway"`
	OrigIfaceName        string                `json:"orig_iface_name"`
	OrigIfaceIndex       int                   `json:"orig_iface_index"`
	OrigDNSServers       []string              `json:"orig_dns_servers,omitempty"`
	WinAdapterDNSBackups []WinAdapterDNSBackup `json:"win_adapter_dns_backups,omitempty"`
	LinuxDNSBackups      []LinuxDNSBackup      `json:"linux_dns_backups,omitempty"`
	DNSStrategy          string                `json:"dns_strategy"`
	ResolvConfBackup     string                `json:"resolv_conf_backup"`
	TUNIfaceName         string                `json:"tun_iface_name"`
	InstalledRoutes      []string              `json:"installed_routes,omitempty"`
}

// RecoveryState represents the on-disk schema of recovery_state.json.
type RecoveryState struct {
	SchemaVersion int                     `json:"schema_version"`
	Dirty         bool                    `json:"dirty"`
	Mode          string                  `json:"mode"`
	PID           int                     `json:"pid"`
	UpdatedAtUTC  time.Time               `json:"updated_at_utc"`
	ProxySnapshot *sysproxy.ProxySnapshot `json:"proxy_snapshot,omitempty"`
	TUNSnapshot   *TUNSnapshot            `json:"tun_snapshot,omitempty"`
}

// RecoveryStore persists recovery_state.json atomically prior to OS network mutation.
type RecoveryStore interface {
	Load() (*RecoveryState, error)
	SaveDirty(state RecoveryState) error
	MarkClean() error
}

// DefaultConfigDir returns the per-user tunssh configuration directory.
func DefaultConfigDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("recovery: resolve user config dir: %w", err)
	}
	return filepath.Join(base, appDirName), nil
}

// FileRecoveryStore persists RecoveryState atomically to <configDir>/recovery_state.json.
type FileRecoveryStore struct {
	mu        sync.Mutex
	configDir string
	path      string
	nowFn     func() time.Time
}

var _ RecoveryStore = (*FileRecoveryStore)(nil)

// NewFileRecoveryStore constructs a FileRecoveryStore targeting <configDir>/recovery_state.json.
func NewFileRecoveryStore(configDir string) (*FileRecoveryStore, error) {
	trimmed := strings.TrimSpace(configDir)
	if trimmed == "" {
		return nil, errors.New("recovery: config directory must not be empty")
	}
	cleanDir := filepath.Clean(trimmed)
	return &FileRecoveryStore{
		configDir: cleanDir,
		path:      filepath.Join(cleanDir, StateFileName),
		nowFn:     func() time.Time { return time.Now().UTC() },
	}, nil
}

// Path returns the full path to recovery_state.json.
func (s *FileRecoveryStore) Path() string {
	return s.path
}

// Load reads and decodes recovery_state.json, returning (nil, nil) if the file does not exist.
func (s *FileRecoveryStore) Load() (*RecoveryState, error) {
	if err := s.validateStore(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("recovery: read %s: %w", s.path, err)
	}

	var state RecoveryState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("recovery: decode %s: %w", s.path, err)
	}
	if state.SchemaVersion != 0 && state.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSchemaVersion, state.SchemaVersion)
	}
	return &state, nil
}

// SaveDirty atomically writes a dirty RecoveryState record prior to OS network mutation.
func (s *FileRecoveryStore) SaveDirty(state RecoveryState) error {
	if err := s.validateStore(); err != nil {
		return err
	}

	state.SchemaVersion = SchemaVersion
	state.Dirty = true
	if state.UpdatedAtUTC.IsZero() {
		state.UpdatedAtUTC = s.nowFn().UTC()
	} else {
		state.UpdatedAtUTC = state.UpdatedAtUTC.UTC()
	}

	return s.writeState(state)
}

// MarkClean atomically writes a clean RecoveryState record with dirty=false.
func (s *FileRecoveryStore) MarkClean() error {
	if err := s.validateStore(); err != nil {
		return err
	}

	clean := RecoveryState{
		SchemaVersion: SchemaVersion,
		Dirty:         false,
		UpdatedAtUTC:  s.nowFn().UTC(),
	}
	return s.writeState(clean)
}

func (s *FileRecoveryStore) validateStore() error {
	if s == nil || s.configDir == "" || s.path == "" {
		return errors.New("recovery: file recovery store is not initialized")
	}
	return nil
}

func (s *FileRecoveryStore) writeState(state RecoveryState) error {
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("recovery: encode state: %w", err)
	}
	payload = append(payload, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.writeAtomicLocked(payload)
}

func (s *FileRecoveryStore) writeAtomicLocked(data []byte) error {
	if err := os.MkdirAll(s.configDir, configDirMode); err != nil {
		return fmt.Errorf("recovery: create config dir %s: %w", s.configDir, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(s.configDir, configDirMode); err != nil {
			return fmt.Errorf("recovery: chmod config dir %s: %w", s.configDir, err)
		}
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("recovery: generate temp file suffix: %w", err)
	}
	tmpPath := fmt.Sprintf("%s.tmp.%s", s.path, hex.EncodeToString(rnd[:]))

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stateFileMode)
	if err != nil {
		return fmt.Errorf("recovery: create temp state file %s: %w", tmpPath, err)
	}

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	n, err := f.Write(data)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("recovery: write temp state file %s: %w", tmpPath, err)
	}
	if n != len(data) {
		_ = f.Close()
		return fmt.Errorf("recovery: short write to %s: wrote %d of %d bytes", tmpPath, n, len(data))
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("recovery: sync temp state file %s: %w", tmpPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("recovery: close temp state file %s: %w", tmpPath, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, stateFileMode); err != nil {
			return fmt.Errorf("recovery: chmod temp state file %s: %w", tmpPath, err)
		}
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("recovery: rename %s to %s: %w", tmpPath, s.path, err)
	}
	cleanup = false

	if err := syncDir(s.configDir); err != nil {
		return fmt.Errorf("recovery: sync config dir %s: %w", s.configDir, err)
	}
	return nil
}

func syncDir(dirPath string) error {
	// Windows does not permit FlushFileBuffers on directory handles.
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
