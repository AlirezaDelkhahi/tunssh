// Package profile implements profile metadata persistence and isolated secret storage.
package profile

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

// AuthType selects the SSH user authentication strategy for a profile.
type AuthType string

const (
	// AuthPassword authenticates via SSH password and PAM keyboard-interactive methods.
	AuthPassword AuthType = "password"
	// AuthKey authenticates via an OpenSSH/PEM/PKCS#8 private key.
	AuthKey AuthType = "key"
)

// TunnelMode selects the desktop traffic interception mode for a profile.
type TunnelMode string

const (
	// ModeProxy uses unprivileged local SOCKS5/HTTP CONNECT system proxy mode (Milestone 1).
	ModeProxy TunnelMode = "proxy"
	// ModeTUN uses full-device split-tunnel TUN + embedded DNS mode (Milestone 2).
	ModeTUN TunnelMode = "tun"
)

var (
	// ErrProfileNotFound is returned when a requested profile ID does not exist.
	ErrProfileNotFound = errors.New("profile: profile not found")
	// ErrInvalidProfile is returned when profile metadata fails validation.
	ErrInvalidProfile = errors.New("profile: invalid profile")
	// ErrVaultLocked is returned when accessing an EncryptedFileSecretStore before Unlock.
	ErrVaultLocked = errors.New("profile: secret vault is locked")
	// ErrInvalidVaultPassphrase is returned when unlocking the encrypted secret vault fails.
	ErrInvalidVaultPassphrase = errors.New("profile: invalid vault passphrase")
)

// HostKeyPin stores a TOFU-pinned SSH server host-key algorithm and SHA-256 fingerprint.
type HostKeyPin struct {
	Algorithm string `json:"algorithm"`
	SHA256    string `json:"sha256"`
}

// Profile holds non-secret SSH tunnel metadata persisted in profiles.json.
// Passwords, private keys, and key passphrases are never stored on Profile.
type Profile struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Host          string      `json:"host"`
	Port          int         `json:"port"`
	Username      string      `json:"username"`
	AuthType      AuthType    `json:"auth_type"`
	PinnedHostKey *HostKeyPin `json:"pinned_host_key,omitempty"`
	BypassIranLAN bool        `json:"bypass_iran_lan"`
	PreferredMode TunnelMode  `json:"preferred_mode"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// Clone returns a deep copy of Profile so callers cannot mutate internal store state.
func (p Profile) Clone() Profile {
	if p.PinnedHostKey != nil {
		pin := *p.PinnedHostKey
		p.PinnedHostKey = &pin
	}
	return p
}

// ProfileSecrets holds sensitive SSH authentication credentials managed exclusively by SecretStore.
type ProfileSecrets struct {
	Password      string `json:"password,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
	KeyPassphrase string `json:"key_passphrase,omitempty"`
}

// ProfileStore persists non-secret Profile metadata.
type ProfileStore interface {
	List(ctx context.Context) ([]Profile, error)
	Get(ctx context.Context, id string) (Profile, error)
	Save(ctx context.Context, p Profile) (Profile, error)
	Delete(ctx context.Context, id string) error
}

// SecretStore abstracts OS Keyring and Argon2id/AES-256-GCM encrypted file fallback.
type SecretStore interface {
	BackendName() string // "keyring" | "encrypted-file"
	IsLocked() bool
	Unlock(passphrase string) error
	Get(ctx context.Context, profileID string) (ProfileSecrets, error)
	Put(ctx context.Context, profileID string, secrets ProfileSecrets) error
	Delete(ctx context.Context, profileID string) error
}

// NewUUID generates a random RFC 4122 version 4 UUID string using crypto/rand.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("profile: generate uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
