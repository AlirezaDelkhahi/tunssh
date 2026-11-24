package profile

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zalando/go-keyring"

	"github.com/AlirezaDelkhahi/tunssh/internal/crypto"
)

const (
	keyringService  = "tunssh"
	keyringProbeKey = "__probe_availability__"

	vaultFileName = "secrets.enc"
	vaultVersion  = 1
	vaultKDF      = "argon2id"
	vaultAAD      = "tunssh:secrets:v1"
	aesGCMTagLen  = 16
)

var keyringSecretFields = []struct {
	name string
	get  func(ProfileSecrets) string
	set  func(*ProfileSecrets, string)
}{
	{
		name: "password",
		get:  func(s ProfileSecrets) string { return s.Password },
		set:  func(s *ProfileSecrets, v string) { s.Password = v },
	},
	{
		name: "private_key",
		get:  func(s ProfileSecrets) string { return s.PrivateKey },
		set:  func(s *ProfileSecrets, v string) { s.PrivateKey = v },
	},
	{
		name: "key_passphrase",
		get:  func(s ProfileSecrets) string { return s.KeyPassphrase },
		set:  func(s *ProfileSecrets, v string) { s.KeyPassphrase = v },
	},
}

// KeyringSecretStore persists credentials in the OS keyring via github.com/zalando/go-keyring.
type KeyringSecretStore struct {
	mu sync.Mutex
}

var _ SecretStore = (*KeyringSecretStore)(nil)

// NewKeyringSecretStore creates a KeyringSecretStore bound to service "tunssh".
func NewKeyringSecretStore() *KeyringSecretStore {
	return &KeyringSecretStore{}
}

// BackendName returns "keyring".
func (s *KeyringSecretStore) BackendName() string {
	return "keyring"
}

// IsLocked always returns false because the OS keyring unlocks with the desktop session.
func (s *KeyringSecretStore) IsLocked() bool {
	return false
}

// Unlock is a no-op for the OS keyring backend.
func (s *KeyringSecretStore) Unlock(_ string) error {
	return nil
}

// Get loads all credential fields for profileID, treating keyring.ErrNotFound as empty.
func (s *KeyringSecretStore) Get(ctx context.Context, profileID string) (ProfileSecrets, error) {
	if err := checkContext(ctx); err != nil {
		return ProfileSecrets{}, err
	}
	if strings.TrimSpace(profileID) == "" {
		return ProfileSecrets{}, fmt.Errorf("%w: profile id must not be empty", ErrInvalidProfile)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var out ProfileSecrets
	for _, field := range keyringSecretFields {
		val, err := keyring.Get(keyringService, keyringUserKey(profileID, field.name))
		if err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				continue
			}
			return ProfileSecrets{}, fmt.Errorf("profile: keyring get %s: %w", field.name, err)
		}
		field.set(&out, val)
	}
	return out, nil
}

// Put stores non-empty credential fields and deletes empty ones from the OS keyring.
func (s *KeyringSecretStore) Put(ctx context.Context, profileID string, secrets ProfileSecrets) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(profileID) == "" {
		return fmt.Errorf("%w: profile id must not be empty", ErrInvalidProfile)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, field := range keyringSecretFields {
		key := keyringUserKey(profileID, field.name)
		val := field.get(secrets)
		if val == "" {
			if err := keyring.Delete(keyringService, key); err != nil && !errors.Is(err, keyring.ErrNotFound) {
				return fmt.Errorf("profile: keyring delete %s: %w", field.name, err)
			}
			continue
		}
		if err := keyring.Set(keyringService, key, val); err != nil {
			return fmt.Errorf("profile: keyring set %s: %w", field.name, err)
		}
	}
	return nil
}

// Delete removes all credential fields for profileID from the OS keyring.
func (s *KeyringSecretStore) Delete(ctx context.Context, profileID string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(profileID) == "" {
		return fmt.Errorf("%w: profile id must not be empty", ErrInvalidProfile)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, field := range keyringSecretFields {
		err := keyring.Delete(keyringService, keyringUserKey(profileID, field.name))
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("profile: keyring delete %s: %w", field.name, err)
		}
	}
	return nil
}

func keyringUserKey(profileID, field string) string {
	return "profile:" + profileID + ":" + field
}

type vaultEnvelope struct {
	V     int                 `json:"v"`
	KDF   string              `json:"kdf"`
	Salt  string              `json:"salt"`
	P     crypto.Argon2Params `json:"p"`
	Nonce string              `json:"nonce"`
	CT    string              `json:"ct"`
}

type rawVaultEnvelope struct {
	V     *int            `json:"v"`
	KDF   json.RawMessage `json:"kdf"`
	Salt  json.RawMessage `json:"salt"`
	P     json.RawMessage `json:"p"`
	Nonce json.RawMessage `json:"nonce"`
	CT    json.RawMessage `json:"ct"`
}

type rawArgon2Params struct {
	T int64 `json:"t"`
	M int64 `json:"m"`
	C int64 `json:"c"`
}

type parsedVaultEnvelope struct {
	params crypto.Argon2Params
	salt   []byte
	nonce  []byte
	ct     []byte
}

// EncryptedFileSecretStore persists credentials in <configDir>/secrets.enc encrypted with Argon2id + AES-256-GCM.
type EncryptedFileSecretStore struct {
	mu        sync.Mutex
	configDir string
	filePath  string
	unlocked  bool
	params    crypto.Argon2Params
	salt      []byte
	key       []byte
	secrets   map[string]ProfileSecrets
}

var _ SecretStore = (*EncryptedFileSecretStore)(nil)

// NewEncryptedFileSecretStore creates a locked EncryptedFileSecretStore managing <configDir>/secrets.enc.
func NewEncryptedFileSecretStore(configDir string) *EncryptedFileSecretStore {
	filePath := ""
	if strings.TrimSpace(configDir) != "" {
		filePath = filepath.Join(configDir, vaultFileName)
	}
	return &EncryptedFileSecretStore{
		configDir: configDir,
		filePath:  filePath,
	}
}

// BackendName returns "encrypted-file".
func (s *EncryptedFileSecretStore) BackendName() string {
	return "encrypted-file"
}

// IsLocked reports whether the encrypted secret vault currently holds no unlocked key material.
func (s *EncryptedFileSecretStore) IsLocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.unlocked
}

// Lock zeroes in-memory key, salt, and secret map state and marks the vault locked.
func (s *EncryptedFileSecretStore) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearInMemoryStateLocked()
}

func (s *EncryptedFileSecretStore) clearInMemoryStateLocked() {
	s.unlocked = false
	if s.key != nil {
		clear(s.key)
		s.key = nil
	}
	if s.salt != nil {
		clear(s.salt)
		s.salt = nil
	}
	if s.secrets != nil {
		clear(s.secrets)
		s.secrets = nil
	}
	s.params = crypto.Argon2Params{}
}

// Unlock validates passphrase, creates an empty 0600 encrypted vault if missing or decrypts secrets.enc,
// and caches derived key material and decrypted secrets in memory until Lock() is called.
func (s *EncryptedFileSecretStore) Unlock(passphrase string) error {
	if passphrase == "" {
		return fmt.Errorf("%w: passphrase must not be empty", ErrInvalidVaultPassphrase)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(s.configDir) == "" || s.filePath == "" {
		return errors.New("profile: config directory must not be empty")
	}

	if s.unlocked {
		candKey, err := crypto.DeriveKey(passphrase, s.salt, s.params)
		if err != nil {
			return err
		}
		defer clear(candKey)

		if len(candKey) != len(s.key) || subtle.ConstantTimeCompare(candKey, s.key) != 1 {
			return ErrInvalidVaultPassphrase
		}
		return nil
	}

	raw, err := os.ReadFile(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.initNewVaultLocked(passphrase)
		}
		return fmt.Errorf("profile: read secret vault: %w", err)
	}

	return s.unlockExistingVaultLocked(passphrase, raw)
}

func (s *EncryptedFileSecretStore) initNewVaultLocked(passphrase string) error {
	if info, err := os.Stat(s.configDir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("profile: config path %q is not a directory", s.configDir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("profile: stat config directory: %w", err)
	}

	salt, err := crypto.RandomBytes(crypto.SaltLen)
	if err != nil {
		return err
	}
	params := crypto.Argon2Params{
		T: crypto.DefaultArgon2T,
		M: crypto.DefaultArgon2M,
		C: crypto.DefaultArgon2C,
	}
	key, err := crypto.DeriveKey(passphrase, salt, params)
	if err != nil {
		clear(salt)
		return err
	}

	committed := false
	defer func() {
		if !committed {
			clear(key)
			clear(salt)
		}
	}()

	emptySecrets := make(map[string]ProfileSecrets)
	if err := s.writeVaultLocked(key, salt, params, emptySecrets); err != nil {
		return err
	}

	committed = true
	s.unlocked = true
	s.params = params
	s.salt = salt
	s.key = key
	s.secrets = emptySecrets
	return nil
}

func (s *EncryptedFileSecretStore) unlockExistingVaultLocked(passphrase string, raw []byte) error {
	parsed, err := parseVaultEnvelope(raw)
	if err != nil {
		return err
	}

	key, err := crypto.DeriveKey(passphrase, parsed.salt, parsed.params)
	if err != nil {
		clear(parsed.salt)
		return err
	}

	committed := false
	defer func() {
		if !committed {
			clear(key)
			clear(parsed.salt)
		}
	}()

	plaintext, err := crypto.OpenAESGCM(key, parsed.nonce, parsed.ct, []byte(vaultAAD))
	if err != nil {
		if errors.Is(err, crypto.ErrWrongPassphraseOrTampered) {
			return fmt.Errorf("%w: %w", ErrInvalidVaultPassphrase, err)
		}
		return err
	}
	defer clear(plaintext)

	var loaded map[string]ProfileSecrets
	if err := decodeStrictJSONObject(plaintext, &loaded); err != nil {
		return fmt.Errorf("profile: invalid decrypted vault payload: %w", err)
	}
	if loaded == nil {
		loaded = make(map[string]ProfileSecrets)
	}

	committed = true
	s.unlocked = true
	s.params = parsed.params
	s.salt = parsed.salt
	s.key = key
	s.secrets = loaded
	return nil
}

func (s *EncryptedFileSecretStore) writeVaultLocked(key, salt []byte, params crypto.Argon2Params, secrets map[string]ProfileSecrets) error {
	if secrets == nil {
		secrets = map[string]ProfileSecrets{}
	}
	plainJSON, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("profile: marshal vault secrets: %w", err)
	}
	defer clear(plainJSON)

	nonce, err := crypto.RandomBytes(crypto.NonceLen)
	if err != nil {
		return err
	}
	ct, err := crypto.SealAESGCM(key, nonce, plainJSON, []byte(vaultAAD))
	if err != nil {
		return err
	}

	env := vaultEnvelope{
		V:     vaultVersion,
		KDF:   vaultKDF,
		Salt:  base64.RawURLEncoding.EncodeToString(salt),
		P:     params,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		CT:    base64.RawURLEncoding.EncodeToString(ct),
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("profile: marshal vault envelope: %w", err)
	}
	envJSON = append(envJSON, '\n')

	return atomicWriteFile(s.filePath, envJSON)
}

// Get returns credentials for profileID while the vault is unlocked.
func (s *EncryptedFileSecretStore) Get(ctx context.Context, profileID string) (ProfileSecrets, error) {
	if err := checkContext(ctx); err != nil {
		return ProfileSecrets{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.unlocked {
		return ProfileSecrets{}, ErrVaultLocked
	}
	if strings.TrimSpace(profileID) == "" {
		return ProfileSecrets{}, fmt.Errorf("%w: profile id must not be empty", ErrInvalidProfile)
	}
	return s.secrets[profileID], nil
}

// Put updates credentials for profileID and atomically rewrites secrets.enc with a fresh nonce.
func (s *EncryptedFileSecretStore) Put(ctx context.Context, profileID string, secrets ProfileSecrets) error {
	return s.mutateSecrets(ctx, profileID, func(next map[string]ProfileSecrets) {
		if secrets == (ProfileSecrets{}) {
			delete(next, profileID)
		} else {
			next[profileID] = secrets
		}
	})
}

// Delete removes credentials for profileID and atomically rewrites secrets.enc with a fresh nonce.
func (s *EncryptedFileSecretStore) Delete(ctx context.Context, profileID string) error {
	return s.mutateSecrets(ctx, profileID, func(next map[string]ProfileSecrets) {
		delete(next, profileID)
	})
}

func (s *EncryptedFileSecretStore) mutateSecrets(ctx context.Context, profileID string, mutate func(map[string]ProfileSecrets)) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.unlocked {
		return ErrVaultLocked
	}
	if strings.TrimSpace(profileID) == "" {
		return fmt.Errorf("%w: profile id must not be empty", ErrInvalidProfile)
	}

	next := cloneSecretsMap(s.secrets)
	mutate(next)

	if err := s.writeVaultLocked(s.key, s.salt, s.params, next); err != nil {
		return err
	}
	clear(s.secrets)
	s.secrets = next
	return nil
}

func cloneSecretsMap(in map[string]ProfileSecrets) map[string]ProfileSecrets {
	if len(in) == 0 {
		return make(map[string]ProfileSecrets)
	}
	return maps.Clone(in)
}

func parseVaultEnvelope(raw []byte) (parsedVaultEnvelope, error) {
	var rawEnv rawVaultEnvelope
	if err := decodeStrictJSONObject(raw, &rawEnv); err != nil {
		return parsedVaultEnvelope{}, fmt.Errorf("profile: invalid vault envelope: %w", err)
	}
	if rawEnv.V == nil || *rawEnv.V != vaultVersion {
		return parsedVaultEnvelope{}, errors.New("profile: unsupported vault version")
	}
	if !hasRawField(rawEnv.KDF) {
		return parsedVaultEnvelope{}, errors.New("profile: vault envelope missing kdf")
	}
	var kdf string
	if err := json.Unmarshal(rawEnv.KDF, &kdf); err != nil || kdf != vaultKDF {
		return parsedVaultEnvelope{}, errors.New("profile: unsupported vault kdf")
	}

	params, err := parseRawVaultArgon2Params(rawEnv.P)
	if err != nil {
		return parsedVaultEnvelope{}, err
	}
	salt, err := decodeBase64Field(rawEnv.Salt, crypto.SaltLen)
	if err != nil {
		return parsedVaultEnvelope{}, err
	}
	nonce, err := decodeBase64Field(rawEnv.Nonce, crypto.NonceLen)
	if err != nil {
		return parsedVaultEnvelope{}, err
	}
	ct, err := decodeBase64Field(rawEnv.CT, -1)
	if err != nil {
		return parsedVaultEnvelope{}, err
	}
	if len(ct) < aesGCMTagLen {
		return parsedVaultEnvelope{}, errors.New("profile: vault ciphertext shorter than authentication tag")
	}

	return parsedVaultEnvelope{
		params: params,
		salt:   salt,
		nonce:  nonce,
		ct:     ct,
	}, nil
}

func hasRawField(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func decodeBase64Field(raw json.RawMessage, exactLen int) ([]byte, error) {
	if !hasRawField(raw) {
		return nil, errors.New("profile: vault envelope missing required field")
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, errors.New("profile: vault envelope contains invalid string field")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("profile: invalid base64url field in vault: %w", err)
	}
	if exactLen >= 0 && len(decoded) != exactLen {
		return nil, fmt.Errorf("profile: invalid vault field length %d, want %d", len(decoded), exactLen)
	}
	return decoded, nil
}

func parseRawVaultArgon2Params(raw json.RawMessage) (crypto.Argon2Params, error) {
	if !hasRawField(raw) {
		return crypto.Argon2Params{}, errors.New("profile: vault envelope missing kdf params")
	}
	var rp rawArgon2Params
	if err := decodeStrictJSONObject(raw, &rp); err != nil {
		return crypto.Argon2Params{}, fmt.Errorf("profile: invalid vault kdf params: %w", err)
	}
	if rp.T < 0 || rp.T > math.MaxUint32 ||
		rp.M < 0 || rp.M > math.MaxUint32 ||
		rp.C < 0 || rp.C > math.MaxUint8 {
		return crypto.Argon2Params{}, fmt.Errorf("%w: t=%d m=%d c=%d", crypto.ErrKDFBoundsExceeded, rp.T, rp.M, rp.C)
	}
	params := crypto.Argon2Params{
		T: uint32(rp.T),
		M: uint32(rp.M),
		C: uint8(rp.C),
	}
	if err := crypto.ValidateArgon2Params(params); err != nil {
		return crypto.Argon2Params{}, err
	}
	return params, nil
}

// NewAutoSecretStore probes OS keyring availability and falls back to EncryptedFileSecretStore
// when the system keyring service is unavailable.
func NewAutoSecretStore(configDir string) SecretStore {
	return newAutoSecretStore(configDir, func() error {
		_, err := keyring.Get(keyringService, keyringProbeKey)
		return err
	})
}

func newAutoSecretStore(configDir string, probe func() error) SecretStore {
	if probe != nil {
		err := probe()
		if err == nil || errors.Is(err, keyring.ErrNotFound) {
			return NewKeyringSecretStore()
		}
	}
	return NewEncryptedFileSecretStore(configDir)
}
