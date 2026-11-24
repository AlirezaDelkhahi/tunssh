package profile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	profilesFileName = "profiles.json"
	maxTCPPort       = 65535
)

// FileStore manages non-secret Profile metadata in <configDir>/profiles.json.
type FileStore struct {
	mu        sync.Mutex
	configDir string
	filePath  string
	profiles  []Profile
}

var _ ProfileStore = (*FileStore)(nil)

// NewFileStore creates a FileStore backed by <configDir>/profiles.json and loads any existing metadata.
func NewFileStore(configDir string) (*FileStore, error) {
	if strings.TrimSpace(configDir) == "" {
		return nil, fmt.Errorf("%w: config directory must not be empty", ErrInvalidProfile)
	}
	if info, err := os.Stat(configDir); err == nil {
		if !info.IsDir() {
			return nil, fmt.Errorf("profile: config path %q is not a directory", configDir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("profile: stat config directory: %w", err)
	}

	s := &FileStore{
		configDir: configDir,
		filePath:  filepath.Join(configDir, profilesFileName),
		profiles:  make([]Profile, 0),
	}
	if err := s.loadInitial(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) loadInitial() error {
	raw, err := os.ReadFile(s.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("profile: read profiles file: %w", err)
	}

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return errors.New("profile: invalid profiles.json: expected JSON array")
	}

	var loaded []Profile
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&loaded); err != nil {
		return fmt.Errorf("profile: decode profiles.json: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("profile: invalid profiles.json: unexpected trailing JSON data")
	}

	seenIDs := make(map[string]struct{}, len(loaded))
	normalized := make([]Profile, 0, len(loaded))
	for _, p := range loaded {
		if strings.TrimSpace(p.ID) == "" {
			return fmt.Errorf("%w: loaded profile has empty id", ErrInvalidProfile)
		}
		if _, dup := seenIDs[p.ID]; dup {
			return fmt.Errorf("%w: duplicate profile id %q", ErrInvalidProfile, p.ID)
		}
		seenIDs[p.ID] = struct{}{}

		clean, err := validateAndNormalizeProfile(p)
		if err != nil {
			return err
		}
		if !clean.CreatedAt.IsZero() {
			clean.CreatedAt = clean.CreatedAt.UTC()
		}
		if !clean.UpdatedAt.IsZero() {
			clean.UpdatedAt = clean.UpdatedAt.UTC()
		}
		normalized = append(normalized, clean)
	}

	s.profiles = normalized
	return nil
}

// List returns cloned metadata for all persisted profiles.
func (s *FileStore) List(ctx context.Context) ([]Profile, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return cloneProfiles(s.profiles), nil
}

// Get returns a cloned Profile by ID.
func (s *FileStore) Get(ctx context.Context, id string) (Profile, error) {
	if err := checkContext(ctx); err != nil {
		return Profile{}, err
	}
	if strings.TrimSpace(id) == "" {
		return Profile{}, ErrProfileNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range s.profiles {
		if p.ID == id {
			return p.Clone(), nil
		}
	}
	return Profile{}, ErrProfileNotFound
}

// Save validates, normalizes, and atomically persists a Profile.
func (s *FileStore) Save(ctx context.Context, p Profile) (Profile, error) {
	if err := checkContext(ctx); err != nil {
		return Profile{}, err
	}

	clean, err := validateAndNormalizeProfile(p)
	if err != nil {
		return Profile{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	next := cloneProfiles(s.profiles)

	existingIdx := -1
	if clean.ID != "" {
		for i := range next {
			if next[i].ID == clean.ID {
				existingIdx = i
				break
			}
		}
	}

	if existingIdx >= 0 {
		clean.CreatedAt = next[existingIdx].CreatedAt.UTC()
		clean.UpdatedAt = now
		next[existingIdx] = clean.Clone()
	} else {
		if clean.ID == "" {
			id, err := NewUUID()
			if err != nil {
				return Profile{}, err
			}
			clean.ID = id
		}
		clean.CreatedAt = now
		clean.UpdatedAt = now
		next = append(next, clean.Clone())
	}

	if err := writeProfilesAtomically(s.filePath, next); err != nil {
		return Profile{}, err
	}
	s.profiles = next
	return clean.Clone(), nil
}

// Delete removes a Profile by ID and persists the change atomically.
func (s *FileStore) Delete(ctx context.Context, id string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" {
		return ErrProfileNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	deleteIdx := -1
	for i := range s.profiles {
		if s.profiles[i].ID == id {
			deleteIdx = i
			break
		}
	}
	if deleteIdx < 0 {
		return ErrProfileNotFound
	}

	next := make([]Profile, 0, len(s.profiles)-1)
	for i := range s.profiles {
		if i != deleteIdx {
			next = append(next, s.profiles[i].Clone())
		}
	}

	if err := writeProfilesAtomically(s.filePath, next); err != nil {
		return err
	}
	s.profiles = next
	return nil
}

func writeProfilesAtomically(filePath string, profiles []Profile) error {
	if profiles == nil {
		profiles = []Profile{}
	}
	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return fmt.Errorf("profile: marshal profiles: %w", err)
	}
	data = append(data, '\n')
	return atomicWriteFile(filePath, data)
}

func validateAndNormalizeProfile(p Profile) (Profile, error) {
	p = p.Clone()

	if p.ID != "" && strings.TrimSpace(p.ID) == "" {
		return Profile{}, fmt.Errorf("%w: id must not be whitespace", ErrInvalidProfile)
	}
	if strings.TrimSpace(p.Name) == "" {
		return Profile{}, fmt.Errorf("%w: name must not be empty", ErrInvalidProfile)
	}
	if strings.TrimSpace(p.Host) == "" || strings.ContainsAny(p.Host, " \t\r\n") {
		return Profile{}, fmt.Errorf("%w: invalid host", ErrInvalidProfile)
	}
	if p.Port < 1 || p.Port > maxTCPPort {
		return Profile{}, fmt.Errorf("%w: port %d outside [1,%d]", ErrInvalidProfile, p.Port, maxTCPPort)
	}
	if strings.TrimSpace(p.Username) == "" {
		return Profile{}, fmt.Errorf("%w: username must not be empty", ErrInvalidProfile)
	}
	if p.AuthType != AuthPassword && p.AuthType != AuthKey {
		return Profile{}, fmt.Errorf("%w: unsupported auth_type %q", ErrInvalidProfile, p.AuthType)
	}
	if p.PreferredMode == "" {
		p.PreferredMode = ModeProxy
	} else if p.PreferredMode != ModeProxy && p.PreferredMode != ModeTUN {
		return Profile{}, fmt.Errorf("%w: unsupported preferred_mode %q", ErrInvalidProfile, p.PreferredMode)
	}
	if p.PinnedHostKey != nil {
		if strings.TrimSpace(p.PinnedHostKey.Algorithm) == "" || strings.TrimSpace(p.PinnedHostKey.SHA256) == "" {
			return Profile{}, fmt.Errorf("%w: pinned_host_key algorithm and sha256 must be non-empty", ErrInvalidProfile)
		}
	}

	return p, nil
}

func cloneProfiles(in []Profile) []Profile {
	out := make([]Profile, len(in))
	for i := range in {
		out[i] = in[i].Clone()
	}
	return out
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func ensureDir0700(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("profile: create config directory: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("profile: enforce 0700 on config directory: %w", err)
		}
	}
	return nil
}

func atomicWriteFile(targetPath string, data []byte) error {
	dir := filepath.Dir(targetPath)
	if err := ensureDir0700(dir); err != nil {
		return err
	}

	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return fmt.Errorf("profile: generate temp filename entropy: %w", err)
	}
	tmpPath := fmt.Sprintf("%s.tmp.%s", targetPath, hex.EncodeToString(rnd[:]))

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("profile: create temp file: %w", err)
	}

	closed := false
	renamed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

	if runtime.GOOS != "windows" {
		if err := f.Chmod(0o600); err != nil {
			return fmt.Errorf("profile: enforce 0600 on temp file: %w", err)
		}
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("profile: write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("profile: sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		closed = true
		return fmt.Errorf("profile: close temp file: %w", err)
	}
	closed = true

	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("profile: rename temp file: %w", err)
	}
	renamed = true

	if runtime.GOOS != "windows" {
		if err := syncDir(dir); err != nil {
			return fmt.Errorf("profile: sync directory: %w", err)
		}
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil && !errors.Is(syncErr, syscall.EINVAL) {
		return syncErr
	}
	return closeErr
}

func decodeStrictJSONObject(raw []byte, dst any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("expected JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}
