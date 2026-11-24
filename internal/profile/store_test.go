package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Fatalf("read dir %s: %v", dir, err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("unexpected temporary file left in %s: %s", dir, entry.Name())
		}
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}

func validSampleProfile() Profile {
	return Profile{
		Name:          "Germany VPS",
		Host:          "de.example.com",
		Port:          443,
		Username:      "tunnel",
		AuthType:      AuthPassword,
		BypassIranLAN: true,
		PinnedHostKey: &HostKeyPin{
			Algorithm: "ssh-ed25519",
			SHA256:    "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
		},
	}
}

func TestNewUUID(t *testing.T) {
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		id, err := NewUUID()
		if err != nil {
			t.Fatalf("NewUUID() error: %v", err)
		}
		if !uuidRe.MatchString(id) {
			t.Fatalf("NewUUID() = %q does not match RFC 4122 v4 pattern", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate UUID generated: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestProfileStructHasNoSecretFields(t *testing.T) {
	typ := reflect.TypeOf(Profile{})
	forbidden := []string{"password", "private_key", "privatekey", "key_passphrase", "keypassphrase", "passphrase", "secret"}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		nameLower := strings.ToLower(f.Name)
		tagLower := strings.ToLower(f.Tag.Get("json"))
		for _, bad := range forbidden {
			if strings.Contains(nameLower, bad) || strings.Contains(tagLower, bad) {
				t.Fatalf("Profile struct must never contain secret field %q (tag %q)", f.Name, f.Tag.Get("json"))
			}
		}
	}
}

func TestFileStore_ValidationAndConstructorErrors(t *testing.T) {
	if _, err := NewFileStore(""); err == nil {
		t.Fatal("NewFileStore(\"\") expected error, got nil")
	}
	if _, err := NewFileStore("   "); err == nil {
		t.Fatal("NewFileStore(\"   \") expected error, got nil")
	}

	tmpFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := NewFileStore(tmpFile); err == nil {
		t.Fatal("NewFileStore(file) expected error, got nil")
	}

	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}

	ctx := context.Background()
	invalidCases := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"empty_name", func(p *Profile) { p.Name = "" }},
		{"whitespace_name", func(p *Profile) { p.Name = "   \t " }},
		{"empty_host", func(p *Profile) { p.Host = "" }},
		{"whitespace_host", func(p *Profile) { p.Host = "   " }},
		{"host_contains_space", func(p *Profile) { p.Host = "bad host.com" }},
		{"port_zero", func(p *Profile) { p.Port = 0 }},
		{"port_negative", func(p *Profile) { p.Port = -22 }},
		{"port_too_high", func(p *Profile) { p.Port = 65536 }},
		{"empty_username", func(p *Profile) { p.Username = "" }},
		{"whitespace_username", func(p *Profile) { p.Username = "  " }},
		{"empty_auth_type", func(p *Profile) { p.AuthType = "" }},
		{"invalid_auth_type", func(p *Profile) { p.AuthType = AuthType("oauth") }},
		{"invalid_preferred_mode", func(p *Profile) { p.PreferredMode = TunnelMode("wireguard") }},
		{"whitespace_id", func(p *Profile) { p.ID = "   " }},
		{"pin_empty_algorithm", func(p *Profile) { p.PinnedHostKey = &HostKeyPin{Algorithm: "", SHA256: "SHA256:abc"} }},
		{"pin_empty_sha256", func(p *Profile) { p.PinnedHostKey = &HostKeyPin{Algorithm: "ssh-ed25519", SHA256: " "} }},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			p := validSampleProfile()
			tc.mutate(&p)
			_, err := store.Save(ctx, p)
			if !errors.Is(err, ErrInvalidProfile) {
				t.Fatalf("Save(%s) error = %v, want ErrInvalidProfile", tc.name, err)
			}
		})
	}
}

func TestFileStore_CRUDPermissionsAndNoSecrets(t *testing.T) {
	parent := t.TempDir()
	configDir := filepath.Join(parent, "tunssh-config")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	store, err := NewFileStore(configDir)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}
	ctx := context.Background()

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("initial List error: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("initial List len = %d, want 0", len(list))
	}

	if _, err := store.Get(ctx, "missing"); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrProfileNotFound", err)
	}
	if err := store.Delete(ctx, "missing"); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("Delete(missing) error = %v, want ErrProfileNotFound", err)
	}

	in := validSampleProfile()
	saved, err := store.Save(ctx, in)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}
	if saved.ID == "" {
		t.Fatal("expected generated UUID ID")
	}
	if saved.PreferredMode != ModeProxy {
		t.Fatalf("PreferredMode = %q, want %q", saved.PreferredMode, ModeProxy)
	}
	if saved.CreatedAt.IsZero() || saved.UpdatedAt.IsZero() {
		t.Fatalf("expected non-zero timestamps: created=%v updated=%v", saved.CreatedAt, saved.UpdatedAt)
	}
	if saved.CreatedAt.Location() != time.UTC || saved.UpdatedAt.Location() != time.UTC {
		t.Fatalf("timestamps must be UTC: created=%v updated=%v", saved.CreatedAt.Location(), saved.UpdatedAt.Location())
	}

	assertMode(t, configDir, 0o700)
	profilesPath := filepath.Join(configDir, "profiles.json")
	assertMode(t, profilesPath, 0o600)
	assertNoTempFiles(t, configDir)

	// Verify profiles.json bytes never contain secret keys or secret values.
	rawBytes, err := os.ReadFile(profilesPath)
	if err != nil {
		t.Fatalf("read profiles.json: %v", err)
	}
	var rawObjects []map[string]any
	if err := json.Unmarshal(rawBytes, &rawObjects); err != nil {
		t.Fatalf("unmarshal profiles.json objects: %v", err)
	}
	for _, obj := range rawObjects {
		for _, forbiddenKey := range []string{"password", "private_key", "key_passphrase"} {
			if _, exists := obj[forbiddenKey]; exists {
				t.Fatalf("profiles.json unexpectedly contains secret key %q: %s", forbiddenKey, string(rawBytes))
			}
		}
	}
	for _, forbiddenSubstr := range []string{"\"password\":", "\"private_key\":", "\"key_passphrase\":", "super-secret-password", "PRIVATE KEY", "my-key-passphrase"} {
		if bytes.Contains(rawBytes, []byte(forbiddenSubstr)) {
			t.Fatalf("profiles.json unexpectedly contains secret substring %q: %s", forbiddenSubstr, string(rawBytes))
		}
	}

	// Update existing profile: preserve CreatedAt and clear PinnedHostKey.
	time.Sleep(2 * time.Millisecond)
	updatedReq := saved.Clone()
	updatedReq.Name = "Germany VPS Updated"
	updatedReq.AuthType = AuthKey
	updatedReq.PreferredMode = ModeTUN
	updatedReq.PinnedHostKey = nil
	updatedReq.CreatedAt = time.Time{} // store must preserve original CreatedAt

	updated, err := store.Save(ctx, updatedReq)
	if err != nil {
		t.Fatalf("Save update error: %v", err)
	}
	if !updated.CreatedAt.Equal(saved.CreatedAt) {
		t.Fatalf("CreatedAt changed on update: got %v, want %v", updated.CreatedAt, saved.CreatedAt)
	}
	if !updated.UpdatedAt.After(saved.UpdatedAt) {
		t.Fatalf("UpdatedAt did not advance: old=%v new=%v", saved.UpdatedAt, updated.UpdatedAt)
	}
	if updated.PinnedHostKey != nil || updated.PreferredMode != ModeTUN || updated.AuthType != AuthKey {
		t.Fatalf("unexpected updated fields: %+v", updated)
	}
	assertNoTempFiles(t, configDir)

	// Reload from disk in a fresh FileStore instance.
	reloaded, err := NewFileStore(configDir)
	if err != nil {
		t.Fatalf("reload NewFileStore error: %v", err)
	}
	got, err := reloaded.Get(ctx, saved.ID)
	if err != nil {
		t.Fatalf("reloaded Get error: %v", err)
	}
	if !reflect.DeepEqual(got, updated) {
		t.Fatalf("reloaded profile mismatch:\n got: %+v\nwant: %+v", got, updated)
	}

	// Delete profile and confirm persistence across reload.
	if err := reloaded.Delete(ctx, saved.ID); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	assertNoTempFiles(t, configDir)

	reloadedAfterDelete, err := NewFileStore(configDir)
	if err != nil {
		t.Fatalf("reload after delete error: %v", err)
	}
	if _, err := reloadedAfterDelete.Get(ctx, saved.ID); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("Get after delete error = %v, want ErrProfileNotFound", err)
	}
	afterList, err := reloadedAfterDelete.List(ctx)
	if err != nil {
		t.Fatalf("List after delete error: %v", err)
	}
	if len(afterList) != 0 {
		t.Fatalf("List after delete len = %d, want 0", len(afterList))
	}
}

func TestFileStore_CloneIsolation(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}
	ctx := context.Background()

	in := validSampleProfile()
	saved, err := store.Save(ctx, in)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}

	// Mutate caller input pointer and returned pointers/slices.
	in.PinnedHostKey.SHA256 = "mutated-input"
	saved.PinnedHostKey.SHA256 = "mutated-saved"

	got, err := store.Get(ctx, saved.ID)
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if got.PinnedHostKey.SHA256 != "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" {
		t.Fatalf("internal PinnedHostKey mutated via input/save return: %q", got.PinnedHostKey.SHA256)
	}
	got.PinnedHostKey.SHA256 = "mutated-get"

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(list) != 1 || list[0].PinnedHostKey.SHA256 != "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" {
		t.Fatalf("internal PinnedHostKey mutated via Get return: %+v", list)
	}
	list[0].Name = "mutated-list"
	list[0].PinnedHostKey.SHA256 = "mutated-list-pin"

	again, err := store.Get(ctx, saved.ID)
	if err != nil {
		t.Fatalf("Get again error: %v", err)
	}
	if again.Name != "Germany VPS" || again.PinnedHostKey.SHA256 != "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU" {
		t.Fatalf("internal state mutated via List return: %+v", again)
	}
}

func TestFileStore_CorruptAndCancelledContext(t *testing.T) {
	dir := t.TempDir()
	profilesPath := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(profilesPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	if _, err := NewFileStore(dir); err == nil {
		t.Fatal("expected error loading corrupt profiles.json")
	}

	// Duplicate IDs on disk should be rejected.
	dupJSON, err := json.Marshal([]Profile{
		{ID: "dup-1", Name: "A", Host: "a.com", Port: 22, Username: "u", AuthType: AuthPassword, PreferredMode: ModeProxy},
		{ID: "dup-1", Name: "B", Host: "b.com", Port: 22, Username: "u", AuthType: AuthPassword, PreferredMode: ModeProxy},
	})
	if err != nil {
		t.Fatalf("marshal dup: %v", err)
	}
	if err := os.WriteFile(profilesPath, dupJSON, 0o600); err != nil {
		t.Fatalf("write dup file: %v", err)
	}
	if _, err := NewFileStore(dir); err == nil {
		t.Fatal("expected error loading duplicate IDs in profiles.json")
	}

	// Reject unknown fields (such as injected secret fields) in profiles.json.
	unknownFieldJSON := []byte(`[{"id":"x","name":"A","host":"a.com","port":22,"username":"u","auth_type":"password","preferred_mode":"proxy","password":"leak"}]`)
	if err := os.WriteFile(profilesPath, unknownFieldJSON, 0o600); err != nil {
		t.Fatalf("write unknown-field file: %v", err)
	}
	if _, err := NewFileStore(dir); err == nil {
		t.Fatal("expected error loading unknown field in profiles.json")
	}

	// Pre-assigned profile ID should be preserved on Save, and failed atomic rename must leave zero .tmp files.
	preDir := t.TempDir()
	preStore, err := NewFileStore(preDir)
	if err != nil {
		t.Fatalf("NewFileStore(preDir) error: %v", err)
	}
	preID, err := NewUUID()
	if err != nil {
		t.Fatalf("NewUUID error: %v", err)
	}
	preProfile := validSampleProfile()
	preProfile.ID = preID
	savedPre, err := preStore.Save(context.Background(), preProfile)
	if err != nil {
		t.Fatalf("Save with pre-assigned ID error: %v", err)
	}
	if savedPre.ID != preID {
		t.Fatalf("savedPre.ID = %q, want %q", savedPre.ID, preID)
	}

	failDir := t.TempDir()
	failStore, err := NewFileStore(failDir)
	if err != nil {
		t.Fatalf("NewFileStore(failDir) error: %v", err)
	}
	// Make profiles.json a directory so os.Rename fails and verify cleanup removes .tmp files.
	if err := os.Mkdir(filepath.Join(failDir, "profiles.json"), 0o700); err != nil {
		t.Fatalf("mkdir profiles.json trap: %v", err)
	}
	if _, err := failStore.Save(context.Background(), validSampleProfile()); err == nil {
		t.Fatal("expected Save error when target profiles.json is a directory")
	}
	assertNoTempFiles(t, failDir)

	cleanDir := t.TempDir()
	store, err := NewFileStore(cleanDir)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := store.List(cancelledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("List(cancelled) = %v, want context.Canceled", err)
	}
	if _, err := store.Get(cancelledCtx, "id"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get(cancelled) = %v, want context.Canceled", err)
	}
	if _, err := store.Save(cancelledCtx, validSampleProfile()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Save(cancelled) = %v, want context.Canceled", err)
	}
	if err := store.Delete(cancelledCtx, "id"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete(cancelled) = %v, want context.Canceled", err)
	}
}

func TestFileStore_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore error: %v", err)
	}
	ctx := context.Background()

	const workers = 8
	const iters = 10
	var wg sync.WaitGroup
	errCh := make(chan error, workers*iters)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				p := validSampleProfile()
				p.Name = fmt.Sprintf("worker-%d-iter-%d", worker, i)
				saved, err := store.Save(ctx, p)
				if err != nil {
					errCh <- err
					return
				}
				if _, err := store.Get(ctx, saved.ID); err != nil {
					errCh <- err
					return
				}
				if _, err := store.List(ctx); err != nil {
					errCh <- err
					return
				}
				if i%2 == 0 {
					if err := store.Delete(ctx, saved.ID); err != nil {
						errCh <- err
						return
					}
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent store error: %v", err)
	}
	assertNoTempFiles(t, dir)
	assertMode(t, filepath.Join(dir, "profiles.json"), 0o600)

	remaining, err := store.List(ctx)
	if err != nil {
		t.Fatalf("final List error: %v", err)
	}
	wantRemaining := workers * (iters / 2)
	if len(remaining) != wantRemaining {
		t.Fatalf("remaining profiles = %d, want %d", len(remaining), wantRemaining)
	}
}
