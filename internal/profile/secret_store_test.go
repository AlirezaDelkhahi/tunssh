package profile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/AlirezaDelkhahi/tunssh/internal/crypto"
)

type testVaultEnvelope struct {
	V     int                 `json:"v"`
	KDF   string              `json:"kdf"`
	Salt  string              `json:"salt"`
	P     crypto.Argon2Params `json:"p"`
	Nonce string              `json:"nonce"`
	CT    string              `json:"ct"`
}

func readVaultEnvelope(t *testing.T, vaultPath string) (testVaultEnvelope, []byte) {
	t.Helper()
	raw, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read %s: %v", vaultPath, err)
	}
	var env testVaultEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal vault envelope: %v", err)
	}
	return env, raw
}

func flipSingleBitB64(t *testing.T, encoded string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64url: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("cannot flip bit in empty slice")
	}
	b[len(b)/2] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestEncryptedFileSecretStore_LockedAndPassphraseValidation(t *testing.T) {
	dir := t.TempDir()
	store := NewEncryptedFileSecretStore(dir)

	if store.BackendName() != "encrypted-file" {
		t.Fatalf("BackendName() = %q, want encrypted-file", store.BackendName())
	}
	if !store.IsLocked() {
		t.Fatal("new EncryptedFileSecretStore must start locked")
	}

	ctx := context.Background()
	if _, err := store.Get(ctx, "p1"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("Get while locked = %v, want ErrVaultLocked", err)
	}
	if err := store.Put(ctx, "p1", ProfileSecrets{Password: "pw"}); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("Put while locked = %v, want ErrVaultLocked", err)
	}
	if err := store.Delete(ctx, "p1"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("Delete while locked = %v, want ErrVaultLocked", err)
	}

	if err := store.Unlock(""); !errors.Is(err, ErrInvalidVaultPassphrase) {
		t.Fatalf("Unlock(\"\") = %v, want ErrInvalidVaultPassphrase", err)
	}
	if !store.IsLocked() {
		t.Fatal("store must remain locked after empty passphrase error")
	}

	emptyDirStore := NewEncryptedFileSecretStore("")
	if err := emptyDirStore.Unlock("secret-pass"); err == nil {
		t.Fatal("Unlock with empty configDir expected error")
	}
}

func TestEncryptedFileSecretStore_InitialUnlockCreates0600AndRejectsWrongPassphrase(t *testing.T) {
	parent := t.TempDir()
	configDir := filepath.Join(parent, "vault-dir")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	store := NewEncryptedFileSecretStore(configDir)
	if err := store.Unlock("correct-vault-passphrase"); err != nil {
		t.Fatalf("initial Unlock error: %v", err)
	}
	if store.IsLocked() {
		t.Fatal("store must be unlocked after Unlock")
	}

	assertMode(t, configDir, 0o700)
	vaultPath := filepath.Join(configDir, "secrets.enc")
	assertMode(t, vaultPath, 0o600)
	assertNoTempFiles(t, configDir)

	env, _ := readVaultEnvelope(t, vaultPath)
	if env.V != 1 || env.KDF != "argon2id" {
		t.Fatalf("unexpected envelope header: %+v", env)
	}
	if env.P.T != 3 || env.P.M != 65536 || env.P.C != 4 {
		t.Fatalf("unexpected Argon2Params: %+v", env.P)
	}
	saltBytes, err := base64.RawURLEncoding.Strict().DecodeString(env.Salt)
	if err != nil || len(saltBytes) != crypto.SaltLen {
		t.Fatalf("invalid salt: len=%d err=%v", len(saltBytes), err)
	}
	nonceBytes, err := base64.RawURLEncoding.Strict().DecodeString(env.Nonce)
	if err != nil || len(nonceBytes) != crypto.NonceLen {
		t.Fatalf("invalid nonce: len=%d err=%v", len(nonceBytes), err)
	}

	// Re-unlocking already unlocked store with wrong passphrase must fail.
	if err := store.Unlock("wrong-vault-passphrase"); !errors.Is(err, ErrInvalidVaultPassphrase) {
		t.Fatalf("Unlock(wrong) on unlocked store = %v, want ErrInvalidVaultPassphrase", err)
	}

	// Fresh instance on same directory must reject wrong passphrase immediately.
	reloaded := NewEncryptedFileSecretStore(configDir)
	if err := reloaded.Unlock("wrong-vault-passphrase"); !errors.Is(err, ErrInvalidVaultPassphrase) {
		t.Fatalf("reloaded Unlock(wrong) = %v, want ErrInvalidVaultPassphrase", err)
	}
	if !reloaded.IsLocked() {
		t.Fatal("reloaded store must stay locked on wrong passphrase")
	}
}

func TestEncryptedFileSecretStore_CRUDFreshNoncePersistenceDeleteAndLock(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "secrets.enc")

	store := NewEncryptedFileSecretStore(dir)
	if err := store.Unlock("vault-pass-123"); err != nil {
		t.Fatalf("Unlock error: %v", err)
	}
	ctx := context.Background()

	// Missing profile returns empty ProfileSecrets without error.
	missing, err := store.Get(ctx, "unknown-id")
	if err != nil {
		t.Fatalf("Get(unknown) error: %v", err)
	}
	if missing != (ProfileSecrets{}) {
		t.Fatalf("Get(unknown) = %+v, want empty", missing)
	}

	env0, _ := readVaultEnvelope(t, vaultPath)

	sec1 := ProfileSecrets{
		Password:      "super-secret-password-A",
		PrivateKey:    "-----BEGIN OPENSSH PRIVATE KEY-----\nabcdef\n-----END OPENSSH PRIVATE KEY-----",
		KeyPassphrase: "key-passphrase-A",
	}
	if err := store.Put(ctx, "prof-a", sec1); err != nil {
		t.Fatalf("Put(prof-a) error: %v", err)
	}
	assertMode(t, vaultPath, 0o600)
	assertNoTempFiles(t, dir)

	env1, raw1 := readVaultEnvelope(t, vaultPath)
	if env1.Nonce == env0.Nonce {
		t.Fatalf("nonce did not rotate on Put: %q", env1.Nonce)
	}
	for _, plaintextSecret := range []string{sec1.Password, sec1.PrivateKey, sec1.KeyPassphrase} {
		if bytes.Contains(raw1, []byte(plaintextSecret)) {
			t.Fatalf("secrets.enc contains plaintext secret %q", plaintextSecret)
		}
	}

	sec2 := ProfileSecrets{Password: "second-secret-B"}
	if err := store.Put(ctx, "prof-b", sec2); err != nil {
		t.Fatalf("Put(prof-b) error: %v", err)
	}
	assertNoTempFiles(t, dir)
	env2, _ := readVaultEnvelope(t, vaultPath)
	if env2.Nonce == env1.Nonce {
		t.Fatalf("nonce did not rotate on second Put: %q", env2.Nonce)
	}

	// Verify persistence across store reload + unlock.
	reloaded := NewEncryptedFileSecretStore(dir)
	if err := reloaded.Unlock("vault-pass-123"); err != nil {
		t.Fatalf("reloaded Unlock error: %v", err)
	}
	gotA, err := reloaded.Get(ctx, "prof-a")
	if err != nil {
		t.Fatalf("reloaded Get(prof-a) error: %v", err)
	}
	if !reflect.DeepEqual(gotA, sec1) {
		t.Fatalf("reloaded Get(prof-a) = %+v, want %+v", gotA, sec1)
	}
	gotB, err := reloaded.Get(ctx, "prof-b")
	if err != nil {
		t.Fatalf("reloaded Get(prof-b) error: %v", err)
	}
	if !reflect.DeepEqual(gotB, sec2) {
		t.Fatalf("reloaded Get(prof-b) = %+v, want %+v", gotB, sec2)
	}

	// Delete prof-a and verify nonce changes and deletion persists.
	if err := reloaded.Delete(ctx, "prof-a"); err != nil {
		t.Fatalf("Delete(prof-a) error: %v", err)
	}
	assertNoTempFiles(t, dir)
	env3, _ := readVaultEnvelope(t, vaultPath)
	if env3.Nonce == env2.Nonce {
		t.Fatalf("nonce did not rotate on Delete: %q", env3.Nonce)
	}

	afterDelA, err := reloaded.Get(ctx, "prof-a")
	if err != nil {
		t.Fatalf("Get(prof-a) after delete error: %v", err)
	}
	if afterDelA != (ProfileSecrets{}) {
		t.Fatalf("expected empty secrets after delete, got %+v", afterDelA)
	}

	// Put empty ProfileSecrets removes entry cleanly.
	if err := reloaded.Put(ctx, "prof-b", ProfileSecrets{}); err != nil {
		t.Fatalf("Put empty secrets error: %v", err)
	}
	clearedB, err := reloaded.Get(ctx, "prof-b")
	if err != nil {
		t.Fatalf("Get cleared prof-b error: %v", err)
	}
	if clearedB != (ProfileSecrets{}) {
		t.Fatalf("expected empty secrets after putting empty struct, got %+v", clearedB)
	}
	if err := reloaded.Put(ctx, "prof-b", sec2); err != nil {
		t.Fatalf("restore prof-b error: %v", err)
	}

	// Keep aliases to internal buffers before Lock() to verify zeroization via clear(...).
	retainedKey := reloaded.key
	retainedSalt := reloaded.salt
	if len(retainedKey) != crypto.KeyLen || len(retainedSalt) != crypto.SaltLen {
		t.Fatalf("expected key (%d) and salt (%d) cached while unlocked", len(retainedKey), len(retainedSalt))
	}

	reloaded.Lock()
	if !reloaded.IsLocked() {
		t.Fatal("expected IsLocked() == true after Lock()")
	}
	if reloaded.key != nil || reloaded.salt != nil || len(reloaded.secrets) != 0 {
		t.Fatal("expected in-memory key/salt/secrets references cleared after Lock()")
	}
	for i, b := range retainedKey {
		if b != 0 {
			t.Fatalf("retained key byte %d not zeroed on Lock()", i)
		}
	}
	for i, b := range retainedSalt {
		if b != 0 {
			t.Fatalf("retained salt byte %d not zeroed on Lock()", i)
		}
	}

	if _, err := reloaded.Get(ctx, "prof-b"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("Get after Lock() = %v, want ErrVaultLocked", err)
	}
	if err := reloaded.Put(ctx, "prof-b", sec2); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("Put after Lock() = %v, want ErrVaultLocked", err)
	}
	if err := reloaded.Delete(ctx, "prof-b"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("Delete after Lock() = %v, want ErrVaultLocked", err)
	}

	// Re-unlock after Lock() restores persisted prof-b and keeps prof-a deleted.
	if err := reloaded.Unlock("vault-pass-123"); err != nil {
		t.Fatalf("Unlock after Lock() error: %v", err)
	}
	gotBAfterReunlock, err := reloaded.Get(ctx, "prof-b")
	if err != nil {
		t.Fatalf("Get(prof-b) after re-unlock error: %v", err)
	}
	if !reflect.DeepEqual(gotBAfterReunlock, sec2) {
		t.Fatalf("Get(prof-b) after re-unlock = %+v, want %+v", gotBAfterReunlock, sec2)
	}
	gotAAfterReunlock, err := reloaded.Get(ctx, "prof-a")
	if err != nil {
		t.Fatalf("Get(prof-a) after re-unlock error: %v", err)
	}
	if gotAAfterReunlock != (ProfileSecrets{}) {
		t.Fatalf("prof-a unexpectedly restored after re-unlock: %+v", gotAAfterReunlock)
	}
}

func TestEncryptedFileSecretStore_TamperAndKDFBoundsRejection(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "secrets.enc")

	store := NewEncryptedFileSecretStore(dir)
	if err := store.Unlock("tamper-pass"); err != nil {
		t.Fatalf("Unlock error: %v", err)
	}
	if err := store.Put(context.Background(), "p1", ProfileSecrets{Password: "secret"}); err != nil {
		t.Fatalf("Put error: %v", err)
	}
	origEnv, _ := readVaultEnvelope(t, vaultPath)

	writeTampered := func(t *testing.T, mutate func(*testVaultEnvelope)) string {
		t.Helper()
		subDir := t.TempDir()
		env := origEnv
		mutate(&env)
		b, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("marshal tampered env: %v", err)
		}
		if err := os.WriteFile(filepath.Join(subDir, "secrets.enc"), b, 0o600); err != nil {
			t.Fatalf("write tampered env: %v", err)
		}
		return subDir
	}

	t.Run("tampered_ct", func(t *testing.T) {
		subDir := writeTampered(t, func(e *testVaultEnvelope) { e.CT = flipSingleBitB64(t, e.CT) })
		if err := NewEncryptedFileSecretStore(subDir).Unlock("tamper-pass"); !errors.Is(err, ErrInvalidVaultPassphrase) {
			t.Fatalf("got %v, want ErrInvalidVaultPassphrase", err)
		}
	})
	t.Run("tampered_nonce", func(t *testing.T) {
		subDir := writeTampered(t, func(e *testVaultEnvelope) { e.Nonce = flipSingleBitB64(t, e.Nonce) })
		if err := NewEncryptedFileSecretStore(subDir).Unlock("tamper-pass"); !errors.Is(err, ErrInvalidVaultPassphrase) {
			t.Fatalf("got %v, want ErrInvalidVaultPassphrase", err)
		}
	})
	t.Run("tampered_salt", func(t *testing.T) {
		subDir := writeTampered(t, func(e *testVaultEnvelope) { e.Salt = flipSingleBitB64(t, e.Salt) })
		if err := NewEncryptedFileSecretStore(subDir).Unlock("tamper-pass"); !errors.Is(err, ErrInvalidVaultPassphrase) {
			t.Fatalf("got %v, want ErrInvalidVaultPassphrase", err)
		}
	})
	t.Run("oversized_kdf_m_rejected", func(t *testing.T) {
		subDir := writeTampered(t, func(e *testVaultEnvelope) { e.P.M = crypto.MaxArgon2M + 1 })
		if err := NewEncryptedFileSecretStore(subDir).Unlock("tamper-pass"); !errors.Is(err, crypto.ErrKDFBoundsExceeded) {
			t.Fatalf("got %v, want ErrKDFBoundsExceeded", err)
		}
	})
	t.Run("oversized_kdf_t_rejected", func(t *testing.T) {
		subDir := writeTampered(t, func(e *testVaultEnvelope) { e.P.T = crypto.MaxArgon2T + 1 })
		if err := NewEncryptedFileSecretStore(subDir).Unlock("tamper-pass"); !errors.Is(err, crypto.ErrKDFBoundsExceeded) {
			t.Fatalf("got %v, want ErrKDFBoundsExceeded", err)
		}
	})
	t.Run("tampered_kdf_within_bounds", func(t *testing.T) {
		subDir := writeTampered(t, func(e *testVaultEnvelope) { e.P.T = crypto.MinArgon2T })
		if err := NewEncryptedFileSecretStore(subDir).Unlock("tamper-pass"); !errors.Is(err, ErrInvalidVaultPassphrase) {
			t.Fatalf("got %v, want ErrInvalidVaultPassphrase", err)
		}
	})
	t.Run("tampered_version", func(t *testing.T) {
		subDir := writeTampered(t, func(e *testVaultEnvelope) { e.V = 2 })
		if err := NewEncryptedFileSecretStore(subDir).Unlock("tamper-pass"); err == nil {
			t.Fatal("expected error for unsupported vault version")
		}
	})
}

func TestEncryptedFileSecretStore_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	store := NewEncryptedFileSecretStore(dir)
	if err := store.Unlock("race-test-pass"); err != nil {
		t.Fatalf("Unlock error: %v", err)
	}

	ctx := context.Background()
	const workers = 6
	const iters = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers*iters)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				id := fmt.Sprintf("p-%d-%d", worker, i)
				_ = store.IsLocked()
				if err := store.Put(ctx, id, ProfileSecrets{Password: "pw-" + id}); err != nil {
					errCh <- err
					return
				}
				got, err := store.Get(ctx, id)
				if err != nil {
					errCh <- err
					return
				}
				if got.Password != "pw-"+id {
					errCh <- fmt.Errorf("unexpected secret for %s: %+v", id, got)
					return
				}
				if i%2 == 0 {
					if err := store.Delete(ctx, id); err != nil {
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
		t.Fatalf("concurrent vault error: %v", err)
	}
	assertNoTempFiles(t, dir)
}

func TestKeyringSecretStore(t *testing.T) {
	keyring.MockInit()
	t.Cleanup(keyring.MockInit)

	store := NewKeyringSecretStore()
	if store.BackendName() != "keyring" {
		t.Fatalf("BackendName() = %q, want keyring", store.BackendName())
	}
	if store.IsLocked() {
		t.Fatal("KeyringSecretStore.IsLocked() must be false")
	}
	if err := store.Unlock("anything"); err != nil {
		t.Fatalf("KeyringSecretStore.Unlock() = %v, want nil", err)
	}

	ctx := context.Background()
	empty, err := store.Get(ctx, "prof-1")
	if err != nil {
		t.Fatalf("Get missing error: %v", err)
	}
	if empty != (ProfileSecrets{}) {
		t.Fatalf("Get missing = %+v, want empty", empty)
	}

	want := ProfileSecrets{
		Password:      "pw-123",
		PrivateKey:    "PEM-DATA",
		KeyPassphrase: "kp-456",
	}
	if err := store.Put(ctx, "prof-1", want); err != nil {
		t.Fatalf("Put error: %v", err)
	}

	// Verify exact service/key layout in go-keyring.
	for userKey, wantVal := range map[string]string{
		"profile:prof-1:password":       want.Password,
		"profile:prof-1:private_key":    want.PrivateKey,
		"profile:prof-1:key_passphrase": want.KeyPassphrase,
	} {
		gotVal, err := keyring.Get("tunssh", userKey)
		if err != nil {
			t.Fatalf("keyring.Get(tunssh, %q) error: %v", userKey, err)
		}
		if gotVal != wantVal {
			t.Fatalf("keyring[%q] = %q, want %q", userKey, gotVal, wantVal)
		}
	}

	got, err := store.Get(ctx, "prof-1")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Get = %+v, want %+v", got, want)
	}

	// Clearing KeyPassphrase on Put deletes that key while keeping others.
	updated := ProfileSecrets{
		Password:   "pw-123",
		PrivateKey: "PEM-DATA",
	}
	if err := store.Put(ctx, "prof-1", updated); err != nil {
		t.Fatalf("Put update error: %v", err)
	}
	if _, err := keyring.Get("tunssh", "profile:prof-1:key_passphrase"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("expected cleared key_passphrase to be deleted, got err=%v", err)
	}

	if err := store.Delete(ctx, "prof-1"); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if err := store.Delete(ctx, "prof-1"); err != nil {
		t.Fatalf("idempotent Delete error: %v", err)
	}
	for _, userKey := range []string{
		"profile:prof-1:password",
		"profile:prof-1:private_key",
		"profile:prof-1:key_passphrase",
	} {
		if _, err := keyring.Get("tunssh", userKey); !errors.Is(err, keyring.ErrNotFound) {
			t.Fatalf("expected %q deleted, got err=%v", userKey, err)
		}
	}

	if _, err := store.Get(ctx, ""); err == nil {
		t.Fatal("Get with empty profileID expected error")
	}

	backendErr := errors.New("dbus org.freedesktop.secrets failed")
	keyring.MockInitWithError(backendErr)
	if _, err := store.Get(ctx, "prof-1"); !errors.Is(err, backendErr) {
		t.Fatalf("expected backendErr on Get, got %v", err)
	}
	if err := store.Put(ctx, "prof-1", want); !errors.Is(err, backendErr) {
		t.Fatalf("expected backendErr on Put, got %v", err)
	}
	if err := store.Delete(ctx, "prof-1"); !errors.Is(err, backendErr) {
		t.Fatalf("expected backendErr on Delete, got %v", err)
	}
}

func TestNewAutoSecretStore_KeyringAndFallback(t *testing.T) {
	t.Cleanup(keyring.MockInit)
	dir := t.TempDir()

	// Available keyring (ErrNotFound on probe key) selects KeyringSecretStore.
	keyring.MockInit()
	store := NewAutoSecretStore(dir)
	if store.BackendName() != "keyring" {
		t.Fatalf("NewAutoSecretStore with MockInit BackendName() = %q, want keyring", store.BackendName())
	}

	// Probe key existing (err == nil) also selects KeyringSecretStore.
	if err := keyring.Set("tunssh", "__probe_availability__", "ok"); err != nil {
		t.Fatalf("keyring.Set probe error: %v", err)
	}
	storeExisting := NewAutoSecretStore(dir)
	if storeExisting.BackendName() != "keyring" {
		t.Fatalf("NewAutoSecretStore with existing probe key BackendName() = %q, want keyring", storeExisting.BackendName())
	}

	// Keyring error falls back to EncryptedFileSecretStore.
	keyring.MockInitWithError(errors.New("dbus unavailable"))
	fallback := NewAutoSecretStore(dir)
	if fallback.BackendName() != "encrypted-file" {
		t.Fatalf("NewAutoSecretStore with MockInitWithError BackendName() = %q, want encrypted-file", fallback.BackendName())
	}
	if !fallback.IsLocked() {
		t.Fatal("fallback EncryptedFileSecretStore must start locked")
	}

	// Injectable probe hook verification.
	hookKeyring := newAutoSecretStore(dir, func() error { return fmt.Errorf("wrapped: %w", keyring.ErrNotFound) })
	if hookKeyring.BackendName() != "keyring" {
		t.Fatalf("hook ErrNotFound BackendName() = %q, want keyring", hookKeyring.BackendName())
	}
	hookFallback := newAutoSecretStore(dir, func() error { return errors.New("no secret service") })
	if hookFallback.BackendName() != "encrypted-file" {
		t.Fatalf("hook error BackendName() = %q, want encrypted-file", hookFallback.BackendName())
	}
}
