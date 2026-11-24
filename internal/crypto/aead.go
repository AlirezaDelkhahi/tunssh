// Package crypto implements cryptographic primitives and the sshtun:// share-link codec.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// DefaultArgon2T is the default Argon2id iteration count.
	DefaultArgon2T = 3
	// DefaultArgon2M is the default Argon2id memory cost in KiB (64 MiB).
	DefaultArgon2M = 65536
	// DefaultArgon2C is the default Argon2id parallelism degree.
	DefaultArgon2C = 4

	// SaltLen is the required byte length for Argon2id salts.
	SaltLen = 16
	// NonceLen is the required byte length for AES-256-GCM nonces.
	NonceLen = 12
	// KeyLen is the required byte length for AES-256 keys.
	KeyLen = 32

	// MinArgon2T is the minimum permitted Argon2id iteration count.
	MinArgon2T = 1
	// MaxArgon2T is the maximum permitted Argon2id iteration count.
	MaxArgon2T = 10
	// MinArgon2M is the minimum permitted Argon2id memory cost in KiB (8 MiB).
	MinArgon2M = 8192
	// MaxArgon2M is the maximum permitted Argon2id memory cost in KiB (256 MiB).
	MaxArgon2M = 262144
	// MinArgon2C is the minimum permitted Argon2id parallelism degree.
	MinArgon2C = 1
	// MaxArgon2C is the maximum permitted Argon2id parallelism degree.
	MaxArgon2C = 16
)

var (
	// ErrKDFBoundsExceeded is returned when Argon2id parameters fall outside safe bounds.
	ErrKDFBoundsExceeded = errors.New("crypto: argon2id parameters out of allowed bounds")
	// ErrWrongPassphraseOrTampered is returned when AEAD authentication fails.
	ErrWrongPassphraseOrTampered = errors.New("crypto: wrong passphrase or tampered ciphertext")
)

// Argon2Params defines Argon2id key derivation cost parameters.
type Argon2Params struct {
	T uint32 `json:"t"`
	M uint32 `json:"m"`
	C uint8  `json:"c"`
}

// ValidateArgon2Params verifies that p falls strictly within safe CPU and memory limits.
func ValidateArgon2Params(p Argon2Params) error {
	if p.T < MinArgon2T || p.T > MaxArgon2T {
		return fmt.Errorf("%w: t=%d outside [%d,%d]", ErrKDFBoundsExceeded, p.T, MinArgon2T, MaxArgon2T)
	}
	if p.M < MinArgon2M || p.M > MaxArgon2M {
		return fmt.Errorf("%w: m=%d outside [%d,%d]", ErrKDFBoundsExceeded, p.M, MinArgon2M, MaxArgon2M)
	}
	if p.C < MinArgon2C || p.C > MaxArgon2C {
		return fmt.Errorf("%w: c=%d outside [%d,%d]", ErrKDFBoundsExceeded, p.C, MinArgon2C, MaxArgon2C)
	}
	return nil
}

// DeriveKey derives a 32-byte key from passphrase and salt using Argon2id after validating inputs.
func DeriveKey(passphrase string, salt []byte, p Argon2Params) ([]byte, error) {
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("crypto: invalid salt length %d, want %d", len(salt), SaltLen)
	}
	if err := ValidateArgon2Params(p); err != nil {
		return nil, err
	}

	passBytes := []byte(passphrase)
	defer clear(passBytes)

	return argon2.IDKey(passBytes, salt, p.T, p.M, p.C, KeyLen), nil
}

func newAESGCM(key, nonce []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("crypto: invalid key length %d, want %d", len(key), KeyLen)
	}
	if len(nonce) != NonceLen {
		return nil, fmt.Errorf("crypto: invalid nonce length %d, want %d", len(nonce), NonceLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aes-gcm: %w", err)
	}
	return gcm, nil
}

// SealAESGCM encrypts and authenticates plaintext with AES-256-GCM using key, nonce, and aad.
func SealAESGCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newAESGCM(key, nonce)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// OpenAESGCM decrypts and verifies AES-256-GCM ciphertext using key, nonce, and aad.
func OpenAESGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newAESGCM(key, nonce)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrongPassphraseOrTampered, err)
	}
	return plaintext, nil
}

// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("crypto: invalid random byte count %d", n)
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("crypto: read random bytes: %w", err)
	}
	return buf, nil
}
