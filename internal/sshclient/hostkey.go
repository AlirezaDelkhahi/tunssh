package sshclient

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// HostKeyPin identifies a pinned SSH server host key using its algorithm and SHA-256 fingerprint.
type HostKeyPin struct {
	Algorithm string `json:"algorithm"`
	SHA256    string `json:"sha256"`
}

// ErrHostKeyUntrusted indicates the server presented a host key with no pinned expectation yet.
type ErrHostKeyUntrusted struct {
	Host      string
	Port      int
	Algorithm string
	SHA256    string
}

// Error implements the error interface.
func (e *ErrHostKeyUntrusted) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("sshclient: untrusted host key for %s:%d (%s %s)", e.Host, e.Port, e.Algorithm, e.SHA256)
}

// ErrHostKeyMismatch indicates the server presented a host key differing from the pinned key.
type ErrHostKeyMismatch struct {
	Host           string
	Port           int
	ExpectedAlg    string
	ExpectedSHA256 string
	ActualAlg      string
	ActualSHA256   string
}

// Error implements the error interface.
func (e *ErrHostKeyMismatch) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf(
		"sshclient: host key mismatch for %s:%d (expected %s %s, got %s %s)",
		e.Host, e.Port, e.ExpectedAlg, e.ExpectedSHA256, e.ActualAlg, e.ActualSHA256,
	)
}

// HostKeyProbeResult captures structured TOFU verification results directly from
// the HostKeyCallback without depending on x/crypto/ssh error wrapping.
type HostKeyProbeResult struct {
	Untrusted *ErrHostKeyUntrusted
	Mismatch  *ErrHostKeyMismatch
}

// NewTOFUHostKeyCallback builds a non-blocking TOFU ssh.HostKeyCallback that compares
// the server host key against pinned, recording any untrusted or mismatch outcome in res.
func NewTOFUHostKeyCallback(host string, port int, pinned *HostKeyPin) (ssh.HostKeyCallback, *HostKeyProbeResult) {
	res := &HostKeyProbeResult{}
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		alg := key.Type()
		fp := ssh.FingerprintSHA256(key)

		if pinned == nil || (strings.TrimSpace(pinned.Algorithm) == "" && strings.TrimSpace(pinned.SHA256) == "") {
			err := &ErrHostKeyUntrusted{
				Host:      host,
				Port:      port,
				Algorithm: alg,
				SHA256:    fp,
			}
			res.Untrusted = err
			return err
		}

		actualBytes, okActual := decodeFingerprintSHA256(fp)
		expectedBytes, okExpected := decodeFingerprintSHA256(pinned.SHA256)
		algMatch := subtle.ConstantTimeCompare([]byte(alg), []byte(pinned.Algorithm)) == 1
		fpMatch := okActual && okExpected &&
			len(actualBytes) == len(expectedBytes) &&
			subtle.ConstantTimeCompare(actualBytes, expectedBytes) == 1

		if !algMatch || !fpMatch {
			err := &ErrHostKeyMismatch{
				Host:           host,
				Port:           port,
				ExpectedAlg:    pinned.Algorithm,
				ExpectedSHA256: pinned.SHA256,
				ActualAlg:      alg,
				ActualSHA256:   fp,
			}
			res.Mismatch = err
			return err
		}

		return nil
	}
	return cb, res
}

func decodeFingerprintSHA256(fp string) ([]byte, bool) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(fp), "SHA256:")
	if trimmed == "" {
		return nil, false
	}

	var (
		decoded []byte
		err     error
	)
	if strings.Contains(trimmed, "=") {
		decoded, err = base64.StdEncoding.Strict().DecodeString(trimmed)
	} else {
		decoded, err = base64.RawStdEncoding.Strict().DecodeString(trimmed)
	}
	if err != nil || len(decoded) != sha256.Size {
		return nil, false
	}
	return decoded, true
}
