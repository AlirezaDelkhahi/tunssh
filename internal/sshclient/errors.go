// Package sshclient implements the Milestone 1 SSH tunnel engine, including
// PAM/key authentication, TOFU SHA-256 host-key pinning, active keepalive
// watchdog, lock-free epoch-guarded auto-reconnect, and Iran-aware error mapping.
package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

// DialPhase identifies the connection stage where an SSH failure occurred.
type DialPhase string

const (
	PhaseDial      DialPhase = "dial"
	PhaseHandshake DialPhase = "handshake"
	PhaseAuth      DialPhase = "auth"
	PhaseHostKey   DialPhase = "hostkey"
	PhaseChannel   DialPhase = "channel"
	PhaseRuntime   DialPhase = "runtime"
)

// Exact actionable error codes mapped by ClassifyError.
const (
	ERR_PORT22_TIMEOUT    = "ERR_PORT22_TIMEOUT"
	ERR_DPI_RESET         = "ERR_DPI_RESET"
	ERR_CONN_REFUSED      = "ERR_CONN_REFUSED"
	ERR_AUTH_FAILED       = "ERR_AUTH_FAILED"
	ERR_HOSTKEY_UNTRUSTED = "ERR_HOSTKEY_UNTRUSTED"
	ERR_HOSTKEY_MISMATCH  = "ERR_HOSTKEY_MISMATCH"
	ERR_FORWARD_DISABLED  = "ERR_FORWARD_DISABLED"
	ERR_KEY_INVALID       = "ERR_KEY_INVALID"
	ERR_NETWORK           = "ERR_NETWORK"
)

var (
	// ErrAuthFailed indicates rejected SSH authentication or exhausted interactive rounds.
	ErrAuthFailed = errors.New("sshclient: authentication failed")
	// ErrNotConnected indicates no active SSH session is currently available.
	ErrNotConnected = errors.New("sshclient: not connected")
)

// ErrKeyInvalid describes an invalid PEM/OpenSSH key, unsupported .ppk file,
// or missing/incorrect private-key passphrase detected prior to dialing.
type ErrKeyInvalid struct {
	Reason string
	Cause  error
}

// Error implements the error interface.
func (e *ErrKeyInvalid) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil && e.Reason != "" {
		return fmt.Sprintf("sshclient: invalid private key: %s: %v", e.Reason, e.Cause)
	}
	if e.Reason != "" {
		return fmt.Sprintf("sshclient: invalid private key: %s", e.Reason)
	}
	if e.Cause != nil {
		return fmt.Sprintf("sshclient: invalid private key: %v", e.Cause)
	}
	return "sshclient: invalid private key"
}

// Unwrap returns the underlying key parse or decryption error.
func (e *ErrKeyInvalid) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// MappedError wraps a raw transport or SSH error with a stable code, user-facing
// message, actionable recovery hint, and retryability policy.
type MappedError struct {
	Code       string
	Message    string
	ActionHint string
	Retryable  bool
	Cause      error
}

// Error implements the error interface without leaking sensitive payloads.
func (e *MappedError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause for errors.Is and errors.As matching.
func (e *MappedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ClassifyError maps raw networking, TLS/SSH handshake, host-key, auth, key,
// and forwarding failures into actionable Iran-aware MappedError values.
func ClassifyError(err error, port int, phase DialPhase) *MappedError {
	if err == nil {
		return nil
	}

	var existing *MappedError
	if errors.As(err, &existing) {
		return existing
	}

	var untrusted *ErrHostKeyUntrusted
	if errors.As(err, &untrusted) {
		return &MappedError{
			Code:       ERR_HOSTKEY_UNTRUSTED,
			Message:    fmt.Sprintf("Server host key for %s:%d is not trusted yet.", untrusted.Host, untrusted.Port),
			ActionHint: fmt.Sprintf("Verify the server fingerprint (%s %s) and confirm Trust & Connect.", untrusted.Algorithm, untrusted.SHA256),
			Retryable:  false,
			Cause:      err,
		}
	}

	var mismatch *ErrHostKeyMismatch
	if errors.As(err, &mismatch) {
		return &MappedError{
			Code:    ERR_HOSTKEY_MISMATCH,
			Message: fmt.Sprintf("Host key mismatch for %s:%d.", mismatch.Host, mismatch.Port),
			ActionHint: fmt.Sprintf(
				"SECURITY ALERT: Server fingerprint changed (Expected %s vs Actual %s). Do NOT re-trust unless you reinstalled the VPS.",
				mismatch.ExpectedSHA256, mismatch.ActualSHA256,
			),
			Retryable: false,
			Cause:     err,
		}
	}

	var chanErr *ssh.OpenChannelError
	if errors.As(err, &chanErr) && chanErr.Reason == ssh.Prohibited {
		return &MappedError{
			Code:       ERR_FORWARD_DISABLED,
			Message:    "SSH connected, but TCP port forwarding is disabled on the server.",
			ActionHint: "SSH logged in, but port forwarding is blocked on the VPS. Set AllowTcpForwarding yes in /etc/ssh/sshd_config and reload sshd.",
			Retryable:  false,
			Cause:      err,
		}
	}

	var keyErr *ErrKeyInvalid
	var passErr *ssh.PassphraseMissingError
	if errors.As(err, &keyErr) || errors.As(err, &passErr) {
		return &MappedError{
			Code:       ERR_KEY_INVALID,
			Message:    "Failed to load or unlock SSH private key.",
			ActionHint: "Unable to unlock SSH private key. Check passphrase or export key in OpenSSH PEM format (not .ppk).",
			Retryable:  false,
			Cause:      err,
		}
	}

	if isAuthError(err) {
		return &MappedError{
			Code:       ERR_AUTH_FAILED,
			Message:    "SSH authentication failed.",
			ActionHint: "Server rejected credentials. Verify username/password, confirm KbdInteractiveAuthentication / PasswordAuthentication in /etc/ssh/sshd_config, or use an SSH key.",
			Retryable:  false,
			Cause:      err,
		}
	}

	if isConnRefusedError(err) {
		return &MappedError{
			Code:       ERR_CONN_REFUSED,
			Message:    fmt.Sprintf("Connection refused on port %d.", port),
			ActionHint: fmt.Sprintf("VPS refused connection on port %d. Check that sshd is listening on that port (ss -tlnp) and allowed in firewall (ufw).", port),
			Retryable:  true,
			Cause:      err,
		}
	}

	if isTimeoutError(err) {
		if port == 22 {
			return &MappedError{
				Code:       ERR_PORT22_TIMEOUT,
				Message:    "Connection to port 22 timed out.",
				ActionHint: "Port 22 timed out. Iranian ISPs commonly throttle or block port 22. Configure sshd on port 443, 2053, or 8443 and update your profile.",
				Retryable:  true,
				Cause:      err,
			}
		}
		return &MappedError{
			Code:       ERR_NETWORK,
			Message:    fmt.Sprintf("Connection timed out on port %d.", port),
			ActionHint: "Network timeout reaching the VPS. Check your internet connection, firewall, or try another port such as 443, 2053, or 8443.",
			Retryable:  true,
			Cause:      err,
		}
	}

	if isHandshakeResetOrEOF(err, phase) {
		return &MappedError{
			Code:       ERR_DPI_RESET,
			Message:    "Connection was reset during the SSH handshake.",
			ActionHint: "Connection was reset mid-handshake (likely ISP DPI filtering or VPS firewall). Verify sshd is reachable or switch to port 443.",
			Retryable:  true,
			Cause:      err,
		}
	}

	return &MappedError{
		Code:       ERR_NETWORK,
		Message:    "Network connection failed.",
		ActionHint: "Check your internet connectivity and VPS reachability, then try again.",
		Retryable:  true,
		Cause:      err,
	}
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "i/o timeout") || strings.Contains(lower, "timed out")
}

func isConnRefusedError(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "connection refused") || strings.Contains(lower, "actively refused")
}

func isHandshakeResetOrEOF(err error, phase DialPhase) bool {
	isReset := errors.Is(err, syscall.ECONNRESET) ||
		strings.Contains(strings.ToLower(err.Error()), "connection reset by peer") ||
		strings.Contains(strings.ToLower(err.Error()), "forcibly closed by the remote host")
	if isReset && (phase == PhaseHandshake || phase == PhaseDial) {
		return true
	}
	if phase == PhaseHandshake && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		return true
	}
	return false
}

func isAuthError(err error) bool {
	if errors.Is(err, ErrAuthFailed) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "unable to authenticate") ||
		strings.Contains(lower, "too many authentication attempts") ||
		strings.Contains(lower, "too many authentication failures") ||
		strings.Contains(lower, "no more authentication methods available")
}
