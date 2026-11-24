package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"
)

type stubTimeoutNetError struct {
	msg     string
	timeout bool
}

func (e stubTimeoutNetError) Error() string   { return e.msg }
func (e stubTimeoutNetError) Timeout() bool   { return e.timeout }
func (e stubTimeoutNetError) Temporary() bool { return false }

func TestClassifyError(t *testing.T) {
	t.Run("nil_error_returns_nil", func(t *testing.T) {
		if got := ClassifyError(nil, 22, PhaseDial); got != nil {
			t.Fatalf("ClassifyError(nil) = %+v, want nil", got)
		}
	})

	t.Run("port22_timeouts_map_to_ERR_PORT22_TIMEOUT", func(t *testing.T) {
		timeoutErrs := []struct {
			name string
			err  error
		}{
			{"net_timeout", stubTimeoutNetError{msg: "dial tcp 1.2.3.4:22: connect: timed out", timeout: true}},
			{"deadline_exceeded", context.DeadlineExceeded},
			{"wrapped_io_timeout", errors.New("dial tcp 1.2.3.4:22: i/o timeout")},
		}

		for _, tc := range timeoutErrs {
			t.Run(tc.name, func(t *testing.T) {
				mapped := ClassifyError(tc.err, 22, PhaseDial)
				if mapped == nil {
					t.Fatal("expected non-nil MappedError")
				}
				if mapped.Code != ERR_PORT22_TIMEOUT {
					t.Fatalf("Code = %q, want %q", mapped.Code, ERR_PORT22_TIMEOUT)
				}
				if !mapped.Retryable {
					t.Fatal("expected Retryable == true for ERR_PORT22_TIMEOUT")
				}
				if mapped.Message == "" || mapped.ActionHint == "" {
					t.Fatalf("expected non-empty Message and ActionHint, got %+v", mapped)
				}
				for _, portHint := range []string{"443", "2053", "8443"} {
					if !strings.Contains(mapped.ActionHint, portHint) {
						t.Fatalf("ActionHint %q should suggest port %s", mapped.ActionHint, portHint)
					}
				}
				if !errors.Is(mapped, tc.err) {
					t.Fatalf("expected Unwrap() to preserve cause %v", tc.err)
				}
			})
		}

		// Timeout on port 443 should NOT claim port 22 throttling.
		non22 := ClassifyError(context.DeadlineExceeded, 443, PhaseDial)
		if non22.Code != ERR_NETWORK {
			t.Fatalf("timeout on port 443 Code = %q, want %q", non22.Code, ERR_NETWORK)
		}
		if !non22.Retryable {
			t.Fatal("expected timeout on port 443 to be Retryable")
		}
	})

	t.Run("mid_handshake_reset_and_eof_map_to_ERR_DPI_RESET", func(t *testing.T) {
		cases := []struct {
			name  string
			err   error
			phase DialPhase
		}{
			{"syscall_econnreset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, PhaseHandshake},
			{"io_eof_handshake", fmt.Errorf("ssh: handshake failed: %w", io.EOF), PhaseHandshake},
			{"io_unexpected_eof_handshake", fmt.Errorf("ssh: handshake failed: %w", io.ErrUnexpectedEOF), PhaseHandshake},
			{"econnreset_dial", syscall.ECONNRESET, PhaseDial},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mapped := ClassifyError(tc.err, 443, tc.phase)
				if mapped.Code != ERR_DPI_RESET {
					t.Fatalf("Code = %q, want %q", mapped.Code, ERR_DPI_RESET)
				}
				if !mapped.Retryable {
					t.Fatal("expected Retryable == true for ERR_DPI_RESET")
				}
				if mapped.ActionHint == "" {
					t.Fatal("expected non-empty ActionHint for ERR_DPI_RESET")
				}
			})
		}

		// Normal EOF after connection established in runtime is ERR_NETWORK, not mid-handshake DPI reset.
		runtimeEOF := ClassifyError(io.EOF, 443, PhaseRuntime)
		if runtimeEOF.Code != ERR_NETWORK {
			t.Fatalf("runtime EOF Code = %q, want %q", runtimeEOF.Code, ERR_NETWORK)
		}
	})

	t.Run("econnrefused_maps_to_ERR_CONN_REFUSED", func(t *testing.T) {
		err := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		mapped := ClassifyError(err, 2053, PhaseDial)
		if mapped.Code != ERR_CONN_REFUSED {
			t.Fatalf("Code = %q, want %q", mapped.Code, ERR_CONN_REFUSED)
		}
		if !mapped.Retryable {
			t.Fatal("expected Retryable == true for ERR_CONN_REFUSED")
		}
		if !strings.Contains(mapped.ActionHint, "2053") {
			t.Fatalf("ActionHint %q should mention port 2053", mapped.ActionHint)
		}
	})

	t.Run("auth_failures_map_to_ERR_AUTH_FAILED", func(t *testing.T) {
		cases := []error{
			errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain"),
			ErrAuthFailed,
		}
		for _, err := range cases {
			mapped := ClassifyError(err, 443, PhaseAuth)
			if mapped.Code != ERR_AUTH_FAILED {
				t.Fatalf("err %v -> Code = %q, want %q", err, mapped.Code, ERR_AUTH_FAILED)
			}
			if mapped.Retryable {
				t.Fatalf("expected Retryable == false for ERR_AUTH_FAILED")
			}
			if mapped.ActionHint == "" {
				t.Fatal("expected non-empty ActionHint")
			}
		}
	})

	t.Run("hostkey_errors_map_without_retry", func(t *testing.T) {
		untrusted := &ErrHostKeyUntrusted{
			Host:      "vps.example.com",
			Port:      443,
			Algorithm: "ssh-ed25519",
			SHA256:    "SHA256:abc123",
		}
		mappedUntrusted := ClassifyError(fmt.Errorf("ssh: handshake failed: %w", untrusted), 443, PhaseHostKey)
		if mappedUntrusted.Code != ERR_HOSTKEY_UNTRUSTED {
			t.Fatalf("Code = %q, want %q", mappedUntrusted.Code, ERR_HOSTKEY_UNTRUSTED)
		}
		if mappedUntrusted.Retryable {
			t.Fatal("expected Retryable == false for ERR_HOSTKEY_UNTRUSTED")
		}
		if mappedUntrusted.ActionHint == "" {
			t.Fatal("expected non-empty ActionHint for ERR_HOSTKEY_UNTRUSTED")
		}

		mismatch := &ErrHostKeyMismatch{
			Host:           "vps.example.com",
			Port:           443,
			ExpectedAlg:    "ssh-ed25519",
			ExpectedSHA256: "SHA256:expected",
			ActualAlg:      "ssh-ed25519",
			ActualSHA256:   "SHA256:actual",
		}
		mappedMismatch := ClassifyError(fmt.Errorf("ssh: handshake failed: %w", mismatch), 443, PhaseHostKey)
		if mappedMismatch.Code != ERR_HOSTKEY_MISMATCH {
			t.Fatalf("Code = %q, want %q", mappedMismatch.Code, ERR_HOSTKEY_MISMATCH)
		}
		if mappedMismatch.Retryable {
			t.Fatal("expected Retryable == false for ERR_HOSTKEY_MISMATCH")
		}
		if !strings.Contains(mappedMismatch.ActionHint, "SHA256:expected") || !strings.Contains(mappedMismatch.ActionHint, "SHA256:actual") {
			t.Fatalf("ActionHint %q should contain expected and actual fingerprints", mappedMismatch.ActionHint)
		}
	})

	t.Run("prohibited_forwarding_maps_to_ERR_FORWARD_DISABLED", func(t *testing.T) {
		err := &ssh.OpenChannelError{Reason: ssh.Prohibited, Message: "administratively prohibited"}
		mapped := ClassifyError(err, 443, PhaseChannel)
		if mapped.Code != ERR_FORWARD_DISABLED {
			t.Fatalf("Code = %q, want %q", mapped.Code, ERR_FORWARD_DISABLED)
		}
		if mapped.Retryable {
			t.Fatal("expected Retryable == false for ERR_FORWARD_DISABLED")
		}
		if !strings.Contains(mapped.ActionHint, "AllowTcpForwarding") {
			t.Fatalf("ActionHint %q should mention AllowTcpForwarding", mapped.ActionHint)
		}
	})

	t.Run("key_errors_map_to_ERR_KEY_INVALID", func(t *testing.T) {
		for _, err := range []error{
			&ErrKeyInvalid{Reason: "bad pem"},
			&ssh.PassphraseMissingError{},
		} {
			mapped := ClassifyError(err, 443, PhaseAuth)
			if mapped.Code != ERR_KEY_INVALID {
				t.Fatalf("err %T -> Code = %q, want %q", err, mapped.Code, ERR_KEY_INVALID)
			}
			if mapped.Retryable {
				t.Fatal("expected Retryable == false for ERR_KEY_INVALID")
			}
			if mapped.ActionHint == "" {
				t.Fatal("expected non-empty ActionHint")
			}
		}
	})

	t.Run("unknown_error_falls_back_to_ERR_NETWORK", func(t *testing.T) {
		cause := errors.New("unexpected socket anomaly")
		mapped := ClassifyError(cause, 443, PhaseRuntime)
		if mapped.Code != ERR_NETWORK {
			t.Fatalf("Code = %q, want %q", mapped.Code, ERR_NETWORK)
		}
		if !mapped.Retryable {
			t.Fatal("expected Retryable == true for ERR_NETWORK")
		}
		if mapped.Error() == "" || !errors.Is(mapped, cause) {
			t.Fatalf("unexpected Error/Unwrap behavior: %v", mapped)
		}
	})

	t.Run("already_mapped_error_is_preserved", func(t *testing.T) {
		orig := &MappedError{
			Code:       ERR_FORWARD_DISABLED,
			Message:    "blocked",
			ActionHint: "enable AllowTcpForwarding",
			Retryable:  false,
		}
		if got := ClassifyError(fmt.Errorf("wrap: %w", orig), 22, PhaseRuntime); got != orig {
			t.Fatalf("expected original *MappedError pointer to be returned, got %+v", got)
		}
	})
}
