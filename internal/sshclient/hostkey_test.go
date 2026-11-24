package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func generateTestSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

func TestTOFUHostKeyCallback(t *testing.T) {
	signerA := generateTestSSHSigner(t)
	signerB := generateTestSSHSigner(t)
	pubA := signerA.PublicKey()
	pubB := signerB.PublicKey()
	fpA := ssh.FingerprintSHA256(pubA)
	fpB := ssh.FingerprintSHA256(pubB)
	dummyAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}

	t.Run("unpinned_records_and_returns_ErrHostKeyUntrusted", func(t *testing.T) {
		for _, pin := range []*HostKeyPin{nil, {}} {
			cb, res := NewTOFUHostKeyCallback("vps.example.com", 443, pin)
			err := cb("vps.example.com:443", dummyAddr, pubA)
			var untrusted *ErrHostKeyUntrusted
			if !errors.As(err, &untrusted) {
				t.Fatalf("expected *ErrHostKeyUntrusted, got %v", err)
			}
			if res.Untrusted == nil || res.Mismatch != nil {
				t.Fatalf("unexpected probe result: %+v", res)
			}
			if untrusted.Host != "vps.example.com" || untrusted.Port != 443 {
				t.Fatalf("unexpected host/port: %+v", untrusted)
			}
			if untrusted.Algorithm != pubA.Type() || untrusted.SHA256 != fpA {
				t.Fatalf("got (%q, %q), want (%q, %q)", untrusted.Algorithm, untrusted.SHA256, pubA.Type(), fpA)
			}
		}
	})

	t.Run("matching_pin_succeeds_for_raw_and_padded_base64", func(t *testing.T) {
		for _, fp := range []string{fpA, fpA + "="} {
			cb, res := NewTOFUHostKeyCallback("vps.example.com", 443, &HostKeyPin{
				Algorithm: pubA.Type(),
				SHA256:    fp,
			})
			if err := cb("vps.example.com:443", dummyAddr, pubA); err != nil {
				t.Fatalf("pin %q failed unexpectedly: %v", fp, err)
			}
			if res.Untrusted != nil || res.Mismatch != nil {
				t.Fatalf("expected empty probe result, got %+v", res)
			}
		}
	})

	t.Run("mismatched_key_or_algorithm_or_malformed_pin_returns_ErrHostKeyMismatch", func(t *testing.T) {
		cases := []struct {
			name string
			pin  HostKeyPin
		}{
			{"different_key", HostKeyPin{Algorithm: pubB.Type(), SHA256: fpB}},
			{"different_algorithm", HostKeyPin{Algorithm: "ssh-rsa", SHA256: fpA}},
			{"malformed_base64", HostKeyPin{Algorithm: pubA.Type(), SHA256: "SHA256:not-valid-base64!"}},
			{"wrong_digest_length", HostKeyPin{Algorithm: pubA.Type(), SHA256: "SHA256:AAAA"}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cb, res := NewTOFUHostKeyCallback("vps.example.com", 443, &tc.pin)
				err := cb("vps.example.com:443", dummyAddr, pubA)
				var mismatch *ErrHostKeyMismatch
				if !errors.As(err, &mismatch) {
					t.Fatalf("expected *ErrHostKeyMismatch, got %v", err)
				}
				if res.Mismatch == nil || res.Untrusted != nil {
					t.Fatalf("unexpected probe result: %+v", res)
				}
				if mismatch.ExpectedAlg != tc.pin.Algorithm || mismatch.ExpectedSHA256 != tc.pin.SHA256 {
					t.Fatalf("unexpected expected fields: %+v", mismatch)
				}
				if mismatch.ActualAlg != pubA.Type() || mismatch.ActualSHA256 != fpA {
					t.Fatalf("unexpected actual fields: %+v", mismatch)
				}
			})
		}
	})
}

func TestHostKeyTOFUAndRotationOverRealSSH(t *testing.T) {
	signerA := generateTestSSHSigner(t)
	signerB := generateTestSSHSigner(t)
	srv := startTestSSHServer(t, testServerOptions{
		hostSigner: signerA,
		password:   "secret-pass",
	})
	defer srv.Close()

	// Step 1: First connect without pinned host key fails cleanly with ERR_HOSTKEY_UNTRUSTED
	// and surfaces exact SHA-256 fingerprint for user confirmation.
	engine := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var storedPin *HostKeyPin
	err := engine.Connect(ctx, ConnectConfig{
		ProfileID: "p1",
		Host:      srv.Host(),
		Port:      srv.Port(),
		Username:  "ali",
		Auth: AuthConfig{
			Type:     AuthPassword,
			Password: "secret-pass",
		},
		PinnedHostKey: storedPin,
	})
	if err == nil {
		t.Fatal("expected ERR_HOSTKEY_UNTRUSTED when PinnedHostKey is nil")
	}
	var mapped *MappedError
	if !errors.As(err, &mapped) || mapped.Code != ERR_HOSTKEY_UNTRUSTED || mapped.Retryable {
		t.Fatalf("expected non-retryable ERR_HOSTKEY_UNTRUSTED, got %+v (%v)", mapped, err)
	}
	snap := engine.Snapshot()
	if snap.State != StateError || snap.HostKeyPrompt == nil {
		t.Fatalf("expected StateError with HostKeyPrompt, got %+v", snap)
	}
	wantFP := ssh.FingerprintSHA256(signerA.PublicKey())
	if snap.HostKeyPrompt.SHA256 != wantFP || snap.HostKeyPrompt.Algorithm != signerA.PublicKey().Type() {
		t.Fatalf("prompt fingerprint = (%s, %s), want (%s, %s)",
			snap.HostKeyPrompt.Algorithm, snap.HostKeyPrompt.SHA256, signerA.PublicKey().Type(), wantFP)
	}
	// Verify server closed pre-auth connection cleanly without lingering active connections.
	waitCondition(t, 2*time.Second, func() bool { return srv.ActiveRawConns() == 0 }, "server raw socket should close after untrusted rejection")

	// Step 2: Persist pinned key after user confirmation and connect -> succeeds.
	storedPin = &HostKeyPin{
		Algorithm: snap.HostKeyPrompt.Algorithm,
		SHA256:    snap.HostKeyPrompt.SHA256,
	}
	if err := engine.Connect(ctx, ConnectConfig{
		ProfileID: "p1",
		Host:      srv.Host(),
		Port:      srv.Port(),
		Username:  "ali",
		Auth: AuthConfig{
			Type:     AuthPassword,
			Password: "secret-pass",
		},
		PinnedHostKey: storedPin,
	}); err != nil {
		t.Fatalf("connect with matching PinnedHostKey failed: %v", err)
	}
	if got := engine.Snapshot().State; got != StateConnected {
		t.Fatalf("state = %q, want %q", got, StateConnected)
	}
	if err := engine.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}

	// Step 3: Rotate server host key -> ERR_HOSTKEY_MISMATCH, stored pin stays untouched.
	srv.SetHostSigner(signerB)
	err = engine.Connect(ctx, ConnectConfig{
		ProfileID: "p1",
		Host:      srv.Host(),
		Port:      srv.Port(),
		Username:  "ali",
		Auth: AuthConfig{
			Type:     AuthPassword,
			Password: "secret-pass",
		},
		PinnedHostKey: storedPin,
	})
	if !errors.As(err, &mapped) || mapped.Code != ERR_HOSTKEY_MISMATCH || mapped.Retryable {
		t.Fatalf("expected non-retryable ERR_HOSTKEY_MISMATCH, got %+v (%v)", mapped, err)
	}
	snap = engine.Snapshot()
	if snap.State != StateError || snap.HostKeyMismatch == nil {
		t.Fatalf("expected StateError with HostKeyMismatch, got %+v", snap)
	}
	wantNewFP := ssh.FingerprintSHA256(signerB.PublicKey())
	if snap.HostKeyMismatch.ExpectedSHA256 != wantFP || snap.HostKeyMismatch.ActualSHA256 != wantNewFP {
		t.Fatalf("mismatch fingerprints = (%s vs %s), want (%s vs %s)",
			snap.HostKeyMismatch.ExpectedSHA256, snap.HostKeyMismatch.ActualSHA256, wantFP, wantNewFP)
	}
	// Stored pin MUST NOT be silently overwritten.
	if storedPin.SHA256 != wantFP {
		t.Fatalf("storedPin mutated silently to %q", storedPin.SHA256)
	}
	if !strings.Contains(mapped.ActionHint, wantFP) || !strings.Contains(mapped.ActionHint, wantNewFP) {
		t.Fatalf("ActionHint %q should show both fingerprints", mapped.ActionHint)
	}

	// Step 4: Explicit ForgetHostKey (clearing pin) -> prompts untrusted for new key -> user trusts -> connects.
	storedPin = nil
	err = engine.Connect(ctx, ConnectConfig{
		ProfileID: "p1",
		Host:      srv.Host(),
		Port:      srv.Port(),
		Username:  "ali",
		Auth: AuthConfig{
			Type:     AuthPassword,
			Password: "secret-pass",
		},
		PinnedHostKey: storedPin,
	})
	if !errors.As(err, &mapped) || mapped.Code != ERR_HOSTKEY_UNTRUSTED {
		t.Fatalf("expected ERR_HOSTKEY_UNTRUSTED after forgetting pin, got %v", err)
	}
	snap = engine.Snapshot()
	storedPin = &HostKeyPin{
		Algorithm: snap.HostKeyPrompt.Algorithm,
		SHA256:    snap.HostKeyPrompt.SHA256,
	}
	if err := engine.Connect(ctx, ConnectConfig{
		ProfileID: "p1",
		Host:      srv.Host(),
		Port:      srv.Port(),
		Username:  "ali",
		Auth: AuthConfig{
			Type:     AuthPassword,
			Password: "secret-pass",
		},
		PinnedHostKey: storedPin,
	}); err != nil {
		t.Fatalf("connect after re-trusting rotated key failed: %v", err)
	}
	if err := engine.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}
}
