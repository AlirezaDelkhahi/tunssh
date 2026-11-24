package sshclient

import (
	"fmt"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

// AuthType selects the SSH user authentication strategy.
type AuthType string

const (
	// AuthPassword enables both SSH password and PAM keyboard-interactive methods.
	AuthPassword AuthType = "password"
	// AuthKey authenticates using an OpenSSH/PEM/PKCS#8 private key.
	AuthKey AuthType = "key"
)

const maxKbdInteractiveRounds int32 = 3

// AuthConfig holds SSH authentication inputs for a connection attempt.
type AuthConfig struct {
	Type          AuthType
	Password      string
	PrivateKey    string
	KeyPassphrase string
}

// BuildAuthMethods validates auth configuration upfront (prior to TCP dialing)
// and builds the ordered slice of ssh.AuthMethod values for a single dial attempt.
func BuildAuthMethods(cfg AuthConfig) ([]ssh.AuthMethod, error) {
	switch cfg.Type {
	case AuthPassword:
		return buildPasswordAuthMethods(cfg.Password), nil
	case AuthKey:
		return buildKeyAuthMethods(cfg.PrivateKey, cfg.KeyPassphrase)
	default:
		return nil, fmt.Errorf("%w: unsupported auth type %q", ErrAuthFailed, cfg.Type)
	}
}

func buildPasswordAuthMethods(password string) []ssh.AuthMethod {
	rounds := &atomic.Int32{}

	passwordMethod := ssh.PasswordCallback(func() (string, error) {
		return password, nil
	})

	kbdMethod := ssh.KeyboardInteractive(func(_, _ string, questions []string, echos []bool) ([]string, error) {
		if rounds.Add(1) > maxKbdInteractiveRounds {
			return nil, fmt.Errorf("%w: exceeded %d keyboard-interactive rounds", ErrAuthFailed, maxKbdInteractiveRounds)
		}
		if len(questions) == 0 {
			return []string{}, nil
		}

		answers := make([]string, len(questions))
		for i, q := range questions {
			echo := i < len(echos) && echos[i]
			lower := strings.ToLower(q)
			if !echo || strings.Contains(lower, "password") || strings.Contains(lower, "passcode") {
				answers[i] = password
			}
		}
		return answers, nil
	})

	return []ssh.AuthMethod{passwordMethod, kbdMethod}
}

func buildKeyAuthMethods(privateKey, passphrase string) ([]ssh.AuthMethod, error) {
	if strings.TrimSpace(privateKey) == "" {
		return nil, &ErrKeyInvalid{Reason: "private key is empty"}
	}
	if strings.Contains(privateKey, "PuTTY-User-Key-File") {
		return nil, &ErrKeyInvalid{
			Reason: "PuTTY .ppk private keys are not supported; export key in OpenSSH PEM format",
		}
	}

	raw := []byte(privateKey)
	var (
		signer ssh.Signer
		err    error
	)
	if passphrase == "" {
		signer, err = ssh.ParsePrivateKey(raw)
		if err != nil {
			return nil, &ErrKeyInvalid{
				Reason: "unable to parse private key",
				Cause:  err,
			}
		}
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(raw, []byte(passphrase))
		if err != nil {
			return nil, &ErrKeyInvalid{
				Reason: "unable to decrypt or parse private key",
				Cause:  err,
			}
		}
	}

	return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
}
