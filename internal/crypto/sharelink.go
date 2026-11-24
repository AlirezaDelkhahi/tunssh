package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

const (
	// ShareLinkPrefix is the mandatory URI prefix for v1 share links.
	ShareLinkPrefix = "sshtun://v1/"
	// MaxShareLinkBytes limits the total encoded share-link size to 64 KiB.
	MaxShareLinkBytes = 64 * 1024
	// ModeEncrypted identifies Argon2id + AES-256-GCM encrypted share links.
	ModeEncrypted = "enc"
	// ModePlain identifies unencrypted share links requiring explicit user confirmation.
	ModePlain = "plain"

	shareLinkVersion = 1
	shareLinkKDF     = "argon2id"
	aesGCMTagLen     = 16
	maxTCPPort       = 65535
)

var (
	// ErrInvalidShareLink is returned when a share link fails structural or field validation.
	ErrInvalidShareLink = errors.New("crypto: invalid share link")
	// ErrPlainShareNotAllowed is returned when plain-mode encoding or decoding lacks explicit opt-in.
	ErrPlainShareNotAllowed = errors.New("crypto: plain share link requires explicit confirmation")
)

// ShareHostKey represents an optional pinned SSH host-key fingerprint inside a share payload.
type ShareHostKey struct {
	Alg    string `json:"alg"`
	SHA256 string `json:"sha256"`
}

// SharePayload contains the profile metadata and credentials carried by a share link.
type SharePayload struct {
	Name          string        `json:"name"`
	Host          string        `json:"host"`
	Port          int           `json:"port"`
	User          string        `json:"user"`
	AuthType      string        `json:"auth_type"`
	Secret        string        `json:"secret"`
	KeyPassphrase string        `json:"key_passphrase,omitempty"`
	HostKey       *ShareHostKey `json:"host_key,omitempty"`
}

// ShareLinkMeta describes unencrypted envelope metadata discovered prior to import.
type ShareLinkMeta struct {
	Version    int    `json:"version"`
	Mode       string `json:"mode"`
	HasHostKey bool   `json:"has_host_key"`
}

// DecodeOptions configures share-link decryption and unencrypted import policy.
type DecodeOptions struct {
	Passphrase       string
	AllowPlainImport bool
}

type encryptedShareEnvelope struct {
	V     int          `json:"v"`
	M     string       `json:"m"`
	KDF   string       `json:"kdf"`
	Salt  string       `json:"salt"`
	P     Argon2Params `json:"p"`
	Nonce string       `json:"nonce"`
	CT    string       `json:"ct"`
}

type plainShareEnvelope struct {
	V       int          `json:"v"`
	M       string       `json:"m"`
	Payload SharePayload `json:"payload"`
}

type rawShareEnvelope struct {
	V       *int            `json:"v"`
	M       *string         `json:"m"`
	KDF     json.RawMessage `json:"kdf"`
	Salt    json.RawMessage `json:"salt"`
	P       json.RawMessage `json:"p"`
	Nonce   json.RawMessage `json:"nonce"`
	CT      json.RawMessage `json:"ct"`
	Payload json.RawMessage `json:"payload"`
}

type rawArgon2Params struct {
	T int64 `json:"t"`
	M int64 `json:"m"`
	C int64 `json:"c"`
}

type parsedShareEnvelope struct {
	mode    string
	params  Argon2Params
	salt    []byte
	nonce   []byte
	ct      []byte
	payload SharePayload
}

func shareLinkAAD(p Argon2Params) []byte {
	return []byte(fmt.Sprintf("tunssh:share:v1:enc:t=%d,m=%d,c=%d", p.T, p.M, p.C))
}

func validateSharePayload(p SharePayload) error {
	if strings.TrimSpace(p.Host) == "" {
		return fmt.Errorf("%w: host must not be empty", ErrInvalidShareLink)
	}
	if p.Port < 1 || p.Port > maxTCPPort {
		return fmt.Errorf("%w: port %d outside [1,%d]", ErrInvalidShareLink, p.Port, maxTCPPort)
	}
	if strings.TrimSpace(p.User) == "" {
		return fmt.Errorf("%w: user must not be empty", ErrInvalidShareLink)
	}
	if strings.TrimSpace(p.AuthType) == "" {
		return fmt.Errorf("%w: auth_type must not be empty", ErrInvalidShareLink)
	}
	if p.HostKey != nil {
		if strings.TrimSpace(p.HostKey.Alg) == "" || strings.TrimSpace(p.HostKey.SHA256) == "" {
			return fmt.Errorf("%w: host_key alg and sha256 must be non-empty", ErrInvalidShareLink)
		}
	}
	return nil
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

func hasRawField(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func decodeBase64Field(raw json.RawMessage, exactLen int) ([]byte, error) {
	if !hasRawField(raw) {
		return nil, fmt.Errorf("%w: missing required field", ErrInvalidShareLink)
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("%w: invalid string field", ErrInvalidShareLink)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64url field", ErrInvalidShareLink)
	}
	if exactLen >= 0 && len(decoded) != exactLen {
		return nil, fmt.Errorf("%w: decoded length %d, want %d", ErrInvalidShareLink, len(decoded), exactLen)
	}
	return decoded, nil
}

func parseRawArgon2Params(raw json.RawMessage) (Argon2Params, error) {
	if !hasRawField(raw) {
		return Argon2Params{}, fmt.Errorf("%w: missing kdf params", ErrInvalidShareLink)
	}
	var rp rawArgon2Params
	if err := decodeStrictJSONObject(raw, &rp); err != nil {
		return Argon2Params{}, fmt.Errorf("%w: invalid kdf params", ErrInvalidShareLink)
	}
	if rp.T < 0 || rp.T > math.MaxUint32 ||
		rp.M < 0 || rp.M > math.MaxUint32 ||
		rp.C < 0 || rp.C > math.MaxUint8 {
		return Argon2Params{}, fmt.Errorf("%w: t=%d m=%d c=%d", ErrKDFBoundsExceeded, rp.T, rp.M, rp.C)
	}
	params := Argon2Params{
		T: uint32(rp.T),
		M: uint32(rp.M),
		C: uint8(rp.C),
	}
	if err := ValidateArgon2Params(params); err != nil {
		return Argon2Params{}, err
	}
	return params, nil
}

func parseEncryptedEnvelope(rawEnv rawShareEnvelope) (parsedShareEnvelope, error) {
	if len(rawEnv.Payload) > 0 {
		return parsedShareEnvelope{}, fmt.Errorf("%w: encrypted envelope must not contain payload", ErrInvalidShareLink)
	}
	if !hasRawField(rawEnv.KDF) {
		return parsedShareEnvelope{}, fmt.Errorf("%w: missing kdf", ErrInvalidShareLink)
	}
	var kdf string
	if err := json.Unmarshal(rawEnv.KDF, &kdf); err != nil || kdf != shareLinkKDF {
		return parsedShareEnvelope{}, fmt.Errorf("%w: unsupported kdf", ErrInvalidShareLink)
	}

	params, err := parseRawArgon2Params(rawEnv.P)
	if err != nil {
		return parsedShareEnvelope{}, err
	}
	salt, err := decodeBase64Field(rawEnv.Salt, SaltLen)
	if err != nil {
		return parsedShareEnvelope{}, err
	}
	nonce, err := decodeBase64Field(rawEnv.Nonce, NonceLen)
	if err != nil {
		return parsedShareEnvelope{}, err
	}
	ct, err := decodeBase64Field(rawEnv.CT, -1)
	if err != nil {
		return parsedShareEnvelope{}, err
	}
	if len(ct) < aesGCMTagLen {
		return parsedShareEnvelope{}, fmt.Errorf("%w: ciphertext shorter than authentication tag", ErrInvalidShareLink)
	}

	return parsedShareEnvelope{
		mode:   ModeEncrypted,
		params: params,
		salt:   salt,
		nonce:  nonce,
		ct:     ct,
	}, nil
}

func parsePlainEnvelope(rawEnv rawShareEnvelope) (parsedShareEnvelope, error) {
	if len(rawEnv.KDF) > 0 || len(rawEnv.Salt) > 0 || len(rawEnv.P) > 0 ||
		len(rawEnv.Nonce) > 0 || len(rawEnv.CT) > 0 {
		return parsedShareEnvelope{}, fmt.Errorf("%w: plain envelope must not contain encryption fields", ErrInvalidShareLink)
	}
	if !hasRawField(rawEnv.Payload) {
		return parsedShareEnvelope{}, fmt.Errorf("%w: missing payload", ErrInvalidShareLink)
	}

	var payload SharePayload
	if err := decodeStrictJSONObject(rawEnv.Payload, &payload); err != nil {
		return parsedShareEnvelope{}, fmt.Errorf("%w: invalid payload JSON", ErrInvalidShareLink)
	}
	if err := validateSharePayload(payload); err != nil {
		return parsedShareEnvelope{}, err
	}

	return parsedShareEnvelope{
		mode:    ModePlain,
		payload: payload,
	}, nil
}

func parseShareEnvelope(link string) (parsedShareEnvelope, error) {
	if len(link) > MaxShareLinkBytes {
		return parsedShareEnvelope{}, fmt.Errorf("%w: exceeds max size %d bytes", ErrInvalidShareLink, MaxShareLinkBytes)
	}
	if !strings.HasPrefix(link, ShareLinkPrefix) {
		return parsedShareEnvelope{}, fmt.Errorf("%w: invalid prefix", ErrInvalidShareLink)
	}
	encoded := strings.TrimPrefix(link, ShareLinkPrefix)
	if encoded == "" {
		return parsedShareEnvelope{}, fmt.Errorf("%w: empty link payload", ErrInvalidShareLink)
	}

	rawJSON, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return parsedShareEnvelope{}, fmt.Errorf("%w: invalid base64url envelope", ErrInvalidShareLink)
	}

	var rawEnv rawShareEnvelope
	if err := decodeStrictJSONObject(rawJSON, &rawEnv); err != nil {
		return parsedShareEnvelope{}, fmt.Errorf("%w: invalid envelope JSON", ErrInvalidShareLink)
	}
	if rawEnv.V == nil || *rawEnv.V != shareLinkVersion {
		return parsedShareEnvelope{}, fmt.Errorf("%w: unsupported version", ErrInvalidShareLink)
	}
	if rawEnv.M == nil {
		return parsedShareEnvelope{}, fmt.Errorf("%w: missing mode", ErrInvalidShareLink)
	}

	switch *rawEnv.M {
	case ModeEncrypted:
		return parseEncryptedEnvelope(rawEnv)
	case ModePlain:
		return parsePlainEnvelope(rawEnv)
	default:
		return parsedShareEnvelope{}, fmt.Errorf("%w: unknown mode", ErrInvalidShareLink)
	}
}

func marshalShareLink(envelope any) (string, error) {
	rawJSON, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("crypto: marshal share envelope: %w", err)
	}
	defer clear(rawJSON)

	link := ShareLinkPrefix + base64.RawURLEncoding.EncodeToString(rawJSON)
	if len(link) > MaxShareLinkBytes {
		return "", fmt.Errorf("%w: encoded link exceeds %d bytes", ErrInvalidShareLink, MaxShareLinkBytes)
	}
	return link, nil
}

// InspectShareLink validates the outer share-link envelope and returns unencrypted metadata.
func InspectShareLink(link string) (ShareLinkMeta, error) {
	env, err := parseShareEnvelope(link)
	if err != nil {
		return ShareLinkMeta{}, err
	}
	return ShareLinkMeta{
		Version:    shareLinkVersion,
		Mode:       env.mode,
		HasHostKey: env.mode == ModePlain && env.payload.HostKey != nil,
	}, nil
}

// EncodeEncryptedShareLink encrypts payload with Argon2id + AES-256-GCM into an sshtun://v1/ link.
func EncodeEncryptedShareLink(payload SharePayload, passphrase string) (string, error) {
	if passphrase == "" {
		return "", errors.New("crypto: passphrase must not be empty")
	}
	if err := validateSharePayload(payload); err != nil {
		return "", err
	}

	plainJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("crypto: marshal payload: %w", err)
	}
	defer clear(plainJSON)

	salt, err := RandomBytes(SaltLen)
	if err != nil {
		return "", err
	}
	nonce, err := RandomBytes(NonceLen)
	if err != nil {
		return "", err
	}

	params := Argon2Params{
		T: DefaultArgon2T,
		M: DefaultArgon2M,
		C: DefaultArgon2C,
	}
	key, err := DeriveKey(passphrase, salt, params)
	if err != nil {
		return "", err
	}
	defer clear(key)

	ct, err := SealAESGCM(key, nonce, plainJSON, shareLinkAAD(params))
	if err != nil {
		return "", err
	}

	return marshalShareLink(encryptedShareEnvelope{
		V:     shareLinkVersion,
		M:     ModeEncrypted,
		KDF:   shareLinkKDF,
		Salt:  base64.RawURLEncoding.EncodeToString(salt),
		P:     params,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		CT:    base64.RawURLEncoding.EncodeToString(ct),
	})
}

// EncodePlainShareLink encodes payload as an unencrypted sshtun://v1/ link only when confirmUnsafe is true.
func EncodePlainShareLink(payload SharePayload, confirmUnsafe bool) (string, error) {
	if !confirmUnsafe {
		return "", ErrPlainShareNotAllowed
	}
	if err := validateSharePayload(payload); err != nil {
		return "", err
	}

	return marshalShareLink(plainShareEnvelope{
		V:       shareLinkVersion,
		M:       ModePlain,
		Payload: payload,
	})
}

// DecodeShareLink parses, validates, and optionally decrypts an sshtun://v1/ share link.
func DecodeShareLink(link string, opts DecodeOptions) (SharePayload, string, error) {
	env, err := parseShareEnvelope(link)
	if err != nil {
		return SharePayload{}, "", err
	}

	if env.mode == ModePlain {
		if !opts.AllowPlainImport {
			return SharePayload{}, "", ErrPlainShareNotAllowed
		}
		return env.payload, ModePlain, nil
	}

	if opts.Passphrase == "" {
		return SharePayload{}, "", fmt.Errorf("%w: empty passphrase", ErrWrongPassphraseOrTampered)
	}

	key, err := DeriveKey(opts.Passphrase, env.salt, env.params)
	if err != nil {
		return SharePayload{}, "", err
	}
	defer clear(key)

	plaintext, err := OpenAESGCM(key, env.nonce, env.ct, shareLinkAAD(env.params))
	if err != nil {
		return SharePayload{}, "", err
	}
	defer clear(plaintext)

	var payload SharePayload
	if err := decodeStrictJSONObject(plaintext, &payload); err != nil {
		return SharePayload{}, "", fmt.Errorf("%w: invalid decrypted payload", ErrInvalidShareLink)
	}
	if err := validateSharePayload(payload); err != nil {
		return SharePayload{}, "", err
	}

	return payload, ModeEncrypted, nil
}
