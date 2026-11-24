package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sampleEncryptedPayload() SharePayload {
	return SharePayload{
		Name:     "DE-443",
		Host:     "vps.example.com",
		Port:     443,
		User:     "friend",
		AuthType: "key",
		Secret: "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
			"b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0\n" +
			"-----END OPENSSH PRIVATE KEY-----",
		KeyPassphrase: "inner-key-passphrase",
		HostKey: &ShareHostKey{
			Alg:    "ssh-ed25519",
			SHA256: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
		},
	}
}

func samplePasswordPayload() SharePayload {
	return SharePayload{
		Name:     "NL-2053",
		Host:     "nl.example.org",
		Port:     2053,
		User:     "tunnel",
		AuthType: "password",
		Secret:   "super-secret-password",
	}
}

func decodeEnvelopeMap(t *testing.T, link string) map[string]any {
	t.Helper()
	if !strings.HasPrefix(link, ShareLinkPrefix) {
		t.Fatalf("link %q missing prefix %q", link, ShareLinkPrefix)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(link, ShareLinkPrefix))
	if err != nil {
		t.Fatalf("decode base64url: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return env
}

func encodeEnvelopeMap(t *testing.T, env map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return ShareLinkPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func flipSingleBitBase64URL(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64url field: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("cannot flip bit in empty byte slice")
	}
	raw[len(raw)/2] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestValidateArgon2Params(t *testing.T) {
	validCases := []Argon2Params{
		{T: DefaultArgon2T, M: DefaultArgon2M, C: DefaultArgon2C},
		{T: MinArgon2T, M: MinArgon2M, C: MinArgon2C},
		{T: MaxArgon2T, M: MaxArgon2M, C: MaxArgon2C},
	}
	for _, tc := range validCases {
		if err := ValidateArgon2Params(tc); err != nil {
			t.Fatalf("ValidateArgon2Params(%+v) unexpected error: %v", tc, err)
		}
	}

	invalidCases := []struct {
		name   string
		params Argon2Params
	}{
		{"t_below_min", Argon2Params{T: MinArgon2T - 1, M: DefaultArgon2M, C: DefaultArgon2C}},
		{"t_above_max", Argon2Params{T: MaxArgon2T + 1, M: DefaultArgon2M, C: DefaultArgon2C}},
		{"m_below_min", Argon2Params{T: DefaultArgon2T, M: MinArgon2M - 1, C: DefaultArgon2C}},
		{"m_above_max", Argon2Params{T: DefaultArgon2T, M: MaxArgon2M + 1, C: DefaultArgon2C}},
		{"c_below_min", Argon2Params{T: DefaultArgon2T, M: DefaultArgon2M, C: MinArgon2C - 1}},
		{"c_above_max", Argon2Params{T: DefaultArgon2T, M: DefaultArgon2M, C: MaxArgon2C + 1}},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateArgon2Params(tc.params)
			if !errors.Is(err, ErrKDFBoundsExceeded) {
				t.Fatalf("expected ErrKDFBoundsExceeded for %+v, got %v", tc.params, err)
			}
		})
	}
}

func TestDeriveKeyValidationAndDeterminism(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, SaltLen)
	params := Argon2Params{T: MinArgon2T, M: MinArgon2M, C: MinArgon2C}

	k1, err := DeriveKey("passphrase", salt, params)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if len(k1) != KeyLen {
		t.Fatalf("expected key length %d, got %d", KeyLen, len(k1))
	}

	k2, err := DeriveKey("passphrase", salt, params)
	if err != nil {
		t.Fatalf("DeriveKey repeat failed: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("expected deterministic key derivation for identical inputs")
	}

	k3, err := DeriveKey("different", salt, params)
	if err != nil {
		t.Fatalf("DeriveKey different passphrase failed: %v", err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("expected distinct key for different passphrase")
	}

	for _, badSaltLen := range []int{0, SaltLen - 1, SaltLen + 1} {
		if _, err := DeriveKey("passphrase", make([]byte, badSaltLen), params); err == nil {
			t.Fatalf("expected error for salt length %d", badSaltLen)
		}
	}

	start := time.Now()
	_, err = DeriveKey("passphrase", salt, Argon2Params{T: 1, M: 99999999, C: 1})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrKDFBoundsExceeded) {
		t.Fatalf("expected ErrKDFBoundsExceeded, got %v", err)
	}
	if elapsed >= 100*time.Millisecond {
		t.Fatalf("oversized KDF bounds check took %v, expected <100ms", elapsed)
	}
}

func TestSealAndOpenAESGCM(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, KeyLen)
	nonce := bytes.Repeat([]byte{0x22}, NonceLen)
	plaintext := []byte(`{"host":"vps.example.com"}`)
	aad := []byte("tunssh:share:v1:enc:t=3,m=65536,c=4")

	ct, err := SealAESGCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("SealAESGCM failed: %v", err)
	}

	got, err := OpenAESGCM(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("OpenAESGCM failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted mismatch: got %q, want %q", got, plaintext)
	}

	// Tampered ciphertext.
	badCT := append([]byte(nil), ct...)
	badCT[0] ^= 0x01
	if _, err := OpenAESGCM(key, nonce, badCT, aad); !errors.Is(err, ErrWrongPassphraseOrTampered) {
		t.Fatalf("expected ErrWrongPassphraseOrTampered on modified ciphertext, got %v", err)
	}

	// Modified AAD.
	if _, err := OpenAESGCM(key, nonce, ct, []byte("wrong-aad")); !errors.Is(err, ErrWrongPassphraseOrTampered) {
		t.Fatalf("expected ErrWrongPassphraseOrTampered on modified AAD, got %v", err)
	}

	// Wrong key/nonce lengths.
	if _, err := SealAESGCM(make([]byte, KeyLen-1), nonce, plaintext, aad); err == nil {
		t.Fatal("expected error for short key in SealAESGCM")
	}
	if _, err := SealAESGCM(key, make([]byte, NonceLen-1), plaintext, aad); err == nil {
		t.Fatal("expected error for short nonce in SealAESGCM")
	}
	if _, err := OpenAESGCM(make([]byte, KeyLen+1), nonce, ct, aad); err == nil {
		t.Fatal("expected error for long key in OpenAESGCM")
	}
	if _, err := OpenAESGCM(key, make([]byte, NonceLen+1), ct, aad); err == nil {
		t.Fatal("expected error for long nonce in OpenAESGCM")
	}
}

func TestRandomBytes(t *testing.T) {
	empty, err := RandomBytes(0)
	if err != nil || len(empty) != 0 {
		t.Fatalf("RandomBytes(0) = (%v, %v), want empty nil", empty, err)
	}
	if _, err := RandomBytes(-1); err == nil {
		t.Fatal("expected error for RandomBytes(-1)")
	}
	a, err := RandomBytes(SaltLen)
	if err != nil || len(a) != SaltLen {
		t.Fatalf("RandomBytes(%d) failed: %v", SaltLen, err)
	}
	b, err := RandomBytes(SaltLen)
	if err != nil || len(b) != SaltLen {
		t.Fatalf("RandomBytes(%d) failed: %v", SaltLen, err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("expected distinct random outputs")
	}
}

func TestEncryptedShareLinkRoundTrip(t *testing.T) {
	want := sampleEncryptedPayload()
	passphrase := "correct horse battery staple"

	link1, err := EncodeEncryptedShareLink(want, passphrase)
	if err != nil {
		t.Fatalf("EncodeEncryptedShareLink failed: %v", err)
	}
	if !strings.HasPrefix(link1, ShareLinkPrefix) {
		t.Fatalf("expected link prefix %q, got %q", ShareLinkPrefix, link1)
	}
	if strings.Contains(link1, "=") {
		t.Fatalf("expected unpadded base64url, got padding in %q", link1)
	}
	if strings.Contains(link1, want.Secret) || strings.Contains(link1, want.KeyPassphrase) {
		t.Fatal("encrypted share link leaked plaintext secrets")
	}

	link2, err := EncodeEncryptedShareLink(want, passphrase)
	if err != nil {
		t.Fatalf("second EncodeEncryptedShareLink failed: %v", err)
	}
	if link1 == link2 {
		t.Fatal("expected distinct salt/nonce on repeated encryption")
	}

	meta, err := InspectShareLink(link1)
	if err != nil {
		t.Fatalf("InspectShareLink failed: %v", err)
	}
	if meta.Version != 1 || meta.Mode != ModeEncrypted || meta.HasHostKey {
		t.Fatalf("unexpected meta for encrypted link: %+v", meta)
	}

	got, mode, err := DecodeShareLink(link1, DecodeOptions{Passphrase: passphrase})
	if err != nil {
		t.Fatalf("DecodeShareLink failed: %v", err)
	}
	if mode != ModeEncrypted {
		t.Fatalf("mode = %q, want %q", mode, ModeEncrypted)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip payload mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}

	// Verify envelope JSON shape uses exact default Argon2id parameters.
	env := decodeEnvelopeMap(t, link1)
	if env["v"] != float64(1) || env["m"] != ModeEncrypted || env["kdf"] != "argon2id" {
		t.Fatalf("unexpected envelope metadata: %+v", env)
	}
	pMap, ok := env["p"].(map[string]any)
	if !ok {
		t.Fatalf("expected p object in envelope, got %T", env["p"])
	}
	if pMap["t"] != float64(DefaultArgon2T) || pMap["m"] != float64(DefaultArgon2M) || pMap["c"] != float64(DefaultArgon2C) {
		t.Fatalf("unexpected KDF params in envelope: %+v", pMap)
	}
}

func TestEncryptedShareLinkWrongPassphraseAndSecretRedaction(t *testing.T) {
	payload := sampleEncryptedPayload()
	link, err := EncodeEncryptedShareLink(payload, "right-passphrase")
	if err != nil {
		t.Fatalf("EncodeEncryptedShareLink failed: %v", err)
	}

	for _, badPass := range []string{"wrong-passphrase", ""} {
		_, _, err := DecodeShareLink(link, DecodeOptions{Passphrase: badPass})
		if !errors.Is(err, ErrWrongPassphraseOrTampered) {
			t.Fatalf("passphrase=%q: expected ErrWrongPassphraseOrTampered, got %v", badPass, err)
		}
		if badPass != "" && strings.Contains(err.Error(), badPass) {
			t.Fatalf("error message leaked passphrase: %q", err.Error())
		}
		if strings.Contains(err.Error(), link) {
			t.Fatalf("error message leaked share link: %q", err.Error())
		}
	}

	if _, err := EncodeEncryptedShareLink(payload, ""); err == nil {
		t.Fatal("expected EncodeEncryptedShareLink to reject empty passphrase")
	}
}

func TestEncryptedShareLinkTamperingAndAADBinding(t *testing.T) {
	payload := sampleEncryptedPayload()
	passphrase := "tamper-test-passphrase"
	link, err := EncodeEncryptedShareLink(payload, passphrase)
	if err != nil {
		t.Fatalf("EncodeEncryptedShareLink failed: %v", err)
	}

	t.Run("mutate_ct_single_bit", func(t *testing.T) {
		env := decodeEnvelopeMap(t, link)
		env["ct"] = flipSingleBitBase64URL(t, env["ct"].(string))
		_, _, err := DecodeShareLink(encodeEnvelopeMap(t, env), DecodeOptions{Passphrase: passphrase})
		if !errors.Is(err, ErrWrongPassphraseOrTampered) {
			t.Fatalf("expected ErrWrongPassphraseOrTampered, got %v", err)
		}
	})

	t.Run("mutate_salt_single_bit", func(t *testing.T) {
		env := decodeEnvelopeMap(t, link)
		env["salt"] = flipSingleBitBase64URL(t, env["salt"].(string))
		_, _, err := DecodeShareLink(encodeEnvelopeMap(t, env), DecodeOptions{Passphrase: passphrase})
		if !errors.Is(err, ErrWrongPassphraseOrTampered) {
			t.Fatalf("expected ErrWrongPassphraseOrTampered, got %v", err)
		}
	})

	t.Run("mutate_nonce_single_bit", func(t *testing.T) {
		env := decodeEnvelopeMap(t, link)
		env["nonce"] = flipSingleBitBase64URL(t, env["nonce"].(string))
		_, _, err := DecodeShareLink(encodeEnvelopeMap(t, env), DecodeOptions{Passphrase: passphrase})
		if !errors.Is(err, ErrWrongPassphraseOrTampered) {
			t.Fatalf("expected ErrWrongPassphraseOrTampered, got %v", err)
		}
	})

	t.Run("mutate_kdf_t_in_bounds", func(t *testing.T) {
		env := decodeEnvelopeMap(t, link)
		pMap := env["p"].(map[string]any)
		pMap["t"] = float64(DefaultArgon2T ^ 1) // 3 -> 2 (single bit flip, still in bounds)
		_, _, err := DecodeShareLink(encodeEnvelopeMap(t, env), DecodeOptions{Passphrase: passphrase})
		if !errors.Is(err, ErrWrongPassphraseOrTampered) {
			t.Fatalf("expected ErrWrongPassphraseOrTampered, got %v", err)
		}
	})

	t.Run("mutate_kdf_m_in_bounds", func(t *testing.T) {
		env := decodeEnvelopeMap(t, link)
		pMap := env["p"].(map[string]any)
		pMap["m"] = float64(DefaultArgon2M ^ 1) // 65536 -> 65537 (single bit flip, still in bounds)
		_, _, err := DecodeShareLink(encodeEnvelopeMap(t, env), DecodeOptions{Passphrase: passphrase})
		if !errors.Is(err, ErrWrongPassphraseOrTampered) {
			t.Fatalf("expected ErrWrongPassphraseOrTampered, got %v", err)
		}
	})

	t.Run("mutate_kdf_c_in_bounds", func(t *testing.T) {
		env := decodeEnvelopeMap(t, link)
		pMap := env["p"].(map[string]any)
		pMap["c"] = float64(DefaultArgon2C ^ 1) // 4 -> 5 (single bit flip, still in bounds)
		_, _, err := DecodeShareLink(encodeEnvelopeMap(t, env), DecodeOptions{Passphrase: passphrase})
		if !errors.Is(err, ErrWrongPassphraseOrTampered) {
			t.Fatalf("expected ErrWrongPassphraseOrTampered, got %v", err)
		}
	})

	t.Run("aad_mismatch_even_if_same_key_used", func(t *testing.T) {
		// Directly test that sealing with one set of KDF params AAD and opening with another AAD fails.
		salt, err := RandomBytes(SaltLen)
		if err != nil {
			t.Fatalf("RandomBytes salt: %v", err)
		}
		nonce, err := RandomBytes(NonceLen)
		if err != nil {
			t.Fatalf("RandomBytes nonce: %v", err)
		}
		pOrig := Argon2Params{T: 1, M: MinArgon2M, C: 1}
		pTampered := Argon2Params{T: 2, M: MinArgon2M, C: 1}
		key, err := DeriveKey(passphrase, salt, pOrig)
		if err != nil {
			t.Fatalf("DeriveKey: %v", err)
		}
		plainBytes, _ := json.Marshal(payload)
		ct, err := SealAESGCM(key, nonce, plainBytes, []byte(fmt.Sprintf("tunssh:share:v1:enc:t=%d,m=%d,c=%d", pOrig.T, pOrig.M, pOrig.C)))
		if err != nil {
			t.Fatalf("SealAESGCM: %v", err)
		}
		if _, err := OpenAESGCM(key, nonce, ct, []byte(fmt.Sprintf("tunssh:share:v1:enc:t=%d,m=%d,c=%d", pTampered.T, pTampered.M, pTampered.C))); !errors.Is(err, ErrWrongPassphraseOrTampered) {
			t.Fatalf("expected AAD mismatch to fail with ErrWrongPassphraseOrTampered, got %v", err)
		}
	})

	t.Run("tamper_mode_enc_to_plain", func(t *testing.T) {
		env := decodeEnvelopeMap(t, link)
		env["m"] = ModePlain
		tampered := encodeEnvelopeMap(t, env)

		if _, err := InspectShareLink(tampered); !errors.Is(err, ErrInvalidShareLink) {
			t.Fatalf("InspectShareLink expected ErrInvalidShareLink, got %v", err)
		}
		for _, allowPlain := range []bool{false, true} {
			_, _, err := DecodeShareLink(tampered, DecodeOptions{
				Passphrase:       passphrase,
				AllowPlainImport: allowPlain,
			})
			if !errors.Is(err, ErrInvalidShareLink) {
				t.Fatalf("allowPlain=%v: expected ErrInvalidShareLink, got %v", allowPlain, err)
			}
		}
	})
}

func TestOversizedAndInvalidKDFBoundsRejectedBeforeArgon2(t *testing.T) {
	payload := samplePasswordPayload()
	link, err := EncodeEncryptedShareLink(payload, "pass")
	if err != nil {
		t.Fatalf("EncodeEncryptedShareLink failed: %v", err)
	}

	cases := []struct {
		name string
		t    float64
		m    float64
		c    float64
	}{
		{"m_above_max_boundary", 3, float64(MaxArgon2M + 1), 4},
		{"m_dos_99999999", 3, 99999999, 4},
		{"m_dos_above_uint32", 3, 9999999999, 4},
		{"m_below_min", 3, float64(MinArgon2M - 1), 4},
		{"m_zero", 3, 0, 4},
		{"t_above_max", float64(MaxArgon2T + 1), 65536, 4},
		{"t_below_min", float64(MinArgon2T - 1), 65536, 4},
		{"c_above_max", 3, 65536, float64(MaxArgon2C + 1)},
		{"c_below_min", 3, 65536, float64(MinArgon2C - 1)},
		{"c_uint8_wraparound_257", 3, 65536, 257},
		{"missing_p_c_field", 3, 65536, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := decodeEnvelopeMap(t, link)
			env["p"] = map[string]any{"t": tc.t, "m": tc.m, "c": tc.c}
			malicious := encodeEnvelopeMap(t, env)

			start := time.Now()
			_, err := InspectShareLink(malicious)
			if !errors.Is(err, ErrKDFBoundsExceeded) {
				t.Fatalf("InspectShareLink expected ErrKDFBoundsExceeded, got %v", err)
			}
			if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
				t.Fatalf("InspectShareLink took %v, expected <100ms", elapsed)
			}

			start = time.Now()
			_, _, err = DecodeShareLink(malicious, DecodeOptions{Passphrase: "pass"})
			if !errors.Is(err, ErrKDFBoundsExceeded) {
				t.Fatalf("DecodeShareLink expected ErrKDFBoundsExceeded, got %v", err)
			}
			if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
				t.Fatalf("DecodeShareLink took %v, expected <100ms", elapsed)
			}
		})
	}
}

func TestPlainShareLinkGating(t *testing.T) {
	withHostKey := sampleEncryptedPayload()
	withoutHostKey := samplePasswordPayload()

	if _, err := EncodePlainShareLink(withHostKey, false); !errors.Is(err, ErrPlainShareNotAllowed) {
		t.Fatalf("expected ErrPlainShareNotAllowed without confirmUnsafe, got %v", err)
	}

	linkWithHostKey, err := EncodePlainShareLink(withHostKey, true)
	if err != nil {
		t.Fatalf("EncodePlainShareLink failed: %v", err)
	}
	linkWithoutHostKey, err := EncodePlainShareLink(withoutHostKey, true)
	if err != nil {
		t.Fatalf("EncodePlainShareLink (no host key) failed: %v", err)
	}

	meta1, err := InspectShareLink(linkWithHostKey)
	if err != nil {
		t.Fatalf("InspectShareLink plain failed: %v", err)
	}
	if meta1.Version != 1 || meta1.Mode != ModePlain || !meta1.HasHostKey {
		t.Fatalf("unexpected meta for plain link with host key: %+v", meta1)
	}

	meta2, err := InspectShareLink(linkWithoutHostKey)
	if err != nil {
		t.Fatalf("InspectShareLink plain without host key failed: %v", err)
	}
	if meta2.Version != 1 || meta2.Mode != ModePlain || meta2.HasHostKey {
		t.Fatalf("unexpected meta for plain link without host key: %+v", meta2)
	}

	if _, _, err := DecodeShareLink(linkWithHostKey, DecodeOptions{}); !errors.Is(err, ErrPlainShareNotAllowed) {
		t.Fatalf("expected ErrPlainShareNotAllowed when AllowPlainImport is false, got %v", err)
	}

	got, mode, err := DecodeShareLink(linkWithHostKey, DecodeOptions{AllowPlainImport: true})
	if err != nil {
		t.Fatalf("DecodeShareLink with AllowPlainImport failed: %v", err)
	}
	if mode != ModePlain {
		t.Fatalf("mode = %q, want %q", mode, ModePlain)
	}
	if !reflect.DeepEqual(got, withHostKey) {
		t.Fatalf("plain round-trip mismatch:\ngot:  %+v\nwant: %+v", got, withHostKey)
	}
}

func TestShareLinkStrictValidationRejections(t *testing.T) {
	validEncLink, err := EncodeEncryptedShareLink(samplePasswordPayload(), "pass")
	if err != nil {
		t.Fatalf("EncodeEncryptedShareLink failed: %v", err)
	}
	validPlainLink, err := EncodePlainShareLink(samplePasswordPayload(), true)
	if err != nil {
		t.Fatalf("EncodePlainShareLink failed: %v", err)
	}

	t.Run("oversized_link", func(t *testing.T) {
		oversized := ShareLinkPrefix + strings.Repeat("A", MaxShareLinkBytes)
		if len(oversized) <= MaxShareLinkBytes {
			t.Fatal("test setup error: link not oversized")
		}
		if _, err := InspectShareLink(oversized); !errors.Is(err, ErrInvalidShareLink) {
			t.Fatalf("InspectShareLink expected ErrInvalidShareLink, got %v", err)
		}
		if _, _, err := DecodeShareLink(oversized, DecodeOptions{Passphrase: "pass", AllowPlainImport: true}); !errors.Is(err, ErrInvalidShareLink) {
			t.Fatalf("DecodeShareLink expected ErrInvalidShareLink, got %v", err)
		}
	})

	t.Run("wrong_prefix_and_bad_base64_and_bad_json", func(t *testing.T) {
		badLinks := []string{
			"",
			ShareLinkPrefix,
			"sshtun://v2/" + strings.TrimPrefix(validEncLink, ShareLinkPrefix),
			"https://example.com/" + strings.TrimPrefix(validEncLink, ShareLinkPrefix),
			" " + validEncLink,
			validEncLink + "=",
			ShareLinkPrefix + "not!valid!base64",
			ShareLinkPrefix + base64.RawURLEncoding.EncodeToString([]byte(`{not-json`)),
			ShareLinkPrefix + base64.RawURLEncoding.EncodeToString([]byte(`null`)),
			ShareLinkPrefix + base64.RawURLEncoding.EncodeToString([]byte(`[]`)),
			ShareLinkPrefix + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1}{"v":1}`)),
		}
		for _, bad := range badLinks {
			if _, err := InspectShareLink(bad); !errors.Is(err, ErrInvalidShareLink) {
				t.Fatalf("InspectShareLink(%q) expected ErrInvalidShareLink, got %v", bad, err)
			}
			if _, _, err := DecodeShareLink(bad, DecodeOptions{Passphrase: "pass", AllowPlainImport: true}); !errors.Is(err, ErrInvalidShareLink) {
				t.Fatalf("DecodeShareLink(%q) expected ErrInvalidShareLink, got %v", bad, err)
			}
		}
	})

	t.Run("version_mode_kdf_and_field_contamination", func(t *testing.T) {
		// v != 1
		env := decodeEnvelopeMap(t, validEncLink)
		env["v"] = 2
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		// v == 0
		env = decodeEnvelopeMap(t, validEncLink)
		env["v"] = 0
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		// unknown mode
		env = decodeEnvelopeMap(t, validEncLink)
		env["m"] = "unknown"
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		// kdf != argon2id
		env = decodeEnvelopeMap(t, validEncLink)
		env["kdf"] = "scrypt"
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		// unknown envelope field
		env = decodeEnvelopeMap(t, validEncLink)
		env["extra"] = "nope"
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		// enc envelope containing payload (object or null)
		env = decodeEnvelopeMap(t, validEncLink)
		env["payload"] = map[string]any{"host": "a", "port": 22, "user": "u", "auth_type": "password"}
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))
		env["payload"] = nil
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		// plain envelope containing enc-only fields (value or null)
		for _, key := range []string{"kdf", "salt", "p", "nonce", "ct"} {
			pEnv := decodeEnvelopeMap(t, validPlainLink)
			pEnv[key] = "bad"
			assertInvalidBoth(t, encodeEnvelopeMap(t, pEnv))

			pEnvNull := decodeEnvelopeMap(t, validPlainLink)
			pEnvNull[key] = nil
			assertInvalidBoth(t, encodeEnvelopeMap(t, pEnvNull))
		}
	})

	t.Run("wrong_salt_nonce_ct_lengths", func(t *testing.T) {
		env := decodeEnvelopeMap(t, validEncLink)
		env["salt"] = base64.RawURLEncoding.EncodeToString(make([]byte, SaltLen-1))
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		env = decodeEnvelopeMap(t, validEncLink)
		env["salt"] = base64.RawURLEncoding.EncodeToString(make([]byte, SaltLen+1))
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		env = decodeEnvelopeMap(t, validEncLink)
		env["nonce"] = base64.RawURLEncoding.EncodeToString(make([]byte, NonceLen-1))
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		env = decodeEnvelopeMap(t, validEncLink)
		env["nonce"] = base64.RawURLEncoding.EncodeToString(make([]byte, NonceLen+1))
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))

		env = decodeEnvelopeMap(t, validEncLink)
		env["ct"] = base64.RawURLEncoding.EncodeToString(make([]byte, 8))
		assertInvalidBoth(t, encodeEnvelopeMap(t, env))
	})

	t.Run("invalid_payload_fields", func(t *testing.T) {
		invalidPayloads := []SharePayload{
			{Host: "", Port: 443, User: "u", AuthType: "password"},
			{Host: "   ", Port: 443, User: "u", AuthType: "password"},
			{Host: "vps.example.com", Port: 0, User: "u", AuthType: "password"},
			{Host: "vps.example.com", Port: -1, User: "u", AuthType: "password"},
			{Host: "vps.example.com", Port: 65536, User: "u", AuthType: "password"},
			{Host: "vps.example.com", Port: 443, User: "", AuthType: "password"},
			{Host: "vps.example.com", Port: 443, User: "u", AuthType: ""},
			{Host: "vps.example.com", Port: 443, User: "u", AuthType: "password", HostKey: &ShareHostKey{Alg: "", SHA256: "SHA256:abc"}},
			{Host: "vps.example.com", Port: 443, User: "u", AuthType: "password", HostKey: &ShareHostKey{Alg: "ssh-ed25519", SHA256: ""}},
		}

		for _, p := range invalidPayloads {
			if _, err := EncodeEncryptedShareLink(p, "pass"); !errors.Is(err, ErrInvalidShareLink) {
				t.Fatalf("EncodeEncryptedShareLink(%+v) expected ErrInvalidShareLink, got %v", p, err)
			}
			if _, err := EncodePlainShareLink(p, true); !errors.Is(err, ErrInvalidShareLink) {
				t.Fatalf("EncodePlainShareLink(%+v) expected ErrInvalidShareLink, got %v", p, err)
			}

			// Craft raw plain link bypassing encoder checks to verify decoder/inspector reject too.
			plainEnv := map[string]any{"v": 1, "m": ModePlain, "payload": p}
			assertInvalidBoth(t, encodeEnvelopeMap(t, plainEnv))
		}
	})

	t.Run("invalid_decrypted_payload_inside_valid_aead", func(t *testing.T) {
		salt, err := RandomBytes(SaltLen)
		if err != nil {
			t.Fatalf("RandomBytes salt: %v", err)
		}
		nonce, err := RandomBytes(NonceLen)
		if err != nil {
			t.Fatalf("RandomBytes nonce: %v", err)
		}
		params := Argon2Params{T: MinArgon2T, M: MinArgon2M, C: MinArgon2C}
		key, err := DeriveKey("pass", salt, params)
		if err != nil {
			t.Fatalf("DeriveKey: %v", err)
		}

		for _, badPlain := range [][]byte{
			[]byte(`not-json`),
			[]byte(`{"host":"vps.example.com","port":0,"user":"u","auth_type":"password","secret":"s"}`),
		} {
			ct, err := SealAESGCM(key, nonce, badPlain, shareLinkAAD(params))
			if err != nil {
				t.Fatalf("SealAESGCM: %v", err)
			}
			link := encodeEnvelopeMap(t, map[string]any{
				"v":     1,
				"m":     ModeEncrypted,
				"kdf":   "argon2id",
				"salt":  base64.RawURLEncoding.EncodeToString(salt),
				"p":     map[string]any{"t": params.T, "m": params.M, "c": params.C},
				"nonce": base64.RawURLEncoding.EncodeToString(nonce),
				"ct":    base64.RawURLEncoding.EncodeToString(ct),
			})
			if _, _, err := DecodeShareLink(link, DecodeOptions{Passphrase: "pass"}); !errors.Is(err, ErrInvalidShareLink) {
				t.Fatalf("expected ErrInvalidShareLink for bad decrypted payload %q, got %v", badPlain, err)
			}
		}
	})

	t.Run("encode_rejects_oversized_payload", func(t *testing.T) {
		huge := samplePasswordPayload()
		huge.Secret = strings.Repeat("x", MaxShareLinkBytes)
		if _, err := EncodePlainShareLink(huge, true); !errors.Is(err, ErrInvalidShareLink) {
			t.Fatalf("EncodePlainShareLink expected ErrInvalidShareLink on oversized link, got %v", err)
		}
		if _, err := EncodeEncryptedShareLink(huge, "pass"); !errors.Is(err, ErrInvalidShareLink) {
			t.Fatalf("EncodeEncryptedShareLink expected ErrInvalidShareLink on oversized link, got %v", err)
		}
	})

	t.Run("utf8_payload_and_passphrase_roundtrip", func(t *testing.T) {
		want := SharePayload{
			Name:     "تهران-443",
			Host:     "vps.example.com",
			Port:     443,
			User:     "ali",
			AuthType: "password",
			Secret:   "رمز-عبور-قوی",
		}
		pass := "گذرواژه-۱۲۳"
		link, err := EncodeEncryptedShareLink(want, pass)
		if err != nil {
			t.Fatalf("EncodeEncryptedShareLink failed: %v", err)
		}
		got, mode, err := DecodeShareLink(link, DecodeOptions{Passphrase: pass})
		if err != nil {
			t.Fatalf("DecodeShareLink failed: %v", err)
		}
		if mode != ModeEncrypted || !reflect.DeepEqual(got, want) {
			t.Fatalf("UTF-8 roundtrip mismatch: mode=%q got=%+v want=%+v", mode, got, want)
		}
	})
}

func assertInvalidBoth(t *testing.T, link string) {
	t.Helper()
	if _, err := InspectShareLink(link); !errors.Is(err, ErrInvalidShareLink) {
		t.Fatalf("InspectShareLink expected ErrInvalidShareLink for %q, got %v", link, err)
	}
	if _, _, err := DecodeShareLink(link, DecodeOptions{Passphrase: "pass", AllowPlainImport: true}); !errors.Is(err, ErrInvalidShareLink) {
		t.Fatalf("DecodeShareLink expected ErrInvalidShareLink for %q, got %v", link, err)
	}
}
