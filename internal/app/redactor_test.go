package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type testStringer struct {
	val string
}

func (s testStringer) String() string {
	return s.val
}

type testLogValuer struct {
	secret string
}

func (v testLogValuer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("nested", "valuer:"+v.secret),
		slog.String("token", "tok-from-valuer"),
	)
}

func TestSecretScrubber_LongestFirstAndEmptyGuard(t *testing.T) {
	scrubber := NewSecretScrubber()
	// Include empty string "", duplicates, and overlapping prefix/substring secrets.
	scrubber.SetSecrets([]string{
		"",
		"secret",
		"extended",
		"pass",
		"secret-extended-pass",
		"secret",
		"REDACT",
	})

	input := "prefix secret-extended-pass mid secret extended REDACT suffix"
	got := scrubber.Scrub(input)
	want := "prefix [REDACTED] mid [REDACTED] [REDACTED] [REDACTED] suffix"
	if got != want {
		t.Fatalf("Scrub() = %q, want %q", got, want)
	}

	// Empty-string secret guard: normal text must not be corrupted with [REDACTED] between characters.
	clean := "hello world 123"
	if gotClean := scrubber.Scrub(clean); gotClean != clean {
		t.Fatalf("Scrub(%q) = %q, want unchanged", clean, gotClean)
	}

	// Zero-value SecretScrubber must safely scrub regex patterns without panicking.
	var zeroScrubber SecretScrubber
	gotZero := zeroScrubber.Scrub("url sshtun://v1/SecretToken123 done")
	if strings.Contains(gotZero, "SecretToken123") || !strings.Contains(gotZero, "[REDACTED]") {
		t.Fatalf("zero-value Scrub() failed: %q", gotZero)
	}
}

func TestSecretScrubber_ShareLinksAndPEMBlocks(t *testing.T) {
	scrubber := NewSecretScrubber()
	scrubber.UpdateFromSecretMap("", "key-pass-999")

	pemKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\nline2secret\n-----END OPENSSH PRIVATE KEY-----"
	rsaKey := "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEAtest\r\n-----END RSA PRIVATE KEY-----"

	input := fmt.Sprintf(
		"share=%q link2=sshtun://v1/SecretToken123 key1=%s key2=%s pass=key-pass-999",
		"sshtun://v1/AnotherSecretTail",
		pemKey,
		rsaKey,
	)

	got := scrubber.Scrub(input)
	for _, forbidden := range []string{
		"SecretToken123",
		"AnotherSecretTail",
		"sshtun://",
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=",
		"MIIEowIBAAKCAQEAtest",
		"BEGIN OPENSSH PRIVATE KEY",
		"BEGIN RSA PRIVATE KEY",
		"key-pass-999",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("Scrub() leaked %q in %q", forbidden, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("Scrub() missing [REDACTED] placeholder in %q", got)
	}
}

func TestSecretScrubber_ConcurrentSetAndScrub(t *testing.T) {
	scrubber := NewSecretScrubber()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				scrubber.SetSecrets([]string{"", fmt.Sprintf("pw-%d-%d", id, j), "pw"})
				out := scrubber.Scrub(fmt.Sprintf("pw-%d-%d sshtun://v1/SecretToken123", id, j))
				if strings.Contains(out, "SecretToken123") {
					t.Errorf("concurrent scrub leaked share link: %q", out)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestLogBuffer_RingCapClearAndExportText(t *testing.T) {
	buf := NewLogBuffer(0) // defaults to 500
	if got := buf.Entries(); got == nil || len(got) != 0 {
		t.Fatalf("initial Entries() = %#v, want non-nil empty slice", got)
	}

	for i := 0; i < 600; i++ {
		buf.Add(LogEntryDTO{
			Timestamp:  time.Unix(int64(1700000000+i), 0).UTC().Format(time.RFC3339),
			Level:      "INFO",
			Message:    fmt.Sprintf("entry-%03d", i),
			Code:       "CODE_1",
			ActionHint: "hint text",
		})
	}

	entries := buf.Entries()
	if len(entries) != 500 {
		t.Fatalf("len(Entries()) = %d, want 500", len(entries))
	}
	if entries[0].Message != "entry-100" || entries[499].Message != "entry-599" {
		t.Fatalf("ring buffer range = [%s .. %s], want [entry-100 .. entry-599]", entries[0].Message, entries[499].Message)
	}

	// Mutating returned slice must not mutate internal ring buffer.
	entries[0].Message = "mutated"
	if check := buf.Entries(); check[0].Message != "entry-100" {
		t.Fatalf("buffer mutated externally: %q", check[0].Message)
	}

	text := buf.ExportText()
	if !strings.Contains(text, "entry-100") || !strings.Contains(text, "CODE_1") || !strings.Contains(text, "Hint: hint text") {
		t.Fatalf("ExportText() unexpected: %q", text)
	}
	if strings.Contains(text, "entry-099") {
		t.Fatalf("ExportText() retained evicted entry-099")
	}

	buf.Clear()
	if got := buf.Entries(); len(got) != 0 {
		t.Fatalf("after Clear(), len(Entries()) = %d, want 0", len(got))
	}
	if got := buf.ExportText(); got != "" {
		t.Fatalf("after Clear(), ExportText() = %q, want empty", got)
	}
}

func TestRedactingHandler_ScrubsMessagesGroupsAttrsErrorsAndKeys(t *testing.T) {
	rawPassword := "S3cr3t!Pass#2026"
	rawKeyPass := "KeyPass!9876"
	rawPEM := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\nSensitiveKeyMaterialLine\n-----END OPENSSH PRIVATE KEY-----"
	rawShareLink := "sshtun://v1/SecretToken123"

	scrubber := NewSecretScrubber()
	// Deliberately include empty string "" to prove empty-string guard works.
	scrubber.SetSecrets([]string{"", rawPassword, rawKeyPass, rawPEM})

	buf := NewLogBuffer(DefaultLogBufferCapacity)
	var downstreamBuf bytes.Buffer
	downstream := slog.NewTextHandler(&downstreamBuf, &slog.HandlerOptions{Level: slog.LevelDebug})

	var mu sync.Mutex
	var emitted []LogEntryDTO
	handler := NewRedactingHandler(downstream, scrubber, buf, func(entry LogEntryDTO) {
		mu.Lock()
		emitted = append(emitted, entry)
		mu.Unlock()
	})

	// Test pre-bound attrs BEFORE updating secrets, plus WithGroup("").
	preLogger := slog.New(handler).
		WithGroup("").
		With("pre_secret", "DynamicAddedSecret", "token", "unregistered-bearer-token").
		WithGroup("session")
	scrubber.SetSecrets([]string{"", rawPassword, rawKeyPass, rawPEM, "DynamicAddedSecret"})

	wrappedErr := fmt.Errorf("ssh dial failed: %w", errors.Join(
		fmt.Errorf("bad password %s", rawPassword),
		fmt.Errorf("decrypt key with %s failed: %s", rawKeyPass, rawPEM),
		fmt.Errorf("share import %s failed", rawShareLink),
	))

	preLogger.Error(
		fmt.Sprintf("connect failed password=%s link=%s", rawPassword, rawShareLink),
		slog.String("code", "ERR_AUTH_FAILED"),
		slog.String("action_hint", "Check password "+rawPassword+" or key "+rawKeyPass),
		slog.Any("err", wrappedErr),
		slog.Any("stringer", testStringer{val: "str:" + rawShareLink}),
		slog.Any("valuer", testLogValuer{secret: rawPassword}),
		slog.String("PASSWORD", "unregistered-key-case-insensitive"),
		slog.String("secret", "unregistered-secret-val"),
		slog.String("private_key", "unregistered-pk-val"),
		slog.String("passphrase", "unregistered-pp-val"),
		slog.String("key_passphrase", "unregistered-kpp-val"),
		slog.String("share_link", "unregistered-share-val"),
		slog.Group("outer",
			slog.String("note", "ok"),
			slog.Group("inner",
				slog.String("payload", "pem="+rawPEM+" link="+rawShareLink),
				slog.Any("inner_err", fmt.Errorf("inner %s", rawKeyPass)),
			),
		),
	)

	// Sensitive group name must also redact contained attributes.
	slog.New(handler).WithGroup("password").Warn("sensitive group log", "raw", "unregistered-inside-password-group")

	entries := buf.Entries()
	if len(entries) != 2 {
		t.Fatalf("len(LogBuffer.Entries()) = %d, want 2", len(entries))
	}

	mu.Lock()
	emittedCount := len(emitted)
	mu.Unlock()
	if emittedCount != 2 {
		t.Fatalf("onLog callback count = %d, want 2", emittedCount)
	}

	first := entries[0]
	if first.Level != "ERROR" {
		t.Fatalf("first.Level = %q, want ERROR", first.Level)
	}
	if first.Code != "ERR_AUTH_FAILED" {
		t.Fatalf("first.Code = %q, want ERR_AUTH_FAILED", first.Code)
	}
	if !strings.Contains(first.ActionHint, "[REDACTED]") {
		t.Fatalf("first.ActionHint = %q, expected [REDACTED]", first.ActionHint)
	}

	combinedOutputs := []string{
		downstreamBuf.String(),
		buf.ExportText(),
		first.Message,
		first.ActionHint,
	}

	forbiddenSubstrings := []string{
		rawPassword,
		rawKeyPass,
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=",
		"SensitiveKeyMaterialLine",
		rawShareLink,
		"/SecretToken123",
		"SecretToken123",
		"DynamicAddedSecret",
		"unregistered-bearer-token",
		"tok-from-valuer",
		"unregistered-key-case-insensitive",
		"unregistered-secret-val",
		"unregistered-pk-val",
		"unregistered-pp-val",
		"unregistered-kpp-val",
		"unregistered-share-val",
		"unregistered-inside-password-group",
	}

	for _, out := range combinedOutputs {
		if !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in output: %q", out)
		}
		for _, forbidden := range forbiddenSubstrings {
			if strings.Contains(out, forbidden) {
				t.Fatalf("output leaked forbidden secret %q in:\n%s", forbidden, out)
			}
		}
	}

	// Ensure empty string guard didn't corrupt normal text.
	if !strings.Contains(downstreamBuf.String(), "outer.inner") || !strings.Contains(downstreamBuf.String(), "note=ok") {
		t.Fatalf("downstream text handler output corrupted or missing expected fields:\n%s", downstreamBuf.String())
	}

	// Verify Enabled honors downstream handler level.
	warnOnly := NewRedactingHandler(
		slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn}),
		scrubber,
		NewLogBuffer(10),
		nil,
	)
	if warnOnly.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatalf("Enabled(INFO) = true on WARN downstream handler, want false")
	}
	if !warnOnly.Enabled(context.Background(), slog.LevelError) {
		t.Fatalf("Enabled(ERROR) = false on WARN downstream handler, want true")
	}
}
