package mobile

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultLogBufferCapacity = 500
	redactedPlaceholder      = "[REDACTED]"
)

var (
	shareLinkRe     = regexp.MustCompile(`sshtun://[^\s"'<>]+`)
	pemPrivateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

type secretScrubber struct {
	writeMu  sync.Mutex
	secrets  atomic.Pointer[[]string]
	replacer atomic.Pointer[strings.Replacer]
}

func newSecretScrubber() *secretScrubber {
	s := &secretScrubber{}
	empty := make([]string, 0)
	s.secrets.Store(&empty)
	return s
}

func (s *secretScrubber) setSecrets(secrets []string) {
	if s == nil {
		return
	}
	seen := make(map[string]struct{}, len(secrets))
	cleaned := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		if _, exists := seen[secret]; exists {
			continue
		}
		seen[secret] = struct{}{}
		cleaned = append(cleaned, secret)
	}

	sort.Slice(cleaned, func(i, j int) bool {
		if len(cleaned[i]) != len(cleaned[j]) {
			return len(cleaned[i]) > len(cleaned[j])
		}
		return cleaned[i] < cleaned[j]
	})

	var rep *strings.Replacer
	if len(cleaned) > 0 {
		pairs := make([]string, 0, len(cleaned)*2)
		for _, secret := range cleaned {
			pairs = append(pairs, secret, redactedPlaceholder)
		}
		rep = strings.NewReplacer(pairs...)
	}

	s.writeMu.Lock()
	s.secrets.Store(&cleaned)
	s.replacer.Store(rep)
	s.writeMu.Unlock()
}

func (s *secretScrubber) scrub(input string) string {
	if input == "" {
		return ""
	}
	out := input
	if s != nil {
		if rep := s.replacer.Load(); rep != nil {
			out = rep.Replace(out)
		} else if listPtr := s.secrets.Load(); listPtr != nil {
			for _, secret := range *listPtr {
				if secret != "" {
					out = strings.ReplaceAll(out, secret, redactedPlaceholder)
				}
			}
		}
	}
	out = pemPrivateKeyRe.ReplaceAllString(out, redactedPlaceholder)
	out = shareLinkRe.ReplaceAllString(out, redactedPlaceholder)
	return out
}

type logBuffer struct {
	mu      sync.Mutex
	entries []logEntryDTO
	head    int
	count   int
	cap     int
}

func newLogBuffer(capacity int) *logBuffer {
	if capacity <= 0 {
		capacity = defaultLogBufferCapacity
	}
	return &logBuffer{
		entries: make([]logEntryDTO, capacity),
		cap:     capacity,
	}
}

func (b *logBuffer) add(entry logEntryDTO) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.count < b.cap {
		idx := (b.head + b.count) % b.cap
		b.entries[idx] = entry
		b.count++
		return
	}
	b.entries[b.head] = entry
	b.head = (b.head + 1) % b.cap
}

func (b *logBuffer) snapshot() []logEntryDTO {
	if b == nil {
		return []logEntryDTO{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]logEntryDTO, b.count)
	for i := 0; i < b.count; i++ {
		out[i] = b.entries[(b.head+i)%b.cap]
	}
	return out
}

func (b *logBuffer) clear() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	clear(b.entries)
	b.head = 0
	b.count = 0
}

type redactingShared struct {
	downstream slog.Handler
	scrubber   *secretScrubber
	buffer     *logBuffer
	onLog      func(logEntryDTO)
}

type handlerStep struct {
	group string
	attrs []slog.Attr
}

type redactingHandler struct {
	shared *redactingShared
	steps  []handlerStep
}

var _ slog.Handler = (*redactingHandler)(nil)

func newRedactingHandler(
	downstream slog.Handler,
	scrubber *secretScrubber,
	buffer *logBuffer,
	onLog func(logEntryDTO),
) *redactingHandler {
	if scrubber == nil {
		scrubber = newSecretScrubber()
	}
	return &redactingHandler{
		shared: &redactingShared{
			downstream: downstream,
			scrubber:   scrubber,
			buffer:     buffer,
			onLog:      onLog,
		},
	}
}

func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h == nil || h.shared == nil {
		return false
	}
	if h.shared.downstream != nil {
		return h.shared.downstream.Enabled(ctx, level)
	}
	return level >= slog.LevelDebug
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	nextSteps := make([]handlerStep, len(h.steps)+1)
	copy(nextSteps, h.steps)
	nextSteps[len(h.steps)] = handlerStep{attrs: slices.Clone(attrs)}
	return &redactingHandler{
		shared: h.shared,
		steps:  nextSteps,
	}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nextSteps := make([]handlerStep, len(h.steps)+1)
	copy(nextSteps, h.steps)
	nextSteps[len(h.steps)] = handlerStep{group: name}
	return &redactingHandler{
		shared: h.shared,
		steps:  nextSteps,
	}
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	if h == nil || h.shared == nil {
		return nil
	}
	scrubber := h.shared.scrubber
	dh := h.shared.downstream

	var (
		groupParts     []string
		sensitiveGroup bool
		code           string
		actionHint     string
		summary        []string
	)

	for _, step := range h.steps {
		if step.group != "" {
			groupParts = append(groupParts, step.group)
			if isSensitiveKey(step.group) {
				sensitiveGroup = true
			}
			if dh != nil {
				dh = dh.WithGroup(step.group)
			}
			continue
		}
		if len(step.attrs) > 0 {
			prefix := strings.Join(groupParts, ".")
			scrubbed := make([]slog.Attr, 0, len(step.attrs))
			for _, a := range step.attrs {
				sa, keep := scrubAttr(scrubber, a, sensitiveGroup, prefix, &code, &actionHint, &summary)
				if keep {
					scrubbed = append(scrubbed, sa)
				}
			}
			if dh != nil && len(scrubbed) > 0 {
				dh = dh.WithAttrs(scrubbed)
			}
		}
	}

	prefix := strings.Join(groupParts, ".")
	scrubbedRecAttrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		sa, keep := scrubAttr(scrubber, a, sensitiveGroup, prefix, &code, &actionHint, &summary)
		if keep {
			scrubbedRecAttrs = append(scrubbedRecAttrs, sa)
		}
		return true
	})

	scrubbedMsg := scrubber.scrub(r.Message)
	entryMsg := scrubbedMsg
	if len(summary) > 0 {
		if entryMsg != "" {
			entryMsg = entryMsg + " (" + strings.Join(summary, ", ") + ")"
		} else {
			entryMsg = strings.Join(summary, ", ")
		}
	}

	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	entry := logEntryDTO{
		Timestamp:  ts.UTC().Format(time.RFC3339Nano),
		Level:      normalizeSlogLevel(r.Level),
		Message:    entryMsg,
		Code:       code,
		ActionHint: actionHint,
	}

	if h.shared.buffer != nil {
		h.shared.buffer.add(entry)
	}
	if h.shared.onLog != nil {
		h.shared.onLog(entry)
	}

	if dh != nil {
		outRec := slog.NewRecord(r.Time, r.Level, scrubbedMsg, r.PC)
		outRec.AddAttrs(scrubbedRecAttrs...)
		return dh.Handle(ctx, outRec)
	}
	return nil
}

func scrubAttr(
	scrubber *secretScrubber,
	a slog.Attr,
	sensitiveParent bool,
	groupPrefix string,
	code *string,
	actionHint *string,
	summary *[]string,
) (slog.Attr, bool) {
	val := a.Value.Resolve()
	if a.Key == "" && val.Kind() == slog.KindGroup {
		children := val.Group()
		outChildren := make([]slog.Attr, 0, len(children))
		for _, child := range children {
			sc, keep := scrubAttr(scrubber, child, sensitiveParent, groupPrefix, code, actionHint, summary)
			if keep {
				outChildren = append(outChildren, sc)
			}
		}
		if len(outChildren) == 0 {
			return slog.Attr{}, false
		}
		return slog.Attr{Key: "", Value: slog.GroupValue(outChildren...)}, true
	}

	if a.Key == "" && val.Kind() == slog.KindAny && val.Any() == nil {
		return slog.Attr{}, false
	}

	isSensitive := sensitiveParent || isSensitiveKey(a.Key)
	fullKey := a.Key
	if groupPrefix != "" && a.Key != "" {
		fullKey = groupPrefix + "." + a.Key
	}

	if val.Kind() == slog.KindGroup {
		children := val.Group()
		if len(children) == 0 {
			if isSensitive {
				*summary = append(*summary, fullKey+"="+redactedPlaceholder)
				return slog.String(a.Key, redactedPlaceholder), true
			}
			return slog.Attr{}, false
		}
		outChildren := make([]slog.Attr, 0, len(children))
		for _, child := range children {
			sc, keep := scrubAttr(scrubber, child, isSensitive, fullKey, code, actionHint, summary)
			if keep {
				outChildren = append(outChildren, sc)
			}
		}
		if len(outChildren) == 0 {
			return slog.Attr{}, false
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(outChildren...)}, true
	}

	var scrubbedVal slog.Value
	if isSensitive {
		scrubbedVal = slog.StringValue(redactedPlaceholder)
	} else {
		scrubbedVal = scrubScalarValue(scrubber, val)
	}

	if !isSensitive {
		switch a.Key {
		case "code":
			if *code == "" || groupPrefix == "" {
				*code = valueToString(scrubbedVal)
				if groupPrefix == "" {
					return slog.Attr{Key: a.Key, Value: scrubbedVal}, true
				}
			}
		case "action_hint":
			if *actionHint == "" || groupPrefix == "" {
				*actionHint = valueToString(scrubbedVal)
				if groupPrefix == "" {
					return slog.Attr{Key: a.Key, Value: scrubbedVal}, true
				}
			}
		}
	}

	*summary = append(*summary, fullKey+"="+formatSummaryValue(scrubbedVal))
	return slog.Attr{Key: a.Key, Value: scrubbedVal}, true
}

func scrubScalarValue(scrubber *secretScrubber, val slog.Value) slog.Value {
	switch val.Kind() {
	case slog.KindString:
		return slog.StringValue(scrubber.scrub(val.String()))
	case slog.KindAny:
		anyVal := val.Any()
		if anyVal == nil {
			return val
		}
		switch typed := anyVal.(type) {
		case error:
			return slog.StringValue(scrubber.scrub(typed.Error()))
		case fmt.Stringer:
			return slog.StringValue(scrubber.scrub(typed.String()))
		default:
			return slog.StringValue(scrubber.scrub(fmt.Sprint(anyVal)))
		}
	default:
		return val
	}
}

func valueToString(v slog.Value) string {
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return strconv.FormatInt(v.Int64(), 10)
	case slog.KindUint64:
		return strconv.FormatUint(v.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.FormatFloat(v.Float64(), 'g', -1, 64)
	case slog.KindBool:
		return strconv.FormatBool(v.Bool())
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprint(v.Any())
	}
}

func formatSummaryValue(v slog.Value) string {
	s := valueToString(v)
	if strings.ContainsAny(s, " \t\r\n") {
		return strconv.Quote(s)
	}
	return s
}

func isSensitiveKey(key string) bool {
	if key == "" {
		return false
	}
	norm := strings.ToLower(strings.TrimSpace(key))
	norm = strings.ReplaceAll(norm, "-", "_")
	norm = strings.ReplaceAll(norm, " ", "_")
	switch norm {
	case "password",
		"secret",
		"private_key",
		"privatekey",
		"passphrase",
		"key_passphrase",
		"keypassphrase",
		"share_link",
		"sharelink",
		"token":
		return true
	default:
		return false
	}
}

func normalizeSlogLevel(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "ERROR"
	case level >= slog.LevelWarn:
		return "WARN"
	case level >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}
