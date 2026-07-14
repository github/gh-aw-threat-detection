// Package runlog provides structured JSON Lines (JSONL) logging for a single
// threat-detection run. Each call to a logging method appends exactly one JSON
// object, terminated by a newline, to the underlying writer. Records always
// begin with the "time", "level", and "event" keys; any additional fields are
// emitted afterwards in a deterministic (sorted) order so logs are stable and
// easy to diff.
//
// A nil *Logger is a valid no-op logger: every method may be called on it
// safely, which lets callers pass nil when JSONL logging is disabled without
// sprinkling nil checks throughout the call sites.
package runlog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Log levels emitted in the "level" field.
const (
	LevelInfo  = "info"
	LevelError = "error"
)

// Logger writes newline-delimited JSON log records to an underlying writer.
// The zero value is not usable; construct one with New or Open. A nil *Logger
// is a valid no-op.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
	now    func() time.Time
}

// New returns a Logger that writes records to w. The writer is not closed by
// Close; use Open when the Logger should own a file handle.
func New(w io.Writer) *Logger {
	return &Logger{w: w, now: time.Now}
}

// Open creates (truncating any existing file) a JSONL log file at path with
// 0600 permissions and returns a Logger that owns it. The returned Logger's
// Close closes the file.
func Open(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening JSONL log file: %w", err)
	}
	return &Logger{w: f, closer: f, now: time.Now}, nil
}

// Info appends an info-level record for event with the given fields.
func (l *Logger) Info(event string, fields map[string]any) {
	l.emit(LevelInfo, event, fields)
}

// Error appends an error-level record for event with the given fields.
func (l *Logger) Error(event string, fields map[string]any) {
	l.emit(LevelError, event, fields)
}

// Close closes the underlying file when the Logger owns one. It is safe to call
// on a nil Logger or one constructed with New (in which case it is a no-op).
func (l *Logger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	return l.closer.Close()
}

func (l *Logger) emit(level, event string, fields map[string]any) {
	if l == nil || l.w == nil {
		return
	}
	line, err := encodeRecord(l.now().UTC(), level, event, fields)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(line)
}

// encodeRecord renders a single JSONL line: the leading time/level/event keys
// followed by the remaining fields in sorted order, terminated by a newline.
// Reserved keys ("time", "level", "event") in fields are ignored so a caller
// cannot accidentally shadow them.
func encodeRecord(t time.Time, level, event string, fields map[string]any) ([]byte, error) {
	var b strings.Builder
	b.WriteByte('{')
	writeKV(&b, "time", t.Format(time.RFC3339Nano), true)
	writeKV(&b, "level", level, false)
	writeKV(&b, "event", event, false)

	keys := make([]string, 0, len(fields))
	for k := range fields {
		switch k {
		case "time", "level", "event":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val, err := json.Marshal(fields[k])
		if err != nil {
			return nil, err
		}
		key, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		b.WriteByte(',')
		b.Write(key)
		b.WriteByte(':')
		b.Write(val)
	}
	b.WriteString("}\n")
	return []byte(b.String()), nil
}

func writeKV(b *strings.Builder, key, value string, first bool) {
	if !first {
		b.WriteByte(',')
	}
	k, _ := json.Marshal(key)
	v, _ := json.Marshal(value)
	b.Write(k)
	b.WriteByte(':')
	b.Write(v)
}
