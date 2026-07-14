package runlog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoggerWritesJSONLRecords(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	fixed := time.Date(2026, 7, 14, 18, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return fixed }

	l.Info("run_start", map[string]any{"engine": "copilot", "retries": 1})
	l.Error("detection_failed", map[string]any{"reason": "engine_error"})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), buf.String())
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 0 is not valid JSON: %v", err)
	}
	if first["time"] != "2026-07-14T18:00:00Z" {
		t.Errorf("time = %v, want 2026-07-14T18:00:00Z", first["time"])
	}
	if first["level"] != LevelInfo {
		t.Errorf("level = %v, want %s", first["level"], LevelInfo)
	}
	if first["event"] != "run_start" {
		t.Errorf("event = %v, want run_start", first["event"])
	}
	if first["engine"] != "copilot" {
		t.Errorf("engine = %v, want copilot", first["engine"])
	}

	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v", err)
	}
	if second["level"] != LevelError {
		t.Errorf("level = %v, want %s", second["level"], LevelError)
	}
}

func TestLoggerLeadingKeyOrder(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.now = func() time.Time { return time.Unix(0, 0).UTC() }
	l.Info("evt", map[string]any{"zeta": 1, "alpha": 2})

	line := strings.TrimRight(buf.String(), "\n")
	// time, then level, then event must lead; remaining fields sorted.
	wantOrder := []string{`"time"`, `"level"`, `"event"`, `"alpha"`, `"zeta"`}
	prev := -1
	for _, key := range wantOrder {
		idx := strings.Index(line, key)
		if idx < 0 {
			t.Fatalf("key %s missing from %q", key, line)
		}
		if idx < prev {
			t.Fatalf("key %s out of order in %q", key, line)
		}
		prev = idx
	}
}

func TestReservedFieldsCannotBeShadowed(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	l.Info("evt", map[string]any{"event": "override", "level": "override", "time": "override"})

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimRight(buf.String(), "\n")), &rec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rec["event"] != "evt" {
		t.Errorf("event = %v, want evt (reserved key must not be shadowed)", rec["event"])
	}
	if rec["level"] != LevelInfo {
		t.Errorf("level = %v, want %s", rec["level"], LevelInfo)
	}
	if rec["time"] != "2026-01-01T00:00:00Z" {
		t.Errorf("time = %v, want fixed timestamp", rec["time"])
	}
}

func TestNilLoggerIsNoOp(t *testing.T) {
	var l *Logger
	// None of these must panic.
	l.Info("evt", map[string]any{"a": 1})
	l.Error("evt", nil)
	if err := l.Close(); err != nil {
		t.Fatalf("Close() on nil logger error = %v", err)
	}
}

func TestOpenCreatesFileWith0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	l.Info("run_start", map[string]any{"engine": "claude"})
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat error = %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file perm = %o, want 600", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read error = %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimRight(string(data), "\n")), &rec); err != nil {
		t.Fatalf("file content is not valid JSONL: %v", err)
	}
	if rec["event"] != "run_start" {
		t.Errorf("event = %v, want run_start", rec["event"])
	}
}

func TestOpenTruncatesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.jsonl")
	if err := os.WriteFile(path, []byte("stale content\n"), 0o600); err != nil {
		t.Fatalf("seed write error = %v", err)
	}
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	l.Info("fresh", nil)
	if err := l.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read error = %v", err)
	}
	if strings.Contains(string(data), "stale content") {
		t.Fatalf("file was not truncated: %q", string(data))
	}
}
