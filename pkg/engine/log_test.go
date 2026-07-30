package engine

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/runlog"
)

// captureEngineInvoke runs logEngineInvoke with the given inputs, redirecting
// the stderr line into a buffer and the structured record into an in-memory
// JSONL logger. It returns the raw stderr text and the decoded engine_invoke
// record.
func captureEngineInvoke(t *testing.T, engineID, name string, args []string, model string) (string, map[string]any) {
	t.Helper()

	var stderr bytes.Buffer
	prev := engineInvokeStderr
	engineInvokeStderr = &stderr
	t.Cleanup(func() { engineInvokeStderr = prev })

	var jsonl bytes.Buffer
	logger := runlog.New(&jsonl)

	logEngineInvoke(logger, engineID, name, args, model)

	var record map[string]any
	if line := strings.TrimSpace(jsonl.String()); line != "" {
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decoding engine_invoke record: %v (line: %q)", err, line)
		}
	}
	return stderr.String(), record
}

func TestLogEngineInvoke_ExplicitModel(t *testing.T) {
	// Use a binary name that will not resolve in PATH so the assertion is
	// deterministic regardless of the host toolchain.
	stderr, record := captureEngineInvoke(t, "codex", "definitely-not-a-real-binary", []string{"exec", "--", "<prompt>"}, "gpt-5-codex")

	if !strings.HasPrefix(stderr, "[threat-detect] engine invoke: ") {
		t.Fatalf("unexpected stderr prefix: %q", stderr)
	}
	for _, want := range []string{"engine=codex", `model="gpt-5-codex"`, "args=3"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q missing %q", stderr, want)
		}
	}
	if !strings.HasSuffix(stderr, "\n") {
		t.Errorf("stderr should end with a newline: %q", stderr)
	}

	if got := record["event"]; got != "engine_invoke" {
		t.Errorf("event = %v, want engine_invoke", got)
	}
	if got := record["engine"]; got != "codex" {
		t.Errorf("engine = %v, want codex", got)
	}
	if got := record["model"]; got != "gpt-5-codex" {
		t.Errorf("model = %v, want gpt-5-codex", got)
	}
	if got := record["args_count"]; got != float64(3) {
		t.Errorf("args_count = %v, want 3", got)
	}
}

func TestLogEngineInvoke_EmptyModelFallback(t *testing.T) {
	stderr, record := captureEngineInvoke(t, "claude", "definitely-not-a-real-binary", nil, "")

	if !strings.Contains(stderr, "engine=claude") {
		t.Errorf("stderr %q missing engine=claude", stderr)
	}
	if !strings.Contains(stderr, "model=(engine default)") {
		t.Errorf("stderr %q missing model=(engine default)", stderr)
	}

	// An empty model must not be emitted as a structured field.
	if _, ok := record["model"]; ok {
		t.Errorf("record should omit model when empty, got %v", record["model"])
	}
	if got := record["engine"]; got != "claude" {
		t.Errorf("engine = %v, want claude", got)
	}
}

func TestLogEngineInvoke_EscapesControlCharacters(t *testing.T) {
	// A model value carrying a newline and terminal control sequence must not
	// split or forge the single-line diagnostic. Quoting keeps it on one line
	// with the control characters escaped.
	malicious := "evil\n[threat-detect] engine invoke: forged\x1b[31m"
	stderr, record := captureEngineInvoke(t, "copilot", "definitely-not-a-real-binary", []string{"a"}, malicious)

	if strings.Count(stderr, "\n") != 1 {
		t.Errorf("stderr should be a single physical line, got %q", stderr)
	}
	if strings.Contains(stderr, "\x1b") {
		t.Errorf("stderr should not contain a raw escape byte: %q", stderr)
	}
	if !strings.Contains(stderr, `\n`) || !strings.Contains(stderr, `\x1b`) {
		t.Errorf("stderr should contain escaped control characters: %q", stderr)
	}
	// The structured field preserves the exact value (JSON handles escaping).
	if got := record["model"]; got != malicious {
		t.Errorf("record model = %q, want %q", got, malicious)
	}
}
