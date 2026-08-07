package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

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
	if !strings.Contains(stderr, "model=(none; using engine default)") {
		t.Errorf("stderr %q missing model=(none; using engine default)", stderr)
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

// captureEngineComplete runs logEngineComplete, redirecting the stderr line
// into a buffer and the structured record into an in-memory JSONL logger.
func captureEngineComplete(t *testing.T, diagEngineID, name string, c engineCompletion) (string, map[string]any) {
	t.Helper()

	var stderr bytes.Buffer
	prev := engineInvokeStderr
	engineInvokeStderr = &stderr
	t.Cleanup(func() { engineInvokeStderr = prev })

	var jsonl bytes.Buffer
	logger := runlog.New(&jsonl)

	logEngineComplete(cliDiag{engineID: diagEngineID, logger: logger}, name, c)

	var record map[string]any
	if line := strings.TrimSpace(jsonl.String()); line != "" {
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decoding engine_complete record: %v (line: %q)", err, line)
		}
	}
	return stderr.String(), record
}

func TestLogEngineComplete_Success(t *testing.T) {
	stderr, record := captureEngineComplete(t, "copilot", "node", engineCompletion{
		elapsed:     1500 * time.Millisecond,
		exitCode:    0,
		stdoutBytes: 120,
		stderrBytes: 34,
	})

	for _, want := range []string{
		"[threat-detect] engine complete: ",
		"engine=copilot", "command=node", "outcome=ok", "exit=0",
		"duration=1.5s", "stdout=120B", "stderr=34B", "verdict_recorded=false",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q missing %q", stderr, want)
		}
	}

	if got := record["event"]; got != "engine_complete" {
		t.Errorf("event = %v, want engine_complete", got)
	}
	if got := record["duration_ms"]; got != float64(1500) {
		t.Errorf("duration_ms = %v, want 1500", got)
	}
	if got := record["outcome"]; got != "ok" {
		t.Errorf("outcome = %v, want ok", got)
	}
	if _, ok := record["error"]; ok {
		t.Errorf("record should omit error on success, got %v", record["error"])
	}
}

func TestLogEngineComplete_TerminatedEarlyIsNotAnError(t *testing.T) {
	// The subprocess is deliberately killed once the verdict lands, so the
	// resulting "signal: killed" must not be reported as a failure.
	stderr, record := captureEngineComplete(t, "claude", "claude", engineCompletion{
		elapsed:         2 * time.Second,
		exitCode:        -1,
		verdictRecorded: true,
		err:             errors.New("signal: killed"),
	})

	if !strings.Contains(stderr, "outcome=terminated_early") {
		t.Errorf("stderr %q missing outcome=terminated_early", stderr)
	}
	if !strings.Contains(stderr, "verdict_recorded=true") {
		t.Errorf("stderr %q missing verdict_recorded=true", stderr)
	}
	if got := record["outcome"]; got != "terminated_early" {
		t.Errorf("outcome = %v, want terminated_early", got)
	}
	if _, ok := record["error"]; ok {
		t.Errorf("record should omit error when terminated early, got %v", record["error"])
	}
	if got := record["verdict_recorded"]; got != true {
		t.Errorf("verdict_recorded = %v, want true", got)
	}
}

func TestLogEngineComplete_Failure(t *testing.T) {
	stderr, record := captureEngineComplete(t, "codex", "codex", engineCompletion{
		elapsed:  10 * time.Millisecond,
		exitCode: 1,
		err:      errors.New("exit status 1"),
	})

	if !strings.Contains(stderr, "outcome=failed") {
		t.Errorf("stderr %q missing outcome=failed", stderr)
	}
	if got := record["error"]; got != "exit status 1" {
		t.Errorf("error = %v, want exit status 1", got)
	}
	if got := record["exit_code"]; got != float64(1) {
		t.Errorf("exit_code = %v, want 1", got)
	}
}

func TestLogEngineComplete_NilLoggerAndUnknownEngine(t *testing.T) {
	var stderr bytes.Buffer
	prev := engineInvokeStderr
	engineInvokeStderr = &stderr
	t.Cleanup(func() { engineInvokeStderr = prev })

	// A nil logger must still produce the job-log line: the stderr diagnostic
	// is the only sink guaranteed to exist.
	logEngineComplete(cliDiag{}, "sh", engineCompletion{elapsed: time.Second})

	if !strings.Contains(stderr.String(), "engine=unknown") {
		t.Errorf("stderr %q missing engine=unknown", stderr.String())
	}
}
