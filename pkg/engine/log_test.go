package engine

import (
	"bytes"
	"strings"
	"testing"
)

// captureEngineInvoke runs logEngineInvoke with the given inputs, redirecting
// the stderr diagnostics into a buffer, and returns the captured text.
func captureEngineInvoke(t *testing.T, engineID, name string, args []string, model string) string {
	t.Helper()

	var stderr bytes.Buffer
	prev := engineInvokeStderr
	engineInvokeStderr = &stderr
	t.Cleanup(func() { engineInvokeStderr = prev })

	logEngineInvoke(engineID, name, args, model)

	return stderr.String()
}

func TestLogEngineInvoke_ExplicitModel(t *testing.T) {
	// Use a binary name that will not resolve in PATH so the assertion is
	// deterministic regardless of the host toolchain.
	stderr := captureEngineInvoke(t, "codex", "definitely-not-a-real-binary", []string{"exec", "--", "<prompt>"}, "gpt-5-codex")

	if !strings.HasPrefix(stderr, "[threat-detect] engine invoke: ") {
		t.Fatalf("unexpected stderr prefix: %q", stderr)
	}
	for _, want := range []string{"engine=codex", `model="gpt-5-codex"`, "args=3"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q missing %q", stderr, want)
		}
	}
	if !strings.Contains(stderr, `[threat-detect] engine argv: "exec" "--" "<prompt>"`) {
		t.Errorf("stderr %q missing the argv line", stderr)
	}
	if !strings.HasSuffix(stderr, "\n") {
		t.Errorf("stderr should end with a newline: %q", stderr)
	}
}

func TestLogEngineInvoke_EmptyModelFallback(t *testing.T) {
	stderr := captureEngineInvoke(t, "claude", "definitely-not-a-real-binary", nil, "")

	if !strings.Contains(stderr, "engine=claude") {
		t.Errorf("stderr %q missing engine=claude", stderr)
	}
	if !strings.Contains(stderr, "model=(none; using engine default)") {
		t.Errorf("stderr %q missing model=(none; using engine default)", stderr)
	}
	if !strings.Contains(stderr, "[threat-detect] engine argv: (none)") {
		t.Errorf("stderr %q missing the empty-argv line", stderr)
	}
}

func TestLogEngineInvoke_EscapesControlCharacters(t *testing.T) {
	// A model value carrying a newline and terminal control sequence must not
	// split or forge the diagnostic lines. Quoting keeps each on one line with
	// the control characters escaped.
	malicious := "evil\n[threat-detect] engine invoke: forged\x1b[31m"
	stderr := captureEngineInvoke(t, "copilot", "definitely-not-a-real-binary", []string{"a"}, malicious)

	// One line for the invoke summary, one for the argv listing.
	if strings.Count(stderr, "\n") != 2 {
		t.Errorf("stderr should be exactly two physical lines, got %q", stderr)
	}
	if strings.Contains(stderr, "\x1b") {
		t.Errorf("stderr should not contain a raw escape byte: %q", stderr)
	}
	if !strings.Contains(stderr, `\n`) || !strings.Contains(stderr, `\x1b`) {
		t.Errorf("stderr should contain escaped control characters: %q", stderr)
	}
}

func TestLogEngineInvoke_EscapesArgv(t *testing.T) {
	// argv elements are engine-constructed but may embed caller-supplied values
	// (for example a model alias), so they must not be able to add a line.
	stderr := captureEngineInvoke(t, "copilot", "definitely-not-a-real-binary", []string{"--model", "a\nb"}, "")

	if strings.Count(stderr, "\n") != 2 {
		t.Errorf("stderr should be exactly two physical lines, got %q", stderr)
	}
	if !strings.Contains(stderr, `"--model" "a\nb"`) {
		t.Errorf("stderr %q should quote and escape argv elements", stderr)
	}
}

func TestLogEngineInvoke_QuotesCommand(t *testing.T) {
	// The process name can come from GH_AW_NODE_BIN, so a newline in that
	// configuration must not split the diagnostic or forge a workflow command.
	stderr := captureEngineInvoke(t, "claude", "definitely-not-real\n::error::forged", nil, "")

	if strings.Contains(stderr, "\n::error::forged") {
		t.Errorf("command must not open a workflow-command line:\n%q", stderr)
	}
	if !strings.Contains(stderr, `command="definitely-not-real\n::error::forged (binary not found in PATH)"`) {
		t.Errorf("command should be quoted with escapes in place, got:\n%q", stderr)
	}
	if strings.Count(stderr, "\n") != 2 {
		t.Errorf("stderr should be exactly two physical lines, got %q", stderr)
	}
}
