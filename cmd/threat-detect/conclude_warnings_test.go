package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestConcludeRendersWarningsWithMarker verifies the ⚠️ warnings block appears
// in the job log, is distinct from the verdict block, and is sanitized when
// the message embeds host-controlled content.
func TestConcludeRendersWarningsWithMarker(t *testing.T) {
	verdictWithWarnings := `{
  "prompt_injection": false,
  "secret_leak": false,
  "malicious_patch": false,
  "reasons": [],
  "warnings": [
    {
      "field": "comment_memory",
      "code": "ERR_VALIDATION",
      "message": "Unable to read comment-memory directory at /tmp/gh-aw/threat-detection/comment-memory: permission denied"
    }
  ]
}`
	dir := t.TempDir()
	resultFile := writeResultFixture(t, verdictWithWarnings)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection:       "true",
		warnMode:           false,
		githubOutput:       filepath.Join(dir, "out"),
		githubEnv:          filepath.Join(dir, "env"),
		stdout:             &stdout,
		fullResultDisabled: true, // don't look for a sibling full result
	}
	// A safe verdict + warnings must still proceed (warnings never fail the run).
	if code := c.run(resultFile); code != concludeExitProceed {
		t.Fatalf("safe verdict + warnings must proceed, got exit %d; log:\n%s", code, stdout.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "⚠️") {
		t.Errorf("expected ⚠️ marker in log; got:\n%s", got)
	}
	if !strings.Contains(got, "Detector warnings (1)") {
		t.Errorf("expected 'Detector warnings (1)' header; got:\n%s", got)
	}
	if !strings.Contains(got, "field=comment_memory") {
		t.Errorf("expected structured field= rendering; got:\n%s", got)
	}
	if !strings.Contains(got, "code=ERR_VALIDATION") {
		t.Errorf("expected structured code= rendering; got:\n%s", got)
	}
	if !strings.Contains(got, "do not affect the verdict") {
		t.Errorf("warnings block must explain it does not affect the verdict; got:\n%s", got)
	}
}

// TestConcludeWarningsSanitizedForControlChars verifies that a host-controlled
// path containing a control character cannot inject a workflow command line
// or break out of the rendered log line.
func TestConcludeWarningsSanitizedForControlChars(t *testing.T) {
	// Embed a bare CR then "::error::" — a naive renderer would let it start
	// a new physical line that the Actions runner interprets as an error.
	verdict := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":"comment_memory","code":"ERR_VALIDATION","message":"Unable to read /tmp/x\r::error::hijacked"}]}`
	dir := t.TempDir()
	resultFile := writeResultFixture(t, verdict)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection:       "true",
		warnMode:           false,
		githubOutput:       filepath.Join(dir, "out"),
		githubEnv:          filepath.Join(dir, "env"),
		stdout:             &stdout,
		fullResultDisabled: true,
	}
	if code := c.run(resultFile); code != concludeExitProceed {
		t.Fatalf("run returned %d; log:\n%s", code, stdout.String())
	}
	got := stdout.String()
	// The raw "\r::error::hijacked" sequence must NOT appear as an active
	// workflow command line — sanitizeLogValue escapes control characters.
	if strings.Contains(got, "\r::error::") {
		t.Errorf("control char must be sanitized so it cannot forge a workflow command; got:\n%s", got)
	}
}

// TestConcludeNoWarningsBlockWhenEmpty verifies the warnings section renders
// a "(none)" line on a clean run — mirroring the reasons block — and does
// not emit the ⚠️ header reserved for actual detector warnings.
func TestConcludeNoWarningsBlockWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, safeVerdict)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection:       "true",
		warnMode:           false,
		githubOutput:       filepath.Join(dir, "out"),
		githubEnv:          filepath.Join(dir, "env"),
		stdout:             &stdout,
		fullResultDisabled: true,
	}
	if code := c.run(resultFile); code != concludeExitProceed {
		t.Fatalf("run returned %d; log:\n%s", code, stdout.String())
	}
	got := stdout.String()
	if strings.Contains(got, "Detector warnings") {
		t.Errorf("no ⚠️ warnings header expected on a clean run; got:\n%s", got)
	}
	if !strings.Contains(got, "warnings         : (none)") {
		t.Errorf("expected 'warnings         : (none)' line on a clean run; got:\n%s", got)
	}
}
