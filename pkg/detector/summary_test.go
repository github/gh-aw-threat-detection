package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatPromptSummary(t *testing.T) {
	out := FormatPromptSummary("copilot", "gpt-5", 2, "Analyze this prompt.")

	for _, want := range []string{
		"<details>",
		"<summary>Threat Detection Prompt</summary>",
		"**Engine**: copilot",
		"**Model**: gpt-5",
		"**Retries**: 2",
		"<pre><code>",
		"Analyze this prompt.",
		"</code></pre>",
		"</details>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatPromptSummary() missing %q; got:\n%s", want, out)
		}
	}
}

func TestFormatPromptSummary_EscapesHTML(t *testing.T) {
	// A prompt containing a closing fence-equivalent (here, raw HTML/script
	// content) must not be able to break out of the <pre><code> block and be
	// rendered as live Markdown/HTML in the job summary.
	malicious := "</code></pre><script>alert(1)</script><details><summary>spoofed</summary>"
	out := FormatPromptSummary("copilot", "gpt-5", 1, malicious)

	if strings.Contains(out, "<script>") {
		t.Errorf("FormatPromptSummary() did not escape embedded HTML; got:\n%s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("FormatPromptSummary() expected escaped script tag; got:\n%s", out)
	}
}

func TestFormatPromptSummary_Truncates(t *testing.T) {
	longPrompt := strings.Repeat("a", maxStepSummaryPromptBytes+1000)
	out := FormatPromptSummary("copilot", "gpt-5", 1, longPrompt)

	if !strings.Contains(out, "...(truncated)") {
		t.Errorf("FormatPromptSummary() did not truncate long prompt")
	}
	if len(out) > maxStepSummaryPromptBytes+2000 {
		t.Errorf("FormatPromptSummary() output len = %d, want bounded near %d", len(out), maxStepSummaryPromptBytes)
	}
}

func TestFormatVerdictSummary(t *testing.T) {
	result := &Result{PromptInjection: true, SecretLeak: false, MaliciousPatch: false, Reasons: []string{"jailbreak attempt"}}
	out := FormatVerdictSummary(result, "failure", "threat_detected")

	for _, want := range []string{
		"<summary>Threat Detection Verdict</summary>",
		"| Prompt Injection | true |",
		"| Secret Leak | false |",
		"| Malicious Patch | false |",
		"| Conclusion | failure |",
		"| Reason Code | threat_detected |",
		"jailbreak attempt",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("FormatVerdictSummary() missing %q; got:\n%s", want, out)
		}
	}
}

func TestFormatVerdictSummary_EscapesReasons(t *testing.T) {
	// Reasons come from the detection engine's analysis of untrusted artifact
	// content and must not be able to inject Markdown/HTML into the verdict
	// summary (e.g. escaping a list item to add a spoofed heading or a nested
	// <details> block).
	result := &Result{PromptInjection: true, Reasons: []string{"</code></pre><details><summary>spoofed</summary>evil"}}
	out := FormatVerdictSummary(result, "failure", "threat_detected")

	if strings.Contains(out, "<details><summary>spoofed</summary>") {
		t.Errorf("FormatVerdictSummary() did not escape embedded HTML in reason; got:\n%s", out)
	}
	if !strings.Contains(out, "&lt;details&gt;&lt;summary&gt;spoofed&lt;/summary&gt;") {
		t.Errorf("FormatVerdictSummary() expected escaped reason; got:\n%s", out)
	}
}

func TestFormatVerdictSummary_NilResult(t *testing.T) {
	out := FormatVerdictSummary(nil, "skipped", "")

	if !strings.Contains(out, "_no verdict_") {
		t.Errorf("FormatVerdictSummary(nil) missing no-verdict placeholder; got:\n%s", out)
	}
	if strings.Contains(out, "Reason Code") {
		t.Errorf("FormatVerdictSummary(nil) should omit reason code when empty; got:\n%s", out)
	}
}

func TestAppendStepSummary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "step_summary.md")

	if err := AppendStepSummary(path, "first\n"); err != nil {
		t.Fatalf("AppendStepSummary() error = %v", err)
	}
	if err := AppendStepSummary(path, "second\n"); err != nil {
		t.Fatalf("AppendStepSummary() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got, want := string(data), "first\nsecond\n"; got != want {
		t.Errorf("step summary content = %q, want %q", got, want)
	}
}

func TestAppendStepSummary_EmptyPathIsNoop(t *testing.T) {
	if err := AppendStepSummary("", "should not be written"); err != nil {
		t.Fatalf("AppendStepSummary(\"\") error = %v, want nil", err)
	}
}
