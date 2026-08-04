package detector

import (
	"fmt"
	"os"
	"strings"
)

// maxStepSummaryPromptBytes bounds how much of the rendered prompt is embedded
// in the GitHub Actions step summary. Step summaries share a 1MiB per-job
// budget across every step, so a single detection run must not consume it.
const maxStepSummaryPromptBytes = 60_000

// FormatPromptSummary renders a collapsible step-summary block describing the
// prompt actually sent to the detection engine (as opposed to any template
// gh-aw itself may have rendered but never passed to threat-detect), together
// with the resolved engine/model/retries configuration used for this run.
func FormatPromptSummary(engineID, model string, retries int, prompt string) string {
	var b strings.Builder
	b.WriteString("<details>\n<summary>Threat Detection Prompt</summary>\n\n")
	b.WriteString(fmt.Sprintf("- **Engine**: %s\n", engineID))
	b.WriteString(fmt.Sprintf("- **Model**: %s\n", model))
	b.WriteString(fmt.Sprintf("- **Retries**: %d\n\n", retries))
	b.WriteString("```markdown\n")
	b.WriteString(truncateForSummary(prompt, maxStepSummaryPromptBytes))
	b.WriteString("\n```\n\n</details>\n\n")
	return b.String()
}

// FormatVerdictSummary renders a collapsible step-summary block describing the
// detection verdict: per-field booleans, reasons, the gh-aw conclusion the
// verdict resulted in, and the reason code (when the run did not conclude
// cleanly as "success").
func FormatVerdictSummary(result *Result, conclusion, reasonCode string) string {
	var b strings.Builder
	b.WriteString("<details>\n<summary>Threat Detection Verdict</summary>\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("| --- | --- |\n")
	if result != nil {
		b.WriteString(fmt.Sprintf("| Prompt Injection | %v |\n", result.PromptInjection))
		b.WriteString(fmt.Sprintf("| Secret Leak | %v |\n", result.SecretLeak))
		b.WriteString(fmt.Sprintf("| Malicious Patch | %v |\n", result.MaliciousPatch))
	} else {
		b.WriteString("| Prompt Injection | _no verdict_ |\n")
		b.WriteString("| Secret Leak | _no verdict_ |\n")
		b.WriteString("| Malicious Patch | _no verdict_ |\n")
	}
	b.WriteString(fmt.Sprintf("| Conclusion | %s |\n", conclusion))
	if reasonCode != "" {
		b.WriteString(fmt.Sprintf("| Reason Code | %s |\n", reasonCode))
	}
	b.WriteString("\n")

	if result != nil && len(result.Reasons) > 0 {
		b.WriteString("**Reasons:**\n\n")
		for _, r := range result.Reasons {
			b.WriteString(fmt.Sprintf("- %s\n", r))
		}
		b.WriteString("\n")
	}
	b.WriteString("</details>\n\n")
	return b.String()
}

// AppendStepSummary appends content to the GitHub Actions step summary file at
// path, creating it if it does not yet exist. It is a no-op when path is
// empty, so callers can pass an unresolved --step-summary/$GITHUB_STEP_SUMMARY
// value unconditionally.
func AppendStepSummary(path, content string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening step summary file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return fmt.Errorf("writing step summary: %w", err)
	}
	return nil
}

// truncateForSummary bounds s to at most maxBytes bytes, appending a marker
// when truncated so readers know the block was cut short.
func truncateForSummary(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes] + "\n...(truncated)"
}
