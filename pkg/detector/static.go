package detector

import (
	"fmt"
	"os"
	"strings"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

// StaticAnalyze performs deterministic checks for high-confidence threats that
// should not depend on model judgment.
func StaticAnalyze(arts *artifacts.Artifacts) *Result {
	result := &Result{Reasons: []string{}}
	if arts == nil || arts.PromptFilePath == "" || arts.PromptFilePath == "No prompt file found" {
		return result
	}

	data, err := os.ReadFile(arts.PromptFilePath)
	if err != nil {
		return result
	}

	if reason := detectDuplicateSystemBlock(string(data)); reason != "" {
		result.PromptInjection = true
		result.Reasons = append(result.Reasons, reason)
	}

	return result
}

// Merge combines another detection result into r.
func (r *Result) Merge(other *Result) {
	if r == nil || other == nil {
		return
	}
	r.PromptInjection = r.PromptInjection || other.PromptInjection
	r.SecretLeak = r.SecretLeak || other.SecretLeak
	r.MaliciousPatch = r.MaliciousPatch || other.MaliciousPatch
	r.Reasons = append(r.Reasons, other.Reasons...)
}

func detectDuplicateSystemBlock(prompt string) string {
	lines := strings.Split(prompt, "\n")
	firstSystemClosed := false
	for i, line := range lines {
		if strings.Contains(line, "</system>") {
			firstSystemClosed = true
			continue
		}
		if firstSystemClosed && strings.Contains(line, "<system>") {
			lineNumber := i + 1
			reason := fmt.Sprintf("Prompt artifact contains an additional <system> block after the first </system> at line %d, indicating prompt-context contamination with system-level instructions.", lineNumber)
			if looksLikeReplacementTokenExpansion(lines, i) {
				reason += " The duplicate appears immediately after a regex end-anchor location, which matches a prompt-rendering or runtime-import replacement bug signature rather than evidence that the agent patch itself is malicious."
			}
			return reason
		}
	}
	return ""
}

func looksLikeReplacementTokenExpansion(lines []string, systemLine int) bool {
	for i := systemLine; i >= 0 && i >= systemLine-3; i-- {
		if strings.Contains(lines[i], `\s*<system>`) || strings.Contains(lines[i], `\s*`) {
			return true
		}
	}
	return false
}
