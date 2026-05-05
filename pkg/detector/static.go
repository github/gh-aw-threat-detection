package detector

import (
	"os"
	"regexp"
	"strings"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

// templatePlaceholderRE matches mustache-style placeholders (e.g. {{user_input}})
// that mark untrusted input regions in the prompt template.
var templatePlaceholderRE = regexp.MustCompile(`\{\{[^}]+\}\}`)

// StaticAnalyze performs deterministic checks for high-confidence threats.
// It uses the prompt template to identify untrusted regions and only considers
// prompt injection attempts within those regions.
func StaticAnalyze(arts *artifacts.Artifacts) *Result {
	result := &Result{Reasons: []string{}}
	if arts == nil {
		return result
	}

	// If no prompt template is available, we cannot distinguish trusted from
	// untrusted content, so skip static analysis.
	if arts.PromptTemplatePath == "" {
		return result
	}

	templateData, err := os.ReadFile(arts.PromptTemplatePath)
	if err != nil {
		return result
	}

	// If no rendered prompt is available, nothing to analyze.
	if arts.PromptFilePath == "" || arts.PromptFilePath == "No prompt file found" {
		return result
	}

	promptData, err := os.ReadFile(arts.PromptFilePath)
	if err != nil {
		return result
	}

	untrustedRegions := ExtractUntrustedRegions(string(templateData), string(promptData))
	for _, region := range untrustedRegions {
		if reason := checkForPromptInjection(region); reason != "" {
			result.PromptInjection = true
			result.Reasons = append(result.Reasons, reason)
		}
	}

	return result
}

// ExtractUntrustedRegions identifies the portions of a rendered prompt that
// correspond to placeholder expansions in the template. It splits the template
// on its placeholders and uses the static segments as delimiters to carve out
// the untrusted (user-supplied) content from the rendered prompt.
func ExtractUntrustedRegions(template, rendered string) []string {
	// Split template on placeholders to get the fixed "spine" segments.
	placeholderLocs := templatePlaceholderRE.FindAllStringIndex(template, -1)
	if len(placeholderLocs) == 0 {
		// No placeholders means the entire prompt is trusted.
		return nil
	}

	// Build list of static segments (the parts between/around placeholders).
	var segments []string
	prev := 0
	for _, loc := range placeholderLocs {
		segments = append(segments, template[prev:loc[0]])
		prev = loc[1]
	}
	segments = append(segments, template[prev:])

	// Use static segments to locate untrusted regions in the rendered prompt.
	var regions []string
	remaining := rendered

	for i := 0; i < len(segments)-1; i++ {
		seg := segments[i]
		nextSeg := segments[i+1]

		// Find where the current segment ends in the remaining text.
		var afterSeg string
		if seg == "" {
			afterSeg = remaining
		} else {
			idx := strings.Index(remaining, seg)
			if idx == -1 {
				// Template segment not found; skip this region.
				continue
			}
			afterSeg = remaining[idx+len(seg):]
		}

		// Find where the next segment begins to delimit the untrusted region.
		var untrusted string
		if nextSeg == "" {
			// If next segment is empty, the untrusted region extends to the end.
			untrusted = afterSeg
			remaining = ""
		} else {
			nextIdx := strings.Index(afterSeg, nextSeg)
			if nextIdx == -1 {
				// Next segment not found; the rest is untrusted.
				untrusted = afterSeg
				remaining = ""
			} else {
				untrusted = afterSeg[:nextIdx]
				remaining = afterSeg[nextIdx:]
			}
		}

		trimmed := strings.TrimSpace(untrusted)
		if trimmed != "" {
			regions = append(regions, trimmed)
		}
	}

	return regions
}

// MergeResults combines two detection results.
func MergeResults(base, other *Result) *Result {
	if base == nil {
		return other
	}
	if other == nil {
		return base
	}
	base.PromptInjection = base.PromptInjection || other.PromptInjection
	base.SecretLeak = base.SecretLeak || other.SecretLeak
	base.MaliciousPatch = base.MaliciousPatch || other.MaliciousPatch
	base.Reasons = append(base.Reasons, other.Reasons...)
	return base
}

// injectionPatterns are patterns that indicate prompt injection in untrusted content.
var injectionPatterns = []*regexp.Regexp{
	// System-level XML tags that should never appear in user content.
	regexp.MustCompile(`(?i)<\s*system\s*>`),
	// Attempts to override instructions.
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)`),
	// New instruction injection.
	regexp.MustCompile(`(?i)new\s+instructions?\s*:`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+`),
	// Role override attempts.
	regexp.MustCompile(`(?i)from\s+now\s+on[,\s]+(you|your)\s+(are|role|task)`),
}

// checkForPromptInjection checks a single untrusted region for prompt injection patterns.
func checkForPromptInjection(region string) string {
	for _, pat := range injectionPatterns {
		if loc := pat.FindString(region); loc != "" {
			// Truncate region for the reason message.
			preview := region
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			return "Prompt injection pattern detected in untrusted input region: found \"" + loc + "\" in content: " + preview
		}
	}
	return ""
}
