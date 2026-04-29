package detector

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ResultPrefix is the expected prefix for threat detection results in engine output.
const ResultPrefix = "THREAT_DETECTION_RESULT:"

// Result represents the structured output of threat detection analysis.
type Result struct {
	PromptInjection bool     `json:"prompt_injection"`
	SecretLeak      bool     `json:"secret_leak"`
	MaliciousPatch  bool     `json:"malicious_patch"`
	Reasons         []string `json:"reasons"`
}

// HasThreats returns true if any threat category was detected.
func (r *Result) HasThreats() bool {
	return r.PromptInjection || r.SecretLeak || r.MaliciousPatch
}

// ParseResult extracts and parses the THREAT_DETECTION_RESULT from raw engine output.
// It supports both raw text output and stream-json formatted output.
func ParseResult(output string) (*Result, error) {
	lines := strings.Split(output, "\n")

	// Phase 1: Try stream-json extraction
	var matches []string
	for _, line := range lines {
		if extracted := extractFromStreamJSON(line); extracted != "" {
			matches = append(matches, extracted)
		}
	}

	// Phase 2: Fall back to raw line matching
	if len(matches) == 0 {
		for i := 0; i < len(lines); i++ {
			trimmed := strings.TrimSpace(lines[i])
			if strings.HasPrefix(trimmed, ResultPrefix) {
				// Join remaining lines and extract complete JSON
				joined := strings.Join(lines[i:], "\n")
				joined = strings.TrimSpace(joined)
				if extracted := extractResultFromText(joined); extracted != "" {
					matches = append(matches, extracted)
					// Count consumed lines
					jsonPart := strings.TrimPrefix(extracted, ResultPrefix)
					extraLines := strings.Count(jsonPart, "\n")
					i += extraLines
				} else {
					matches = append(matches, trimmed)
				}
			}
		}
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no THREAT_DETECTION_RESULT found in detection output; the detection model may have failed to follow the output format")
	}

	// Deduplicate
	unique := deduplicate(matches)
	if len(unique) > 1 {
		return nil, fmt.Errorf("multiple conflicting THREAT_DETECTION_RESULT entries found (%d unique out of %d total)", len(unique), len(matches))
	}

	// Parse JSON
	jsonPart := strings.TrimPrefix(unique[0], ResultPrefix)
	// Normalize literal newlines to JSON escape sequences
	jsonPart = strings.ReplaceAll(jsonPart, "\n", "\\n")

	var raw map[string]any
	if err := json.Unmarshal([]byte(jsonPart), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from THREAT_DETECTION_RESULT: %w\nRaw value: %s", err, unique[0])
	}

	// Validate that it's an object
	if raw == nil {
		return nil, fmt.Errorf("THREAT_DETECTION_RESULT JSON must be an object, got null")
	}

	// Validate boolean fields
	for _, field := range []string{"prompt_injection", "secret_leak", "malicious_patch"} {
		val, exists := raw[field]
		if !exists {
			return nil, fmt.Errorf("missing required field %q in THREAT_DETECTION_RESULT", field)
		}
		if _, ok := val.(bool); !ok {
			return nil, fmt.Errorf("invalid type for %q: expected boolean, got %T (%v)", field, val, val)
		}
	}

	result := &Result{
		PromptInjection: raw["prompt_injection"].(bool),
		SecretLeak:      raw["secret_leak"].(bool),
		MaliciousPatch:  raw["malicious_patch"].(bool),
	}

	// Parse reasons
	if reasons, exists := raw["reasons"]; exists {
		if reasonsArr, ok := reasons.([]any); ok {
			for _, r := range reasonsArr {
				if s, ok := r.(string); ok {
					result.Reasons = append(result.Reasons, s)
				}
			}
		}
	}

	return result, nil
}

// extractFromStreamJSON attempts to extract a THREAT_DETECTION_RESULT from a stream-json line.
func extractFromStreamJSON(line string) string {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") {
		return ""
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return ""
	}

	// Only extract from "type":"result" (authoritative final summary)
	if objType, ok := obj["type"].(string); !ok || objType != "result" {
		return ""
	}

	resultStr, ok := obj["result"].(string)
	if !ok {
		return ""
	}

	// Find the THREAT_DETECTION_RESULT line within the result text
	resultLines := strings.Split(resultStr, "\n")
	for i, rl := range resultLines {
		if strings.HasPrefix(strings.TrimSpace(rl), ResultPrefix) {
			joined := strings.TrimSpace(strings.Join(resultLines[i:], "\n"))
			return extractResultFromText(joined)
		}
	}

	return ""
}

// extractResultFromText extracts a complete JSON object from text starting with ResultPrefix.
// Uses character-by-character brace counting to find the matching closing brace.
func extractResultFromText(text string) string {
	prefixIdx := strings.Index(text, ResultPrefix)
	if prefixIdx == -1 {
		return ""
	}

	searchStart := prefixIdx + len(ResultPrefix)
	jsonStart := strings.Index(text[searchStart:], "{")
	if jsonStart == -1 {
		return ""
	}
	jsonStart += searchStart

	depth := 0
	inString := false
	escaped := false
	jsonEnd := -1

	for i := jsonStart; i < len(text); i++ {
		ch := text[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 {
				jsonEnd = i
				break
			}
		}
	}

	if jsonEnd == -1 {
		return ""
	}

	return ResultPrefix + text[jsonStart:jsonEnd+1]
}

// deduplicate returns unique strings from a slice.
func deduplicate(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
