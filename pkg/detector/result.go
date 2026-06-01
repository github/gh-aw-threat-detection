package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// ResultJSONSchema is the strict JSON Schema used for structured model output.
var ResultJSONSchema = map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"prompt_injection", "secret_leak", "malicious_patch", "reasons"},
	"properties": map[string]any{
		"prompt_injection": map[string]any{"type": "boolean"},
		"secret_leak":      map[string]any{"type": "boolean"},
		"malicious_patch":  map[string]any{"type": "boolean"},
		"reasons": map[string]any{
			"type":  "array",
			"items": map[string]any{"type": "string"},
		},
	},
}

// HasThreats returns true if any threat category was detected.
func (r *Result) HasThreats() bool {
	if r == nil {
		return false
	}
	return r.PromptInjection || r.SecretLeak || r.MaliciousPatch
}

// IsSafe returns true when the result is valid and all threat categories are false.
func (r *Result) IsSafe() bool {
	return r != nil && !r.HasThreats()
}

// ParseStructuredResult parses a strict JSON object matching ResultJSONSchema.
func ParseStructuredResult(data []byte) (*Result, error) {
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse structured result JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		preview, marshalErr := json.Marshal(extra)
		if marshalErr != nil {
			preview = []byte(fmt.Sprintf("<%T>", extra))
		}
		previewText := string(TruncateCorrectionBytes(preview))
		return nil, fmt.Errorf("structured result must be exactly one JSON object; found: %s", previewText)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("structured result JSON must be a non-empty object")
	}
	if err := validateRawResult(raw, "structured result"); err != nil {
		return nil, err
	}
	return resultFromRaw(raw), nil
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

	if err := validateRawResult(raw, "THREAT_DETECTION_RESULT"); err != nil {
		return nil, err
	}

	return resultFromRaw(raw), nil
}

func validateRawResult(raw map[string]any, label string) error {
	for field := range raw {
		switch field {
		case "prompt_injection", "secret_leak", "malicious_patch", "reasons":
		default:
			return fmt.Errorf("unexpected field %q in %s", field, label)
		}
	}
	for _, field := range []string{"prompt_injection", "secret_leak", "malicious_patch"} {
		val, exists := raw[field]
		if !exists {
			return fmt.Errorf("missing required field %q in %s", field, label)
		}
		if _, ok := val.(bool); !ok {
			return fmt.Errorf("invalid type for %q: expected boolean, got %T (%v)", field, val, val)
		}
	}
	reasons, exists := raw["reasons"]
	if !exists {
		return fmt.Errorf("missing required field %q in %s", "reasons", label)
	}
	reasonsArr, ok := reasons.([]any)
	if !ok {
		return fmt.Errorf("invalid type for %q: expected array, got %T (%v)", "reasons", reasons, reasons)
	}
	for i, reason := range reasonsArr {
		if _, ok := reason.(string); !ok {
			return fmt.Errorf("invalid type for %q[%d]: expected string, got %T (%v)", "reasons", i, reason, reason)
		}
	}
	return nil
}

// WriteResultFile atomically writes r as canonical THREAT_DETECTION_RESULT JSON
// to path (temp file in the same dir + rename), with 0o600 permissions.
func WriteResultFile(path string, r *Result) error {
	if r == nil {
		return fmt.Errorf("cannot write nil result")
	}
	if r.Reasons == nil {
		r.Reasons = []string{}
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling result: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".threat-detect-result-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp result file: %w", err)
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("setting result file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing result file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing result file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming result file: %w", err)
	}
	return nil
}

// ReadResultFile reads path and parses it with ParseStructuredResult, returning
// a validated *Result. Returns an error if the file is missing, empty, or invalid.
func ReadResultFile(path string) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("result file %q is empty", path)
	}
	return ParseStructuredResult(data)
}

// BuildResultFromReport constructs a *Result from individual report fields.
// reasons may be nil; it is normalized to a non-nil empty slice.
func BuildResultFromReport(promptInjection, secretLeak, maliciousPatch bool, reasons []string) *Result {
	if reasons == nil {
		reasons = []string{}
	}
	return &Result{
		PromptInjection: promptInjection,
		SecretLeak:      secretLeak,
		MaliciousPatch:  maliciousPatch,
		Reasons:         reasons,
	}
}

// ValidateReportFields validates a report payload using the same rules as
// validateRawResult and returns a single bounded, human-readable error string
// suitable for feeding back to the model (already passed through
// TruncateCorrectionMessage). Returns "" when valid.
func ValidateReportFields(promptInjection, secretLeak, maliciousPatch any, reasons any) string {
	raw := map[string]any{
		"prompt_injection": promptInjection,
		"secret_leak":      secretLeak,
		"malicious_patch":  maliciousPatch,
		"reasons":          reasons,
	}
	if err := validateRawResult(raw, "report payload"); err != nil {
		return TruncateCorrectionMessage(err.Error())
	}
	return ""
}

func resultFromRaw(raw map[string]any) *Result {
	result := &Result{
		PromptInjection: raw["prompt_injection"].(bool),
		SecretLeak:      raw["secret_leak"].(bool),
		MaliciousPatch:  raw["malicious_patch"].(bool),
		Reasons:         []string{},
	}
	if reasons, ok := raw["reasons"].([]any); ok {
		for _, r := range reasons {
			if reason, ok := r.(string); ok {
				result.Reasons = append(result.Reasons, reason)
			}
		}
	}
	return result
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
