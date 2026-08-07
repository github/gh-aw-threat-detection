package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Bounds on the free-text portion of the result contract. The three boolean
// fields are fully constrained by their type, but `reasons` is model-authored
// open text that flows into job logs, workflow commands, and the run log, so it
// is bounded on both the reporting and the reading side.
const (
	// MaxReasons is the maximum number of entries allowed in `reasons`. Three
	// threat categories never need more than a handful of explanations.
	MaxReasons = 20
	// MaxReasonRunes is the maximum length of a single reason. Reasons are
	// human-readable explanations, not transcripts or embedded artifacts.
	MaxReasonRunes = 1000
	// MaxResultFileBytes caps how much of a result file is read before parsing.
	// It is far above any schema-valid result (MaxReasons × MaxReasonRunes plus
	// JSON overhead) yet bounds memory for a corrupt or hostile file.
	MaxResultFileBytes = 1 << 20 // 1 MiB
)

// Result represents the structured output of threat detection analysis.
type Result struct {
	PromptInjection bool     `json:"prompt_injection"`
	SecretLeak      bool     `json:"secret_leak"`
	MaliciousPatch  bool     `json:"malicious_patch"`
	Reasons         []string `json:"reasons"`
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

// ParseStructuredResult parses a strict JSON object containing exactly the
// prompt_injection, secret_leak, malicious_patch, and reasons fields.
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
	if len(reasonsArr) > MaxReasons {
		return fmt.Errorf("too many entries in %q: got %d, maximum is %d", "reasons", len(reasonsArr), MaxReasons)
	}
	for i, reason := range reasonsArr {
		text, ok := reason.(string)
		if !ok {
			return fmt.Errorf("invalid type for %q[%d]: expected string, got %T (%v)", "reasons", i, reason, reason)
		}
		if strings.TrimSpace(text) == "" {
			return fmt.Errorf("invalid value for %q[%d]: reason must not be empty or whitespace-only", "reasons", i)
		}
		if n := utf8.RuneCountInString(text); n > MaxReasonRunes {
			return fmt.Errorf("invalid value for %q[%d]: reason is %d characters, maximum is %d", "reasons", i, n, MaxReasonRunes)
		}
	}
	return nil
}

// WriteResultFile atomically writes r as canonical THREAT_DETECTION_RESULT JSON
// to path (temp file in the same dir + rename), with 0o600 permissions.
//
// The marshaled bytes are validated against the same rules ReadResultFile
// applies before any file is created, so a result that would not survive being
// read back is rejected at the source rather than persisted as an unreadable
// file. Validating the canonical JSON — rather than the in-memory struct —
// makes the guarantee exact: what is checked is byte-for-byte what a reader
// would parse.
func WriteResultFile(path string, r *Result) error {
	if r == nil {
		return fmt.Errorf("cannot write nil result")
	}
	// Copy before normalizing so we don't mutate the caller-provided Result.
	out := *r
	if out.Reasons == nil {
		out.Reasons = []string{}
	}
	data, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling result: %w", err)
	}
	if int64(len(data)) > MaxResultFileBytes {
		return fmt.Errorf("refusing to write result: encoded result is %d bytes, exceeding the maximum of %d", len(data), MaxResultFileBytes)
	}
	if _, err := ParseStructuredResult(data); err != nil {
		return fmt.Errorf("refusing to write result that could not be read back: %w", err)
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
// a validated *Result. Returns an error if the file is missing, empty, larger
// than MaxResultFileBytes, or invalid.
func ReadResultFile(path string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Read one byte past the cap so an oversized file is rejected rather than
	// silently truncated into a parse error that hides the real cause.
	data, err := io.ReadAll(io.LimitReader(f, MaxResultFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxResultFileBytes {
		return nil, fmt.Errorf("result file %q exceeds the maximum size of %d bytes", path, MaxResultFileBytes)
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
