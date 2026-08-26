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
	// MaxReasonRunes is the maximum length of a single reason. Reasons must
	// carry enough forensic detail to locate a finding — artifact, position,
	// verbatim trigger text, provenance, remediation — but are still
	// explanations, not transcripts or embedded artifacts.
	MaxReasonRunes = 2000
	// MaxResultFileBytes caps how much of a result file is read before parsing.
	// It is far above any schema-valid result (MaxReasons × MaxReasonRunes plus
	// JSON overhead) yet bounds memory for a corrupt or hostile file.
	MaxResultFileBytes = 1 << 20 // 1 MiB
	// MaxWarnings is the maximum number of entries allowed in `warnings`. Each
	// entry describes an artifact channel that could not be inspected; the
	// artifact set the detector recognizes is small enough that a handful is
	// generous. Bounded here so a hostile or corrupt result file cannot embed
	// unbounded diagnostic text.
	MaxWarnings = 20
	// MaxWarningFieldRunes bounds the `field` identifier (e.g. "prompt",
	// "agent_output"). It is a short symbolic name, not free text.
	MaxWarningFieldRunes = 64
	// MaxWarningCodeRunes bounds the `code` identifier (e.g. "ERR_VALIDATION").
	MaxWarningCodeRunes = 64
	// MaxWarningMessageRunes bounds the human-readable warning message. The
	// message embeds host-controlled paths, so it may be long, but must remain
	// a diagnostic line rather than an unbounded transcript.
	MaxWarningMessageRunes = 2000
)

// ResultWarning describes a single detector-authored warning: a structural
// finding about the input the detector could not fully inspect (e.g. an
// unreadable `comment-memory` directory, or a `HAS_PATCH=true` bundle that was
// absent). Warnings are assembled by the detector from Artifacts.Warnings and
// attached on write; the model never authors or influences them.
//
// Warnings MUST NOT affect the verdict or the exit code. A warning says "the
// detector could not inspect everything", not "a threat was found". Warnings
// are safe to publish in the uploaded result (unlike `reasons`, which is
// model-authored text that only lives in the full result).
type ResultWarning struct {
	// Field identifies the artifact channel the warning concerns (e.g.
	// "prompt", "agent_output", "patch", "comment_memory").
	Field string `json:"field"`
	// Code is a short, stable identifier categorizing the warning (e.g.
	// "ERR_VALIDATION"), matching the code already surfaced in
	// GitHub Actions annotations.
	Code string `json:"code"`
	// Message is the human-readable diagnostic. It may embed host-controlled
	// paths and other fixed strings composed by the detector; it never carries
	// model-authored text.
	Message string `json:"message"`
}

// Result represents the structured output of threat detection analysis.
type Result struct {
	PromptInjection bool            `json:"prompt_injection"`
	SecretLeak      bool            `json:"secret_leak"`
	MaliciousPatch  bool            `json:"malicious_patch"`
	Reasons         []string        `json:"reasons"`
	Warnings        []ResultWarning `json:"warnings"`
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

// FullResultSuffix is appended to the stem of a result path to derive the
// companion full-result path (detection_result.json -> detection_result_full.json).
const FullResultSuffix = "_full"

// Redacted returns a copy of r with the model-authored reasons removed. The
// `reasons` key is retained as an empty array rather than dropped, so the
// redacted result remains schema-valid under TD-10a and every existing reader
// parses it unchanged.
//
// Warnings are detector-authored and safe to publish, so they are preserved
// unchanged on the redacted copy: partial-inspection failures must remain
// visible on the uploaded result, not confined to the runner-local full result.
func (r *Result) Redacted() *Result {
	if r == nil {
		return nil
	}
	out := *r
	out.Reasons = []string{}
	return &out
}

// SameVerdict reports whether r and other agree on all three threat booleans.
// It deliberately ignores `reasons`: it is the check that lets a companion full
// result contribute its reasons only when it describes the same verdict.
func (r *Result) SameVerdict(other *Result) bool {
	if r == nil || other == nil {
		return false
	}
	return r.PromptInjection == other.PromptInjection &&
		r.SecretLeak == other.SecretLeak &&
		r.MaliciousPatch == other.MaliciousPatch
}

// FullResultPath derives the companion full-result path for a result file path
// by inserting FullResultSuffix before the extension. It returns "" for an empty
// input so callers can use it directly for a "no result file configured" case.
func FullResultPath(resultPath string) string {
	if resultPath == "" {
		return ""
	}
	dir, base := filepath.Split(resultPath)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	// A dotfile with no extension (".detection_result") must not have its whole
	// name treated as the extension, which would produce a bare "_full" name.
	if stem == "" {
		stem = base
		ext = ""
	}
	return dir + stem + FullResultSuffix + ext
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
		case "prompt_injection", "secret_leak", "malicious_patch", "reasons", "warnings":
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
	// warnings is optional — a result without the field is a well-formed
	// warning-free result. When present it must be an array of objects with
	// the three required string fields, bounded identically to reasons so no
	// result accepted on write can be rejected on read.
	if warnings, exists := raw["warnings"]; exists {
		warningsArr, ok := warnings.([]any)
		if !ok {
			return fmt.Errorf("invalid type for %q: expected array, got %T (%v)", "warnings", warnings, warnings)
		}
		if len(warningsArr) > MaxWarnings {
			return fmt.Errorf("too many entries in %q: got %d, maximum is %d", "warnings", len(warningsArr), MaxWarnings)
		}
		for i, entry := range warningsArr {
			obj, ok := entry.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid type for %q[%d]: expected object, got %T (%v)", "warnings", i, entry, entry)
			}
			for key := range obj {
				switch key {
				case "field", "code", "message":
				default:
					return fmt.Errorf("unexpected field %q in %q[%d]", key, "warnings", i)
				}
			}
			if err := validateWarningStringField(obj, "field", i, MaxWarningFieldRunes); err != nil {
				return err
			}
			if err := validateWarningStringField(obj, "code", i, MaxWarningCodeRunes); err != nil {
				return err
			}
			if err := validateWarningStringField(obj, "message", i, MaxWarningMessageRunes); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateWarningStringField(obj map[string]any, key string, index, maxRunes int) error {
	val, exists := obj[key]
	if !exists {
		return fmt.Errorf("missing required field %q in %q[%d]", key, "warnings", index)
	}
	text, ok := val.(string)
	if !ok {
		return fmt.Errorf("invalid type for %q[%d].%q: expected string, got %T (%v)", "warnings", index, key, val, val)
	}
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("invalid value for %q[%d].%q: must not be empty or whitespace-only", "warnings", index, key)
	}
	if n := utf8.RuneCountInString(text); n > maxRunes {
		return fmt.Errorf("invalid value for %q[%d].%q: %d characters, maximum is %d", "warnings", index, key, n, maxRunes)
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
	if out.Warnings == nil {
		out.Warnings = []ResultWarning{}
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

// ReadReasonsFile reads path and parses it as a JSON array of reason strings.
//
// This is the shell-free transport for reasons. Reasons quote attacker-authored
// artifact content verbatim, and the detection engine reports its verdict by
// running the threat_detection_result wrapper through a shell — so evidence
// passed as a `--reason` argument would be subject to shell expansion
// (`$(...)`, backticks, quoting) before the tool ever received it. Routing that
// text through a file the engine writes with its file-editing tool keeps it out
// of any command line, and a malformed file is a correctable parse error rather
// than an executed command.
//
// Only the element types are validated here; the count and per-entry bounds are
// applied by validateRawResult so every transport is bounded identically.
func ReadReasonsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading reasons file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxResultFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading reasons file %q: %w", path, err)
	}
	if int64(len(data)) > MaxResultFileBytes {
		return nil, fmt.Errorf("reasons file %q exceeds the maximum size of %d bytes", path, MaxResultFileBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("reasons file %q is empty; it must contain a JSON array of reason strings", path)
	}
	var raw []any
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("reasons file %q must contain a JSON array of strings: %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("reasons file %q must contain exactly one JSON array", path)
	}
	reasons := make([]string, 0, len(raw))
	for i, entry := range raw {
		text, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf("invalid type for reasons file entry [%d]: expected string, got %T (%v)", i, entry, entry)
		}
		reasons = append(reasons, text)
	}
	return reasons, nil
}

// BuildResultFromReport constructs a *Result from individual report fields.
// reasons may be nil; it is normalized to a non-nil empty slice. Warnings are
// not part of the model's report and are always initialized empty here; the
// detector attaches them from Artifacts.Warnings at write time.
func BuildResultFromReport(promptInjection, secretLeak, maliciousPatch bool, reasons []string) *Result {
	if reasons == nil {
		reasons = []string{}
	}
	return &Result{
		PromptInjection: promptInjection,
		SecretLeak:      secretLeak,
		MaliciousPatch:  maliciousPatch,
		Reasons:         reasons,
		Warnings:        []ResultWarning{},
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
		Warnings:        []ResultWarning{},
	}
	if reasons, ok := raw["reasons"].([]any); ok {
		for _, r := range reasons {
			if reason, ok := r.(string); ok {
				result.Reasons = append(result.Reasons, reason)
			}
		}
	}
	if warnings, ok := raw["warnings"].([]any); ok {
		for _, w := range warnings {
			obj, ok := w.(map[string]any)
			if !ok {
				continue
			}
			field, _ := obj["field"].(string)
			code, _ := obj["code"].(string)
			message, _ := obj["message"].(string)
			result.Warnings = append(result.Warnings, ResultWarning{
				Field:   field,
				Code:    code,
				Message: message,
			})
		}
	}
	return result
}
