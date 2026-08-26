package detector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseStructuredResult_WarningsOptional verifies that a result without a
// `warnings` field parses successfully — backward compatibility with pre-#954
// results is required so an older detector's output remains readable and the
// field remains additive rather than a breaking change.
func TestParseStructuredResult_WarningsOptional(t *testing.T) {
	// Pre-warnings shape must still parse.
	r, err := ParseStructuredResult([]byte(`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`))
	if err != nil {
		t.Fatalf("expected pre-warnings result to parse, got: %v", err)
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("expected empty warnings, got %#v", r.Warnings)
	}
}

func TestParseStructuredResult_WarningsShape(t *testing.T) {
	good := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":"comment_memory","code":"ERR_VALIDATION","message":"Unable to read comment-memory directory at /tmp/x: permission denied"}]}`
	r, err := ParseStructuredResult([]byte(good))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Warnings) != 1 || r.Warnings[0].Field != "comment_memory" || r.Warnings[0].Code != "ERR_VALIDATION" {
		t.Fatalf("warnings not parsed: %#v", r.Warnings)
	}

	cases := map[string]string{
		"non-array warnings":    `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":"nope"}`,
		"non-object entry":      `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":["x"]}`,
		"missing field":         `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"code":"c","message":"m"}]}`,
		"missing code":          `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":"f","message":"m"}]}`,
		"missing message":       `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":"f","code":"c"}]}`,
		"unexpected key":        `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":"f","code":"c","message":"m","extra":true}]}`,
		"empty message":         `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":"f","code":"c","message":""}]}`,
		"whitespace-only field": `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":" ","code":"c","message":"m"}]}`,
		"non-string field":      `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":1,"code":"c","message":"m"}]}`,
	}
	for name, payload := range cases {
		if _, err := ParseStructuredResult([]byte(payload)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseStructuredResult_WarningsBounds(t *testing.T) {
	buildWarnings := func(n int) string {
		entries := make([]string, n)
		for i := range entries {
			entries[i] = `{"field":"f","code":"c","message":"m"}`
		}
		return strings.Join(entries, ",")
	}
	ok := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[` + buildWarnings(MaxWarnings) + `]}`
	if _, err := ParseStructuredResult([]byte(ok)); err != nil {
		t.Fatalf("MaxWarnings must be accepted: %v", err)
	}
	bad := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[` + buildWarnings(MaxWarnings+1) + `]}`
	if _, err := ParseStructuredResult([]byte(bad)); err == nil {
		t.Fatal("MaxWarnings+1 must be rejected")
	}

	overMessage := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":"f","code":"c","message":"` + strings.Repeat("x", MaxWarningMessageRunes+1) + `"}]}`
	if _, err := ParseStructuredResult([]byte(overMessage)); err == nil {
		t.Fatal("over-long message must be rejected")
	}
	overField := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"warnings":[{"field":"` + strings.Repeat("f", MaxWarningFieldRunes+1) + `","code":"c","message":"m"}]}`
	if _, err := ParseStructuredResult([]byte(overField)); err == nil {
		t.Fatal("over-long field must be rejected")
	}
}

// TestWriteResultFile_WarningsRoundTrip verifies that Warnings survive an
// atomic write and round-trip read unchanged.
func TestWriteResultFile_WarningsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "detection_result.json")
	want := &Result{
		SecretLeak: false,
		Reasons:    []string{},
		Warnings: []ResultWarning{
			{Field: "comment_memory", Code: "ERR_VALIDATION", Message: "Unable to read comment-memory directory at /tmp/x: permission denied"},
			{Field: "patch", Code: "ERR_VALIDATION", Message: "HAS_PATCH=true but no readable patch file found in /tmp/y"},
		},
	}
	if err := WriteResultFile(path, want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadResultFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Warnings) != 2 || got.Warnings[0].Field != "comment_memory" || got.Warnings[1].Field != "patch" {
		t.Fatalf("warnings did not round trip: %#v", got.Warnings)
	}
}

// TestRedacted_PreservesWarnings verifies that warnings survive redaction and
// appear on the uploaded result — the whole point of warnings (vs reasons) is
// that they are safe to publish so a partially-inspected bundle is visible to
// a host programmatically, not only in job-log annotations.
func TestRedacted_PreservesWarnings(t *testing.T) {
	orig := &Result{
		PromptInjection: true,
		Reasons:         []string{"why"},
		Warnings: []ResultWarning{
			{Field: "comment_memory", Code: "ERR_VALIDATION", Message: "m"},
		},
	}
	red := orig.Redacted()
	if len(red.Reasons) != 0 {
		t.Fatal("Redacted must drop reasons")
	}
	if len(red.Warnings) != 1 || red.Warnings[0].Field != "comment_memory" {
		t.Fatalf("Redacted must preserve warnings: %#v", red.Warnings)
	}
}

// TestWriteResultFile_RedactedWarningsShapeOnUpload verifies the uploaded
// result carries `warnings` as a JSON array (not null, not missing), so a
// host consumer can always index into the field without a null check.
func TestWriteResultFile_EmptyWarningsSerializeAsArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "detection_result.json")
	if err := WriteResultFile(path, &Result{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	w, ok := raw["warnings"]
	if !ok {
		t.Fatal("warnings field must always be present")
	}
	if string(w) != "[]" {
		t.Fatalf("empty warnings must be serialized as []; got %s", string(w))
	}
}
