package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseStructuredResult_Strict(t *testing.T) {
	result, err := ParseStructuredResult([]byte(`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsSafe() {
		t.Fatal("expected safe result")
	}

	if _, err := ParseStructuredResult([]byte(`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[],"extra":true}`)); err == nil {
		t.Fatal("expected extra field error")
	}
	if _, err := ParseStructuredResult([]byte(`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[1]}`)); err == nil {
		t.Fatal("expected non-string reason error")
	}
}

func TestResult_HasThreats(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   bool
	}{
		{"all false", Result{}, false},
		{"prompt injection", Result{PromptInjection: true}, true},
		{"secret leak", Result{SecretLeak: true}, true},
		{"malicious patch", Result{MaliciousPatch: true}, true},
		{"all true", Result{PromptInjection: true, SecretLeak: true, MaliciousPatch: true}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.HasThreats(); got != tt.want {
				t.Errorf("HasThreats() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseStructuredResult_ReasonBounds(t *testing.T) {
	build := func(reasons string) []byte {
		return []byte(`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[` + reasons + `]}`)
	}

	tests := []struct {
		name    string
		reasons string
		wantErr bool
	}{
		{"single reason", `"looks fine"`, false},
		{"max length reason", `"` + strings.Repeat("x", MaxReasonRunes) + `"`, false},
		{"max count reasons", strings.TrimSuffix(strings.Repeat(`"r",`, MaxReasons), ","), false},
		{"empty reason", `""`, true},
		{"whitespace-only reason", `" \t "`, true},
		{"over-long reason", `"` + strings.Repeat("x", MaxReasonRunes+1) + `"`, true},
		{"too many reasons", strings.TrimSuffix(strings.Repeat(`"r",`, MaxReasons+1), ","), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseStructuredResult(build(tt.reasons))
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %s: %v", tt.name, err)
			}
		})
	}
}

func TestParseStructuredResult_ReasonRunesCountedAsRunes(t *testing.T) {
	// MaxReasonRunes bounds characters, not bytes: a multi-byte reason at the
	// limit must be accepted even though its byte length exceeds the limit.
	data := []byte(`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":["` +
		strings.Repeat("é", MaxReasonRunes) + `"]}`)
	if _, err := ParseStructuredResult(data); err != nil {
		t.Fatalf("unexpected error for multi-byte reason at the rune limit: %v", err)
	}
}

func TestReadResultFile_RejectsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detection_result.json")
	// A syntactically valid but oversized file must be rejected on size before
	// it is parsed, so a hostile file cannot be read into memory in full.
	payload := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":["` +
		strings.Repeat("x", MaxResultFileBytes) + `"]}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("writing oversize result file: %v", err)
	}
	_, err := ReadResultFile(path)
	if err == nil {
		t.Fatal("expected oversize result file to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds the maximum size") {
		t.Fatalf("expected size error, got: %v", err)
	}
}

func TestReadResultFile_RoundTripsWrittenResult(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detection_result.json")
	// Every result the detector writes must pass its own read-side validation.
	want := BuildResultFromReport(true, false, false, []string{"injected instruction in issue body"})
	if err := WriteResultFile(path, want); err != nil {
		t.Fatalf("writing result: %v", err)
	}
	got, err := ReadResultFile(path)
	if err != nil {
		t.Fatalf("reading back written result: %v", err)
	}
	if !got.HasThreats() || len(got.Reasons) != 1 || got.Reasons[0] != want.Reasons[0] {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestValidateReportFields_BoundsReasons(t *testing.T) {
	if msg := ValidateReportFields(false, false, false, []any{"  "}); msg == "" {
		t.Fatal("expected whitespace-only reason to be rejected at report time")
	}
	if msg := ValidateReportFields(true, false, false, []any{"real reason"}); msg != "" {
		t.Fatalf("unexpected rejection: %s", msg)
	}
}
