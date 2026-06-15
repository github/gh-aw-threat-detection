package detector

import (
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
