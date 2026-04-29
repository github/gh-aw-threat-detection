package detector

import (
	"testing"
)

func TestParseResult_Safe(t *testing.T) {
	output := `Some analysis text here...
THREAT_DETECTION_RESULT:{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}
Done.`

	result, err := ParseResult(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasThreats() {
		t.Error("expected no threats")
	}
	if result.PromptInjection {
		t.Error("expected prompt_injection=false")
	}
	if result.SecretLeak {
		t.Error("expected secret_leak=false")
	}
	if result.MaliciousPatch {
		t.Error("expected malicious_patch=false")
	}
}

func TestParseResult_ThreatDetected(t *testing.T) {
	output := `THREAT_DETECTION_RESULT:{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["Found injection attempt in prompt"]}`

	result, err := ParseResult(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasThreats() {
		t.Error("expected threats detected")
	}
	if !result.PromptInjection {
		t.Error("expected prompt_injection=true")
	}
	if len(result.Reasons) != 1 {
		t.Fatalf("expected 1 reason, got %d", len(result.Reasons))
	}
	if result.Reasons[0] != "Found injection attempt in prompt" {
		t.Errorf("unexpected reason: %s", result.Reasons[0])
	}
}

func TestParseResult_MultipleThreats(t *testing.T) {
	output := `THREAT_DETECTION_RESULT:{"prompt_injection":true,"secret_leak":true,"malicious_patch":true,"reasons":["injection","leak","backdoor"]}`

	result, err := ParseResult(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.PromptInjection {
		t.Error("expected prompt_injection=true")
	}
	if !result.SecretLeak {
		t.Error("expected secret_leak=true")
	}
	if !result.MaliciousPatch {
		t.Error("expected malicious_patch=true")
	}
	if len(result.Reasons) != 3 {
		t.Fatalf("expected 3 reasons, got %d", len(result.Reasons))
	}
}

func TestParseResult_StreamJSON(t *testing.T) {
	output := `{"type":"result","result":"Some analysis...\nTHREAT_DETECTION_RESULT:{\"prompt_injection\":false,\"secret_leak\":false,\"malicious_patch\":false,\"reasons\":[]}"}`

	result, err := ParseResult(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasThreats() {
		t.Error("expected no threats")
	}
}

func TestParseResult_NoResult(t *testing.T) {
	output := "Just some random output with no result marker"

	_, err := ParseResult(output)
	if err == nil {
		t.Fatal("expected error for missing result")
	}
}

func TestParseResult_InvalidJSON(t *testing.T) {
	output := "THREAT_DETECTION_RESULT:{invalid json}"

	_, err := ParseResult(output)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseResult_NonBooleanField(t *testing.T) {
	output := `THREAT_DETECTION_RESULT:{"prompt_injection":"false","secret_leak":false,"malicious_patch":false,"reasons":[]}`

	_, err := ParseResult(output)
	if err == nil {
		t.Fatal("expected error for non-boolean field")
	}
}

func TestParseResult_DuplicateResults(t *testing.T) {
	// Same result appearing multiple times (from tee + debug-file) should be deduplicated
	output := `THREAT_DETECTION_RESULT:{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}
THREAT_DETECTION_RESULT:{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`

	result, err := ParseResult(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasThreats() {
		t.Error("expected no threats")
	}
}

func TestParseResult_ConflictingResults(t *testing.T) {
	output := `THREAT_DETECTION_RESULT:{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}
THREAT_DETECTION_RESULT:{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["conflict"]}`

	_, err := ParseResult(output)
	if err == nil {
		t.Fatal("expected error for conflicting results")
	}
}

func TestParseResult_MissingField(t *testing.T) {
	output := `THREAT_DETECTION_RESULT:{"prompt_injection":false,"secret_leak":false,"reasons":[]}`

	_, err := ParseResult(output)
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestExtractResultFromText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple",
			input:    `THREAT_DETECTION_RESULT:{"a":true}`,
			expected: `THREAT_DETECTION_RESULT:{"a":true}`,
		},
		{
			name:     "nested braces",
			input:    `THREAT_DETECTION_RESULT:{"a":{"b":1}}`,
			expected: `THREAT_DETECTION_RESULT:{"a":{"b":1}}`,
		},
		{
			name:     "braces in string",
			input:    `THREAT_DETECTION_RESULT:{"a":"val{ue}"}`,
			expected: `THREAT_DETECTION_RESULT:{"a":"val{ue}"}`,
		},
		{
			name:     "escaped quotes",
			input:    `THREAT_DETECTION_RESULT:{"a":"val\"ue"}`,
			expected: `THREAT_DETECTION_RESULT:{"a":"val\"ue"}`,
		},
		{
			name:     "no json",
			input:    `THREAT_DETECTION_RESULT:`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractResultFromText(tt.input)
			if got != tt.expected {
				t.Errorf("extractResultFromText(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
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
