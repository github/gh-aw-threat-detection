package detector

import (
	"strings"
	"testing"
)

func TestParseUsageClaudeStreamJSON(t *testing.T) {
	// Claude stream-json emits a final result line carrying nested usage and
	// total_cost_usd, plus assistant events with cumulative usage.
	transcript := strings.Join([]string{
		`{"type":"assistant","message":{"usage":{"input_tokens":1200,"output_tokens":80}}}`,
		`{"type":"result","total_cost_usd":0.0123,"usage":{"input_tokens":1500,"output_tokens":300,"cache_read_input_tokens":200}}`,
	}, "\n")

	tokens, cost := ParseUsage(transcript)
	if want := 1500 + 300 + 200; tokens != want {
		t.Fatalf("tokens = %d, want %d", tokens, want)
	}
	if cost != 0.0123 {
		t.Fatalf("cost = %v, want 0.0123", cost)
	}
}

func TestParseUsageCodexTextual(t *testing.T) {
	transcript := strings.Join([]string{
		"[2026-06-16T00:00:00] thinking",
		"tokens used: 13934",
		"TokenCount(TokenCountEvent { total_tokens: 13281 })",
	}, "\n")

	tokens, cost := ParseUsage(transcript)
	if tokens != 13934 {
		t.Fatalf("tokens = %d, want 13934 (largest counter)", tokens)
	}
	if cost != 0 {
		t.Fatalf("cost = %v, want 0", cost)
	}
}

func TestParseUsageOpenAIUsageShape(t *testing.T) {
	transcript := `noise {"usage":{"prompt_tokens":100,"completion_tokens":50}} trailing`
	tokens, _ := ParseUsage(transcript)
	if tokens != 150 {
		t.Fatalf("tokens = %d, want 150", tokens)
	}
}

func TestParseUsageTopLevelCostAndTokens(t *testing.T) {
	transcript := `{"tokens":500,"billing":{"total_cost_usd":0.12}}`
	tokens, cost := ParseUsage(transcript)
	if tokens != 500 {
		t.Fatalf("tokens = %d, want 500", tokens)
	}
	if cost != 0.12 {
		t.Fatalf("cost = %v, want 0.12", cost)
	}
}

func TestParseUsageNoUsage(t *testing.T) {
	tokens, cost := ParseUsage("just some plain copilot log output\nno json here")
	if tokens != 0 || cost != 0 {
		t.Fatalf("tokens=%d cost=%v, want 0/0", tokens, cost)
	}
}
