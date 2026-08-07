package detector

import (
	"strings"
	"testing"
)

func TestIsToolingFailureReason(t *testing.T) {
	tests := map[string]bool{
		ReasonAgentFailure:   true,
		ReasonParseError:     true,
		" agent_failure ":    true,
		ReasonThreatDetected: false,
		"":                   false,
		"something_else":     false,
	}
	for reason, want := range tests {
		if got := IsToolingFailureReason(reason); got != want {
			t.Errorf("IsToolingFailureReason(%q) = %v, want %v", reason, got, want)
		}
	}
}

func TestThreatHeadline(t *testing.T) {
	if got := ThreatHeadline(ReasonAgentFailure); got == "" || !strings.Contains(got, "tooling failure, not a security finding") {
		t.Errorf("ThreatHeadline(agent_failure) = %q, want tooling-failure copy", got)
	}
	if got := ThreatHeadline(ReasonThreatDetected); got == "" || !strings.Contains(got, "Agentic threat detected") {
		t.Errorf("ThreatHeadline(threat_detected) = %q, want threat copy", got)
	}
	if got := ThreatHeadline(""); got != "" {
		t.Errorf("ThreatHeadline(\"\") = %q, want empty", got)
	}
}
