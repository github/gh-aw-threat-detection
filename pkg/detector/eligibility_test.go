package detector

import (
	"strings"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

func TestComputeEligibility(t *testing.T) {
	tests := []struct {
		name     string
		arts     *artifacts.Artifacts
		analysis *PromptAnalysis
		want     Eligibility
	}{
		{
			name:     "nil inputs yield all-false",
			arts:     nil,
			analysis: nil,
			want:     Eligibility{},
		},
		{
			name: "untrusted input enables prompt_injection",
			arts: &artifacts.Artifacts{},
			analysis: &PromptAnalysis{
				UntrustedInputs: []UntrustedInput{
					{Placeholder: "{{issue_body}}", Content: "hello"},
				},
			},
			want: Eligibility{PromptInjection: true},
		},
		{
			name: "whitespace-only untrusted input does not enable prompt_injection",
			arts: &artifacts.Artifacts{},
			analysis: &PromptAnalysis{
				UntrustedInputs: []UntrustedInput{
					{Placeholder: "{{issue_body}}", Content: "   \n\t "},
				},
			},
			want: Eligibility{},
		},
		{
			name:     "agent output enables secret_leak but not malicious_patch",
			arts:     &artifacts.Artifacts{AgentOutputFileSize: 42},
			analysis: &PromptAnalysis{},
			want:     Eligibility{SecretLeak: true},
		},
		{
			name:     "patch enables both secret_leak and malicious_patch",
			arts:     &artifacts.Artifacts{PatchFiles: []string{"aw-1.patch"}},
			analysis: &PromptAnalysis{},
			want:     Eligibility{SecretLeak: true, MaliciousPatch: true},
		},
		{
			name: "everything present",
			arts: &artifacts.Artifacts{
				AgentOutputFileSize: 1,
				PatchFiles:          []string{"aw-1.patch"},
			},
			analysis: &PromptAnalysis{
				UntrustedInputs: []UntrustedInput{{Placeholder: "{{x}}", Content: "y"}},
			},
			want: Eligibility{PromptInjection: true, SecretLeak: true, MaliciousPatch: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeEligibility(tt.arts, tt.analysis)
			if got != tt.want {
				t.Fatalf("ComputeEligibility() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEligibilityEnvRoundTrip(t *testing.T) {
	e := Eligibility{PromptInjection: true, SecretLeak: false, MaliciousPatch: true}
	for _, kv := range e.Env() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			t.Fatalf("malformed env entry: %q", kv)
		}
		t.Setenv(parts[0], parts[1])
	}
	got := EligibilityFromEnv()
	if got != e {
		t.Fatalf("EligibilityFromEnv() = %+v, want %+v", got, e)
	}
}

func TestEligibilityFromEnvUnsetIsPermissive(t *testing.T) {
	// Unset the vars; a caller that didn't opt in must not be tightened.
	t.Setenv(envEligiblePromptInjection, "")
	t.Setenv(envEligibleSecretLeak, "")
	t.Setenv(envEligibleMaliciousPatch, "")
	got := EligibilityFromEnv()
	want := Eligibility{PromptInjection: true, SecretLeak: true, MaliciousPatch: true}
	if got != want {
		t.Fatalf("unset env should be permissive; got %+v want %+v", got, want)
	}
}

func TestEligibilityFromEnvUnparseableIsPermissive(t *testing.T) {
	t.Setenv(envEligiblePromptInjection, "not-a-bool")
	got := EligibilityFromEnv()
	if !got.PromptInjection {
		t.Fatalf("unparseable value should default to true; got %+v", got)
	}
}

func TestEligibilityValidate(t *testing.T) {
	tests := []struct {
		name            string
		e               Eligibility
		promptInjection bool
		secretLeak      bool
		maliciousPatch  bool
		wantEmpty       bool
		wantContains    []string
	}{
		{
			name:            "all-false report is always valid",
			e:               Eligibility{},
			promptInjection: false, secretLeak: false, maliciousPatch: false,
			wantEmpty: true,
		},
		{
			name:            "eligible verdict passes",
			e:               Eligibility{PromptInjection: true, MaliciousPatch: true},
			promptInjection: true, maliciousPatch: true,
			wantEmpty: true,
		},
		{
			name:            "prompt_injection ineligible is rejected",
			e:               Eligibility{},
			promptInjection: true,
			wantContains:    []string{"--prompt-injection=true is not eligible"},
		},
		{
			name:           "malicious_patch ineligible is rejected",
			e:              Eligibility{},
			maliciousPatch: true,
			wantContains:   []string{"--malicious-patch=true is not eligible", "no .patch or .bundle file"},
		},
		{
			name:            "multiple ineligible claims are joined",
			e:               Eligibility{},
			promptInjection: true, maliciousPatch: true,
			wantContains: []string{"--prompt-injection=true is not eligible", "--malicious-patch=true is not eligible"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.e.Validate(tt.promptInjection, tt.secretLeak, tt.maliciousPatch)
			if tt.wantEmpty {
				if got != "" {
					t.Fatalf("Validate() = %q, want empty", got)
				}
				return
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Fatalf("Validate() = %q, want substring %q", got, want)
				}
			}
		})
	}
}
