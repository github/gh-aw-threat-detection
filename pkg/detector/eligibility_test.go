package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

func TestComputeEligibility(t *testing.T) {
	// A non-degraded analysis: the prompt template artifact was available, so
	// an empty UntrustedInputs list genuinely means "no untrusted content".
	withTemplate := func(inputs ...UntrustedInput) *PromptAnalysis {
		return &PromptAnalysis{PromptTemplate: "template body", UntrustedInputs: inputs}
	}

	tests := []struct {
		name     string
		arts     *artifacts.Artifacts
		analysis *PromptAnalysis
		want     Eligibility
	}{
		{
			name:     "nil analysis is degraded so prompt_injection is permitted",
			arts:     nil,
			analysis: nil,
			want:     Eligibility{PromptInjection: true},
		},
		{
			name:     "no untrusted content with a template yields all-false",
			arts:     &artifacts.Artifacts{},
			analysis: withTemplate(),
			want:     Eligibility{},
		},
		{
			name:     "missing template is degraded so prompt_injection is permitted",
			arts:     &artifacts.Artifacts{},
			analysis: &PromptAnalysis{},
			want:     Eligibility{PromptInjection: true},
		},
		{
			name:     "untrusted input enables prompt_injection",
			arts:     &artifacts.Artifacts{},
			analysis: withTemplate(UntrustedInput{Placeholder: "{{issue_body}}", Content: "hello"}),
			want:     Eligibility{PromptInjection: true},
		},
		{
			name:     "whitespace-only untrusted input does not enable prompt_injection",
			arts:     &artifacts.Artifacts{},
			analysis: withTemplate(UntrustedInput{Placeholder: "{{issue_body}}", Content: "   \n\t "}),
			want:     Eligibility{},
		},
		{
			name:     "comment memory enables prompt_injection and secret_leak",
			arts:     &artifacts.Artifacts{CommentMemoryFiles: []string{"comment-memory/a.md"}},
			analysis: withTemplate(),
			want:     Eligibility{PromptInjection: true, SecretLeak: true},
		},
		{
			name:     "agent output enables secret_leak but not malicious_patch",
			arts:     &artifacts.Artifacts{AgentOutputFileSize: 42},
			analysis: withTemplate(),
			want:     Eligibility{SecretLeak: true},
		},
		{
			name:     "patch enables both secret_leak and malicious_patch",
			arts:     &artifacts.Artifacts{PatchFiles: []string{"aw-1.patch"}},
			analysis: withTemplate(),
			want:     Eligibility{SecretLeak: true, MaliciousPatch: true},
		},
		{
			name: "everything present",
			arts: &artifacts.Artifacts{
				AgentOutputFileSize: 1,
				PatchFiles:          []string{"aw-1.patch"},
				CommentMemoryFiles:  []string{"comment-memory/a.md"},
			},
			analysis: withTemplate(UntrustedInput{Placeholder: "{{x}}", Content: "y"}),
			want:     Eligibility{PromptInjection: true, SecretLeak: true, MaliciousPatch: true},
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

func TestEligibilityValidateResult(t *testing.T) {
	e := Eligibility{PromptInjection: true}

	if msg := e.ValidateResult(nil); msg != "" {
		t.Fatalf("ValidateResult(nil) = %q, want empty", msg)
	}

	eligible := &Result{PromptInjection: true, Reasons: []string{"x"}}
	if msg := e.ValidateResult(eligible); msg != "" {
		t.Fatalf("ValidateResult(eligible) = %q, want empty", msg)
	}

	ineligible := &Result{MaliciousPatch: true, Reasons: []string{"x"}}
	msg := e.ValidateResult(ineligible)
	if !strings.Contains(msg, "--malicious-patch=true is not eligible") {
		t.Fatalf("ValidateResult(ineligible) = %q, want malicious-patch rejection", msg)
	}

	safe := &Result{Reasons: []string{}}
	if msg := (Eligibility{}).ValidateResult(safe); msg != "" {
		t.Fatalf("ValidateResult(all-false) = %q, want empty", msg)
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
			wantContains:   []string{"--malicious-patch=true is not eligible", "requires a patch or bundle file"},
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

// When every category is rejected at once the joined explanation is longer than
// the bound applied to untrusted correction feedback. It must still reach the
// model whole: a model told only that its verdict was rejected, without the
// reason for each category, cannot re-answer them.
func TestValidateMessageSurvivesCorrectionPrompt(t *testing.T) {
	msg := Eligibility{}.Validate(true, true, true)
	if msg == "" {
		t.Fatal("expected all three categories to be reported ineligible")
	}
	if len(msg) <= 512 {
		t.Fatalf("expected the combined message to exceed the untrusted-feedback bound, got %d bytes", len(msg))
	}

	built := BuildTrustedCorrectionPrompt("PROMPT", "rejected", msg, "instruction")
	if !strings.Contains(built, msg) {
		t.Error("trusted correction prompt truncated detector-authored feedback")
	}
	for _, flag := range []string{"--prompt-injection=true", "--secret-leak=true", "--malicious-patch=true"} {
		if !strings.Contains(built, flag) {
			t.Errorf("correction prompt lost the explanation for %s", flag)
		}
	}
	if strings.Contains(built, "(truncated)") {
		t.Error("trusted correction prompt should not carry a truncation marker")
	}
}

// Each of these bundles once made a category ineligible because an artifact
// could not be read or matched, which would let a staging failure suppress a
// real finding through the binding parent-side check. Eligibility must fail
// open on every one of them.
func TestComputeEligibilityFailsOpenOnDegradedProvenance(t *testing.T) {
	t.Run("rendered prompt unavailable while template is present", func(t *testing.T) {
		dir := t.TempDir()
		template := filepath.Join(dir, "prompt-template.txt")
		if err := os.WriteFile(template, []byte("static {{issue_body}} tail"), 0o600); err != nil {
			t.Fatal(err)
		}
		// PromptFilePath points nowhere, so extraction cannot run even though
		// the template is available and declares an untrusted placeholder.
		arts := &artifacts.Artifacts{
			PromptTemplatePath: template,
			PromptFilePath:     filepath.Join(dir, "absent-prompt.txt"),
		}
		analysis := BuildPromptAnalysis(arts)
		if !analysis.UntrustedInputsIndeterminate {
			t.Error("expected extraction to be recorded as indeterminate")
		}
		if got := ComputeEligibility(arts, analysis); !got.PromptInjection {
			t.Error("prompt_injection must stay eligible when the rendered prompt is unavailable")
		}
	})

	t.Run("template placeholders that do not match the rendered prompt", func(t *testing.T) {
		dir := t.TempDir()
		template := filepath.Join(dir, "prompt-template.txt")
		prompt := filepath.Join(dir, "prompt.txt")
		if err := os.WriteFile(template, []byte("EXPECTED SPINE {{issue_body}} TAIL"), 0o600); err != nil {
			t.Fatal(err)
		}
		// The rendered prompt shares no static segment with the template, so
		// every region is skipped and extraction silently yields nothing.
		if err := os.WriteFile(prompt, []byte("entirely different rendered text"), 0o600); err != nil {
			t.Fatal(err)
		}
		arts := &artifacts.Artifacts{PromptTemplatePath: template, PromptFilePath: prompt}
		analysis := BuildPromptAnalysis(arts)
		if len(analysis.UntrustedInputs) != 0 {
			t.Fatalf("expected extraction to yield nothing, got %d region(s)", len(analysis.UntrustedInputs))
		}
		if !analysis.UntrustedInputsIndeterminate {
			t.Error("a placeholder-bearing template that extracted nothing must be indeterminate")
		}
		if got := ComputeEligibility(arts, analysis); !got.PromptInjection {
			t.Error("prompt_injection must stay eligible when extraction failed to match")
		}
	})

	t.Run("unreadable comment memory is a channel, not an absence", func(t *testing.T) {
		arts := &artifacts.Artifacts{
			Warnings: []artifacts.ArtifactWarning{{Field: "comment_memory", Message: "unreadable"}},
		}
		got := ComputeEligibility(arts, &PromptAnalysis{PromptTemplate: "body"})
		if !got.PromptInjection {
			t.Error("prompt_injection must stay eligible when comment memory could not be inspected")
		}
		if !got.SecretLeak {
			t.Error("secret_leak must stay eligible when comment memory could not be inspected")
		}
	})

	t.Run("a patch the host failed to stage is uninspectable, not absent", func(t *testing.T) {
		// gh-aw sets HAS_PATCH when the agent job reported a patch; artifact
		// loading warns when no readable patch backs that claim.
		arts := &artifacts.Artifacts{
			Warnings: []artifacts.ArtifactWarning{{Field: "patch", Message: "HAS_PATCH=true but no readable patch"}},
		}
		got := ComputeEligibility(arts, &PromptAnalysis{PromptTemplate: "body"})
		if !got.MaliciousPatch {
			t.Error("malicious_patch must stay eligible when a reported patch was not staged")
		}
		if !got.SecretLeak {
			t.Error("secret_leak must stay eligible when a reported patch was not staged")
		}
	})

	t.Run("a determinate empty analysis still yields no eligibility", func(t *testing.T) {
		dir := t.TempDir()
		template := filepath.Join(dir, "prompt-template.txt")
		prompt := filepath.Join(dir, "prompt.txt")
		body := "a workflow prompt with no placeholders at all"
		if err := os.WriteFile(template, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(prompt, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		arts := &artifacts.Artifacts{PromptTemplatePath: template, PromptFilePath: prompt}
		analysis := BuildPromptAnalysis(arts)
		if analysis.UntrustedInputsIndeterminate {
			t.Error("a placeholder-free template that matched is determinate, not degraded")
		}
		if got := ComputeEligibility(arts, analysis); got.PromptInjection {
			t.Error("failing open must not extend to a bundle with genuinely no untrusted input")
		}
	})
}

// Adding a channel must not silently leave the rejection message describing the
// old set: the message is what tells the model what would make the category
// eligible, so a channel missing from it is guidance the model never receives.
func TestValidateMessagesEnumerateEveryChannel(t *testing.T) {
	ineligible := Eligibility{}
	cases := []struct {
		category string
		message  string
		channels []channel
	}{
		{"prompt_injection", ineligible.Validate(true, false, false), inputChannels(nil, nil)},
		{"secret_leak", ineligible.Validate(false, true, false), outputChannels(nil)},
		{"malicious_patch", ineligible.Validate(false, false, true), []channel{patchChannel(nil)}},
	}
	for _, tc := range cases {
		if len(tc.channels) == 0 {
			t.Errorf("%s declares no channels", tc.category)
		}
		for _, c := range tc.channels {
			if !strings.Contains(tc.message, c.name) {
				t.Errorf("%s rejection message does not mention channel %q; message was: %s",
					tc.category, c.name, tc.message)
			}
		}
	}
}

// Every channel must make its category eligible on either signal. A channel
// wired to only `present` would reintroduce the fail-closed bug in which an
// artifact that could not be read is mistaken for one that does not exist.
func TestEveryChannelIsEligibleOnEitherSignal(t *testing.T) {
	groups := map[string][]channel{
		"input":  inputChannels(nil, nil),
		"output": outputChannels(nil),
		"patch":  {patchChannel(nil)},
	}
	for group, channels := range groups {
		for _, c := range channels {
			if !(channel{name: c.name, present: true}).eligible() {
				t.Errorf("%s channel %q is not eligible when present", group, c.name)
			}
			if !(channel{name: c.name, uninspectable: true}).eligible() {
				t.Errorf("%s channel %q is not eligible when uninspectable", group, c.name)
			}
		}
	}
}
