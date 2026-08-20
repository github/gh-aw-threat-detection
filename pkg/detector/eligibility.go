package detector

import (
	"os"
	"strconv"
	"strings"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

// Eligibility describes which threat categories can be structurally raised from
// the current artifact bundle.
//
// A category is eligible only when the bundle contains the input that category
// is defined against. Setting a category to true when it is ineligible is not a
// judgment error the prompt can talk the model out of — it is a claim that
// cannot be evaluated from the artifacts at hand, so the report-result tool
// wrapper rejects it as a correction. Together with the prompt-taxonomy
// guidance, this gives detection a deterministic safety net: the model cannot
// ship a structurally impossible verdict such as `malicious_patch=true` with
// zero patch files or `prompt_injection=true` with zero untrusted input.
type Eligibility struct {
	// PromptInjection is true when at least one non-empty untrusted region
	// reached the workflow prompt. Without any untrusted content in the
	// instruction channel, there is nothing an injection could have arrived
	// through, so a prompt_injection finding cannot be raised.
	PromptInjection bool
	// SecretLeak is true when there is a channel a secret could have leaked
	// through: the agent output has non-zero content or at least one patch or
	// bundle file was produced.
	SecretLeak bool
	// MaliciousPatch is true when at least one .patch or .bundle file was
	// produced by the agent. Framework-rejected safe-output validation errors
	// are not a patch: they are the guardrails working.
	MaliciousPatch bool
}

// Environment variables used to transport eligibility from the detector process
// to the report-result subprocess launched via the threat_detection_result
// wrapper. The transport is set by the detector, not the model, and is not part
// of the tool contract exposed to the engine.
const (
	envEligiblePromptInjection = "THREAT_DETECTION_ELIGIBLE_PROMPT_INJECTION"
	envEligibleSecretLeak      = "THREAT_DETECTION_ELIGIBLE_SECRET_LEAK"
	envEligibleMaliciousPatch  = "THREAT_DETECTION_ELIGIBLE_MALICIOUS_PATCH"
)

// ComputeEligibility derives per-category eligibility from the loaded artifacts
// and the static prompt analysis. It is safe to call with nil inputs — nil is
// treated as "no artifacts, no analysis" and yields an all-false eligibility.
func ComputeEligibility(arts *artifacts.Artifacts, analysis *PromptAnalysis) Eligibility {
	e := Eligibility{}
	if analysis != nil {
		for _, u := range analysis.UntrustedInputs {
			if strings.TrimSpace(u.Content) != "" {
				e.PromptInjection = true
				break
			}
		}
	}
	if arts != nil && (arts.AgentOutputFileSize > 0 || len(arts.PatchFiles) > 0) {
		e.SecretLeak = true
	}
	if arts != nil && len(arts.PatchFiles) > 0 {
		e.MaliciousPatch = true
	}
	return e
}

// Env returns the environment variable assignments used to transport e to a
// subprocess. The variables are always emitted (including false values) so the
// receiving process can distinguish "not configured" from "configured to false".
func (e Eligibility) Env() []string {
	return []string{
		envEligiblePromptInjection + "=" + strconv.FormatBool(e.PromptInjection),
		envEligibleSecretLeak + "=" + strconv.FormatBool(e.SecretLeak),
		envEligibleMaliciousPatch + "=" + strconv.FormatBool(e.MaliciousPatch),
	}
}

// EligibilityFromEnv reads the transport variables set by Env. A missing or
// unparseable variable defaults to true — the check is a guard against
// impossible claims made by a detector that already computed eligibility, so an
// unset transport (a caller that predates the variables, or a direct
// report-result invocation from a test) must not tighten the contract in a way
// that would reject otherwise valid reports.
func EligibilityFromEnv() Eligibility {
	return Eligibility{
		PromptInjection: envBoolDefault(envEligiblePromptInjection, true),
		SecretLeak:      envBoolDefault(envEligibleSecretLeak, true),
		MaliciousPatch:  envBoolDefault(envEligibleMaliciousPatch, true),
	}
}

func envBoolDefault(name string, def bool) bool {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// Validate reports any category the caller set true that is structurally
// ineligible under e. It returns a single joined message suitable for feeding
// back to the model as a correction, or "" when the report is eligible. Only
// categories set to true are checked: setting a category to false is always
// allowed (a clean verdict is never rejected on eligibility grounds).
func (e Eligibility) Validate(promptInjection, secretLeak, maliciousPatch bool) string {
	var problems []string
	if promptInjection && !e.PromptInjection {
		problems = append(problems,
			"--prompt-injection=true is not eligible: no untrusted input reached the workflow prompt (the Prompt Analysis section listed zero non-empty untrusted regions), so a prompt-injection finding cannot be raised from these artifacts. Instruction non-compliance without any attacker-controlled content causing it is a quality signal, not a security verdict.")
	}
	if secretLeak && !e.SecretLeak {
		problems = append(problems,
			"--secret-leak=true is not eligible: the agent output is empty and no patch or bundle was produced, so there is no channel a secret could have leaked through.")
	}
	if maliciousPatch && !e.MaliciousPatch {
		problems = append(problems,
			"--malicious-patch=true is not eligible: no .patch or .bundle file was produced by the agent, so there is no code change to be malicious. Framework-rejected safe-output validation errors (for example a review_id type mismatch that the framework rejected) are the guardrails working, not a malicious patch.")
	}
	return strings.Join(problems, " ")
}
