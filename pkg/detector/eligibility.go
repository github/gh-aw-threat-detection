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
// cannot be evaluated from the artifacts at hand, so it is rejected.
//
// Enforcement happens in two places with different standing:
//
//   - The report-result subprocess checks eligibility from environment
//     variables so an ineligible claim is rejected in-session and the model can
//     re-answer immediately. This is an optimization: the environment reaches
//     the subprocess through a command line the model composes, so the model
//     can override or strip it. It is not authoritative.
//   - The detector process re-checks every sink result against the eligibility
//     it computed itself, from artifacts the model never touched. That check is
//     the actual invariant (see ValidateResult).
//
// The scope of this check is the artifact bundle. Channels that reach the agent
// mid-run — MCP tool results, fetched web content, the engine transcript — are
// not staged as artifacts, so an injection delivered exclusively through one of
// them leaves no evidence the detector can see, and is outside the reach of
// both this check and the detection pass generally.
type Eligibility struct {
	// PromptInjection is true when untrusted content could have reached this
	// run's inputs: a non-empty untrusted region in the prompt analysis, a
	// comment-memory file (which the agent reads back into the prompt), or a
	// degraded analysis that cannot rule untrusted content out.
	//
	// This gate is deliberately narrow. The activation context is appended as
	// an untrusted input whenever aw_info.json parses, so in practice the gate
	// only rejects workflows with no untrusted input at all — a cron-triggered
	// workflow with no interpolation and no activation metadata. It is not a
	// general defense against over-reporting prompt injection; the prompt
	// taxonomy owns that.
	PromptInjection bool
	// SecretLeak is true when there is a channel a secret could have leaked
	// through: a non-empty agent output, at least one patch or bundle file, or
	// at least one comment-memory file (a persisted channel the agent writes).
	//
	// agent_output.json is the framework's safe-output file, so textual outputs
	// the agent asked to have published — create_issue, add_comment and
	// create_pull_request bodies — are covered by the agent-output channel; they
	// are not staged as separate artifacts and need no separate condition.
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
// and the static prompt analysis. It is safe to call with nil inputs: a nil
// analysis is maximally degraded, so prompt-injection eligibility is granted,
// while a nil artifact set offers no channel for the output-derived categories.
func ComputeEligibility(arts *artifacts.Artifacts, analysis *PromptAnalysis) Eligibility {
	e := Eligibility{}

	for _, u := range analysisUntrustedInputs(analysis) {
		if strings.TrimSpace(u.Content) != "" {
			e.PromptInjection = true
			break
		}
	}
	// A degraded analysis cannot rule untrusted content out. An empty
	// UntrustedInputs list means "nothing untrusted was interpolated" only when
	// extraction actually ran to completion; when the template or the rendered
	// prompt was unavailable, or the two diverged so that regions were skipped,
	// the list is empty for reasons that say nothing about untrusted content.
	// Failing closed there would let a missing or malformed artifact suppress a
	// real finding, so eligibility is granted whenever provenance could not be
	// established.
	//
	// The absent-template case is also tested directly rather than relying on
	// the flag alone: the flag's zero value is "determinate", so an analysis
	// built by any path that does not set it would otherwise fail closed, and
	// this gate must never become stricter by omission.
	if analysis == nil || analysis.UntrustedInputsIndeterminate || analysis.PromptTemplate == "" {
		e.PromptInjection = true
	}
	// Comment memory is read back into a later run's prompt, so it is an
	// untrusted input channel for this run's analysis. A directory that exists
	// but could not be read is an uninspectable channel, not an absent one.
	if arts != nil && (len(arts.CommentMemoryFiles) > 0 || arts.HasWarningForField("comment_memory")) {
		e.PromptInjection = true
	}

	if arts != nil {
		// Every channel a secret could have reached: the agent's structured
		// output, committed code, or the persisted comment-memory channel. A
		// comment-memory directory that could not be read is counted as a
		// channel: it may hold content, and an artifact the detector failed to
		// inspect must not be treated as one the agent never wrote to.
		if arts.AgentOutputFileSize > 0 || len(arts.PatchFiles) > 0 ||
			len(arts.CommentMemoryFiles) > 0 || arts.HasWarningForField("comment_memory") {
			e.SecretLeak = true
		}
		if len(arts.PatchFiles) > 0 {
			e.MaliciousPatch = true
		}
	}
	return e
}

func analysisUntrustedInputs(analysis *PromptAnalysis) []UntrustedInput {
	if analysis == nil {
		return nil
	}
	return analysis.UntrustedInputs
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
// unparseable variable defaults to true so a caller that predates the variables
// (or a direct report-result invocation) is not tightened into rejecting
// otherwise valid reports.
//
// The values this reads are not authoritative. They arrive through the
// environment of a command line the detection model composes, so the model can
// set them to true or omit them entirely and this check will pass. It exists to
// give a confused model a fast in-session correction, not to constrain a model
// that is trying to get around it. The binding check is the detector's own
// ValidateResult call against the eligibility it computed from artifacts.
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
			"--prompt-injection=true is not eligible: no untrusted input reached this run's inputs — prompt analysis completed against the template and rendered prompt and found no non-empty untrusted region, and no comment-memory file was staged — so a prompt-injection finding cannot be raised from these artifacts. Instruction non-compliance without attacker-controlled content causing it is a quality signal, not a security verdict.")
	}
	if secretLeak && !e.SecretLeak {
		problems = append(problems,
			"--secret-leak=true is not eligible: the agent produced no output at all — agent_output.json (which carries every safe output, including create_issue, add_comment and create_pull_request bodies) is empty, and no patch, bundle, or comment-memory file was staged — so there is no channel a secret could have reached.")
	}
	if maliciousPatch && !e.MaliciousPatch {
		problems = append(problems,
			"--malicious-patch=true is not eligible: no .patch or .bundle file was produced by the agent, so there is no code change to be malicious. Framework-rejected safe-output validation errors (for example a review_id type mismatch that the framework rejected) are the guardrails working, not a malicious patch.")
	}
	return strings.Join(problems, " ")
}

// ValidateResult applies Validate to a parsed result. It is the detector-side
// enforcement point: the eligibility it is called on is computed by the
// detector process from the artifact bundle, so unlike the environment-based
// check in the report-result subprocess it cannot be influenced by the
// detection model. A non-empty return means the result must not be recorded.
func (e Eligibility) ValidateResult(r *Result) string {
	if r == nil {
		return ""
	}
	return e.Validate(r.PromptInjection, r.SecretLeak, r.MaliciousPatch)
}
