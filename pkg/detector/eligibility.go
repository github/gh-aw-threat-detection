package detector

import (
	"fmt"
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

// A channel is one place untrusted content could have entered this run, or one
// place the agent's output could have reached. Eligibility is derived entirely
// from channels, so adding a new artifact source means describing it as a
// channel rather than adding another condition to a boolean expression.
//
// The two fields are deliberately separate. `present` means content was found;
// `uninspectable` means the channel may hold content the detector could not
// read — an unreadable directory, an artifact the host failed to stage, an
// analysis that could not run. Both make a category eligible, because a channel
// the detector failed to inspect must never be mistaken for one that does not
// exist. Collapsing them into a single boolean is what produced the
// fail-closed bugs this type exists to prevent.
type channel struct {
	// name completes the sentence "...could have reached" or "...reached this
	// run's inputs" in a rejection message, so it reads as a noun phrase.
	name          string
	present       bool
	uninspectable bool
}

func (c channel) eligible() bool { return c.present || c.uninspectable }

// eligibleFrom reports whether any channel makes a category raisable, and
// returns the names of every channel that was checked, for the rejection
// message. Message text is derived from the same declarations that decide the
// verdict, so a new channel cannot be added to one without appearing in the
// other.
func eligibleFrom(channels []channel) (bool, []string) {
	names := make([]string, 0, len(channels))
	eligible := false
	for _, c := range channels {
		names = append(names, c.name)
		if c.eligible() {
			eligible = true
		}
	}
	return eligible, names
}

// inputChannels enumerates the ways untrusted content could have reached this
// run's own inputs, which is what `prompt_injection` is defined against.
//
// To extend: append a channel here. Content that reaches the agent only during
// execution (MCP tool results, fetched web pages, the engine transcript) is not
// staged as an artifact today, so it cannot be described as a channel yet; that
// requires the host to stage it first (see the scope note in TD-10g).
func inputChannels(arts *artifacts.Artifacts, analysis *PromptAnalysis) []channel {
	var hasUntrustedRegion bool
	for _, u := range analysisUntrustedInputs(analysis) {
		if strings.TrimSpace(u.Content) != "" {
			hasUntrustedRegion = true
			break
		}
	}
	return []channel{
		{
			name:    "an untrusted region interpolated into the prompt",
			present: hasUntrustedRegion,
			// An empty region list means "nothing untrusted was interpolated"
			// only when extraction ran to completion. The template or the
			// rendered prompt may have been unavailable, or the two may have
			// diverged so that regions were silently skipped.
			//
			// The absent-template case is tested directly rather than relying
			// on the flag alone: the flag's zero value is "determinate", so an
			// analysis built by any path that does not set it would otherwise
			// fail closed, and this gate must never become stricter by
			// omission.
			uninspectable: analysis == nil || analysis.UntrustedInputsIndeterminate || analysis.PromptTemplate == "",
		},
		{
			// Comment memory is written by one run and read back into a later
			// run's prompt, so it is an input channel here and an output
			// channel below.
			name:          "a comment-memory file read back into the prompt",
			present:       arts != nil && len(arts.CommentMemoryFiles) > 0,
			uninspectable: arts != nil && arts.HasWarningForField("comment_memory"),
		},
	}
}

// outputChannels enumerates the places a secret could have reached, which is
// what `secret_leak` is defined against.
//
// To extend: append a channel here.
func outputChannels(arts *artifacts.Artifacts) []channel {
	return []channel{
		{
			// agent_output.json is the framework's safe-output file, so textual
			// outputs the agent asked to have published — create_issue,
			// add_comment and create_pull_request bodies — are covered here and
			// are not staged as separate artifacts.
			name:    "a non-empty agent output file",
			present: arts != nil && arts.AgentOutputFileSize > 0,
		},
		patchChannel(arts),
		{
			name:          "a comment-memory file",
			present:       arts != nil && len(arts.CommentMemoryFiles) > 0,
			uninspectable: arts != nil && arts.HasWarningForField("comment_memory"),
		},
	}
}

// patchChannel describes committed code, which `malicious_patch` is defined
// against and which is also one of the channels a secret could reach.
//
// A patch the agent produced but the host failed to stage is uninspectable, not
// absent: gh-aw sets HAS_PATCH when the agent job reported one, and artifact
// loading records a warning when no readable patch backs that claim. Treating
// that as "no patch exists" would let a staging failure suppress a finding.
func patchChannel(arts *artifacts.Artifacts) channel {
	return channel{
		name:          "a patch or bundle file",
		present:       arts != nil && len(arts.PatchFiles) > 0,
		uninspectable: arts != nil && arts.HasWarningForField("patch"),
	}
}

// ComputeEligibility derives per-category eligibility from the loaded artifacts
// and the static prompt analysis. It is safe to call with nil inputs: a nil
// analysis is maximally degraded, so prompt-injection eligibility is granted,
// while a nil artifact set offers no channel for the output-derived categories.
func ComputeEligibility(arts *artifacts.Artifacts, analysis *PromptAnalysis) Eligibility {
	e := Eligibility{}
	e.PromptInjection, _ = eligibleFrom(inputChannels(arts, analysis))
	e.SecretLeak, _ = eligibleFrom(outputChannels(arts))
	e.MaliciousPatch, _ = eligibleFrom([]channel{patchChannel(arts)})
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
		problems = append(problems, fmt.Sprintf(
			"--prompt-injection=true is not eligible: no untrusted content reached this run's inputs. A prompt-injection finding must come from one of %s, and none was present or unreadable here. Instruction non-compliance without attacker-controlled content causing it is a quality signal, not a security verdict.",
			describeChannels(inputChannels(nil, nil))))
	}
	if secretLeak && !e.SecretLeak {
		problems = append(problems, fmt.Sprintf(
			"--secret-leak=true is not eligible: the agent produced nothing a secret could have reached. A secret must have reached one of %s, and none was present or unreadable here. Note that agent_output.json carries every safe output, including create_issue, add_comment and create_pull_request bodies.",
			describeChannels(outputChannels(nil))))
	}
	if maliciousPatch && !e.MaliciousPatch {
		problems = append(problems, fmt.Sprintf(
			"--malicious-patch=true is not eligible: the agent produced no code change to be malicious. A malicious-patch finding requires %s, and none was present or unreadable here. Framework-rejected safe-output validation errors (for example a review_id type mismatch that the framework rejected) are the guardrails working, not a malicious patch.",
			describeChannels([]channel{patchChannel(nil)})))
	}
	return strings.Join(problems, " ")
}

// describeChannels renders channel names for a rejection message. It is driven
// by the same declarations that decide eligibility — passing nil artifacts
// yields the channel set with its presence flags unset, and only the static
// names are read — so a channel cannot be added to the verdict without also
// appearing in the explanation of a rejection.
func describeChannels(channels []channel) string {
	_, names := eligibleFrom(channels)
	switch len(names) {
	case 0:
		return "(no channel)"
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
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
