// Package detector provides the core threat detection logic including
// prompt building and result parsing.
package detector

import (
	"embed"
	"fmt"
	"strings"
	"time"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

// Version is set at build time via ldflags.
var Version = "dev"

// promptAnalysisPlaceholder is the template token replaced by the
// trusted-vs-untrusted prompt analysis and framework-scaffolding findings.
const promptAnalysisPlaceholder = "{PROMPT_ANALYSIS}"

// budgetPlaceholder is the template token replaced by a description of the
// wall-clock and turn budgets the detector is running under. The model uses
// this to pace itself and avoid triggering the runaway-model kill switch.
const budgetPlaceholder = "{BUDGET}"

// PromptBudget describes the per-attempt runaway-model kill switches so the
// prompt can tell the model how much wall-clock time and how many agentic
// turns it has. Zero values mean "disabled" and are rendered as "unlimited".
type PromptBudget struct {
	EngineTimeout time.Duration
	MaxTurns      int
}

// FormatForPrompt renders the budget as a short paragraph suitable for
// inclusion in the detection prompt. It never returns an empty string — the
// model always gets *some* budget guidance, even when both caps are disabled.
func (b PromptBudget) FormatForPrompt() string {
	timeStr := "unlimited"
	if b.EngineTimeout > 0 {
		timeStr = formatDurationForPrompt(b.EngineTimeout)
	}
	turnStr := "unlimited"
	if b.MaxTurns > 0 {
		turnStr = fmt.Sprintf("%d", b.MaxTurns)
	}
	return fmt.Sprintf(
		"You are running under a per-attempt budget: **wall-clock timeout %s**, **agentic turn cap %s**. "+
			"The wall-clock is a hard `SIGKILL` on your process group (this subprocess and every descendant) "+
			"when the deadline fires, so no partial verdict survives. The turn cap is enforced by the engine "+
			"host when supported (which is the common case). When either budget is exhausted the run fails "+
			"with `engine_timeout` and no retry runs — the same prompt would just run away again. Pace "+
			"yourself: read only what you need to reach a decision, avoid re-reading the same file, and call "+
			"`threat_detection_result` as soon as you have enough evidence to commit to a verdict. If you "+
			"are running out of budget, still call `threat_detection_result` with your best current "+
			"assessment rather than letting the deadline fire with no result recorded.",
		timeStr, turnStr,
	)
}

// formatDurationForPrompt renders a duration in the most readable unit for the
// model — whole minutes when possible, otherwise seconds. Avoids "5m0s" style.
func formatDurationForPrompt(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	if d >= time.Second && d%time.Second == 0 {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	return d.String()
}

//go:embed prompts/threat_detection.md
var defaultPromptFS embed.FS

// DefaultPromptTemplate returns the embedded default prompt template.
func DefaultPromptTemplate() (string, error) {
	data, err := defaultPromptFS.ReadFile("prompts/threat_detection.md")
	if err != nil {
		return "", fmt.Errorf("reading embedded prompt template: %w", err)
	}
	return string(data), nil
}

// BuildPrompt constructs the full detection prompt from the template and artifacts.
// If promptTemplate is empty, the built-in default template is used.
// The prompt analysis (untrusted input breakdown) is included when available.
// The budget is rendered as "unlimited" for both caps; use
// BuildPromptWithBudget for a real budget.
func BuildPrompt(arts *artifacts.Artifacts, promptTemplate string) (string, error) {
	prompt, _, err := BuildPromptWithAnalysis(arts, PromptBudget{}, promptTemplate)
	return prompt, err
}

// BuildPromptWithBudget is the same as BuildPrompt but also tells the model
// how much wall-clock time and how many agentic turns it has.
func BuildPromptWithBudget(arts *artifacts.Artifacts, budget PromptBudget, promptTemplate string) (string, error) {
	prompt, _, err := BuildPromptWithAnalysis(arts, budget, promptTemplate)
	return prompt, err
}

// BuildPromptWithAnalysis constructs the detection prompt and returns the exact
// static analysis used to render it.
func BuildPromptWithAnalysis(arts *artifacts.Artifacts, budget PromptBudget, promptTemplate string) (string, *PromptAnalysis, error) {
	if promptTemplate == "" {
		var err error
		promptTemplate, err = DefaultPromptTemplate()
		if err != nil {
			return "", nil, err
		}
	}

	// Build prompt analysis from template/rendered prompt/import tree
	analysis := BuildPromptAnalysis(arts)
	analysisContent := analysis.FormatForPrompt()
	appendAnalysis := analysisContent != "" && !strings.Contains(promptTemplate, promptAnalysisPlaceholder)
	if analysisContent == "" {
		analysisContent = "No prompt template or import tree available. Prompt analysis was not performed."
	}

	budgetContent := budget.FormatForPrompt()
	appendBudget := !strings.Contains(promptTemplate, budgetPlaceholder)

	// Replace template placeholders with artifact information
	prompt := promptTemplate
	prompt = strings.ReplaceAll(prompt, "{WORKFLOW_NAME}", arts.WorkflowName)
	prompt = strings.ReplaceAll(prompt, "{WORKFLOW_DESCRIPTION}", arts.WorkflowDescription)
	prompt = strings.ReplaceAll(prompt, "{WORKFLOW_PROMPT_FILE}", arts.PromptFilePath)
	prompt = strings.ReplaceAll(prompt, "{AGENT_OUTPUT_FILE}", arts.AgentOutputFilePath)
	prompt = strings.ReplaceAll(prompt, "{AGENT_PATCH_FILE}", arts.PatchFileInfo)
	prompt = strings.ReplaceAll(prompt, "{ACTIVATION_CONTEXT}", arts.FormatActivationContext())
	prompt = strings.ReplaceAll(prompt, "{COMMENT_MEMORY_FILES}", arts.CommentMemoryFileInfo)
	prompt = strings.ReplaceAll(prompt, promptAnalysisPlaceholder, analysisContent)
	prompt = strings.ReplaceAll(prompt, budgetPlaceholder, budgetContent)

	// A custom template (--prompt-template) may omit the placeholder entirely.
	// The trusted-vs-untrusted breakdown and the framework-scaffolding
	// identification are required guidance, so append them rather than
	// silently dropping them.
	if appendAnalysis {
		prompt += "\n\n## Prompt Analysis (Trusted vs Untrusted Content)\n\n" + analysisContent
	}

	// Same reasoning as above: budget guidance is required so the model can
	// pace itself, so a custom template that omits the placeholder still gets
	// the budget appended rather than silently running without it.
	if appendBudget {
		prompt += "\n\n## Budget\n\n" + budgetContent
	}

	// Append custom prompt instructions if provided
	if arts.CustomPrompt != "" {
		prompt += "\n\n## Additional Instructions\n\n" + arts.CustomPrompt
	}

	return prompt, analysis, nil
}
