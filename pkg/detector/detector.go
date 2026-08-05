// Package detector provides the core threat detection logic including
// prompt building and result parsing.
package detector

import (
	"embed"
	"fmt"
	"strings"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

// Version is set at build time via ldflags.
var Version = "dev"

// promptAnalysisPlaceholder is the template token replaced by the
// trusted-vs-untrusted prompt analysis and framework-scaffolding findings.
const promptAnalysisPlaceholder = "{PROMPT_ANALYSIS}"

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
func BuildPrompt(arts *artifacts.Artifacts, promptTemplate string) (string, error) {
	prompt, _, err := BuildPromptWithAnalysis(arts, promptTemplate)
	return prompt, err
}

// BuildPromptWithAnalysis constructs the detection prompt and returns the exact
// static analysis used to render it.
func BuildPromptWithAnalysis(arts *artifacts.Artifacts, promptTemplate string) (string, *PromptAnalysis, error) {
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

	// A custom template (--prompt-template) may omit the placeholder entirely.
	// The trusted-vs-untrusted breakdown and the framework-scaffolding
	// identification are required guidance, so append them rather than
	// silently dropping them.
	if appendAnalysis {
		prompt += "\n\n## Prompt Analysis (Trusted vs Untrusted Content)\n\n" + analysisContent
	}

	// Append custom prompt instructions if provided
	if arts.CustomPrompt != "" {
		prompt += "\n\n## Additional Instructions\n\n" + arts.CustomPrompt
	}

	return prompt, analysis, nil
}
