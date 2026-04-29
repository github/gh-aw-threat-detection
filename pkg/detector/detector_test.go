package detector

import (
	"strings"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

func TestBuildPrompt_Default(t *testing.T) {
	arts := &artifacts.Artifacts{
		Dir:                 "/tmp/test",
		PromptFilePath:      "/tmp/test/aw-prompts/prompt.txt",
		AgentOutputFilePath: "/tmp/test/agent_output.json",
		PatchFileInfo:       "No patch or bundle file found",
		WorkflowName:        "Test Workflow",
		WorkflowDescription: "A test workflow",
	}

	prompt, err := BuildPrompt(arts, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prompt == "" {
		t.Fatal("expected non-empty prompt")
	}

	// Check that placeholders were replaced
	if strings.Contains(prompt, "{WORKFLOW_NAME}") {
		t.Error("expected {WORKFLOW_NAME} to be replaced")
	}
	if strings.Contains(prompt, "{WORKFLOW_DESCRIPTION}") {
		t.Error("expected {WORKFLOW_DESCRIPTION} to be replaced")
	}
	if !strings.Contains(prompt, "Test Workflow") {
		t.Error("expected workflow name in prompt")
	}
	if !strings.Contains(prompt, "A test workflow") {
		t.Error("expected workflow description in prompt")
	}
}

func TestBuildPrompt_CustomTemplate(t *testing.T) {
	arts := &artifacts.Artifacts{
		Dir:                 "/tmp/test",
		WorkflowName:        "My Workflow",
		WorkflowDescription: "desc",
		PromptFilePath:      "/tmp/prompt.txt",
		AgentOutputFilePath: "/tmp/output.json",
		PatchFileInfo:       "none",
	}

	template := "Analyze {WORKFLOW_NAME} for threats."
	prompt, err := BuildPrompt(arts, template)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "Analyze My Workflow for threats."
	if prompt != expected {
		t.Errorf("got %q, want %q", prompt, expected)
	}
}

func TestBuildPrompt_CustomPromptAppended(t *testing.T) {
	arts := &artifacts.Artifacts{
		Dir:                 "/tmp/test",
		WorkflowName:        "WF",
		WorkflowDescription: "desc",
		PromptFilePath:      "p",
		AgentOutputFilePath: "o",
		PatchFileInfo:       "none",
		CustomPrompt:        "Focus on SQL injection",
	}

	template := "Base prompt."
	prompt, err := BuildPrompt(arts, template)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(prompt, "Base prompt.") {
		t.Error("expected base prompt")
	}
	if !strings.Contains(prompt, "Focus on SQL injection") {
		t.Error("expected custom prompt appended")
	}
	if !strings.Contains(prompt, "## Additional Instructions") {
		t.Error("expected Additional Instructions header")
	}
}

func TestDefaultPromptTemplate(t *testing.T) {
	tmpl, err := DefaultPromptTemplate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl == "" {
		t.Fatal("expected non-empty template")
	}
	if !strings.Contains(tmpl, "THREAT_DETECTION_RESULT") {
		t.Error("expected template to contain THREAT_DETECTION_RESULT")
	}
}
