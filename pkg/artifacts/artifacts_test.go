package artifacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create expected structure
	promptDir := filepath.Join(dir, "aw-prompts")
	os.MkdirAll(promptDir, 0755)
	os.WriteFile(filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"), 0644)
	os.WriteFile(filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`), 0644)
	os.WriteFile(filepath.Join(dir, "aw-feature.patch"), []byte("diff content"), 0644)

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if arts.Dir != dir {
		t.Errorf("Dir = %q, want %q", arts.Dir, dir)
	}
	if arts.PromptFilePath != filepath.Join(promptDir, "prompt.txt") {
		t.Errorf("PromptFilePath = %q", arts.PromptFilePath)
	}
	if arts.AgentOutputFilePath != filepath.Join(dir, "agent_output.json") {
		t.Errorf("AgentOutputFilePath = %q", arts.AgentOutputFilePath)
	}
	if len(arts.PatchFiles) != 1 {
		t.Fatalf("expected 1 patch file, got %d", len(arts.PatchFiles))
	}
	if arts.PatchFiles[0] != filepath.Join(dir, "aw-feature.patch") {
		t.Errorf("PatchFile = %q", arts.PatchFiles[0])
	}
}

func TestLoad_BundleFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "aw-main.bundle"), []byte("bundle"), 0644)

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(arts.PatchFiles) != 1 {
		t.Fatalf("expected 1 bundle file, got %d", len(arts.PatchFiles))
	}
}

func TestLoad_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if arts.PromptFilePath != "No prompt file found" {
		t.Errorf("expected no prompt file info, got %q", arts.PromptFilePath)
	}
	if arts.AgentOutputFilePath != "No agent output file found" {
		t.Errorf("expected no agent output info, got %q", arts.AgentOutputFilePath)
	}
	if arts.PatchFileInfo != "No patch or bundle file found" {
		t.Errorf("expected no patch info, got %q", arts.PatchFileInfo)
	}
}

func TestLoad_NonExistentDirectory(t *testing.T) {
	_, err := Load("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for non-existent directory")
	}
}

func TestLoad_FileInsteadOfDirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	os.WriteFile(f, []byte("not a dir"), 0644)

	_, err := Load(f)
	if err == nil {
		t.Fatal("expected error for file path")
	}
}

func TestLoad_WorkflowNameFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WORKFLOW_NAME", "My Custom Workflow")

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if arts.WorkflowName != "My Custom Workflow" {
		t.Errorf("WorkflowName = %q, want %q", arts.WorkflowName, "My Custom Workflow")
	}
}
