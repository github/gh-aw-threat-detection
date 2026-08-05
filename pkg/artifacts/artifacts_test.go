package artifacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestFile is a test helper that writes a file and fails the test on error.
func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing test file %s: %v", path, err)
	}
}

// writeMinimalArtifactsForTest populates dir with a non-empty prompt and
// agent output file so Load does not emit unrelated prompt/agent_output
// warnings, keeping comment-memory-focused tests focused on comment-memory
// warnings only.
func writeMinimalArtifactsForTest(t *testing.T, dir string) {
	t.Helper()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))
}

func TestLoad_ValidDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create expected structure
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))
	writeTestFile(t, filepath.Join(dir, "aw-feature.patch"), []byte("diff content"))

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
	writeTestFile(t, filepath.Join(dir, "aw-main.bundle"), []byte("bundle"))

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
	if arts.CommentMemoryFileInfo != "No comment-memory files found" {
		t.Errorf("expected no comment-memory info, got %q", arts.CommentMemoryFileInfo)
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
	writeTestFile(t, f, []byte("not a dir"))

	_, err := Load(f)
	if err == nil {
		t.Fatal("expected error for file path")
	}
}

func TestLoad_CommentMemorySymlinkedDirRejected(t *testing.T) {
	dir := t.TempDir()
	// A real directory outside the artifacts tree that a symlink would point to.
	outside := t.TempDir()
	writeTestFile(t, filepath.Join(outside, "secret.md"), []byte("outside the tree"))

	link := filepath.Join(dir, "comment-memory")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(arts.CommentMemoryFiles) != 0 {
		t.Errorf("expected symlinked dir to be rejected, got %v", arts.CommentMemoryFiles)
	}
	if arts.CommentMemoryFileInfo != "No comment-memory files found" {
		t.Errorf("expected no comment-memory info, got %q", arts.CommentMemoryFileInfo)
	}
}

func TestLoad_CommentMemorySymlinkedFileSkipped(t *testing.T) {
	dir := t.TempDir()
	cmDir := filepath.Join(dir, "comment-memory")
	if err := os.MkdirAll(cmDir, 0o755); err != nil {
		t.Fatalf("creating comment-memory dir: %v", err)
	}
	writeTestFile(t, filepath.Join(cmDir, "real.md"), []byte("real memory"))

	// A .md symlink pointing outside the tree must be skipped.
	outside := filepath.Join(t.TempDir(), "target.md")
	writeTestFile(t, outside, []byte("outside"))
	if err := os.Symlink(outside, filepath.Join(cmDir, "link.md")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(arts.CommentMemoryFiles) != 1 {
		t.Fatalf("expected only the regular file, got %v", arts.CommentMemoryFiles)
	}
	if strings.Contains(arts.CommentMemoryFileInfo, "link.md") {
		t.Errorf("expected symlinked file to be skipped, got %q", arts.CommentMemoryFileInfo)
	}
}

// findWarning returns the first warning for the given field, or nil.
func findWarning(warnings []ArtifactWarning, field string) *ArtifactWarning {
	for i := range warnings {
		if warnings[i].Field == field {
			return &warnings[i]
		}
	}
	return nil
}

func TestLoad_MissingPromptEmitsWarning(t *testing.T) {
	dir := t.TempDir()
	// Prompt missing, but agent output and a patch present so this is not the
	// all-primary-inputs-missing case.
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))
	writeTestFile(t, filepath.Join(dir, "aw-feature.patch"), []byte("diff"))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := findWarning(arts.Warnings, "prompt")
	if w == nil {
		t.Fatalf("expected a prompt warning, got: %#v", arts.Warnings)
	}
	if !strings.Contains(w.Message, "ERR_VALIDATION") || !strings.Contains(w.Message, "Missing detection context prompt") {
		t.Errorf("unexpected prompt warning message: %q", w.Message)
	}
	if arts.AllPrimaryInputsMissing {
		t.Errorf("AllPrimaryInputsMissing = true, want false")
	}
}

func TestLoad_EmptyPromptEmitsWarning(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte(""))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := findWarning(arts.Warnings, "prompt")
	if w == nil {
		t.Fatalf("expected a prompt warning for empty file, got: %#v", arts.Warnings)
	}
	if !strings.Contains(w.Message, "is empty") {
		t.Errorf("unexpected prompt warning message: %q", w.Message)
	}
	if arts.PromptFileSize != 0 {
		t.Errorf("PromptFileSize = %d, want 0", arts.PromptFileSize)
	}
}

func TestLoad_MissingAgentOutputEmitsWarning(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := findWarning(arts.Warnings, "agent_output")
	if w == nil {
		t.Fatalf("expected an agent_output warning, got: %#v", arts.Warnings)
	}
	if !strings.Contains(w.Message, "ERR_VALIDATION") || !strings.Contains(w.Message, "Missing agent output file") {
		t.Errorf("unexpected agent_output warning message: %q", w.Message)
	}
}

func TestLoad_InvalidJSONAgentOutputEmitsWarning(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte("not json{{{"))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := findWarning(arts.Warnings, "agent_output")
	if w == nil {
		t.Fatalf("expected an agent_output warning for invalid JSON, got: %#v", arts.Warnings)
	}
	if !strings.Contains(w.Message, "not valid JSON") {
		t.Errorf("unexpected agent_output warning message: %q", w.Message)
	}
}

func TestLoad_EmptyAgentOutputEmitsWarning(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(""))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := findWarning(arts.Warnings, "agent_output")
	if w == nil {
		t.Fatalf("expected an agent_output warning for empty file, got: %#v", arts.Warnings)
	}
	if !strings.Contains(w.Message, "is empty") {
		t.Errorf("unexpected agent_output warning message: %q", w.Message)
	}
}

func TestLoad_HasPatchEnvButNoPatchFileEmitsWarning(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))
	t.Setenv("HAS_PATCH", "true")

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := findWarning(arts.Warnings, "patch")
	if w == nil {
		t.Fatalf("expected a patch warning, got: %#v", arts.Warnings)
	}
	if !strings.Contains(w.Message, "HAS_PATCH=true") {
		t.Errorf("unexpected patch warning message: %q", w.Message)
	}
}

func TestLoad_HasPatchEnvWithPatchFileNoWarning(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))
	writeTestFile(t, filepath.Join(dir, "aw-feature.patch"), []byte("diff"))
	t.Setenv("HAS_PATCH", "true")

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if w := findWarning(arts.Warnings, "patch"); w != nil {
		t.Errorf("unexpected patch warning: %q", w.Message)
	}
}

func TestLoad_HasPatchEnvWithZeroLengthPatchEmitsWarning(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))
	// A zero-length patch file is present on disk but provides no actual patch
	// context, so it must not be treated as satisfying HAS_PATCH.
	writeTestFile(t, filepath.Join(dir, "aw-feature.patch"), []byte(""))
	t.Setenv("HAS_PATCH", "true")

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := findWarning(arts.Warnings, "patch")
	if w == nil {
		t.Fatalf("expected a patch warning for a zero-length patch file, got: %#v", arts.Warnings)
	}
	if !strings.Contains(w.Message, "HAS_PATCH=true") {
		t.Errorf("unexpected patch warning message: %q", w.Message)
	}
}

func TestLoad_AllPrimaryInputsMissingIsFlagged(t *testing.T) {
	dir := t.TempDir()

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !arts.AllPrimaryInputsMissing {
		t.Errorf("AllPrimaryInputsMissing = false, want true for a fully empty artifacts dir")
	}
	if len(arts.Warnings) < 2 {
		t.Errorf("expected at least prompt and agent_output warnings, got: %#v", arts.Warnings)
	}
}

func TestLoad_AllPrimaryInputsMissingIgnoresZeroLengthPatch(t *testing.T) {
	dir := t.TempDir()
	// A zero-length patch file must not count as "present" for the
	// all-primary-inputs-missing check either.
	writeTestFile(t, filepath.Join(dir, "aw-feature.patch"), []byte(""))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !arts.AllPrimaryInputsMissing {
		t.Errorf("AllPrimaryInputsMissing = false, want true when only a zero-length patch is present")
	}
}

func TestLoad_ValidDirectoryHasNoWarnings(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))
	writeTestFile(t, filepath.Join(dir, "aw-feature.patch"), []byte("diff content"))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(arts.Warnings) != 0 {
		t.Errorf("expected no warnings for a fully populated artifacts dir, got: %#v", arts.Warnings)
	}
	if arts.AllPrimaryInputsMissing {
		t.Errorf("AllPrimaryInputsMissing = true, want false")
	}
	if arts.PromptFileSize != int64(len("test prompt")) {
		t.Errorf("PromptFileSize = %d, want %d", arts.PromptFileSize, len("test prompt"))
	}
	if arts.AgentOutputFileSize != int64(len(`{"items":[]}`)) {
		t.Errorf("AgentOutputFileSize = %d, want %d", arts.AgentOutputFileSize, len(`{"items":[]}`))
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

func TestLoad_ActivationContextIsAllowlistedAndBounded(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "aw_info.json"), []byte(`{
		"event_name":"issue_comment",
		"actor":"external-user",
		"engine_id":"copilot",
		"model":"claude-sonnet-5",
		"workflow_name":"Triage",
		"repository":"octo/repo",
		"run_id":123,
		"allowed_domains":["example.com"],
		"context":{
			"repo":"octo/caller",
			"workflow_id":"octo/caller/.github/workflows/call.yml@refs/heads/main",
			"actor":"caller-user",
			"ignored":"not exposed"
		},
		"secret_field":"must not be exposed"
	}`))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if arts.ActivationContext == nil {
		t.Fatal("ActivationContext = nil")
	}
	if arts.ActivationContext.EventName != "issue_comment" {
		t.Errorf("EventName = %q, want issue_comment", arts.ActivationContext.EventName)
	}
	if arts.ActivationContext.RunID != "123" {
		t.Errorf("RunID = %q, want 123", arts.ActivationContext.RunID)
	}
	if arts.ActivationContext.Context == nil || arts.ActivationContext.Context.Actor != "caller-user" {
		t.Fatalf("caller context not loaded: %#v", arts.ActivationContext.Context)
	}
	formatted := arts.FormatActivationContext()
	for _, excluded := range []string{"allowed_domains", "secret_field", "ignored", "must not be exposed"} {
		if strings.Contains(formatted, excluded) {
			t.Errorf("activation context contains non-allowlisted value %q:\n%s", excluded, formatted)
		}
	}
}

func TestLoad_RejectsOversizedActivationValue(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "aw_info.json"), []byte(`{"actor":"`+strings.Repeat("a", maxActivationValue+1)+`"}`))

	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "actor") || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Load() error = %v, want bounded actor error", err)
	}
}

func TestLoad_RejectsOversizedAWInfoFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "aw_info.json"), []byte(strings.Repeat(" ", maxAWInfoBytes+1)))

	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "aw_info.json exceeds") {
		t.Fatalf("Load() error = %v, want file size limit error", err)
	}
}

func TestLoad_RejectsMalformedActivationContext(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "aw_info.json"), []byte(`{"event_name":`))

	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "parsing aw_info.json") {
		t.Fatalf("Load() error = %v, want aw_info parse error", err)
	}
}

func TestLoad_InventoryIncludesNestedConsumedAndUnconsumedFiles(t *testing.T) {
	dir := t.TempDir()
	for _, subdir := range []string{"aw-prompts", "experiments", "comment-memory"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o755); err != nil {
			t.Fatalf("creating %s: %v", subdir, err)
		}
	}
	writeTestFile(t, filepath.Join(dir, "aw-prompts", "prompt.txt"), []byte("prompt"))
	writeTestFile(t, filepath.Join(dir, "experiments", "assignment.json"), []byte("{}"))
	writeTestFile(t, filepath.Join(dir, "comment-memory", "memory.md"), []byte("memory"))
	writeTestFile(t, filepath.Join(dir, "aw-change.patch"), []byte("diff"))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got := make(map[string]InventoryEntry, len(arts.Inventory))
	for _, entry := range arts.Inventory {
		got[entry.Path] = entry
	}
	if len(got) != 4 {
		t.Fatalf("inventory = %#v, want 4 entries", arts.Inventory)
	}
	for _, path := range []string{"aw-prompts/prompt.txt", "aw-change.patch"} {
		if !got[path].Consumed {
			t.Errorf("%s consumed = false, want true", path)
		}
	}
	for _, path := range []string{"experiments/assignment.json", "comment-memory/memory.md"} {
		if got[path].Consumed {
			t.Errorf("%s consumed = true, want false", path)
		}
	}
	if got["experiments/assignment.json"].Size != 2 {
		t.Errorf("experiment size = %d, want 2", got["experiments/assignment.json"].Size)
	}
}

func TestLoad_CommentMemoryFiles(t *testing.T) {
	dir := t.TempDir()
	writeMinimalArtifactsForTest(t, dir)
	cmDir := filepath.Join(dir, "comment-memory")
	if err := os.MkdirAll(cmDir, 0o755); err != nil {
		t.Fatalf("creating comment-memory dir: %v", err)
	}
	writeTestFile(t, filepath.Join(cmDir, "note-a.md"), []byte("memory a"))
	writeTestFile(t, filepath.Join(cmDir, "note-b.md"), []byte("memory b"))
	// Non-markdown files and subdirectories must be ignored.
	writeTestFile(t, filepath.Join(cmDir, "ignore.txt"), []byte("not md"))
	if err := os.MkdirAll(filepath.Join(cmDir, "sub"), 0o755); err != nil {
		t.Fatalf("creating sub dir: %v", err)
	}

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(arts.CommentMemoryFiles) != 2 {
		t.Fatalf("expected 2 comment-memory files, got %d (%v)", len(arts.CommentMemoryFiles), arts.CommentMemoryFiles)
	}
	for _, want := range []string{"note-a.md", "note-b.md"} {
		if !strings.Contains(arts.CommentMemoryFileInfo, want) {
			t.Errorf("CommentMemoryFileInfo missing %q: %q", want, arts.CommentMemoryFileInfo)
		}
	}
	if len(arts.Warnings) != 0 {
		t.Errorf("expected no warnings, got %v", arts.Warnings)
	}
}

func TestLoad_CommentMemoryEmptyDir(t *testing.T) {
	dir := t.TempDir()
	writeMinimalArtifactsForTest(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "comment-memory"), 0o755); err != nil {
		t.Fatalf("creating comment-memory dir: %v", err)
	}

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if arts.CommentMemoryFileInfo != "No comment-memory files found" {
		t.Errorf("expected no comment-memory info, got %q", arts.CommentMemoryFileInfo)
	}
	if len(arts.Warnings) != 0 {
		t.Errorf("expected no warnings, got %v", arts.Warnings)
	}
}

func TestLoad_CommentMemoryNotADirectory(t *testing.T) {
	dir := t.TempDir()
	writeMinimalArtifactsForTest(t, dir)
	// A regular file named comment-memory should not be treated as the dir and
	// must not warn (parity: only inspection failures warn).
	writeTestFile(t, filepath.Join(dir, "comment-memory"), []byte("not a dir"))

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if arts.CommentMemoryFileInfo != "No comment-memory files found" {
		t.Errorf("expected no comment-memory info, got %q", arts.CommentMemoryFileInfo)
	}
	if len(arts.Warnings) != 0 {
		t.Errorf("expected no warnings, got %v", arts.Warnings)
	}
}
func TestLoad_RequiredInputWarningsAreMarked(t *testing.T) {
	dir := t.TempDir()

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !arts.HasRequiredInputWarnings() {
		t.Fatalf("expected required-input warnings, got %+v", arts.Warnings)
	}
	fields := map[string]bool{}
	for _, w := range arts.Warnings {
		if !w.RequiredInput {
			t.Errorf("warning for %q should be marked as a required input: %s", w.Field, w.Message)
		}
		fields[w.Field] = true
	}
	for _, field := range []string{"prompt", "agent_output"} {
		if !fields[field] {
			t.Errorf("expected a %q warning, got %+v", field, arts.Warnings)
		}
	}
}

func TestLoad_ExpectedPatchWarningIsRequiredInput(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))
	t.Setenv("HAS_PATCH", "true")

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(arts.Warnings) != 1 || arts.Warnings[0].Field != "patch" {
		t.Fatalf("Warnings = %+v, want a single patch warning", arts.Warnings)
	}
	if !arts.Warnings[0].RequiredInput || !arts.HasRequiredInputWarnings() {
		t.Errorf("expected the patch warning to be a required input: %+v", arts.Warnings[0])
	}
}

func TestAddWarning_MarksOnlyRequiredInputFields(t *testing.T) {
	arts := &Artifacts{}
	arts.addWarning("comment_memory", "ERR_VALIDATION: advisory")
	if arts.Warnings[0].RequiredInput {
		t.Errorf("comment_memory warning should not be a required input: %+v", arts.Warnings[0])
	}
	if arts.HasRequiredInputWarnings() {
		t.Error("HasRequiredInputWarnings() = true, want false for advisory findings only")
	}

	for _, field := range []string{"prompt", "agent_output", "patch"} {
		required := &Artifacts{}
		required.addWarning(field, "ERR_VALIDATION: degraded")
		if !required.Warnings[0].RequiredInput || !required.HasRequiredInputWarnings() {
			t.Errorf("%q warning should be a required input: %+v", field, required.Warnings[0])
		}
	}
}

func TestLoad_CompleteArtifactsHaveNoRequiredInputWarnings(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	writeTestFile(t, filepath.Join(promptDir, "prompt.txt"), []byte("test prompt"))
	writeTestFile(t, filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`))
	writeTestFile(t, filepath.Join(dir, "aw-feature.patch"), []byte("diff content"))
	t.Setenv("HAS_PATCH", "true")

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if arts.HasRequiredInputWarnings() {
		t.Errorf("expected no required-input warnings, got %+v", arts.Warnings)
	}
}
