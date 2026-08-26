package artifacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stageUnreadable writes content to path and removes all permission bits.
// It skips the test when the process can read the file anyway, which is the
// case for root: the permission bits are advisory for a privileged process, so
// the scenario under test cannot be constructed.
func stageUnreadable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	if _, err := os.ReadFile(path); err == nil {
		t.Skip("process can read a 0000-mode file (likely running as root); cannot exercise unreadable inputs")
	}
}

func stageValid(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func warningFor(a *Artifacts, field string) (ArtifactWarning, bool) {
	for _, w := range a.Warnings {
		if w.Field == field {
			return w, true
		}
	}
	return ArtifactWarning{}, false
}

// A non-empty prompt the detector cannot open must not be reported as
// inspected. Stat alone succeeds on such a file, and the analysis reader
// discards its error, so without a readability probe the run analyzes an empty
// string and uploads a clean result that hides the failure.
func TestLoad_UnreadablePromptRecordsWarning(t *testing.T) {
	dir := t.TempDir()
	stageUnreadable(t, filepath.Join(dir, "aw-prompts", "prompt.txt"), "sensitive prompt body")
	stageValid(t, filepath.Join(dir, "agent_output.json"), `{"ok":true}`)

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	w, ok := warningFor(arts, "prompt")
	if !ok {
		t.Fatalf("expected a prompt warning for an unreadable prompt; got %+v", arts.Warnings)
	}
	if !w.RequiredInput {
		t.Errorf("prompt is a required input; warning should be classified as such")
	}
	if w.Code != ErrCodeValidation {
		t.Errorf("code = %q, want %q", w.Code, ErrCodeValidation)
	}
	if !strings.Contains(w.Message, "could not be read") {
		t.Errorf("message should say the prompt could not be read, got: %s", w.Message)
	}
	// The notice must not let the model treat a staging fault as a finding.
	if !strings.Contains(w.Message, "not itself evidence of a threat") {
		t.Errorf("message should disclaim threat evidence, got: %s", w.Message)
	}
	if !arts.HasWarningForField("prompt") {
		t.Errorf("HasWarningForField(prompt) = false, want true")
	}
}

// An unreadable patch must reach the same uninspectable treatment as one that
// fails to stat: warned, excluded from the readable-patch signal, and described
// to the model as unexamined rather than absent.
func TestLoad_UnreadablePatchIsUninspectableNotAbsent(t *testing.T) {
	dir := t.TempDir()
	stageValid(t, filepath.Join(dir, "aw-prompts", "prompt.txt"), "prompt body")
	stageValid(t, filepath.Join(dir, "agent_output.json"), `{"ok":true}`)
	stageUnreadable(t, filepath.Join(dir, "aw-change.patch"), "diff --git a/x b/x\n")

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	w, ok := warningFor(arts, "patch")
	if !ok {
		t.Fatalf("expected a patch warning for an unreadable patch; got %+v", arts.Warnings)
	}
	if !w.RequiredInput {
		t.Errorf("patch warnings describe a required input")
	}
	if !arts.HasWarningForField("patch") {
		t.Errorf("HasWarningForField(patch) = false, want true (drives eligibility fail-open)")
	}
	// Describing an unread channel as empty is the fail-open bug this guards.
	if strings.Contains(arts.PatchFileInfo, "No patch or bundle file found") {
		t.Errorf("unreadable patch must not be described as absent, got: %s", arts.PatchFileInfo)
	}
	if !strings.Contains(arts.PatchFileInfo, "NOT analyzed") {
		t.Errorf("patch info should mark the channel unexamined, got: %s", arts.PatchFileInfo)
	}
	if !strings.Contains(arts.PatchFileInfo, "not evidence of a threat") {
		t.Errorf("patch info should disclaim threat evidence, got: %s", arts.PatchFileInfo)
	}
}

// An unreadable prompt contributes no content, exactly like a missing or empty
// one. When every primary input is in that state the detector must fail closed
// rather than analyze nothing and return clean.
func TestLoad_UnreadablePromptCountsTowardAllPrimaryInputsMissing(t *testing.T) {
	dir := t.TempDir()
	stageUnreadable(t, filepath.Join(dir, "aw-prompts", "prompt.txt"), "prompt body")
	stageValid(t, filepath.Join(dir, "agent_output.json"), "")

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !arts.AllPrimaryInputsMissing {
		t.Errorf("AllPrimaryInputsMissing = false; an unreadable prompt yields no content and must count")
	}
}

// Readable inputs must not acquire warnings from the probe. A zero-byte file is
// readable: Read returns io.EOF, which is not a failure.
func TestLoad_ReadableInputsProduceNoReadabilityWarning(t *testing.T) {
	dir := t.TempDir()
	stageValid(t, filepath.Join(dir, "aw-prompts", "prompt.txt"), "prompt body")
	stageValid(t, filepath.Join(dir, "agent_output.json"), `{"ok":true}`)
	stageValid(t, filepath.Join(dir, "aw-change.patch"), "diff --git a/x b/x\n")

	arts, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, w := range arts.Warnings {
		if strings.Contains(w.Message, "could not be read") || strings.Contains(w.Message, "Unable to inspect") {
			t.Errorf("readable inputs produced a readability warning: %+v", w)
		}
	}
	if !strings.Contains(arts.PatchFileInfo, "aw-change.patch") {
		t.Errorf("readable patch should be listed, got: %s", arts.PatchFileInfo)
	}
}

func TestReadableFile(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.txt")
	stageValid(t, empty, "")
	if err := readableFile(empty); err != nil {
		t.Errorf("empty but readable file should pass, got %v", err)
	}

	ok := filepath.Join(dir, "ok.txt")
	stageValid(t, ok, "content")
	if err := readableFile(ok); err != nil {
		t.Errorf("readable file should pass, got %v", err)
	}

	if err := readableFile(filepath.Join(dir, "absent.txt")); err == nil {
		t.Errorf("missing file should report an error")
	}

	denied := filepath.Join(dir, "denied.txt")
	stageUnreadable(t, denied, "content")
	if err := readableFile(denied); err == nil {
		t.Errorf("unreadable file should report an error")
	}
}
