package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

func TestBuildTriagePrompt_InlinesBoundedContent(t *testing.T) {
	dir := t.TempDir()
	promptDir := filepath.Join(dir, "aw-prompts")
	if err := os.MkdirAll(promptDir, 0o755); err != nil {
		t.Fatalf("creating prompt dir: %v", err)
	}
	promptPath := filepath.Join(promptDir, "prompt.txt")
	outputPath := filepath.Join(dir, "agent_output.json")
	patchPath := filepath.Join(dir, "aw-change.patch")
	if err := os.WriteFile(promptPath, []byte("workflow prompt content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("agent output content that will be truncated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patchPath, []byte("diff --git a/a b/a\n+change"), 0o644); err != nil {
		t.Fatal(err)
	}

	prompt, err := BuildTriagePrompt(&artifacts.Artifacts{
		PromptFilePath:      promptPath,
		AgentOutputFilePath: outputPath,
		PatchFiles:          []string{patchPath},
		WorkflowName:        "WF",
		WorkflowDescription: "desc",
	}, 24)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"Return only a JSON object", "workflow prompt content", "agent output", "truncated to 24 bytes", "```diff"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("expected triage prompt to contain %q\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, "Output format: THREAT_DETECTION_RESULT:") {
		t.Fatal("triage prompt should request raw structured JSON, not legacy prefixed output")
	}
}

func TestBuildTriagePrompt_RepresentsBundleByMetadata(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "aw-change.bundle")
	if err := os.WriteFile(bundlePath, []byte("bundle bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, err := BuildTriagePrompt(&artifacts.Artifacts{
		PromptFilePath:      "No prompt file found",
		AgentOutputFilePath: "No agent output file found",
		PatchFiles:          []string{bundlePath},
		WorkflowName:        "WF",
		WorkflowDescription: "desc",
	}, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(prompt, "git-bundle binary; content omitted") {
		t.Fatalf("expected bundle metadata, got:\n%s", prompt)
	}
}

func TestReadBoundedText_ReadsThroughLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.txt")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, truncated, err := readBoundedText(path, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Fatal("did not expect truncation at exact limit")
	}
	if got != "0123456789" {
		t.Fatalf("got %q, want full file", got)
	}

	got, truncated, err = readBoundedText(path, 9)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncation beyond limit")
	}
	if got != "012345678" {
		t.Fatalf("got %q, want bounded prefix", got)
	}
}

func TestReadBoundedText_TrimsSplitUTF8Suffix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact.txt")
	if err := os.WriteFile(path, []byte("safe ☃"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, truncated, err := readBoundedText(path, len("safe ")+1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncation")
	}
	if got != "safe " {
		t.Fatalf("got %q, want valid UTF-8 prefix", got)
	}
}
