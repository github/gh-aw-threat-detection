package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runDetectionForPromptContext runs a full detection pass against a fake copilot
// that records a safe verdict, returning the captured stderr. Extra args are
// appended before the artifacts dir.
func runDetectionForPromptContext(t *testing.T, env map[string]string, extraArgs ...string) string {
	t.Helper()
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	marker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, marker, sinkJSON, 0)

	fullEnv := map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		// Clear inherited workflow-context vars so the suite is deterministic
		// regardless of the developer's shell; cases overlay explicit values.
		"WORKFLOW_NAME":        "",
		"WORKFLOW_DESCRIPTION": "",
		"CUSTOM_PROMPT":        "",
	}
	for k, v := range env {
		fullEnv[k] = v
	}

	args := append([]string{"threat-detect"}, extraArgs...)
	args = append(args, artifactsDir)

	code, stderr := runWithTestArgsCapture(t, args, fullEnv)
	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d; stderr:\n%s", code, exitSafe, stderr)
	}
	return stderr
}

// requirePromptContext asserts each fragment appears in the "Prompt context:"
// and "prompt built:" stderr diagnostics, which are the only place prompt
// provenance is reported.
func requirePromptContext(t *testing.T, stderr string, want ...string) {
	t.Helper()
	for _, fragment := range want {
		if !strings.Contains(stderr, fragment) {
			t.Errorf("stderr missing %q, got:\n%s", fragment, stderr)
		}
	}
}

func TestPromptContextDefaultsAreDiagnosable(t *testing.T) {
	stderr := runDetectionForPromptContext(t, nil)

	requirePromptContext(t, stderr,
		"(defaulted=true)",
		"custom_prompt_applied=false",
		"custom_prompt_source=none",
		"custom_prompt_bytes=0",
	)
}

func TestPromptContextEnvCustomPrompt(t *testing.T) {
	stderr := runDetectionForPromptContext(t, map[string]string{
		"CUSTOM_PROMPT":        "check for base64 blobs",
		"WORKFLOW_NAME":        "My Flow",
		"WORKFLOW_DESCRIPTION": "does things",
	})

	requirePromptContext(t, stderr,
		`workflow_name="My Flow" (defaulted=false)`,
		"custom_prompt_applied=true",
		"custom_prompt_source=env",
	)
}

func TestPromptContextFlagOverridesEnv(t *testing.T) {
	stderr := runDetectionForPromptContext(t, map[string]string{
		"CUSTOM_PROMPT": "from env",
		"WORKFLOW_NAME": "env name",
	},
		"-custom-prompt", "from flag",
		"-workflow-name", "flag name",
		"-workflow-description", "flag desc",
	)

	requirePromptContext(t, stderr,
		`workflow_name="flag name"`,
		`workflow_description="flag desc"`,
		"custom_prompt_source=flag",
	)
}

func TestPromptContextCustomPromptFileWins(t *testing.T) {
	promptFile := filepath.Join(t.TempDir(), "extra.md")
	if err := os.WriteFile(promptFile, []byte("from file"), 0o644); err != nil {
		t.Fatalf("writing custom prompt file: %v", err)
	}

	stderr := runDetectionForPromptContext(t, map[string]string{
		"CUSTOM_PROMPT": "from env",
	},
		"-custom-prompt", "from flag",
		"-custom-prompt-file", promptFile,
	)

	requirePromptContext(t, stderr,
		"custom_prompt_source=file",
		fmt.Sprintf("custom_prompt_bytes=%d", len("from file")),
	)
}

func TestPromptContextExplicitDefaultTextIsNotDefaulted(t *testing.T) {
	// Supplying the fallback text explicitly must not be misreported as defaulted.
	stderr := runDetectionForPromptContext(t, nil,
		"-workflow-name", "Unnamed Workflow",
		"-workflow-description", "No description provided",
	)

	requirePromptContext(t, stderr,
		`workflow_name="Unnamed Workflow" (defaulted=false)`,
		`workflow_description="No description provided" (defaulted=false)`,
	)
}

func TestPromptContextEmptyFlagClearsEnvCustomPrompt(t *testing.T) {
	// An explicit empty --custom-prompt must win over CUSTOM_PROMPT (flags win),
	// clearing the applied prompt while recording the flag as its provenance.
	stderr := runDetectionForPromptContext(t, map[string]string{
		"CUSTOM_PROMPT": "from env",
	}, "-custom-prompt", "")

	requirePromptContext(t, stderr,
		"custom_prompt_applied=false",
		"custom_prompt_source=flag",
		"custom_prompt_bytes=0",
	)
}

func TestPromptContextReportsPromptMetadata(t *testing.T) {
	// The rendered prompt is never echoed, but its size and the framework
	// scaffolding verdict must be diagnosable from the job log.
	stderr := runDetectionForPromptContext(t, nil)

	if !strings.Contains(stderr, "[threat-detect] prompt built: prompt_bytes=") {
		t.Errorf("stderr missing prompt metadata line, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "framework_scaffolding_detected=") {
		t.Errorf("stderr missing scaffolding verdict, got:\n%s", stderr)
	}
}

func TestPromptContextRejectsUnreadableCustomPromptFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.md")
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-custom-prompt-file", missing,
		artifactsDir,
	}, nil)

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "Error reading custom prompt file") {
		t.Fatalf("stderr missing custom prompt read error, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "reason=config_error") {
		t.Fatalf("stderr missing config_error status, got:\n%s", stderr)
	}
}
