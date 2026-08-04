package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runDetectionForPromptContext runs a full detection pass against a fake copilot
// that records a safe verdict, returning the parsed prompt_built log record and
// the captured stderr. Extra args are appended before the artifacts dir.
func runDetectionForPromptContext(t *testing.T, env map[string]string, extraArgs ...string) (map[string]any, string) {
	t.Helper()
	artifactsDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "run.jsonl")
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

	args := append([]string{"threat-detect", "-log-file", logPath}, extraArgs...)
	args = append(args, artifactsDir)

	code, stderr := runWithTestArgsCapture(t, args, fullEnv)
	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d; stderr:\n%s", code, exitSafe, stderr)
	}
	records := readJSONLRecords(t, logPath)
	built := findRecord(records, "prompt_built")
	if built == nil {
		t.Fatalf("missing prompt_built record: %#v", records)
	}
	return built, stderr
}

func TestPromptContextDefaultsAreDiagnosable(t *testing.T) {
	built, stderr := runDetectionForPromptContext(t, nil)

	if built["workflow_name_defaulted"] != true {
		t.Errorf("workflow_name_defaulted = %v, want true", built["workflow_name_defaulted"])
	}
	if built["workflow_description_defaulted"] != true {
		t.Errorf("workflow_description_defaulted = %v, want true", built["workflow_description_defaulted"])
	}
	if built["custom_prompt_applied"] != false {
		t.Errorf("custom_prompt_applied = %v, want false", built["custom_prompt_applied"])
	}
	if built["custom_prompt_source"] != "none" {
		t.Errorf("custom_prompt_source = %v, want none", built["custom_prompt_source"])
	}
	if !strings.Contains(stderr, "custom_prompt_source=none") {
		t.Errorf("stderr missing prompt context diagnostic, got:\n%s", stderr)
	}
}

func TestPromptContextEnvCustomPrompt(t *testing.T) {
	built, _ := runDetectionForPromptContext(t, map[string]string{
		"CUSTOM_PROMPT":        "check for base64 blobs",
		"WORKFLOW_NAME":        "My Flow",
		"WORKFLOW_DESCRIPTION": "does things",
	})

	if built["workflow_name"] != "My Flow" {
		t.Errorf("workflow_name = %v, want My Flow", built["workflow_name"])
	}
	if built["workflow_name_defaulted"] != false {
		t.Errorf("workflow_name_defaulted = %v, want false", built["workflow_name_defaulted"])
	}
	if built["custom_prompt_applied"] != true {
		t.Errorf("custom_prompt_applied = %v, want true", built["custom_prompt_applied"])
	}
	if built["custom_prompt_source"] != "env" {
		t.Errorf("custom_prompt_source = %v, want env", built["custom_prompt_source"])
	}
}

func TestPromptContextFlagOverridesEnv(t *testing.T) {
	built, _ := runDetectionForPromptContext(t, map[string]string{
		"CUSTOM_PROMPT": "from env",
		"WORKFLOW_NAME": "env name",
	},
		"-custom-prompt", "from flag",
		"-workflow-name", "flag name",
		"-workflow-description", "flag desc",
	)

	if built["workflow_name"] != "flag name" {
		t.Errorf("workflow_name = %v, want flag name", built["workflow_name"])
	}
	if built["workflow_description"] != "flag desc" {
		t.Errorf("workflow_description = %v, want flag desc", built["workflow_description"])
	}
	if built["custom_prompt_source"] != "flag" {
		t.Errorf("custom_prompt_source = %v, want flag", built["custom_prompt_source"])
	}
}

func TestPromptContextCustomPromptFileWins(t *testing.T) {
	promptFile := filepath.Join(t.TempDir(), "extra.md")
	if err := os.WriteFile(promptFile, []byte("from file"), 0o644); err != nil {
		t.Fatalf("writing custom prompt file: %v", err)
	}

	built, _ := runDetectionForPromptContext(t, map[string]string{
		"CUSTOM_PROMPT": "from env",
	},
		"-custom-prompt", "from flag",
		"-custom-prompt-file", promptFile,
	)

	if built["custom_prompt_source"] != "file" {
		t.Errorf("custom_prompt_source = %v, want file", built["custom_prompt_source"])
	}
	if bytes, ok := built["custom_prompt_bytes"].(float64); !ok || int(bytes) != len("from file") {
		t.Errorf("custom_prompt_bytes = %v, want %d", built["custom_prompt_bytes"], len("from file"))
	}
}

func TestPromptContextExplicitDefaultTextIsNotDefaulted(t *testing.T) {
	// Supplying the fallback text explicitly must not be misreported as defaulted.
	built, stderr := runDetectionForPromptContext(t, nil,
		"-workflow-name", "Unnamed Workflow",
		"-workflow-description", "No description provided",
	)

	if built["workflow_name_defaulted"] != false {
		t.Errorf("workflow_name_defaulted = %v, want false", built["workflow_name_defaulted"])
	}
	if built["workflow_description_defaulted"] != false {
		t.Errorf("workflow_description_defaulted = %v, want false", built["workflow_description_defaulted"])
	}
	if !strings.Contains(stderr, "workflow_description=\"No description provided\"") {
		t.Errorf("stderr missing resolved description, got:\n%s", stderr)
	}
}

func TestPromptContextEmptyFlagClearsEnvCustomPrompt(t *testing.T) {
	// An explicit empty --custom-prompt must win over CUSTOM_PROMPT (flags win),
	// clearing the applied prompt while recording the flag as its provenance.
	built, _ := runDetectionForPromptContext(t, map[string]string{
		"CUSTOM_PROMPT": "from env",
	}, "-custom-prompt", "")

	if built["custom_prompt_applied"] != false {
		t.Errorf("custom_prompt_applied = %v, want false", built["custom_prompt_applied"])
	}
	if built["custom_prompt_source"] != "flag" {
		t.Errorf("custom_prompt_source = %v, want flag", built["custom_prompt_source"])
	}
	if bytes, ok := built["custom_prompt_bytes"].(float64); !ok || int(bytes) != 0 {
		t.Errorf("custom_prompt_bytes = %v, want 0", built["custom_prompt_bytes"])
	}
}

func TestPromptContextRejectsUnreadableCustomPromptFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.md")

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-custom-prompt-file", missing,
		t.TempDir(),
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
