package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseKV reads a name=value file (as written to $GITHUB_OUTPUT / $GITHUB_ENV)
// into a map. Later assignments win, mirroring how GitHub Actions collapses
// repeated keys.
func parseKV(t *testing.T, path string) map[string]string {
	t.Helper()
	out := map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out
		}
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed key=value line: %q", line)
		}
		out[k] = v
	}
	return out
}

// writeResultFixture writes a verdict JSON to a temp file and returns its path.
func writeResultFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "detection_result.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	return path
}

const safeVerdict = `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
const threatVerdict = `{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["jailbreak attempt"]}`

func TestConcludeContract(t *testing.T) {
	tests := []struct {
		name            string
		runDetection    string
		warnMode        bool
		executionFailed bool
		// resultContent is written to the result file unless resultMissing is set.
		resultContent  string
		resultMissing  bool
		wantExit       int
		wantConclusion string
		wantSuccess    string
		wantReason     string
	}{
		{
			name:           "skipped when detection not required",
			runDetection:   "false",
			warnMode:       false,
			resultMissing:  true,
			wantExit:       concludeExitProceed,
			wantConclusion: "skipped",
			wantSuccess:    "true",
			wantReason:     "",
		},
		{
			name:           "success on safe verdict",
			runDetection:   "true",
			resultContent:  safeVerdict,
			wantExit:       concludeExitProceed,
			wantConclusion: "success",
			wantSuccess:    "true",
			wantReason:     "",
		},
		{
			name:           "threat fails closed in strict mode",
			runDetection:   "true",
			warnMode:       false,
			resultContent:  threatVerdict,
			wantExit:       concludeExitFail,
			wantConclusion: "failure",
			wantSuccess:    "false",
			wantReason:     "threat_detected",
		},
		{
			name:           "threat warns (not fail) in warn mode",
			runDetection:   "true",
			warnMode:       true,
			resultContent:  threatVerdict,
			wantExit:       concludeExitProceed,
			wantConclusion: "warning",
			wantSuccess:    "false",
			wantReason:     "threat_detected",
		},
		{
			name:           "missing file is agent_failure (strict)",
			runDetection:   "true",
			warnMode:       false,
			resultMissing:  true,
			wantExit:       concludeExitFail,
			wantConclusion: "failure",
			wantSuccess:    "false",
			wantReason:     "agent_failure",
		},
		{
			name:            "missing file warns when execution succeeded",
			runDetection:    "true",
			warnMode:        true,
			executionFailed: false,
			resultMissing:   true,
			wantExit:        concludeExitProceed,
			wantConclusion:  "warning",
			wantSuccess:     "false",
			wantReason:      "agent_failure",
		},
		{
			name:            "missing file fails closed when execution failed (mustFail)",
			runDetection:    "true",
			warnMode:        true,
			executionFailed: true,
			resultMissing:   true,
			wantExit:        concludeExitFail,
			wantConclusion:  "failure",
			wantSuccess:     "false",
			wantReason:      "agent_failure",
		},
		{
			name:           "malformed file is parse_error (strict)",
			runDetection:   "true",
			warnMode:       false,
			resultContent:  "{not json",
			wantExit:       concludeExitFail,
			wantConclusion: "failure",
			wantSuccess:    "false",
			wantReason:     "parse_error",
		},
		{
			name:            "malformed file fails closed when execution failed (mustFail)",
			runDetection:    "true",
			warnMode:        true,
			executionFailed: true,
			resultContent:   "{not json",
			wantExit:        concludeExitFail,
			wantConclusion:  "failure",
			wantSuccess:     "false",
			wantReason:      "parse_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			outPath := filepath.Join(dir, "github_output")
			envPath := filepath.Join(dir, "github_env")

			resultFile := filepath.Join(dir, "detection_result.json")
			if !tt.resultMissing {
				if err := os.WriteFile(resultFile, []byte(tt.resultContent), 0o600); err != nil {
					t.Fatalf("WriteFile error = %v", err)
				}
			}

			var stdout bytes.Buffer
			c := &concluder{
				runDetection:    tt.runDetection,
				warnMode:        tt.warnMode,
				executionFailed: tt.executionFailed,
				githubOutput:    outPath,
				githubEnv:       envPath,
				stdout:          &stdout,
			}

			code := c.run(resultFile)
			if code != tt.wantExit {
				t.Fatalf("exit code = %d, want %d (stdout: %s)", code, tt.wantExit, stdout.String())
			}

			outputs := parseKV(t, outPath)
			if got := outputs["conclusion"]; got != tt.wantConclusion {
				t.Errorf("conclusion output = %q, want %q", got, tt.wantConclusion)
			}
			if got := outputs["success"]; got != tt.wantSuccess {
				t.Errorf("success output = %q, want %q", got, tt.wantSuccess)
			}
			if got := outputs["reason"]; got != tt.wantReason {
				t.Errorf("reason output = %q, want %q", got, tt.wantReason)
			}

			// The exported GH_AW_DETECTION_* variables must agree with outputs.
			env := parseKV(t, envPath)
			if got := env["GH_AW_DETECTION_CONCLUSION"]; got != tt.wantConclusion {
				t.Errorf("GH_AW_DETECTION_CONCLUSION = %q, want %q", got, tt.wantConclusion)
			}
			if got := env["GH_AW_DETECTION_REASON"]; got != tt.wantReason {
				t.Errorf("GH_AW_DETECTION_REASON = %q, want %q", got, tt.wantReason)
			}
		})
	}
}

// TestConcludeUnreadableFileIsAgentFailure verifies that an IO error reading the
// result file (here, the path is a directory) is classified as agent_failure
// (ERR_SYSTEM), not parse_error — unreadable files are a system-side failure,
// while parse_error is reserved for readable-but-malformed content.
func TestConcludeUnreadableFileIsAgentFailure(t *testing.T) {
	dir := t.TempDir()
	// A directory at the result path yields a non-ErrNotExist *fs.PathError from
	// os.ReadFile, deterministically across platforms and regardless of euid.
	resultFile := filepath.Join(dir, "detection_result.json")
	if err := os.Mkdir(resultFile, 0o755); err != nil {
		t.Fatalf("Mkdir error = %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     false,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d (stdout: %s)", code, concludeExitFail, stdout.String())
	}
	if got := parseKV(t, filepath.Join(dir, "out"))["reason"]; got != "agent_failure" {
		t.Errorf("reason output = %q, want %q", got, "agent_failure")
	}
}

func TestConcludeThreatMessageEscaped(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, threatVerdict)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     false,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d", code, concludeExitFail)
	}
	got := stdout.String()
	// The multi-line threat message must be emitted as a single ::error:: line
	// with the newline escaped to %0A.
	if !strings.Contains(got, "::error::") {
		t.Fatalf("expected ::error:: command, got: %q", got)
	}
	if strings.Contains(got, "\nReasons:") {
		t.Fatalf("newline in message must be escaped, got: %q", got)
	}
	if !strings.Contains(got, "%0AReasons:") {
		t.Fatalf("expected escaped newline before Reasons, got: %q", got)
	}
	if !strings.Contains(got, errCodeValidation) {
		t.Fatalf("expected %s prefix, got: %q", errCodeValidation, got)
	}
}

func TestRunConcludeReadsEnv(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, safeVerdict)
	outPath := filepath.Join(dir, "out")
	envPath := filepath.Join(dir, "env")

	t.Setenv("RUN_DETECTION", "true")
	t.Setenv("GH_AW_DETECTION_CONTINUE_ON_ERROR", "false")
	t.Setenv("DETECTION_AGENTIC_EXECUTION_OUTCOME", "success")
	t.Setenv("GITHUB_OUTPUT", outPath)
	t.Setenv("GITHUB_ENV", envPath)

	code := runConclude([]string{"--result-file", resultFile})
	if code != concludeExitProceed {
		t.Fatalf("runConclude() = %d, want %d", code, concludeExitProceed)
	}
	outputs := parseKV(t, outPath)
	if outputs["conclusion"] != "success" {
		t.Fatalf("conclusion = %q, want success", outputs["conclusion"])
	}
}
