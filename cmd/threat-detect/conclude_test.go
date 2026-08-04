package main

import (
	"bytes"
	"fmt"
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
		// --- Remaining matrix combinations from
		// {RUN_DETECTION} x {result file present/absent/malformed} x {warn/strict} x
		// {execution outcome} (gh-aw-threat-detection#694). The cases above cover the
		// primary decision paths; these fill in the combinations that exercise
		// mustFail's scope (agent_failure/parse_error only, never threat_detected) and
		// confirm executionFailed is inert on the success path.
		{
			name:           "success on safe verdict is unaffected by warn mode",
			runDetection:   "true",
			warnMode:       true,
			resultContent:  safeVerdict,
			wantExit:       concludeExitProceed,
			wantConclusion: "success",
			wantSuccess:    "true",
			wantReason:     "",
		},
		{
			name:            "success on safe verdict is unaffected by executionFailed",
			runDetection:    "true",
			warnMode:        false,
			executionFailed: true,
			resultContent:   safeVerdict,
			wantExit:        concludeExitProceed,
			wantConclusion:  "success",
			wantSuccess:     "true",
			wantReason:      "",
		},
		{
			name:            "threat_detected warns even when execution failed (mustFail excludes threat_detected)",
			runDetection:    "true",
			warnMode:        true,
			executionFailed: true,
			resultContent:   threatVerdict,
			wantExit:        concludeExitProceed,
			wantConclusion:  "warning",
			wantSuccess:     "false",
			wantReason:      "threat_detected",
		},
		{
			name:            "malformed file warns when execution succeeded",
			runDetection:    "true",
			warnMode:        true,
			executionFailed: false,
			resultContent:   "{not json",
			wantExit:        concludeExitProceed,
			wantConclusion:  "warning",
			wantSuccess:     "false",
			wantReason:      "parse_error",
		},
		{
			name:            "missing file fails closed in strict mode regardless of execution outcome",
			runDetection:    "true",
			warnMode:        false,
			executionFailed: true,
			resultMissing:   true,
			wantExit:        concludeExitFail,
			wantConclusion:  "failure",
			wantSuccess:     "false",
			wantReason:      "agent_failure",
		},
		{
			name:            "malformed file fails closed in strict mode regardless of execution outcome",
			runDetection:    "true",
			warnMode:        false,
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
// while parse_error is reserved for readable-but-malformed content. It also
// completes the {warn/strict} x {execution outcome} matrix for the unreadable-file
// path (gh-aw-threat-detection#694).
func TestConcludeUnreadableFileIsAgentFailure(t *testing.T) {
	tests := []struct {
		name            string
		warnMode        bool
		executionFailed bool
		wantExit        int
		wantConclusion  string
	}{
		{
			name:           "strict mode fails closed",
			warnMode:       false,
			wantExit:       concludeExitFail,
			wantConclusion: "failure",
		},
		{
			name:            "strict mode fails closed regardless of execution outcome",
			warnMode:        false,
			executionFailed: true,
			wantExit:        concludeExitFail,
			wantConclusion:  "failure",
		},
		{
			name:           "warn mode warns when execution succeeded",
			warnMode:       true,
			wantExit:       concludeExitProceed,
			wantConclusion: "warning",
		},
		{
			name:            "warn mode fails closed when execution failed (mustFail)",
			warnMode:        true,
			executionFailed: true,
			wantExit:        concludeExitFail,
			wantConclusion:  "failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// A directory at the result path yields a non-ErrNotExist *fs.PathError
			// from os.ReadFile, deterministically across platforms and regardless of
			// euid.
			resultFile := filepath.Join(dir, "detection_result.json")
			if err := os.Mkdir(resultFile, 0o755); err != nil {
				t.Fatalf("Mkdir error = %v", err)
			}

			var stdout bytes.Buffer
			c := &concluder{
				runDetection:    "true",
				warnMode:        tt.warnMode,
				executionFailed: tt.executionFailed,
				githubOutput:    filepath.Join(dir, "out"),
				githubEnv:       filepath.Join(dir, "env"),
				stdout:          &stdout,
			}
			if code := c.run(resultFile); code != tt.wantExit {
				t.Fatalf("exit code = %d, want %d (stdout: %s)", code, tt.wantExit, stdout.String())
			}
			outputs := parseKV(t, filepath.Join(dir, "out"))
			if got := outputs["reason"]; got != "agent_failure" {
				t.Errorf("reason output = %q, want %q", got, "agent_failure")
			}
			if got := outputs["conclusion"]; got != tt.wantConclusion {
				t.Errorf("conclusion output = %q, want %q", got, tt.wantConclusion)
			}
			// success=false on every fail path, warn or strict — only a clean
			// verdict (or skip) sets success=true.
			if got := outputs["success"]; got != "false" {
				t.Errorf("success output = %q, want %q", got, "false")
			}
			env := parseKV(t, filepath.Join(dir, "env"))
			if got := env["GH_AW_DETECTION_REASON"]; got != "agent_failure" {
				t.Errorf("GH_AW_DETECTION_REASON = %q, want %q", got, "agent_failure")
			}
			if got := env["GH_AW_DETECTION_CONCLUSION"]; got != tt.wantConclusion {
				t.Errorf("GH_AW_DETECTION_CONCLUSION = %q, want %q", got, tt.wantConclusion)
			}
		})
	}
}

func TestConcludeWritesVerdictStepSummary(t *testing.T) {
	dir := t.TempDir()
	stepSummaryPath := filepath.Join(dir, "step_summary.md")
	resultFile := writeResultFixture(t, threatVerdict)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     false,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stepSummary:  stepSummaryPath,
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d (stdout: %s)", code, concludeExitFail, stdout.String())
	}

	data, err := os.ReadFile(stepSummaryPath)
	if err != nil {
		t.Fatalf("ReadFile(stepSummaryPath) error = %v", err)
	}
	summary := string(data)
	for _, want := range []string{
		"<summary>Threat Detection Verdict</summary>",
		"| Prompt Injection | true |",
		"| Conclusion | failure |",
		"| Reason Code | threat_detected |",
		"jailbreak attempt",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("step summary missing %q; got:\n%s", want, summary)
		}
	}
}

func TestConcludeSkippedWritesVerdictStepSummary(t *testing.T) {
	dir := t.TempDir()
	stepSummaryPath := filepath.Join(dir, "step_summary.md")

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "false",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stepSummary:  stepSummaryPath,
		stdout:       &stdout,
	}
	if code := c.run(filepath.Join(dir, "detection_result.json")); code != concludeExitProceed {
		t.Fatalf("exit code = %d, want %d (stdout: %s)", code, concludeExitProceed, stdout.String())
	}

	data, err := os.ReadFile(stepSummaryPath)
	if err != nil {
		t.Fatalf("ReadFile(stepSummaryPath) error = %v", err)
	}
	if !strings.Contains(string(data), "| Conclusion | skipped |") {
		t.Errorf("step summary missing skipped conclusion; got:\n%s", string(data))
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

// TestDetectionFailureReasonMapping verifies every THREAT_DETECTION_STATUS
// reason from the detection run's captured log maps to the correct gh-aw
// reason when the structured result file is missing, per the table in issue
// #693 and specs/threat-detection-spec.md TD-20b.
func TestDetectionFailureReasonMapping(t *testing.T) {
	tests := []struct {
		statusReason string // reason= value in the captured THREAT_DETECTION_STATUS line
		wantReason   string // gh-aw reason expected on the conclude output
	}{
		{"invalid_report_exhausted", "parse_error"},
		{"output_write_error", "parse_error"},
		{"engine_error", "agent_failure"},
		{"cancelled", "agent_failure"},
		{"config_error", "agent_failure"},
		{"result_recorded", "agent_failure"}, // not a failure reason; falls back to default
		{"some_future_unknown_reason", "agent_failure"},
	}

	for _, tt := range tests {
		t.Run(tt.statusReason, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, "detection.log")
			logLine := "THREAT_DETECTION_STATUS: reason=" + tt.statusReason + " exit=2\n"
			if err := os.WriteFile(logPath, []byte(logLine), 0o600); err != nil {
				t.Fatalf("WriteFile error = %v", err)
			}

			outPath := filepath.Join(dir, "out")
			envPath := filepath.Join(dir, "env")
			resultFile := filepath.Join(dir, "detection_result.json") // deliberately absent

			var stdout bytes.Buffer
			c := &concluder{
				runDetection: "true",
				warnMode:     false,
				githubOutput: outPath,
				githubEnv:    envPath,
				detectionLog: logPath,
				stdout:       &stdout,
			}
			code := c.run(resultFile)
			if code != concludeExitFail {
				t.Fatalf("exit code = %d, want %d (stdout: %s)", code, concludeExitFail, stdout.String())
			}
			outputs := parseKV(t, outPath)
			if got := outputs["reason"]; got != tt.wantReason {
				t.Errorf("reason output = %q, want %q", got, tt.wantReason)
			}
		})
	}
}

// TestDetectionFailureReasonUsesLastStatusLine verifies that when the captured
// log contains multiple THREAT_DETECTION_STATUS lines (e.g. from a retried
// invocation), only the last one is consulted.
func TestDetectionFailureReasonUsesLastStatusLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "detection.log")
	content := "THREAT_DETECTION_STATUS: reason=engine_error exit=2\n" +
		"THREAT_DETECTION_STATUS: reason=invalid_report_exhausted exit=2\n"
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	outPath := filepath.Join(dir, "out")
	envPath := filepath.Join(dir, "env")
	resultFile := filepath.Join(dir, "detection_result.json")

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     false,
		githubOutput: outPath,
		githubEnv:    envPath,
		detectionLog: logPath,
		stdout:       &stdout,
	}
	c.run(resultFile)
	outputs := parseKV(t, outPath)
	if got := outputs["reason"]; got != "parse_error" {
		t.Errorf("reason output = %q, want %q (should use last status line)", got, "parse_error")
	}
}

// TestDetectionFailureReasonTerminalLineWithoutReasonResetsCandidate verifies
// that a terminal THREAT_DETECTION_STATUS: line lacking a reason= token (e.g.
// truncated or malformed) does not let an earlier line's reason leak through
// as a stale candidate; per TD-20b an absent/unrecognized reason on the
// terminal line falls back to agent_failure.
func TestDetectionFailureReasonTerminalLineWithoutReasonResetsCandidate(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "detection.log")
	content := "THREAT_DETECTION_STATUS: reason=invalid_report_exhausted exit=2\n" +
		"THREAT_DETECTION_STATUS: exit=2\n" // terminal line has no reason= token
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	outPath := filepath.Join(dir, "out")
	envPath := filepath.Join(dir, "env")
	resultFile := filepath.Join(dir, "detection_result.json")

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     false,
		githubOutput: outPath,
		githubEnv:    envPath,
		detectionLog: logPath,
		stdout:       &stdout,
	}
	c.run(resultFile)
	outputs := parseKV(t, outPath)
	if got := outputs["reason"]; got != "agent_failure" {
		t.Errorf("reason output = %q, want %q (stale reason from earlier line must not leak through)", got, "agent_failure")
	}
}

// TestDetectionFailureReasonWithoutLogFallsBackToAgentFailure verifies that a
// missing or absent detection log preserves the pre-existing agent_failure
// default rather than erroring.
func TestDetectionFailureReasonWithoutLogFallsBackToAgentFailure(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out")
	envPath := filepath.Join(dir, "env")
	resultFile := filepath.Join(dir, "detection_result.json")

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     false,
		githubOutput: outPath,
		githubEnv:    envPath,
		detectionLog: filepath.Join(dir, "does-not-exist.log"),
		stdout:       &stdout,
	}
	c.run(resultFile)
	outputs := parseKV(t, outPath)
	if got := outputs["reason"]; got != "agent_failure" {
		t.Errorf("reason output = %q, want %q", got, "agent_failure")
	}
}

// TestRunConcludeDefaultsDetectionLogPath verifies that --detection-log, when
// not set, defaults to detection.log next to the result file, and that its
// status line correctly refines the reported reason.
func TestRunConcludeDefaultsDetectionLogPath(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json") // absent
	logPath := filepath.Join(dir, "detection.log")
	if err := os.WriteFile(logPath, []byte("THREAT_DETECTION_STATUS: reason=invalid_report_exhausted exit=2\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	outPath := filepath.Join(dir, "out")
	envPath := filepath.Join(dir, "env")

	t.Setenv("RUN_DETECTION", "true")
	t.Setenv("GH_AW_DETECTION_CONTINUE_ON_ERROR", "false")
	t.Setenv("GITHUB_OUTPUT", outPath)
	t.Setenv("GITHUB_ENV", envPath)

	code := runConclude([]string{"--result-file", resultFile})
	if code != concludeExitFail {
		t.Fatalf("runConclude() = %d, want %d", code, concludeExitFail)
	}
	outputs := parseKV(t, outPath)
	if got := outputs["reason"]; got != "parse_error" {
		t.Fatalf("reason = %q, want %q", got, "parse_error")
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

// TestConcludeDiagnosticOutput verifies the verbose job-log rendering: the
// banners, the echoed environment inputs, and the per-field verdict breakdown
// with an indexed reasons list. This is the parity contract with gh-aw's inline
// conclusion step — debugging must be possible from the job log alone.
func TestConcludeDiagnosticOutput(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json")
	if err := os.WriteFile(resultFile, []byte(threatVerdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection:     "true",
		warnMode:         true,
		executionOutcome: "success",
		githubOutput:     filepath.Join(dir, "out"),
		githubEnv:        filepath.Join(dir, "env"),
		stdout:           &stdout,
	}
	if code := c.run(resultFile); code != concludeExitProceed {
		t.Fatalf("exit code = %d, want %d", code, concludeExitProceed)
	}

	got := stdout.String()
	for _, want := range []string{
		bannerRule,
		"🛡️  Threat Detection: Parse Results & Conclude",
		`📋 RUN_DETECTION env: "true"`,
		"📋 continue-on-error: true",
		`📋 detection execution outcome: "success"`,
		"📁 Threat detection directory: " + dir,
		"📄 Detection log path: " + filepath.Join(dir, defaultDetectionLogName),
		"📄 Structured result path: " + resultFile,
		"🔎 Checking for structured result file: " + resultFile,
		"✔️  Structured result file found and parsed successfully.",
		"📋 Threat detection verdict (from structured result file):",
		"   prompt_injection : true",
		"   secret_leak      : false",
		"   malicious_patch  : false",
		"   reasons (1):",
		"     [1] jailbreak attempt",
		"🛡️  Threat detection conclusion complete.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stdout missing %q\n--- got ---\n%s", want, got)
		}
	}
}

// TestConcludeSafeVerdictBreakdown verifies the verdict breakdown is emitted on
// the success path too, with the "(none)" reasons rendering.
func TestConcludeSafeVerdictBreakdown(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json")
	if err := os.WriteFile(resultFile, []byte(safeVerdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitProceed {
		t.Fatalf("exit code = %d, want %d", code, concludeExitProceed)
	}
	got := stdout.String()
	for _, want := range []string{
		"   prompt_injection : false",
		"   reasons          : (none)",
		"✅ No security threats detected. Safe outputs may proceed.",
		"🛡️  Threat detection conclusion complete.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stdout missing %q\n--- got ---\n%s", want, got)
		}
	}
}

// TestConcludeSkippedOutput verifies the skip path is framed by both banners and
// explains itself, rather than emitting a single bare line.
func TestConcludeSkippedOutput(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(filepath.Join(dir, "detection_result.json")); code != concludeExitProceed {
		t.Fatalf("exit code = %d, want %d", code, concludeExitProceed)
	}
	got := stdout.String()
	for _, want := range []string{
		"🛡️  Threat Detection: Parse Results & Conclude",
		"✅ Detection skipped — no threats to evaluate.",
		"🛡️  Threat detection conclusion complete.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stdout missing %q\n--- got ---\n%s", want, got)
		}
	}
	// The skip path must not read or report on any verdict.
	if strings.Contains(got, "Threat detection verdict") {
		t.Errorf("skip path must not report a verdict, got:\n%s", got)
	}
}

// TestConcludeMissingResultDiagnostics verifies that a missing result file
// triggers a recursive directory listing plus detection-log stats and an echo of
// the THREAT_DETECTION marker lines.
func TestConcludeMissingResultDiagnostics(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatalf("MkdirAll error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nested", "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	logPath := filepath.Join(dir, defaultDetectionLogName)
	logBody := "starting\nTHREAT_DETECTION_STATUS: reason=engine_error exit=2\ndone\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     true,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	code := c.run(filepath.Join(dir, "detection_result.json"))
	if code != concludeExitProceed {
		t.Fatalf("exit code = %d, want %d", code, concludeExitProceed)
	}

	got := stdout.String()
	for _, want := range []string{
		"📁 Listing all files in artifact directory for diagnosis: " + dir,
		"     - " + filepath.Join("nested", "stray.txt"),
		"     - " + defaultDetectionLogName,
		fmt.Sprintf("📊 Detection log stats: 4 lines, %d bytes", len(logBody)),
		"📄 Lines containing THREAT_DETECTION markers (1 of 4 lines):",
		"   [2] THREAT_DETECTION_STATUS: reason=engine_error exit=2",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stdout missing %q\n--- got ---\n%s", want, got)
		}
	}
}

// TestConcludeMissingDetectionLogIsReported verifies the diagnostics degrade
// gracefully when the detection log itself is absent.
func TestConcludeMissingDetectionLogIsReported(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	c.run(filepath.Join(dir, "detection_result.json"))
	if want := "📄 No detection log found at: " + filepath.Join(dir, defaultDetectionLogName); !strings.Contains(stdout.String(), want) {
		t.Errorf("stdout missing %q\n--- got ---\n%s", want, stdout.String())
	}
}

// TestConcludeDetectionLogOverride verifies --detection-log points the
// diagnostics at an explicit path instead of the default sibling file.
func TestConcludeDetectionLogOverride(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.log")
	if err := os.WriteFile(custom, []byte("THREAT_DETECTION_RESULT: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		detectionLog: custom,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	c.run(filepath.Join(dir, "detection_result.json"))
	got := stdout.String()
	if !strings.Contains(got, "📄 Detection log path: "+custom) {
		t.Errorf("stdout missing custom detection log path\n--- got ---\n%s", got)
	}
	if !strings.Contains(got, "[1] THREAT_DETECTION_RESULT: {}") {
		t.Errorf("stdout missing echoed marker line\n--- got ---\n%s", got)
	}
}

// TestConcludeRunLog verifies the conclusion is mirrored into the JSONL run log
// when --log-file is set.
func TestConcludeRunLog(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json")
	if err := os.WriteFile(resultFile, []byte(threatVerdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	logPath := filepath.Join(dir, "run.jsonl")

	t.Setenv("RUN_DETECTION", "true")
	t.Setenv("GH_AW_DETECTION_CONTINUE_ON_ERROR", "false")
	t.Setenv("DETECTION_AGENTIC_EXECUTION_OUTCOME", "success")
	t.Setenv("GITHUB_OUTPUT", filepath.Join(dir, "out"))
	t.Setenv("GITHUB_ENV", filepath.Join(dir, "env"))

	if code := runConclude([]string{"--result-file", resultFile, "--log-file", logPath}); code != concludeExitFail {
		t.Fatalf("runConclude() = %d, want %d", code, concludeExitFail)
	}

	records := readJSONLRecords(t, logPath)
	start := findRecord(records, "conclude_start")
	if start == nil {
		t.Fatal("missing conclude_start record")
	}
	if start["run_detection"] != "true" || start["execution_outcome"] != "success" || start["result_file"] != resultFile {
		t.Errorf("conclude_start fields = %v", start)
	}

	verdict := findRecord(records, "conclude_verdict")
	if verdict == nil {
		t.Fatal("missing conclude_verdict record")
	}
	if verdict["prompt_injection"] != true || verdict["secret_leak"] != false || verdict["has_threats"] != true {
		t.Errorf("conclude_verdict fields = %v", verdict)
	}

	outcome := findRecord(records, "conclude_outcome")
	if outcome == nil {
		t.Fatal("missing conclude_outcome record")
	}
	if outcome["conclusion"] != "failure" || outcome["reason"] != "threat_detected" || outcome["level"] != "error" {
		t.Errorf("conclude_outcome fields = %v", outcome)
	}
}

// TestSanitizeLogValue verifies untrusted values cannot break out of their log
// line. An embedded newline would otherwise let a model-authored reason or an
// artifact filename emit a line of its own beginning with "::", which the
// Actions runner interprets as a workflow command.
func TestSanitizeLogValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is unchanged", "jailbreak attempt", "jailbreak attempt"},
		{"unicode is preserved", "emoji 🚨 and accents é", "emoji 🚨 and accents é"},
		{"newline is escaped", "text\n::add-mask::secret", `text\n::add-mask::secret`},
		{"carriage return is escaped", "text\r::error::boom", `text\r::error::boom`},
		{"tab is escaped", "a\tb", `a\tb`},
		{"other control chars are escaped", "a\x00b\x1bc", `a\x00b\x1bc`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeLogValue(tt.in); got != tt.want {
				t.Errorf("sanitizeLogValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestConcludeReasonCannotInjectWorkflowCommand verifies a malicious reason in
// the verdict cannot emit an unprefixed workflow command into the job log.
func TestConcludeReasonCannotInjectWorkflowCommand(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json")
	verdict := `{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,` +
		`"reasons":["benign looking\n::add-mask::injected"]}`
	if err := os.WriteFile(resultFile, []byte(verdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     true,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	c.run(resultFile)

	for _, line := range strings.Split(stdout.String(), "\n") {
		trimmed := strings.TrimSpace(line)
		// The only workflow command this run may emit is the threat warning.
		if strings.HasPrefix(trimmed, "::") && !strings.HasPrefix(trimmed, "::warning::") {
			t.Errorf("unexpected workflow command emitted: %q", line)
		}
	}
	if !strings.Contains(stdout.String(), `[1] benign looking\n::add-mask::injected`) {
		t.Errorf("escaped reason not rendered on a single line:\n%s", stdout.String())
	}
}

// TestConcludeFilenameCannotInjectWorkflowCommand verifies the directory
// listing escapes newlines in artifact filenames, which are untrusted.
func TestConcludeFilenameCannotInjectWorkflowCommand(t *testing.T) {
	dir := t.TempDir()
	// Linux permits newlines in filenames; a crafted artifact name must not be
	// able to start a new log line.
	evil := filepath.Join(dir, "evil\n::add-mask::injected.txt")
	if err := os.WriteFile(evil, []byte("x"), 0o600); err != nil {
		t.Skipf("filesystem rejects newline in filename: %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     true,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	c.run(filepath.Join(dir, "detection_result.json"))

	for _, line := range strings.Split(stdout.String(), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "::") && !strings.HasPrefix(trimmed, "::warning::") {
			t.Errorf("unexpected workflow command emitted: %q", line)
		}
	}
	if !strings.Contains(stdout.String(), `- evil\n::add-mask::injected.txt`) {
		t.Errorf("escaped filename not rendered on a single line:\n%s", stdout.String())
	}
}

// TestConcludeTruncatedDetectionLogStats verifies that when only a prefix of a
// large detection log is scanned, the reported stats say so instead of passing
// the prefix off as the whole file.
func TestConcludeTruncatedDetectionLogStats(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, defaultDetectionLogName)
	// Comfortably larger than the read bound so truncation is guaranteed.
	body := strings.Repeat("padding line to fill the detection log\n", 300000)
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if int64(len(body)) <= diagnosticLogMaxSize {
		t.Fatalf("fixture too small: %d bytes, want > %d", len(body), diagnosticLogMaxSize)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     true,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	c.run(filepath.Join(dir, "detection_result.json"))

	got := stdout.String()
	if !strings.Contains(got, fmt.Sprintf("%d bytes total", len(body))) {
		t.Errorf("stats must report the true file size (%d bytes):\n%s", len(body), got)
	}
	for _, want := range []string{
		fmt.Sprintf("scanned first %d bytes", diagnosticLogMaxSize),
		"log truncated for diagnostics",
		"scanned lines",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stdout missing %q:\n%s", want, got)
		}
	}
}

// TestConcludeRejectsLogFileCollisions verifies --log-file (opened O_TRUNC) is
// refused when it aliases an input this command reads: truncating the result
// file would erase the verdict, and truncating the detection log would erase
// the failure diagnostics.
func TestConcludeRejectsLogFileCollisions(t *testing.T) {
	t.Run("collides with result file", func(t *testing.T) {
		dir := t.TempDir()
		resultFile := filepath.Join(dir, "detection_result.json")
		if err := os.WriteFile(resultFile, []byte(safeVerdict), 0o600); err != nil {
			t.Fatalf("WriteFile error = %v", err)
		}
		t.Setenv("RUN_DETECTION", "true")
		t.Setenv("GITHUB_OUTPUT", filepath.Join(dir, "out"))
		t.Setenv("GITHUB_ENV", filepath.Join(dir, "env"))

		if code := runConclude([]string{"--result-file", resultFile, "--log-file", resultFile}); code != concludeExitFail {
			t.Fatalf("runConclude() = %d, want %d", code, concludeExitFail)
		}
		// The verdict must survive: rejection happens before the log is opened.
		data, err := os.ReadFile(resultFile)
		if err != nil {
			t.Fatalf("ReadFile error = %v", err)
		}
		if string(data) != safeVerdict {
			t.Errorf("result file was modified: %q", string(data))
		}
	})

	t.Run("collides with detection log", func(t *testing.T) {
		dir := t.TempDir()
		resultFile := filepath.Join(dir, "detection_result.json")
		logPath := filepath.Join(dir, defaultDetectionLogName)
		if err := os.WriteFile(logPath, []byte("THREAT_DETECTION_STATUS: reason=engine_error exit=2\n"), 0o600); err != nil {
			t.Fatalf("WriteFile error = %v", err)
		}
		t.Setenv("RUN_DETECTION", "true")
		t.Setenv("GITHUB_OUTPUT", filepath.Join(dir, "out"))
		t.Setenv("GITHUB_ENV", filepath.Join(dir, "env"))

		// The default detection-log path must participate in the check even
		// though --detection-log was not passed explicitly.
		if code := runConclude([]string{"--result-file", resultFile, "--log-file", logPath}); code != concludeExitFail {
			t.Fatalf("runConclude() = %d, want %d", code, concludeExitFail)
		}
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("ReadFile error = %v", err)
		}
		if len(data) == 0 {
			t.Error("detection log was truncated")
		}
	})
}

// TestConcludeUnopenableLogFileIsConfigError verifies that failing to open an
// explicitly requested --log-file fails the step (TD-20a) rather than silently
// concluding without the required JSONL mirroring.
func TestConcludeUnopenableLogFileIsConfigError(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, safeVerdict)
	// A directory cannot be opened for writing.
	logPath := filepath.Join(dir, "logdir")
	if err := os.Mkdir(logPath, 0o755); err != nil {
		t.Fatalf("Mkdir error = %v", err)
	}

	t.Setenv("RUN_DETECTION", "true")
	t.Setenv("GITHUB_OUTPUT", filepath.Join(dir, "out"))
	t.Setenv("GITHUB_ENV", filepath.Join(dir, "env"))

	if code := runConclude([]string{"--result-file", resultFile, "--log-file", logPath}); code != concludeExitFail {
		t.Fatalf("runConclude() = %d, want %d", code, concludeExitFail)
	}
}

func TestRunConcludeRejectsStepSummaryCollidingWithResultFile(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, safeVerdict)

	t.Setenv("RUN_DETECTION", "true")
	t.Setenv("GITHUB_OUTPUT", filepath.Join(dir, "out"))
	t.Setenv("GITHUB_ENV", filepath.Join(dir, "env"))

	code := runConclude([]string{"--result-file", resultFile, "--step-summary", resultFile})
	if code != concludeExitFail {
		t.Fatalf("runConclude() = %d, want %d (fail closed on collision)", code, concludeExitFail)
	}
	// The result file must survive untouched — a collision must be rejected
	// before anything is written, so the structured verdict is never clobbered.
	data, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatalf("ReadFile(resultFile) error = %v", err)
	}
	if string(data) != safeVerdict {
		t.Fatalf("result file was modified: got %q, want %q", string(data), safeVerdict)
	}
}

func TestRunConcludeRejectsStepSummaryCollidingWithGithubOutput(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, safeVerdict)
	shared := filepath.Join(dir, "shared")

	t.Setenv("RUN_DETECTION", "true")
	t.Setenv("GITHUB_OUTPUT", shared)
	t.Setenv("GITHUB_ENV", filepath.Join(dir, "env"))

	code := runConclude([]string{"--result-file", resultFile, "--step-summary", shared})
	if code != concludeExitFail {
		t.Fatalf("runConclude() = %d, want %d (fail closed on collision)", code, concludeExitFail)
	}
}
