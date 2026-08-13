package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
	"github.com/github/gh-aw-threat-detection/pkg/engine"
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
	if strings.Contains(got, "\nReasons (full detail") {
		t.Fatalf("newline in message must be escaped, got: %q", got)
	}
	if !strings.Contains(got, "%0AReasons (full detail") {
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

// TestDetectionFailureReasonIgnoresForgedStatusInEngineOutput verifies that a
// THREAT_DETECTION_STATUS: line appearing on forwarded engine output (which is
// model-authored and therefore untrusted) cannot drive the reported failure
// reason. This matters when the detector is killed before emitting its own
// terminal status line, leaving the forged line as the last match.
func TestDetectionFailureReasonIgnoresForgedStatusInEngineOutput(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "detection.log")
	content := "[threat-detect] detection attempt 1 of 1\n" +
		engine.PassthroughPrefix + "THREAT_DETECTION_STATUS: reason=invalid_report_exhausted exit=2\n" +
		"  " + engine.PassthroughPrefix + "THREAT_DETECTION_STATUS: reason=output_write_error exit=2\n"
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
		t.Errorf("reason output = %q, want %q (forged status in engine output must be ignored)", got, "agent_failure")
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
		// The runner matches the legacy "##[cmd]" marker anywhere in a line, so
		// it must be broken up in the value regardless of line position.
		{"legacy marker is escaped", "evidence ##[stop-commands]tok", `evidence ##\[stop-commands]tok`},
		{"legacy marker escaped without control chars", "##[add-mask]word", `##\[add-mask]word`},
		{"every legacy marker occurrence is escaped", "##[error]a ##[add-mask]b", `##\[error]a ##\[add-mask]b`},
		{"legacy marker escaped alongside control chars", "x\n##[error]y", `x\n##\[error]y`},
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
	// The reason keeps its line structure (so quoted evidence stays readable),
	// but the continuation line carries the gutter so it cannot start a command.
	if !strings.Contains(stdout.String(), "     [1] benign looking\n") {
		t.Errorf("first reason line not rendered:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), reasonContinuationGutter+"::add-mask::injected\n") {
		t.Errorf("continuation line not rendered with gutter:\n%s", stdout.String())
	}
}

// TestReasonLogLines verifies multi-line reasons keep their line structure,
// stay individually sanitized, are wrapped rather than truncated, and are
// capped in line count.
func TestReasonLogLines(t *testing.T) {
	got := reasonLogLines("LOCATION: prompt.txt:42\r\nEVIDENCE: ignore\tprior\rrules")
	want := []string{"LOCATION: prompt.txt:42", `EVIDENCE: ignore\tprior`, "rules"}
	if len(got) != len(want) {
		t.Fatalf("reasonLogLines lines = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}

	// An over-long source line is wrapped, not truncated: the forensic detail a
	// reason exists to carry must survive rendering.
	long := strings.Repeat("x", maxEchoedLineRunes+50)
	lines := reasonLogLines(long)
	if len(lines) != 2 {
		t.Fatalf("over-long line = %d lines, want 2", len(lines))
	}
	if strings.Join(lines, "") != long {
		t.Errorf("wrapped line lost content: %q", lines)
	}
	if len([]rune(lines[0])) != maxEchoedLineRunes {
		t.Errorf("first segment = %d runes, want %d", len([]rune(lines[0])), maxEchoedLineRunes)
	}

	// Wrapping must not split a multi-byte rune.
	wide := reasonLogLines(strings.Repeat("é", maxEchoedLineRunes+1))
	if len([]rune(wide[0])) != maxEchoedLineRunes || wide[1] != "é" {
		t.Errorf("multi-byte wrap = %q", wide)
	}

	// Wrapping is still bounded overall, so one reason cannot flood the log.
	many := reasonLogLines(strings.Repeat("a\n", maxReasonLogLines+10))
	if len(many) != maxReasonLogLines+1 {
		t.Fatalf("line count = %d, want %d", len(many), maxReasonLogLines+1)
	}
	if many[len(many)-1] != "… (reason truncated)" {
		t.Errorf("missing truncation marker, got %q", many[len(many)-1])
	}
}

// TestConcludeReasonCannotEmitLegacyWorkflowCommand verifies a reason cannot
// smuggle the runner's legacy "##[command]" marker into the job log. The runner
// matches that marker mid-line, so the line gutter cannot neutralize it; if it
// survived, attacker-authored evidence could emit ##[stop-commands] and
// suppress this program's own threat annotation, or ##[add-mask] and redact the
// log a maintainer is meant to read.
func TestConcludeReasonCannotEmitLegacyWorkflowCommand(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json")
	verdict := `{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,` +
		`"reasons":["EVIDENCE:\nharmless ##[stop-commands]pwn3d then ##[add-mask]detected"]}`
	if err := os.WriteFile(resultFile, []byte(verdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d", code, concludeExitFail)
	}
	got := stdout.String()
	if strings.Contains(got, "##[") {
		t.Fatalf("live legacy workflow-command marker reached the log:\n%s", got)
	}
	// The evidence must still be present and readable, just inert.
	if !strings.Contains(got, `##\[stop-commands]pwn3d`) || !strings.Contains(got, `##\[add-mask]detected`) {
		t.Fatalf("escaped evidence not rendered:\n%s", got)
	}
	// The threat annotation must still be emitted (it is what stop-commands
	// would have suppressed).
	if !strings.Contains(got, "::error::") {
		t.Fatalf("expected ::error:: annotation, got:\n%s", got)
	}
}

// TestConcludeDiagnosticsCannotEmitLegacyWorkflowCommand verifies the other
// untrusted echo paths — artifact filenames and detection-log lines — are
// neutralized the same way.
func TestConcludeDiagnosticsCannotEmitLegacyWorkflowCommand(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "detection.log")
	logLine := "THREAT_DETECTION_STATUS: reason=engine_error exit=2 ##[add-mask]x\n"
	if err := os.WriteFile(logPath, []byte(logLine), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evil##[error]name.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     true,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		detectionLog: logPath,
		stdout:       &stdout,
	}
	c.run(filepath.Join(dir, "missing_result.json"))

	if strings.Contains(stdout.String(), "##[") {
		t.Fatalf("live legacy workflow-command marker reached the log:\n%s", stdout.String())
	}
}

// TestConcludeAnnotationCannotEmitLegacyWorkflowCommand verifies the workflow
// *command data* path is neutralized too. A parse error quotes the offending
// value from the result file, and that message is emitted as the data portion
// of an "::error::" annotation, which the toolkit's escaping does not clear of
// legacy markers. The runner does not currently rescan the data of a command it
// has already recognized, so this is defense in depth rather than a live
// exposure — but it keeps the annotation consistent with the same value as
// rendered everywhere else in the log.
func TestConcludeAnnotationCannotEmitLegacyWorkflowCommand(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json")
	malformed := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,` +
		`"reasons":[],"##[stop-commands]pwn3d":1}`
	if err := os.WriteFile(resultFile, []byte(malformed), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d", code, concludeExitFail)
	}
	got := stdout.String()
	if strings.Contains(got, "##[") {
		t.Fatalf("live legacy workflow-command marker reached the log:\n%s", got)
	}
	if !strings.Contains(got, `##\[stop-commands]pwn3d`) {
		t.Fatalf("neutralized field name should stay visible:\n%s", got)
	}
	if !strings.Contains(got, "::error::") {
		t.Fatalf("expected ::error:: annotation, got:\n%s", got)
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

func TestRunConcludeRejectsResultFileCollidingWithGithubOutput(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, safeVerdict)
	shared := resultFile

	t.Setenv("RUN_DETECTION", "true")
	t.Setenv("GITHUB_OUTPUT", shared)
	t.Setenv("GITHUB_ENV", filepath.Join(dir, "env"))

	code := runConclude([]string{"--result-file", resultFile})
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

// A missing verdict is a tooling failure, not a security finding: the job log
// must say so plainly, matching gh-aw's engine-error rendering.
func TestConcludeToolingFailureLogsEngineFailure(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json")

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		warnMode:     true,
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitProceed {
		t.Fatalf("exit code = %d, want %d (stdout: %s)", code, concludeExitProceed, stdout.String())
	}
	if !strings.Contains(stdout.String(), "This is a tooling failure, not a security finding.") {
		t.Errorf("job log missing tooling-failure disclaimer; got:\n%s", stdout.String())
	}
}

// TestConcludeThreatMessageSanitizesReasons verifies that model-authored reason
// text cannot inject control characters into the ::error:: annotation. The
// reasons list is open text, so it is escaped the same way reportVerdict
// escapes it before being folded into the workflow command.
func TestConcludeThreatMessageSanitizesReasons(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t,
		`{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["esc\u001b[31m tab\there"]}`)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d", code, concludeExitFail)
	}
	errorLine := ""
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(line, "::error::") {
			errorLine = line
		}
	}
	if errorLine == "" {
		t.Fatalf("expected ::error:: command, got: %q", stdout.String())
	}
	if strings.ContainsAny(errorLine, "\x1b\t") {
		t.Fatalf("control characters must be escaped in the annotation, got: %q", errorLine)
	}
	if !strings.Contains(errorLine, `esc\x1b[31m tab\there`) {
		t.Fatalf("expected escaped reason text, got: %q", errorLine)
	}
}

// TestConcludeRejectsOversizeResultFile verifies that an oversized result file
// is reported as a parse error and fails closed, instead of being read into
// memory and echoed in full into the job log.
func TestConcludeRejectsOversizeResultFile(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t,
		`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":["`+
			strings.Repeat("x", detector.MaxResultFileBytes)+`"]}`)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d", code, concludeExitFail)
	}
	got := stdout.String()
	if !strings.Contains(got, errCodeParse) {
		t.Fatalf("expected %s, got: %q", errCodeParse, got)
	}
	if len(got) > 1<<16 {
		t.Fatalf("oversize result file must not be echoed into the job log; got %d bytes", len(got))
	}
	if outputs := parseKV(t, filepath.Join(dir, "out")); outputs["reason"] != detector.ReasonParseError {
		t.Fatalf("reason = %q, want %q", outputs["reason"], detector.ReasonParseError)
	}
}

// redactedThreatVerdict is the post-split shape of the uploaded result: the
// verdict with no reasons.
const redactedThreatVerdict = `{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":[]}`

// writeSplitResultFixture writes a redacted result plus its conventional
// companion full result, returning the redacted path.
func writeSplitResultFixture(t *testing.T, redacted, full string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "detection_result.json")
	if err := os.WriteFile(path, []byte(redacted), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if full != "" {
		if err := os.WriteFile(detector.FullResultPath(path), []byte(full), 0o600); err != nil {
			t.Fatalf("WriteFile error = %v", err)
		}
	}
	return path
}

// TestConcludeRendersReasonsFromFullResultFile verifies the reasons stripped
// from the uploaded result are recovered from the companion full result and
// rendered into the job log and the threat annotation.
func TestConcludeRendersReasonsFromFullResultFile(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeSplitResultFixture(t, redactedThreatVerdict, threatVerdict)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d", code, concludeExitFail)
	}
	got := stdout.String()
	for _, want := range []string{
		"📄 Full result path: " + detector.FullResultPath(resultFile),
		"✔️  Full result file found; recovered 1 reason(s).",
		"   reasons (1):",
		"     [1] jailbreak attempt",
		"Reasons (full detail in the verdict block above): jailbreak attempt",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stdout missing %q\n--- got ---\n%s", want, got)
		}
	}
}

// TestConcludeFallsBackToInFileReasons verifies a pre-split result — one that
// still carries its own reasons — renders them when no full result exists.
func TestConcludeFallsBackToInFileReasons(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, threatVerdict)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d", code, concludeExitFail)
	}
	got := stdout.String()
	if !strings.Contains(got, "📄 No full result file found at: "+detector.FullResultPath(resultFile)) {
		t.Errorf("expected missing-full-result notice\n--- got ---\n%s", got)
	}
	if !strings.Contains(got, "     [1] jailbreak attempt") {
		t.Errorf("expected in-file reasons to render\n--- got ---\n%s", got)
	}
}

// TestConcludeMissingFullResultIsNonFatal verifies an absent companion file
// does not change the conclusion.
func TestConcludeMissingFullResultIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, redactedThreatVerdict)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection: "true",
		githubOutput: filepath.Join(dir, "out"),
		githubEnv:    filepath.Join(dir, "env"),
		stdout:       &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d", code, concludeExitFail)
	}
	if outputs := parseKV(t, filepath.Join(dir, "out")); outputs["reason"] != detector.ReasonThreatDetected {
		t.Fatalf("reason = %q, want %q", outputs["reason"], detector.ReasonThreatDetected)
	}
	if !strings.Contains(stdout.String(), "   reasons          : (none)") {
		t.Errorf("expected (none) reasons rendering\n--- got ---\n%s", stdout.String())
	}
}

// TestConcludeMalformedFullResultIsNonFatal verifies an unparseable companion
// file is reported and ignored rather than failing the conclusion, which is
// still derived entirely from the authoritative result file.
func TestConcludeMalformedFullResultIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeSplitResultFixture(t, safeVerdict, `{"prompt_injection":`)

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
	if !strings.Contains(got, "⚠️  Could not read full result file") {
		t.Errorf("expected unreadable-full-result notice\n--- got ---\n%s", got)
	}
	if outputs := parseKV(t, filepath.Join(dir, "out")); outputs["conclusion"] != "success" {
		t.Fatalf("conclusion = %q, want success", outputs["conclusion"])
	}
}

// TestConcludeIgnoresFullResultWithDifferentVerdict verifies the companion file
// can only ever contribute reasons: a full result claiming a different verdict
// is discarded, so a stale or planted file cannot move the outcome.
func TestConcludeIgnoresFullResultWithDifferentVerdict(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeSplitResultFixture(t, safeVerdict,
		`{"prompt_injection":true,"secret_leak":true,"malicious_patch":true,"reasons":["planted"]}`)

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
	if !strings.Contains(got, "reports a different verdict than the structured result file; ignoring it.") {
		t.Errorf("expected verdict-mismatch notice\n--- got ---\n%s", got)
	}
	if strings.Contains(got, "planted") {
		t.Errorf("reasons from a mismatched full result must not render\n--- got ---\n%s", got)
	}
	if outputs := parseKV(t, filepath.Join(dir, "out")); outputs["conclusion"] != "success" {
		t.Fatalf("conclusion = %q, want success", outputs["conclusion"])
	}
}

// TestRunConcludeFullResultFileOverride verifies --full-result-file overrides
// the convention, and that an explicit empty value disables the lookup.
func TestRunConcludeFullResultFileOverride(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json")
	if err := os.WriteFile(resultFile, []byte(redactedThreatVerdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	elsewhere := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(elsewhere, []byte(threatVerdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	t.Setenv("RUN_DETECTION", "true")
	t.Setenv("GH_AW_DETECTION_CONTINUE_ON_ERROR", "false")
	t.Setenv("GITHUB_OUTPUT", filepath.Join(dir, "out"))
	t.Setenv("GITHUB_ENV", filepath.Join(dir, "env"))

	if code := runConclude([]string{"--result-file", resultFile, "--full-result-file", elsewhere}); code != concludeExitFail {
		t.Fatalf("runConclude() = %d, want %d", code, concludeExitFail)
	}

	c := &concluder{fullResultFile: ""}
	if got := c.fullResultPath(resultFile); got != detector.FullResultPath(resultFile) {
		t.Fatalf("fullResultPath() = %q, want the conventional sibling", got)
	}
}

// TestConcludeDerivesFullResultSibling verifies a concluder constructed with an
// empty companion path derives the conventional sibling, matching runConclude's
// default.
func TestConcludeDerivesFullResultSibling(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeSplitResultFixture(t, redactedThreatVerdict, threatVerdict)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection:   "true",
		fullResultFile: "",
		githubOutput:   filepath.Join(dir, "out"),
		githubEnv:      filepath.Join(dir, "env"),
		stdout:         &stdout,
	}
	if code := c.run(resultFile); code != concludeExitFail {
		t.Fatalf("exit code = %d, want %d", code, concludeExitFail)
	}
	if !strings.Contains(stdout.String(), "     [1] jailbreak attempt") {
		t.Errorf("expected reasons from the conventional sibling\n--- got ---\n%s", stdout.String())
	}
}

// TestConcludeMalformedFullResultCannotInjectWorkflowCommand verifies that the
// parse error reported for an unreadable companion file — which quotes the
// offending, attacker-influenced value — cannot emit a line of its own that the
// Actions runner would read as a workflow command (TD-20d).
func TestConcludeMalformedFullResultCannotInjectWorkflowCommand(t *testing.T) {
	dir := t.TempDir()
	// `reasons` is a string rather than an array, so the validation error
	// quotes its value verbatim. The value carries a newline followed by a
	// workflow command.
	resultFile := writeSplitResultFixture(t, safeVerdict,
		`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":"oops\n::error::forged"}`)

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
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "::error::") {
			t.Fatalf("malformed full result forged a workflow command: %q", line)
		}
	}
	if !strings.Contains(stdout.String(), `oops\n::error::forged`) {
		t.Errorf("expected the escaped value to remain visible\n--- got ---\n%s", stdout.String())
	}
}

// TestConcludeFullResultPathCannotInjectWorkflowCommand verifies the companion
// path is escaped too, since it reaches the job log on both the missing and the
// verdict-mismatch branch.
func TestConcludeFullResultPathCannotInjectWorkflowCommand(t *testing.T) {
	dir := t.TempDir()
	resultFile := writeResultFixture(t, safeVerdict)

	var stdout bytes.Buffer
	c := &concluder{
		runDetection:   "true",
		fullResultFile: "/tmp/full.json\n::error::forged",
		githubOutput:   filepath.Join(dir, "out"),
		githubEnv:      filepath.Join(dir, "env"),
		stdout:         &stdout,
	}
	if code := c.run(resultFile); code != concludeExitProceed {
		t.Fatalf("exit code = %d, want %d", code, concludeExitProceed)
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "::error::") {
			t.Fatalf("full result path forged a workflow command: %q", line)
		}
	}
}

// TestRunConcludeExplicitEmptyFullResultFileDisablesLookup verifies that an
// explicitly empty --full-result-file skips the companion lookup rather than
// falling back to the convention.
func TestRunConcludeExplicitEmptyFullResultFileDisablesLookup(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "detection_result.json")
	if err := os.WriteFile(resultFile, []byte(redactedThreatVerdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.WriteFile(detector.FullResultPath(resultFile), []byte(threatVerdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	t.Setenv("RUN_DETECTION", "true")
	t.Setenv("GH_AW_DETECTION_CONTINUE_ON_ERROR", "false")
	t.Setenv("GITHUB_OUTPUT", filepath.Join(dir, "out"))
	t.Setenv("GITHUB_ENV", filepath.Join(dir, "env"))

	// runConclude honors the explicit empty value, so the sibling holding the
	// reasons is never consulted even though it exists on disk. The conclusion
	// itself is unchanged, since the verdict comes from the result file.
	stdout := captureStdout(t, func() {
		if code := runConclude([]string{"--result-file", resultFile, "--full-result-file", ""}); code != concludeExitFail {
			t.Fatalf("runConclude() = %d, want %d", code, concludeExitFail)
		}
	})
	if strings.Contains(stdout, "jailbreak attempt") {
		t.Errorf("companion file must not be consulted when disabled\n--- got ---\n%s", stdout)
	}
	if !strings.Contains(stdout, "📄 Full result path: (disabled)") {
		t.Errorf("expected the disabled path rendering\n--- got ---\n%s", stdout)
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns what was
// written, so runConclude's job-log rendering can be asserted.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	defer func() {
		os.Stdout = orig
	}()
	fn()
	w.Close()
	out := <-done
	r.Close()
	return out
}

// TestConcludeHeaderDiagnosticsNeutralizeLegacyWorkflowCommand covers the
// header lines, which echo the host-supplied environment values and paths
// before any verdict is read. They are the earliest untrusted echo in the
// conclusion, and they are emitted through c.info rather than through the
// annotation path, so they need the choke point to be doing its job.
func TestConcludeHeaderDiagnosticsNeutralizeLegacyWorkflowCommand(t *testing.T) {
	dir := t.TempDir()
	resultFile := filepath.Join(dir, "##[add-mask]result.json")
	verdict := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	if err := os.WriteFile(resultFile, []byte(verdict), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	var stdout bytes.Buffer
	c := &concluder{
		runDetection:     "true",
		executionOutcome: "##[stop-commands]outcome",
		githubOutput:     filepath.Join(dir, "out"),
		githubEnv:        filepath.Join(dir, "env"),
		stdout:           &stdout,
	}
	if code := c.run(resultFile); code != concludeExitProceed {
		t.Fatalf("exit code = %d, want %d", code, concludeExitProceed)
	}
	got := stdout.String()
	if strings.Contains(got, "##[") {
		t.Fatalf("live legacy workflow-command marker reached the log:\n%s", got)
	}
	// The values must still be present and readable, just inert.
	if !strings.Contains(got, `##\[add-mask]result.json`) {
		t.Fatalf("escaped result path not rendered:\n%s", got)
	}
	if !strings.Contains(got, `##\[stop-commands]outcome`) {
		t.Fatalf("escaped execution outcome not rendered:\n%s", got)
	}
}
