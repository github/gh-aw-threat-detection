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
		"📄 Lines containing THREAT_DETECTION markers (1 of 4):",
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
