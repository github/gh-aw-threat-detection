package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

func TestRunInvokesAgenticEngine(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["agentic detection"]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitThreat {
		t.Fatalf("run() exit code = %d, want %d", code, exitThreat)
	}
	if _, err := os.Stat(copilotMarker); err != nil {
		t.Fatalf("expected copilot to run: %v", err)
	}
	result := readResultFile(t, outputPath)
	if !result["prompt_injection"].(bool) {
		t.Fatalf("result prompt_injection = false, want true: %#v", result)
	}
}

func TestRunPassesPromptAnalysisToEngine(t *testing.T) {
	artifactsDir := t.TempDir()
	promptsDir := filepath.Join(artifactsDir, "aw-prompts")
	if err := os.MkdirAll(promptsDir, 0o755); err != nil {
		t.Fatalf("creating prompts directory: %v", err)
	}
	files := map[string]string{
		"prompt-template.txt":     "Trusted instructions.\nRequest: {{user_input}}\nEnd.",
		"prompt.txt":              "Trusted instructions.\nRequest: inspect this issue\nEnd.",
		"prompt-import-tree.json": `{"version":1,"children":[]}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(promptsDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "agent_output.json"), []byte(`{"items":[]}`), 0o600); err != nil {
		t.Fatalf("writing agent output: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "result.json")
	promptCapture := filepath.Join(t.TempDir(), "engine-prompt.txt")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotCapturingPrompt(t, copilotMarker, promptCapture, sinkJSON)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})
	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d", code, exitSafe)
	}
	if strings.Contains(stderr, "prompt analysis artifact") {
		t.Fatalf("unexpected degraded-analysis warning:\n%s", stderr)
	}

	prompt, err := os.ReadFile(promptCapture)
	if err != nil {
		t.Fatalf("reading captured engine prompt: %v", err)
	}
	for _, want := range []string{
		"## Prompt Analysis (Trusted vs Untrusted Content)",
		"### Prompt Template (pre-interpolation)",
		"### Import Tree (runtime-import provenance)",
		"### Extracted Untrusted Inputs",
		"inspect this issue",
	} {
		if !strings.Contains(string(prompt), want) {
			t.Errorf("engine prompt missing %q", want)
		}
	}
}

func TestRunPrefersSinkResultOverTranscript(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["from sink"]}`
	// stdout carries a conflicting legacy THREAT_DETECTION_RESULT line that
	// reports a *safe* verdict. The sink (first valid result) must win and the
	// transcript line must be ignored entirely; if stdout scraping is ever
	// reintroduced, this test fails.
	conflictingStdout := `THREAT_DETECTION_RESULT:{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":["from transcript"]}`
	fakeBinDir := writeFakeCopilotWithSinkAndStdout(t, copilotMarker, sinkJSON, conflictingStdout, 0)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitThreat {
		t.Fatalf("run() exit code = %d, want %d", code, exitThreat)
	}
	if _, err := os.Stat(copilotMarker); err != nil {
		t.Fatalf("expected copilot to run: %v", err)
	}
	result := readResultFile(t, outputPath)
	if !result["prompt_injection"].(bool) {
		t.Fatalf("expected sink-derived result, got %#v", result)
	}
	// The uploaded result is always redacted; the sink reasons land in the
	// companion full result.
	reasons, _ := result["reasons"].([]any)
	if len(reasons) != 0 {
		t.Fatalf("expected redacted reasons in %s, got %#v", outputPath, result["reasons"])
	}
	full := readResultFile(t, detector.FullResultPath(outputPath))
	if !full["prompt_injection"].(bool) {
		t.Fatalf("expected sink-derived full result, got %#v", full)
	}
	fullReasons, _ := full["reasons"].([]any)
	if len(fullReasons) != 1 || fullReasons[0].(string) != "from sink" {
		t.Fatalf("expected sink reasons, got %#v", full["reasons"])
	}
}

func TestRunSplitsReasonsIntoFullResultFile(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "detection_result.json")
	fullPath := filepath.Join(filepath.Dir(outputPath), "detection_result_full.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["exfiltration attempt in comment body"]}`
	fakeBinDir := writeFakeCopilotWithSinkAndStdout(t, copilotMarker, sinkJSON, "", 0)

	stderr := captureStderr(t, func() {
		code := runWithTestArgs(t, []string{
			"threat-detect",
			"-output", outputPath,
			artifactsDir,
		}, map[string]string{
			"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		})
		if code != exitThreat {
			t.Fatalf("run() exit code = %d, want %d", code, exitThreat)
		}
	})

	// The reason must not appear on stderr: hosts tee stderr into files they
	// publish, so echoing it there would defeat the split.
	if strings.Contains(stderr, "exfiltration attempt in comment body") {
		t.Errorf("reason text leaked into stderr:\n%s", stderr)
	}

	redacted, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading redacted result: %v", err)
	}
	if strings.Contains(string(redacted), "exfiltration attempt") {
		t.Errorf("reason text leaked into %s: %s", outputPath, redacted)
	}
	full := readResultFile(t, fullPath)
	fullReasons, _ := full["reasons"].([]any)
	if len(fullReasons) != 1 || fullReasons[0].(string) != "exfiltration attempt in comment body" {
		t.Fatalf("full result reasons = %#v, want the reported reason", full["reasons"])
	}
}

func TestRunFullOutputCanBeDisabled(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "detection_result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSinkAndStdout(t, copilotMarker, sinkJSON, "", 0)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-full-output", "",
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})
	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d", code, exitSafe)
	}
	if _, err := os.Stat(detector.FullResultPath(outputPath)); !os.IsNotExist(err) {
		t.Fatalf("expected no full result file, stat err = %v", err)
	}
}

func TestRunRejectsFullOutputAliasingOutput(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "detection_result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSinkAndStdout(t, copilotMarker, sinkJSON, "", 0)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-full-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})
	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d", code, exitError)
	}
}

func TestRunFullResultWriteFailureIsNonFatal(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "detection_result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSinkAndStdout(t, copilotMarker, sinkJSON, "", 0)

	// A directory that does not exist makes the full-result write fail while
	// leaving the authoritative result perfectly writable.
	unwritable := filepath.Join(t.TempDir(), "missing-dir", "full.json")
	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-full-output", unwritable,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})
	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d (full-result write must be non-fatal)", code, exitSafe)
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("expected authoritative result to be written: %v", err)
	}
}

func TestRunEngineFailsWithoutSinkResult(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	// The engine emits a legacy-looking safe verdict on stdout but exits
	// non-zero without ever recording a sink result. A killed/failed engine
	// without a valid sink verdict must NOT be treated as success: detection
	// must fail closed with the infrastructure exit code and write no result.
	stdout := `THREAT_DETECTION_RESULT:{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotFailing(t, copilotMarker, stdout, 1)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (fail closed)", code, exitError)
	}
	if _, err := os.Stat(copilotMarker); err != nil {
		t.Fatalf("expected copilot to run: %v", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("expected no result file to be written, stat err = %v", err)
	}
}

func TestRunEarlyTerminationOnSink(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	// The fake engine writes the sink then sleeps 30s; early termination must
	// cancel the subprocess well before the sleep elapses.
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 30)

	start := time.Now()
	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})
	elapsed := time.Since(start)

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d", code, exitSafe)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("run did not terminate early: took %v", elapsed)
	}
	result := readResultFile(t, outputPath)
	if result["prompt_injection"].(bool) || result["secret_leak"].(bool) || result["malicious_patch"].(bool) {
		t.Fatalf("expected safe result, got %#v", result)
	}
}

func TestRunEmitsResultRecordedStatus(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["agentic detection"]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitThreat {
		t.Fatalf("run() exit code = %d, want %d", code, exitThreat)
	}
	want := "THREAT_DETECTION_STATUS: reason=result_recorded exit=1"
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr missing status line %q, got:\n%s", want, stderr)
	}
}

func TestRunEmitsEngineErrorStatusOnFailClosed(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	// Engine dies without recording a sink verdict: fail closed with exit 2 and
	// an engine_error status line, even though no result JSON is written.
	stdout := `THREAT_DETECTION_RESULT:{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotFailing(t, copilotMarker, stdout, 1)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (fail closed)", code, exitError)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("expected no result file to be written, stat err = %v", err)
	}
	want := "THREAT_DETECTION_STATUS: reason=engine_error exit=2"
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr missing status line %q, got:\n%s", want, stderr)
	}
}

func TestRunFailsClosedOnEmptyArtifactsDirectory(t *testing.T) {
	artifactsDir := t.TempDir() // deliberately empty: no prompt, no agent output, no patch.
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (fail closed on all-primary-inputs-missing)", code, exitError)
	}
	if _, err := os.Stat(copilotMarker); !os.IsNotExist(err) {
		t.Fatalf("expected the engine to never run, but copilot marker exists (stat err = %v)", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("expected no result file to be written, stat err = %v", err)
	}
	want := "THREAT_DETECTION_STATUS: reason=config_error exit=2"
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr missing status line %q, got:\n%s", want, stderr)
	}
	if !strings.Contains(stderr, "ERR_VALIDATION") {
		t.Fatalf("stderr missing ERR_VALIDATION warning annotations, got:\n%s", stderr)
	}
}

// TestRunReportsArtifactInventoryOnStderr verifies the recursive artifact
// inventory (TD-17b) is surfaced in the job log, which is the only place it is
// reported now that the separate JSONL run-log artifact is gone.
func TestRunReportsArtifactInventoryOnStderr(t *testing.T) {
	artifactsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(artifactsDir, "aw-prompts"), 0o755); err != nil {
		t.Fatalf("MkdirAll error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "aw-prompts", "prompt.txt"), []byte("analyze this"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "agent_output.json"), []byte(`{"items":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d; stderr:\n%s", code, exitSafe, stderr)
	}
	for _, want := range []string{
		"[threat-detect] run start:",
		"[threat-detect] artifacts loaded:",
		"[threat-detect] artifact inventory (2 entries):",
		"aw-prompts/prompt.txt",
		"agent_output.json",
		"[threat-detect] prompt built:",
		"[threat-detect] detection attempt 1 of 1",
		"THREAT_DETECTION_STATUS: reason=result_recorded exit=0",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q, got:\n%s", want, stderr)
		}
	}
}

// TestRunEmitsEngineTimeoutStatusAndDoesNotRetry verifies that a runaway
// engine — one that neither records a verdict nor exits — is killed on the
// per-attempt --engine-timeout, that the terminal status reason is the
// distinct engine_timeout (not the generic engine_error), and that the
// timeout is TERMINAL: even with --retries=3 the runaway is only attempted
// once, because retrying a runaway would just burn credits on another
// runaway (a same-prompt, same-model attempt is overwhelmingly likely to
// exhibit the same runaway behavior).
func TestRunEmitsEngineTimeoutStatusAndDoesNotRetry(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	// The fake sleeps far longer than the configured per-attempt budget so the
	// wall-clock kill path is taken deterministically.
	fakeBinDir := writeFakeCopilotHanging(t, copilotMarker, 30)

	start := time.Now()
	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-engine-timeout", "500ms",
		"-retries", "3", // explicitly non-zero: the timeout terminal rule must override it
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})
	elapsed := time.Since(start)

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d; stderr:\n%s", code, exitError, stderr)
	}
	// One attempt × 500ms plus overhead: comfortably under a few seconds. A
	// larger wall clock would indicate the timeout retried.
	if elapsed > 10*time.Second {
		t.Fatalf("run did not treat timeout as terminal: took %v (would be >= %s if retried)",
			elapsed, 4*500*time.Millisecond)
	}
	if _, err := os.Stat(copilotMarker); err != nil {
		t.Fatalf("expected copilot to run: %v", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("expected no result file to be written, stat err = %v", err)
	}
	want := "THREAT_DETECTION_STATUS: reason=engine_timeout exit=2"
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr missing status line %q, got:\n%s", want, stderr)
	}
	if !strings.Contains(stderr, "outcome=timeout duration=500ms") {
		t.Fatalf("stderr missing per-attempt timeout diagnostic, got:\n%s", stderr)
	}
	// The follow-on attempts must not run: the runaway retry would be pure
	// credit burn, so the loop must stop after attempt 1.
	if strings.Contains(stderr, "detection attempt 2 of ") {
		t.Fatalf("stderr shows a retry after a timeout; timeouts must be terminal:\n%s", stderr)
	}
}

// TestRunHonorsVerdictWrittenBeforeDeadline covers the race where the sink is
// populated by the engine but the wall-clock timeout also fires. A recorded
// verdict must win over the timeout, otherwise a healthy run near its budget
// would be reclassified as a runaway kill.
func TestRunHonorsVerdictWrittenBeforeDeadline(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	// The fake writes the sink immediately and then sleeps well past the
	// per-attempt budget. Early-cancel on sink-write should still let the run
	// report result_recorded.
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 30)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-engine-timeout", "500ms",
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d; stderr:\n%s", code, exitSafe, stderr)
	}
	if !strings.Contains(stderr, "THREAT_DETECTION_STATUS: reason=result_recorded exit=0") {
		t.Fatalf("stderr missing result_recorded status line, got:\n%s", stderr)
	}
}

// TestRunExportsMaxTurnsToEngineEnv verifies that --max-turns is exported to the
// engine subprocess as GH_AW_MAX_TURNS, which is the universal gh-aw contract
// the Claude, Codex, and Copilot harnesses read to enforce turn limits.
func TestRunExportsMaxTurnsToEngineEnv(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	envDumpPath := filepath.Join(t.TempDir(), "env-dump")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotDumpingEnv(t, copilotMarker, envDumpPath, sinkJSON, []string{"GH_AW_MAX_TURNS"})

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-max-turns", "17",
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d", code, exitSafe)
	}
	data, err := os.ReadFile(envDumpPath)
	if err != nil {
		t.Fatalf("reading env dump: %v", err)
	}
	if got, want := strings.TrimSpace(string(data)), "GH_AW_MAX_TURNS=17"; got != want {
		t.Fatalf("engine env dump = %q, want %q", got, want)
	}
}

// TestRunOmitsMaxTurnsEnvWhenDisabled verifies that --max-turns=0 does NOT
// export GH_AW_MAX_TURNS. Setting the env var to "0" would collide with a
// downstream harness's own default resolution and mislead it into treating
// zero as a hard cap.
func TestRunOmitsMaxTurnsEnvWhenDisabled(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	envDumpPath := filepath.Join(t.TempDir(), "env-dump")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotDumpingEnv(t, copilotMarker, envDumpPath, sinkJSON, []string{"GH_AW_MAX_TURNS"})

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-max-turns", "0",
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d", code, exitSafe)
	}
	data, err := os.ReadFile(envDumpPath)
	if err != nil {
		t.Fatalf("reading env dump: %v", err)
	}
	// GH_AW_MAX_TURNS should be unset (empty value in the dump line).
	if got := strings.TrimSpace(string(data)); got != "GH_AW_MAX_TURNS=" {
		t.Fatalf("engine env dump = %q, want %q (var must be unset when max-turns disabled)", got, "GH_AW_MAX_TURNS=")
	}
}

// TestRunResolvesMaxTurnsFromGhAwEnv verifies that when neither --max-turns nor
// THREAT_DETECTION_MAX_TURNS is set, the detector falls back to gh-aw's
// universal GH_AW_MAX_TURNS. This matches how the smoke workflows plumb the
// turn budget through and keeps the standalone detector consistent with the
// harness-driven path.
func TestRunResolvesMaxTurnsFromGhAwEnv(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":            fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_MAX_TURNS": "42",
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d; stderr:\n%s", code, exitSafe, stderr)
	}
	if !strings.Contains(stderr, "max_turns=42") {
		t.Fatalf("stderr does not show max_turns=42 resolved from GH_AW_MAX_TURNS, got:\n%s", stderr)
	}
}

// TestRunScrubsInheritedMaxTurnsWhenDisabled verifies that --max-turns=0
// prevents an ambient GH_AW_MAX_TURNS in the detector's own environment from
// leaking into the engine subprocess. Without the scrub, a caller who
// explicitly disables the cap could still have it silently reimposed by an
// inherited env var, defeating the disablement.
func TestRunScrubsInheritedMaxTurnsWhenDisabled(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	envDumpPath := filepath.Join(t.TempDir(), "env-dump")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotDumpingEnv(t, copilotMarker, envDumpPath, sinkJSON, []string{"GH_AW_MAX_TURNS"})

	// Explicitly set --max-turns=0 to override the ambient GH_AW_MAX_TURNS=99
	// resolved by envMaxTurns. The engine subprocess must see the variable
	// unset entirely, not "99" (inherited) and not "0" (silently disabling any
	// downstream default).
	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-max-turns", "0",
		artifactsDir,
	}, map[string]string{
		"PATH":            fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_MAX_TURNS": "99",
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d", code, exitSafe)
	}
	data, err := os.ReadFile(envDumpPath)
	if err != nil {
		t.Fatalf("reading env dump: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "GH_AW_MAX_TURNS=" {
		t.Fatalf("engine env dump = %q, want %q (inherited GH_AW_MAX_TURNS must be scrubbed when cap disabled)",
			got, "GH_AW_MAX_TURNS=")
	}
}

// TestRunRejectsNegativeCapFlags verifies that negative values on the kill-switch
// flags are refused with config_error rather than silently bypassing the cap.
// A --engine-timeout of -1s would skip context.WithTimeout entirely; a
// --max-turns of -1 would silently pass through maxTurnsEnv (which treats
// non-positive values as "no cap"). Both bypasses would defeat the whole
// point of the flags.
func TestRunRejectsNegativeCapFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag string
		val  string
	}{
		{"negative retries", "-retries", "-1"},
		{"negative max-turns", "-max-turns", "-1"},
		{"negative engine-timeout", "-engine-timeout", "-1s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifactsDir := t.TempDir()
			writeMinimalArtifacts(t, artifactsDir)
			outputPath := filepath.Join(t.TempDir(), "result.json")

			code, stderr := runWithTestArgsCapture(t, []string{
				"threat-detect",
				"-output", outputPath,
				tc.flag, tc.val,
				artifactsDir,
			}, nil)

			if code != exitError {
				t.Fatalf("run() exit code = %d, want %d", code, exitError)
			}
			if !strings.Contains(stderr, "THREAT_DETECTION_STATUS: reason=config_error exit=2") {
				t.Fatalf("stderr missing config_error status line, got:\n%s", stderr)
			}
		})
	}
}

func runWithTestArgs(t *testing.T, args []string, env map[string]string) int {
	t.Helper()
	code, _ := runWithTestArgsCapture(t, args, env)
	return code
}

// runWithTestArgsCapture runs the CLI like runWithTestArgs but also captures
// everything written to os.Stderr so tests can assert the status line.
func runWithTestArgsCapture(t *testing.T, args []string, env map[string]string) (int, string) {
	t.Helper()
	originalArgs := os.Args
	originalFlags := flag.CommandLine
	originalStderr := os.Stderr
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalFlags
		os.Stderr = originalStderr
	})
	os.Args = args
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)

	for key, value := range env {
		t.Setenv(key, value)
	}
	if _, ok := env["PATH"]; !ok {
		// Keep the package hermetic: a test that reaches the engine without
		// explicitly stubbing one must not fall through to a real engine CLI on
		// the host PATH, which can block on network/auth until the test timeout.
		t.Setenv("PATH", t.TempDir())
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stderr pipe: %v", err)
	}
	os.Stderr = w
	// Route flag parse/usage output to the same pipe so it is captured too.
	flag.CommandLine.SetOutput(w)

	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	code := run()
	w.Close()
	os.Stderr = originalStderr
	stderr := <-done
	r.Close()

	return code, stderr
}

// TestRunRejectsIneligibleVerdictFromSink verifies the detector-side eligibility
// revalidation (TD-10g): a sink result claiming malicious_patch when no patch
// was staged is discarded even though it is schema-valid, because the check that
// binds is the one the detector performs against its own artifact-derived
// eligibility — not the environment-based check in the report subprocess, whose
// inputs the model controls.
func TestRunRejectsIneligibleVerdictFromSink(t *testing.T) {
	artifactsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(artifactsDir, "aw-prompts"), 0o755); err != nil {
		t.Fatalf("MkdirAll error = %v", err)
	}
	// A prompt template with no placeholders: analysis is not degraded and there
	// is no untrusted input, so prompt_injection is ineligible too.
	if err := os.WriteFile(filepath.Join(artifactsDir, "aw-prompts", "prompt.txt"), []byte("static prompt"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "aw-prompts", "prompt-template.txt"), []byte("static prompt"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "agent_output.json"), []byte(`{"items":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	// Deliberately no aw-*.patch file: malicious_patch is ineligible.

	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	// The fake engine writes the sink directly, bypassing report-result entirely
	// — the strongest form of the bypass the env transport cannot prevent.
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":true,"reasons":["fabricated patch finding"]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-retries", "1",
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (ineligible verdict must not be recorded); stderr:\n%s", code, exitError, stderr)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("expected no result file for an ineligible verdict, stat err = %v", err)
	}
	for _, want := range []string{
		"[threat-detect] eligibility: prompt_injection=false secret_leak=true malicious_patch=false",
		"outcome=ineligible; discarding",
		"THREAT_DETECTION_STATUS: reason=invalid_report_exhausted exit=2",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q, got:\n%s", want, stderr)
		}
	}
}

// TestRunAcceptsEligibleThreatVerdict is the companion to the test above: the
// same threat verdict is recorded normally once the artifact bundle can support
// it, so eligibility rejects impossible claims without suppressing real ones.
func TestRunAcceptsEligibleThreatVerdict(t *testing.T) {
	artifactsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(artifactsDir, "aw-prompts"), 0o755); err != nil {
		t.Fatalf("MkdirAll error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "aw-prompts", "prompt.txt"), []byte("static prompt"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "aw-prompts", "prompt-template.txt"), []byte("static prompt"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "agent_output.json"), []byte(`{"items":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "aw-changes.patch"), []byte("diff --git a/x b/x\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":true,"reasons":["real patch finding"]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitThreat {
		t.Fatalf("run() exit code = %d, want %d (eligible threat must be recorded); stderr:\n%s", code, exitThreat, stderr)
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("expected a result file for an eligible verdict, stat err = %v", err)
	}
	if !strings.Contains(stderr, "THREAT_DETECTION_STATUS: reason=result_recorded exit=1") {
		t.Fatalf("stderr missing recorded status line, got:\n%s", stderr)
	}
}

func writeFakeCopilotWithSink(t *testing.T, markerPath, sinkJSON string, sleepSeconds int) string {
	t.Helper()
	return writeFakeCopilotWithSinkAndStdout(t, markerPath, sinkJSON, "no result line here", sleepSeconds)
}

// writeFakeCopilotWithSinkAndStdout writes a fake copilot that records a valid
// verdict to $THREAT_DETECTION_RESULT_FILE (simulating the model calling the
// report tool), emits stdoutLine on stdout, then optionally sleeps for
// sleepSeconds to exercise early termination.
func writeFakeCopilotWithSinkAndStdout(t *testing.T, markerPath, sinkJSON, stdoutLine string, sleepSeconds int) string {
	t.Helper()

	binDir := t.TempDir()
	scriptPath := filepath.Join(binDir, "copilot")
	lines := []string{
		"#!/bin/sh",
		"cat >/dev/null",
		"printf called > " + shellQuote(markerPath),
		"printf '%s' " + shellQuote(sinkJSON) + " > \"$THREAT_DETECTION_RESULT_FILE\"",
		"printf '%s\\n' " + shellQuote(stdoutLine),
	}
	if sleepSeconds > 0 {
		lines = append(lines, "sleep "+strconv.Itoa(sleepSeconds))
	}
	lines = append(lines, "")
	if err := os.WriteFile(scriptPath, []byte(strings.Join(lines, "\n")), 0o700); err != nil {
		t.Fatalf("writing fake copilot: %v", err)
	}
	return binDir
}

func writeFakeCopilotCapturingPrompt(t *testing.T, markerPath, promptPath, sinkJSON string) string {
	t.Helper()

	binDir := t.TempDir()
	scriptPath := filepath.Join(binDir, "copilot")
	script := strings.Join([]string{
		"#!/bin/sh",
		"cat > " + shellQuote(promptPath),
		"printf called > " + shellQuote(markerPath),
		"printf '%s' " + shellQuote(sinkJSON) + " > \"$THREAT_DETECTION_RESULT_FILE\"",
		"",
	}, "\n")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("writing fake copilot: %v", err)
	}
	return binDir
}

// writeFakeCopilotFailing writes a fake copilot that emits stdout, never writes
// the sink, and exits with exitCode — simulating an engine that dies without
// reporting a verdict.
func writeFakeCopilotFailing(t *testing.T, markerPath, stdout string, exitCode int) string {
	t.Helper()

	binDir := t.TempDir()
	scriptPath := filepath.Join(binDir, "copilot")
	script := strings.Join([]string{
		"#!/bin/sh",
		"cat >/dev/null",
		"printf called > " + shellQuote(markerPath),
		"printf '%s\\n' " + shellQuote(stdout),
		"exit " + strconv.Itoa(exitCode),
		"",
	}, "\n")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("writing fake copilot: %v", err)
	}
	return binDir
}

// writeFakeCopilotHanging writes a fake copilot that never writes the sink and
// blocks for sleepSeconds — enough to reliably exceed a short --engine-timeout
// so the wall-clock kill path is exercised.
func writeFakeCopilotHanging(t *testing.T, markerPath string, sleepSeconds int) string {
	t.Helper()

	binDir := t.TempDir()
	scriptPath := filepath.Join(binDir, "copilot")
	script := strings.Join([]string{
		"#!/bin/sh",
		"cat >/dev/null",
		"printf called > " + shellQuote(markerPath),
		"sleep " + strconv.Itoa(sleepSeconds),
		"",
	}, "\n")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("writing fake copilot: %v", err)
	}
	return binDir
}

// writeFakeCopilotDumpingEnv writes a fake copilot that records selected env
// variables into envDumpPath (one per line as KEY=VALUE) and then records a
// safe verdict via the sink. It is used to assert env-var propagation
// (e.g. GH_AW_MAX_TURNS) into the engine subprocess.
func writeFakeCopilotDumpingEnv(t *testing.T, markerPath, envDumpPath, sinkJSON string, envKeys []string) string {
	t.Helper()

	binDir := t.TempDir()
	scriptPath := filepath.Join(binDir, "copilot")
	lines := []string{
		"#!/bin/sh",
		"cat >/dev/null",
		"printf called > " + shellQuote(markerPath),
		": > " + shellQuote(envDumpPath),
	}
	for _, key := range envKeys {
		lines = append(lines,
			"printf '%s=%s\\n' "+shellQuote(key)+" \"${"+key+"}\" >> "+shellQuote(envDumpPath))
	}
	lines = append(lines,
		"printf '%s' "+shellQuote(sinkJSON)+" > \"$THREAT_DETECTION_RESULT_FILE\"",
		"",
	)
	if err := os.WriteFile(scriptPath, []byte(strings.Join(lines, "\n")), 0o700); err != nil {
		t.Fatalf("writing fake copilot: %v", err)
	}
	return binDir
}

// writeMinimalArtifacts populates dir with a non-empty prompt and agent
// output file so run() proceeds past artifacts loading. Tests that only
// exercise engine/result-sink behavior use this to avoid tripping the
// AllPrimaryInputsMissing hard-fail (see pkg/artifacts.Load).
func writeMinimalArtifacts(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "aw-prompts"), 0o755); err != nil {
		t.Fatalf("creating aw-prompts dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aw-prompts", "prompt.txt"), []byte("test workflow prompt"), 0o644); err != nil {
		t.Fatalf("writing prompt.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent_output.json"), []byte(`{"items":[]}`), 0o644); err != nil {
		t.Fatalf("writing agent_output.json: %v", err)
	}
}

func readResultFile(t *testing.T, path string) map[string]any {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading result file: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parsing result JSON: %v", err)
	}
	return result
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func TestRunWarnsOnDegradedRequiredInput(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	if err := os.Remove(filepath.Join(artifactsDir, "agent_output.json")); err != nil {
		t.Fatalf("removing agent output: %v", err)
	}
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d (warn mode must not fail)", code, exitSafe)
	}
	if _, err := os.Stat(copilotMarker); err != nil {
		t.Fatalf("expected detection to run in warn mode: %v", err)
	}
	if !strings.Contains(stderr, "::warning::ERR_VALIDATION: Missing agent output file at ") {
		t.Errorf("expected missing agent output warning, got:\n%s", stderr)
	}
}

func TestRunFailsOnDegradedRequiredInputInStrictMode(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	if err := os.Remove(filepath.Join(artifactsDir, "agent_output.json")); err != nil {
		t.Fatalf("removing agent output: %v", err)
	}
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "false",
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (strict mode must fail)", code, exitError)
	}
	if _, err := os.Stat(copilotMarker); err == nil {
		t.Fatal("expected detection not to run in strict mode")
	}
	if !strings.Contains(stderr, "::error::ERR_VALIDATION: Missing agent output file at ") {
		t.Errorf("expected missing agent output error annotation, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, statusPrefix+" reason="+reasonConfigError) {
		t.Errorf("expected config_error status line, got:\n%s", stderr)
	}
}

func TestRunStrictModeSucceedsWithCompleteArtifacts(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "false",
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d\n%s", code, exitSafe, stderr)
	}
}

func TestRunFailsOnExpectedButMissingPatchInStrictMode(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "false",
		"HAS_PATCH":                         "true",
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "::error::ERR_VALIDATION: HAS_PATCH=true was set but no readable") {
		t.Errorf("expected missing patch error annotation, got:\n%s", stderr)
	}
}

// Advisory (non-required-input) findings must stay warnings even in strict
// mode, so a degraded prompt-analysis artifact never blocks detection.
func TestRunStrictModeKeepsAdvisoryFindingsNonFatal(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "false",
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d (prompt-analysis degradation is advisory)\n%s", code, exitSafe, stderr)
	}
	if !strings.Contains(stderr, "::warning::"+promptAnalysisValidationCode) {
		t.Errorf("expected advisory prompt-analysis warning, got:\n%s", stderr)
	}
}

func TestDetectionContinueOnError(t *testing.T) {
	tests := []struct {
		value string
		set   bool
		want  bool
	}{
		{set: false, want: true},
		{value: "", set: true, want: true},
		{value: "true", set: true, want: true},
		{value: "false", set: true, want: false},
		{value: "False", set: true, want: false},
		{value: "FALSE", set: true, want: false},
		{value: "no", set: true, want: true},
	}
	for _, tt := range tests {
		name := "unset"
		if tt.set {
			name = "value=" + tt.value
		}
		t.Run(name, func(t *testing.T) {
			if tt.set {
				t.Setenv("GH_AW_DETECTION_CONTINUE_ON_ERROR", tt.value)
			} else {
				t.Setenv("GH_AW_DETECTION_CONTINUE_ON_ERROR", "true")
				if err := os.Unsetenv("GH_AW_DETECTION_CONTINUE_ON_ERROR"); err != nil {
					t.Fatalf("unsetting env: %v", err)
				}
			}
			if got := detectionContinueOnError(); got != tt.want {
				t.Errorf("detectionContinueOnError() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestDetectionContinueOnWarning(t *testing.T) {
	tests := []struct {
		value string
		set   bool
		want  bool
	}{
		{set: false, want: true},
		{value: "", set: true, want: true},
		{value: "true", set: true, want: true},
		{value: "false", set: true, want: false},
		{value: "False", set: true, want: false},
		{value: "FALSE", set: true, want: false},
		{value: "no", set: true, want: true},
	}
	for _, tt := range tests {
		name := "unset"
		if tt.set {
			name = "value=" + tt.value
		}
		t.Run(name, func(t *testing.T) {
			if tt.set {
				t.Setenv("GH_AW_DETECTION_CONTINUE_ON_WARNING", tt.value)
			} else {
				t.Setenv("GH_AW_DETECTION_CONTINUE_ON_WARNING", "true")
				if err := os.Unsetenv("GH_AW_DETECTION_CONTINUE_ON_WARNING"); err != nil {
					t.Fatalf("unsetting env: %v", err)
				}
			}
			if got := detectionContinueOnWarning(); got != tt.want {
				t.Errorf("detectionContinueOnWarning() = %t, want %t", got, tt.want)
			}
		})
	}
}

// stagePromptAnalysisArtifacts adds the TD-18b prompt-analysis artifacts so a
// bundle is fully readable and the TD-18f gate stays inert.
func stagePromptAnalysisArtifacts(t *testing.T, artifactsDir string) {
	t.Helper()
	promptsDir := filepath.Join(artifactsDir, "aw-prompts")
	files := map[string]string{
		"prompt-template.txt":     "Trusted instructions.\nRequest: {{user_input}}\nEnd.",
		"prompt-import-tree.json": `{"version":1,"children":[]}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(promptsDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
}

// stageUninspectableCommentMemory shapes comment-memory as a symlink, which
// loadCommentMemory refuses to follow and reports as an uninspectable optional
// channel. This is the adversarially reachable shape TD-18f exists to gate on.
func stageUninspectableCommentMemory(t *testing.T, artifactsDir string) {
	t.Helper()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(artifactsDir, "comment-memory")); err != nil {
		t.Fatalf("symlinking comment-memory: %v", err)
	}
}

// An uninspectable optional channel stays advisory by default, so hosts that
// set neither variable see no behavior change from TD-18f.
func TestRunKeepsUninspectableOptionalChannelAdvisoryByDefault(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	stageUninspectableCommentMemory(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d (default must stay advisory)\n%s", code, exitSafe, stderr)
	}
	if _, err := os.Stat(copilotMarker); err != nil {
		t.Fatalf("expected detection to run by default: %v", err)
	}
	if !strings.Contains(stderr, "[threat-detect] artifact degraded: field=comment_memory required_input=false") {
		t.Errorf("expected advisory comment-memory finding, got:\n%s", stderr)
	}
}

// Strict continue-on-error alone must not gate an optional channel: that flag
// covers the host's staging contract for required inputs only.
func TestRunKeepsUninspectableOptionalChannelAdvisoryInStrictErrorMode(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	stageUninspectableCommentMemory(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "false",
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d (CONTINUE_ON_ERROR must not gate optional channels)\n%s", code, exitSafe, stderr)
	}
}

func TestRunFailsOnUninspectableOptionalChannelWhenWarningsGated(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	stageUninspectableCommentMemory(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                                fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_WARNING": "false",
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (gated warnings must fail closed)\n%s", code, exitError, stderr)
	}
	if _, err := os.Stat(copilotMarker); err == nil {
		t.Fatal("expected detection not to run when warnings are gated")
	}
	if !strings.Contains(stderr, "::error::ERR_VALIDATION: Expected ") {
		t.Errorf("expected comment-memory error annotation, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "GH_AW_DETECTION_CONTINUE_ON_WARNING is \"false\"") {
		t.Errorf("expected the refusal to name the gate, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, statusPrefix+" reason="+reasonConfigError+" exit="+strconv.Itoa(exitError)) {
		t.Errorf("expected config_error status line, got:\n%s", stderr)
	}
	// A refusal to certify must never be laundered into a threat verdict.
	if _, err := os.Stat(outputPath); err == nil {
		t.Error("expected no result file to be written for a configuration error")
	}
}

// Mixed case must select the gate, matching CONTINUE_ON_ERROR parsing.
func TestRunFailsOnUninspectableOptionalChannelWithMixedCaseGate(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	stageUninspectableCommentMemory(t, artifactsDir)
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		artifactsDir,
	}, map[string]string{
		"PATH":                                fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_WARNING": "False",
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (\"False\" must select the gate)\n%s", code, exitError, stderr)
	}
}

// With a fully readable bundle the gate is inert, so opting in does not turn a
// clean run into a configuration error.
func TestRunSucceedsWithWarningsGatedAndCompleteArtifacts(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	stagePromptAnalysisArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                                fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_WARNING": "false",
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d\n%s", code, exitSafe, stderr)
	}
	if strings.Contains(stderr, "::error::") {
		t.Errorf("expected no error annotation for a complete bundle, got:\n%s", stderr)
	}
}

// Degraded prompt analysis (TD-18b) is recorded after artifacts loading, so it
// is not in arts.Warnings. It must still be gated, or a host that opted out of
// partial-bundle verdicts would keep certifying a bundle whose
// trusted-vs-untrusted split could not be computed.
func TestRunFailsOnDegradedPromptAnalysisWhenWarningsGated(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                                fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_WARNING": "false",
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (degraded prompt analysis must be gated)\n%s", code, exitError, stderr)
	}
	if _, err := os.Stat(copilotMarker); err == nil {
		t.Fatal("expected detection not to run when prompt analysis is degraded and gated")
	}
	for _, want := range []string{
		"::error::" + promptAnalysisValidationCode + ": Missing or empty prompt analysis artifact: aw-prompts/prompt-template.txt",
		"::error::" + promptAnalysisValidationCode + ": Missing or empty prompt analysis artifact: aw-prompts/prompt-import-tree.json",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("expected prompt-analysis error annotation %q, got:\n%s", want, stderr)
		}
	}
	if !strings.Contains(stderr, statusPrefix+" reason="+reasonConfigError) {
		t.Errorf("expected config_error status line, got:\n%s", stderr)
	}
	if _, err := os.Stat(outputPath); err == nil {
		t.Error("expected no result file to be written for a configuration error")
	}
}

// Degraded prompt analysis remains advisory in strict continue-on-error mode:
// see TestRun_DegradedPromptAnalysisDoesNotBlockStrictMode in warnings_test.go.

func TestRunFailsOnDegradedRequiredInputInMixedCaseStrictMode(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	if err := os.Remove(filepath.Join(artifactsDir, "agent_output.json")); err != nil {
		t.Fatalf("removing agent output: %v", err)
	}
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "False",
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (\"False\" must select strict mode)", code, exitError)
	}
	if !strings.Contains(stderr, "::error::ERR_VALIDATION: Missing agent output file at ") {
		t.Errorf("expected missing agent output error annotation, got:\n%s", stderr)
	}
}

// TestRunWarnsWhenPromptAnalysisArtifactsAreMissing verifies the TD-18b
// degraded-analysis finding reaches the job log. Now that stderr is the sole
// diagnostic sink, this is the only place the warning is observable.
func TestRunWarnsWhenPromptAnalysisArtifactsAreMissing(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})
	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d; stderr:\n%s", code, exitSafe, stderr)
	}
	for _, want := range []string{
		"::warning::ERR_VALIDATION:",
		"aw-prompts/prompt-template.txt",
		"aw-prompts/prompt-import-tree.json",
		"Trusted-vs-untrusted prompt analysis is degraded",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

// TestReportArtifactsBoundsAndEscapesInventory verifies the TD-20a guarantees
// for the stderr inventory: the listing is bounded with a labelled omission
// count, and a filename carrying control characters cannot open a line of its
// own (which the Actions runner would read as a workflow command).
func TestReportArtifactsBoundsAndEscapesInventory(t *testing.T) {
	t.Run("bounds the listing and labels the omission", func(t *testing.T) {
		arts := &artifacts.Artifacts{}
		for i := 0; i < maxInventoryEntries+25; i++ {
			arts.Inventory = append(arts.Inventory, artifacts.InventoryEntry{
				Path: fmt.Sprintf("file-%03d.txt", i),
				Kind: "file",
			})
		}

		stderr := captureStderr(t, func() { reportArtifacts("/artifacts", arts) })

		if !strings.Contains(stderr, fmt.Sprintf("artifact inventory (%d entries):", maxInventoryEntries+25)) {
			t.Errorf("stderr should report the true total, got:\n%s", stderr)
		}
		if strings.Contains(stderr, "file-200.txt") {
			t.Errorf("stderr should not list entries beyond the bound:\n%s", stderr)
		}
		if !strings.Contains(stderr, "... 25 more entry(ies) omitted") {
			t.Errorf("stderr should label the omission, got:\n%s", stderr)
		}
		// One header, one bound line, maxInventoryEntries listed, one omission line.
		if got, want := strings.Count(stderr, "\n"), maxInventoryEntries+3; got != want {
			t.Errorf("stderr line count = %d, want %d:\n%s", got, want, stderr)
		}
	})

	t.Run("escapes control characters in paths", func(t *testing.T) {
		arts := &artifacts.Artifacts{Inventory: []artifacts.InventoryEntry{
			{Path: "evil.txt\n::error::forged", Kind: "file\nbogus", Size: 1},
		}}

		stderr := captureStderr(t, func() { reportArtifacts("/artifacts\n::error::dir", arts) })

		if strings.Contains(stderr, "\n::error::") {
			t.Errorf("a path must not be able to open a workflow-command line:\n%q", stderr)
		}
		if !strings.Contains(stderr, `\n::error::forged`) {
			t.Errorf("the newline should be escaped in place, got:\n%q", stderr)
		}
		// Header, bound line, and the single entry.
		if got, want := strings.Count(stderr, "\n"), 3; got != want {
			t.Errorf("stderr line count = %d, want %d:\n%q", got, want, stderr)
		}
	})
}

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating stderr pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = original })

	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()

	fn()
	w.Close()
	os.Stderr = original
	out := <-done
	r.Close()
	return out
}

// TestRunStartLineEscapesEngineID verifies the run-configuration diagnostic
// cannot be split by a hostile --engine value. The ID is echoed before
// engine.New validates it, and Canonical only lowercases, so an arbitrary
// string reaches this line.
func TestRunStartLineEscapesEngineID(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)

	_, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-engine", "copilot\n::error::forged",
		artifactsDir,
	}, nil)

	if strings.Contains(stderr, "\n::error::forged") {
		t.Errorf("engine ID must not open a workflow-command line:\n%q", stderr)
	}
	if !strings.Contains(stderr, `[threat-detect] run start: version=`) {
		t.Fatalf("stderr missing the run start line:\n%s", stderr)
	}
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "[threat-detect] run start:") && !strings.Contains(line, `\n::error::forged`) {
			t.Errorf("engine ID should be escaped in place on the run start line: %q", line)
		}
	}
}

// TestRunAcceptsAndIgnoresStepSummaryFlag verifies the removed --step-summary
// option is still parsed and dropped (TD-20c) so hosts that still pass it do not
// abort detection with a flag error.
func TestRunAcceptsAndIgnoresStepSummaryFlag(t *testing.T) {
	artifactsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(artifactsDir, "aw-prompts"), 0o755); err != nil {
		t.Fatalf("MkdirAll error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "aw-prompts", "prompt.txt"), []byte("analyze this"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "agent_output.json"), []byte(`{"items":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "result.json")
	summaryPath := filepath.Join(t.TempDir(), "step-summary.md")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-step-summary", summaryPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d; stderr:\n%s", code, exitSafe, stderr)
	}
	if !strings.Contains(stderr, "ignoring deprecated --step-summary") {
		t.Errorf("stderr missing the ignored --step-summary notice, got:\n%s", stderr)
	}
	if _, err := os.Stat(summaryPath); !os.IsNotExist(err) {
		t.Errorf("expected no step summary to be written to %s, stat err = %v", summaryPath, err)
	}
}

// TestDetectionDiagnosticsNeutralizeLegacyWorkflowCommand covers the detection
// run's own stderr diagnostics. The artifacts directory is host-supplied and is
// echoed verbatim in the fail-closed error, so — like every other detector
// diagnostic — it must not be able to emit the runner's legacy workflow command
// from mid-line.
func TestDetectionDiagnosticsNeutralizeLegacyWorkflowCommand(t *testing.T) {
	artifactsDir := filepath.Join(t.TempDir(), "##[stop-commands]artifacts")
	if err := os.MkdirAll(artifactsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll error = %v", err)
	}

	code, stderr := runWithTestArgsCapture(t, []string{"threat-detect", artifactsDir}, nil)

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d; stderr:\n%s", code, exitError, stderr)
	}
	if strings.Contains(stderr, "##[") {
		t.Fatalf("live legacy workflow-command marker reached the log:\n%s", stderr)
	}
	// The path must still be present and readable, just inert.
	if !strings.Contains(stderr, `##\[stop-commands]artifacts`) {
		t.Fatalf("escaped artifacts dir not rendered:\n%s", stderr)
	}
}

// TestRunReportsUnreadableRenderedPromptOnce checks that an unreadable rendered
// prompt is reported, and reported exactly once. artifacts.Load probes required
// inputs for readability, so it owns this case; the analysis pass must recognise
// the finding as already recorded rather than emitting a second copy into the
// bounded, published warnings array.
func TestRunReportsUnreadableRenderedPromptOnce(t *testing.T) {
	artifactsDir := t.TempDir()
	promptsDir := filepath.Join(artifactsDir, "aw-prompts")
	if err := os.MkdirAll(promptsDir, 0o755); err != nil {
		t.Fatalf("creating prompts directory: %v", err)
	}
	files := map[string]string{
		"prompt-template.txt":     "Trusted instructions.\nRequest: {{user_input}}\nEnd.",
		"prompt-import-tree.json": `{"version":1,"children":[]}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(promptsDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	// A directory in place of the rendered prompt passes the loader's size
	// check but fails the read, for any user including root.
	if err := os.MkdirAll(filepath.Join(promptsDir, "prompt.txt"), 0o755); err != nil {
		t.Fatalf("creating unreadable prompt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "agent_output.json"), []byte(`{"items":[]}`), 0o600); err != nil {
		t.Fatalf("writing agent output: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "result.json")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, filepath.Join(t.TempDir(), "copilot-called"), sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d\n%s", code, exitSafe, stderr)
	}
	if !strings.Contains(stderr, "could not be read") {
		t.Fatalf("stderr missing unreadable-prompt warning:\n%s", stderr)
	}
	if got := strings.Count(stderr, "[threat-detect] artifact degraded: field=prompt required_input=true"); got != 1 {
		t.Fatalf("prompt finding reported %d times, want 1:\n%s", got, stderr)
	}
	// The two optional aids were staged and read, so nothing should claim they
	// are missing.
	if strings.Contains(stderr, "Missing or empty prompt analysis artifact") {
		t.Fatalf("unexpected missing-artifacts warning:\n%s", stderr)
	}

	result := readResultFile(t, outputPath)
	for _, category := range []string{"prompt_injection", "secret_leak", "malicious_patch"} {
		if result[category].(bool) {
			t.Errorf("result %s = true, want false: %#v", category, result)
		}
	}
}

// TestRunWarnsWhenPromptAnalysisAidsMissing keeps the optional analysis aids
// advisory: a host that never stages them is warned, but the finding must not be
// classified as concerning a required input or strict mode would start refusing
// those runs.
func TestRunWarnsWhenPromptAnalysisAidsMissing(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)

	outputPath := filepath.Join(t.TempDir(), "result.json")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, filepath.Join(t.TempDir(), "copilot-called"), sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "false",
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d\n%s", code, exitSafe, stderr)
	}
	for _, want := range []string{
		"Missing or empty prompt analysis artifact: aw-prompts/prompt-template.txt",
		"Missing or empty prompt analysis artifact: aw-prompts/prompt-import-tree.json",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if !strings.Contains(stderr, "[threat-detect] artifact degraded: field=prompt_template required_input=false") {
		t.Fatalf("stderr missing advisory classification for the analysis aids:\n%s", stderr)
	}
}

// TestRunStrictModeRefusesAnalysisTimePromptFailure covers the strict-mode side
// of a required-input failure that only the prompt analysis can see. The bundle
// passes every check artifacts.Load makes — the prompt is present, non-empty and
// readable — and carries no content by the time the analysis reads it, so the
// load-time strict gate has already been cleared. The finding must be re-gated
// here and terminate as a configuration error before the engine is invoked.
func TestRunStrictModeRefusesAnalysisTimePromptFailure(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	blankAfterLoad(t, filepath.Join(artifactsDir, "aw-prompts", "prompt.txt"))

	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "false",
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d\n%s", code, exitError, stderr)
	}
	if !strings.Contains(stderr, "THREAT_DETECTION_STATUS: reason=config_error exit=2") {
		t.Fatalf("stderr missing config_error status line:\n%s", stderr)
	}
	if !strings.Contains(stderr, "::error::ERR_VALIDATION:") ||
		!strings.Contains(stderr, "was empty when the prompt analysis read it") {
		t.Fatalf("stderr missing strict-mode error annotation:\n%s", stderr)
	}
	if _, err := os.Stat(copilotMarker); err == nil {
		t.Fatal("engine was invoked despite a strict-mode required-input failure")
	}
	if _, err := os.Stat(outputPath); err == nil {
		t.Fatal("result file was written despite refusing to run detection")
	}
}

// TestRunWarnsWhenRenderedPromptBlankedAfterLoad covers the prompt that passes
// the loader's size check and is empty by the time the analysis reads it. Load
// saw content and warned about nothing, so this is the only place the condition
// can be reported.
func TestRunWarnsWhenRenderedPromptBlankedAfterLoad(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	promptPath := filepath.Join(artifactsDir, "aw-prompts", "prompt.txt")

	outputPath := filepath.Join(t.TempDir(), "result.json")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, filepath.Join(t.TempDir(), "copilot-called"), sinkJSON, 0)

	// Stand in for a mid-run truncation: the loader's stat already happened
	// against the staged content in the equivalent real-world race.
	blankAfterLoad(t, promptPath)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d\n%s", code, exitSafe, stderr)
	}
	if !strings.Contains(stderr, "was empty when the prompt analysis read it") {
		t.Fatalf("stderr missing blanked-prompt warning:\n%s", stderr)
	}
	if !strings.Contains(stderr, "[threat-detect] artifact degraded: field=prompt required_input=true") {
		t.Fatalf("stderr missing required-input classification for the prompt:\n%s", stderr)
	}
	// The loader's own missing/empty-prompt findings must not be duplicated by
	// this pass when they already covered the same condition.
	if strings.Count(stderr, "artifact degraded: field=prompt required_input=true") != 1 {
		t.Fatalf("prompt finding reported more than once:\n%s", stderr)
	}
}

// blankAfterLoad truncates path to whitespace only, leaving a non-empty file so
// artifacts.Load's size check still passes.
func blankAfterLoad(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("blanking %s: %v", path, err)
	}
}

// TestRunWarningGateCoversAnalysisTimePromptFailure pins the TD-18f gate to
// findings raised by the prompt analysis, not just those artifacts.Load records.
// A host that declined to certify a partially readable bundle must not have that
// refusal bypassed by a degradation Load could not have seen.
func TestRunWarningGateCoversAnalysisTimePromptFailure(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	blankAfterLoad(t, filepath.Join(artifactsDir, "aw-prompts", "prompt.txt"))

	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		// Warn mode stays on, so only the warning gate can refuse this run.
		"GH_AW_DETECTION_CONTINUE_ON_ERROR":   "true",
		"GH_AW_DETECTION_CONTINUE_ON_WARNING": "false",
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d\n%s", code, exitError, stderr)
	}
	if !strings.Contains(stderr, statusPrefix+" reason="+reasonConfigError) {
		t.Fatalf("stderr missing config_error status line:\n%s", stderr)
	}
	if !strings.Contains(stderr, "::error::"+promptAnalysisValidationCode+": Detection context prompt at") {
		t.Fatalf("stderr missing escalated analysis-time annotation:\n%s", stderr)
	}
	if _, err := os.Stat(copilotMarker); err == nil {
		t.Fatal("engine was invoked despite the warning gate refusing the bundle")
	}
	if _, err := os.Stat(outputPath); err == nil {
		t.Fatal("result file was written despite refusing to run detection")
	}
}
