package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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
	if strings.Contains(stderr, "prompt analysis artifacts") {
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
	reasons, _ := result["reasons"].([]any)
	if len(reasons) != 1 || reasons[0].(string) != "from sink" {
		t.Fatalf("expected sink reasons, got %#v", result["reasons"])
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

func TestRunFailsClosedOnEmptyArtifactsDirectoryWithLogFile(t *testing.T) {
	artifactsDir := t.TempDir() // deliberately empty.
	outputPath := filepath.Join(t.TempDir(), "result.json")
	logPath := filepath.Join(t.TempDir(), "run.jsonl")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-log-file", logPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d (fail closed)", code, exitError)
	}
	if _, err := os.Stat(copilotMarker); !os.IsNotExist(err) {
		t.Fatalf("expected the engine to never run, but copilot marker exists (stat err = %v)", err)
	}

	records := readJSONLRecords(t, logPath)

	degraded := 0
	for _, rec := range records {
		if rec["event"] == "artifact_degraded" {
			degraded++
		}
	}
	if degraded < 2 {
		t.Fatalf("expected at least 2 artifact_degraded records (prompt + agent_output), got %d: %#v", degraded, records)
	}

	if findRecord(records, "artifacts_all_primary_inputs_missing") == nil {
		t.Fatalf("missing artifacts_all_primary_inputs_missing record: %#v", records)
	}

	status := findRecord(records, "status")
	if status == nil {
		t.Fatalf("missing status record: %#v", records)
	}
	if status["reason"] != reasonConfigError {
		t.Errorf("status reason = %v, want %s", status["reason"], reasonConfigError)
	}
	if exit, ok := status["exit"].(float64); !ok || int(exit) != exitError {
		t.Errorf("status exit = %v, want %d", status["exit"], exitError)
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
