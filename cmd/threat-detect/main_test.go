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

func TestRunPrefersSinkResultOverTranscript(t *testing.T) {
	artifactsDir := t.TempDir()
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
