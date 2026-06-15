package main

import (
	"encoding/json"
	"flag"
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
		t.Fatalf("expected sink-derived result, got %#v", result)
	}
	reasons, _ := result["reasons"].([]any)
	if len(reasons) != 1 || reasons[0].(string) != "from sink" {
		t.Fatalf("expected sink reasons, got %#v", result["reasons"])
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

func runWithTestArgs(t *testing.T, args []string, env map[string]string) int {
	t.Helper()
	originalArgs := os.Args
	originalFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalFlags
	})
	os.Args = args
	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)

	for key, value := range env {
		t.Setenv(key, value)
	}

	return run()
}

func writeFakeCopilotWithSink(t *testing.T, markerPath, sinkJSON string, sleepSeconds int) string {
	t.Helper()

	binDir := t.TempDir()
	scriptPath := filepath.Join(binDir, "copilot")
	lines := []string{
		"#!/bin/sh",
		"cat >/dev/null",
		"printf called > " + shellQuote(markerPath),
		"printf '%s' " + shellQuote(sinkJSON) + " > \"$THREAT_DETECTION_RESULT_FILE\"",
		"printf 'no result line here\\n'",
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
