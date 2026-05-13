package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRunReflectUnavailableFallsBackToAgenticEngine(t *testing.T) {
	var reflectRequests atomic.Int32
	reflectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reflectRequests.Add(1)
		http.Error(w, "reflect not implemented", http.StatusNotImplemented)
	}))
	defer reflectServer.Close()

	artifactsDir := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	fakeBinDir := writeFakeCopilot(t, copilotMarker, `THREAT_DETECTION_RESULT:{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["agentic fallback"]}`)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-reflect-url", reflectServer.URL,
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitThreat {
		t.Fatalf("run() exit code = %d, want %d", code, exitThreat)
	}
	if reflectRequests.Load() == 0 {
		t.Fatal("expected /reflect to be attempted before fallback")
	}
	if _, err := os.Stat(copilotMarker); err != nil {
		t.Fatalf("expected copilot fallback to run: %v", err)
	}
	result := readResultFile(t, outputPath)
	if !result["prompt_injection"].(bool) {
		t.Fatalf("fallback result prompt_injection = false, want true: %#v", result)
	}
}

func TestRunReflectSuccessDoesNotInvokeAgenticEngine(t *testing.T) {
	var postRequests atomic.Int32
	reflectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"models":[{"id":"schema","provider":"openai","capabilities":{"json_schema":true}}]}`))
		case http.MethodPost:
			postRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`))
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))
	defer reflectServer.Close()

	artifactsDir := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	fakeBinDir := writeFakeCopilot(t, copilotMarker, "copilot should not run")

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-triage=false",
		"-reflect-url", reflectServer.URL,
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH": fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d", code, exitSafe)
	}
	if postRequests.Load() == 0 {
		t.Fatal("expected successful structured /reflect detection")
	}
	if _, err := os.Stat(copilotMarker); !os.IsNotExist(err) {
		t.Fatalf("copilot should not run when /reflect succeeds, stat err = %v", err)
	}
	result := readResultFile(t, outputPath)
	if result["prompt_injection"].(bool) || result["secret_leak"].(bool) || result["malicious_patch"].(bool) {
		t.Fatalf("reflect result is not safe: %#v", result)
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

func writeFakeCopilot(t *testing.T, markerPath, output string) string {
	t.Helper()

	binDir := t.TempDir()
	scriptPath := filepath.Join(binDir, "copilot")
	script := strings.Join([]string{
		"#!/bin/sh",
		"cat >/dev/null",
		"printf called > " + shellQuote(markerPath),
		"printf '%s\\n' " + shellQuote(output),
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
