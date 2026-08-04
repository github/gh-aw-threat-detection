package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readJSONLRecords parses a JSONL file into a slice of decoded records.
func readJSONLRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not valid JSON (%q): %v", line, err)
		}
		records = append(records, rec)
	}
	return records
}

func findRecord(records []map[string]any, event string) map[string]any {
	for _, rec := range records {
		if rec["event"] == event {
			return rec
		}
	}
	return nil
}

func TestRunWritesJSONLLog(t *testing.T) {
	artifactsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(artifactsDir, "experiments"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactsDir, "experiments", "assignment.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "result.json")
	logPath := filepath.Join(t.TempDir(), "run.jsonl")
	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":true,"secret_leak":false,"malicious_patch":false,"reasons":["agentic detection"]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-log-file", logPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GITHUB_STEP_SUMMARY": summaryPath,
	})

	if code != exitThreat {
		t.Fatalf("run() exit code = %d, want %d", code, exitThreat)
	}

	records := readJSONLRecords(t, logPath)

	// The primary audit record must reflect the engine that actually runs:
	// an omitted --engine resolves to copilot, not "".
	start := findRecord(records, "run_start")
	if start == nil {
		t.Fatalf("missing run_start record: %#v", records)
	}
	if start["engine"] != "copilot" {
		t.Errorf("run_start engine = %v, want copilot", start["engine"])
	}

	loaded := findRecord(records, "artifacts_loaded")
	if loaded == nil {
		t.Fatalf("missing artifacts_loaded record: %#v", records)
	}
	inventory, ok := loaded["inventory"].([]any)
	if !ok || len(inventory) != 1 {
		t.Fatalf("artifacts_loaded inventory = %#v, want one entry", loaded["inventory"])
	}
	entry, ok := inventory[0].(map[string]any)
	if !ok {
		t.Fatalf("inventory entry = %#v", inventory[0])
	}
	if entry["path"] != "experiments/assignment.json" || entry["consumed"] != false {
		t.Errorf("inventory entry = %#v, want unconsumed experiment", entry)
	}

	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("reading step summary: %v", err)
	}
	if !strings.Contains(string(summary), "| <code>experiments/assignment.json</code> | 2 | file | No |") {
		t.Errorf("step summary missing experiment inventory:\n%s", summary)
	}

	verdict := findRecord(records, "verdict")
	if verdict == nil {
		t.Fatalf("missing verdict record: %#v", records)
	}
	if verdict["prompt_injection"] != true {
		t.Errorf("verdict prompt_injection = %v, want true", verdict["prompt_injection"])
	}
	if verdict["has_threats"] != true {
		t.Errorf("verdict has_threats = %v, want true", verdict["has_threats"])
	}

	// The terminal status record must mirror the stderr status line: reason +
	// exit, using the JSON number 1 for a detected threat.
	status := findRecord(records, "status")
	if status == nil {
		t.Fatalf("missing status record: %#v", records)
	}
	if status["reason"] != reasonResultRecorded {
		t.Errorf("status reason = %v, want %s", status["reason"], reasonResultRecorded)
	}
	if exit, ok := status["exit"].(float64); !ok || int(exit) != exitThreat {
		t.Errorf("status exit = %v, want %d", status["exit"], exitThreat)
	}
}

func TestRunDefaultsLogBesideOutput(t *testing.T) {
	artifactsDir := t.TempDir()
	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "result.json")
	logPath := filepath.Join(outputDir, "detection-runlog.jsonl")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                      fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"THREAT_DETECTION_LOG_FILE": "",
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d", code, exitSafe)
	}
	records := readJSONLRecords(t, logPath)
	if findRecord(records, "run_start") == nil {
		t.Fatalf("expected default log file to receive records: %#v", records)
	}
	if status := findRecord(records, "status"); status == nil || status["reason"] != reasonResultRecorded {
		t.Fatalf("expected result_recorded status, got %#v", status)
	}
}

func TestRunUsesLogFileEnvVar(t *testing.T) {
	artifactsDir := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "result.json")
	logPath := filepath.Join(t.TempDir(), "run.jsonl")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code := runWithTestArgs(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                      fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"THREAT_DETECTION_LOG_FILE": logPath,
	})

	if code != exitSafe {
		t.Fatalf("run() exit code = %d, want %d", code, exitSafe)
	}
	records := readJSONLRecords(t, logPath)
	if findRecord(records, "run_start") == nil {
		t.Fatalf("expected env-configured log file to receive records: %#v", records)
	}
	status := findRecord(records, "status")
	if status == nil || status["reason"] != reasonResultRecorded {
		t.Fatalf("expected result_recorded status, got %#v", status)
	}
}

func TestRunRejectsLogFileCollidingWithOutput(t *testing.T) {
	artifactsDir := t.TempDir()
	shared := filepath.Join(t.TempDir(), "same.json")

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", shared,
		"-log-file", shared,
		artifactsDir,
	}, nil)

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "must not point to the same file") {
		t.Fatalf("stderr missing collision error, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "reason=config_error") {
		t.Fatalf("stderr missing config_error status, got:\n%s", stderr)
	}
	// Neither file should have been created by the aborted run.
	if _, err := os.Stat(shared); !os.IsNotExist(err) {
		t.Fatalf("expected no file to be written, stat err = %v", err)
	}
}

func TestRunRejectsDefaultLogCollidingThroughDanglingOutputSymlink(t *testing.T) {
	artifactsDir := t.TempDir()
	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "result.json")
	logPath := filepath.Join(outputDir, "detection-runlog.jsonl")
	if err := os.Symlink(filepath.Base(logPath), outputPath); err != nil {
		t.Fatalf("creating dangling output symlink: %v", err)
	}

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{"THREAT_DETECTION_LOG_FILE": ""})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "must not point to the same file") {
		t.Fatalf("stderr missing collision error, got:\n%s", stderr)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("expected no log file to be written, stat err = %v", err)
	}
}

func TestRunRejectsCollisionWithParentTraversalAfterSymlink(t *testing.T) {
	artifactsDir := t.TempDir()
	root := t.TempDir()
	targetDir := filepath.Join(root, "target")
	childDir := filepath.Join(targetDir, "child")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		t.Fatalf("creating symlink target: %v", err)
	}
	linkPath := filepath.Join(root, "link")
	if err := os.Symlink(childDir, linkPath); err != nil {
		t.Fatalf("creating directory symlink: %v", err)
	}
	outputPath := linkPath + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "result.json"
	logPath := filepath.Join(targetDir, "result.json")

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		"-log-file", logPath,
		artifactsDir,
	}, nil)

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "must not point to the same file") {
		t.Fatalf("stderr missing collision error, got:\n%s", stderr)
	}
}

func TestRunRejectsUnopenableLogFile(t *testing.T) {
	artifactsDir := t.TempDir()
	// Parent directory does not exist, so runlog.Open must fail.
	logPath := filepath.Join(t.TempDir(), "missing-dir", "run.jsonl")

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-log-file", logPath,
		artifactsDir,
	}, nil)

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "Error opening log file") {
		t.Fatalf("stderr missing open error, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "reason=config_error") {
		t.Fatalf("stderr missing config_error status, got:\n%s", stderr)
	}
}

func TestRunRejectsUnwritableStepSummary(t *testing.T) {
	artifactsDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "run.jsonl")
	summaryPath := filepath.Join(t.TempDir(), "missing-dir", "summary.md")

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-log-file", logPath,
		artifactsDir,
	}, map[string]string{
		"GITHUB_STEP_SUMMARY": summaryPath,
	})

	if code != exitError {
		t.Fatalf("run() exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "Error writing artifact inventory summary") {
		t.Fatalf("stderr missing summary error, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "reason=config_error") {
		t.Fatalf("stderr missing config_error status, got:\n%s", stderr)
	}
	records := readJSONLRecords(t, logPath)
	if findRecord(records, "artifact_inventory_summary_failed") == nil {
		t.Fatalf("missing artifact_inventory_summary_failed record: %#v", records)
	}
}
