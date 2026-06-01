package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

func TestProvisionResultTool(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	env, cleanup, err := provisionResultTool(sink)
	if err != nil {
		t.Fatalf("provisionResultTool() error = %v", err)
	}
	defer cleanup()

	var toolDir, pathEnv, fileEnv string
	for _, e := range env {
		switch {
		case strings.HasPrefix(e, "THREAT_DETECTION_RESULT_FILE="):
			fileEnv = strings.TrimPrefix(e, "THREAT_DETECTION_RESULT_FILE=")
		case strings.HasPrefix(e, "PATH="):
			pathEnv = strings.TrimPrefix(e, "PATH=")
			toolDir = strings.SplitN(pathEnv, string(os.PathListSeparator), 2)[0]
		}
	}
	if fileEnv != sink {
		t.Fatalf("THREAT_DETECTION_RESULT_FILE = %q, want %q", fileEnv, sink)
	}
	if toolDir == "" {
		t.Fatal("expected PATH prefix with tool dir")
	}
	wrapper := filepath.Join(toolDir, "threat_detection_result")
	info, err := os.Stat(wrapper)
	if err != nil {
		t.Fatalf("stat wrapper error = %v", err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("wrapper not executable: %o", info.Mode().Perm())
	}
}

func TestProvisionResultToolCleanup(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	env, cleanup, err := provisionResultTool(sink)
	if err != nil {
		t.Fatalf("provisionResultTool() error = %v", err)
	}
	var toolDir string
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			toolDir = strings.SplitN(strings.TrimPrefix(e, "PATH="), string(os.PathListSeparator), 2)[0]
		}
	}
	cleanup()
	if _, err := os.Stat(toolDir); !os.IsNotExist(err) {
		t.Fatalf("expected tool dir removed, stat err = %v", err)
	}
}

func TestWatchResultSinkCancels(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		watchResultSink(ctx, cancel, sink)
		close(done)
	}()

	// Write a valid result; the watcher should cancel the context.
	if err := detector.WriteResultFile(sink, &detector.Result{Reasons: []string{}}); err != nil {
		t.Fatalf("WriteResultFile() error = %v", err)
	}

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("watchResultSink did not cancel context")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchResultSink did not return")
	}
}

func TestRunCLIEnvWithSinkSuppressesKilledError(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	if err := detector.WriteResultFile(sink, &detector.Result{Reasons: []string{}}); err != nil {
		t.Fatalf("WriteResultFile() error = %v", err)
	}
	// A command that fails (false) but with a valid sink should be treated as success.
	out, err := runCLIEnvWithSink(context.Background(), "sh", []string{"-c", "echo hi; exit 1"}, "", nil, sink)
	if err != nil {
		t.Fatalf("expected nil error when sink is valid, got %v", err)
	}
	if !strings.Contains(out, "hi") {
		t.Fatalf("expected captured stdout, got %q", out)
	}
}

func TestRunCLIEnvWithSinkSurfacesErrorWithoutSink(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "missing.json")
	_, err := runCLIEnvWithSink(context.Background(), "sh", []string{"-c", "exit 1"}, "", nil, sink)
	if err == nil {
		t.Fatal("expected error when no valid sink result exists")
	}
}
