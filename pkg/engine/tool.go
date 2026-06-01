package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

// resultSinkPollInterval is how often watchResultSink polls the sink file.
const resultSinkPollInterval = 250 * time.Millisecond

// provisionResultTool creates a temp dir containing an executable
// "threat_detection_result" wrapper that execs the current binary's
// report-result subcommand. It returns the env additions
// (THREAT_DETECTION_RESULT_FILE and a PATH prefix) and a cleanup func.
func provisionResultTool(sinkPath string) (env []string, cleanup func(), err error) {
	self, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving executable path: %w", err)
	}

	toolDir, err := os.MkdirTemp("", "threat-detect-tool-")
	if err != nil {
		return nil, nil, fmt.Errorf("creating tool dir: %w", err)
	}
	cleanup = func() { os.RemoveAll(toolDir) }

	wrapperPath := filepath.Join(toolDir, "threat_detection_result")
	script := "#!/bin/sh\nexec " + shellQuote(self) + " report-result \"$@\"\n"
	if err := os.WriteFile(wrapperPath, []byte(script), 0o700); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("writing result tool wrapper: %w", err)
	}

	pathEnv := os.Getenv("PATH")
	env = []string{
		"THREAT_DETECTION_RESULT_FILE=" + sinkPath,
		"PATH=" + toolDir + string(os.PathListSeparator) + pathEnv,
	}
	return env, cleanup, nil
}

// watchResultSink polls sinkPath; when ReadResultFile(sinkPath) first succeeds,
// it calls cancel() to terminate the engine subprocess. It returns when ctx is done.
func watchResultSink(ctx context.Context, cancel context.CancelFunc, sinkPath string) {
	ticker := time.NewTicker(resultSinkPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := detector.ReadResultFile(sinkPath); err == nil {
				cancel()
				return
			}
		}
	}
}

// shellQuote wraps a value in single quotes for safe use in a POSIX shell script.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
