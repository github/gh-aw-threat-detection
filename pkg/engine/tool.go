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

// reasonsFileName is the conventional name of the reasons file the engine
// writes. It is provisioned in the same directory as the result sink, which is
// also the directory holding the rendered prompt file — a directory every
// engine can already reach (Copilot is given it via --add-dir), so the model is
// never told to write somewhere it may be refused.
const reasonsFileName = "threat-detection-reasons.json"

// provisionResultTool creates a temp dir containing an executable
// "threat_detection_result" wrapper that execs the current binary's
// report-result subcommand. It returns the env additions
// (THREAT_DETECTION_RESULT_FILE, THREAT_DETECTION_REASONS_FILE and a PATH
// prefix) and a cleanup func.
func provisionResultTool(sinkPath string) (env []string, cleanup func(), err error) {
	self, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving executable path: %w", err)
	}

	// Drop any reasons file left by an earlier attempt so a retry cannot report
	// stale reasons that the model did not author this time around.
	reasonsPath := filepath.Join(filepath.Dir(sinkPath), reasonsFileName)
	if err := os.Remove(reasonsPath); err != nil && !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("removing stale reasons file: %w", err)
	}

	toolDir, err := os.MkdirTemp("", "threat-detect-tool-")
	if err != nil {
		return nil, nil, fmt.Errorf("creating tool dir: %w", err)
	}
	cleanup = func() { os.RemoveAll(toolDir) }

	wrapperPath := filepath.Join(toolDir, "threat_detection_result")
	if err := os.WriteFile(wrapperPath, []byte(resultToolScript(self)), 0o700); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("writing result tool wrapper: %w", err)
	}

	pathEnv := os.Getenv("PATH")
	env = []string{
		"THREAT_DETECTION_RESULT_FILE=" + sinkPath,
		"THREAT_DETECTION_REASONS_FILE=" + reasonsPath,
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

// resultToolScript renders the threat_detection_result wrapper that execs self's
// report-result subcommand.
//
// The arguments are forwarded with "$@" (double-quoted, never $* or bare $@) so
// each argument the engine passed reaches the subcommand as one intact
// argument, without a second round of word splitting or globbing. This matters
// because reason text quotes attacker-authored artifact content; the wrapper
// must never re-interpret it. It is only half the boundary, though — the engine
// composes the command line in its own shell, which is why reason text is
// transported through --reasons-file rather than as an argument.
func resultToolScript(self string) string {
	return "#!/bin/sh\nexec " + shellQuote(self) + " report-result \"$@\"\n"
}

// shellQuote wraps a value in single quotes for safe use in a POSIX shell script.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
