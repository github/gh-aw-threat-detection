// Package engine provides AI engine abstractions for threat detection.
// It supports multiple AI engines (copilot, claude, codex) and handles
// the invocation of the detection analysis.
package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

// AnalyzeOptions carries optional in-session reporting configuration.
type AnalyzeOptions struct {
	// ResultSinkPath, when non-empty, enables the threat_detection_result tool:
	// the engine provisions the wrapper on PATH, sets THREAT_DETECTION_RESULT_FILE,
	// and cancels the subprocess as soon as a valid result is written to this path.
	ResultSinkPath string
}

// Engine represents an AI engine capable of analyzing content for threats.
type Engine interface {
	// Analyze sends the prompt to the AI engine and returns the raw output.
	Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error)
}

// DefaultReflectURL is the default local api-proxy reflect endpoint.
const DefaultReflectURL = "http://127.0.0.1:8080/reflect"

// New creates a new engine instance based on the engine ID.
// If engineID is empty, it defaults to "copilot".
func New(engineID, model string) (Engine, error) {
	if engineID == "" {
		engineID = "copilot"
	}

	switch strings.ToLower(engineID) {
	case "copilot":
		return &copilotEngine{model: model}, nil
	case "claude":
		return &claudeEngine{model: model}, nil
	case "codex":
		return &codexEngine{model: model}, nil
	default:
		return nil, fmt.Errorf("unsupported engine: %q (supported: copilot, claude, codex)", engineID)
	}
}

// copilotEngine implements Engine using GitHub Copilot CLI.
type copilotEngine struct {
	model string
}

func (e *copilotEngine) Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error) {
	env := copilotEnv(e.model)
	toolEnv, cleanup, err := maybeProvisionResultTool(opts.ResultSinkPath)
	if err != nil {
		return "", err
	}
	defer cleanup()
	env = append(env, toolEnv...)

	if _, ok := copilotHarnessPath(); ok {
		return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
			return copilotCommand(promptPath)
		}, "", env, opts.ResultSinkPath)
	}
	return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
		return "copilot", copilotDirectArgs(promptPath)
	}, prompt, env, opts.ResultSinkPath)
}

// claudeEngine implements Engine using the Claude CLI.
type claudeEngine struct {
	model string
}

func (e *claudeEngine) Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error) {
	toolEnv, cleanup, err := maybeProvisionResultTool(opts.ResultSinkPath)
	if err != nil {
		return "", err
	}
	defer cleanup()
	enableBashTool := opts.ResultSinkPath != ""
	return runCLIEnvWithSink(ctx, "claude", claudeArgs(e.model, enableBashTool), prompt, toolEnv, opts.ResultSinkPath)
}

// codexEngine implements Engine using the Codex CLI.
type codexEngine struct {
	model string
}

func (e *codexEngine) Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error) {
	toolEnv, cleanup, err := maybeProvisionResultTool(opts.ResultSinkPath)
	if err != nil {
		return "", err
	}
	defer cleanup()
	return runCLIEnvWithSink(ctx, "codex", codexArgs(e.model, ""), prompt, toolEnv, opts.ResultSinkPath)
}

// maybeProvisionResultTool provisions the threat_detection_result tool when a
// sink path is configured, returning the env additions and a cleanup func. When
// sinkPath is empty it returns no env and a no-op cleanup.
func maybeProvisionResultTool(sinkPath string) (env []string, cleanup func(), err error) {
	if sinkPath == "" {
		return nil, func() {}, nil
	}
	return provisionResultTool(sinkPath)
}

func copilotCommand(promptPath string) (string, []string) {
	if harnessPath, ok := copilotHarnessPath(); ok {
		return nodeCommand(), append([]string{harnessPath, copilotBinary()}, copilotArgs(promptPath)...)
	}
	return "copilot", copilotDirectArgs(promptPath)
}

func copilotArgs(promptPath string) []string {
	return append(copilotDirectArgs(promptPath), "--prompt-file", promptPath)
}

func copilotDirectArgs(promptPath string) []string {
	args := []string{
		"--add-dir", filepath.Dir(promptPath),
		"--log-level", "all",
		"--disable-builtin-mcps",
		"--no-ask-user",
		"--allow-all-tools",
	}
	if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" {
		args = append(args, "--add-dir", workspace)
	}
	return args
}

func copilotHarnessPath() (string, bool) {
	runnerTemp := os.Getenv("RUNNER_TEMP")
	if runnerTemp == "" {
		return "", false
	}
	harnessPath := filepath.Join(runnerTemp, "gh-aw", "actions", "copilot_harness.cjs")
	if _, err := os.Stat(harnessPath); err != nil {
		return "", false
	}
	return harnessPath, true
}

func nodeCommand() string {
	if node := os.Getenv("GH_AW_NODE_BIN"); node != "" {
		return node
	}
	return "node"
}

func copilotBinary() string {
	if _, err := os.Stat("/usr/local/bin/copilot"); err == nil {
		return "/usr/local/bin/copilot"
	}
	return "copilot"
}

func copilotEnv(model string) []string {
	if model == "" {
		return nil
	}
	return []string{"COPILOT_MODEL=" + model}
}

func claudeArgs(model string, allowBash bool) []string {
	args := []string{"--print", "--verbose", "--output-format", "stream-json"}
	if allowBash {
		args = append(args, "--allowed-tools", "Bash")
	}
	if model != "" {
		args = append(args, "--model", model)
	}
	return append(args, "-")
}

func codexArgs(model, prompt string) []string {
	args := []string{
		"exec",
		"-c", "web_search=disabled",
		"-c", "fetch=disabled",
		"--dangerously-bypass-approvals-and-sandbox",
		"--skip-git-repo-check",
		"--",
		prompt,
	}
	if model != "" {
		args = append([]string{"-c", "model=" + model}, args...)
	}
	return args
}

// runCLI executes a CLI command, passing the prompt via stdin, and returns its
// stdout output. Using stdin avoids OS argument length limits and prevents the
// prompt content from appearing in process listings.
func runCLI(ctx context.Context, name string, args []string, stdinData string) (string, error) {
	return runCLIEnv(ctx, name, args, stdinData, nil)
}

func runCLIWithPromptFile(ctx context.Context, prompt string, commandBuilder func(string) (string, []string), stdinData string, env []string, sinkPath string) (output string, err error) {
	promptFile, err := os.CreateTemp("", "threat-detect-prompt-*.txt")
	if err != nil {
		return "", fmt.Errorf("creating temporary prompt file: %w", err)
	}
	promptPath := promptFile.Name()
	defer func() {
		if removeErr := os.Remove(promptPath); err == nil && removeErr != nil {
			err = fmt.Errorf("removing temporary prompt file: %w", removeErr)
		}
	}()
	if _, err := promptFile.WriteString(prompt); err != nil {
		promptFile.Close()
		return "", fmt.Errorf("writing temporary prompt file: %w", err)
	}
	if err := promptFile.Close(); err != nil {
		return "", fmt.Errorf("closing temporary prompt file: %w", err)
	}
	name, args := commandBuilder(promptPath)
	return runCLIEnvWithSink(ctx, name, args, stdinData, env, sinkPath)
}

func runCLIEnv(ctx context.Context, name string, args []string, stdinData string, env []string) (string, error) {
	return runCLIEnvWithSink(ctx, name, args, stdinData, env, "")
}

// runCLIEnvWithSink runs the CLI command and, when sinkPath is non-empty, watches
// the sink file and cancels the subprocess as soon as a valid result is recorded.
// A subprocess error is suppressed when a valid sink result exists, because the
// process was intentionally killed once the verdict was reported.
func runCLIEnvWithSink(ctx context.Context, name string, args []string, stdinData string, env []string, sinkPath string) (string, error) {
	if sinkPath != "" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go watchResultSink(ctx, cancel, sinkPath)
	}

	cmd := exec.CommandContext(ctx, name, args...)
	if stdinData != "" {
		cmd.Stdin = strings.NewReader(stdinData)
	}
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	if sinkPath != "" {
		// Bound how long Run waits for stdout I/O after the process is killed on
		// early termination, in case the engine left descendants holding the pipe.
		cmd.WaitDelay = resultSinkPollInterval
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if sinkPath != "" {
			if _, sinkErr := detector.ReadResultFile(sinkPath); sinkErr == nil {
				// The verdict was recorded; the process was intentionally killed.
				return stdout.String(), nil
			}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%s exited with code %d: %s", name, exitErr.ExitCode(), stderr.String())
		}
		return "", fmt.Errorf("failed to execute %s: %w", name, err)
	}

	return stdout.String(), nil
}
