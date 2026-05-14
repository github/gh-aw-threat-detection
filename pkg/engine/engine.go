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
)

// Engine represents an AI engine capable of analyzing content for threats.
type Engine interface {
	// Analyze sends the prompt to the AI engine and returns the raw output.
	Analyze(ctx context.Context, prompt string) (string, error)
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

func (e *copilotEngine) Analyze(ctx context.Context, prompt string) (string, error) {
	return runCLIWithPromptFile(ctx, "copilot", prompt, func(promptPath string) []string {
		return copilotArgs(promptPath)
	}, copilotEnv(e.model))
}

// claudeEngine implements Engine using the Claude CLI.
type claudeEngine struct {
	model string
}

func (e *claudeEngine) Analyze(ctx context.Context, prompt string) (string, error) {
	return runCLI(ctx, "claude", claudeArgs(e.model), prompt)
}

// codexEngine implements Engine using the Codex CLI.
type codexEngine struct {
	model string
}

func (e *codexEngine) Analyze(ctx context.Context, prompt string) (string, error) {
	return runCLIEnv(ctx, "codex", codexArgs(e.model, ""), prompt, nil)
}

func copilotArgs(promptPath string) []string {
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
	return append(args, "--prompt-file", promptPath)
}

func copilotEnv(model string) []string {
	if model == "" {
		return nil
	}
	return []string{"COPILOT_MODEL=" + model}
}

func claudeArgs(model string) []string {
	args := []string{"--print", "--verbose", "--output-format", "stream-json"}
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

func runCLIWithPromptFile(ctx context.Context, name string, prompt string, argsForPrompt func(string) []string, env []string) (output string, err error) {
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
	return runCLIEnv(ctx, name, argsForPrompt(promptPath), "", env)
}

func runCLIEnv(ctx context.Context, name string, args []string, stdinData string, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdinData != "" {
		cmd.Stdin = strings.NewReader(stdinData)
	}
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%s exited with code %d: %s", name, exitErr.ExitCode(), stderr.String())
		}
		return "", fmt.Errorf("failed to execute %s: %w", name, err)
	}

	return stdout.String(), nil
}
