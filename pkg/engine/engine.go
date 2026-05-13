// Package engine provides AI engine abstractions for threat detection.
// It supports multiple AI engines (copilot, claude, codex) and handles
// the invocation of the detection analysis.
package engine

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
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
	args := []string{"--print"}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, "-")
	return runCLI(ctx, "copilot", args, prompt)
}

// claudeEngine implements Engine using the Claude CLI.
type claudeEngine struct {
	model string
}

func (e *claudeEngine) Analyze(ctx context.Context, prompt string) (string, error) {
	args := []string{"--print", "--output-format", "stream-json"}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, "-")
	return runCLI(ctx, "claude", args, prompt)
}

// codexEngine implements Engine using the Codex CLI.
type codexEngine struct {
	model string
}

func (e *codexEngine) Analyze(ctx context.Context, prompt string) (string, error) {
	args := []string{"--print"}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, "-")
	return runCLI(ctx, "codex", args, prompt)
}

// runCLI executes a CLI command, passing the prompt via stdin, and returns its
// stdout output. Using stdin avoids OS argument length limits and prevents the
// prompt content from appearing in process listings.
func runCLI(ctx context.Context, name string, args []string, stdinData string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdinData)

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
