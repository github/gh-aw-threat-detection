// Package engine provides AI engine abstractions for threat detection.
// It supports multiple AI engines (copilot, claude, codex) and handles
// the invocation of the detection analysis.
package engine

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Engine represents an AI engine capable of analyzing content for threats.
type Engine interface {
	// Analyze sends the prompt to the AI engine and returns the raw output.
	Analyze(prompt string) (string, error)
}

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

func (e *copilotEngine) Analyze(prompt string) (string, error) {
	return runCLI("copilot", e.buildArgs(prompt))
}

func (e *copilotEngine) buildArgs(prompt string) []string {
	args := []string{"--print"}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, prompt)
	return args
}

// claudeEngine implements Engine using the Claude CLI.
type claudeEngine struct {
	model string
}

func (e *claudeEngine) Analyze(prompt string) (string, error) {
	return runCLI("claude", e.buildArgs(prompt))
}

func (e *claudeEngine) buildArgs(prompt string) []string {
	args := []string{"--print", "--output-format", "stream-json"}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, prompt)
	return args
}

// codexEngine implements Engine using the Codex CLI.
type codexEngine struct {
	model string
}

func (e *codexEngine) Analyze(prompt string) (string, error) {
	return runCLI("codex", e.buildArgs(prompt))
}

func (e *codexEngine) buildArgs(prompt string) []string {
	args := []string{"--print"}
	if e.model != "" {
		args = append(args, "--model", e.model)
	}
	args = append(args, prompt)
	return args
}

// runCLI executes a CLI command and returns its stdout output.
func runCLI(name string, args []string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%s exited with code %d: %s", name, exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return "", fmt.Errorf("failed to execute %s: %w", name, err)
	}

	return string(output), nil
}
