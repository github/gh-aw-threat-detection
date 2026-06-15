// Package main provides the CLI entry point for the threat detection tool.
//
// Usage:
//
//	threat-detect [flags] <artifacts-dir>
//
// The tool analyzes AI agent output for security threats including prompt injection,
// secret leaks, and malicious patches.
//
// Exit codes:
//
//	0 - Safe (no threats detected)
//	1 - Threat detected
//	2 - Infrastructure/configuration error
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
	"github.com/github/gh-aw-threat-detection/pkg/detector"
	"github.com/github/gh-aw-threat-detection/pkg/engine"
)

const (
	exitSafe   = 0
	exitThreat = 1
	exitError  = 2

	fullDetectionCorrectionSummaryFormat     = "Your previous response did not contain a valid %s JSON object"
	fullDetectionCorrectionInstructionFormat = "Re-run the threat_detection_result command with corrected values, or return exactly one corrected result line using the required %s prefix."
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "report-result" {
		os.Exit(runReport(os.Args[2:]))
	}
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var (
		engineID   string
		model      string
		promptFile string
		outputJSON string
		version    bool
		retries    int
	)

	flag.StringVar(&engineID, "engine", "", "AI engine to use (copilot, claude, codex)")
	flag.StringVar(&model, "model", "", "Model to use for detection")
	flag.StringVar(&promptFile, "prompt-template", "", "Path to custom prompt template (defaults to built-in)")
	flag.StringVar(&outputJSON, "output", "", "Path to write JSON result (defaults to stdout)")
	flag.BoolVar(&version, "version", false, "Print version and exit")
	flag.IntVar(&retries, "retries", envInt("THREAT_DETECTION_RETRIES", 1), "Retries for malformed detection outputs (env: THREAT_DETECTION_RETRIES)")
	flag.Parse()

	if version {
		fmt.Printf("threat-detect %s\n", detector.Version)
		return exitSafe
	}

	// Determine artifacts directory from positional args
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: threat-detect [flags] <artifacts-dir>\n")
		flag.PrintDefaults()
		return exitError
	}
	artifactsDir := args[0]

	// Load artifacts
	arts, err := artifacts.Load(artifactsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading artifacts: %v\n", err)
		return exitError
	}

	// Build the prompt
	promptTemplate := ""
	if promptFile != "" {
		data, err := os.ReadFile(promptFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading prompt template: %v\n", err)
			return exitError
		}
		promptTemplate = string(data)
	}

	prompt, err := detector.BuildPrompt(arts, promptTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building prompt: %v\n", err)
		return exitError
	}

	// Create engine
	eng, err := engine.New(engineID, model)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
		return exitError
	}

	// Provision an out-of-band result sink for the in-session reporting tool.
	sinkFile, err := os.CreateTemp("", "threat-detect-result-*.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating result sink: %v\n", err)
		return exitError
	}
	sinkPath := sinkFile.Name()
	sinkFile.Close()
	// Remove the empty placeholder so ReadResultFile only succeeds once the tool writes it.
	os.Remove(sinkPath)
	defer os.Remove(sinkPath)

	result, err := analyzeWithRetries(ctx, eng, prompt, sinkPath, retries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running detection: %v\n", err)
		return exitError
	}

	return writeResult(result, outputJSON)
}

func analyzeWithRetries(ctx context.Context, eng engine.Engine, prompt, sinkPath string, retries int) (*detector.Result, error) {
	attempts := retries + 1
	if attempts < 1 {
		attempts = 1
	}
	currentPrompt := prompt
	var lastErr error
	for i := 0; i < attempts; i++ {
		// Remove any stale sink result before each attempt.
		if sinkPath != "" {
			os.Remove(sinkPath)
		}
		rawOutput, err := eng.Analyze(ctx, currentPrompt, engine.AnalyzeOptions{ResultSinkPath: sinkPath})
		if err != nil {
			return nil, err
		}
		// Prefer the out-of-band sink result over transcript scraping.
		if sinkPath != "" {
			if result, sinkErr := detector.ReadResultFile(sinkPath); sinkErr == nil {
				return result, nil
			}
		}
		result, err := detector.ParseResult(rawOutput)
		if err == nil {
			return result, nil
		}
		lastErr = err
		summary := fmt.Sprintf(fullDetectionCorrectionSummaryFormat, detector.ResultPrefix)
		instruction := fmt.Sprintf(fullDetectionCorrectionInstructionFormat, detector.ResultPrefix)
		currentPrompt = detector.BuildCorrectionPrompt(prompt, summary, err.Error(), instruction)
	}
	return nil, lastErr
}

func writeResult(result *detector.Result, outputJSON string) int {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling result: %v\n", err)
		return exitError
	}

	if outputJSON != "" {
		if err := os.WriteFile(outputJSON, jsonBytes, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			return exitError
		}
	} else {
		fmt.Println(string(jsonBytes))
	}

	// Exit code based on threat detection
	if result.HasThreats() {
		return exitThreat
	}
	return exitSafe
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
