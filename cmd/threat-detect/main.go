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
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var (
		engineID       string
		model          string
		promptFile     string
		outputJSON     string
		version        bool
		triage         bool
		reflectURL     string
		triageModel    string
		triageMaxBytes int
		triageRetries  int
	)

	flag.StringVar(&engineID, "engine", "", "AI engine to use (copilot, claude, codex)")
	flag.StringVar(&model, "model", "", "Model to use for detection")
	flag.StringVar(&promptFile, "prompt-template", "", "Path to custom prompt template (defaults to built-in)")
	flag.StringVar(&outputJSON, "output", "", "Path to write JSON result (defaults to stdout)")
	flag.BoolVar(&version, "version", false, "Print version and exit")
	flag.BoolVar(&triage, "triage", envBool("THREAT_DETECTION_TRIAGE", true), "Run Phase 1 structured-output triage before full detection (env: THREAT_DETECTION_TRIAGE)")
	flag.StringVar(&reflectURL, "reflect-url", envFirstOrDefault(engine.DefaultReflectURL, "THREAT_DETECTION_REFLECT_URL", "API_PROXY_REFLECT_URL", "REFLECT_URL"), "api-proxy reflect base URL")
	flag.StringVar(&triageModel, "triage-model", os.Getenv("THREAT_DETECTION_TRIAGE_MODEL"), "Model to use for reflect triage")
	flag.IntVar(&triageMaxBytes, "triage-max-bytes", envInt("THREAT_DETECTION_TRIAGE_MAX_BYTES", detector.DefaultTriageMaxBytes()), "Maximum bytes per artifact to inline for triage")
	flag.IntVar(&triageRetries, "triage-retries", envInt("THREAT_DETECTION_TRIAGE_RETRIES", 1), "Retries for malformed structured outputs")
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

	if triage && reflectURL != "" {
		triagePrompt, err := detector.BuildTriagePrompt(arts, triageMaxBytes)
		if err == nil {
			triageResult, err := (&engine.ReflectClient{
				BaseURL: reflectURL,
				Model:   triageModel,
				Retries: triageRetries,
			}).AnalyzeStructured(ctx, triagePrompt)
			if err == nil && triageResult.IsSafe() {
				return writeResult(triageResult, outputJSON)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Triage inconclusive, running full detection: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "Triage found possible threats, running full detection")
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error building triage prompt, running full detection: %v\n", err)
		}
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

	if reflectURL != "" {
		reflectResult, err := (&engine.ReflectClient{
			BaseURL: reflectURL,
			Model:   firstNonEmpty(model, triageModel),
			Retries: triageRetries,
		}).AnalyzeStructured(ctx, prompt)
		if err == nil {
			return writeResult(reflectResult, outputJSON)
		}
		fmt.Fprintf(os.Stderr, "Structured reflect detection unavailable, using CLI engine: %v\n", err)
	}

	// Create engine
	eng, err := engine.New(engineID, model)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
		return exitError
	}

	result, err := analyzeWithRetries(ctx, eng, prompt, triageRetries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running detection: %v\n", err)
		return exitError
	}

	return writeResult(result, outputJSON)
}

func analyzeWithRetries(ctx context.Context, eng engine.Engine, prompt string, retries int) (*detector.Result, error) {
	attempts := retries + 1
	if attempts < 1 {
		attempts = 1
	}
	currentPrompt := prompt
	var lastErr error
	for i := 0; i < attempts; i++ {
		rawOutput, err := eng.Analyze(ctx, currentPrompt)
		if err != nil {
			return nil, err
		}
		result, err := detector.ParseResult(rawOutput)
		if err == nil {
			return result, nil
		}
		lastErr = err
		summary := fmt.Sprintf("Your previous response did not contain a valid %s JSON object", detector.ResultPrefix)
		instruction := "Return exactly one corrected result line using the required " + detector.ResultPrefix + " prefix."
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

func envFirstOrDefault(fallback string, keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
