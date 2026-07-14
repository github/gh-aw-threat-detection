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
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
	"github.com/github/gh-aw-threat-detection/pkg/detector"
	"github.com/github/gh-aw-threat-detection/pkg/engine"
	"github.com/github/gh-aw-threat-detection/pkg/runlog"
)

const (
	exitSafe   = 0
	exitThreat = 1
	exitError  = 2

	detectionCorrectionPrefix      = "Your previous response did not record a verdict"
	detectionCorrectionMessage     = "The threat_detection_result command was not run, or it reported an error and exited before a verdict was recorded."
	detectionCorrectionInstruction = "Run the threat_detection_result command exactly once with --prompt-injection, --secret-leak, and --malicious-patch each set to true or false, plus a --reason for every threat set to true."
)

// statusPrefix is the marker for the single machine-readable status line
// emitted to stderr at the end of every detection run. It is deliberately
// distinct from the THREAT_DETECTION_RESULT: verdict prefix consumed by gh-aw
// so the two never collide. Because the result JSON is not written on error
// paths, this line is often the only structured signal a caller receives.
const statusPrefix = "THREAT_DETECTION_STATUS:"

// Terminal reasons reported on the status line. Exactly one is emitted per run.
const (
	reasonResultRecorded         = "result_recorded"          // verdict obtained (exit 0 or 1)
	reasonConfigError            = "config_error"             // setup/validation failed before the engine ran
	reasonEngineError            = "engine_error"             // engine subprocess failed without recording a verdict
	reasonInvalidReportExhausted = "invalid_report_exhausted" // engine ran but never recorded a valid verdict across retries
	reasonCancelled              = "cancelled"                // run was interrupted before a verdict
	reasonOutputWriteError       = "output_write_error"       // verdict obtained but writing the result failed
)

// errEngineExecution marks a failure of the engine subprocess itself (as
// opposed to the engine running but never recording a verdict). It lets run()
// distinguish engine_error from invalid_report_exhausted on the status line.
var errEngineExecution = errors.New("engine execution failed")

// emitStatus writes the single terminal status line to stderr.
func emitStatus(reason string, code int) {
	fmt.Fprintf(os.Stderr, "%s reason=%s exit=%d\n", statusPrefix, reason, code)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "report-result" {
		os.Exit(runReport(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "conclude" {
		os.Exit(runConclude(os.Args[2:]))
	}
	os.Exit(run())
}

func run() (code int) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// reason is set at each terminal point; the deferred emitter writes the
	// single status line. An empty reason (e.g. --version) emits nothing.
	reason := ""
	// logger, when non-nil, mirrors the run's key events (including the terminal
	// status) to a JSONL log file. It is nil until --log-file is resolved.
	var logger *runlog.Logger
	defer func() {
		if reason != "" {
			emitStatus(reason, code)
			logger.Info("status", map[string]any{"reason": reason, "exit": code})
		}
		if err := logger.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing log file: %v\n", err)
		}
	}()

	var (
		engineID   string
		model      string
		promptFile string
		outputJSON string
		logFile    string
		version    bool
		retries    int
	)

	// Parse flags with ContinueOnError so usage/flag errors return through the
	// deferred status emitter instead of calling os.Exit and bypassing it.
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)

	flag.StringVar(&engineID, "engine", "", "AI engine to use (copilot, claude, codex)")
	flag.StringVar(&model, "model", "", "Model to use for detection")
	flag.StringVar(&promptFile, "prompt-template", "", "Path to custom prompt template (defaults to built-in)")
	flag.StringVar(&outputJSON, "output", "", "Path to write JSON result (defaults to stdout)")
	flag.StringVar(&logFile, "log-file", os.Getenv("THREAT_DETECTION_LOG_FILE"), "Path to write JSONL run logs (env: THREAT_DETECTION_LOG_FILE)")
	flag.BoolVar(&version, "version", false, "Print version and exit")
	flag.IntVar(&retries, "retries", envInt("THREAT_DETECTION_RETRIES", 1), "Retries for malformed detection outputs (env: THREAT_DETECTION_RETRIES)")
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		// -h/-help prints usage and exits cleanly with no status line.
		if errors.Is(err, flag.ErrHelp) {
			return exitSafe
		}
		reason = reasonConfigError
		return exitError
	}

	if version {
		fmt.Printf("threat-detect %s\n", detector.Version)
		return exitSafe
	}

	// Reject a --log-file that collides with --output: they are opened and
	// truncated independently, so sharing an inode would interleave the JSONL
	// trace and the result JSON and corrupt both while still reporting success.
	if logFile != "" && outputJSON != "" {
		if same, err := samePath(logFile, outputJSON); err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving output paths: %v\n", err)
			reason = reasonConfigError
			return exitError
		} else if same {
			fmt.Fprintf(os.Stderr, "Error: --log-file and --output must not point to the same file (%q)\n", logFile)
			reason = reasonConfigError
			return exitError
		}
	}

	// Open the JSONL run log if requested. A failure here is a config error:
	// the caller explicitly asked for logs and should learn they were not written.
	if logFile != "" {
		l, err := runlog.Open(logFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
			reason = reasonConfigError
			return exitError
		}
		logger = l
	}
	logger.Info("run_start", map[string]any{
		"version": detector.Version,
		"engine":  engine.Canonical(engineID),
		"model":   model,
		"retries": retries,
	})

	// Determine artifacts directory from positional args
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: threat-detect [flags] <artifacts-dir>\n")
		flag.PrintDefaults()
		reason = reasonConfigError
		return exitError
	}
	artifactsDir := args[0]

	// Load artifacts
	arts, err := artifacts.Load(artifactsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading artifacts: %v\n", err)
		logger.Error("artifacts_load_failed", map[string]any{"artifacts_dir": artifactsDir, "error": err.Error()})
		reason = reasonConfigError
		return exitError
	}
	logger.Info("artifacts_loaded", map[string]any{"artifacts_dir": artifactsDir})

	// Build the prompt
	promptTemplate := ""
	if promptFile != "" {
		data, err := os.ReadFile(promptFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading prompt template: %v\n", err)
			reason = reasonConfigError
			return exitError
		}
		promptTemplate = string(data)
	}

	prompt, err := detector.BuildPrompt(arts, promptTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building prompt: %v\n", err)
		logger.Error("prompt_build_failed", map[string]any{"error": err.Error()})
		reason = reasonConfigError
		return exitError
	}
	logger.Info("prompt_built", map[string]any{"prompt_bytes": len(prompt)})

	// Create engine
	eng, err := engine.New(engineID, model)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
		logger.Error("engine_create_failed", map[string]any{"error": err.Error()})
		reason = reasonConfigError
		return exitError
	}

	// Provision an out-of-band result sink for the in-session reporting tool.
	sinkFile, err := os.CreateTemp("", "threat-detect-result-*.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating result sink: %v\n", err)
		reason = reasonConfigError
		return exitError
	}
	sinkPath := sinkFile.Name()
	sinkFile.Close()
	// Remove the empty placeholder so ReadResultFile only succeeds once the tool writes it.
	os.Remove(sinkPath)
	defer os.Remove(sinkPath)

	result, err := analyzeWithRetries(ctx, eng, prompt, sinkPath, retries, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running detection: %v\n", err)
		switch {
		case ctx.Err() != nil:
			reason = reasonCancelled
		case errors.Is(err, errEngineExecution):
			reason = reasonEngineError
		default:
			reason = reasonInvalidReportExhausted
		}
		logger.Error("detection_failed", map[string]any{"reason": reason, "error": err.Error()})
		return exitError
	}
	logger.Info("verdict", map[string]any{
		"prompt_injection": result.PromptInjection,
		"secret_leak":      result.SecretLeak,
		"malicious_patch":  result.MaliciousPatch,
		"reasons":          result.Reasons,
		"has_threats":      result.HasThreats(),
	})

	var resultReason string
	code, resultReason = writeResult(result, outputJSON)
	reason = resultReason
	return code
}

func analyzeWithRetries(ctx context.Context, eng engine.Engine, prompt, sinkPath string, retries int, logger *runlog.Logger) (*detector.Result, error) {
	if sinkPath == "" {
		return nil, fmt.Errorf("result sink path is required for detection")
	}
	attempts := retries + 1
	if attempts < 1 {
		attempts = 1
	}
	currentPrompt := prompt
	var lastErr error
	for i := 0; i < attempts; i++ {
		logger.Info("attempt_start", map[string]any{"attempt": i + 1, "attempts": attempts})
		// Remove any stale sink result before each attempt.
		os.Remove(sinkPath)
		if _, err := eng.Analyze(ctx, currentPrompt, engine.AnalyzeOptions{ResultSinkPath: sinkPath}); err != nil {
			return nil, fmt.Errorf("%w: %w", errEngineExecution, err)
		}
		// The verdict must be reported in-session through the
		// threat_detection_result tool, which records it to the sink.
		result, err := detector.ReadResultFile(sinkPath)
		if err == nil {
			logger.Info("attempt_recorded", map[string]any{"attempt": i + 1})
			return result, nil
		}
		lastErr = err
		logger.Info("attempt_no_verdict", map[string]any{"attempt": i + 1, "error": err.Error()})
		currentPrompt = detector.BuildCorrectionPrompt(prompt, detectionCorrectionPrefix, detectionCorrectionMessage, detectionCorrectionInstruction)
	}
	return nil, fmt.Errorf("detection model did not record a verdict via the threat_detection_result tool after %d attempt(s): %w", attempts, lastErr)
}

// writeResult marshals and writes the verdict, returning the exit code and the
// terminal reason for the status line. The result JSON is only ever produced on
// the success path; an output failure yields no JSON and reasonOutputWriteError.
func writeResult(result *detector.Result, outputJSON string) (int, string) {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling result: %v\n", err)
		return exitError, reasonOutputWriteError
	}

	if outputJSON != "" {
		if err := os.WriteFile(outputJSON, jsonBytes, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			return exitError, reasonOutputWriteError
		}
	} else {
		fmt.Println(string(jsonBytes))
	}

	// Exit code based on threat detection
	if result.HasThreats() {
		return exitThreat, reasonResultRecorded
	}
	return exitSafe, reasonResultRecorded
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

// samePath reports whether a and b refer to the same file. It first compares
// resolved absolute paths (handling "." segments and symlinked directories),
// then, when both files already exist, confirms with os.SameFile so hardlinks
// and other symlink equivalences are caught too.
func samePath(a, b string) (bool, error) {
	ra, err := resolvePath(a)
	if err != nil {
		return false, err
	}
	rb, err := resolvePath(b)
	if err != nil {
		return false, err
	}
	if ra == rb {
		return true, nil
	}
	ia, errA := os.Stat(a)
	ib, errB := os.Stat(b)
	if errA == nil && errB == nil {
		return os.SameFile(ia, ib), nil
	}
	return false, nil
}

// resolvePath returns an absolute, symlink-resolved path. When the target does
// not yet exist, it resolves the deepest existing ancestor directory and rejoins
// the remaining components so not-yet-created siblings still compare correctly.
func resolvePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	dir, base := filepath.Split(abs)
	dir = filepath.Clean(dir)
	if resolvedDir, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Join(resolvedDir, base), nil
	}
	return filepath.Clean(abs), nil
}
