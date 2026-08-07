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
	"strings"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
	"github.com/github/gh-aw-threat-detection/pkg/detector"
	"github.com/github/gh-aw-threat-detection/pkg/engine"
)

const (
	exitSafe   = 0
	exitThreat = 1
	exitError  = 2

	detectionCorrectionPrefix      = "Your previous response did not record a verdict"
	detectionCorrectionMessage     = "The threat_detection_result command was not run, or it reported an error and exited before a verdict was recorded."
	detectionCorrectionInstruction = "Run the threat_detection_result command exactly once with --prompt-injection, --secret-leak, and --malicious-patch each set to true or false, plus a --reason for every threat set to true."
	promptAnalysisValidationCode   = "ERR_VALIDATION"

	// maxInventoryEntries bounds the artifact inventory printed to stderr so a
	// pathological artifacts directory cannot flood the job log.
	maxInventoryEntries = 200
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

// detectionContinueOnError reports whether the host selected warn mode. It is
// the single interpretation of GH_AW_DETECTION_CONTINUE_ON_ERROR shared by the
// detection run and the conclude subcommand: anything other than "false" is
// warn mode, so an unset variable defaults to warning rather than failing. The
// comparison is case-insensitive to match gh-aw's detection setup, so a host
// that writes "False" or "FALSE" selects strict mode on both paths.
func detectionContinueOnError() bool {
	return !strings.EqualFold(os.Getenv("GH_AW_DETECTION_CONTINUE_ON_ERROR"), "false")
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
	defer func() {
		if reason != "" {
			emitStatus(reason, code)
		}
	}()

	var (
		engineID            string
		model               string
		promptFile          string
		outputJSON          string
		workflowName        string
		workflowDescription string
		customPrompt        string
		customPromptFile    string
		stepSummary         string
		version             bool
		retries             int
	)

	// Parse flags with ContinueOnError so usage/flag errors return through the
	// deferred status emitter instead of calling os.Exit and bypassing it.
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)

	flag.StringVar(&engineID, "engine", "", "AI engine to use (copilot, claude, codex)")
	flag.StringVar(&model, "model", "", "Model to use for detection")
	flag.StringVar(&promptFile, "prompt-template", "", "Path to custom prompt template (defaults to built-in)")
	flag.StringVar(&outputJSON, "output", "", "Path to write JSON result (defaults to stdout)")
	flag.StringVar(&workflowName, "workflow-name", "", "Workflow name for the prompt (overrides WORKFLOW_NAME)")
	flag.StringVar(&workflowDescription, "workflow-description", "", "Workflow description for the prompt (overrides WORKFLOW_DESCRIPTION)")
	flag.StringVar(&customPrompt, "custom-prompt", "", "Additional detection instructions appended to the prompt (overrides CUSTOM_PROMPT)")
	flag.StringVar(&customPromptFile, "custom-prompt-file", "", "Path to a file with additional detection instructions (takes precedence over --custom-prompt and CUSTOM_PROMPT)")
	// Accepted and ignored for backward compatibility: older gh-aw releases pass
	// --step-summary, but the detector no longer writes a step summary (TD-20c).
	// Rejecting the flag would abort detection in those hosts, so it is parsed
	// and dropped instead.
	flag.StringVar(&stepSummary, "step-summary", "", "Deprecated and ignored; the detector no longer writes a GitHub Actions step summary")
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

	stepSummaryProvided := false
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name == "step-summary" {
			stepSummaryProvided = true
		}
	})
	if stepSummaryProvided {
		fmt.Fprintf(os.Stderr, "[threat-detect] ignoring deprecated --step-summary %s: the detector no longer writes a step summary\n",
			sanitizeLogValue(stepSummary))
	}

	// When --model is not set, fall back to the engine-specific detection model
	// environment variable (GH_AW_MODEL_DETECTION_{COPILOT,CLAUDE,CODEX}) or the
	// engine CLI's native model env var (COPILOT_MODEL, ANTHROPIC_MODEL), so the
	// standalone detector honors the model gh-aw configured for detection.
	model = engine.ResolveModel(engineID, model)

	// Announce the resolved run configuration on stderr so the job log records
	// which detector build, engine, and model produced the verdict. The engine ID
	// is echoed before engine.New validates it, and Canonical only lowercases, so
	// an arbitrary --engine value reaches this line; it is sanitized alongside the
	// model and version so none can split the line or forge a workflow command.
	modelDesc := model
	if modelDesc == "" {
		modelDesc = "(none; using engine default)"
	}
	fmt.Fprintf(os.Stderr, "[threat-detect] run start: version=%s engine=%s model=%s retries=%d\n",
		sanitizeLogValue(detector.Version), sanitizeLogValue(engine.Canonical(engineID)),
		sanitizeLogValue(modelDesc), retries)

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
		reason = reasonConfigError
		return exitError
	}
	reportArtifacts(artifactsDir, arts)
	// Degraded inputs (missing/empty prompt or agent output, an expected but
	// absent patch, an unreadable comment-memory directory, ...) are surfaced
	// as GitHub Actions annotations so they are visible even when this binary
	// runs outside gh-aw's own "Prepare threat detection files" step. See
	// pkg/artifacts.Load. Messages embed a caller-controlled artifacts
	// directory path, so they must be escaped per the workflow-command rules
	// to prevent a path containing "%" or a newline from forging another
	// workflow command.
	//
	// Findings about a required detection input follow the host's
	// continue-on-error policy, mirroring gh-aw's detection setup: in warn mode
	// (the default) they are warnings and detection proceeds with whatever was
	// staged; in strict mode they are errors and the run stops as a
	// configuration error before the engine is invoked. Findings about other
	// artifacts stay advisory warnings in both modes.
	warnMode := detectionContinueOnError()
	for _, w := range arts.Warnings {
		command := "warning"
		if w.RequiredInput && !warnMode {
			command = "error"
		}
		fmt.Fprintf(os.Stderr, "::%s::%s\n", command, escapeWorkflowData(w.Message))
		// The annotation text alone does not say whether the finding concerns an
		// artifact the host was required to stage — in warn mode both kinds are
		// emitted as "::warning::". Record that classification alongside it so
		// TD-18c stays diagnosable from the job log.
		fmt.Fprintf(os.Stderr, "[threat-detect] artifact degraded: field=%s required_input=%t\n",
			sanitizeLogValue(w.Field), w.RequiredInput)
	}

	// All primary inputs missing simultaneously means detection would silently
	// analyze nothing and return a clean verdict — a fail-open failure mode in
	// a security control. Fail closed instead of proceeding.
	if arts.AllPrimaryInputsMissing {
		fmt.Fprintf(os.Stderr, "Error: prompt, agent output, and patch/bundle files are all missing or empty in %s; refusing to run detection on empty input.\n", artifactsDir)
		reason = reasonConfigError
		return exitError
	}

	if !warnMode && arts.HasRequiredInputWarnings() {
		fmt.Fprintf(os.Stderr, "Error: one or more required detection inputs in %s are missing or unusable and GH_AW_DETECTION_CONTINUE_ON_ERROR is \"false\"; refusing to run degraded detection.\n", artifactsDir)
		reason = reasonConfigError
		return exitError
	}

	// Resolve workflow-context overrides. Provenance is tracked from whether a
	// flag was explicitly provided (FlagSet.Visit) rather than from the value's
	// content, so an explicit flag wins even when empty and a value that merely
	// equals the built-in default text is not misreported as defaulted. This
	// gives gh-aw and local callers a plumbing-independent way to inject workflow
	// context so it cannot be silently dropped by an env-passthrough filter.
	providedFlags := map[string]bool{}
	flag.CommandLine.Visit(func(f *flag.Flag) { providedFlags[f.Name] = true })

	// A value is "defaulted" only when neither the flag nor its environment
	// variable supplied it; equality with the fallback text is not sufficient.
	nameDefaulted := !providedFlags["workflow-name"] && os.Getenv("WORKFLOW_NAME") == ""
	descriptionDefaulted := !providedFlags["workflow-description"] && os.Getenv("WORKFLOW_DESCRIPTION") == ""
	if providedFlags["workflow-name"] {
		arts.WorkflowName = workflowName
	}
	if providedFlags["workflow-description"] {
		arts.WorkflowDescription = workflowDescription
	}

	// Custom prompt precedence: --custom-prompt-file, then --custom-prompt, then
	// the CUSTOM_PROMPT environment variable already loaded into arts. Presence is
	// determined by explicit flag provision, so an explicit empty flag clears an
	// env-supplied prompt (flags win).
	customPromptSource := "none"
	if arts.CustomPrompt != "" {
		customPromptSource = "env"
	}
	if providedFlags["custom-prompt"] {
		arts.CustomPrompt = customPrompt
		customPromptSource = "flag"
	}
	if providedFlags["custom-prompt-file"] {
		data, err := os.ReadFile(customPromptFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading custom prompt file: %v\n", err)
			reason = reasonConfigError
			return exitError
		}
		arts.CustomPrompt = string(data)
		customPromptSource = "file"
	}

	// Surface the resolved workflow context on stderr so a dropped CUSTOM_PROMPT
	// or missing workflow name/description is diagnosable from the job log alone,
	// not silently absorbed into the prompt.
	fmt.Fprintf(os.Stderr,
		"Prompt context: workflow_name=%q (defaulted=%t) workflow_description=%q (defaulted=%t) custom_prompt_applied=%t custom_prompt_source=%s custom_prompt_bytes=%d\n",
		arts.WorkflowName, nameDefaulted, arts.WorkflowDescription, descriptionDefaulted,
		arts.CustomPrompt != "", customPromptSource, len(arts.CustomPrompt))

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

	prompt, promptAnalysis, err := detector.BuildPromptWithAnalysis(arts, promptTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building prompt: %v\n", err)
		reason = reasonConfigError
		return exitError
	}
	warnDegradedPromptAnalysis(promptAnalysis)

	// The rendered prompt itself is never echoed; only its metadata, so a
	// truncated or scaffolding-free prompt is diagnosable from the job log.
	scaffoldingDesc := "(none)"
	if markers := scaffoldingMarkers(promptAnalysis); len(markers) > 0 {
		scaffoldingDesc = sanitizeLogValue(strings.Join(markers, ", "))
	}
	fmt.Fprintf(os.Stderr,
		"[threat-detect] prompt built: prompt_bytes=%d framework_scaffolding_detected=%t framework_scaffolding_markers=%s\n",
		len(prompt),
		promptAnalysis != nil && promptAnalysis.Scaffolding != nil && promptAnalysis.Scaffolding.Detected,
		scaffoldingDesc)

	// Create engine
	eng, err := engine.New(engineID, model)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
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

	result, err := analyzeWithRetries(ctx, eng, prompt, sinkPath, retries)
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
		return exitError
	}

	var resultReason string
	code, resultReason = writeResult(result, outputJSON)
	reason = resultReason
	return code
}

// reportArtifacts prints the loaded-artifact summary and the recursive inventory
// (per TD-17b) to stderr, so the job log alone shows exactly what detection
// consumed. Inventory paths originate from the caller-controlled artifacts
// directory, so each is sanitized and confined to one physical line; the listing
// is bounded so a pathological directory cannot flood the job log.
func reportArtifacts(artifactsDir string, arts *artifacts.Artifacts) {
	fmt.Fprintf(os.Stderr,
		"[threat-detect] artifacts loaded: dir=%s prompt_bytes=%d agent_output_bytes=%d patch_files=%d all_primary_inputs_missing=%t\n",
		sanitizeLogValue(artifactsDir), arts.PromptFileSize, arts.AgentOutputFileSize,
		len(arts.PatchFiles), arts.AllPrimaryInputsMissing)

	if len(arts.Inventory) == 0 {
		fmt.Fprintf(os.Stderr, "[threat-detect] artifact inventory: (empty)\n")
		return
	}
	shown := arts.Inventory
	if len(shown) > maxInventoryEntries {
		shown = shown[:maxInventoryEntries]
	}
	fmt.Fprintf(os.Stderr, "[threat-detect] artifact inventory (%d entries):\n", len(arts.Inventory))
	for _, entry := range shown {
		fmt.Fprintf(os.Stderr, "[threat-detect]   %s bytes=%d kind=%s consumed=%t\n",
			sanitizeLogValue(entry.Path), entry.Size, sanitizeLogValue(entry.Kind), entry.Consumed)
	}
	if len(shown) < len(arts.Inventory) {
		fmt.Fprintf(os.Stderr, "[threat-detect]   ... %d more entry(ies) omitted\n", len(arts.Inventory)-len(shown))
	}
}

// scaffoldingMarkers returns the framework markers found in the detected
// `<system>` preamble, for run-log observability.
func scaffoldingMarkers(analysis *detector.PromptAnalysis) []string {
	if analysis == nil || analysis.Scaffolding == nil {
		return nil
	}
	return analysis.Scaffolding.Markers
}

func warnDegradedPromptAnalysis(analysis *detector.PromptAnalysis) {
	var unavailable []string
	if analysis == nil || analysis.PromptTemplate == "" {
		unavailable = append(unavailable, "aw-prompts/prompt-template.txt")
	}
	if analysis == nil || analysis.ImportTree == "" {
		unavailable = append(unavailable, "aw-prompts/prompt-import-tree.json")
	}
	if len(unavailable) == 0 {
		return
	}

	fmt.Fprintf(
		os.Stderr,
		"::warning::%s: Missing or unusable prompt analysis artifacts: %s. Trusted-vs-untrusted prompt analysis is degraded; ensure the host stages both non-empty files.\n",
		promptAnalysisValidationCode,
		strings.Join(unavailable, ", "),
	)
}

func analyzeWithRetries(ctx context.Context, eng engine.Engine, prompt, sinkPath string, retries int) (*detector.Result, error) {
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
		fmt.Fprintf(os.Stderr, "[threat-detect] detection attempt %d of %d\n", i+1, attempts)
		// Remove any stale sink result before each attempt.
		os.Remove(sinkPath)
		if _, err := eng.Analyze(ctx, currentPrompt, engine.AnalyzeOptions{ResultSinkPath: sinkPath}); err != nil {
			return nil, fmt.Errorf("%w: %w", errEngineExecution, err)
		}
		// The verdict must be reported in-session through the
		// threat_detection_result tool, which records it to the sink.
		result, err := detector.ReadResultFile(sinkPath)
		if err == nil {
			fmt.Fprintf(os.Stderr, "[threat-detect] attempt %d recorded a verdict via the threat_detection_result tool\n", i+1)
			return result, nil
		}
		lastErr = err
		fmt.Fprintf(os.Stderr, "[threat-detect] attempt %d recorded no usable verdict: %s\n", i+1, sanitizeLogValue(err.Error()))
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

// resolvePath returns an absolute, symlink-resolved path. Components are
// processed in filesystem order so ".." after a symlink applies to the symlink
// target, matching how the operating system resolves the path.
func resolvePath(p string) (string, error) {
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		p = wd + string(os.PathSeparator) + p
	}
	volume := filepath.VolumeName(p)
	resolved := volume + string(os.PathSeparator)
	pending := splitPathComponents(strings.TrimPrefix(p, volume))
	symlinks := 0

	for len(pending) > 0 {
		component := pending[0]
		pending = pending[1:]
		switch component {
		case ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}

		candidate := filepath.Join(resolved, component)
		if info, err := os.Lstat(candidate); err == nil && info.Mode()&os.ModeSymlink != 0 {
			symlinks++
			if symlinks > 255 {
				return "", fmt.Errorf("resolving %q: too many symlinks", p)
			}
			target, err := os.Readlink(candidate)
			if err != nil {
				return "", fmt.Errorf("reading symlink %q: %w", candidate, err)
			}
			if filepath.IsAbs(target) {
				volume = filepath.VolumeName(target)
				resolved = volume + string(os.PathSeparator)
				target = strings.TrimPrefix(target, volume)
			}
			pending = append(splitPathComponents(target), pending...)
			continue
		}
		resolved = candidate
	}
	return filepath.Clean(resolved), nil
}

func splitPathComponents(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool {
		return r <= 255 && os.IsPathSeparator(uint8(r))
	})
}
