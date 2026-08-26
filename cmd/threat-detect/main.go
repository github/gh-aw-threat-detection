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
	"time"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
	"github.com/github/gh-aw-threat-detection/pkg/detector"
	"github.com/github/gh-aw-threat-detection/pkg/engine"
)

const (
	exitSafe   = 0
	exitThreat = 1
	exitError  = 2

	detectionCorrectionPrefix        = "Your previous response did not record a verdict"
	detectionCorrectionMessage       = "The threat_detection_result command was not run, or it reported an error and exited before a verdict was recorded."
	detectionCorrectionInstruction   = "Run the threat_detection_result command exactly once with --prompt-injection, --secret-leak, and --malicious-patch each set to true or false. When any of them is true, use your file-writing tool to write your reasons as a JSON array of strings to the path in $THREAT_DETECTION_REASONS_FILE and pass it with --reasons-file; do not paste quoted artifact content onto the command line."
	eligibilityCorrectionPrefix      = "Your previous verdict was rejected as structurally ineligible"
	eligibilityCorrectionInstruction = "A threat category can only be reported true when the artifacts contain the input that category is defined against. Re-analyze the artifacts and run threat_detection_result again with the ineligible category set to false, keeping any category you can still support with evidence from the artifacts listed above."
	promptAnalysisValidationCode     = "ERR_VALIDATION"

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
	reasonEngineTimeout          = "engine_timeout"           // per-attempt wall-clock timeout expired without a verdict
	reasonInvalidReportExhausted = "invalid_report_exhausted" // engine ran but never recorded a valid verdict across retries
	reasonCancelled              = "cancelled"                // run was interrupted before a verdict
	reasonOutputWriteError       = "output_write_error"       // verdict obtained but writing the result failed
)

// Default budgets bounding a single detection attempt. Both are conservative
// enough to catch a runaway model while leaving comfortable headroom under the
// smoke workflows' 15-minute job timeout with retries=0 (1 attempt).
const (
	// defaultEngineTimeout bounds a single engine invocation. A single 5m
	// attempt plus artifact prep and upload fits comfortably inside the
	// 15-minute smoke job budget. Zero (via --engine-timeout=0) disables the
	// wall-clock cap.
	defaultEngineTimeout = 5 * time.Minute
	// defaultMaxTurns bounds the number of agentic tool-use turns per attempt.
	// The turn cap's real job is catching tool-loop pathology (e.g. the model
	// gets stuck calling Read in a loop); the wall-clock is the primary
	// credit kill switch. A verdict-only run typically needs ~5-15 turns, but
	// legitimate wide exploration (e.g. a patch touching many files) can burn
	// 20+ just on Reads, so 50 gives comfortable headroom while still
	// bounding a truly runaway loop. Zero disables the cap.
	defaultMaxTurns = 50
)

// errEngineExecution marks a failure of the engine subprocess itself (as
// opposed to the engine running but never recording a verdict). It lets run()
// distinguish engine_error from invalid_report_exhausted on the status line.
var errEngineExecution = errors.New("engine execution failed")

// errEngineTimeout marks a per-attempt wall-clock timeout expiring before the
// engine recorded a verdict. Timeouts are terminal — analyzeWithRetries never
// retries a runaway — so this propagates straight through to the terminal
// reason reasonEngineTimeout, which `conclude` maps into the gh-aw
// `agent_failure` category for daily statistics.
var errEngineTimeout = errors.New("engine timeout")

// stderrf writes one diagnostic line to standard error.
//
// Every detector diagnostic goes through here so that sanitization is a
// property of the output path rather than of each call site. The lines
// interpolate untrusted and host-supplied values — artifact filenames and
// inventory paths, the artifacts directory, engine and model identifiers,
// result paths, and error text that quotes any of them — and a future call site
// must not be able to reintroduce a log-injection gap by forgetting to escape
// its own arguments. The message is rendered as exactly one physical line, so
// callers pass no trailing newline. Sanitizing is idempotent, so a caller that
// additionally bounds a value may still escape it itself.
func stderrf(format string, args ...any) {
	fmt.Fprintln(os.Stderr, sanitizeLogValue(fmt.Sprintf(format, args...)))
}

// emitStatus writes the single terminal status line to stderr.
func emitStatus(reason string, code int) {
	stderrf("%s reason=%s exit=%d", statusPrefix, reason, code)
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
		fullOutputJSON      string
		workflowName        string
		workflowDescription string
		customPrompt        string
		customPromptFile    string
		stepSummary         string
		version             bool
		retries             int
		maxTurns            int
		engineTimeout       time.Duration
	)

	// Parse flags with ContinueOnError so usage/flag errors return through the
	// deferred status emitter instead of calling os.Exit and bypassing it.
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)

	flag.StringVar(&engineID, "engine", "", "AI engine to use (copilot, claude, codex)")
	flag.StringVar(&model, "model", "", "Model to use for detection")
	flag.StringVar(&promptFile, "prompt-template", "", "Path to custom prompt template (defaults to built-in)")
	flag.StringVar(&outputJSON, "output", "", "Path to write the JSON result (defaults to stdout). Reasons are always empty in this file; see --full-output")
	flag.StringVar(&fullOutputJSON, "full-output", "", "Path to write the JSON result including reasons (defaults to the --output path with \"_full\" inserted before the extension; empty disables it). Hosts MUST NOT upload this file")
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
	flag.IntVar(&retries, "retries", envInt("THREAT_DETECTION_RETRIES", 0),
		"Retries after a failed detection attempt, including one rejected on structural eligibility. Default 0 because a from-scratch retry rarely fixes anything (the engine CLIs already retry transient provider errors internally, and the in-session iteration on the threat_detection_result tool wrapper already handles bad tool calls, including ineligible ones, without restarting). --engine-timeout is always terminal regardless of this value (env: THREAT_DETECTION_RETRIES)")
	flag.IntVar(&maxTurns, "max-turns", envMaxTurns(defaultMaxTurns),
		"Maximum agentic tool-use turns per attempt; 0 disables the cap. Exported to the engine subprocess as GH_AW_MAX_TURNS and passed as --max-turns to engines whose CLI accepts it (env: THREAT_DETECTION_MAX_TURNS, GH_AW_MAX_TURNS)")
	flag.DurationVar(&engineTimeout, "engine-timeout", envDuration("THREAT_DETECTION_ENGINE_TIMEOUT", defaultEngineTimeout),
		"Wall-clock timeout per detection attempt (e.g. 5m, 300s); 0 disables. On expiry the engine subprocess (and its harness descendants) are killed; the run exits 2 with reason engine_timeout without retrying, because a runaway model is overwhelmingly likely to run away again (env: THREAT_DETECTION_ENGINE_TIMEOUT)")
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

	// Reject negative bounds: the documented contract is that only 0 disables a
	// cap, and a negative value silently bypassing the kill switch would defeat
	// the whole point of adding one. Env-variable parsing already rejects
	// negatives (and falls back to the default); this closes the same gap for
	// the flags.
	if retries < 0 {
		stderrf("Error: --retries must be >= 0 (got %d)", retries)
		reason = reasonConfigError
		return exitError
	}
	if maxTurns < 0 {
		stderrf("Error: --max-turns must be >= 0 (got %d); use 0 to disable the cap", maxTurns)
		reason = reasonConfigError
		return exitError
	}
	if engineTimeout < 0 {
		stderrf("Error: --engine-timeout must be >= 0 (got %s); use 0 to disable the cap", engineTimeout)
		reason = reasonConfigError
		return exitError
	}

	stepSummaryProvided := false
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name == "step-summary" {
			stepSummaryProvided = true
		}
	})
	if stepSummaryProvided {
		stderrf("[threat-detect] ignoring deprecated --step-summary %s: the detector no longer writes a step summary",
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
	stderrf("[threat-detect] run start: version=%s engine=%s model=%s retries=%d max_turns=%d engine_timeout=%s",
		sanitizeLogValue(detector.Version), sanitizeLogValue(engine.Canonical(engineID)),
		sanitizeLogValue(modelDesc), retries, maxTurns, formatTimeout(engineTimeout))

	// Determine artifacts directory from positional args
	args := flag.Args()
	if len(args) < 1 {
		stderrf("Usage: threat-detect [flags] <artifacts-dir>")
		flag.PrintDefaults()
		reason = reasonConfigError
		return exitError
	}
	artifactsDir := args[0]

	// Load artifacts
	arts, err := artifacts.Load(artifactsDir)
	if err != nil {
		stderrf("Error loading artifacts: %v", err)
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
		reportArtifactWarning(w, warnMode)
	}

	// All primary inputs missing simultaneously means detection would silently
	// analyze nothing and return a clean verdict — a fail-open failure mode in
	// a security control. Fail closed instead of proceeding.
	if arts.AllPrimaryInputsMissing {
		stderrf("Error: prompt, agent output, and patch/bundle files are all missing or empty in %s; refusing to run detection on empty input.", artifactsDir)
		reason = reasonConfigError
		return exitError
	}

	if !warnMode && arts.HasRequiredInputWarnings() {
		stderrf("Error: one or more required detection inputs in %s are missing or unusable and GH_AW_DETECTION_CONTINUE_ON_ERROR is \"false\"; refusing to run degraded detection.", artifactsDir)
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

	// Resolve the companion full-result path. An explicit --full-output always
	// wins (including an explicit empty value, which disables the sidecar);
	// otherwise it is derived from --output by convention so a host that only
	// knows about --output still gets the reasons on disk without any change.
	// With no --output at all there is no path to derive from, so the sidecar
	// exists in stdout mode only when --full-output names one explicitly — the
	// escape hatch for placing it where no upload glob can reach.
	if !providedFlags["full-output"] {
		fullOutputJSON = detector.FullResultPath(outputJSON)
	}
	// The whole point of the split is that the two files have different
	// exposure: --output is uploaded, --full-output is not. If they resolve to
	// the same file, writing the full result would leak reasons into the
	// uploaded artifact, so refuse rather than silently pick one.
	if outputJSON != "" && fullOutputJSON != "" {
		same, err := samePath(outputJSON, fullOutputJSON)
		if err != nil {
			stderrf("Error resolving result paths: %v", err)
			reason = reasonConfigError
			return exitError
		}
		if same {
			stderrf("Error: --full-output %s resolves to the same file as --output; the full result must be written to a separate path that the host does not upload.",
				fullOutputJSON)
			reason = reasonConfigError
			return exitError
		}
	}
	stderrf("[threat-detect] result destinations: output=%s full_output=%s",
		describeResultPath(outputJSON, "(stdout)"),
		describeResultPath(fullOutputJSON, "(disabled)"))

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
			stderrf("Error reading custom prompt file: %v", err)
			reason = reasonConfigError
			return exitError
		}
		arts.CustomPrompt = string(data)
		customPromptSource = "file"
	}

	// Surface the resolved workflow context on stderr so a dropped CUSTOM_PROMPT
	// or missing workflow name/description is diagnosable from the job log alone,
	// not silently absorbed into the prompt.
	//
	// The workflow name and description originate outside the detector, so they
	// are quoted for readability here and rendered inert by stderrf.
	stderrf(
		"Prompt context: workflow_name=%q (defaulted=%t) workflow_description=%q (defaulted=%t) custom_prompt_applied=%t custom_prompt_source=%s custom_prompt_bytes=%d",
		arts.WorkflowName, nameDefaulted, arts.WorkflowDescription, descriptionDefaulted,
		arts.CustomPrompt != "", customPromptSource, len(arts.CustomPrompt))

	// Build the prompt
	promptTemplate := ""
	if promptFile != "" {
		data, err := os.ReadFile(promptFile)
		if err != nil {
			stderrf("Error reading prompt template: %v", err)
			reason = reasonConfigError
			return exitError
		}
		promptTemplate = string(data)
	}

	prompt, promptAnalysis, err := detector.BuildPromptWithAnalysis(arts, detector.PromptBudget{
		EngineTimeout: engineTimeout,
		MaxTurns:      maxTurns,
	}, promptTemplate)
	if err != nil {
		stderrf("Error building prompt: %v", err)
		reason = reasonConfigError
		return exitError
	}
	// Prompt-analysis inputs are read after artifacts.Load has validated them,
	// so a read can still fail here (a file replaced or truncated mid-run, an
	// I/O error) on a bundle that loaded cleanly. Those findings are recorded
	// on the Artifacts value alongside the load-time ones so every
	// degraded-inspection condition reaches the same reporting path (TD-10h),
	// and re-gated on the host's continue-on-error policy — the engine has not
	// been invoked yet, so strict mode can still refuse degraded detection.
	analysisWarnings := promptAnalysisWarnings(promptAnalysis, arts)
	arts.Warnings = append(arts.Warnings, analysisWarnings...)
	requiredDegraded := false
	for _, w := range analysisWarnings {
		reportArtifactWarning(w, warnMode)
		requiredDegraded = requiredDegraded || w.RequiredInput
	}
	if !warnMode && requiredDegraded {
		stderrf("Error: one or more required detection inputs in %s are missing or unusable and GH_AW_DETECTION_CONTINUE_ON_ERROR is \"false\"; refusing to run degraded detection.", artifactsDir)
		reason = reasonConfigError
		return exitError
	}

	// The rendered prompt itself is never echoed; only its metadata, so a
	// truncated or scaffolding-free prompt is diagnosable from the job log.
	scaffoldingDesc := "(none)"
	if markers := scaffoldingMarkers(promptAnalysis); len(markers) > 0 {
		scaffoldingDesc = sanitizeLogValue(strings.Join(markers, ", "))
	}
	stderrf(
		"[threat-detect] prompt built: prompt_bytes=%d framework_scaffolding_detected=%t framework_scaffolding_host_removed=%t framework_scaffolding_markers=%s",
		len(prompt),
		promptAnalysis != nil && promptAnalysis.Scaffolding != nil && promptAnalysis.Scaffolding.Detected,
		promptAnalysis != nil && promptAnalysis.Scaffolding != nil && promptAnalysis.Scaffolding.HostRemoved,
		scaffoldingDesc)

	// Create engine
	eng, err := engine.New(engineID, model)
	if err != nil {
		stderrf("Error creating engine: %v", err)
		reason = reasonConfigError
		return exitError
	}

	// Provision an out-of-band result sink for the in-session reporting tool.
	sinkFile, err := os.CreateTemp("", "threat-detect-result-*.json")
	if err != nil {
		stderrf("Error creating result sink: %v", err)
		reason = reasonConfigError
		return exitError
	}
	sinkPath := sinkFile.Name()
	sinkFile.Close()
	// Remove the empty placeholder so ReadResultFile only succeeds once the tool writes it.
	os.Remove(sinkPath)
	defer os.Remove(sinkPath)

	result, err := analyzeWithRetries(ctx, eng, prompt, sinkPath, retries, maxTurns, engineTimeout, promptAnalysis, arts)
	if err != nil {
		// The message can embed captured engine output (engineExitError), which
		// is untrusted; stderrf renders it inert.
		stderrf("Error running detection: %v", err)
		switch {
		case ctx.Err() != nil:
			reason = reasonCancelled
		case errors.Is(err, errEngineTimeout):
			reason = reasonEngineTimeout
		case errors.Is(err, errEngineExecution):
			reason = reasonEngineError
		default:
			reason = reasonInvalidReportExhausted
		}
		return exitError
	}

	var resultReason string
	code, resultReason = writeResult(result, outputJSON, fullOutputJSON)
	reason = resultReason
	return code
}

// describeResultPath renders a result destination for the run log, substituting
// a human-readable placeholder when no path is configured.
func describeResultPath(path, placeholder string) string {
	if path == "" {
		return placeholder
	}
	return path
}

// reportArtifacts prints the loaded-artifact summary and the recursive inventory
// (per TD-17b) to stderr, so the job log alone shows exactly what detection
// consumed. Inventory paths originate from the caller-controlled artifacts
// directory, so each is sanitized and confined to one physical line; the listing
// is bounded so a pathological directory cannot flood the job log.
func reportArtifacts(artifactsDir string, arts *artifacts.Artifacts) {
	stderrf(
		"[threat-detect] artifacts loaded: dir=%s prompt_bytes=%d agent_output_bytes=%d patch_files=%d all_primary_inputs_missing=%t",
		sanitizeLogValue(artifactsDir), arts.PromptFileSize, arts.AgentOutputFileSize,
		len(arts.PatchFiles), arts.AllPrimaryInputsMissing)

	if len(arts.Inventory) == 0 {
		stderrf("[threat-detect] artifact inventory: (empty)")
		return
	}
	shown := arts.Inventory
	if len(shown) > maxInventoryEntries {
		shown = shown[:maxInventoryEntries]
	}
	stderrf("[threat-detect] artifact inventory (%d entries):", len(arts.Inventory))
	for _, entry := range shown {
		stderrf("[threat-detect]   %s bytes=%d kind=%s consumed=%t",
			sanitizeLogValue(entry.Path), entry.Size, sanitizeLogValue(entry.Kind), entry.Consumed)
	}
	if len(shown) < len(arts.Inventory) {
		stderrf("[threat-detect]   ... %d more entry(ies) omitted", len(arts.Inventory)-len(shown))
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

// reportArtifactWarning emits one degraded-input finding as a GitHub Actions
// annotation plus a structured run-log line.
//
// Findings about a required detection input follow the host's continue-on-error
// policy: in warn mode (the default) they are warnings, in strict mode they are
// errors. Findings about other artifacts stay advisory in both modes. The
// annotation text alone does not say which kind it is — in warn mode both are
// emitted as "::warning::" — so the classification is logged alongside it and
// TD-18c stays diagnosable from the job log.
//
// Messages can embed caller-controlled paths and OS error text, so they are
// escaped per the workflow-command rules to prevent a path containing "%" or a
// newline from forging another workflow command.
func reportArtifactWarning(w artifacts.ArtifactWarning, warnMode bool) {
	command := "warning"
	if w.RequiredInput && !warnMode {
		command = "error"
	}
	stderrf("::%s::%s", command, escapeWorkflowData(w.Message))
	stderrf("[threat-detect] artifact degraded: field=%s required_input=%t",
		sanitizeLogValue(w.Field), w.RequiredInput)
}

// promptAnalysisWarnings converts the analysis input outcomes into reportable
// degraded-inspection findings.
//
// Unreadable and absent are reported separately. They degrade the analysis the
// same way but are different failures: an absent file was never staged, while an
// unreadable one holds content the detector did not look at. Only the latter
// means the run inspected less than the bundle contains, and only the rendered
// prompt is a required input — the template and the import tree are optional
// analysis aids, so promoting their findings would make strict mode refuse runs
// of hosts that legitimately never stage them (TD-18c).
//
// Findings already recorded by artifacts.Load are not repeated: a prompt that
// was missing or zero-length at load time is reported there, and re-reporting it
// here would double-count the same condition.
func promptAnalysisWarnings(analysis *detector.PromptAnalysis, arts *artifacts.Artifacts) []artifacts.ArtifactWarning {
	var warnings []artifacts.ArtifactWarning

	for _, in := range analysis.UnreadableInputs() {
		warnings = append(warnings, artifacts.NewWarning(in.Field, fmt.Sprintf(
			"%s: Prompt analysis input %s (%s) could not be read: %v. That content exists but was not inspected; the trusted-vs-untrusted prompt analysis is degraded.",
			promptAnalysisValidationCode, promptAnalysisLabels[in.Field], in.Path, in.Err)))
	}

	// The rendered prompt can also turn up empty here on a bundle that loaded
	// cleanly — it passed Load's size check and was blanked or truncated before
	// the analysis read it. Load saw content, so nobody else reports this.
	if analysis.Input(detector.PromptInputFieldPrompt).Status == detector.PromptInputAbsent &&
		!arts.HasWarningForField(detector.PromptInputFieldPrompt) {
		warnings = append(warnings, artifacts.NewWarning(detector.PromptInputFieldPrompt, fmt.Sprintf(
			"%s: Detection context prompt at %s was empty when the prompt analysis read it, though it was present and non-empty when the artifacts were loaded. The prompt channel was not analyzed.",
			promptAnalysisValidationCode, promptAnalysisLabels[detector.PromptInputFieldPrompt])))
	}

	// Absent aids are reported per file so each finding names the artifact it
	// concerns, matching the field classification the reporting path logs.
	for _, field := range []string{detector.PromptInputFieldTemplate, detector.PromptInputFieldImportTree} {
		switch analysis.Input(field).Status {
		case detector.PromptInputOK, detector.PromptInputUnreadable:
			// Read, or already reported above as unreadable.
		default:
			warnings = append(warnings, artifacts.NewWarning(field, fmt.Sprintf(
				"%s: Missing or empty prompt analysis artifact: %s. Trusted-vs-untrusted prompt analysis is degraded; ensure the host stages it non-empty.",
				promptAnalysisValidationCode, promptAnalysisLabels[field])))
		}
	}

	return warnings
}

// promptAnalysisLabels maps analysis input fields to the artifact paths hosts
// stage them at, so a finding names the file the host has to fix.
var promptAnalysisLabels = map[string]string{
	detector.PromptInputFieldPrompt:     "aw-prompts/prompt.txt",
	detector.PromptInputFieldTemplate:   "aw-prompts/prompt-template.txt",
	detector.PromptInputFieldImportTree: "aw-prompts/prompt-import-tree.json",
}

func analyzeWithRetries(ctx context.Context, eng engine.Engine, prompt, sinkPath string, retries, maxTurns int, engineTimeout time.Duration, analysis *detector.PromptAnalysis, arts *artifacts.Artifacts) (*detector.Result, error) {
	if sinkPath == "" {
		return nil, fmt.Errorf("result sink path is required for detection")
	}
	eligibility := detector.ComputeEligibility(arts, analysis)
	stderrf("[threat-detect] eligibility: prompt_injection=%t secret_leak=%t malicious_patch=%t",
		eligibility.PromptInjection, eligibility.SecretLeak, eligibility.MaliciousPatch)
	attempts := retries + 1
	if attempts < 1 {
		attempts = 1
	}
	currentPrompt := prompt
	var lastErr error
	for i := 0; i < attempts; i++ {
		stderrf("[threat-detect] detection attempt %d of %d", i+1, attempts)
		// Remove any stale sink result before each attempt.
		os.Remove(sinkPath)

		// Apply the per-attempt wall-clock timeout. The parent ctx still carries
		// interrupt cancellation (Ctrl+C, SIGTERM), so this narrows rather than
		// replaces the deadline for each engine invocation. A completed verdict
		// races the deadline: if the engine records a result and the sink
		// watcher cancels the process before the timeout fires, the read below
		// still succeeds and the run reports result_recorded.
		attemptCtx := ctx
		var attemptCancel context.CancelFunc = func() {}
		if engineTimeout > 0 {
			attemptCtx, attemptCancel = context.WithTimeout(ctx, engineTimeout)
		}

		opts := engine.AnalyzeOptions{
			ResultSinkPath: sinkPath,
			MaxTurns:       maxTurns,
			Eligibility:    &eligibility,
		}
		_, execErr := eng.Analyze(attemptCtx, currentPrompt, opts)

		// The verdict might still have been written just before the deadline
		// fired; check the sink first, regardless of the engine's exit path.
		result, readErr := detector.ReadResultFile(sinkPath)
		attemptCancel()

		// Re-check any recorded verdict against the eligibility this process
		// computed from the artifacts. The identical check in the report-result
		// subprocess reads its inputs from an environment carried on a command
		// line the model composes, so the model can override or omit it; this
		// check reads artifacts the model never touched, and is therefore the
		// binding one. An ineligible verdict is treated exactly like a
		// malformed one: discarded, fed back as a correction, and retried. No
		// verdict is ever rewritten here — the sink remains the sole source of
		// a recorded result.
		ineligible := ""
		if readErr == nil {
			if ineligible = eligibility.ValidateResult(result); ineligible == "" {
				stderrf("[threat-detect] attempt %d outcome=recorded", i+1)
				return result, nil
			}
			stderrf("[threat-detect] attempt %d outcome=ineligible; discarding: %s", i+1, sanitizeLogValue(ineligible))
		}

		if execErr != nil {
			// Distinguish a per-attempt timeout from other engine failures so
			// the terminal status reason can name it separately. The parent
			// ctx is checked first: if the user cancelled the whole run, that
			// takes precedence over any per-attempt deadline.
			if ctx.Err() == nil && attemptCtx.Err() == context.DeadlineExceeded {
				stderrf("[threat-detect] attempt %d outcome=timeout duration=%s (no retry; runaway models are overwhelmingly likely to run away again)",
					i+1, formatTimeout(engineTimeout))
				return nil, fmt.Errorf("%w: detection engine did not record a verdict within %s",
					errEngineTimeout, formatTimeout(engineTimeout))
			}
			stderrf("[threat-detect] attempt %d outcome=engine_error err=%v", i+1, execErr)
			return nil, fmt.Errorf("%w: %w", errEngineExecution, execErr)
		}

		// Reached only when the engine exited cleanly, so a timeout or engine
		// failure that also happened to leave an ineligible verdict behind has
		// already returned terminally above.
		if ineligible != "" {
			lastErr = fmt.Errorf("recorded verdict is not structurally eligible: %s", ineligible)
			currentPrompt = detector.BuildTrustedCorrectionPrompt(prompt, eligibilityCorrectionPrefix, ineligible, eligibilityCorrectionInstruction)
			continue
		}

		lastErr = readErr
		stderrf("[threat-detect] attempt %d outcome=no_verdict err=%v", i+1, readErr)
		currentPrompt = detector.BuildCorrectionPrompt(prompt, detectionCorrectionPrefix, detectionCorrectionMessage, detectionCorrectionInstruction)
	}
	return nil, fmt.Errorf("detection model did not record a usable verdict via the threat_detection_result tool after %d attempt(s): %w", attempts, lastErr)
}

// writeResult writes the verdict to its two destinations and returns the exit
// code and the terminal reason for the status line.
//
// The result reachable by the host's artifact upload (--output, or stdout) is
// always redacted: it carries the three booleans with an empty `reasons` array.
// The model-authored reasons go only to fullOutput, which stays on the runner.
//
// No diagnostic composed here echoes the reasons, because hosts tee stdout and
// stderr into files they publish. That guarantee covers detector-authored output
// only: forwarded engine output (TD-20a) reproduces the reason text wherever the
// engine renders the threat_detection_result invocation the model made. Framing
// makes those lines identifiable and inert, but does not remove the text, so a
// captured stderr file must be treated as carrying model-authored text and must
// not be published.
//
// A failure to write the full result is non-fatal: it is diagnostic-only, and a
// read-only or missing detection directory must not turn a completed detection
// into an infrastructure error. A failure to write the authoritative redacted
// result is fatal, and yields no JSON at all.
func writeResult(result *detector.Result, outputJSON, fullOutputJSON string) (int, string) {
	if fullOutputJSON != "" {
		if err := detector.WriteResultFile(fullOutputJSON, result); err != nil {
			stderrf("::warning::Could not write the full detection result to %s: %v. The verdict is unaffected; reasons will not be available to the conclusion step.",
				escapeWorkflowData(fullOutputJSON), escapeWorkflowData(err.Error()))
		} else {
			stderrf("[threat-detect] full result written: path=%s reasons=%d",
				sanitizeLogValue(fullOutputJSON), len(result.Reasons))
		}
	}

	redacted := result.Redacted()
	jsonBytes, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		stderrf("Error marshaling result: %v", err)
		return exitError, reasonOutputWriteError
	}

	if outputJSON != "" {
		if err := os.WriteFile(outputJSON, jsonBytes, 0o600); err != nil {
			stderrf("Error writing output: %v", err)
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

// envMaxTurns resolves the default value for the --max-turns flag. It prefers
// the detector-specific THREAT_DETECTION_MAX_TURNS variable, then falls back to
// gh-aw's universal GH_AW_MAX_TURNS (which gh-aw's harnesses read directly), so
// a caller who has configured the turn budget in either place gets the same
// behavior in the standalone detector. A non-integer or negative value is
// ignored in favor of the compile-time fallback rather than silently disabling
// the cap.
func envMaxTurns(fallback int) int {
	for _, key := range []string{"THREAT_DETECTION_MAX_TURNS", "GH_AW_MAX_TURNS"} {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			continue
		}
		return parsed
	}
	return fallback
}

// envDuration parses a duration env var (e.g. "5m", "300s"). An unparseable
// value or a negative value silently falls back to the default rather than
// disabling the timeout: a typo in a YAML value must not accidentally remove
// the runaway kill switch. Explicit disablement requires a parsed zero
// (env=`0s` or flag=`0`), which is honored.
func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

// formatTimeout renders a duration for the run log. Zero is rendered as
// "(disabled)" so a caller reading the log can tell the difference between
// "not configured" and "set to zero".
func formatTimeout(d time.Duration) string {
	if d <= 0 {
		return "(disabled)"
	}
	return d.String()
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
