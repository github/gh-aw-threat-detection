package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
	"github.com/github/gh-aw-threat-detection/pkg/runlog"
)

// Exit codes for the conclude subcommand. These map directly onto whether the
// detection job should fail closed: a non-zero exit fails the step, which (when
// the step is not continue-on-error) fails the detection job and blocks the
// downstream safe_outputs gate.
const (
	concludeExitProceed = 0 // success, skipped, or warn-only — job may proceed
	concludeExitFail    = 1 // fail closed — block safe outputs
)

// Error-code prefixes mirrored from gh-aw's error_codes.cjs so downstream log
// consumers and humans see identical categorization of failures.
const (
	errCodeValidation = "ERR_VALIDATION"
	errCodeParse      = "ERR_PARSE"
	errCodeSystem     = "ERR_SYSTEM"
)

// defaultConcludeResultFile is the host-visible structured verdict written by
// the detector via --output and surfaced through the AWF read-write mount.
const defaultConcludeResultFile = "/tmp/gh-aw/threat-detection/detection_result.json"

// defaultDetectionLogName is the conventional filename for the detection run's
// captured log, sitting alongside the result file. It is a plain-text capture
// of the run's stderr (which includes the terminal THREAT_DETECTION_STATUS:
// line emitted by emitStatus in main.go), not the JSONL --log-file trace. It is
// consulted to refine the failure reason and to render diagnostics, but never
// parsed for a verdict.
const defaultDetectionLogName = "detection.log"

// Diagnostic bounds. Job logs are a shared resource, so the directory listing
// and echoed log lines are capped rather than dumped in full.
const (
	maxListedFiles       = 200
	maxEchoedLogLines    = 50
	maxEchoedLineRunes   = 500
	diagnosticLogMaxSize = 8 << 20 // 8 MiB: read no more of the detection log
)

// bannerRule is the horizontal rule framing the conclude banners. It mirrors
// gh-aw's inline conclusion step so both paths read identically in job logs.
const bannerRule = "════════════════════════════════════════════════════════"

// Prefixes echoed from the detection log for focused diagnosis. These are the
// two machine-readable markers the detector emits.
var detectionLogMarkers = []string{"THREAT_DETECTION_STATUS:", "THREAT_DETECTION_RESULT:"}

// detectionStatusReasonMap maps the terminal status-line reason emitted by a
// detection run (main.go's reasonXxx constants) onto the gh-aw job-output
// reason contract consumed by threat_detection_warning.cjs's
// isToolingFailureReason (only "agent_failure" and "parse_error" are
// tooling-failure reasons; result_recorded never reaches this path because a
// recorded verdict always leaves a readable result file). Status reasons are
// intentionally reused from main.go rather than restated as string literals.
var detectionStatusReasonMap = map[string]string{
	reasonInvalidReportExhausted: "parse_error",   // engine ran but never recorded a valid verdict
	reasonOutputWriteError:       "parse_error",   // verdict obtained but writing the result failed
	reasonEngineError:            "agent_failure", // engine subprocess itself failed
	reasonCancelled:              "agent_failure", // run was interrupted before a verdict
	reasonConfigError:            "agent_failure", // setup/validation failed before the engine ran
}

// runConclude implements the "conclude" subcommand. It reads the structured
// detection verdict produced by the detection run, evaluates it against the
// gh-aw job-output contract (conclusion/success/reason plus the exported
// GH_AW_DETECTION_* variables), and returns an exit code that fails the job
// when detection must block downstream safe outputs.
func runConclude(args []string) int {
	fs := flag.NewFlagSet("conclude", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		resultFile   string
		stepSummary  string
		detectionLog string
		logFile      string
	)
	fs.StringVar(&resultFile, "result-file", defaultConcludeResultFile, "Path to the structured detection_result.json verdict file")
	fs.StringVar(&stepSummary, "step-summary", os.Getenv("GITHUB_STEP_SUMMARY"), "Path to append the verdict to the job step summary (defaults to env GITHUB_STEP_SUMMARY)")
	fs.StringVar(&detectionLog, "detection-log", "", "Path to the detection run's captured log, consulted to refine agent_failure/parse_error and to render diagnostics when the result file is missing (default: <result-file dir>/detection.log)")
	fs.StringVar(&logFile, "log-file", os.Getenv("THREAT_DETECTION_LOG_FILE"), "Path to write JSONL run logs (env: THREAT_DETECTION_LOG_FILE)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return concludeExitProceed
		}
		return concludeExitFail
	}
	if detectionLog == "" {
		detectionLog = filepath.Join(filepath.Dir(resultFile), defaultDetectionLogName)
	}

	githubOutput := os.Getenv("GITHUB_OUTPUT")
	githubEnv := os.Getenv("GITHUB_ENV")

	// Reject collisions among the run's independently-written destinations:
	// --step-summary must not alias the structured result file (which would be
	// overwritten with Markdown after being read) or the GitHub Actions command
	// files (which the runner may reject outright if polluted with Markdown).
	if err := rejectPathCollisions(
		namedPath{"--result-file", resultFile},
		namedPath{"--step-summary", stepSummary},
		namedPath{"$GITHUB_OUTPUT", githubOutput},
		namedPath{"$GITHUB_ENV", githubEnv},
	); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return concludeExitFail
	}

	// The JSONL log is opened with O_TRUNC, so it must not alias an input this
	// command reads. Aliasing --result-file would erase the verdict (yielding a
	// bogus parse_error) and aliasing the detection log would erase the failure
	// diagnostics; both are configuration errors, checked before anything is
	// opened. The detection-log path is resolved first so the default sibling
	// path participates in the check.
	resolvedDetectionLog := detectionLog
	if resolvedDetectionLog == "" {
		resolvedDetectionLog = filepath.Join(filepath.Dir(resultFile), defaultDetectionLogName)
	}
	if logFile != "" {
		for _, other := range []struct{ path, flag string }{
			{resultFile, "--result-file"},
			{resolvedDetectionLog, "--detection-log"},
		} {
			same, err := samePath(logFile, other.path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "conclude: error resolving log paths: %v\n", err)
				return concludeExitFail
			}
			if same {
				fmt.Fprintf(os.Stderr, "conclude: --log-file and %s must not point to the same file (%q)\n", other.flag, logFile)
				return concludeExitFail
			}
		}
	}

	// A failure to open the requested JSONL log is a configuration error
	// (TD-20a): the caller explicitly asked for logs, and concluding without
	// them would report success while the required mirroring is absent.
	var logger *runlog.Logger
	if logFile != "" {
		opened, err := runlog.Open(logFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "conclude: error opening log file: %v\n", err)
			return concludeExitFail
		}
		logger = opened
		defer func() {
			if err := logger.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "conclude: failed to close log file: %v\n", err)
			}
		}()
	}

	c := &concluder{
		runDetection:     os.Getenv("RUN_DETECTION"),
		warnMode:         detectionContinueOnError(),
		executionFailed:  os.Getenv("DETECTION_AGENTIC_EXECUTION_OUTCOME") == "failure",
		executionOutcome: os.Getenv("DETECTION_AGENTIC_EXECUTION_OUTCOME"),
		githubOutput:     githubOutput,
		githubEnv:        githubEnv,
		stepSummary:      stepSummary,
		detectionLog:     detectionLog,
		logger:           logger,
		stdout:           os.Stdout,
	}
	return c.run(resultFile)
}

// concluder holds the inputs and sinks for a single conclude invocation. It is
// constructed from the environment by runConclude and exercised directly by
// tests with temp files.
type concluder struct {
	runDetection     string // RUN_DETECTION; "true" means a verdict is expected
	warnMode         bool   // GH_AW_DETECTION_CONTINUE_ON_ERROR != "false"
	executionFailed  bool   // DETECTION_AGENTIC_EXECUTION_OUTCOME == "failure"
	executionOutcome string // raw DETECTION_AGENTIC_EXECUTION_OUTCOME, echoed for diagnosis

	githubOutput string // path of $GITHUB_OUTPUT (may be empty)
	githubEnv    string // path of $GITHUB_ENV (may be empty)
	stepSummary  string // path of $GITHUB_STEP_SUMMARY (may be empty)
	detectionLog string // detection run log path; empty derives the sibling default
	logger       *runlog.Logger
	stdout       io.Writer
}

// run emits the conclusion banner, evaluates the verdict, and always closes
// with the completion banner so the section is unambiguously delimited in the
// job log regardless of which path was taken.
func (c *concluder) run(resultFile string) int {
	code := c.conclude(resultFile)
	c.banner("🛡️  Threat detection conclusion complete.")
	return code
}

func (c *concluder) conclude(resultFile string) int {
	// Resolve the detection-log path once and store it, so the diagnostics and
	// detectionFailureReason (which reads c.detectionLog) always agree — including
	// for a concluder constructed directly with only the sibling default implied.
	c.detectionLog = c.detectionLogPath(resultFile)
	detectionLog := c.detectionLog
	detectionDir := filepath.Dir(resultFile)

	c.banner("🛡️  Threat Detection: Parse Results & Conclude")
	c.info(fmt.Sprintf("📋 RUN_DETECTION env: %q", c.runDetection))
	c.info(fmt.Sprintf("📋 continue-on-error: %t", c.warnMode))
	c.info(fmt.Sprintf("📋 detection execution outcome: %q", c.executionOutcome))
	c.info(fmt.Sprintf("📁 Threat detection directory: %s", detectionDir))
	c.info(fmt.Sprintf("📄 Detection log path: %s", detectionLog))
	c.info(fmt.Sprintf("📄 Structured result path: %s", resultFile))
	c.logger.Info("conclude_start", map[string]any{
		"run_detection":     c.runDetection,
		"continue_on_error": c.warnMode,
		"execution_outcome": c.executionOutcome,
		"detection_dir":     detectionDir,
		"detection_log":     detectionLog,
		"result_file":       resultFile,
	})

	// Step 1 — detection not required: skip without reading any verdict.
	if c.runDetection != "true" {
		c.info("⏭️  Detection not required (RUN_DETECTION != \"true\"); conclusion=skipped.")
		c.info("   Reason: no agent output types or patch files were produced.")
		c.info("   Setting conclusion=skipped, success=true.")
		c.setOutput("conclusion", "skipped")
		c.exportVariable("GH_AW_DETECTION_CONCLUSION", "skipped")
		c.setOutput("success", "true")
		c.setOutput("reason", "")
		c.exportVariable("GH_AW_DETECTION_REASON", "")
		c.writeVerdictSummary(nil, "skipped", "")
		c.info("✅ Detection skipped — no threats to evaluate.")
		c.logger.Info("conclude_outcome", map[string]any{
			"conclusion": "skipped",
			"reason":     "",
			"success":    true,
			"exit":       concludeExitProceed,
		})
		return concludeExitProceed
	}

	c.info("🔍 Detection is required. Proceeding to parse detection result...")

	// Step 2 — locate and read the structured verdict file. A missing or
	// otherwise unreadable file (not-exist, permission/IO error, or a TOCTOU
	// where the file is removed mid-read) means the detection run never produced
	// a readable verdict. detectionFailureReason refines this into agent_failure
	// or parse_error using the detection run's captured THREAT_DETECTION_STATUS:
	// line when available, defaulting to agent_failure/ERR_SYSTEM otherwise. Only
	// a file that is readable but whose contents are empty or malformed is
	// unconditionally a parse error (ERR_PARSE).
	c.info(fmt.Sprintf("🔎 Checking for structured result file: %s", resultFile))
	result, err := detector.ReadResultFile(resultFile)
	if err != nil {
		// The structured result is the only verdict source, so dump everything
		// that helps explain its absence before failing.
		c.listDirectory(detectionDir)
		c.reportDetectionLog(detectionLog)

		if errors.Is(err, fs.ErrNotExist) {
			reason, code := c.detectionFailureReason()
			return c.fail(nil, reason, fmt.Sprintf("%s: ❌ Detection result file not found at: %s", code, resultFile))
		}
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			reason, code := c.detectionFailureReason()
			return c.fail(nil, reason, fmt.Sprintf("%s: ❌ Detection result file unreadable at %s: %v", code, resultFile, err))
		}
		c.info("💡 This usually means the AI engine did not record a verdict in the expected format.")
		c.info(`   Expected content: {"prompt_injection":bool,"secret_leak":bool,"malicious_patch":bool,"reasons":[...]}`)
		return c.fail(nil, "parse_error", fmt.Sprintf("%s: ❌ Failed to parse detection result file %s: %v", errCodeParse, resultFile, err))
	}

	c.info("✔️  Structured result file found and parsed successfully.")

	// Step 3 — report and evaluate the verdict.
	c.reportVerdict(result)
	if result.HasThreats() {
		threats := make([]string, 0, 3)
		if result.PromptInjection {
			threats = append(threats, "prompt injection")
		}
		if result.SecretLeak {
			threats = append(threats, "secret leak")
		}
		if result.MaliciousPatch {
			threats = append(threats, "malicious patch")
		}
		message := fmt.Sprintf("%s: ❌ Security threats detected: %s", errCodeValidation, strings.Join(threats, ", "))
		if len(result.Reasons) > 0 {
			message += "\nReasons: " + strings.Join(result.Reasons, "; ")
		}
		return c.fail(result, "threat_detected", message)
	}

	c.info("✅ No security threats detected. Safe outputs may proceed.")
	c.setOutput("conclusion", "success")
	c.exportVariable("GH_AW_DETECTION_CONCLUSION", "success")
	c.setOutput("success", "true")
	c.setOutput("reason", "")
	c.exportVariable("GH_AW_DETECTION_REASON", "")
	c.writeVerdictSummary(result, "success", "")
	c.logger.Info("conclude_outcome", map[string]any{
		"conclusion": "success",
		"reason":     "",
		"success":    true,
		"exit":       concludeExitProceed,
	})
	return concludeExitProceed
}

// detectionLogPath resolves the detection log location, defaulting to
// detection.log alongside the structured result file.
func (c *concluder) detectionLogPath(resultFile string) string {
	if c.detectionLog != "" {
		return c.detectionLog
	}
	return filepath.Join(filepath.Dir(resultFile), defaultDetectionLogName)
}

// reportVerdict prints the per-field verdict breakdown and the indexed reasons
// list. It runs on both the safe and threat paths so the job log always shows
// exactly what the detector concluded.
func (c *concluder) reportVerdict(result *detector.Result) {
	c.info("📋 Threat detection verdict (from structured result file):")
	c.info(fmt.Sprintf("   prompt_injection : %t", result.PromptInjection))
	c.info(fmt.Sprintf("   secret_leak      : %t", result.SecretLeak))
	c.info(fmt.Sprintf("   malicious_patch  : %t", result.MaliciousPatch))
	if len(result.Reasons) > 0 {
		c.info(fmt.Sprintf("   reasons (%d):", len(result.Reasons)))
		for i, reason := range result.Reasons {
			c.info(fmt.Sprintf("     [%d] %s", i+1, sanitizeLogValue(reason)))
		}
	} else {
		c.info("   reasons          : (none)")
	}
	c.logger.Info("conclude_verdict", map[string]any{
		"prompt_injection": result.PromptInjection,
		"secret_leak":      result.SecretLeak,
		"malicious_patch":  result.MaliciousPatch,
		"reasons":          result.Reasons,
		"has_threats":      result.HasThreats(),
		"source":           "structured_result_file",
	})
}

// listDirectory prints a recursive listing of dir so a missing or unusable
// result file can be diagnosed from the job log alone.
func (c *concluder) listDirectory(dir string) {
	c.info(fmt.Sprintf("📁 Listing all files in artifact directory for diagnosis: %s", dir))
	files, err := listFilesRecursively(dir)
	if err != nil {
		c.info(fmt.Sprintf("   ⚠️  Could not list files in %s: %v", dir, err))
		c.logger.Info("conclude_directory_listing", map[string]any{"dir": dir, "error": err.Error()})
		return
	}
	if len(files) == 0 {
		c.info(fmt.Sprintf("   ⚠️  No files found in %s", dir))
		c.logger.Info("conclude_directory_listing", map[string]any{"dir": dir, "count": 0, "files": []string{}})
		return
	}
	shown := files
	if len(shown) > maxListedFiles {
		shown = shown[:maxListedFiles]
	}
	c.info(fmt.Sprintf("   Found %d file(s):", len(files)))
	for _, file := range shown {
		c.info("     - " + sanitizeLogValue(file))
	}
	if len(shown) < len(files) {
		c.info(fmt.Sprintf("     ... %d more file(s) omitted", len(files)-len(shown)))
	}
	c.logger.Info("conclude_directory_listing", map[string]any{
		"dir":   dir,
		"count": len(files),
		"files": shown,
	})
}

// reportDetectionLog prints size statistics for the detection log plus every
// line carrying a THREAT_DETECTION_* marker. The log is never used to derive a
// verdict — this is diagnostics only. Only a bounded prefix of the file is read,
// so the output distinguishes the true file size from the scanned prefix rather
// than reporting the prefix as if it were the whole log.
func (c *concluder) reportDetectionLog(path string) {
	data, totalBytes, err := readBounded(path, diagnosticLogMaxSize)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			c.info(fmt.Sprintf("📄 No detection log found at: %s", path))
		} else {
			c.info(fmt.Sprintf("   ⚠️  Could not read detection log %s: %v", path, err))
		}
		c.logger.Info("conclude_detection_log", map[string]any{"path": path, "error": err.Error()})
		return
	}

	truncated := totalBytes > int64(len(data))
	lines := strings.Split(string(data), "\n")
	if truncated {
		c.info(fmt.Sprintf("📊 Detection log stats: %d bytes total; scanned first %d bytes (%d lines) — log truncated for diagnostics",
			totalBytes, len(data), len(lines)))
	} else {
		c.info(fmt.Sprintf("📊 Detection log stats: %d lines, %d bytes", len(lines), len(data)))
	}

	scope := "lines"
	if truncated {
		scope = "scanned lines"
	}

	matches := make([]string, 0, 8)
	for i, line := range lines {
		if !containsMarker(line) {
			continue
		}
		matches = append(matches, fmt.Sprintf("[%d] %s", i+1, sanitizeLogValue(truncateRunes(strings.TrimRight(line, "\r"), maxEchoedLineRunes))))
	}
	if len(matches) == 0 {
		c.info(fmt.Sprintf("📄 No lines containing THREAT_DETECTION markers found in %d %s", len(lines), scope))
	} else {
		shown := matches
		if len(shown) > maxEchoedLogLines {
			shown = shown[:maxEchoedLogLines]
		}
		c.info(fmt.Sprintf("📄 Lines containing THREAT_DETECTION markers (%d of %d %s):", len(matches), len(lines), scope))
		for _, m := range shown {
			c.info("   " + m)
		}
		if len(shown) < len(matches) {
			c.info(fmt.Sprintf("   ... %d more matching line(s) omitted", len(matches)-len(shown)))
		}
		matches = shown
	}
	c.logger.Info("conclude_detection_log", map[string]any{
		"path":          path,
		"bytes_total":   totalBytes,
		"bytes_scanned": len(data),
		"lines_scanned": len(lines),
		"truncated":     truncated,
		"marker_lines":  matches,
		"marker_count":  len(matches),
	})
}

func containsMarker(line string) bool {
	for _, marker := range detectionLogMarkers {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

// listFilesRecursively returns the paths of all regular files under dir,
// relative to dir and sorted for deterministic output. Unreadable
// subdirectories are skipped rather than aborting the whole listing.
func listFilesRecursively(dir string) ([]string, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			rel = path
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// readBounded reads at most limit bytes from path and also reports the file's
// total size, so callers can tell how much of the file they actually scanned.
func readBounded(path string, limit int64) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var totalBytes int64
	if info, err := f.Stat(); err == nil {
		totalBytes = info.Size()
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, 0, err
	}
	// A growing or non-regular file can report a size smaller than what was
	// read; never claim a total below the bytes actually scanned.
	if totalBytes < int64(len(data)) {
		totalBytes = int64(len(data))
	}
	return data, totalBytes, nil
}

// sanitizeLogValue renders an untrusted string (a model-authored reason, an
// artifact filename, or a detection-log line) so it cannot break out of its
// single physical log line. Embedded newlines would otherwise let the value
// emit a line of its own beginning with "::", which the Actions runner would
// interpret as a workflow command. Control characters are escaped rather than
// dropped so the original content stays visible and diagnosable.
func sanitizeLogValue(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsControl(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncateRunes shortens s to at most max runes, appending an ellipsis marker
// when content was dropped, so a single pathological log line cannot flood the
// job log.
func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "… (truncated)"
}

// detectionFailureReason returns the gh-aw reason (and matching error-code
// prefix) to report when the structured result file is missing or unreadable.
// It defaults to "agent_failure"/ERR_SYSTEM (no verdict was recorded at all),
// but first consults the detection run's captured log for a terminal
// THREAT_DETECTION_STATUS: line so a parse failure (invalid_report_exhausted,
// output_write_error) is distinguished from a genuine infrastructure failure
// (engine_error, cancelled, config_error), per TD-20b.
func (c *concluder) detectionFailureReason() (reason, errCode string) {
	if statusReason := lastDetectionStatusReason(c.detectionLog); statusReason != "" {
		if mapped, ok := detectionStatusReasonMap[statusReason]; ok {
			code := errCodeSystem
			if mapped == "parse_error" {
				code = errCodeParse
			}
			return mapped, code
		}
	}
	return "agent_failure", errCodeSystem
}

// lastDetectionStatusReason reads path (the detection run's captured log) and
// returns the reason field of the last THREAT_DETECTION_STATUS: line found, or
// "" if the file cannot be read or no such line is present. Only the last
// occurrence is used because a retried run may have emitted earlier lines from
// unrelated invocations captured in the same file.
func lastDetectionStatusReason(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	reason := ""
	for _, line := range strings.Split(string(data), "\n") {
		idx := strings.Index(line, statusPrefix)
		if idx < 0 {
			continue
		}
		// Reset per status line so a malformed/truncated terminal line (no
		// reason= token) clears any reason parsed from an earlier line,
		// rather than leaving it stale.
		lineReason := ""
		for _, tok := range strings.Fields(line[idx+len(statusPrefix):]) {
			if r, ok := strings.CutPrefix(tok, "reason="); ok {
				lineReason = r
			}
		}
		reason = lineReason
	}
	return reason
}

// fail records a failure verdict and decides whether to fail closed. It mirrors
// gh-aw's setDetectionFailure exactly:
//
//   - mustFail is true only when the detection run itself failed AND the reason
//     is an infrastructure category (agent_failure/parse_error).
//   - In warn mode and not mustFail, emit a warning, set conclusion=warning, and
//     let the job proceed (exit 0).
//   - Otherwise set conclusion=failure, emit an error, and fail closed (exit 1).
func (c *concluder) fail(result *detector.Result, reason, message string) int {
	mustFail := c.executionFailed && (reason == "agent_failure" || reason == "parse_error")
	c.setOutput("reason", reason)
	c.exportVariable("GH_AW_DETECTION_REASON", reason)
	if c.warnMode && !mustFail {
		c.command("warning", message)
		c.setOutput("conclusion", "warning")
		c.exportVariable("GH_AW_DETECTION_CONCLUSION", "warning")
		c.setOutput("success", "false")
		c.writeVerdictSummary(result, "warning", reason)
		c.logger.Error("conclude_outcome", map[string]any{
			"conclusion": "warning",
			"reason":     reason,
			"success":    false,
			"exit":       concludeExitProceed,
			"message":    message,
		})
		return concludeExitProceed
	}
	c.command("error", message)
	c.setOutput("conclusion", "failure")
	c.exportVariable("GH_AW_DETECTION_CONCLUSION", "failure")
	c.setOutput("success", "false")
	c.writeVerdictSummary(result, "failure", reason)
	c.logger.Error("conclude_outcome", map[string]any{
		"conclusion": "failure",
		"reason":     reason,
		"success":    false,
		"exit":       concludeExitFail,
		"message":    message,
	})
	return concludeExitFail
}

// writeVerdictSummary appends the verdict block to the job step summary,
// logging (but not failing on) any write error since the summary is a
// best-effort diagnostic aid, not part of the conclude contract.
func (c *concluder) writeVerdictSummary(result *detector.Result, conclusion, reasonCode string) {
	if err := detector.AppendStepSummary(c.stepSummary, detector.FormatVerdictSummary(result, conclusion, reasonCode)); err != nil {
		fmt.Fprintf(os.Stderr, "conclude: failed to write step summary: %v\n", err)
	}
}

// setOutput appends a step output to $GITHUB_OUTPUT. Values are single-line
// tokens, so the simple name=value form is sufficient and unambiguous.
func (c *concluder) setOutput(name, value string) {
	c.appendKV(c.githubOutput, name, value)
}

// exportVariable appends an environment variable to $GITHUB_ENV so later steps
// in the job (and the gh-aw safe_outputs gate) observe it.
func (c *concluder) exportVariable(name, value string) {
	c.appendKV(c.githubEnv, name, value)
}

func (c *concluder) appendKV(path, name, value string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "conclude: failed to write %s: %v\n", name, err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s=%s\n", name, value)
}

// info prints a human-readable line to stdout (the job log).
func (c *concluder) info(message string) {
	fmt.Fprintln(c.stdout, message)
}

// banner prints a title framed by horizontal rules, delimiting the conclusion
// section in the job log.
func (c *concluder) banner(title string) {
	c.info(bannerRule)
	c.info(title)
	c.info(bannerRule)
}

// command emits a GitHub Actions workflow command (::error:: / ::warning::)
// with the message data properly escaped.
func (c *concluder) command(kind, message string) {
	fmt.Fprintf(c.stdout, "::%s::%s\n", kind, escapeWorkflowData(message))
}

// escapeWorkflowData escapes a string for use as the data portion of a workflow
// command, per the GitHub Actions toolkit rules.
func escapeWorkflowData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}
