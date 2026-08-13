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
	"unicode/utf8"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
	"github.com/github/gh-aw-threat-detection/pkg/engine"
	"github.com/github/gh-aw-threat-detection/pkg/logsafe"
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
// line emitted by emitStatus in main.go). It is
// consulted to refine the failure reason and to render diagnostics, but never
// parsed for a verdict.
const defaultDetectionLogName = "detection.log"

// Diagnostic bounds. Job logs are a shared resource, so the directory listing
// and echoed log lines are capped rather than dumped in full.
const (
	maxListedFiles       = 200
	maxEchoedLogLines    = 50
	maxEchoedLineRunes   = 500
	maxReasonLogLines    = 40
	diagnosticLogMaxSize = 8 << 20 // 8 MiB: read no more of the detection log
)

// reasonContinuationGutter prefixes every physical line of a multi-line reason
// after the first. Reasons are untrusted text and a line of theirs could start
// with "::", which the Actions runner would interpret as a workflow command
// (leading whitespace is not protection — the runner trims it). The gutter puts
// a non-"::" character first on every continuation line, so the line stays a
// plain log line while remaining readable and copy-pasteable.
const reasonContinuationGutter = "         | "

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
	reasonInvalidReportExhausted: detector.ReasonParseError,   // engine ran but never recorded a valid verdict
	reasonOutputWriteError:       detector.ReasonParseError,   // verdict obtained but writing the result failed
	reasonEngineError:            detector.ReasonAgentFailure, // engine subprocess itself failed
	reasonCancelled:              detector.ReasonAgentFailure, // run was interrupted before a verdict
	reasonConfigError:            detector.ReasonAgentFailure, // setup/validation failed before the engine ran
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
		resultFile     string
		fullResultFile string
		detectionLog   string
	)
	fs.StringVar(&resultFile, "result-file", defaultConcludeResultFile, "Path to the structured detection_result.json verdict file")
	fs.StringVar(&fullResultFile, "full-result-file", "", "Path to the companion result file carrying the model-authored reasons, which the host does not upload (default: the --result-file path with \"_full\" inserted before the extension; empty disables the lookup)")
	fs.StringVar(&detectionLog, "detection-log", "", "Path to the detection run's captured log, consulted to refine agent_failure/parse_error and to render diagnostics when the result file is missing (default: <result-file dir>/detection.log)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return concludeExitProceed
		}
		return concludeExitFail
	}
	if detectionLog == "" {
		detectionLog = filepath.Join(filepath.Dir(resultFile), defaultDetectionLogName)
	}
	fullResultProvided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "full-result-file" {
			fullResultProvided = true
		}
	})
	// An explicitly empty --full-result-file disables the companion lookup;
	// omitting the flag derives the conventional sibling. The two cases are
	// distinguished by flag provision rather than by the value, because "" is
	// itself a meaningful value here.
	fullResultDisabled := fullResultProvided && fullResultFile == ""
	if !fullResultProvided {
		fullResultFile = detector.FullResultPath(resultFile)
	}

	githubOutput := os.Getenv("GITHUB_OUTPUT")
	githubEnv := os.Getenv("GITHUB_ENV")

	// Reject collisions among the run's independently-written destinations:
	// the structured result file must not alias the GitHub Actions command
	// files, which the runner may reject outright if polluted with JSON.
	if err := rejectPathCollisions(
		namedPath{"--result-file", resultFile},
		namedPath{"$GITHUB_OUTPUT", githubOutput},
		namedPath{"$GITHUB_ENV", githubEnv},
	); err != nil {
		stderrf("Error: %v", err)
		return concludeExitFail
	}

	c := &concluder{
		runDetection:       os.Getenv("RUN_DETECTION"),
		warnMode:           detectionContinueOnError(),
		executionFailed:    os.Getenv("DETECTION_AGENTIC_EXECUTION_OUTCOME") == "failure",
		executionOutcome:   os.Getenv("DETECTION_AGENTIC_EXECUTION_OUTCOME"),
		githubOutput:       githubOutput,
		githubEnv:          githubEnv,
		fullResultFile:     fullResultFile,
		fullResultDisabled: fullResultDisabled,
		detectionLog:       detectionLog,
		stdout:             os.Stdout,
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
	// fullResultFile is the companion result carrying the model-authored
	// reasons. Empty derives the sibling default from the result file path,
	// unless fullResultDisabled is set.
	fullResultFile string
	// fullResultDisabled suppresses the companion lookup entirely, for a host
	// that passed an explicitly empty --full-result-file.
	fullResultDisabled bool
	detectionLog       string // detection run log path; empty derives the sibling default
	stdout             io.Writer
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
	c.fullResultFile = c.fullResultPath(resultFile)
	detectionDir := filepath.Dir(resultFile)

	c.banner("🛡️  Threat Detection: Parse Results & Conclude")
	c.info(fmt.Sprintf("📋 RUN_DETECTION env: %q", c.runDetection))
	c.info(fmt.Sprintf("📋 continue-on-error: %t", c.warnMode))
	c.info(fmt.Sprintf("📋 detection execution outcome: %q", c.executionOutcome))
	c.info(fmt.Sprintf("📁 Threat detection directory: %s", detectionDir))
	c.info(fmt.Sprintf("📄 Detection log path: %s", detectionLog))
	c.info(fmt.Sprintf("📄 Structured result path: %s", resultFile))
	c.info(fmt.Sprintf("📄 Full result path: %s", sanitizeLogValue(describeResultPath(c.fullResultFile, "(disabled)"))))

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
		c.info("✅ Detection skipped — no threats to evaluate.")
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
		return c.fail(nil, detector.ReasonParseError, fmt.Sprintf("%s: ❌ Failed to parse detection result file %s: %v", errCodeParse, resultFile, err))
	}

	c.info("✔️  Structured result file found and parsed successfully.")

	// Step 3 — recover the model-authored reasons. The uploaded result carries
	// an empty `reasons` array by design; the explanations live in the
	// companion full result, which stays on the runner. A pre-split result that
	// still carries its own reasons is honored as-is.
	reasons := c.resolveReasons(result)

	// Step 4 — report and evaluate the verdict.
	c.reportVerdict(result, reasons)
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
		if len(reasons) > 0 {
			// Reasons are model-authored open text; sanitize and bound them the
			// same way reportVerdict does before folding them into the workflow
			// command and the run log.
			safe := make([]string, 0, len(reasons))
			for _, reason := range reasons {
				safe = append(safe, sanitizeLogValue(truncateRunes(reason, maxEchoedLineRunes)))
			}
			message += "\nReasons (full detail in the verdict block above): " + strings.Join(safe, "; ")
		}
		return c.fail(result, detector.ReasonThreatDetected, message)
	}

	c.info("✅ No security threats detected. Safe outputs may proceed.")
	c.setOutput("conclusion", "success")
	c.exportVariable("GH_AW_DETECTION_CONCLUSION", "success")
	c.setOutput("success", "true")
	c.setOutput("reason", "")
	c.exportVariable("GH_AW_DETECTION_REASON", "")
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

// fullResultPath resolves the companion full-result location, defaulting to the
// conventional sibling derived from the result file path.
func (c *concluder) fullResultPath(resultFile string) string {
	if c.fullResultDisabled {
		return ""
	}
	if c.fullResultFile != "" {
		return c.fullResultFile
	}
	return detector.FullResultPath(resultFile)
}

// resolveReasons returns the reasons to render for result.
//
// The authoritative verdict is always the one already parsed from the result
// file; the companion full result contributes explanations only. It is
// therefore consulted defensively: a missing or malformed file is reported and
// ignored, and a file whose verdict disagrees with the authoritative one is
// discarded outright, so no on-disk file the detector did not write for this
// run can move or contradict the verdict.
//
// When no usable full result is available, any reasons carried inside the
// result file itself are used. That is the pre-split shape, so a result written
// by an older detector still renders its explanations.
func (c *concluder) resolveReasons(result *detector.Result) []string {
	if c.fullResultFile == "" {
		c.info("📄 Full result lookup disabled; reasons will be rendered from the structured result file, if it carries any.")
		return result.Reasons
	}
	full, err := detector.ReadResultFile(c.fullResultFile)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			c.info(fmt.Sprintf("📄 No full result file found at: %s", sanitizeLogValue(c.fullResultFile)))
		default:
			// A parse error quotes the offending value, which is
			// attacker-influenced content from the file itself, so both the
			// path and the error text are escaped and bounded before they
			// reach the job log (TD-20d).
			c.info(fmt.Sprintf("   ⚠️  Could not read full result file %s: %s",
				sanitizeLogValue(c.fullResultFile),
				sanitizeLogValue(truncateRunes(err.Error(), maxEchoedLineRunes))))
		}
		c.info("   Reasons will be rendered from the structured result file, if it carries any.")
		return result.Reasons
	}
	if !result.SameVerdict(full) {
		c.info(fmt.Sprintf("   ⚠️  Full result file %s reports a different verdict than the structured result file; ignoring it.",
			sanitizeLogValue(c.fullResultFile)))
		c.info("   The structured result file remains authoritative.")
		return result.Reasons
	}
	c.info(fmt.Sprintf("✔️  Full result file found; recovered %d reason(s).", len(full.Reasons)))
	return full.Reasons
}

// reportVerdict prints the per-field verdict breakdown and the indexed reasons
// list. It runs on both the safe and threat paths so the job log always shows
// exactly what the detector concluded. Reasons are passed in rather than read
// from result, because the uploaded result deliberately carries none.
func (c *concluder) reportVerdict(result *detector.Result, reasons []string) {
	c.info("📋 Threat detection verdict (from structured result file):")
	c.info(fmt.Sprintf("   prompt_injection : %t", result.PromptInjection))
	c.info(fmt.Sprintf("   secret_leak      : %t", result.SecretLeak))
	c.info(fmt.Sprintf("   malicious_patch  : %t", result.MaliciousPatch))
	if len(reasons) > 0 {
		c.info(fmt.Sprintf("   reasons (%d):", len(reasons)))
		for i, reason := range reasons {
			lines := reasonLogLines(reason)
			c.info(fmt.Sprintf("     [%d] %s", i+1, lines[0]))
			for _, line := range lines[1:] {
				c.info(reasonContinuationGutter + line)
			}
		}
	} else {
		c.info("   reasons          : (none)")
	}
}

// reasonLogLines renders an untrusted, model-authored reason as the physical
// log lines to print. Reasons carry forensic detail — verbatim quotes of the
// triggering content, file and line references — which is only usable if it
// keeps its line structure, so embedded newlines become real lines rather than
// escaped "\n" runs.
//
// A source line longer than the per-line bound is wrapped across continuation
// lines rather than truncated. Truncating would silently discard up to three
// quarters of a reason written to the maximum MaxReasonRunes budget — precisely
// the located, verbatim evidence the reason exists to carry — for a reason that
// merely happens not to be pre-wrapped. The overall line count is still capped
// so one pathological reason cannot flood the job log.
//
// Each returned line is individually sanitized, so no line can carry a control
// character, start a line of its own, or embed a legacy workflow-command
// marker. The result always has at least one element.
func reasonLogLines(reason string) []string {
	normalized := strings.ReplaceAll(reason, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := make([]string, 0, maxReasonLogLines+1)
	truncated := false
	for _, source := range strings.Split(normalized, "\n") {
		for _, segment := range wrapRunes(source, maxEchoedLineRunes) {
			if len(lines) == maxReasonLogLines {
				truncated = true
				break
			}
			lines = append(lines, sanitizeLogValue(segment))
		}
		if truncated {
			break
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "")
	}
	if truncated {
		lines = append(lines, "… (reason truncated)")
	}
	return lines
}

// wrapRunes splits s into segments of at most max runes, counting runes rather
// than bytes so a multi-byte character is never split across segments. An empty
// input yields a single empty segment, so a blank line inside a reason survives
// as a blank line.
func wrapRunes(s string, max int) []string {
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return []string{s}
	}
	var segments []string
	count := 0
	start := 0
	for i := range s {
		if count == max {
			segments = append(segments, s[start:i])
			start = i
			count = 0
		}
		count++
	}
	return append(segments, s[start:])
}

// listDirectory prints a recursive listing of dir so a missing or unusable
// result file can be diagnosed from the job log alone.
func (c *concluder) listDirectory(dir string) {
	c.info(fmt.Sprintf("📁 Listing all files in artifact directory for diagnosis: %s", dir))
	files, err := listFilesRecursively(dir)
	if err != nil {
		c.info(fmt.Sprintf("   ⚠️  Could not list files in %s: %v", dir, err))
		return
	}
	if len(files) == 0 {
		c.info(fmt.Sprintf("   ⚠️  No files found in %s", dir))
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
// artifact filename, or a detection-log line) so it cannot act as a workflow
// command. Two things are neutralized:
//
//   - Control characters are escaped rather than dropped, so the original
//     content stays visible and diagnosable. This confines the value to one
//     physical line, since an embedded newline would otherwise let it emit a
//     line of its own beginning with "::" — which the runner would interpret.
//     (Reasons are rendered across real lines by reasonLogLines, which calls
//     this per line and prefixes continuations so none can start with "::".)
//   - The legacy "##[" marker is escaped wherever it appears, because the
//     runner matches it mid-line and line-position defenses cannot reach it.
func sanitizeLogValue(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return logsafe.EscapeLegacyCommandMarker(s)
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
	// The control-character escapes above emit only backslash sequences, so they
	// can neither create nor hide a "##[" marker; escaping it afterwards is safe.
	return logsafe.EscapeLegacyCommandMarker(b.String())
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
			if mapped == detector.ReasonParseError {
				code = errCodeParse
			}
			return mapped, code
		}
	}
	return detector.ReasonAgentFailure, errCodeSystem
}

// lastDetectionStatusReason reads path (the detection run's captured log) and
// returns the reason field of the last THREAT_DETECTION_STATUS: line found, or
// "" if the file cannot be read or no such line is present. Only the last
// occurrence is used because a retried run may have emitted earlier lines from
// unrelated invocations captured in the same file.
//
// Lines carrying engine.PassthroughPrefix are forwarded engine subprocess output
// — untrusted, model-authored text — and are skipped so a status line the
// detector never emitted cannot drive the reported failure reason.
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
		if isForwardedEngineLine(line) {
			continue
		}
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

// isForwardedEngineLine reports whether a captured-log line is engine subprocess
// output the detector forwarded, rather than a diagnostic the detector authored.
// Leading whitespace is tolerated so a line indented by an outer log capture is
// still recognized.
func isForwardedEngineLine(line string) bool {
	return strings.HasPrefix(strings.TrimLeft(line, " \t"), engine.PassthroughPrefix)
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
	mustFail := c.executionFailed && detector.IsToolingFailureReason(reason)
	if headline := detector.ThreatHeadline(reason); headline != "" {
		icon := "🚨"
		if detector.IsToolingFailureReason(reason) {
			icon = "⚠️ "
		}
		c.info(fmt.Sprintf("%s %s", icon, headline))
	}
	c.setOutput("reason", reason)
	c.exportVariable("GH_AW_DETECTION_REASON", reason)
	if c.warnMode && !mustFail {
		c.command("warning", message)
		c.setOutput("conclusion", "warning")
		c.exportVariable("GH_AW_DETECTION_CONCLUSION", "warning")
		c.setOutput("success", "false")
		return concludeExitProceed
	}
	c.command("error", message)
	c.setOutput("conclusion", "failure")
	c.exportVariable("GH_AW_DETECTION_CONCLUSION", "failure")
	c.setOutput("success", "false")
	return concludeExitFail
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
		stderrf("conclude: failed to write %s: %v", name, err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s=%s\n", name, value)
}

// info prints one diagnostic line to the conclusion's output stream.
//
// Sanitizing here rather than at each call site makes this the single choke
// point for the conclusion diagnostics: every value these lines interpolate —
// model-authored reasons, artifact filenames, detection-log lines, and the
// host-supplied paths and environment values echoed in the header — is rendered
// inert before it can reach the job log, and a future call site cannot
// reintroduce the gap by forgetting to escape its own arguments. Sanitizing is
// idempotent, so callers that additionally bound a value may keep escaping it
// themselves.
func (c *concluder) info(message string) {
	fmt.Fprintln(c.stdout, sanitizeLogValue(message))
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
//
// The toolkit rules cover only the characters that would terminate or extend
// this command (`%`, CR, LF); they leave the legacy `##[` marker alone. The
// runner does not currently rescan the data of a command it has already
// recognized — it tries the `::` form first and falls back to legacy parsing
// only when that fails — so a marker embedded in the message of an `::error::`
// this program emits is not live today. Neutralizing it anyway costs nothing
// and does not depend on that parse order holding, and it keeps annotation text
// consistent with the same value rendered by sanitizeLogValue elsewhere in the
// log. The percent-escaping below emits only `%XX` sequences, so it can neither
// create nor hide a marker.
func escapeWorkflowData(s string) string {
	s = logsafe.EscapeLegacyCommandMarker(s)
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}
