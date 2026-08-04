package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
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
// line emitted by emitStatus in main.go), not the JSONL --log-file trace.
const defaultDetectionLogName = "detection.log"

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
	var resultFile string
	var stepSummary string
	var detectionLog string
	fs.StringVar(&resultFile, "result-file", defaultConcludeResultFile, "Path to the structured detection_result.json verdict file")
	fs.StringVar(&stepSummary, "step-summary", os.Getenv("GITHUB_STEP_SUMMARY"), "Path to append the verdict to the job step summary (defaults to env GITHUB_STEP_SUMMARY)")
	fs.StringVar(&detectionLog, "detection-log", "", "Path to the detection run's captured log, consulted to refine agent_failure/parse_error when the result file is missing (default: <result-file dir>/detection.log)")
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

	c := &concluder{
		runDetection:    os.Getenv("RUN_DETECTION"),
		warnMode:        os.Getenv("GH_AW_DETECTION_CONTINUE_ON_ERROR") != "false",
		executionFailed: os.Getenv("DETECTION_AGENTIC_EXECUTION_OUTCOME") == "failure",
		githubOutput:    githubOutput,
		githubEnv:       githubEnv,
		stepSummary:     stepSummary,
		detectionLog:    detectionLog,
		stdout:          os.Stdout,
	}
	return c.run(resultFile)
}

// concluder holds the inputs and sinks for a single conclude invocation. It is
// constructed from the environment by runConclude and exercised directly by
// tests with temp files.
type concluder struct {
	runDetection    string // RUN_DETECTION; "true" means a verdict is expected
	warnMode        bool   // GH_AW_DETECTION_CONTINUE_ON_ERROR != "false"
	executionFailed bool   // DETECTION_AGENTIC_EXECUTION_OUTCOME == "failure"

	githubOutput string // path of $GITHUB_OUTPUT (may be empty)
	githubEnv    string // path of $GITHUB_ENV (may be empty)
	stepSummary  string // path of $GITHUB_STEP_SUMMARY (may be empty)
	detectionLog string // path of the detection run's captured log (may be empty or unreadable)
	stdout       io.Writer
}

func (c *concluder) run(resultFile string) int {
	// Step 1 — detection not required: skip without reading any verdict.
	if c.runDetection != "true" {
		c.info("⏭️  Detection not required (RUN_DETECTION != \"true\"); conclusion=skipped.")
		c.setOutput("conclusion", "skipped")
		c.exportVariable("GH_AW_DETECTION_CONCLUSION", "skipped")
		c.setOutput("success", "true")
		c.setOutput("reason", "")
		c.exportVariable("GH_AW_DETECTION_REASON", "")
		c.writeVerdictSummary(nil, "skipped", "")
		return concludeExitProceed
	}

	// Step 2 — locate and read the structured verdict file. A missing or
	// otherwise unreadable file (not-exist, permission/IO error, or a TOCTOU
	// where the file is removed mid-read) means the detection run never produced
	// a readable verdict. detectionFailureReason refines this into agent_failure
	// or parse_error using the detection run's captured THREAT_DETECTION_STATUS:
	// line when available, defaulting to agent_failure/ERR_SYSTEM otherwise. Only
	// a file that is readable but whose contents are empty or malformed is
	// unconditionally a parse error (ERR_PARSE).
	result, err := detector.ReadResultFile(resultFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			reason, code := c.detectionFailureReason()
			return c.fail(nil, reason, fmt.Sprintf("%s: ❌ Detection result file not found at: %s", code, resultFile))
		}
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			reason, code := c.detectionFailureReason()
			return c.fail(nil, reason, fmt.Sprintf("%s: ❌ Detection result file unreadable at %s: %v", code, resultFile, err))
		}
		return c.fail(nil, "parse_error", fmt.Sprintf("%s: ❌ Failed to parse detection result file %s: %v", errCodeParse, resultFile, err))
	}

	// Step 3 — evaluate the verdict.
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
	return concludeExitProceed
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
		return concludeExitProceed
	}
	c.command("error", message)
	c.setOutput("conclusion", "failure")
	c.exportVariable("GH_AW_DETECTION_CONCLUSION", "failure")
	c.setOutput("success", "false")
	c.writeVerdictSummary(result, "failure", reason)
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
