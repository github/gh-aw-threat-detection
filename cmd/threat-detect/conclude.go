package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
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

// runConclude implements the "conclude" subcommand. It reads the structured
// detection verdict produced by the detection run, evaluates it against the
// gh-aw job-output contract (conclusion/success/reason plus the exported
// GH_AW_DETECTION_* variables), and returns an exit code that fails the job
// when detection must block downstream safe outputs.
func runConclude(args []string) int {
	fs := flag.NewFlagSet("conclude", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var resultFile string
	fs.StringVar(&resultFile, "result-file", defaultConcludeResultFile, "Path to the structured detection_result.json verdict file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return concludeExitProceed
		}
		return concludeExitFail
	}

	c := &concluder{
		runDetection:    os.Getenv("RUN_DETECTION"),
		warnMode:        os.Getenv("GH_AW_DETECTION_CONTINUE_ON_ERROR") != "false",
		executionFailed: os.Getenv("DETECTION_AGENTIC_EXECUTION_OUTCOME") == "failure",
		githubOutput:    os.Getenv("GITHUB_OUTPUT"),
		githubEnv:       os.Getenv("GITHUB_ENV"),
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
		return concludeExitProceed
	}

	// Step 2 — locate the structured verdict file. A missing file means the
	// detection run never produced a verdict (agent/infra failure); a present
	// but malformed file is a parse error.
	if _, statErr := os.Stat(resultFile); errors.Is(statErr, fs.ErrNotExist) {
		return c.fail("agent_failure", fmt.Sprintf("%s: ❌ Detection result file not found at: %s", errCodeSystem, resultFile))
	}
	result, err := detector.ReadResultFile(resultFile)
	if err != nil {
		return c.fail("parse_error", fmt.Sprintf("%s: ❌ Failed to parse detection result file %s: %v", errCodeParse, resultFile, err))
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
		return c.fail("threat_detected", message)
	}

	c.info("✅ No security threats detected. Safe outputs may proceed.")
	c.setOutput("conclusion", "success")
	c.exportVariable("GH_AW_DETECTION_CONCLUSION", "success")
	c.setOutput("success", "true")
	c.setOutput("reason", "")
	c.exportVariable("GH_AW_DETECTION_REASON", "")
	return concludeExitProceed
}

// fail records a failure verdict and decides whether to fail closed. It mirrors
// gh-aw's setDetectionFailure exactly:
//
//   - mustFail is true only when the detection run itself failed AND the reason
//     is an infrastructure category (agent_failure/parse_error).
//   - In warn mode and not mustFail, emit a warning, set conclusion=warning, and
//     let the job proceed (exit 0).
//   - Otherwise set conclusion=failure, emit an error, and fail closed (exit 1).
func (c *concluder) fail(reason, message string) int {
	mustFail := c.executionFailed && (reason == "agent_failure" || reason == "parse_error")
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
