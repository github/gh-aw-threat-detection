package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

// Exit codes for the report-result subcommand.
const (
	reportExitOK      = 0
	reportExitInvalid = 2
	reportExitConfig  = 3
)

// stringSliceFlag collects repeatable string flag values.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return fmt.Sprintf("%v", []string(*s))
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// runReport implements the "report-result" subcommand invoked in-session by the
// detection model through the generated threat_detection_result wrapper.
func runReport(args []string) int {
	fs := flag.NewFlagSet("report-result", flag.ContinueOnError)
	// Suppress FlagSet's own parse/usage output so tool output stays
	// deterministic; parse errors are routed through reportError below.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	var (
		promptInjection bool
		secretLeak      bool
		maliciousPatch  bool
		reasons         stringSliceFlag
		reasonsFile     string
		resultFile      string
	)
	fs.BoolVar(&promptInjection, "prompt-injection", false, "Whether a prompt injection threat was detected (required)")
	fs.BoolVar(&secretLeak, "secret-leak", false, "Whether a secret leak threat was detected (required)")
	fs.BoolVar(&maliciousPatch, "malicious-patch", false, "Whether a malicious patch threat was detected (required)")
	fs.Var(&reasons, "reason", "Reason explaining a detected threat (repeatable; use --reasons-file for text quoting artifact content)")
	fs.StringVar(&reasonsFile, "reasons-file", "", "Path to a file containing a JSON array of reason strings; the shell-free way to report reasons that quote artifact content")
	fs.StringVar(&resultFile, "result-file", os.Getenv("THREAT_DETECTION_RESULT_FILE"), "Path to the result sink file (defaults to env THREAT_DETECTION_RESULT_FILE)")

	if err := fs.Parse(normalizeBoolFlagArgs(args)); err != nil {
		reportError(err.Error())
		return reportExitInvalid
	}

	// All three boolean flags are required and must be explicitly provided.
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	for _, name := range boolReportFlags {
		if !provided[name] {
			reportError(fmt.Sprintf("missing required flag --%s (must be true or false)", name))
			return reportExitInvalid
		}
	}

	if resultFile == "" {
		emitMessage("THREAT_DETECTION_RESULT_ERROR: no result sink configured; THREAT_DETECTION_RESULT_FILE is unset.")
		return reportExitConfig
	}

	// Reasons from the file transport are appended after any --reason flags, so
	// the recorded order matches the order the model supplied them.
	reasonsSlice := []string(reasons)
	if reasonsFile != "" {
		fileReasons, err := detector.ReadReasonsFile(reasonsFile)
		if err != nil {
			reportError(detector.TruncateCorrectionMessage(err.Error()))
			return reportExitInvalid
		}
		reasonsSlice = append(reasonsSlice, fileReasons...)
	}
	if msg := detector.ValidateReportFields(promptInjection, secretLeak, maliciousPatch, toAnySlice(reasonsSlice)); msg != "" {
		reportError(msg)
		return reportExitInvalid
	}

	// Require at least one reason when any threat is reported.
	if (promptInjection || secretLeak || maliciousPatch) && len(reasonsSlice) == 0 {
		reportError("at least one reason is required when any threat is true; supply --reasons-file (preferred) or --reason")
		return reportExitInvalid
	}

	// Idempotent: first valid write wins.
	if _, err := detector.ReadResultFile(resultFile); err == nil {
		fmt.Println("THREAT_DETECTION_RESULT_RECORDED: result already recorded; analysis complete; stop now and produce no further output.")
		return reportExitOK
	}

	result := detector.BuildResultFromReport(promptInjection, secretLeak, maliciousPatch, reasonsSlice)
	if err := detector.WriteResultFile(resultFile, result); err != nil {
		emitMessage(fmt.Sprintf("THREAT_DETECTION_RESULT_ERROR: failed to record result: %v.", err))
		return reportExitConfig
	}

	fmt.Println("THREAT_DETECTION_RESULT_RECORDED: analysis complete; stop now and produce no further output.")
	return reportExitOK
}

// boolReportFlags are the boolean flags of the report-result subcommand.
var boolReportFlags = []string{"prompt-injection", "secret-leak", "malicious-patch"}

// normalizeBoolFlagArgs rewrites space-separated boolean flag values
// (`--prompt-injection true`) into the `--prompt-injection=true` form that Go's
// flag package requires. The documented tool invocation uses the space-separated
// form, which flag would otherwise parse as a bare `true` boolean flag followed
// by a positional argument that silently terminates parsing.
func normalizeBoolFlagArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			out = append(out, args[i:]...)
			break
		}
		name := strings.TrimLeft(arg, "-")
		if name != arg && isBoolReportFlag(name) && i+1 < len(args) {
			if value, err := strconv.ParseBool(args[i+1]); err == nil {
				out = append(out, arg+"="+strconv.FormatBool(value))
				i++
				continue
			}
		}
		out = append(out, arg)
	}
	return out
}

func isBoolReportFlag(name string) bool {
	for _, candidate := range boolReportFlags {
		if name == candidate {
			return true
		}
	}
	return false
}

// reportError prints a bounded, actionable error to both stdout (so it is visible
// in the model's tool output) and stderr, instructing the model to retry.
func reportError(reason string) {
	emitMessage(fmt.Sprintf("THREAT_DETECTION_RESULT_ERROR: %s. Re-run threat_detection_result with corrected values.", reason))
}

// emitMessage writes msg to both stdout (so it appears in the model's tool
// output) and stderr, keeping the THREAT_DETECTION_RESULT_ERROR prefix visible
// regardless of how the tool output is captured.
func emitMessage(msg string) {
	fmt.Println(msg)
	fmt.Fprintln(os.Stderr, msg)
}

func toAnySlice(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}
