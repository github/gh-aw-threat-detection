package main

import (
	"flag"
	"fmt"
	"os"

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
	var (
		promptInjection bool
		secretLeak      bool
		maliciousPatch  bool
		reasons         stringSliceFlag
		resultFile      string
	)
	fs.BoolVar(&promptInjection, "prompt-injection", false, "Whether a prompt injection threat was detected (required)")
	fs.BoolVar(&secretLeak, "secret-leak", false, "Whether a secret leak threat was detected (required)")
	fs.BoolVar(&maliciousPatch, "malicious-patch", false, "Whether a malicious patch threat was detected (required)")
	fs.Var(&reasons, "reason", "Reason explaining a detected threat (repeatable)")
	fs.StringVar(&resultFile, "result-file", os.Getenv("THREAT_DETECTION_RESULT_FILE"), "Path to the result sink file (defaults to env THREAT_DETECTION_RESULT_FILE)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "THREAT_DETECTION_RESULT_ERROR: %v. Re-run threat_detection_result with corrected values.\n", err)
		return reportExitInvalid
	}

	// All three boolean flags are required and must be explicitly provided.
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	for _, name := range []string{"prompt-injection", "secret-leak", "malicious-patch"} {
		if !provided[name] {
			reportError(fmt.Sprintf("missing required flag --%s (must be true or false)", name))
			return reportExitInvalid
		}
	}

	if resultFile == "" {
		fmt.Fprintln(os.Stderr, "THREAT_DETECTION_RESULT_ERROR: no result sink configured; THREAT_DETECTION_RESULT_FILE is unset.")
		return reportExitConfig
	}

	reasonsSlice := []string(reasons)
	if msg := detector.ValidateReportFields(promptInjection, secretLeak, maliciousPatch, toAnySlice(reasonsSlice)); msg != "" {
		reportError(msg)
		return reportExitInvalid
	}

	// Require at least one reason when any threat is reported.
	if (promptInjection || secretLeak || maliciousPatch) && len(reasonsSlice) == 0 {
		reportError("at least one --reason is required when any threat is true")
		return reportExitInvalid
	}

	// Idempotent: first valid write wins.
	if _, err := detector.ReadResultFile(resultFile); err == nil {
		fmt.Println("THREAT_DETECTION_RESULT_RECORDED: result already recorded; analysis complete; stop now and produce no further output.")
		return reportExitOK
	}

	result := detector.BuildResultFromReport(promptInjection, secretLeak, maliciousPatch, reasonsSlice)
	if err := detector.WriteResultFile(resultFile, result); err != nil {
		fmt.Fprintf(os.Stderr, "THREAT_DETECTION_RESULT_ERROR: failed to record result: %v.\n", err)
		return reportExitConfig
	}

	fmt.Println("THREAT_DETECTION_RESULT_RECORDED: analysis complete; stop now and produce no further output.")
	return reportExitOK
}

// reportError prints a bounded, actionable error to both stdout (so it is visible
// in the model's tool output) and stderr.
func reportError(reason string) {
	msg := fmt.Sprintf("THREAT_DETECTION_RESULT_ERROR: %s. Re-run threat_detection_result with corrected values.", reason)
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
