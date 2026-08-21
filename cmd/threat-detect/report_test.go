package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

// reportHelperEnv makes the test binary behave as the detector binary's
// report-result subcommand, so the end-to-end shell test below can exercise the
// real provisioned-wrapper invocation path without building a separate binary.
const reportHelperEnv = "THREAT_DETECT_TEST_REPORT_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(reportHelperEnv) == "1" {
		args := os.Args[1:]
		// Mirror the real wrapper, which execs "<binary> report-result "$@"".
		if len(args) > 0 && args[0] == "report-result" {
			args = args[1:]
		}
		os.Exit(runReport(args))
	}
	os.Exit(m.Run())
}

func TestRunReportValidWritesSink(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	t.Setenv("THREAT_DETECTION_RESULT_FILE", sink)

	code := runReport([]string{"--prompt-injection=true", "--secret-leak=false", "--malicious-patch=false", "--reason", "found injection"})
	if code != reportExitOK {
		t.Fatalf("runReport() = %d, want %d", code, reportExitOK)
	}
	result, err := detector.ReadResultFile(sink)
	if err != nil {
		t.Fatalf("ReadResultFile() error = %v", err)
	}
	if !result.PromptInjection || result.SecretLeak || result.MaliciousPatch {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != "found injection" {
		t.Fatalf("unexpected reasons: %#v", result.Reasons)
	}
}

func TestRunReportInvalidLeavesNoSink(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	t.Setenv("THREAT_DETECTION_RESULT_FILE", sink)

	t.Run("missing boolean", func(t *testing.T) {
		code := runReport([]string{"--secret-leak=false", "--malicious-patch=false"})
		if code != reportExitInvalid {
			t.Fatalf("runReport() = %d, want %d", code, reportExitInvalid)
		}
		if _, err := os.Stat(sink); !os.IsNotExist(err) {
			t.Fatalf("expected no sink file, stat err = %v", err)
		}
	})

	t.Run("threat without reason", func(t *testing.T) {
		code := runReport([]string{"--prompt-injection=true", "--secret-leak=false", "--malicious-patch=false"})
		if code != reportExitInvalid {
			t.Fatalf("runReport() = %d, want %d", code, reportExitInvalid)
		}
		if _, err := os.Stat(sink); !os.IsNotExist(err) {
			t.Fatalf("expected no sink file, stat err = %v", err)
		}
	})
}

func TestRunReportMissingConfig(t *testing.T) {
	t.Setenv("THREAT_DETECTION_RESULT_FILE", "")
	code := runReport([]string{"--prompt-injection=false", "--secret-leak=false", "--malicious-patch=false"})
	if code != reportExitConfig {
		t.Fatalf("runReport() = %d, want %d", code, reportExitConfig)
	}
}

func TestRunReportIdempotent(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	t.Setenv("THREAT_DETECTION_RESULT_FILE", sink)

	if code := runReport([]string{"--prompt-injection=false", "--secret-leak=false", "--malicious-patch=false"}); code != reportExitOK {
		t.Fatalf("first runReport() = %d, want %d", code, reportExitOK)
	}
	// Second valid call with different values must not overwrite the first.
	if code := runReport([]string{"--prompt-injection=true", "--secret-leak=false", "--malicious-patch=false", "--reason", "x"}); code != reportExitOK {
		t.Fatalf("second runReport() = %d, want %d", code, reportExitOK)
	}
	result, err := detector.ReadResultFile(sink)
	if err != nil {
		t.Fatalf("ReadResultFile() error = %v", err)
	}
	if result.PromptInjection {
		t.Fatalf("expected first-write-wins; got %#v", result)
	}
}

func TestRunReportSpaceSeparatedBooleans(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	t.Setenv("THREAT_DETECTION_RESULT_FILE", sink)

	code := runReport([]string{"--prompt-injection", "false", "--secret-leak", "true", "--malicious-patch", "false", "--reason", "leaked token"})
	if code != reportExitOK {
		t.Fatalf("runReport() = %d, want %d", code, reportExitOK)
	}
	result, err := detector.ReadResultFile(sink)
	if err != nil {
		t.Fatalf("ReadResultFile() error = %v", err)
	}
	if result.PromptInjection || !result.SecretLeak || result.MaliciousPatch {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != "leaked token" {
		t.Fatalf("unexpected reasons: %#v", result.Reasons)
	}
}

func TestRunReportSpaceSeparatedSingleDash(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	t.Setenv("THREAT_DETECTION_RESULT_FILE", sink)

	code := runReport([]string{"-prompt-injection", "true", "-secret-leak", "false", "-malicious-patch", "false", "-reason", "injection"})
	if code != reportExitOK {
		t.Fatalf("runReport() = %d, want %d", code, reportExitOK)
	}
	result, err := detector.ReadResultFile(sink)
	if err != nil {
		t.Fatalf("ReadResultFile() error = %v", err)
	}
	if !result.PromptInjection {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestRunReportEligibilityRejectsIneligibleThreat(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	t.Setenv("THREAT_DETECTION_RESULT_FILE", sink)
	// The detector process sets these; here we simulate an artifact bundle
	// with no patch and no untrusted input.
	t.Setenv("THREAT_DETECTION_ELIGIBLE_PROMPT_INJECTION", "false")
	t.Setenv("THREAT_DETECTION_ELIGIBLE_SECRET_LEAK", "true")
	t.Setenv("THREAT_DETECTION_ELIGIBLE_MALICIOUS_PATCH", "false")

	t.Run("malicious_patch without a patch", func(t *testing.T) {
		code := runReport([]string{"--prompt-injection=false", "--secret-leak=false", "--malicious-patch=true", "--reason", "x"})
		if code != reportExitInvalid {
			t.Fatalf("runReport() = %d, want %d", code, reportExitInvalid)
		}
		if _, err := os.Stat(sink); !os.IsNotExist(err) {
			t.Fatalf("expected no sink file after ineligible claim, stat err = %v", err)
		}
	})

	t.Run("prompt_injection without untrusted input", func(t *testing.T) {
		code := runReport([]string{"--prompt-injection=true", "--secret-leak=false", "--malicious-patch=false", "--reason", "x"})
		if code != reportExitInvalid {
			t.Fatalf("runReport() = %d, want %d", code, reportExitInvalid)
		}
		if _, err := os.Stat(sink); !os.IsNotExist(err) {
			t.Fatalf("expected no sink file after ineligible claim, stat err = %v", err)
		}
	})

	t.Run("safe verdict is unaffected", func(t *testing.T) {
		code := runReport([]string{"--prompt-injection=false", "--secret-leak=false", "--malicious-patch=false"})
		if code != reportExitOK {
			t.Fatalf("runReport() = %d, want %d", code, reportExitOK)
		}
	})
}

func TestRunReportEligibilityAllowsEligibleThreat(t *testing.T) {
	sink := filepath.Join(t.TempDir(), "result.json")
	t.Setenv("THREAT_DETECTION_RESULT_FILE", sink)
	t.Setenv("THREAT_DETECTION_ELIGIBLE_PROMPT_INJECTION", "true")
	t.Setenv("THREAT_DETECTION_ELIGIBLE_SECRET_LEAK", "true")
	t.Setenv("THREAT_DETECTION_ELIGIBLE_MALICIOUS_PATCH", "true")

	code := runReport([]string{"--prompt-injection=true", "--secret-leak=false", "--malicious-patch=true", "--reason", "found injection", "--reason", "found patch"})
	if code != reportExitOK {
		t.Fatalf("runReport() = %d, want %d", code, reportExitOK)
	}
	result, err := detector.ReadResultFile(sink)
	if err != nil {
		t.Fatalf("ReadResultFile() error = %v", err)
	}
	if !result.PromptInjection || !result.MaliciousPatch {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestNormalizeBoolFlagArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "space separated booleans joined",
			in:   []string{"--prompt-injection", "true", "--secret-leak", "FALSE", "--malicious-patch", "0"},
			want: []string{"--prompt-injection=true", "--secret-leak=false", "--malicious-patch=false"},
		},
		{
			name: "equals form untouched",
			in:   []string{"--prompt-injection=true", "--reason", "x"},
			want: []string{"--prompt-injection=true", "--reason", "x"},
		},
		{
			name: "reason value that looks boolean untouched",
			in:   []string{"--reason", "true", "--prompt-injection", "true"},
			want: []string{"--reason", "true", "--prompt-injection=true"},
		},
		{
			name: "non boolean value untouched",
			in:   []string{"--prompt-injection", "yes"},
			want: []string{"--prompt-injection", "yes"},
		},
		{
			name: "terminator stops rewriting",
			in:   []string{"--", "--prompt-injection", "true"},
			want: []string{"--", "--prompt-injection", "true"},
		},
		{
			name: "trailing flag without value untouched",
			in:   []string{"--prompt-injection"},
			want: []string{"--prompt-injection"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeBoolFlagArgs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeBoolFlagArgs() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("normalizeBoolFlagArgs() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// hostileReason is a reason whose EVIDENCE section quotes attacker-authored
// content containing every shell construct that would let quoted text escape a
// command line: command substitution in both forms, a command separator, a
// pipe, globbing, quotes, and a newline.
const hostileReason = "[prompt_injection] LOCATION: aw-prompts/prompt.txt:42\n" +
	"EVIDENCE:\n" +
	"  $(touch CANARY) `touch CANARY` ${IFS}\n" +
	"  \"; touch CANARY; echo \" | touch CANARY\n" +
	"  rm -rf * && touch 'CANARY'\n" +
	"ORIGIN: issue body #1 by @attacker\nWHY: attempts command execution\nREMEDIATION: delete the comment"

// TestRunReportReasonsFileRoundTrip verifies reasons supplied through the file
// transport are recorded byte-for-byte, including shell metacharacters and
// newlines, and are appended after any --reason flags.
func TestRunReportReasonsFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sink := filepath.Join(dir, "result.json")
	t.Setenv("THREAT_DETECTION_RESULT_FILE", sink)

	reasonsFile := filepath.Join(dir, "reasons.json")
	writeJSONReasons(t, reasonsFile, []string{hostileReason, "second finding"})

	code := runReport([]string{
		"--prompt-injection", "true", "--secret-leak", "false", "--malicious-patch", "false",
		"--reason", "flag reason",
		"--reasons-file", reasonsFile,
	})
	if code != reportExitOK {
		t.Fatalf("runReport() = %d, want %d", code, reportExitOK)
	}
	result, err := detector.ReadResultFile(sink)
	if err != nil {
		t.Fatalf("ReadResultFile() error = %v", err)
	}
	want := []string{"flag reason", hostileReason, "second finding"}
	if len(result.Reasons) != len(want) {
		t.Fatalf("reasons = %#v, want %#v", result.Reasons, want)
	}
	for i := range want {
		if result.Reasons[i] != want[i] {
			t.Errorf("reason[%d] = %q, want %q", i, result.Reasons[i], want[i])
		}
	}
}

// TestRunReportReasonsFileInvalid verifies malformed transport input is a
// correctable error that records nothing, rather than anything executable.
func TestRunReportReasonsFileInvalid(t *testing.T) {
	tests := []struct {
		name     string
		contents string // file contents; "" means do not create the file
	}{
		{name: "missing file", contents: ""},
		{name: "not json", contents: "just some text"},
		{name: "not an array", contents: `{"reasons":["x"]}`},
		{name: "non-string entry", contents: `["ok", 7]`},
		{name: "trailing content", contents: `["ok"] ["more"]`},
		{name: "blank entry", contents: `["   "]`},
		{name: "empty file", contents: "   \n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			sink := filepath.Join(dir, "result.json")
			t.Setenv("THREAT_DETECTION_RESULT_FILE", sink)
			reasonsFile := filepath.Join(dir, "reasons.json")
			if tt.contents != "" {
				if err := os.WriteFile(reasonsFile, []byte(tt.contents), 0o600); err != nil {
					t.Fatalf("WriteFile error = %v", err)
				}
			}
			code := runReport([]string{
				"--prompt-injection", "true", "--secret-leak", "false", "--malicious-patch", "false",
				"--reasons-file", reasonsFile,
			})
			if code != reportExitInvalid {
				t.Fatalf("runReport() = %d, want %d", code, reportExitInvalid)
			}
			if _, err := os.Stat(sink); !os.IsNotExist(err) {
				t.Fatalf("expected no sink file, stat err = %v", err)
			}
		})
	}
}

// TestReportResultShellEndToEndHostileEvidence is the end-to-end guarantee: a
// reason quoting hostile shell syntax reaches the sink intact when reported the
// documented way, and no part of it is executed. The tool is invoked exactly as
// the detection engine invokes it — through /bin/sh, via the provisioned
// wrapper script on PATH — with the hostile text carried only in the reasons
// file, never on the command line.
func TestReportResultShellEndToEndHostileEvidence(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot resolve test binary: %v", err)
	}
	dir := t.TempDir()
	sink := filepath.Join(dir, "result.json")

	wrapper := filepath.Join(dir, "threat_detection_result")
	script := "#!/bin/sh\nexec '" + self + "' report-result \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	reasonsFile := filepath.Join(dir, "reasons.json")
	writeJSONReasons(t, reasonsFile, []string{hostileReason})

	// The command line the model is instructed to run: booleans and a path, no
	// artifact-derived text.
	cmd := exec.Command("/bin/sh", "-c",
		"threat_detection_result --prompt-injection true --secret-leak false --malicious-patch false --reasons-file "+reasonsFile)
	cmd.Dir = dir // any CANARY created by an executed substitution lands here
	cmd.Env = append(os.Environ(),
		reportHelperEnv+"=1",
		"THREAT_DETECTION_RESULT_FILE="+sink,
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tool invocation error = %v (output: %s)", err, out)
	}
	if !strings.Contains(string(out), "THREAT_DETECTION_RESULT_RECORDED") {
		t.Fatalf("expected recorded confirmation, got: %s", out)
	}

	// Nothing in the evidence may have been executed.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir error = %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "CANARY") {
			t.Fatalf("evidence was executed by a shell: %q created", entry.Name())
		}
	}

	// And the evidence must have survived byte-for-byte, or it would not be
	// copy-pasteable back to the source.
	result, err := detector.ReadResultFile(sink)
	if err != nil {
		t.Fatalf("ReadResultFile() error = %v", err)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != hostileReason {
		t.Fatalf("reason not preserved verbatim:\ngot:  %#v\nwant: %q", result.Reasons, hostileReason)
	}
}

func writeJSONReasons(t *testing.T, path string, reasons []string) {
	t.Helper()
	data, err := json.Marshal(reasons)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
}
