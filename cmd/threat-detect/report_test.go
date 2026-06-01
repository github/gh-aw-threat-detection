package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

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
