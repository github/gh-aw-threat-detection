package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

func TestBuildResultWarnings_ConvertsArtifactWarnings(t *testing.T) {
	in := []artifacts.ArtifactWarning{
		{
			Field:   "comment_memory",
			Code:    artifacts.ErrCodeValidation,
			Message: "ERR_VALIDATION: Unable to read comment-memory directory at /tmp/x: permission denied",
		},
		{
			Field:   "patch",
			Code:    artifacts.ErrCodeValidation,
			Message: "ERR_VALIDATION: HAS_PATCH=true but no readable patch file found in /tmp/y",
		},
	}
	got := buildResultWarnings(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 warnings, got %d: %#v", len(got), got)
	}
	if got[0].Field != "comment_memory" || got[0].Code != "ERR_VALIDATION" {
		t.Errorf("unexpected [0]: %#v", got[0])
	}
	// Message must have the "CODE: " prefix stripped so it is not repeated
	// alongside the separate Code field.
	if strings.HasPrefix(got[0].Message, "ERR_VALIDATION:") {
		t.Errorf("message must not repeat the code prefix: %q", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "comment-memory") {
		t.Errorf("message must retain its body: %q", got[0].Message)
	}
}

func TestBuildResultWarnings_EmptyInputProducesEmptySlice(t *testing.T) {
	if got := buildResultWarnings(nil); got == nil || len(got) != 0 {
		t.Fatalf("expected non-nil empty slice, got %#v", got)
	}
	if got := buildResultWarnings([]artifacts.ArtifactWarning{}); len(got) != 0 {
		t.Fatalf("expected empty, got %#v", got)
	}
}

func TestBuildResultWarnings_DropsInvalidEntries(t *testing.T) {
	in := []artifacts.ArtifactWarning{
		{Field: "", Code: "ERR_VALIDATION", Message: "no field"},
		{Field: "prompt", Code: "ERR_VALIDATION", Message: ""},
		{Field: "agent_output", Code: "ERR_VALIDATION", Message: "ERR_VALIDATION: real message"},
	}
	got := buildResultWarnings(in)
	if len(got) != 1 || got[0].Field != "agent_output" {
		t.Fatalf("expected only the valid entry to survive, got %#v", got)
	}
}

func TestBuildResultWarnings_TruncatesAtSchemaCap(t *testing.T) {
	in := make([]artifacts.ArtifactWarning, detector.MaxWarnings+5)
	for i := range in {
		in[i] = artifacts.ArtifactWarning{
			Field:   "prompt",
			Code:    "ERR_VALIDATION",
			Message: "ERR_VALIDATION: msg",
		}
	}
	got := buildResultWarnings(in)
	if len(got) != detector.MaxWarnings {
		t.Fatalf("expected truncation at MaxWarnings=%d, got %d", detector.MaxWarnings, len(got))
	}
}

func TestBuildResultWarnings_TruncatesOverlongMessage(t *testing.T) {
	big := strings.Repeat("x", detector.MaxWarningMessageRunes+50)
	in := []artifacts.ArtifactWarning{{
		Field:   "comment_memory",
		Code:    "ERR_VALIDATION",
		Message: "ERR_VALIDATION: " + big,
	}}
	got := buildResultWarnings(in)
	if len(got) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(got))
	}
	if runes := []rune(got[0].Message); len(runes) > detector.MaxWarningMessageRunes {
		t.Fatalf("message must be clipped to MaxWarningMessageRunes; got %d runes", len(runes))
	}
}

// TestWriteResult_WarningsAppearInBothFiles verifies the plumbing: detector-
// authored warnings must appear in both --output and --full-output. This is
// what lets a host see the partial-inspection signal in the uploaded result
// even when it does not consult the runner-local full result.
func TestWriteResult_WarningsAppearInBothFiles(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "detection_result.json")
	fullPath := filepath.Join(dir, "detection_result_full.json")

	result := &detector.Result{
		PromptInjection: false,
		SecretLeak:      false,
		MaliciousPatch:  false,
		Reasons:         []string{}, // the sink Result carries no reasons in this case
	}
	warnings := []artifacts.ArtifactWarning{
		{
			Field:   "comment_memory",
			Code:    "ERR_VALIDATION",
			Message: "ERR_VALIDATION: Unable to read comment-memory directory at /tmp/x: permission denied",
		},
	}
	code, reason := writeResult(result, warnings, outputPath, fullPath)
	if code != exitSafe {
		t.Fatalf("expected exitSafe (warnings do not fail the verdict), got %d reason=%s", code, reason)
	}

	// Both files must exist and both must carry the warning.
	for _, path := range []string{outputPath, fullPath} {
		r, err := detector.ReadResultFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if len(r.Warnings) != 1 {
			t.Fatalf("%s: expected 1 warning, got %d (%#v)", path, len(r.Warnings), r.Warnings)
		}
		if r.Warnings[0].Field != "comment_memory" || r.Warnings[0].Code != "ERR_VALIDATION" {
			t.Fatalf("%s: unexpected warning shape: %#v", path, r.Warnings[0])
		}
	}
}

// TestWriteResult_WarningsDoNotChangeExitCode is the guardrail for the
// invariant called out in #954: "A warning says 'the detector could not
// inspect everything', not 'a threat was found'. Conflating the two would
// reintroduce false positives, which is the failure mode #916 exists to
// reduce." Warnings must never influence the exit code.
func TestWriteResult_WarningsDoNotChangeExitCode(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "detection_result.json")

	warnings := []artifacts.ArtifactWarning{
		{Field: "comment_memory", Code: "ERR_VALIDATION", Message: "ERR_VALIDATION: something"},
	}

	// Safe verdict + warnings → still safe.
	safe := &detector.Result{Reasons: []string{}}
	if code, _ := writeResult(safe, warnings, outputPath, ""); code != exitSafe {
		t.Errorf("safe verdict with warnings must exit exitSafe, got %d", code)
	}

	// Threat verdict + warnings → still threat (not somehow suppressed).
	threat := &detector.Result{PromptInjection: true, Reasons: []string{}}
	if code, _ := writeResult(threat, warnings, outputPath, ""); code != exitThreat {
		t.Errorf("threat verdict with warnings must exit exitThreat, got %d", code)
	}
}

// TestWriteResult_UploadedResultEmitsWarningsField verifies the on-wire shape
// of the uploaded result: `warnings` is always a JSON array, so a host reader
// can index into it without a null check even in the common warning-free case.
func TestWriteResult_UploadedResultEmitsWarningsField(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "detection_result.json")

	result := &detector.Result{Reasons: []string{}}
	if code, _ := writeResult(result, nil, outputPath, ""); code != exitSafe {
		t.Fatalf("unexpected exit: %d", code)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	w, ok := raw["warnings"]
	if !ok {
		t.Fatal("warnings field must always be present in the uploaded result")
	}
	if string(w) != "[]" {
		t.Fatalf("empty warnings must serialize as []; got %s", string(w))
	}
}
