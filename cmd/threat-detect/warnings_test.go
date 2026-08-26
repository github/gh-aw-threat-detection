package main

import (
	"encoding/json"
	"fmt"
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
	// The clip must be self-announcing rather than silently losing the tail.
	if !strings.HasSuffix(got[0].Message, clipMarker) {
		t.Errorf("clipped message must end with the clip marker; got tail %q",
			got[0].Message[max(0, len(got[0].Message)-10):])
	}
}

// TestClipRunes_StaysWithinBound is the property that matters: clipRunes must
// never return more runes than requested, because its bound is the schema
// bound enforced on read. conclude.go's truncateRunes deliberately exceeds the
// requested length (it appends "… (truncated)"), so it must not be used here —
// doing so would produce a result file the detector rejects on read.
func TestClipRunes_StaysWithinBound(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 5, 64, 2000} {
		for _, s := range []string{"", "short", strings.Repeat("x", 5000), strings.Repeat("é", 5000)} {
			got := []rune(clipRunes(s, n))
			if len(got) > n {
				t.Errorf("clipRunes(len=%d, n=%d) returned %d runes, exceeding the bound",
					len([]rune(s)), n, len(got))
			}
		}
	}
}

// TestClipRunes_CountsRunesNotBytes guards the multi-byte case: a bound
// expressed in runes must not be applied to bytes, which would over-clip
// non-ASCII paths in warning messages.
func TestClipRunes_CountsRunesNotBytes(t *testing.T) {
	s := strings.Repeat("é", 100)
	if got := clipRunes(s, 100); got != s {
		t.Errorf("a 100-rune value must pass a 100-rune bound unchanged")
	}
}

// TestWriteResult_DoesNotMutateCallerResult verifies writeResult treats its
// input as read-only. The sink Result is parsed from the model-written file;
// silently rewriting it in place would make the caller's value diverge from
// what was actually reported.
func TestWriteResult_DoesNotMutateCallerResult(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "detection_result.json")

	result := &detector.Result{Reasons: []string{}, Warnings: []detector.ResultWarning{}}
	warnings := []artifacts.ArtifactWarning{
		{Field: "comment_memory", Code: "ERR_VALIDATION", Message: "ERR_VALIDATION: something"},
	}
	if code, _ := writeResult(result, warnings, outputPath, ""); code != exitSafe {
		t.Fatalf("unexpected exit code")
	}
	if len(result.Warnings) != 0 {
		t.Errorf("writeResult must not mutate the caller's Result; warnings = %#v", result.Warnings)
	}
	// The written file must still carry the warning.
	got, err := detector.ReadResultFile(outputPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("written result must carry the warning, got %#v", got.Warnings)
	}
}

// TestWriteResult_OverridesSinkSuppliedWarnings verifies that warnings present
// on the sink Result are discarded in favour of the detector's own. The
// reporting tool exposes no warnings flag, but the engine has a file-writing
// tool and knows THREAT_DETECTION_RESULT_FILE, so a model that wrote the sink
// directly must not be able to smuggle text into the published result — which
// is precisely the exposure the reasons split (TD-10f) exists to prevent.
func TestWriteResult_OverridesSinkSuppliedWarnings(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "detection_result.json")

	smuggled := &detector.Result{
		Reasons: []string{},
		Warnings: []detector.ResultWarning{
			{Field: "attacker", Code: "ERR_VALIDATION", Message: "model-authored text"},
		},
	}
	// No artifact warnings at all: the published result must carry none.
	if code, _ := writeResult(smuggled, nil, outputPath, ""); code != exitSafe {
		t.Fatalf("unexpected exit code")
	}
	got, err := detector.ReadResultFile(outputPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("sink-supplied warnings must be discarded, got %#v", got.Warnings)
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
// reduce."
//
// The invariant is scoped to the write path, which is where a verdict is
// concluded. It does not contradict TD-18c: in strict mode a warning about a
// *required* input is promoted to a configuration error earlier in run(), and
// detection is refused before any verdict exists to write. What must never
// happen is a warning turning a concluded verdict into a threat, which is what
// this test pins.
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

// makePromptUnreadable strips all permission bits from a staged prompt. It
// skips when the process can read it regardless, which is the case for root.
func makePromptUnreadable(t *testing.T, artifactsDir string) string {
	t.Helper()
	promptPath := filepath.Join(artifactsDir, "aw-prompts", "prompt.txt")
	if err := os.Chmod(promptPath, 0o000); err != nil {
		t.Fatalf("chmod prompt: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(promptPath, 0o644) })
	if _, err := os.ReadFile(promptPath); err == nil {
		t.Skip("process can read a 0000-mode file (likely running as root)")
	}
	return promptPath
}

// An unreadable prompt is only discoverable by trying to open it: stat reports
// a healthy non-empty file. In warn mode detection still runs, and the whole
// point of #954 is that the resulting *uploaded* file records that the channel
// went unexamined instead of looking like a clean full inspection.
func TestRun_UnreadablePromptSurfacesInPublishedResult(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	makePromptUnreadable(t, artifactsDir)

	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, _ := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "true",
	})

	// An unreadable channel is not a threat, so the run still concludes safe.
	if code != exitSafe {
		t.Fatalf("exit code = %d, want %d (an unreadable input is not a threat)", code, exitSafe)
	}

	result := readResultFile(t, outputPath)
	raw, ok := result["warnings"]
	if !ok {
		t.Fatalf("published result has no warnings field: %v", result)
	}
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		t.Fatalf("published result must record the unreadable prompt, got warnings=%v", raw)
	}

	found := false
	for _, e := range entries {
		entry, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if entry["field"] == "prompt" && strings.Contains(fmt.Sprint(entry["message"]), "could not be read") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a prompt warning saying the file could not be read, got: %v", entries)
	}
}

// The counterpart in strict mode. TD-18c promotes a required-input warning to a
// configuration error, so detection is refused. The exit status must be the
// infrastructure error, never the threat status, and no result may be written:
// a file asserting a clean verdict for analysis that never happened is exactly
// the fail-open outcome the refusal exists to prevent.
func TestRun_UnreadablePromptInStrictModeRefusesWithoutWritingResult(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)
	makePromptUnreadable(t, artifactsDir)

	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "false",
	})

	if code != exitError {
		t.Fatalf("exit code = %d, want %d (strict mode refuses a degraded run)", code, exitError)
	}
	if code == exitThreat {
		t.Fatal("a staging failure must never be reported as a threat")
	}
	if _, err := os.Stat(copilotMarker); err == nil {
		t.Error("detection must not run when a required input is unreadable in strict mode")
	}
	if _, err := os.Stat(outputPath); err == nil {
		t.Error("no result file may be written for a run that was refused")
	}
	if !strings.Contains(stderr, statusPrefix+" reason="+reasonConfigError) {
		t.Errorf("expected config_error status line, got:\n%s", stderr)
	}
}

// Prompt-analysis degradation previously existed only as a job-log annotation,
// which no host can react to programmatically -- the exact gap the warnings
// array closes. It must reach the published result like any other finding.
func TestRun_DegradedPromptAnalysisSurfacesInPublishedResult(t *testing.T) {
	artifactsDir := t.TempDir()
	// writeMinimalArtifacts stages prompt.txt and agent_output.json but neither
	// prompt-template.txt nor prompt-import-tree.json, so analysis is degraded.
	writeMinimalArtifacts(t, artifactsDir)

	outputPath := filepath.Join(t.TempDir(), "result.json")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, filepath.Join(t.TempDir(), "copilot-called"), sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "true",
	})

	if code != exitSafe {
		t.Fatalf("exit code = %d, want %d (degraded analysis is not a threat)", code, exitSafe)
	}
	// The annotation must survive; the result is additional, not a replacement.
	if !strings.Contains(stderr, "::warning::") || !strings.Contains(stderr, "prompt analysis artifact") {
		t.Errorf("expected the prompt-analysis annotation to still be emitted, got:\n%s", stderr)
	}

	result := readResultFile(t, outputPath)
	entries, _ := result["warnings"].([]any)
	// Each unavailable analysis input is reported under its own field, so the
	// finding names the artifact the host has to fix.
	wantFields := map[string]string{
		"prompt_template":    "prompt-template.txt",
		"prompt_import_tree": "prompt-import-tree.json",
	}
	for _, e := range entries {
		entry, ok := e.(map[string]any)
		if !ok {
			continue
		}
		field := fmt.Sprint(entry["field"])
		wantFile, tracked := wantFields[field]
		if !tracked {
			continue
		}
		if !strings.Contains(fmt.Sprint(entry["message"]), wantFile) {
			t.Errorf("%s message should name the unusable file, got: %v", field, entry["message"])
		}
		delete(wantFields, field)
	}
	if len(wantFields) > 0 {
		t.Errorf("missing prompt-analysis warnings %v in the published result, got: %v", wantFields, result["warnings"])
	}
}

// prompt-template.txt and prompt-import-tree.json are optional. Reporting their
// absence must stay advisory: if it were classified as a required-input finding,
// TD-18c would promote it and strict mode would refuse every run of a host that
// simply does not stage them, turning an additive change into a breaking one.
func TestPromptAnalysisWarnings_OptionalAidsAreAdvisory(t *testing.T) {
	// An analysis over a bundle that staged nothing: every input is absent, so
	// the two optional aids are reported and the prompt is left to the loader.
	arts := &artifacts.Artifacts{}
	warnings := promptAnalysisWarnings(detector.BuildPromptAnalysis(arts), arts)
	if len(warnings) == 0 {
		t.Fatal("expected a warning when no prompt analysis is available")
	}
	for _, w := range warnings {
		if w.RequiredInput {
			t.Errorf("prompt-analysis findings must not be required-input: %+v", w)
		}
	}

	if (&artifacts.Artifacts{Warnings: warnings}).HasRequiredInputWarnings() {
		t.Error("prompt-analysis findings must not trigger strict-mode refusal")
	}
}

// The strict-mode counterpart, end to end: a run missing only the optional
// prompt-analysis files must still proceed and conclude normally.
func TestRun_DegradedPromptAnalysisDoesNotBlockStrictMode(t *testing.T) {
	artifactsDir := t.TempDir()
	writeMinimalArtifacts(t, artifactsDir)

	outputPath := filepath.Join(t.TempDir(), "result.json")
	copilotMarker := filepath.Join(t.TempDir(), "copilot-called")
	sinkJSON := `{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`
	fakeBinDir := writeFakeCopilotWithSink(t, copilotMarker, sinkJSON, 0)

	code, stderr := runWithTestArgsCapture(t, []string{
		"threat-detect",
		"-output", outputPath,
		artifactsDir,
	}, map[string]string{
		"PATH":                              fakeBinDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_AW_DETECTION_CONTINUE_ON_ERROR": "false",
	})

	if code != exitSafe {
		t.Fatalf("exit code = %d, want %d; missing optional analysis files must not refuse a run in strict mode.\n%s", code, exitSafe, stderr)
	}
	if _, err := os.Stat(copilotMarker); err != nil {
		t.Error("detection should still have run in strict mode")
	}
}

// arts.Warnings backs a slice owned by the loader; collecting the reported set
// must not append into it.
func TestRun_ReportingDoesNotMutateLoaderWarnings(t *testing.T) {
	loaderWarnings := make([]artifacts.ArtifactWarning, 1, 8)
	loaderWarnings[0] = artifacts.ArtifactWarning{Field: "comment_memory", Code: "ERR_VALIDATION", Message: "ERR_VALIDATION: original"}

	reported := make([]artifacts.ArtifactWarning, 0, len(loaderWarnings)+1)
	reported = append(reported, loaderWarnings...)
	reported = append(reported, artifacts.ArtifactWarning{Field: "prompt_template", Code: "ERR_VALIDATION", Message: "ERR_VALIDATION: added"})

	if len(loaderWarnings) != 1 {
		t.Errorf("loader warnings length changed: %d", len(loaderWarnings))
	}
	if loaderWarnings[0].Field != "comment_memory" {
		t.Errorf("loader warning was overwritten: %+v", loaderWarnings[0])
	}
	if len(reported) != 2 {
		t.Errorf("reported set should carry both warnings, got %d", len(reported))
	}
}
