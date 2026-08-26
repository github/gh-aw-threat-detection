package detector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWriteReadResultFileRoundTrip(t *testing.T) {
	cases := map[string]*Result{
		"safe":   {PromptInjection: false, SecretLeak: false, MaliciousPatch: false, Reasons: []string{}, Warnings: []ResultWarning{}},
		"threat": {PromptInjection: true, SecretLeak: false, MaliciousPatch: true, Reasons: []string{"injection", "patch"}, Warnings: []ResultWarning{}},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result.json")
			if err := WriteResultFile(path, want); err != nil {
				t.Fatalf("WriteResultFile() error = %v", err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat error = %v", err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Fatalf("file perm = %o, want 600", perm)
			}
			got, err := ReadResultFile(path)
			if err != nil {
				t.Fatalf("ReadResultFile() error = %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip = %#v, want %#v", got, want)
			}
		})
	}
}

func TestReadResultFileErrors(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		if _, err := ReadResultFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
	t.Run("empty", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.json")
		if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadResultFile(path); err == nil {
			t.Fatal("expected error for empty file")
		}
	})
	t.Run("invalid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(path, []byte(`{"prompt_injection":"false"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadResultFile(path); err == nil {
			t.Fatal("expected error for invalid file")
		}
	})
}

func TestValidateReportFields(t *testing.T) {
	if msg := ValidateReportFields(false, false, false, []any{}); msg != "" {
		t.Fatalf("expected valid, got %q", msg)
	}
	if msg := ValidateReportFields(true, false, false, []any{"r"}); msg != "" {
		t.Fatalf("expected valid, got %q", msg)
	}
	// Wrong type for a boolean field.
	if msg := ValidateReportFields("false", false, false, []any{}); msg == "" {
		t.Fatal("expected error for string boolean")
	}
	// Wrong type for reasons.
	if msg := ValidateReportFields(false, false, false, "not-an-array"); msg == "" {
		t.Fatal("expected error for non-array reasons")
	}
}

func TestBuildResultFromReport(t *testing.T) {
	r := BuildResultFromReport(true, false, false, nil)
	if r.Reasons == nil {
		t.Fatal("expected non-nil reasons slice")
	}
	if !r.PromptInjection || r.SecretLeak || r.MaliciousPatch {
		t.Fatalf("unexpected booleans: %#v", r)
	}
}

func TestFullResultPath(t *testing.T) {
	cases := map[string]string{
		"":                                    "",
		"detection_result.json":               "detection_result_full.json",
		"/tmp/gh-aw/td/detection_result.json": "/tmp/gh-aw/td/detection_result_full.json",
		"/tmp/result":                         "/tmp/result_full",
		"/tmp/a.b/result.json":                "/tmp/a.b/result_full.json",
		"/tmp/.detection_result":              "/tmp/.detection_result_full",
		"/tmp/archive.tar.gz":                 "/tmp/archive.tar_full.gz",
		"relative/dir/detection_result.json":  "relative/dir/detection_result_full.json",
	}
	for in, want := range cases {
		if got := FullResultPath(in); got != want {
			t.Errorf("FullResultPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFullResultPathNeverAliasesInput(t *testing.T) {
	for _, in := range []string{"detection_result.json", "/tmp/result", "/tmp/.hidden", "a.tar.gz"} {
		if got := FullResultPath(in); got == in {
			t.Errorf("FullResultPath(%q) aliased its input", in)
		}
	}
}

func TestRedactedDropsReasonsWithoutMutating(t *testing.T) {
	original := &Result{PromptInjection: true, SecretLeak: true, MaliciousPatch: false, Reasons: []string{"a", "b"}}
	redacted := original.Redacted()
	if len(redacted.Reasons) != 0 {
		t.Fatalf("Redacted() reasons = %#v, want empty", redacted.Reasons)
	}
	if redacted.Reasons == nil {
		t.Fatal("Redacted() must keep reasons as an empty array, not null")
	}
	if !redacted.PromptInjection || !redacted.SecretLeak || redacted.MaliciousPatch {
		t.Fatalf("Redacted() changed the verdict: %#v", redacted)
	}
	if len(original.Reasons) != 2 {
		t.Fatalf("Redacted() mutated the receiver: %#v", original)
	}
	// The redacted result must still be schema-valid.
	path := filepath.Join(t.TempDir(), "result.json")
	if err := WriteResultFile(path, redacted); err != nil {
		t.Fatalf("redacted result is not writable: %v", err)
	}
	if _, err := ReadResultFile(path); err != nil {
		t.Fatalf("redacted result is not readable: %v", err)
	}
}

func TestSameVerdictIgnoresReasons(t *testing.T) {
	a := &Result{PromptInjection: true, Reasons: []string{}}
	b := &Result{PromptInjection: true, Reasons: []string{"why"}}
	if !a.SameVerdict(b) {
		t.Error("SameVerdict() = false for identical verdicts with differing reasons")
	}
	c := &Result{PromptInjection: true, SecretLeak: true}
	if a.SameVerdict(c) {
		t.Error("SameVerdict() = true for differing verdicts")
	}
	if a.SameVerdict(nil) {
		t.Error("SameVerdict(nil) = true")
	}
	var nilResult *Result
	if nilResult.SameVerdict(a) {
		t.Error("nil.SameVerdict() = true")
	}
	if nilResult.Redacted() != nil {
		t.Error("nil.Redacted() must be nil")
	}
}
