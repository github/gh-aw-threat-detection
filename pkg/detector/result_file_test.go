package detector

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWriteReadResultFileRoundTrip(t *testing.T) {
	cases := map[string]*Result{
		"safe":   {PromptInjection: false, SecretLeak: false, MaliciousPatch: false, Reasons: []string{}},
		"threat": {PromptInjection: true, SecretLeak: false, MaliciousPatch: true, Reasons: []string{"injection", "patch"}},
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
