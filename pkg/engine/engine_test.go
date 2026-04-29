package engine

import (
	"testing"
)

func TestNew_Copilot(t *testing.T) {
	eng, err := New("copilot", "gpt-4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestNew_Claude(t *testing.T) {
	eng, err := New("claude", "claude-3-opus")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestNew_Codex(t *testing.T) {
	eng, err := New("codex", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestNew_Default(t *testing.T) {
	eng, err := New("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine (default=copilot)")
	}
}

func TestNew_Unsupported(t *testing.T) {
	_, err := New("unsupported-engine", "")
	if err == nil {
		t.Fatal("expected error for unsupported engine")
	}
}

func TestNew_CaseInsensitive(t *testing.T) {
	engines := []string{"Copilot", "CLAUDE", "Codex"}
	for _, e := range engines {
		eng, err := New(e, "")
		if err != nil {
			t.Errorf("New(%q): unexpected error: %v", e, err)
		}
		if eng == nil {
			t.Errorf("New(%q): expected non-nil engine", e)
		}
	}
}
