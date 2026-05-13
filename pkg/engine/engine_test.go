package engine

import (
	"reflect"
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

func TestEngineCommandArgs(t *testing.T) {
	t.Run("copilot", func(t *testing.T) {
		t.Setenv("GITHUB_WORKSPACE", "/workspace/repo")
		got := copilotArgs("/tmp/prompt.txt")
		want := []string{
			"--add-dir", "/tmp",
			"--log-level", "all",
			"--disable-builtin-mcps",
			"--no-ask-user",
			"--allow-all-tools",
			"--add-dir", "/workspace/repo",
			"--prompt-file", "/tmp/prompt.txt",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("copilotArgs() = %#v, want %#v", got, want)
		}
		if gotEnv, wantEnv := copilotEnv("claude-sonnet-4.6"), []string{"COPILOT_MODEL=claude-sonnet-4.6"}; !reflect.DeepEqual(gotEnv, wantEnv) {
			t.Fatalf("copilotEnv() = %#v, want %#v", gotEnv, wantEnv)
		}
	})

	t.Run("claude", func(t *testing.T) {
		got := claudeArgs("claude-sonnet-4.6")
		want := []string{"--print", "--verbose", "--output-format", "stream-json", "--model", "claude-sonnet-4.6", "-"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("claudeArgs() = %#v, want %#v", got, want)
		}
	})

	t.Run("codex", func(t *testing.T) {
		got := codexArgs("gpt-5-codex", "/tmp/prompt.txt")
		want := []string{
			"-c", "model=gpt-5-codex",
			"exec",
			"-c", "web_search=disabled",
			"-c", "fetch=disabled",
			"--dangerously-bypass-approvals-and-sandbox",
			"--skip-git-repo-check",
			"--prompt-file", "/tmp/prompt.txt",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("codexArgs() = %#v, want %#v", got, want)
		}
	})
}
