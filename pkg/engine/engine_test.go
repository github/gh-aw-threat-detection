package engine

import (
	"os"
	"path/filepath"
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

func TestNew_ModelEnvVarFallback(t *testing.T) {
	tests := []struct {
		name      string
		engineID  string
		envKey    string
		envModel  string
		wantModel string
	}{
		{
			name:      "copilot env model used when no flag model",
			engineID:  "copilot",
			envKey:    EnvCopilotModel,
			envModel:  "gpt-5",
			wantModel: "gpt-5",
		},
		{
			name:      "claude env model used when no flag model",
			engineID:  "claude",
			envKey:    EnvClaudeModel,
			envModel:  "claude-opus-4.5",
			wantModel: "claude-opus-4.5",
		},
		{
			name:      "codex env model used when no flag model",
			engineID:  "codex",
			envKey:    EnvCodexModel,
			envModel:  "gpt-5-codex",
			wantModel: "gpt-5-codex",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envKey, tc.envModel)
			eng, err := New(tc.engineID, "")
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			var gotModel string
			switch e := eng.(type) {
			case *copilotEngine:
				gotModel = e.model
			case *claudeEngine:
				gotModel = e.model
			case *codexEngine:
				gotModel = e.model
			default:
				t.Fatalf("unexpected engine type %T", eng)
			}
			if gotModel != tc.wantModel {
				t.Fatalf("engine.model = %q, want %q", gotModel, tc.wantModel)
			}
		})
	}
}

func TestNew_FlagModelOverridesEnvVar(t *testing.T) {
	t.Setenv(EnvCopilotModel, "env-model")
	eng, err := New("copilot", "flag-model")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got := eng.(*copilotEngine).model
	if got != "flag-model" {
		t.Fatalf("engine.model = %q, want %q (flag must override env)", got, "flag-model")
	}
}

func TestNew_EnvVarNotLeakedToOtherEngine(t *testing.T) {
	// THREAT_DETECTION_COPILOT_MODEL must not affect the claude engine.
	t.Setenv(EnvCopilotModel, "copilot-specific-model")
	eng, err := New("claude", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got := eng.(*claudeEngine).model
	if got != "" {
		t.Fatalf("claude engine.model = %q, want empty (copilot env must not leak)", got)
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

	t.Run("copilot direct args omits prompt file", func(t *testing.T) {
		t.Setenv("GITHUB_WORKSPACE", "/workspace/repo")
		got := copilotDirectArgs("/tmp/prompt.txt")
		want := []string{
			"--add-dir", "/tmp",
			"--log-level", "all",
			"--disable-builtin-mcps",
			"--no-ask-user",
			"--allow-all-tools",
			"--add-dir", "/workspace/repo",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("copilotDirectArgs() = %#v, want %#v", got, want)
		}
	})

	t.Run("copilot harness command", func(t *testing.T) {
		t.Setenv("GITHUB_WORKSPACE", "/workspace/repo")
		t.Setenv("GH_AW_NODE_BIN", "/custom/node")
		runnerTemp := t.TempDir()
		t.Setenv("RUNNER_TEMP", runnerTemp)
		harnessPath := filepath.Join(runnerTemp, "gh-aw", "actions", "copilot_harness.cjs")
		if err := os.MkdirAll(filepath.Dir(harnessPath), 0o755); err != nil {
			t.Fatalf("MkdirAll() error = %v", err)
		}
		if err := os.WriteFile(harnessPath, []byte(""), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		gotName, gotArgs := copilotCommand("/tmp/prompt.txt")
		wantName := "/custom/node"
		wantArgs := []string{
			harnessPath,
			copilotBinary(),
			"--add-dir", "/tmp",
			"--log-level", "all",
			"--disable-builtin-mcps",
			"--no-ask-user",
			"--allow-all-tools",
			"--add-dir", "/workspace/repo",
			"--prompt-file", "/tmp/prompt.txt",
		}
		if gotName != wantName {
			t.Fatalf("copilotCommand() name = %q, want %q", gotName, wantName)
		}
		if !reflect.DeepEqual(gotArgs, wantArgs) {
			t.Fatalf("copilotCommand() args = %#v, want %#v", gotArgs, wantArgs)
		}
	})

	t.Run("copilot command falls back without harness", func(t *testing.T) {
		t.Setenv("GITHUB_WORKSPACE", "/workspace/repo")
		t.Setenv("RUNNER_TEMP", t.TempDir())

		gotName, gotArgs := copilotCommand("/tmp/prompt.txt")
		wantName := "copilot"
		wantArgs := []string{
			"--add-dir", "/tmp",
			"--log-level", "all",
			"--disable-builtin-mcps",
			"--no-ask-user",
			"--allow-all-tools",
			"--add-dir", "/workspace/repo",
		}
		if gotName != wantName {
			t.Fatalf("copilotCommand() name = %q, want %q", gotName, wantName)
		}
		if !reflect.DeepEqual(gotArgs, wantArgs) {
			t.Fatalf("copilotCommand() args = %#v, want %#v", gotArgs, wantArgs)
		}
	})

	t.Run("node command defaults to node", func(t *testing.T) {
		t.Setenv("GH_AW_NODE_BIN", "")
		if got, want := nodeCommand(), "node"; got != want {
			t.Fatalf("nodeCommand() = %q, want %q", got, want)
		}
	})

	t.Run("claude", func(t *testing.T) {
		got := claudeArgs("claude-sonnet-4.6", false)
		want := []string{"--print", "--verbose", "--output-format", "stream-json", "--model", "claude-sonnet-4.6", "-"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("claudeArgs() = %#v, want %#v", got, want)
		}
	})

	t.Run("claude with bash grant", func(t *testing.T) {
		got := claudeArgs("claude-sonnet-4.6", true)
		want := []string{"--print", "--verbose", "--output-format", "stream-json", "--allowed-tools", "Bash", "--model", "claude-sonnet-4.6", "-"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("claudeArgs() = %#v, want %#v", got, want)
		}
	})

	t.Run("codex", func(t *testing.T) {
		got := codexArgs("gpt-5-codex", "detect threats")
		want := []string{
			"-c", "model=gpt-5-codex",
			"exec",
			"-c", "web_search=disabled",
			"-c", "fetch=disabled",
			"--dangerously-bypass-approvals-and-sandbox",
			"--skip-git-repo-check",
			"--",
			"detect threats",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("codexArgs() = %#v, want %#v", got, want)
		}
	})

	t.Run("codex default model", func(t *testing.T) {
		got := codexArgs("", "detect threats")
		want := []string{
			"exec",
			"-c", "web_search=disabled",
			"-c", "fetch=disabled",
			"--dangerously-bypass-approvals-and-sandbox",
			"--skip-git-repo-check",
			"--",
			"detect threats",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("codexArgs() = %#v, want %#v", got, want)
		}
	})
}
