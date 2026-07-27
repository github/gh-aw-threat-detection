package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestCanonical(t *testing.T) {
	cases := map[string]string{
		"":        DefaultEngineID,
		"copilot": "copilot",
		"Copilot": "copilot",
		"CLAUDE":  "claude",
		"Codex":   "codex",
	}
	for in, want := range cases {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
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
		got := codexArgs("gpt-5-codex", "", "detect threats")
		want := []string{
			"exec",
			"-c", "model=gpt-5-codex",
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
		got := codexArgs("", "", "detect threats")
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

	t.Run("codex with forced provider", func(t *testing.T) {
		got := codexArgs("gpt-5-codex", "openai-proxy", "detect threats")
		want := []string{
			"exec",
			"-c", "model=gpt-5-codex",
			"-c", "model_provider=openai-proxy",
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

func TestEngineExitError(t *testing.T) {
	tests := []struct {
		name     string
		stdout   string
		stderr   string
		wantSub  []string
		wantMiss []string
	}{
		{
			name:    "stderr only",
			stderr:  "boom on stderr",
			wantSub: []string{"exited with code 1", "stderr: boom on stderr"},
		},
		{
			name:    "stream-json error on stdout with empty stderr",
			stdout:  `{"type":"system"}` + "\n" + `{"type":"error","error":{"type":"invalid_request_error","message":"model: claude-bogus not found"}}`,
			wantSub: []string{"engine error: model: claude-bogus not found"},
		},
		{
			name:    "result is_error on stdout",
			stdout:  `{"type":"result","subtype":"error_during_execution","is_error":true,"result":"credit balance too low"}`,
			wantSub: []string{"engine error: credit balance too low"},
		},
		{
			name:    "unstructured stdout falls back to raw",
			stdout:  "panic: something bad",
			wantSub: []string{"stdout: panic: something bad"},
		},
		{
			name:    "no output at all",
			wantSub: []string{"no output captured on stdout or stderr"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engineExitError("claude", 1, tt.stdout, tt.stderr)
			msg := err.Error()
			for _, want := range tt.wantSub {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q missing %q", msg, want)
				}
			}
			for _, miss := range tt.wantMiss {
				if strings.Contains(msg, miss) {
					t.Errorf("error %q unexpectedly contains %q", msg, miss)
				}
			}
		})
	}
}

func TestTailTruncate(t *testing.T) {
	if got := tailTruncate("short", 100); got != "short" {
		t.Errorf("tailTruncate short = %q", got)
	}
	got := tailTruncate("abcdefghij", 4)
	if !strings.HasSuffix(got, "ghij") {
		t.Errorf("tailTruncate should keep tail, got %q", got)
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("tailTruncate should mark truncation, got %q", got)
	}
}

func TestExtractStreamJSONErrorNoError(t *testing.T) {
	stdout := `{"type":"system","subtype":"init"}` + "\n" + `{"type":"result","subtype":"success","is_error":false}`
	if msg := extractStreamJSONError(stdout); msg != "" {
		t.Errorf("expected no error message, got %q", msg)
	}
}
