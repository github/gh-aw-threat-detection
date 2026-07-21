package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCodexForcedProvider(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "misordered selection nested under history table",
			content: `[history]
persistence = "none"

model_provider = "openai-proxy"

[model_providers.openai-proxy]
name = "OpenAI AWF proxy"
base_url = "http://172.30.0.30:10000"
env_key = "OPENAI_API_KEY"
`,
			want: "openai-proxy",
		},
		{
			name: "correct top-level selection is respected (no override)",
			content: `model_provider = "openai-proxy"

[model_providers.openai-proxy]
base_url = "http://172.30.0.30:10000"

[history]
persistence = "none"
`,
			want: "",
		},
		{
			name: "provider table without any selection",
			content: `[history]
persistence = "none"

[model_providers.openai-proxy]
base_url = "http://172.30.0.30:10000"
`,
			want: "openai-proxy",
		},
		{
			name: "no custom provider defined",
			content: `[history]
persistence = "none"
`,
			want: "",
		},
		{
			name: "ambiguous multiple providers",
			content: `[model_providers.one]
base_url = "http://one"

[model_providers.two]
base_url = "http://two"
`,
			want: "",
		},
		{
			name: "comments are ignored",
			content: `# model_provider = "commented-out"
[history]
persistence = "none"
# [model_providers.ignored]
[model_providers.real]
base_url = "http://real"
`,
			want: "real",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseCodexForcedProvider(tt.content); got != tt.want {
				t.Fatalf("parseCodexForcedProvider() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCodexForcedProviderReadsFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	content := `[history]
persistence = "none"

model_provider = "openai-proxy"

[model_providers.openai-proxy]
base_url = "http://172.30.0.30:10000"
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	if got := codexForcedProvider(configPath); got != "openai-proxy" {
		t.Fatalf("codexForcedProvider() = %q, want %q", got, "openai-proxy")
	}

	if got := codexForcedProvider(filepath.Join(dir, "missing.toml")); got != "" {
		t.Fatalf("codexForcedProvider(missing) = %q, want empty", got)
	}
	if got := codexForcedProvider(""); got != "" {
		t.Fatalf("codexForcedProvider(empty path) = %q, want empty", got)
	}
}

func TestCodexConfigPathHonorsCodexHome(t *testing.T) {
	t.Setenv("CODEX_HOME", "/tmp/example-codex-home")
	if got, want := codexConfigPath(), filepath.Join("/tmp/example-codex-home", "config.toml"); got != want {
		t.Fatalf("codexConfigPath() = %q, want %q", got, want)
	}
}

func TestResolveModel(t *testing.T) {
	// Ensure a clean slate for all detection-model env vars.
	for _, name := range []string{
		"GH_AW_MODEL_DETECTION_COPILOT",
		"GH_AW_MODEL_DETECTION_CLAUDE",
		"GH_AW_MODEL_DETECTION_CODEX",
	} {
		t.Setenv(name, "")
	}

	t.Run("explicit flag always wins", func(t *testing.T) {
		t.Setenv("GH_AW_MODEL_DETECTION_CODEX", "gpt-5.4")
		if got := ResolveModel("codex", "gpt-flag"); got != "gpt-flag" {
			t.Fatalf("ResolveModel() = %q, want %q", got, "gpt-flag")
		}
	})

	t.Run("codex falls back to env", func(t *testing.T) {
		t.Setenv("GH_AW_MODEL_DETECTION_CODEX", "gpt-5.4")
		if got := ResolveModel("codex", ""); got != "gpt-5.4" {
			t.Fatalf("ResolveModel() = %q, want %q", got, "gpt-5.4")
		}
	})

	t.Run("claude falls back to env", func(t *testing.T) {
		t.Setenv("GH_AW_MODEL_DETECTION_CLAUDE", "claude-sonnet-4.6")
		if got := ResolveModel("claude", ""); got != "claude-sonnet-4.6" {
			t.Fatalf("ResolveModel() = %q, want %q", got, "claude-sonnet-4.6")
		}
	})

	t.Run("copilot falls back to env", func(t *testing.T) {
		t.Setenv("GH_AW_MODEL_DETECTION_COPILOT", "some-copilot-model")
		if got := ResolveModel("copilot", ""); got != "some-copilot-model" {
			t.Fatalf("ResolveModel() = %q, want %q", got, "some-copilot-model")
		}
	})

	t.Run("empty engine uses default copilot env", func(t *testing.T) {
		t.Setenv("GH_AW_MODEL_DETECTION_COPILOT", "default-engine-model")
		if got := ResolveModel("", ""); got != "default-engine-model" {
			t.Fatalf("ResolveModel() = %q, want %q", got, "default-engine-model")
		}
	})

	t.Run("no flag and no env yields empty", func(t *testing.T) {
		if got := ResolveModel("codex", ""); got != "" {
			t.Fatalf("ResolveModel() = %q, want empty", got)
		}
	})

	t.Run("env value is trimmed", func(t *testing.T) {
		t.Setenv("GH_AW_MODEL_DETECTION_CODEX", "  gpt-5.4  ")
		if got := ResolveModel("codex", ""); got != "gpt-5.4" {
			t.Fatalf("ResolveModel() = %q, want %q", got, "gpt-5.4")
		}
	})
}
