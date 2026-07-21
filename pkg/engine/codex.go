package engine

import (
	"os"
	"path/filepath"
	"strings"
)

// codexConfigPath returns the path to the Codex config.toml, honoring CODEX_HOME
// and falling back to ~/.codex/config.toml. It returns "" when neither can be
// resolved.
func codexConfigPath() string {
	if home := os.Getenv("CODEX_HOME"); home != "" {
		return filepath.Join(home, "config.toml")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".codex", "config.toml")
	}
	return ""
}

// codexForcedProvider inspects the Codex config file and returns the name of a
// custom model provider that must be selected explicitly on the command line.
//
// It returns "" when the config already selects a provider at the top level
// (which Codex honors), when the config cannot be read, or when no unambiguous
// custom provider is defined. This repairs configs where the top-level
// `model_provider` key was accidentally emitted under another table (for example
// `[history]`), which Codex silently ignores — causing it to fall back to the
// default `openai` provider and bypass the AWF API proxy.
func codexForcedProvider(configPath string) string {
	if configPath == "" {
		return ""
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	return parseCodexForcedProvider(string(data))
}

// parseCodexForcedProvider scans TOML content for a top-level `model_provider`
// selection and any `[model_providers.<name>]` tables. See codexForcedProvider
// for the return-value semantics.
func parseCodexForcedProvider(content string) string {
	section := "" // current table header; "" means top level
	topLevelProvider := ""
	var providers []string

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if name, ok := strings.CutPrefix(section, "model_providers."); ok {
				name = strings.Trim(strings.TrimSpace(name), `"'`)
				if name != "" {
					providers = append(providers, name)
				}
			}
			continue
		}
		if section != "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(key) == "model_provider" {
			topLevelProvider = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}

	if topLevelProvider != "" {
		// Codex already honors a correctly-placed selection; don't override it.
		return ""
	}
	if len(providers) == 1 {
		return providers[0]
	}
	return ""
}
