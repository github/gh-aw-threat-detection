package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findCheck returns the check with the given name, failing the test when absent.
func findCheck(t *testing.T, checks []PreflightCheck, name string) PreflightCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no preflight check named %q in %+v", name, checks)
	return PreflightCheck{}
}

func hasCheck(checks []PreflightCheck, name string) bool {
	for _, c := range checks {
		if c.Name == name {
			return true
		}
	}
	return false
}

func TestPreflight_ReportsEngineAndModel(t *testing.T) {
	t.Setenv("RUNNER_TEMP", t.TempDir())

	checks := Preflight("", "")
	if got := findCheck(t, checks, "engine"); got.Detail != DefaultEngineID {
		t.Errorf("engine detail = %q, want %q", got.Detail, DefaultEngineID)
	}
	if got := findCheck(t, checks, "model"); got.Status != PreflightUnset {
		t.Errorf("model status = %q, want %q", got.Status, PreflightUnset)
	}

	checks = Preflight("CODEX", "gpt-5-codex")
	if got := findCheck(t, checks, "engine"); got.Detail != "codex" {
		t.Errorf("engine detail = %q, want codex", got.Detail)
	}
	if got := findCheck(t, checks, "model"); got.Status != PreflightOK || got.Detail != "gpt-5-codex" {
		t.Errorf("model check = %+v, want ok/gpt-5-codex", got)
	}
}

func TestPreflight_SecretValuesAreNeverEchoed(t *testing.T) {
	const token = "ghp_supersecretvalue"
	t.Setenv("RUNNER_TEMP", t.TempDir())
	t.Setenv("COPILOT_GITHUB_TOKEN", token)

	checks := Preflight("copilot", "")
	got := findCheck(t, checks, "COPILOT_GITHUB_TOKEN")
	if got.Status != PreflightSet {
		t.Errorf("status = %q, want %q", got.Status, PreflightSet)
	}
	if strings.Contains(got.Detail, token) {
		t.Fatalf("preflight leaked the secret value: %q", got.Detail)
	}
	if want := "20 characters"; got.Detail != want {
		t.Errorf("detail = %q, want %q", got.Detail, want)
	}

	// The rendered job-log lines must not leak it either.
	rendered := strings.Join(FormatPreflightLines(checks), "\n")
	if strings.Contains(rendered, token) {
		t.Fatalf("rendered preflight leaked the secret value:\n%s", rendered)
	}
}

func TestPreflight_WhitespaceOnlySecretIsUnset(t *testing.T) {
	t.Setenv("RUNNER_TEMP", t.TempDir())
	t.Setenv("ANTHROPIC_API_KEY", "   ")

	got := findCheck(t, Preflight("claude", ""), "ANTHROPIC_API_KEY")
	if got.Status != PreflightUnset {
		t.Errorf("status = %q, want %q", got.Status, PreflightUnset)
	}
	if got.Detail != "" {
		t.Errorf("detail = %q, want empty", got.Detail)
	}
}

func TestPreflight_RedactsProxyCredentials(t *testing.T) {
	t.Setenv("RUNNER_TEMP", t.TempDir())
	t.Setenv("HTTPS_PROXY", "https://alice:hunter2@proxy.internal:3128")

	got := findCheck(t, Preflight("copilot", ""), "HTTPS_PROXY")
	if strings.Contains(got.Detail, "hunter2") {
		t.Fatalf("proxy password leaked: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "proxy.internal:3128") {
		t.Errorf("detail = %q, should retain the proxy host", got.Detail)
	}
}

func TestPreflight_SanitizesControlCharacters(t *testing.T) {
	t.Setenv("RUNNER_TEMP", t.TempDir())
	// A host-supplied value with an embedded newline must not be able to forge
	// an extra preflight line or a workflow command.
	t.Setenv("ANTHROPIC_BASE_URL", "https://ok\n::error::forged")

	checks := Preflight("claude", "")
	got := findCheck(t, checks, "ANTHROPIC_BASE_URL")
	if strings.Contains(got.Detail, "\n") {
		t.Fatalf("detail contains a raw newline: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, `\n`) {
		t.Errorf("detail = %q, want an escaped newline", got.Detail)
	}
	for _, line := range FormatPreflightLines(checks) {
		if strings.Contains(line, "\n") {
			t.Errorf("preflight line is not a single physical line: %q", line)
		}
	}
}

func TestPreflight_HarnessDetection(t *testing.T) {
	runnerTemp := t.TempDir()
	t.Setenv("RUNNER_TEMP", runnerTemp)

	// Without the harness file, the check explains where it looked.
	got := findCheck(t, Preflight("copilot", ""), "harness")
	if got.Status != PreflightMissing {
		t.Fatalf("harness status = %q, want %q", got.Status, PreflightMissing)
	}
	if !strings.Contains(got.Detail, "copilot_harness.cjs") {
		t.Errorf("detail = %q, should name the searched path", got.Detail)
	}
	if hasCheck(Preflight("copilot", ""), "node") {
		t.Error("node should not be checked when no harness is present")
	}

	actionsDir := filepath.Join(runnerTemp, "gh-aw", "actions")
	if err := os.MkdirAll(actionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(actionsDir, "copilot_harness.cjs")
	if err := os.WriteFile(harness, []byte("// harness"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := Preflight("copilot", "")
	got = findCheck(t, checks, "harness")
	if got.Status != PreflightOK || got.Detail != harness {
		t.Errorf("harness check = %+v, want ok/%s", got, harness)
	}
	// The harness spawns node, so node's resolution becomes relevant.
	if !hasCheck(checks, "node") {
		t.Error("node should be checked when the harness is present")
	}
}

func TestPreflight_MissingBinary(t *testing.T) {
	t.Setenv("RUNNER_TEMP", t.TempDir())
	t.Setenv("PATH", t.TempDir())

	got := findCheck(t, Preflight("claude", ""), "engine_binary")
	if got.Status != PreflightMissing {
		t.Errorf("engine_binary status = %q, want %q", got.Status, PreflightMissing)
	}
	if !strings.Contains(got.Detail, "not found in PATH") {
		t.Errorf("detail = %q, want a PATH explanation", got.Detail)
	}
}

func TestPreflight_DirectoryChecks(t *testing.T) {
	runnerTemp := t.TempDir()
	t.Setenv("RUNNER_TEMP", runnerTemp)
	t.Setenv("GITHUB_WORKSPACE", filepath.Join(runnerTemp, "does-not-exist"))

	if got := findCheck(t, Preflight("copilot", ""), "RUNNER_TEMP"); got.Status != PreflightSet {
		t.Errorf("RUNNER_TEMP status = %q, want %q", got.Status, PreflightSet)
	}
	got := findCheck(t, Preflight("copilot", ""), "GITHUB_WORKSPACE")
	if got.Status != PreflightMissing {
		t.Errorf("GITHUB_WORKSPACE status = %q, want %q", got.Status, PreflightMissing)
	}
	if !strings.Contains(got.Detail, "not a readable directory") {
		t.Errorf("detail = %q, should explain the directory is unusable", got.Detail)
	}
}

func TestPreflight_EngineSpecificVariables(t *testing.T) {
	t.Setenv("RUNNER_TEMP", t.TempDir())

	// Each engine reports only its own credentials, so an unrelated engine's
	// unset key is not misread as this run's problem.
	copilotChecks := Preflight("copilot", "")
	if hasCheck(copilotChecks, "ANTHROPIC_API_KEY") {
		t.Error("copilot preflight should not report ANTHROPIC_API_KEY")
	}
	if !hasCheck(copilotChecks, "COPILOT_GITHUB_TOKEN") {
		t.Error("copilot preflight should report COPILOT_GITHUB_TOKEN")
	}
	if !hasCheck(Preflight("codex", ""), "OPENAI_API_KEY") {
		t.Error("codex preflight should report OPENAI_API_KEY")
	}
}

func TestFormatPreflightLines(t *testing.T) {
	lines := FormatPreflightLines([]PreflightCheck{
		{Name: "engine", Status: PreflightOK, Detail: "copilot"},
		{Name: "GITHUB_TOKEN", Status: PreflightUnset},
	})
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	if want := "[threat-detect] preflight: engine=ok (copilot)"; lines[0] != want {
		t.Errorf("line 0 = %q, want %q", lines[0], want)
	}
	if want := "[threat-detect] preflight: GITHUB_TOKEN=unset"; lines[1] != want {
		t.Errorf("line 1 = %q, want %q", lines[1], want)
	}
}

func TestRedactURLCredentials(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"scheme with userinfo", "https://alice:hunter2@proxy:3128", "https://redacted@proxy:3128"},
		// url.Parse reads this as scheme "alice" with an opaque body and no
		// User, so a parser-based redaction would leak the password verbatim.
		{"scheme-less userinfo", "alice:hunter2@proxy:3128", "redacted@proxy:3128"},
		// url.Parse rejects this outright ("first path segment cannot contain
		// colon"), which a parser-based redaction would pass through unchanged.
		{"scheme-less single token", "token123@proxy:3128", "redacted@proxy:3128"},
		{"protocol-relative", "//alice:hunter2@proxy:3128", "//redacted@proxy:3128"},
		{"at inside credential", "https://alice:pa@ss@proxy:3128", "https://redacted@proxy:3128"},
		{"with path", "http://alice:hunter2@proxy:3128/pac.txt", "http://redacted@proxy:3128/pac.txt"},
		// An "@" after the authority belongs to the path, not to a credential.
		{"at only in path", "http://proxy:3128/a@b", "http://proxy:3128/a@b"},
		{"no credentials", "http://proxy.internal:3128", "http://proxy.internal:3128"},
		{"not a url", "not a url at all", "not a url at all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactURLCredentials(tc.in)
			if got != tc.want {
				t.Errorf("redactURLCredentials(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.Contains(got, "hunter2") || strings.Contains(got, "token123") {
				t.Errorf("redactURLCredentials(%q) leaked a credential: %q", tc.in, got)
			}
		})
	}
}

func TestPreflight_RedactsSchemeLessProxyCredentials(t *testing.T) {
	t.Setenv("RUNNER_TEMP", t.TempDir())
	t.Setenv("HTTP_PROXY", "alice:hunter2@proxy.internal:3128")

	checks := Preflight("copilot", "")
	got := findCheck(t, checks, "HTTP_PROXY")
	if strings.Contains(got.Detail, "hunter2") {
		t.Fatalf("scheme-less proxy password leaked: %q", got.Detail)
	}
	rendered := strings.Join(FormatPreflightLines(checks), "\n")
	if strings.Contains(rendered, "hunter2") {
		t.Fatalf("rendered preflight leaked the proxy password:\n%s", rendered)
	}
}

func TestPreflight_SecretLengthCountsRunes(t *testing.T) {
	t.Setenv("RUNNER_TEMP", t.TempDir())
	// Five runes, but nine UTF-8 bytes. The diagnostic promises characters, so
	// an operator comparing against the credential they configured must see 5.
	t.Setenv("ANTHROPIC_API_KEY", "kéy😀z")

	got := findCheck(t, Preflight("claude", ""), "ANTHROPIC_API_KEY")
	if want := "5 characters"; got.Detail != want {
		t.Errorf("detail = %q, want %q", got.Detail, want)
	}
}

// Every detail is environment-derived one way or another, so sanitization must
// happen for all of them rather than only the values whose producer remembered.
func TestPreflight_SanitizesEveryEnvironmentDerivedDetail(t *testing.T) {
	runnerTemp := t.TempDir()
	forged := "x\n::error::forged"

	cases := []struct {
		name  string
		env   map[string]string
		check string
	}{
		// The model reaches preflight from the resolved value, which can come
		// from COPILOT_MODEL / ANTHROPIC_MODEL / GH_AW_MODEL_DETECTION_*.
		{"model", nil, "model"},
		// The harness search message embeds RUNNER_TEMP.
		{"harness", map[string]string{"RUNNER_TEMP": filepath.Join(runnerTemp, forged)}, "harness"},
		// Binary paths are resolved against PATH.
		{"engine_binary", map[string]string{"PATH": filepath.Join(runnerTemp, forged)}, "engine_binary"},
		{"dir", map[string]string{"GITHUB_WORKSPACE": forged}, "GITHUB_WORKSPACE"},
		{"proxy", map[string]string{"NO_PROXY": forged}, "NO_PROXY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RUNNER_TEMP", runnerTemp)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			model := ""
			if tc.check == "model" {
				model = forged
			}

			checks := Preflight("copilot", model)
			got := findCheck(t, checks, tc.check)
			if strings.Contains(got.Detail, "\n") {
				t.Errorf("%s detail contains a raw newline: %q", tc.check, got.Detail)
			}
			for _, line := range FormatPreflightLines(checks) {
				if strings.Contains(line, "\n") {
					t.Errorf("preflight line is not a single physical line: %q", line)
				}
			}
		})
	}
}
