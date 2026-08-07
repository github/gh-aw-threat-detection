package engine

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Preflight check statuses. They are deliberately coarse so a reader can scan
// the job log for anything that is not "ok" or "set".
const (
	// PreflightOK marks a resolved resource (a binary found on PATH, a
	// harness script present on disk).
	PreflightOK = "ok"
	// PreflightMissing marks a resource that was looked for and not found.
	// It is not necessarily fatal: an absent gh-aw harness simply means the
	// engine CLI is invoked directly.
	PreflightMissing = "missing"
	// PreflightSet / PreflightUnset mark the presence of an environment
	// variable, never its value.
	PreflightSet   = "set"
	PreflightUnset = "unset"
)

// PreflightCheck is a single observation about the environment the detection
// engine is about to run in. Checks are diagnostics only: none of them gate the
// run, because the authoritative answer to "can this engine run here" is the
// engine subprocess itself, and a check that guessed wrong would fail a run
// that would otherwise have succeeded.
type PreflightCheck struct {
	// Name identifies the observation (e.g. "engine_binary", "COPILOT_GITHUB_TOKEN").
	Name string `json:"name"`
	// Status is one of the Preflight* constants.
	Status string `json:"status"`
	// Detail carries the non-sensitive specifics: a resolved path, a model
	// name, a redacted URL, or the character length of a secret. It is empty
	// when the status says everything.
	Detail string `json:"detail,omitempty"`
}

// engineEnvVar describes an environment variable worth reporting for an engine,
// and whether its value may be echoed.
type engineEnvVar struct {
	name string
	// secret suppresses the value; only presence and length are reported.
	secret bool
}

// engineEnvVars returns the environment variables that determine whether a
// given engine can authenticate and which endpoint it talks to. Reporting their
// presence turns the most common detection-job failure — a missing or
// misrouted credential, which the engine reports only as an opaque 401 — into a
// self-evident line in the job log.
func engineEnvVars(canonicalEngineID string) []engineEnvVar {
	switch canonicalEngineID {
	case "copilot":
		return []engineEnvVar{
			{name: "COPILOT_GITHUB_TOKEN", secret: true},
			{name: "GITHUB_TOKEN", secret: true},
			{name: copilotCLIModelEnvVar},
		}
	case "claude":
		return []engineEnvVar{
			{name: "ANTHROPIC_API_KEY", secret: true},
			{name: "ANTHROPIC_AUTH_TOKEN", secret: true},
			{name: "ANTHROPIC_BASE_URL"},
			{name: claudeCLIModelEnvVar},
		}
	case "codex":
		return []engineEnvVar{
			{name: "OPENAI_API_KEY", secret: true},
			{name: "CODEX_API_KEY", secret: true},
			{name: "OPENAI_BASE_URL"},
			{name: "CODEX_HOME"},
		}
	default:
		return nil
	}
}

// engineBinaryName returns the CLI command a given engine invokes. It mirrors
// the resolution performed by the Analyze paths so the reported binary is the
// one that will actually be executed: with a harness present, Copilot is
// launched through copilotBinary() (which prefers /usr/local/bin/copilot),
// while the direct path resolves a plain "copilot" against PATH.
func engineBinaryName(canonicalEngineID string, harnessFound bool) string {
	switch canonicalEngineID {
	case "copilot":
		if harnessFound {
			return copilotBinary()
		}
		return "copilot"
	case "claude", "codex":
		return canonicalEngineID
	default:
		return ""
	}
}

// engineHarnessName returns the gh-aw harness script filename for an engine.
func engineHarnessName(canonicalEngineID string) string {
	switch canonicalEngineID {
	case "copilot", "claude", "codex":
		return canonicalEngineID + "_harness.cjs"
	default:
		return ""
	}
}

// Preflight collects environment diagnostics for the engine that is about to
// run: which binary will be executed, whether the gh-aw harness wrapper is in
// play, which credentials are present, and how egress is routed. It never
// reveals a secret value and never fails — an environment it cannot describe
// simply yields fewer checks.
//
// model is the already-resolved model (see ResolveModel), reported so the job
// log records the value actually passed to the engine rather than requiring the
// reader to re-derive it from the flag and environment precedence rules.
func Preflight(engineID, model string) []PreflightCheck {
	canonical := Canonical(engineID)
	checks := []PreflightCheck{{Name: "engine", Status: PreflightOK, Detail: canonical}}

	if model != "" {
		checks = append(checks, PreflightCheck{Name: "model", Status: PreflightOK, Detail: model})
	} else {
		checks = append(checks, PreflightCheck{Name: "model", Status: PreflightUnset, Detail: "engine default"})
	}

	// The harness decides which process is actually spawned, so report it
	// before the binaries: "node" in the invoke line is only explicable once
	// the reader knows a harness was found.
	harnessFound := false
	if name := engineHarnessName(canonical); name != "" {
		if path, ok := engineHarnessPath(name); ok {
			harnessFound = true
			checks = append(checks, PreflightCheck{Name: "harness", Status: PreflightOK, Detail: path})
		} else {
			checks = append(checks, PreflightCheck{Name: "harness", Status: PreflightMissing, Detail: harnessSearchDetail(name)})
		}
	}
	if harnessFound {
		checks = append(checks, lookPathCheck("node", nodeCommand()))
	}
	if binary := engineBinaryName(canonical, harnessFound); binary != "" {
		checks = append(checks, lookPathCheck("engine_binary", binary))
	}

	for _, v := range engineEnvVars(canonical) {
		checks = append(checks, envCheck(v))
	}

	// Egress routing. Under AWF every engine call traverses the Squid proxy, so
	// an unset HTTPS_PROXY (or a NO_PROXY that excludes the API host) explains
	// connection failures that otherwise look like engine bugs.
	for _, name := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"} {
		checks = append(checks, proxyCheck(name))
	}

	// Runner directories: RUNNER_TEMP is how the harness and the AWF config are
	// located, and GITHUB_WORKSPACE is added to the engine's allowed dirs.
	for _, name := range []string{"RUNNER_TEMP", "GITHUB_WORKSPACE"} {
		checks = append(checks, dirCheck(name))
	}

	return checks
}

// harnessSearchDetail explains where the harness was looked for, so a missing
// harness is actionable rather than merely reported.
func harnessSearchDetail(filename string) string {
	runnerTemp := os.Getenv("RUNNER_TEMP")
	if runnerTemp == "" {
		return "RUNNER_TEMP unset; invoking the engine CLI directly"
	}
	return "not at " + filepath.Join(runnerTemp, "gh-aw", "actions", filename) + "; invoking the engine CLI directly"
}

// lookPathCheck resolves command against PATH and reports the absolute path.
func lookPathCheck(name, command string) PreflightCheck {
	resolved, err := exec.LookPath(command)
	if err != nil {
		return PreflightCheck{Name: name, Status: PreflightMissing, Detail: command + " not found in PATH"}
	}
	return PreflightCheck{Name: name, Status: PreflightOK, Detail: resolved}
}

// envCheck reports whether an environment variable is set. A secret variable
// reports only its length: enough to distinguish "set but empty" and an
// obviously truncated value from a plausible credential, without disclosing it.
// A value consisting only of whitespace is reported as unset because every
// consumer trims it.
func envCheck(v engineEnvVar) PreflightCheck {
	value := os.Getenv(v.name)
	if strings.TrimSpace(value) == "" {
		return PreflightCheck{Name: v.name, Status: PreflightUnset}
	}
	if v.secret {
		return PreflightCheck{Name: v.name, Status: PreflightSet, Detail: fmt.Sprintf("%d characters", len(value))}
	}
	return PreflightCheck{Name: v.name, Status: PreflightSet, Detail: sanitizeDetail(value)}
}

// proxyCheck reports a proxy variable with any embedded credentials removed.
func proxyCheck(name string) PreflightCheck {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return PreflightCheck{Name: name, Status: PreflightUnset}
	}
	return PreflightCheck{Name: name, Status: PreflightSet, Detail: sanitizeDetail(redactURLCredentials(value))}
}

// dirCheck reports a directory-valued environment variable and whether the
// directory it names actually exists, since a path that is set but not mounted
// inside the AWF sandbox is a distinct and common failure.
func dirCheck(name string) PreflightCheck {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return PreflightCheck{Name: name, Status: PreflightUnset}
	}
	detail := sanitizeDetail(value)
	if info, err := os.Stat(value); err != nil || !info.IsDir() {
		return PreflightCheck{Name: name, Status: PreflightMissing, Detail: detail + " (not a readable directory)"}
	}
	return PreflightCheck{Name: name, Status: PreflightSet, Detail: detail}
}

// redactURLCredentials replaces the userinfo component of a URL with the
// literal "redacted" so a proxy configured as https://user:password@proxy:3128
// can be reported without leaking the password. A placeholder word is used
// rather than a mask like "***" because URL encoding would escape the
// punctuation and render the detail unreadable. Values that do not parse as a
// URL are returned as-is; they carry no userinfo to redact.
func redactURLCredentials(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.User == nil {
		return value
	}
	u.User = url.User("redacted")
	return u.String()
}

// sanitizeDetail confines an environment-derived value to a single physical log
// line. These values come from the host environment, which in a compromised or
// merely careless configuration could contain a newline — enough to forge a
// "::error::" workflow command or an extra preflight line. Control characters
// are escaped rather than dropped so the real value stays diagnosable.
func sanitizeDetail(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// FormatPreflightLines renders the checks as human-readable stderr lines, one
// per check, each prefixed so they are greppable in a GitHub Actions job log.
func FormatPreflightLines(checks []PreflightCheck) []string {
	lines := make([]string, 0, len(checks))
	for _, c := range checks {
		line := fmt.Sprintf("[threat-detect] preflight: %s=%s", c.Name, c.Status)
		if c.Detail != "" {
			line += " (" + c.Detail + ")"
		}
		lines = append(lines, line)
	}
	return lines
}
