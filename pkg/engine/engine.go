// Package engine provides AI engine abstractions for threat detection.
// It supports multiple AI engines (copilot, claude, codex) and handles
// the invocation of the detection analysis.
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
	"github.com/github/gh-aw-threat-detection/pkg/runlog"
)

// AnalyzeOptions carries optional in-session reporting configuration.
type AnalyzeOptions struct {
	// ResultSinkPath, when non-empty, enables the threat_detection_result tool:
	// the engine provisions the wrapper on PATH, sets THREAT_DETECTION_RESULT_FILE,
	// and cancels the subprocess as soon as a valid result is written to this path.
	ResultSinkPath string
	// Logger, when non-nil, receives structured diagnostic events for the engine
	// invocation — including the resolved binary path, arg count, and model —
	// so failures can be diagnosed even when the engine subprocess produces no output.
	Logger *runlog.Logger
}

// Engine represents an AI engine capable of analyzing content for threats.
type Engine interface {
	// Analyze sends the prompt to the AI engine and returns the raw output.
	Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error)
}

// DefaultEngineID is the engine used when no engine is explicitly selected.
const DefaultEngineID = "copilot"

// Canonical normalizes an engine ID: it applies the default for an empty ID and
// lowercases the result, matching the resolution performed by New. Callers use
// it so audit/log records reflect the engine that will actually run.
func Canonical(engineID string) string {
	if engineID == "" {
		return DefaultEngineID
	}
	return strings.ToLower(engineID)
}

// Native CLI model environment variables. Setting these is equivalent to
// passing --model to the corresponding engine CLI. gh-aw uses the same names,
// so honoring them keeps the standalone detector consistent with the harness.
const (
	// copilotCLIModelEnvVar is read natively by the Copilot CLI. gh-aw sets it
	// (resolved from the GH_AW_MODEL_DETECTION_COPILOT Actions variable) in the
	// compiled standalone detection step.
	copilotCLIModelEnvVar = "COPILOT_MODEL"
	// claudeCLIModelEnvVar is read natively by the Claude CLI.
	claudeCLIModelEnvVar = "ANTHROPIC_MODEL"
)

// detectionModelEnvVar returns the gh-aw detection model environment variable
// name for the given canonical engine ID
// (GH_AW_MODEL_DETECTION_{COPILOT,CLAUDE,CODEX}).
func detectionModelEnvVar(canonicalEngineID string) string {
	return "GH_AW_MODEL_DETECTION_" + strings.ToUpper(canonicalEngineID)
}

// nativeCLIModelEnvVar returns the engine CLI's own model environment variable
// name for the given canonical engine ID, or "" when the engine's CLI has no
// native model env var (Codex selects the model via a -c model= flag).
func nativeCLIModelEnvVar(canonicalEngineID string) string {
	switch canonicalEngineID {
	case "copilot":
		return copilotCLIModelEnvVar
	case "claude":
		return claudeCLIModelEnvVar
	default:
		return ""
	}
}

// ResolveModel returns the model to use for detection, mirroring how gh-aw
// configures the model for each engine. Resolution precedence:
//
//  1. an explicit flagModel (the --model flag) always wins;
//  2. the engine-specific detection model variable set by gh-aw
//     (GH_AW_MODEL_DETECTION_{COPILOT,CLAUDE,CODEX});
//  3. the engine CLI's native model environment variable (COPILOT_MODEL for
//     copilot, ANTHROPIC_MODEL for claude), which gh-aw sets directly for some
//     engines in the compiled standalone detection step.
//
// This keeps the standalone detector consistent with the model the caller
// configured for the base (harness-driven) detection path, and makes the
// resolved model observable in logs and the run report.
func ResolveModel(engineID, flagModel string) string {
	if flagModel != "" {
		return flagModel
	}
	canonical := Canonical(engineID)
	if v := strings.TrimSpace(os.Getenv(detectionModelEnvVar(canonical))); v != "" {
		return v
	}
	if native := nativeCLIModelEnvVar(canonical); native != "" {
		return strings.TrimSpace(os.Getenv(native))
	}
	return ""
}

// New creates a new engine instance based on the engine ID.
// If engineID is empty, it defaults to "copilot".
func New(engineID, model string) (Engine, error) {
	switch Canonical(engineID) {
	case "copilot":
		return &copilotEngine{model: model}, nil
	case "claude":
		return &claudeEngine{model: model}, nil
	case "codex":
		return &codexEngine{model: model}, nil
	default:
		return nil, fmt.Errorf("unsupported engine: %q (supported: copilot, claude, codex)", engineID)
	}
}

// copilotEngine implements Engine using GitHub Copilot CLI.
type copilotEngine struct {
	model string
}

func (e *copilotEngine) Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error) {
	diag := cliDiag{engineID: "copilot", logger: opts.Logger}
	env := copilotEnv(e.model)
	env = append(env, copilotHarnessAwfConfigEnv()...)
	toolEnv, cleanup, err := maybeProvisionResultTool(opts.ResultSinkPath)
	if err != nil {
		return "", err
	}
	defer cleanup()
	env = append(env, toolEnv...)

	if harnessPath, ok := copilotHarnessPath(); ok {
		logEngineInvoke(opts.Logger, "copilot", nodeCommand(), append([]string{harnessPath, copilotBinary()}, copilotArgs("<prompt-file>")...), e.model)
		return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
			return copilotCommand(promptPath)
		}, "", env, opts.ResultSinkPath, diag)
	}
	logEngineInvoke(opts.Logger, "copilot", "copilot", copilotDirectArgs("<prompt-file>"), e.model)
	return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
		return "copilot", copilotDirectArgs(promptPath)
	}, prompt, env, opts.ResultSinkPath, diag)
}

// claudeEngine implements Engine using the Claude CLI.
type claudeEngine struct {
	model string
}

func (e *claudeEngine) Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error) {
	diag := cliDiag{engineID: "claude", logger: opts.Logger}
	toolEnv, cleanup, err := maybeProvisionResultTool(opts.ResultSinkPath)
	if err != nil {
		return "", err
	}
	defer cleanup()
	enableBashTool := opts.ResultSinkPath != ""

	if harnessPath, ok := claudeHarnessPath(); ok {
		logEngineInvoke(opts.Logger, "claude", nodeCommand(), append([]string{harnessPath, "claude"}, claudeHarnessArgs("<prompt-file>", e.model, enableBashTool)...), e.model)
		return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
			return nodeCommand(), append([]string{harnessPath, "claude"}, claudeHarnessArgs(promptPath, e.model, enableBashTool)...)
		}, "", toolEnv, opts.ResultSinkPath, diag)
	}
	args := claudeArgs(e.model, enableBashTool)
	logEngineInvoke(opts.Logger, "claude", "claude", args, e.model)
	return runCLIEnvWithSink(ctx, "claude", args, prompt, toolEnv, opts.ResultSinkPath, diag)
}

// codexEngine implements Engine using the Codex CLI.
type codexEngine struct {
	model string
}

func (e *codexEngine) Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error) {
	diag := cliDiag{engineID: "codex", logger: opts.Logger}
	toolEnv, cleanup, err := maybeProvisionResultTool(opts.ResultSinkPath)
	if err != nil {
		return "", err
	}
	defer cleanup()
	provider := codexForcedProvider(codexConfigPath())

	if harnessPath, ok := codexHarnessPath(); ok {
		logEngineInvoke(opts.Logger, "codex", nodeCommand(), append([]string{harnessPath, "codex"}, codexHarnessArgs("<prompt-file>", e.model, provider)...), e.model)
		return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
			return nodeCommand(), append([]string{harnessPath, "codex"}, codexHarnessArgs(promptPath, e.model, provider)...)
		}, "", toolEnv, opts.ResultSinkPath, diag)
	}
	// Codex embeds the prompt as a positional argument; pass a placeholder here
	// so the logged args do not expose the detection prompt.
	logEngineInvoke(opts.Logger, "codex", "codex", codexArgs(e.model, provider, "<prompt>"), e.model)
	return runCLIEnvWithSink(ctx, "codex", codexArgs(e.model, provider, ""), prompt, toolEnv, opts.ResultSinkPath, diag)
}

// maybeProvisionResultTool provisions the threat_detection_result tool when a
// sink path is configured, returning the env additions and a cleanup func. When
// sinkPath is empty it returns no env and a no-op cleanup.
func maybeProvisionResultTool(sinkPath string) (env []string, cleanup func(), err error) {
	if sinkPath == "" {
		return nil, func() {}, nil
	}
	return provisionResultTool(sinkPath)
}

func copilotCommand(promptPath string) (string, []string) {
	if harnessPath, ok := copilotHarnessPath(); ok {
		return nodeCommand(), append([]string{harnessPath, copilotBinary()}, copilotArgs(promptPath)...)
	}
	return "copilot", copilotDirectArgs(promptPath)
}

func copilotArgs(promptPath string) []string {
	return append(copilotDirectArgs(promptPath), "--prompt-file", promptPath)
}

func copilotDirectArgs(promptPath string) []string {
	args := []string{
		"--add-dir", filepath.Dir(promptPath),
		"--log-level", "all",
		"--disable-builtin-mcps",
		"--no-ask-user",
		"--allow-all-tools",
	}
	if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" {
		args = append(args, "--add-dir", workspace)
	}
	return args
}

func copilotHarnessPath() (string, bool) {
	return engineHarnessPath("copilot_harness.cjs")
}

func claudeHarnessPath() (string, bool) {
	return engineHarnessPath("claude_harness.cjs")
}

func codexHarnessPath() (string, bool) {
	return engineHarnessPath("codex_harness.cjs")
}

// engineHarnessPath returns the absolute path to a gh-aw harness script and
// true when the file exists. All engine harnesses live under the same
// $RUNNER_TEMP/gh-aw/actions/ directory.
func engineHarnessPath(filename string) (string, bool) {
	runnerTemp := os.Getenv("RUNNER_TEMP")
	if runnerTemp == "" {
		return "", false
	}
	harnessPath := filepath.Join(runnerTemp, "gh-aw", "actions", filename)
	if _, err := os.Stat(harnessPath); err != nil {
		return "", false
	}
	return harnessPath, true
}

func nodeCommand() string {
	if node := os.Getenv("GH_AW_NODE_BIN"); node != "" {
		return node
	}
	return "node"
}

func copilotBinary() string {
	if _, err := os.Stat("/usr/local/bin/copilot"); err == nil {
		return "/usr/local/bin/copilot"
	}
	return "copilot"
}

func copilotEnv(model string) []string {
	if model == "" {
		return nil
	}
	return []string{"COPILOT_MODEL=" + model}
}

// copilotHarnessDefaultAwfConfigPath is where the gh-aw copilot harness looks
// for the AWF config (which carries the model alias map) when
// GH_AW_AWF_CONFIG_PATH is unset.
const copilotHarnessDefaultAwfConfigPath = "/tmp/gh-aw/awf-config.json"

// copilotHarnessAwfConfigEnv points the gh-aw copilot harness at the AWF config
// file so it can resolve model aliases (e.g. "auto") against the api-proxy
// model map before spawning the Copilot CLI.
//
// Under AWF, the gh-aw agent job copies awf-config.json to the harness's default
// location (/tmp/gh-aw/awf-config.json), but the standalone detection job does
// not — it only mounts the config at $RUNNER_TEMP/gh-aw/awf-config.json. Without
// the alias map the harness passes the literal alias (e.g. COPILOT_MODEL=auto)
// straight to the Copilot CLI, which rejects it with
// "400 The requested model is not supported". Exporting GH_AW_AWF_CONFIG_PATH so
// the harness finds the mounted config restores the same alias resolution the
// agent job performs.
//
// It returns nil when GH_AW_AWF_CONFIG_PATH is already set, when the harness
// default path exists (the harness will find it there), or when no mounted
// config can be located.
func copilotHarnessAwfConfigEnv() []string {
	return copilotHarnessAwfConfigEnvAt(copilotHarnessDefaultAwfConfigPath)
}

// copilotHarnessAwfConfigEnvAt implements copilotHarnessAwfConfigEnv against an
// explicit harness default path so tests can stay hermetic.
func copilotHarnessAwfConfigEnvAt(harnessDefaultPath string) []string {
	if strings.TrimSpace(os.Getenv("GH_AW_AWF_CONFIG_PATH")) != "" {
		return nil
	}
	if _, err := os.Stat(harnessDefaultPath); err == nil {
		return nil
	}
	runnerTemp := strings.TrimSpace(os.Getenv("RUNNER_TEMP"))
	if runnerTemp == "" {
		return nil
	}
	candidate := filepath.Join(runnerTemp, "gh-aw", "awf-config.json")
	if _, err := os.Stat(candidate); err != nil {
		return nil
	}
	return []string{"GH_AW_AWF_CONFIG_PATH=" + candidate}
}

func claudeArgs(model string, allowBash bool) []string {
	args := []string{"--print", "--verbose", "--output-format", "stream-json"}
	if allowBash {
		args = append(args, "--allowed-tools", "Bash")
	}
	if model != "" {
		args = append(args, "--model", model)
	}
	return append(args, "-")
}

// claudeHarnessArgs builds the claude flags for harness invocation. It is
// identical to claudeArgs except that it uses --prompt-file <path> instead of
// the stdin sentinel "-", matching the invocation pattern used by the gh-aw
// claude_harness.cjs script.
func claudeHarnessArgs(promptPath, model string, allowBash bool) []string {
	args := []string{"--print", "--verbose", "--output-format", "stream-json"}
	if allowBash {
		args = append(args, "--allowed-tools", "Bash")
	}
	if model != "" {
		args = append(args, "--model", model)
	}
	return append(args, "--prompt-file", promptPath)
}

func codexArgs(model, provider, prompt string) []string {
	// The model and model_provider overrides MUST be passed as `-c` flags of the
	// `exec` subcommand (i.e. after `exec`). Codex ignores `-c` config overrides
	// placed before the subcommand, so prepending them silently drops the model
	// and provider selection — causing Codex to fall back to its default `openai`
	// provider (bypassing the AWF API proxy and hitting api.openai.com directly
	// with the isolation placeholder key, which returns 401).
	args := []string{"exec"}
	if model != "" {
		args = append(args, "-c", "model="+model)
	}
	if provider != "" {
		args = append(args, "-c", "model_provider="+provider)
	}
	args = append(args,
		"-c", "web_search=disabled",
		"-c", "fetch=disabled",
		"--dangerously-bypass-approvals-and-sandbox",
		"--skip-git-repo-check",
		"--",
		prompt,
	)
	return args
}

// codexHarnessArgs builds the codex flags for harness invocation. It is
// equivalent to codexArgs except that the prompt is passed via --prompt-file
// <path> instead of being embedded as a positional argument, matching the
// invocation pattern used by the gh-aw codex_harness.cjs script.
func codexHarnessArgs(promptPath, model, provider string) []string {
	args := []string{"exec"}
	if model != "" {
		args = append(args, "-c", "model="+model)
	}
	if provider != "" {
		args = append(args, "-c", "model_provider="+provider)
	}
	args = append(args,
		"-c", "web_search=disabled",
		"-c", "fetch=disabled",
		"--dangerously-bypass-approvals-and-sandbox",
		"--skip-git-repo-check",
		"--prompt-file", promptPath,
	)
	return args
}

// cliDiag carries the diagnostic identity of an engine invocation so the
// completion record can name the engine the user selected and reach the
// structured run log. The zero value disables the run-log record; the stderr
// line is always emitted because the job log is the only diagnostic sink that
// is always available.
type cliDiag struct {
	engineID string
	logger   *runlog.Logger
}

// runCLI executes a CLI command, passing the prompt via stdin, and returns its
// stdout output. Using stdin avoids OS argument length limits and prevents the
// prompt content from appearing in process listings.
func runCLI(ctx context.Context, name string, args []string, stdinData string) (string, error) {
	return runCLIEnv(ctx, name, args, stdinData, nil)
}

func runCLIWithPromptFile(ctx context.Context, prompt string, commandBuilder func(string) (string, []string), stdinData string, env []string, sinkPath string, diag cliDiag) (output string, err error) {
	promptFile, err := os.CreateTemp("", "threat-detect-prompt-*.txt")
	if err != nil {
		return "", fmt.Errorf("creating temporary prompt file: %w", err)
	}
	promptPath := promptFile.Name()
	defer func() {
		if removeErr := os.Remove(promptPath); err == nil && removeErr != nil {
			err = fmt.Errorf("removing temporary prompt file: %w", removeErr)
		}
	}()
	if _, err := promptFile.WriteString(prompt); err != nil {
		promptFile.Close()
		return "", fmt.Errorf("writing temporary prompt file: %w", err)
	}
	if err := promptFile.Close(); err != nil {
		return "", fmt.Errorf("closing temporary prompt file: %w", err)
	}
	name, args := commandBuilder(promptPath)
	return runCLIEnvWithSink(ctx, name, args, stdinData, env, sinkPath, diag)
}

func runCLIEnv(ctx context.Context, name string, args []string, stdinData string, env []string) (string, error) {
	return runCLIEnvWithSink(ctx, name, args, stdinData, env, "", cliDiag{})
}

// runCLIEnvWithSink runs the CLI command and, when sinkPath is non-empty, watches
// the sink file and cancels the subprocess as soon as a valid result is recorded.
// A subprocess error is suppressed when a valid sink result exists, because the
// process was intentionally killed once the verdict was reported.
func runCLIEnvWithSink(ctx context.Context, name string, args []string, stdinData string, env []string, sinkPath string, diag cliDiag) (string, error) {
	if sinkPath != "" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go watchResultSink(ctx, cancel, sinkPath)
	}

	cmd := exec.CommandContext(ctx, name, args...)
	if stdinData != "" {
		cmd.Stdin = strings.NewReader(stdinData)
	}
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	if sinkPath != "" {
		// Bound how long Run waits for stdout I/O after the process is killed on
		// early termination, in case the engine left descendants holding the pipe.
		cmd.WaitDelay = resultSinkPollInterval
	}

	var stdout, stderr bytes.Buffer
	// Tee both stdout and stderr to os.Stderr so that harness lifecycle output
	// ([copilot-harness], [claude-harness], [codex-harness]) and engine errors
	// appear in the GitHub Actions job log in real-time, mirroring the agent
	// job's "2>&1 | tee" pattern. The buffers are still populated for error
	// reporting and sink-result checking.
	cmd.Stdout = io.MultiWriter(&stdout, os.Stderr)
	cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)

	started := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(started)

	// Whether the verdict landed decides how a non-zero exit is interpreted, so
	// resolve it once and reuse it for both the diagnostics and the return value.
	verdictRecorded := false
	if sinkPath != "" {
		_, sinkErr := detector.ReadResultFile(sinkPath)
		verdictRecorded = sinkErr == nil
	}

	logEngineComplete(diag, name, engineCompletion{
		elapsed:         elapsed,
		exitCode:        processExitCode(cmd),
		stdoutBytes:     stdout.Len(),
		stderrBytes:     stderr.Len(),
		verdictRecorded: verdictRecorded,
		err:             runErr,
	})

	if runErr != nil {
		// The verdict was recorded; the process was intentionally killed.
		if verdictRecorded {
			return stdout.String(), nil
		}
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			return "", engineExitError(name, exitErr.ExitCode(), stdout.String(), stderr.String())
		}
		return "", fmt.Errorf("failed to execute %s: %w", name, runErr)
	}

	return stdout.String(), nil
}

// processExitCode reports the subprocess exit code, or -1 when the process
// never started or was terminated by a signal (which includes the deliberate
// kill performed once the verdict is recorded).
func processExitCode(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return -1
	}
	return cmd.ProcessState.ExitCode()
}

// engineCompletion is the observed outcome of one engine subprocess.
type engineCompletion struct {
	elapsed         time.Duration
	exitCode        int
	stdoutBytes     int
	stderrBytes     int
	verdictRecorded bool
	err             error
}

// logEngineComplete records how the engine subprocess ended, to both stderr and
// the structured run log. It is the counterpart of logEngineInvoke: without it,
// an engine that exits silently, hangs until the job timeout, or dies instantly
// on an auth failure are indistinguishable in the job log, because each simply
// produces no output after the invoke line.
//
// A subprocess killed after recording its verdict is expected, not a failure,
// so it is reported as terminated_early rather than as an error.
func logEngineComplete(diag cliDiag, name string, c engineCompletion) {
	terminatedEarly := c.err != nil && c.verdictRecorded
	outcome := "ok"
	switch {
	case terminatedEarly:
		outcome = "terminated_early"
	case c.err != nil:
		outcome = "failed"
	}

	engineID := diag.engineID
	if engineID == "" {
		engineID = "unknown"
	}

	fmt.Fprintf(engineStderr(),
		"[threat-detect] engine complete: engine=%s command=%s outcome=%s exit=%d duration=%s stdout=%dB stderr=%dB verdict_recorded=%t\n",
		engineID, name, outcome, c.exitCode, c.elapsed.Round(time.Millisecond), c.stdoutBytes, c.stderrBytes, c.verdictRecorded)

	fields := map[string]any{
		"engine":           engineID,
		"name":             name,
		"outcome":          outcome,
		"exit_code":        c.exitCode,
		"duration_ms":      c.elapsed.Milliseconds(),
		"stdout_bytes":     c.stdoutBytes,
		"stderr_bytes":     c.stderrBytes,
		"verdict_recorded": c.verdictRecorded,
	}
	// Only a genuine failure carries an error: the deliberate kill after a
	// recorded verdict would otherwise fill the log with "signal: killed".
	if c.err != nil && !terminatedEarly {
		fields["error"] = c.err.Error()
	}
	diag.logger.Info("engine_complete", fields)
}

// maxEngineOutputInError bounds how much captured engine output is embedded in a
// failure message, keeping the tail (where fatal errors and stack traces appear).
const maxEngineOutputInError = 4000

// engineExitError builds a diagnostic error for a non-zero engine exit. It
// surfaces both stderr and stdout because engines that emit structured output
// (notably `claude --output-format stream-json`) report the real failure —
// e.g. an invalid model or an API 4xx — as a JSON line on stdout while leaving
// stderr empty. Without stdout the caller only sees an opaque
// "<engine> exited with code N", which is not actionable.
func engineExitError(name string, exitCode int, stdout, stderr string) error {
	var parts []string
	if s := strings.TrimSpace(stderr); s != "" {
		parts = append(parts, "stderr: "+tailTruncate(s, maxEngineOutputInError))
	}
	if s := strings.TrimSpace(stdout); s != "" {
		if msg := extractStreamJSONError(s); msg != "" {
			parts = append(parts, "engine error: "+tailTruncate(msg, maxEngineOutputInError))
		} else {
			parts = append(parts, "stdout: "+tailTruncate(s, maxEngineOutputInError))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "no output captured on stdout or stderr")
	}
	return fmt.Errorf("%s exited with code %d: %s", name, exitCode, strings.Join(parts, "; "))
}

// tailTruncate returns at most max characters from the end of s, prefixing an
// ellipsis marker when content was dropped. The tail is kept because fatal
// engine diagnostics are emitted last.
func tailTruncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return "...(truncated)... " + s[len(s)-max:]
}

// engineInvokeStderr overrides the destination for the human-readable engine
// diagnostic lines. It is nil in production, where the lines resolve to
// os.Stderr at emit time (so a caller that replaces os.Stderr, as the CLI tests
// do, still captures them); tests set it directly to assert on the output.
var engineInvokeStderr io.Writer

// engineStderr resolves the destination for engine diagnostic lines.
func engineStderr() io.Writer {
	if engineInvokeStderr != nil {
		return engineInvokeStderr
	}
	return os.Stderr
}

// logEngineInvoke logs the engine subprocess invocation details to both the
// structured run log and stderr. It is called immediately before the engine
// process starts so that silent engine failures (exit with no output) leave
// enough context in the logs to diagnose the root cause.
//
// args must not contain sensitive data (prompt text, API keys). For engines
// that embed the prompt in argv (Codex), callers pass a safe placeholder.
//
// engineID is the canonical engine selected by the user (copilot/claude/codex),
// while name is the process actually spawned — which is often "node" when the
// gh-aw harness wrapper is used. Logging both makes the job log unambiguous
// about which engine and model were requested.
func logEngineInvoke(logger *runlog.Logger, engineID, name string, args []string, model string) {
	resolvedPath, err := exec.LookPath(name)
	if err != nil {
		resolvedPath = ""
	}

	// Note when the actual process differs from the engine (harness wrapper),
	// so "node" in the command does not obscure which engine is running.
	command := name
	if resolvedPath != "" {
		command = fmt.Sprintf("%s (%s)", name, resolvedPath)
	} else {
		command = fmt.Sprintf("%s (binary not found in PATH)", name)
	}

	// Describe the model on stderr so the job log makes clear which model each
	// engine was asked for. An empty model means no override was passed and the
	// engine CLI selects its own default. The model can originate from --model or
	// an environment variable, so it is quoted with %q: a value containing
	// newlines or terminal control sequences would otherwise split or forge the
	// diagnostic line, and quoting keeps any control characters escaped on one
	// physical line.
	modelDesc := "(none; using engine default)"
	if model != "" {
		modelDesc = fmt.Sprintf("%q", model)
	}

	// Emit to stderr so the message appears in the GitHub Actions job log even
	// when the engine subprocess produces no output of its own.
	fmt.Fprintf(engineStderr(), "[threat-detect] engine invoke: engine=%s model=%s command=%s args=%d\n", engineID, modelDesc, command, len(args))

	fields := map[string]any{
		"engine":     engineID,
		"name":       name,
		"args":       args,
		"args_count": len(args),
	}
	if resolvedPath != "" {
		fields["binary"] = resolvedPath
	} else {
		fields["binary_not_found"] = true
	}
	if model != "" {
		fields["model"] = model
	}
	logger.Info("engine_invoke", fields)
}

// extractStreamJSONError scans newline-delimited JSON output (the format used by
// returns a concatenated, human-readable summary. It returns "" when no
// structured error is found, so callers can fall back to the raw stdout tail.
func extractStreamJSONError(stdout string) string {
	var messages []string
	seen := make(map[string]struct{})
	add := func(msg string) {
		msg = strings.TrimSpace(msg)
		if msg == "" {
			return
		}
		if _, ok := seen[msg]; ok {
			return
		}
		seen[msg] = struct{}{}
		messages = append(messages, msg)
	}

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		// Shape 1: {"type":"error","error":{"type":..,"message":..}}
		if errField, ok := obj["error"].(map[string]any); ok {
			if msg, ok := errField["message"].(string); ok {
				add(msg)
				continue
			}
		}
		// Shape 2: {"type":"result","is_error":true,"result":"..."}
		if isErr, _ := obj["is_error"].(bool); isErr {
			if res, ok := obj["result"].(string); ok {
				add(res)
				continue
			}
			if sub, ok := obj["subtype"].(string); ok {
				add(sub)
				continue
			}
		}
		// Shape 3: top-level {"type":"error","message":"..."}.
		if t, _ := obj["type"].(string); t == "error" {
			if msg, ok := obj["message"].(string); ok {
				add(msg)
			}
		}
	}
	return strings.Join(messages, " | ")
}
