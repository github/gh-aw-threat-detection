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
	"strconv"
	"strings"
	"syscall"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

// AnalyzeOptions carries optional in-session reporting configuration.
type AnalyzeOptions struct {
	// ResultSinkPath, when non-empty, enables the threat_detection_result tool:
	// the engine provisions the wrapper on PATH, sets THREAT_DETECTION_RESULT_FILE,
	// and cancels the subprocess as soon as a valid result is written to this path.
	ResultSinkPath string

	// Eligibility, when non-nil, is transported to the report-result subprocess
	// so it can reject structurally impossible verdicts (e.g. malicious_patch
	// with zero patch files). When nil, the subprocess defaults to permissive
	// eligibility — callers that predate the field are not tightened.
	Eligibility *detector.Eligibility

	// MaxTurns bounds the number of agentic tool-use turns the engine may take
	// before the CLI exits on its own. Zero means "no cap". The value is
	// exported to the engine subprocess as GH_AW_MAX_TURNS (matching gh-aw's
	// universal turn-limit contract, honored by all supported engine harnesses)
	// and, for engines whose bare CLI accepts a dedicated flag, also passed as
	// an explicit flag (e.g. `--max-turns` for Claude). The bare Copilot CLI
	// has no equivalent flag; only the wall-clock timeout constrains it there.
	MaxTurns int
}

// MaxTurnsEnvVar is the environment-variable name used to convey the turn cap
// to engine harnesses. It matches gh-aw's `GH_AW_MAX_TURNS` contract so the
// standalone detector and the harness-driven detection path enforce turn
// limits through a single mechanism.
const MaxTurnsEnvVar = "GH_AW_MAX_TURNS"

// scrubEngineInheritedEnv lists environment variables that must never be
// silently inherited from the detector's parent process into an engine
// subprocess. Currently only GH_AW_MAX_TURNS: the detector always resolves the
// turn cap from flag/env before invoking an engine (see envMaxTurns), and if
// the caller disables it (--max-turns=0), inheriting an ambient GH_AW_MAX_TURNS
// from the parent process would silently defeat the disablement. The resolved
// value is re-added explicitly via maxTurnsEnv when the cap is non-zero.
var scrubEngineInheritedEnv = []string{MaxTurnsEnvVar}

// filterEnv returns a copy of env with entries whose key is in drop removed.
// It is used to scrub inherited variables from the parent process's
// environment before an engine subprocess is launched (see
// scrubEngineInheritedEnv).
func filterEnv(env, drop []string) []string {
	if len(drop) == 0 {
		return env
	}
	dropSet := make(map[string]struct{}, len(drop))
	for _, k := range drop {
		dropSet[k] = struct{}{}
	}
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key := entry
		if idx := strings.IndexByte(entry, '='); idx >= 0 {
			key = entry[:idx]
		}
		if _, drop := dropSet[key]; drop {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// maxTurnsEnv returns the env-var assignment used to convey the turn cap to
// engine subprocesses, or nil when no cap is configured. When MaxTurns is 0
// the caller must not export the variable so a downstream harness can still
// fall back to its own default rather than treating "0" as a hard cap; the
// parent process's own GH_AW_MAX_TURNS is scrubbed by runCLIEnvWithSink via
// scrubEngineInheritedEnv, so an inherited value cannot leak past this either.
func maxTurnsEnv(maxTurns int) []string {
	if maxTurns <= 0 {
		return nil
	}
	return []string{fmt.Sprintf("%s=%d", MaxTurnsEnvVar, maxTurns)}
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
	env := copilotEnv(e.model)
	env = append(env, copilotHarnessAwfConfigEnv()...)
	env = append(env, maxTurnsEnv(opts.MaxTurns)...)
	toolEnv, cleanup, err := maybeProvisionResultTool(opts.ResultSinkPath)
	if err != nil {
		return "", err
	}
	defer cleanup()
	toolEnv = appendEligibilityEnv(toolEnv, opts.Eligibility)
	env = append(env, toolEnv...)

	if harnessPath, ok := copilotHarnessPath(); ok {
		logEngineInvoke("copilot", nodeCommand(), append([]string{harnessPath, copilotBinary()}, copilotArgs("<prompt-file>")...), e.model)
		return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
			return copilotCommand(promptPath)
		}, "", env, opts.ResultSinkPath)
	}
	if opts.MaxTurns > 0 {
		// The bare Copilot CLI does not accept a turn-limit flag; the wall-clock
		// timeout is the only bound for the direct-CLI path. Announce this once
		// per invocation so a caller who set --max-turns knows the cap will not
		// be enforced by the CLI itself.
		fmt.Fprintf(engineInvokeStderr, "[threat-detect] copilot bare CLI does not accept a turn-limit flag; --max-turns=%d is advisory here and the wall-clock timeout remains the only cap\n", opts.MaxTurns)
	}
	logEngineInvoke("copilot", "copilot", copilotDirectArgs("<prompt-file>"), e.model)
	return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
		return "copilot", copilotDirectArgs(promptPath)
	}, prompt, env, opts.ResultSinkPath)
}

// claudeEngine implements Engine using the Claude CLI.
type claudeEngine struct {
	model string
}

func (e *claudeEngine) Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error) {
	toolEnv, cleanup, err := maybeProvisionResultTool(opts.ResultSinkPath)
	if err != nil {
		return "", err
	}
	defer cleanup()
	env := append([]string(nil), toolEnv...)
	env = append(env, maxTurnsEnv(opts.MaxTurns)...)
	env = appendEligibilityEnv(env, opts.Eligibility)
	enableResultTool := opts.ResultSinkPath != ""

	if harnessPath, ok := claudeHarnessPath(); ok {
		logEngineInvoke("claude", nodeCommand(), append([]string{harnessPath, "claude"}, claudeHarnessArgs("<prompt-file>", e.model, enableResultTool, opts.MaxTurns)...), e.model)
		return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
			return nodeCommand(), append([]string{harnessPath, "claude"}, claudeHarnessArgs(promptPath, e.model, enableResultTool, opts.MaxTurns)...)
		}, "", env, opts.ResultSinkPath)
	}
	args := claudeArgs(e.model, enableResultTool, opts.MaxTurns)
	logEngineInvoke("claude", "claude", args, e.model)
	return runCLIEnvWithSink(ctx, "claude", args, prompt, env, opts.ResultSinkPath)
}

// codexEngine implements Engine using the Codex CLI.
type codexEngine struct {
	model string
}

func (e *codexEngine) Analyze(ctx context.Context, prompt string, opts AnalyzeOptions) (string, error) {
	toolEnv, cleanup, err := maybeProvisionResultTool(opts.ResultSinkPath)
	if err != nil {
		return "", err
	}
	defer cleanup()
	env := append([]string(nil), toolEnv...)
	env = append(env, maxTurnsEnv(opts.MaxTurns)...)
	env = appendEligibilityEnv(env, opts.Eligibility)
	provider := codexForcedProvider(codexConfigPath())

	if harnessPath, ok := codexHarnessPath(); ok {
		logEngineInvoke("codex", nodeCommand(), append([]string{harnessPath, "codex"}, codexHarnessArgs("<prompt-file>", e.model, provider)...), e.model)
		return runCLIWithPromptFile(ctx, prompt, func(promptPath string) (string, []string) {
			return nodeCommand(), append([]string{harnessPath, "codex"}, codexHarnessArgs(promptPath, e.model, provider)...)
		}, "", env, opts.ResultSinkPath)
	}
	// Codex embeds the prompt as a positional argument; pass a placeholder here
	// so the logged args do not expose the detection prompt.
	logEngineInvoke("codex", "codex", codexArgs(e.model, provider, "<prompt>"), e.model)
	return runCLIEnvWithSink(ctx, "codex", codexArgs(e.model, provider, ""), prompt, env, opts.ResultSinkPath)
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

// appendEligibilityEnv appends eligibility transport variables to env when
// eligibility is non-nil, returning the extended slice.
//
// This transport is advisory. It reaches the report-result subprocess through a
// command line the detection model composes, so the model can override or strip
// it; the binding check is the detector's own revalidation of the sink result
// against the eligibility it computed from artifacts. What this buys is a fast
// in-session correction for a model that is simply mistaken, which is the
// common case and much cheaper than another engine pass.
func appendEligibilityEnv(env []string, eligibility *detector.Eligibility) []string {
	if eligibility == nil {
		return env
	}
	return append(env, eligibility.Env()...)
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

// resultToolClaudeTools are the Claude tools granted when the in-session result
// sink is provisioned. Bash runs the threat_detection_result wrapper, while
// Write and Edit let the model author the reasons file that carries verbatim
// evidence out of band of the shell (see ReadReasonsFile). Without the file
// tools the model's only remaining ways to report a reason are a shell heredoc
// or a --reason argument — the exact shell-expansion surface the file transport
// exists to remove — so the tool grant and the prompt must stay in step.
//
// Read, Read(/tmp/*), and Read(/tmp/gh-aw/*) let the model load the artifact
// files the prompt tells it to analyze (workflow prompt file, agent output,
// patch/bundle, comment memory) directly, without falling back to `Bash cat`.
// Those artifacts live under /tmp/gh-aw/threat-detection/, outside the
// process's working directory, so plain "Read" alone is not always sufficient
// under Claude's workingDir sandbox; the path-scoped grants cover that case.
//
// This grants no capability beyond Bash, which can already read and write files.
var resultToolClaudeTools = []string{"Bash", "Write", "Edit", "Read", "Read(/tmp/*)", "Read(/tmp/gh-aw/*)"}

// claudePermissionMode is passed via --permission-mode when the result-tool
// grant is active. Claude Code defaults to interactive permission prompting,
// which has no user to respond in a CI run and denies tool use (including
// Read outside the working directory) after a few attempts. acceptEdits
// makes --allowed-tools the effective boundary instead, matching gh-aw's own
// Claude engine invocation (pkg/workflow/claude_engine.go).
const claudePermissionMode = "acceptEdits"

func claudeArgs(model string, allowResultTool bool, maxTurns int) []string {
	args := []string{"--print", "--verbose", "--output-format", "stream-json"}
	if allowResultTool {
		args = append(args, "--permission-mode", claudePermissionMode, "--allowed-tools", strings.Join(resultToolClaudeTools, ","))
	}
	if model != "" {
		args = append(args, "--model", model)
	}
	if maxTurns > 0 {
		args = append(args, "--max-turns", strconv.Itoa(maxTurns))
	}
	return append(args, "-")
}

// claudeHarnessArgs builds the claude flags for harness invocation. It is
// identical to claudeArgs except that it uses --prompt-file <path> instead of
// the stdin sentinel "-", matching the invocation pattern used by the gh-aw
// claude_harness.cjs script.
func claudeHarnessArgs(promptPath, model string, allowResultTool bool, maxTurns int) []string {
	args := []string{"--print", "--verbose", "--output-format", "stream-json"}
	if allowResultTool {
		args = append(args, "--permission-mode", claudePermissionMode, "--allowed-tools", strings.Join(resultToolClaudeTools, ","))
	}
	if model != "" {
		args = append(args, "--model", model)
	}
	if maxTurns > 0 {
		args = append(args, "--max-turns", strconv.Itoa(maxTurns))
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

// runCLI executes a CLI command, passing the prompt via stdin, and returns its
// stdout output. Using stdin avoids OS argument length limits and prevents the
// prompt content from appearing in process listings.
func runCLI(ctx context.Context, name string, args []string, stdinData string) (string, error) {
	return runCLIEnv(ctx, name, args, stdinData, nil)
}

func runCLIWithPromptFile(ctx context.Context, prompt string, commandBuilder func(string) (string, []string), stdinData string, env []string, sinkPath string) (output string, err error) {
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
	return runCLIEnvWithSink(ctx, name, args, stdinData, env, sinkPath)
}

func runCLIEnv(ctx context.Context, name string, args []string, stdinData string, env []string) (string, error) {
	return runCLIEnvWithSink(ctx, name, args, stdinData, env, "")
}

// runCLIEnvWithSink runs the CLI command and, when sinkPath is non-empty, watches
// the sink file and cancels the subprocess as soon as a valid result is recorded.
// A subprocess error is suppressed when a valid sink result exists, because the
// process was intentionally killed once the verdict was reported.
//
// The subprocess (and any descendants it spawns) run in a dedicated process
// group so that on context cancellation — either the sink watcher's early
// cancel or the caller's wall-clock timeout — we can SIGKILL the entire group
// and reliably reap harness grandchildren. Without this, on harness paths the
// direct process is `node` and the actual Copilot/Claude/Codex CLI is a
// grandchild; exec.CommandContext's default cancellation only signals the
// direct process, so a timed-out runaway could keep burning credits after the
// detector has moved on.
func runCLIEnvWithSink(ctx context.Context, name string, args []string, stdinData string, env []string, sinkPath string) (string, error) {
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
	// Compose the child env from a scrubbed parent env plus caller-supplied
	// additions. Keys in scrubEngineInheritedEnv are stripped from the parent so
	// callers can explicitly disable a cap (e.g. --max-turns=0) even when the
	// enclosing process inherits the corresponding variable; the additions run
	// last so the caller always wins.
	if len(env) > 0 || len(scrubEngineInheritedEnv) > 0 {
		cmd.Env = append(filterEnv(os.Environ(), scrubEngineInheritedEnv), env...)
	}
	// Start the subprocess as the leader of a new process group so we can kill
	// the whole group on cancellation, not just the direct process.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Override exec.CommandContext's default cancellation (SIGKILL to the
	// direct process only) with a group-wide SIGKILL, so harness grandchildren
	// die too. cmd.Process is guaranteed non-nil by the time Cancel is invoked
	// because Go only calls it after Start succeeds.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		// Negative pid means "signal the process group whose id is |pid|"; we
		// installed the subprocess as its own group leader via Setpgid, so its
		// pid is also the group id.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			// Fall back to signaling just the direct process when the group
			// kill fails (e.g. the group is already gone). Losing this race is
			// fine — the sink watcher path or normal exit will still reap the
			// process.
			return cmd.Process.Kill()
		}
		return nil
	}
	if sinkPath != "" {
		// Bound how long Run waits for stdout I/O after the process is killed on
		// early termination, in case the engine left descendants holding the pipe.
		cmd.WaitDelay = resultSinkPollInterval
	}

	var stdout, stderr bytes.Buffer
	// Tee both stdout and stderr to the detector's stderr so that harness
	// lifecycle output ([copilot-harness], [claude-harness], [codex-harness])
	// and engine errors appear in the GitHub Actions job log in real-time,
	// mirroring the agent job's "2>&1 | tee" pattern. Forwarding goes through a
	// framer: the engine is analyzing attacker-controlled artifacts, so each
	// forwarded line is prefixed (PassthroughPrefix) and stripped of its ability
	// to open a workflow command, keeping it distinguishable from
	// detector-attested diagnostics. The buffers are still populated for error
	// reporting and sink-result checking.
	framer := newPassthroughFramer(enginePassthroughStderr)
	defer framer.Close()
	cmd.Stdout = io.MultiWriter(&stdout, framer.writer())
	cmd.Stderr = io.MultiWriter(&stderr, framer.writer())

	if err := cmd.Run(); err != nil {
		if sinkPath != "" {
			if _, sinkErr := detector.ReadResultFile(sinkPath); sinkErr == nil {
				// The verdict was recorded; the process was intentionally killed.
				return stdout.String(), nil
			}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", engineExitError(name, exitErr.ExitCode(), stdout.String(), stderr.String())
		}
		return "", fmt.Errorf("failed to execute %s: %w", name, err)
	}

	return stdout.String(), nil
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

// engineInvokeStderr is the destination for the human-readable engine-invoke
// line. It is a package variable so tests can capture the emitted output; in
// production it is os.Stderr, matching the GitHub Actions job log.
var engineInvokeStderr io.Writer = os.Stderr

// enginePassthroughStderr is the destination for forwarded engine subprocess
// output. It is a package variable for the same reason as engineInvokeStderr.
var enginePassthroughStderr io.Writer = os.Stderr

// logEngineInvoke logs the engine subprocess invocation details to stderr. It is
// called immediately before the engine process starts so that silent engine
// failures (exit with no output) leave enough context in the job log to diagnose
// the root cause.
//
// args must not contain sensitive data (prompt text, API keys). For engines
// that embed the prompt in argv (Codex), callers pass a safe placeholder.
//
// engineID is the canonical engine selected by the user (copilot/claude/codex),
// while name is the process actually spawned — which is often "node" when the
// gh-aw harness wrapper is used. Logging both makes the job log unambiguous
// about which engine and model were requested.
func logEngineInvoke(engineID, name string, args []string, model string) {
	resolvedPath, err := exec.LookPath(name)
	if err != nil {
		resolvedPath = ""
	}

	// Note when the actual process differs from the engine (harness wrapper),
	// so "node" in the command does not obscure which engine is running. The
	// process name can come from GH_AW_NODE_BIN (and its resolved path from
	// PATH lookup), so the composed description is quoted with %q for the same
	// reason as the model: a newline or control sequence in that configuration
	// would otherwise split the line or forge a workflow command.
	command := name
	if resolvedPath != "" {
		command = fmt.Sprintf("%s (%s)", name, resolvedPath)
	} else {
		command = fmt.Sprintf("%s (binary not found in PATH)", name)
	}
	command = fmt.Sprintf("%q", command)

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
	fmt.Fprintf(engineInvokeStderr, "[threat-detect] engine invoke: engine=%s model=%s command=%s args=%d\n", engineID, modelDesc, command, len(args))
	fmt.Fprintf(engineInvokeStderr, "[threat-detect] engine argv: %s\n", quoteArgs(args))
}

// quoteArgs renders argv for the job log. Each element is %q-quoted so an
// argument containing whitespace, newlines, or terminal control sequences cannot
// split or forge the diagnostic line.
func quoteArgs(args []string) string {
	if len(args) == 0 {
		return "(none)"
	}
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, fmt.Sprintf("%q", arg))
	}
	return strings.Join(quoted, " ")
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
