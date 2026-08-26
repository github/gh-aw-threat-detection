# gh-aw-threat-detection

Threat Detection component for [GitHub Agentic Workflows](https://github.com/github/gh-aw). Analyzes AI agent output for security threats including prompt injection, secret leaks, and malicious patches.

## Contents

- [Quick Start](#quick-start)
- [Overview](#overview)
- [Guardrails and Security Considerations](#guardrails-and-security-considerations)
- [Usage](#usage)
- [Stage Status and Decisions](#stage-status-and-decisions)
- [Release Asset Setup](#release-asset-setup)
- [Development](#development)
- [Architecture](#architecture)
- [Integration with gh-aw](#integration-with-gh-aw)
- [Specification](#specification)
- [Contributing](#contributing)
- [Support](#support)
- [Code of Conduct](#code-of-conduct)
- [Security](#security)
- [License](#license)

## Quick Start

Build the CLI and run it against an artifacts directory:

```bash
make build
./bin/threat-detect /path/to/artifacts
```

Run tests locally:

```bash
make test
```

## Overview

This tool runs as a standalone binary that analyzes artifacts produced by AI agents before safe outputs are permitted. It supports multiple AI engines (Copilot, Claude, Codex) for detection analysis.

## Guardrails and Security Considerations

This project is designed to help reduce risk when running AI agent workflows by inspecting generated artifacts before they are accepted as safe output. Detection is advisory and should be combined with defense-in-depth controls such as least-privilege permissions, human review, and repository protections.

Do not treat a "safe" result as a security guarantee. Use the output as one signal in a broader security review process.

### What this layer is for

Threat detection is a **gate on downstream actions**, not a post-hoc audit of
the agent's session. It runs after the agent finishes and before the
safe-output job, and it decides whether the effects the agent is asking for —
issues, comments, pull requests, patches — may be applied. What it analyzes is
the staged artifact bundle, which is the record of what the agent wants
published.

So anything the agent already **did** during its session is outside what this
can gate, because it happened before detection ran:

- **Mid-run injection sources are not staged.** MCP tool results, fetched web
  pages, and the engine transcript never become artifacts, so an injection that
  arrived only through one of those leaves no trace in the analyzed inputs.
- **Mid-run exfiltration never enters the bundle.** A secret sent out over an
  outbound request or an MCP call is gone by the time detection runs; there is
  no artifact for it to appear in.

Neither is a gap this component intends to close. Those risks belong to the
controls that are live *while* the agent runs — network egress restriction (the
[agentic workflow firewall](https://github.com/github/gh-aw-firewall)) and limits on which
MCP servers and tools are reachable. Threat detection complements those controls
and does not substitute for them.

This is also why the [structural eligibility](#structural-eligibility) rules are
written in terms of artifacts: the bundle is the evidence that exists at the
moment the gate is applied.

## Usage

### CLI

```bash
threat-detect [flags] <artifacts-dir>
```

**Flags:**
- `--engine` — AI engine to use (`copilot`, `claude`, `codex`). Default: `copilot`
- `--model` — Model override for the engine. When unset, the detector resolves the model from `GH_AW_MODEL_DETECTION_{COPILOT,CLAUDE,CODEX}`, then the engine CLI's native model env var (`COPILOT_MODEL`, `ANTHROPIC_MODEL`). The value is forwarded to the engine CLI verbatim and may be a model alias (`gh-aw` defaults the detection model to the `detection` alias when none is configured); aliases are resolved by the AWF API proxy, not by the detector. Alias resolution is not guaranteed to land on a priced model — if the proxy steers to a model with no AI-credits pricing it rejects the request and the engine fails, so hosts that need a deterministic detection pass should configure a concrete model (see [AW Smoke Workflows](#aw-smoke-workflows))
- `--prompt-template` — Path to custom prompt template
- `--workflow-name` — Workflow name for the prompt. Overrides `WORKFLOW_NAME`
- `--workflow-description` — Workflow description for the prompt. Overrides `WORKFLOW_DESCRIPTION`
- `--custom-prompt` — Additional detection instructions appended to the prompt. Overrides `CUSTOM_PROMPT`
- `--custom-prompt-file` — Path to a file with additional detection instructions. Takes precedence over `--custom-prompt` and `CUSTOM_PROMPT`
- `--output` — Path to write the JSON result (defaults to stdout). Its `reasons` array is always empty; see [Where the reasons go](#where-the-reasons-go)
- `--full-output` — Path to write the JSON result *including* reasons. Defaults to the `--output` path with `_full` inserted before the extension (`detection_result.json` → `detection_result_full.json`); pass an explicitly empty value to disable it. **Hosts must not upload this file**
- `--retries` — Retries after a failed detection attempt, including one rejected on structural [eligibility](#structural-eligibility). **Default: `0`** (env: `THREAT_DETECTION_RETRIES`). A from-scratch retry rarely fixes anything: the engine CLIs already retry transient provider errors internally, and the `threat_detection_result` tool wrapper's non-zero exit + stderr already lets the agent iterate in-session on a bad tool call — including an ineligible one — without a subprocess restart. `--engine-timeout` is **always terminal** regardless of this value — retrying a runaway is overwhelmingly likely to run away again
- `--engine-timeout` — Wall-clock timeout per detection attempt (Go duration, e.g. `5m`, `300s`). On expiry the engine subprocess **and its harness descendants** are killed via a process-group `SIGKILL`, so the actual model CLI running as a grandchild under `node` cannot keep burning credits after the deadline. If the result sink already holds a valid verdict written just before the deadline, that verdict wins over the timeout. Timeouts are terminal — the run exits `2` with the status reason `engine_timeout` immediately, without consuming any `--retries`. `0` disables the cap. Default: `5m` (env: `THREAT_DETECTION_ENGINE_TIMEOUT`)
- `--max-turns` — Maximum agentic tool-use turns per attempt. Exported to the engine subprocess as `GH_AW_MAX_TURNS` (which the Claude, Codex, and Copilot harnesses read) and additionally passed as `--max-turns` to the bare Claude CLI. The bare Copilot CLI has no equivalent flag, so on that path only `--engine-timeout` enforces the cap; the detector logs a diagnostic when `--max-turns` is set for that path. `0` disables the cap and scrubs any inherited `GH_AW_MAX_TURNS` from the engine subprocess's env. Default: `50` — the turn cap's real job is catching tool-loop pathology (model stuck calling Read in a loop), not being the primary credit bound; the wall-clock is the primary bound, and 50 gives comfortable headroom for legitimate wide exploration (e.g. a patch touching many files). (env: `THREAT_DETECTION_MAX_TURNS`; also honors `GH_AW_MAX_TURNS` as a fallback so a turn budget configured for the harness-driven path applies to the standalone detector too)
- `--step-summary` — Deprecated and ignored. Accepted so hosts that still pass it (older `gh-aw` releases) do not fail; the detector no longer writes a GitHub Actions step summary
- `--version` — Print version and exit

`threat-detect` runs a single agentic CLI engine pass. The engine reports its
verdict in-session by invoking the `threat_detection_result` tool, which writes
a strict JSON object matching the result contract to an out-of-band result sink;
the detector cancels the engine subprocess as soon as a valid result is written.
The verdict is read exclusively from that sink; if no sink result is produced,
or the reported verdict is rejected on structural eligibility (see [Structural
eligibility](#structural-eligibility)), a self-correction prompt is retried
(`--retries`, once by default), and retry exhaustion is treated as an
infrastructure error.

#### In-session result reporting (`threat_detection_result`)

On the agentic CLI engine path (`copilot`, `claude`, `codex`), the detector
provisions a `threat_detection_result` command on the model's `PATH` and sets
`THREAT_DETECTION_RESULT_FILE` to a private sink file, plus
`THREAT_DETECTION_REASONS_FILE` to the path the model writes its reasons to
(alongside the sink, in a directory every engine can reach), before each engine
invocation. Any reasons file left by a previous attempt is removed at
provisioning time so a retry cannot report stale reasons. The model reports its
verdict by running the command exactly once:

```bash
threat_detection_result --prompt-injection <true|false> --secret-leak <true|false> --malicious-patch <true|false> --reasons-file <path>
```

The three boolean flags accept both the space-separated form shown above and the
`--prompt-injection=true` form.

Reasons are transported through a **file**, not the command line. Reasons quote
attacker-authored artifact content verbatim, and the model runs this command
through a shell, so evidence containing `$(...)`, backticks, or quotes passed as
a `--reason` argument would be expanded or executed by the shell before the tool
received it. `--reasons-file` points at a file — written by the model with its
file-editing tool — containing a JSON array of reason strings, which is parsed
by the tool itself. A malformed file is a correctable parse error rather than an
executed command. A repeatable `--reason "<text>"` flag remains for short,
model-authored text that quotes nothing; both sources are validated against the
same bounds and concatenated in order.

The command validates the input synchronously: on bad input it prints
`THREAT_DETECTION_RESULT_ERROR:` and exits non-zero without recording anything,
so the model can correct it in-session; on valid input it atomically records the
canonical JSON verdict to the sink (first valid write wins, idempotent) and
prints `THREAT_DETECTION_RESULT_RECORDED:`. As soon as a valid verdict is
recorded, the detector cancels the engine subprocess (early termination),
eliminating dead-spiral latency and cost. The detector reads the verdict
exclusively from the sink; it does not scrape the engine transcript.

**Exit codes:**
- `0` — Safe (no threats detected)
- `1` — Threat detected
- `2` — Infrastructure/configuration error

#### Structural eligibility

Each threat category is only raisable against an artifact bundle that could
plausibly exhibit it:

- `prompt_injection` requires untrusted content that could have reached this
  run's inputs — a non-empty untrusted region in the prompt analysis, or a
  comment-memory file (which the agent reads back into its prompt).
- `malicious_patch` requires at least one `.patch` or `.bundle` file in the
  artifact bundle. Framework-rejected safe-output validation errors are the
  guardrails working; they are not patches.
- `secret_leak` requires a channel a secret could have reached — a non-empty
  agent output, a patch or bundle, or a comment-memory file. Note that
  `agent_output.json` is gh-aw's safe-outputs file, so issue bodies, comment
  bodies and PR descriptions the agent asked the framework to publish are
  covered by the agent-output channel rather than being separate ones.

Eligibility fails open whenever the evidence for a precondition could not be
established — a missing, unreadable, or malformed artifact must never be able to
suppress a real finding. An empty set of untrusted regions only proves the prompt
received nothing untrusted if the analysis actually ran: if `prompt-template.txt`
or the rendered prompt was unavailable, or the two could not be reconciled so
regions were skipped, `prompt_injection` stays eligible. Likewise a
comment-memory directory that exists but could not be read counts as a channel
rather than as an absence.

The check runs in two places, with different standing:

- **In the reporting tool**, from `THREAT_DETECTION_ELIGIBLE_*` environment
  variables, so an ineligible report is corrected in-session without another
  engine pass. The tool prints `THREAT_DETECTION_RESULT_ERROR:` naming the
  category and what would make it eligible. This check is **advisory** — the
  model composes the command line that carries those variables, so it can
  override or omit them.
- **In the detector process**, against the eligibility it computed from the
  artifacts itself. Every result read from the sink is re-checked here before
  it is recorded, so a verdict that bypassed the tool (or overrode its
  environment) is still rejected. This is the binding check.

An ineligible result is treated exactly like a malformed one: it is discarded,
never rewritten, so the sink stays the sole source of any recorded result. With
the default `--retries 0` the advisory tier is what recovers the run — the tool
rejects the call and the model re-answers in-session, without a restart. The
binding tier is the backstop for a verdict that reached the sink anyway: with no
retries left it ends the run at `invalid_report_exhausted` and exit 2, and where
retries are configured it first feeds the rejection back as a self-correction.
An attempt that also hit `--engine-timeout` stays terminal and is not retried.

#### Adding a channel

Eligibility is derived from *channels* — declared in `inputChannels`,
`outputChannels` and `patchChannel` in `pkg/detector/eligibility.go` — rather
than from conditions written per category. To make a new artifact source count,
append a channel to the relevant list:

```go
{
    name:          "an MCP tool result recorded during the run",
    present:       len(arts.MCPToolResults) > 0,
    uninspectable: arts.HasWarningForField("mcp_tool_results"),
}
```

Both signals matter. `present` means content was found; `uninspectable` means
the channel may hold content the detector could not read. Either makes the
category eligible, because an artifact the detector failed to inspect must never
be mistaken for one that does not exist — collapsing the two is what caused the
fail-closed bugs this shape prevents. Tests enforce both halves: every channel
must be eligible on either signal, and every channel must be named in the
rejection message, which is generated from the same declarations.

A source also has to be *staged* before it can be a channel. Adding one to the
detector only matters once the host writes it into the artifacts directory and
`pkg/artifacts` loads it; until then there is nothing to point at.

A channel that is `uninspectable` also has to *say so in the prompt*. Eligibility
decides whether a verdict may be raised from a channel; it does not decide what
the model is told about it. If the loader describes an unread channel as empty,
the model reports clean about content nobody looked at and the run exits 0 —
a fail-open outcome one layer above eligibility. Use
`artifacts.uninspectableNotice` so the description says the channel was
unexamined rather than empty, and states that the failure is not itself evidence
of a threat. That second half is not decoration: without it a staging fault
becomes a false-positive source, which is the failure mode eligibility exists to
reduce.

Eligibility is scoped to the artifact bundle. MCP tool results, fetched web
content, and the engine transcript are never staged as artifacts, so an
injection delivered only through those channels leaves no evidence in the
analyzed inputs and is outside what this detection pass can see. See spec
TD-10g.

The detector also emits a single machine-readable status line to stderr at the end
of every detection run: `THREAT_DETECTION_STATUS: reason=<reason> exit=<code>`.
(Informational modes that exit before running detection — `--help` and `--version` —
emit no status line, so callers should not treat its absence in those modes as a
malfunction.) The `reason` distinguishes outcomes that share exit code `2` — notably
`invalid_report_exhausted` (the engine ran but the model never recorded a valid
verdict) from `engine_error`, `config_error`, and `cancelled`. Integration wrappers
use this to decide the
detection step's success/failure outcome without being stricter than `gh-aw`: a
recorded verdict (exit 0/1) and an `invalid_report_exhausted` outcome do not fail
the step, so warn-mode workflows proceed exactly as they do under `gh-aw`'s native
engine (which treats a missing verdict as a recoverable `parse_error`). Only genuine
engine/config failures surface as a step failure. See spec TD-21a.

#### Diagnostics

The detector writes no log artifact of its own. Apart from the result JSON, every
diagnostic goes to stderr, so capturing the step's output (for example
`threat-detect ... 2>&1 | tee detection.log`) preserves the full trace. Reported
on stderr are the resolved run configuration (version, engine, model, retries),
the recursive artifact inventory with per-file size and consumed status, the
prompt metadata (byte count, resolved workflow name/description, custom-prompt
provenance, framework-scaffolding detection), each detection attempt and whether
it recorded a verdict, the engine subprocess invocation and argv, any
`::warning::`/`::error::` annotations for degraded inputs, and the terminal status
line. The rendered prompt itself is never echoed.

Untrusted values interpolated into these detector-authored lines are escaped so
that each stays on lines of its own and listings are bounded, so neither a
model-authored string nor a hostile filename can forge a workflow command or
flood the job log. Escaping happens on the way out — every detector diagnostic
goes through one writer, and so does every `conclude` line — rather than at each
call site, so a new diagnostic cannot reintroduce the gap. It covers **both**
marker forms the Actions runner accepts: the `::command::` form, which it honors
only at the start of a line, and the legacy `##[command]` form, which it locates
anywhere within a line and which is therefore broken up inside the value (`##[`
is rendered `##\[`). Annotation data is neutralized the same way; the runner
does not rescan the data of a command it already recognized, so that part is
defense in depth. The
engine subprocess's own stdout/stderr are a separate, untrusted stream: they are
forwarded line by line in real time (so harness output and engine errors stay
visible), each line prefixed with `[engine] ` and stripped of its ability to open
a workflow command in either form. Forwarded lines are not detector-attested —
log consumers must ignore any `THREAT_DETECTION_*` marker that carries the
`[engine] ` prefix.

```text
[threat-detect] run start: version=1.2.3 engine=copilot model=(none; using engine default) retries=0 max_turns=50 engine_timeout=5m0s
[threat-detect] artifacts loaded: dir=/tmp/gh-aw/threat-detection prompt_bytes=4096 agent_output_bytes=812 patch_files=1 all_primary_inputs_missing=false
[threat-detect] artifact inventory (3 entries):
[threat-detect]   aw-prompts/prompt.txt bytes=4096 kind=file consumed=true
[threat-detect]   comment-memory/notes.md bytes=128 kind=file consumed=false
[threat-detect] prompt built: prompt_bytes=9241 framework_scaffolding_detected=true framework_scaffolding_host_removed=false framework_scaffolding_markers=<github-context>, <safe-output-tools>
[threat-detect] detection attempt 1 of 2
[threat-detect] attempt 1 recorded a verdict via the threat_detection_result tool
THREAT_DETECTION_STATUS: reason=result_recorded exit=0
```

#### Where the reasons go

`reasons` is model-authored text derived from the untrusted content being
analyzed, so it is never written to a file the host publishes. The verdict is
split across two files:

| File | Contents | Fate |
|------|----------|------|
| `detection_result.json` (`--output`) | the three booleans, with `reasons: []` | uploaded as the detection artifact |
| `detection_result_full.json` (`--full-output`) | the identical verdict plus the reported `reasons` | stays on the runner, never uploaded |

The schema is unchanged: `reasons` is still a required array, just empty, so
every existing parser reads the redacted result as-is. `conclude` reads the full
result and renders the reasons into the job log, where the runner's masking
applies and they expire with normal log retention.

Consequences worth knowing:

- Reasons are **not** available to anything reading artifacts after the fact.
  Post-hoc triage of an old blocked run depends on the job log still being
  retained.
- No diagnostic the detector writes echoes the reasons, because hosts routinely
  tee stdout and stderr into published files. This covers detector-authored
  output only — forwarded engine output (the `[engine] `-prefixed lines) still
  reproduces the reason text wherever the engine renders the
  `threat_detection_result` invocation the model made. Framing makes those lines
  identifiable and inert, but does not remove the text, so a captured stderr file
  must be treated as carrying model-authored text and must not be uploaded.
- A failure to write the full result is non-fatal — it carries no verdict, so a
  read-only detection directory does not turn a completed detection into an
  infrastructure error.

#### Warnings vs reasons

The result also carries a `warnings` array, which is **not** the same as
`reasons`:

| | `reasons` | `warnings` |
|---|---|---|
| Author | The detection model | The detector itself |
| Content | Free-form explanations quoting untrusted artifact content | Fixed strings composed by the detector, embedding host-controlled paths |
| Where written | Full result only (`detection_result_full.json`) | **Both** files (`detection_result.json` and `_full.json`) |
| Uploaded? | No | Yes — safe to publish |
| Affects verdict? | Yes (present iff at least one threat is true) | **No.** A warning never sets a threat category or triggers a threat exit |
| Signal | "here is a threat and why" | "the detector could not inspect part of the input" |

A warning is recorded when an artifact channel is present but cannot be fully
inspected — for example, `HAS_PATCH=true` was set but no readable patch bundle
was found, a staged prompt or patch exists but cannot be opened, the
`comment-memory` directory could not be listed, or the optional prompt-analysis
inputs (`prompt-template.txt`, `prompt-import-tree.json`) were missing or
unusable. Readability is probed by
actually opening the file: a stat-only check succeeds on a file the detector has
no permission to read, which would report a non-empty, inspected-looking channel
for content nobody examined. Without the `warnings` array, a partially
inspectable bundle would be indistinguishable from a fully inspected clean one
on the uploaded result: the detector analyzed less than the full artifact set,
reported clean, and exited 0. Gating a run on advisory warnings is a
**host-level policy** decision; the detector deliberately does not do it, so a
staging failure cannot suppress a real finding by turning "could not inspect"
into "must fail". Each entry has three fields:

```json
"warnings": [
  {
    "field": "comment_memory",
    "code": "ERR_VALIDATION",
    "message": "Unable to read comment-memory directory at /tmp/gh-aw/threat-detection/comment-memory: permission denied"
  }
]
```

`conclude` renders any warnings under a `⚠️` block distinct from both the
verdict and the reasons, so a misconfigured job is visible in the job log
without a reader having to consult GitHub Actions annotations.

One exception is worth knowing about. Warnings are advisory *within a run that
executes*. When `GH_AW_DETECTION_CONTINUE_ON_ERROR` is `false`, a warning about
a **required** input (`prompt`, `agent_output`, `patch`) is promoted to a
configuration error and the detector refuses to run degraded detection, exiting
`2` before any analysis happens. That is an infrastructure error, not a threat
verdict (exit `1`), and no result file is written — writing one would assert a
clean verdict for analysis that never ran. Warnings about *optional* artifacts,
such as `prompt_template` and `prompt_import_tree`, are never promoted this way,
so reporting them cannot start failing a host that does not stage them. In the default warn mode, where
detection does run, every recorded warning appears in both result files.

#### Concluding a run (`conclude`)

In `gh-aw`-compiled workflows the detector runs inside the AWF sandbox, where the
verdict cannot reach the host over stdout. Instead, detection writes its structured
result to `detection_result.json` in a read-write mount, and a host-side step reads
it back with the `conclude` subcommand:

```bash
threat-detect conclude --result-file /tmp/gh-aw/threat-detection/detection_result.json
```

`conclude` recovers the reasons from the companion full result, deriving its path
from `--result-file` by the same convention the detection run uses (override with
`--full-result-file <path>`). The result file remains the sole source of the
verdict: a missing or unparseable full result is reported and ignored, a full
result whose booleans disagree is discarded outright, and a pre-split result that
still carries its own reasons renders them directly.

Reasons are rendered into the verdict block with their line structure intact —
each embedded newline becomes a real log line, prefixed with a gutter so no
continuation line can begin a workflow command — and a line longer than the
per-line bound is wrapped onto further lines rather than truncated, so the
located, verbatim evidence a reason exists to carry survives the job log. The
`::error::` annotation that follows is a summary and does bound each reason;
it points back at the verdict block for the full text.

`conclude` reproduces the `gh-aw` job-output contract — it writes `conclusion`,
`reason`, and `success` to `GITHUB_OUTPUT` and exports `GH_AW_DETECTION_CONCLUSION`
and `GH_AW_DETECTION_REASON` to `GITHUB_ENV`. It reads these environment inputs:

- `RUN_DETECTION` — when not `"true"`, the verdict is `skipped`/`success`
- `GH_AW_DETECTION_CONTINUE_ON_ERROR` — anything other than `"false"` (compared case-insensitively) is warn mode
- `DETECTION_AGENTIC_EXECUTION_OUTCOME` — `"failure"` makes `agent_failure`/`parse_error` hard-fail

A malformed (readable but unparseable) result file always reports `parse_error`,
and detected threats report `threat_detected`. When the result file is missing,
`conclude` consults the detection run's captured log (`--detection-log <path>`,
default `<result-file-dir>/detection.log`) for the terminal
`THREAT_DETECTION_STATUS: reason=<reason> exit=<code>` line and maps it onto the
host-side reason:

| status reason | host-side `reason` |
|---|---|
| `invalid_report_exhausted` | `parse_error` |
| `output_write_error` | `parse_error` |
| `engine_error` | `agent_failure` |
| `cancelled` | `agent_failure` |
| `config_error` | `agent_failure` |
| absent / unrecognized / log unreadable | `agent_failure` ("Detection result file not found at: <path>") |

Tooling failures are reported distinctly from real security findings so
reviewers can tell them apart: an `agent_failure`/`parse_error` outcome states
plainly in the job log that the analysis engine could not complete and that this
is a tooling failure, not a security finding.

`conclude` writes a verbose, self-contained diagnostic section to the job log:
banners framing the section, the environment inputs and resolved paths, and the
per-field verdict breakdown (`prompt_injection`/`secret_leak`/`malicious_patch`)
with an indexed reasons list. When the result file is missing or unusable it also
prints a recursive listing of the result directory plus detection-log statistics
and every line carrying a `THREAT_DETECTION_STATUS:`/`THREAT_DETECTION_RESULT:`
marker, so a failed run can be diagnosed without downloading artifacts.

Additional flags:

- `--detection-log <path>` — the detection run's captured log (see the reason
  table above); it is also the source of the diagnostic log statistics and marker
  lines. It is consulted for the terminal status reason but never parsed for a
  verdict.

Like the detection run, `conclude` writes no separate log artifact; its
diagnostics go to stdout only. Diagnostic output is bounded so a pathological run cannot flood the job log, and
truncation is always labelled rather than passed off as a complete reading.
Untrusted values (model-authored reasons, artifact filenames, detection-log
lines) have control characters escaped so each stays on one line and cannot
inject a workflow command into the host job log.

### AI Credits and Token Usage

The threat-detection pass is a **separate agentic engine invocation** from the main
agentic run it guards. It builds its own prompt and runs the selected engine
(`copilot`, `claude`, or `codex`) once, so it consumes AI credits/tokens
**independently** — in addition to (not shared with) the workflow's primary run.
The cost is billed to the same engine account/credentials used for detection
(`COPILOT_GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, or `OPENAI_API_KEY`).

**Is there a separate token cap for the detection job?** `threat-detect` itself
enforces no credit budget — it has no notion of AI credits and does not read or
count tokens. On the path `gh-aw` actually ships, the cap is enforced **around**
the detector, not inside it:

- **AWF API-proxy `maxAiCredits`** — when `threat-detect` runs under the
  Agentic Workflow Firewall with the API proxy and token steering enabled
  (`apiProxy.enabled` + `enableTokenSteering`), the compiled detection step sets
  `apiProxy.maxAiCredits` from `max-ai-credits` (default 400, or
  `vars.GH_AW_DEFAULT_DETECTION_MAX_AI_CREDITS`). The proxy enforces this as a
  **cumulative** per-run credit counter, so it bounds the whole pass —
  **including `--retries`**, not just the first attempt. This is the enforcement
  mechanism for the external detector path; there is no `threat-detect`-side
  budget flag to plumb.
- **Early termination** — as soon as the model records a verdict through the
  `threat_detection_result` tool, the detector cancels the engine subprocess, so
  the pass stops at the first valid verdict instead of running to the engine's
  own limit.
- **`max-turns`** — `gh-aw`'s `threat-detection.engine` configuration accepts a
  `max-turns` value that bounds the agentic loop (see the [spec](specs/threat-detection-spec.md), TD-14).

A plain, non-AWF `./bin/threat-detect` invocation (no API proxy) has **no**
credit cap and produces no proxy token log. It is not bounded by `max-turns`
either — that is a `gh-aw` workflow setting, and the CLI neither accepts it nor
forwards one to the engine. Only **early termination** (cancelling the engine as
soon as a verdict is recorded) and the engine's own built-in limits bound its
cost.

**Where does the `aic` (AI credits) figure come from?** Not from `threat-detect`.
On the AWF path the proxy records every steered model request to
`token-usage.jsonl` under `…/sandbox/firewall/**/api-proxy-logs/`, and `gh-aw`'s
`parse_token_usage.cjs` aggregates those records into the detection job's `aic`
output and `agent_usage.json`. That figure is therefore **independent of**
`threat-detect`'s engine flags and of any diagnostics it interleaves into
`detection.log`; the detector's stdout is not the source of truth for credits.

For authoritative billing, use the AWF proxy token log / `agent_usage.json` (or
the engine's own logs, which recent `gh-aw` releases render into the detection
job's log rather than uploading as an artifact) together with `gh-aw`'s `logs`
tooling.

### Released binary

The `threat-detect` binary is published as GitHub Release assets for Linux and
macOS on amd64 and arm64 alongside a shared `checksums.txt`. Download the asset
matching your runner platform and run it directly:

```bash
# Pick the asset for your operating system and architecture.
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64|Linux/amd64)  asset=threat-detect-linux-amd64 ;;
  Linux/aarch64|Linux/arm64) asset=threat-detect-linux-arm64 ;;
  Darwin/x86_64)             asset=threat-detect-darwin-x64 ;;
  Darwin/arm64)              asset=threat-detect-darwin-arm64 ;;
  *) echo "unsupported platform" >&2; exit 1 ;;
esac
gh release download --repo github/gh-aw-threat-detection \
  --pattern "$asset" --pattern checksums.txt
awk -v asset="$asset" '$2 == asset' checksums.txt |
  if command -v sha256sum >/dev/null; then sha256sum --check; else shasum -a 256 --check; fi
install -m 0755 "$asset" ./threat-detect
./threat-detect /path/to/artifacts
```

Omitting a tag downloads the latest stable (promoted) release. Production
AI-backed detection requires the selected engine CLI and its authentication to
be available on the runner where the binary runs.

The macOS binaries are not code-signed or notarized. The `gh-aw` installer
checksum-verifies CI downloads before execution. Browser downloads may be
quarantined by Gatekeeper; prefer the installer, or verify the checksum before
removing quarantine.

### Input (Artifacts Directory)

```
<artifacts-dir>/
├── aw-prompts/
│   ├── prompt.txt          # Expanded workflow prompt file
│   ├── prompt-template.txt # Pre-expansion prompt template
│   └── prompt-import-tree.json # Runtime-import provenance
├── agent_output.json       # Agent structured output
├── aw_info.json            # Bounded activation context (optional, consumed as untrusted)
├── aw-*.patch              # Git format-patch files (optional)
├── aw-*.bundle             # Git bundle files (optional)
├── experiments/            # Experiment assignment/state files (optional, inventoried only)
└── comment-memory/         # Agent comment memory (optional, inventoried only)
    └── *.md
```

Integrated hosts must stage all three files under `aw-prompts/`. Direct callers
may omit the template or import tree, but the detector emits an
`ERR_VALIDATION` warning because trusted-vs-untrusted prompt analysis is then
degraded. Empty or unreadable analysis files produce the same warning.

`aw-prompts/prompt.txt` and `agent_output.json` are the required detection
inputs, as is at least one `aw-*.patch` / `aw-*.bundle` when the host sets
`HAS_PATCH=true`. When one of them is missing, empty, or unusable the detector
follows the host's continue-on-error policy: by default it warns and analyzes
whatever was staged, and with `GH_AW_DETECTION_CONTINUE_ON_ERROR=false` it
reports each finding as an error and exits `2` (`config_error`) before the
engine runs. Findings about other artifacts stay advisory warnings in both
modes.

Every file below the artifacts directory is recorded with its size and consumed
status in the artifact inventory printed to stderr. Only an allowlisted, size-bounded subset of
`aw_info.json` is added to the detection prompt, and all of its values are
explicitly treated as untrusted runtime data.

### Output (JSON)

```json
{
  "prompt_injection": false,
  "secret_leak": false,
  "malicious_patch": false,
  "reasons": [],
  "warnings": []
}
```

The three booleans are fully constrained by the schema: all are required, no
other fields are accepted, and a result that adds, omits, or mistypes a field is
rejected. `reasons` is model-authored free text and is bounded as well — at most
20 entries, each non-blank and at most 2000 characters — and the whole result
file is capped at 1 MiB before it is parsed. The same bounds apply when the model
reports a result and when the file is read back, so a recorded result can never
fail validation later. A rejected report is returned to the model as a
correctable tool error; an oversized or malformed result file is a parse error
that fails the detection closed.

`warnings` is a detector-authored, optional array of partial-inspection
findings (see [Warnings vs reasons](#warnings-vs-reasons)). It is additive and
backward-compatible: a pre-existing consumer sees the field absent on results
from an older detector, and one indexing into it always finds an array on
results from a newer detector. Each entry is a `{ "field", "code", "message" }`
object; the array is bounded at 20 entries with each `field` and `code` at most
64 characters and each `message` at most 2000 characters. A warning never sets a
threat category or causes a threat exit; see the note above on strict mode,
where a required-input warning is instead promoted to a configuration error.

### Replay workflow

Maintainers can manually run **Replay Threat Detection** from the Actions tab to rerun detection against artifacts from a prior workflow run. Provide the source repository and run ID; the workflow downloads the `agent`, `activation`, optional experiment, and optional original `detection` artifacts, normalizes them into the CLI input contract above, runs `threat-detect`, and uploads a sanitized `replay-detection-<run_id>` artifact with the manifest, file inventory, replay result, and original-result comparison.

The replay log and the source run's detection log stay on the runner and are visible in the job log only. Both tee the detector's standard error, which forwards the engine subprocess's output, so they can reproduce the model-authored reasons and are never uploaded (usage-spec U-09 and U-27). The same applies to the reasons companion file: reasons are printed into the job log and left out of every artifact.

Replay uses the dispatching repository's `GITHUB_TOKEN`; no extra replay token is required. The selected source run must be accessible to that token.

Common dispatch examples:

- Current checkout, direct CLI replay: set `run_id`, leave `detector_source=current`, `engine=copilot`, and `use_awf=false`.
- Released detector replay: set `detector_source=release` and `detector_ref` to a release tag such as `v0.0.2`. The workflow downloads the release asset matching the runner architecture (`threat-detect-linux-amd64` or `threat-detect-linux-arm64`) and runs it on the host so the selected engine CLI can be installed there.
- Model comparison: set `model` to the engine-specific model name to pass through `--model`.
- Additional detection instructions: set `custom_prompt`; it is passed as `CUSTOM_PROMPT` and appended to the default detector prompt.
- AWF mode: set `use_awf=true` only on a runner image that already provides the `awf` CLI. Direct mode is the default.

The `run_attempt` input is only safe for the latest attempt of a source run because GitHub artifact downloads are not attempt-scoped. The workflow fails with a clear error if an older attempt is requested.

## Stage Status and Decisions

The extraction staging model is:
- Stage 1: standalone repository
- Stage 2: published release-asset binary
- Stage 3: `github/gh-aw` integration

Stage 1 is functionally represented in this repository.
The standalone Go CLI, artifact reader, prompt builder, result parser, engine abstraction, W3C-style specification, unit tests, CI, and release workflow are present.
Remaining work involves integration with `github/gh-aw` and production hardening in Stage 2/3, not additional JavaScript porting in this repository.

Decisions for the unresolved extraction questions:

- **JavaScript scripts**: detection setup and result parsing are implemented in Go here; the old GitHub Actions JavaScript scripts should not be needed once `gh-aw` switches to the released-binary contract.
- **Engine CLIs**: do not bundle Copilot, Claude, or Codex CLIs into the detector binary. The detector invokes the selected engine CLI from `PATH` and forwards the `--model` value. Production `gh-aw` integration should install or provide the selected engine CLI in the detection job, then run the pinned detector binary downloaded from the GitHub Release in that same runner/AWF environment. This keeps the binary small, avoids runtime installation, and reuses the existing engine installation/authentication path.
- **Custom steps**: custom `threat-detection.steps` remain orchestrator-owned. They should run before or after the detector in the `gh-aw` job rather than being passed into the detector as arbitrary scripts.
- **Backward compatibility**: do not ship a long-lived dual-mode compatibility window. Stage 3 should switch `gh-aw` to the pinned detector binary path after Stage 4 validation passes; users that need inline detection can pin an older `gh-aw` release. A temporary internal fallback is acceptable during implementation only, but should not become a documented public feature flag unless Stage 4 exposes a blocking compatibility issue.
- **Ollama/LlamaGuard**: keep this as a custom-step pattern unless a dedicated detector variant is explicitly required.
- **Version coupling**: use strict, semver-compatible release tags and have `gh-aw` pin a specific `DefaultThreatDetectionVersion`, matching the firewall pattern.
- **Isolation**: the detector should run in the standard detection job initially. Running the detector itself inside an additional firewall/isolation layer can be evaluated later.

## Release Asset Setup

The repository can remain private while publishing release assets. The release
workflow builds Linux and macOS binaries for amd64 and arm64, records each
asset's sha256 in the release notes, and attaches them (plus a shared
`checksums.txt`) to a GitHub **prerelease** using the automatic `GITHUB_TOKEN`
with `contents: write`. `release-targets.txt` is the canonical build matrix for
both tagged and rolling releases. The scheduled Release Platform Parity workflow
compares its asset names with the platforms supported by `gh-aw`'s installer.

Maintainers need to configure the following before the binary is consumed by `gh-aw`:

1. Keep Actions enabled for this private repository.
2. Grant the consuming `github/gh-aw` repository (or its `GITHUB_TOKEN`) `contents: read` access to download the release asset from this repository.
3. Keep the `release-publish` and `release-promote` environments if manual approval is desired; otherwise update the environment protection rules in repository settings.
4. Tag releases with semantic versions such as `v0.0.2`. The release workflow publishes the version-tagged prerelease; the promote workflow verifies the recorded asset sha256 and marks the release **Latest** (stable).

No additional secrets are required for unit tests, `make build`, `make test`, or the binary smoke test. Engine authentication is only needed when running real AI-backed detection:

| Variable | Required when | Notes |
|----------|---------------|-------|
| `COPILOT_GITHUB_TOKEN` | Running `--engine copilot` in an environment that needs explicit token-based Copilot authentication | Use a fine-grained PAT owned by a user account with **Account permissions → Copilot Requests: Read**. `GITHUB_TOKEN` is not sufficient for Copilot inference. |
| `ANTHROPIC_API_KEY` | Running `--engine claude` with the Claude CLI | Not used by unit tests. |
| `OPENAI_API_KEY` | Running `--engine codex` with the Codex CLI | Not used by unit tests. |
| `WORKFLOW_NAME` | Optional local runs | Included in the generated prompt. Overridable with `--workflow-name`. |
| `WORKFLOW_DESCRIPTION` | Optional local runs | Included in the generated prompt. Overridable with `--workflow-description`. |
| `CUSTOM_PROMPT` | Optional local runs | Appended to the default detection prompt. Overridable with `--custom-prompt` / `--custom-prompt-file`. |
| `GH_AW_DETECTION_CONTINUE_ON_ERROR` | Optional, host-integrated runs | Anything other than `"false"` is warn mode; the value is compared case-insensitively, so `"False"` also selects strict mode. Strict mode makes a degraded required input a `config_error` (exit `2`), and is also honored by `conclude`. |
| `HAS_PATCH` | Optional, host-integrated runs | `"true"` declares that the agent job produced a patch, so a missing `aw-*.patch` / `aw-*.bundle` is reported as a degraded required input. |

## Development

### Prerequisites

- Go 1.26+

### AW Smoke Workflows

This repository includes three Agentic Workflows smoke tests, one per engine:

- `.github/workflows/smoke-copilot-standalone.md`
- `.github/workflows/smoke-claude-standalone.md`
- `.github/workflows/smoke-codex-standalone.md`

Each runs daily and by `workflow_dispatch`. The top-level `Smoke` workflow can be dispatched manually to start all three at once. The matching `.lock.yml` files are the compiled AW workflows. gh-aw natively downloads this repo's released binary matching the runner platform (the external detector path is the compile-time default), runs it under AWF, and reads the structured `detection_result.json` to conclude. The detector version they install is resolved at run time — see [Detector Version Selection](#detector-version-selection).

**The smokes do exercise `threat-detect conclude`.** The compiled locks call gh-aw's `conclude_threat_detection.sh`, which does no JSON parsing of its own: it verifies `threat-detect` is on `PATH` and then `exec`s `threat-detect conclude --result-file … --detection-log …`. Because it passes no `--full-result-file`, the conventional sibling (`detection_result_full.json`) is derived and the reasons *are* recovered into the smokes' job logs, as are any `⚠️` warnings. The full result is written next to the result file and is not uploaded — the detection artifact lists `detection_result.json` by exact filename rather than a glob, so the companion never leaves the runner. Use [`replay-detection.yml`](#replay-workflow) when you want to rerun detection against a past run's artifacts, rather than as a way to see reasons.

**Codex detection model pin.** The Codex smokes pin the detection model explicitly:

```yaml
safe-outputs:
  threat-detection:
    engine:
      runtime:
        id: codex
      provider:
        model: gpt-5.4-mini
```

Without this, `gh-aw` passes its default `detection` model alias to `codex exec`. The
alias is resolved by the AWF API proxy's token steering, which can land on an
unpriced preview model; the proxy then rejects the request with
`unknown_model_ai_credits` and every Codex attempt exits non-zero, failing the
detection job with `reason=engine_error exit=2`. Copilot and Claude do not hit
this because `gh-aw` does not set `GH_AW_MODEL_DETECTION_{COPILOT,CLAUDE}` for
them. Pinning a concrete, priced OpenAI model keeps the pass cheap and
deterministic.

### Detector Version Selection

The smoke workflows do **not** pin a detector version. gh-aw emits the literal `latest` to `install_threat_detect_binary.sh`, which resolves it at run time via `GET /repos/github/gh-aw-threat-detection/releases/latest` — the newest **non-prerelease** release. Promoting a detector release is therefore all it takes to put that build in front of the smokes; no recompile, no new gh-aw release.

> [!NOTE]
> This repo previously carried a `smoke-<engine>-standalone-latest` counterpart of each smoke, compiled by a gh-aw whose `constants.DefaultThreatDetectVersion` had been patched to the newest detector build. That existed only because the constant used to be a hard-pinned tag that could not be moved without a new gh-aw release. gh-aw v0.86.x changed the default to `latest`, so those variants — and the patched-compiler build step they required — were removed.

Because `releases/latest` ignores prereleases, an **unpromoted** prerelease is never picked up automatically. To exercise one before promoting it, dispatch [`.github/workflows/replay-detection.yml`](.github/workflows/replay-detection.yml) with `detector_source=release`, `detector_ref=<prerelease tag>`, and `use_awf=true` against a prior gh-aw run's artifacts.

### Keeping the Compiled Locks Current

Every compiled workflow lock tracks a single gh-aw version: the newest `github/gh-aw` release **or prerelease**, whichever was published most recently (drafts and non-`v<digit>` tags ignored). There are no per-workflow categories — a bump recompiles all the locks together.

The `.github/workflows/gh-aw-version-check.yml` workflow runs daily (and on demand). It is **read-only** — it builds and compiles nothing. It reads the `compiler_version` already baked into each `.lock.yml`, compares it against that single target, and, when any lock is stale, opens (or updates) a single tracking issue listing every workflow that needs regenerating and the target version. When everything is in sync it closes that issue.

Regenerating the locks is a **separate, manual, human-reviewed step** because pushing changes under `.github/workflows/` requires a token with the `workflows` permission, which the built-in `GITHUB_TOKEN` lacks. Follow the [`update-workflow-versions`](skills/update-workflow-versions/SKILL.md) skill: recompile the affected sources with the target gh-aw version, then open a PR.

**Tag → test → promote loop:**

1. Cut a release tag (`create-release-tag.yml`); `release.yml` publishes a version-tagged **prerelease** with the recorded asset sha256.
2. Optionally exercise the prerelease under AWF via `replay-detection.yml` with `detector_source=release`, `detector_ref=<prerelease tag>`, and `use_awf=true`, as described above.
3. Promote with `promote-release.yml`; it re-verifies the asset sha256 and marks the release **Latest** (stable). The smokes pick up the promoted tag on their next run with no recompile.

> [!NOTE]
> `gh-aw-version-check.yml` only needs `contents: read` and `issues: write` — it detects drift and files an issue, but never pushes. Regenerating the `*.lock.yml` files (via the `update-workflow-versions` skill) is done by a maintainer/agent whose credentials carry the `workflows` permission.
>
> If you build the gh-aw compiler from source rather than installing the released extension, you must pass **both** `-X main.version=<TAG>` and `-X main.isRelease=true`. Without the latter, gh-aw normalizes the emitted `compiler_version` / `GH_AW_VERSION` to `dev` and skips release-only generation.

| Secret | Required for | Notes |
|--------|--------------|-------|
| `COPILOT_GITHUB_TOKEN` | Copilot smoke workflow and Copilot detection | Use a fine-grained PAT owned by a user account with **Account permissions → Copilot Requests: Read**. |
| `ANTHROPIC_API_KEY` | Claude smoke workflow and Claude detection | Used by the Claude CLI. |
| `OPENAI_API_KEY` or `CODEX_API_KEY` | Codex smoke workflow and Codex detection | Configure whichever token your Codex CLI setup expects. |
| `GH_AW_GITHUB_TOKEN` | Recommended for GitHub MCP access, safe outputs, and release-asset downloads | The generated workflows fall back to `GITHUB_TOKEN` where possible. |
| `GH_AW_GITHUB_MCP_SERVER_TOKEN` | Optional GitHub MCP override | Falls back to `GITHUB_TOKEN` in the compiled workflows. |

Optional Actions variables:

| Variable | Purpose |
|----------|---------|
| `GH_AW_MODEL_AGENT_COPILOT`, `GH_AW_MODEL_AGENT_CLAUDE`, `GH_AW_MODEL_AGENT_CODEX` | Override the agent model for each smoke workflow. |
| `GH_AW_MODEL_DETECTION_COPILOT`, `GH_AW_MODEL_DETECTION_CLAUDE`, `GH_AW_MODEL_DETECTION_CODEX` | Override the detection model for each engine. When `--model` is not passed, the detector reads the variable matching the selected engine; if it is unset, it falls back to the engine CLI's native model env var (`COPILOT_MODEL` for copilot, `ANTHROPIC_MODEL` for claude). |

### Detection Statistics Workflow

`.github/workflows/detection-stats-daily.md` (compiled to `detection-stats-daily.lock.yml`) is a daily agentic workflow that reports **error rates and detection results** for the `detection` jobs of another repository's agentic workflow runs — by default `github/gh-aw` — restricted to the runs that use the external `threat-detect` binary this repository ships.

It runs on a daily schedule and can be dispatched for any prior UTC date:

| Input | Default | Purpose |
|-------|---------|---------|
| `date` | yesterday | UTC day to analyse, `YYYY-MM-DD`. Backfill is bounded by the target repository's artifact retention: verdicts for expired artifacts are reported as `expired`. |
| `target_repo` | `github/gh-aw` | Repository to analyse, `owner/repo`. |
| `fetch_results` | `true` | Set to `false` for a cheap outcome-only scan that skips artifact downloads. |
| `max_requests` | `3000` | API request budget for the collector. |

**Data collection is deterministic, not agentic.** A dedicated `collect_detection_stats` job runs [`scripts/collect-detection-stats.sh`](scripts/collect-detection-stats.sh) before the agent and uploads a `detection-stats-<run id>` artifact; the agent only reads the pre-rendered digest and files the report issue. Keeping collection out of the agent is what makes the volume tractable — and it keeps the token that reads the target repository out of the agent job entirely.

What the collector records per run:

- whether the run had a `detection` job at all, and which detector it used. The `Install threat-detect binary` marker step is only observable on a job that got far enough to reach it — a skipped job reports no steps at all, and a cancelled or setup-failed one reports a truncated list — so classifying per run would drop exactly the failures this report exists to measure into the "built-in" bucket and out of every rate. The evidence is therefore rolled up per **workflow**: if any run of a workflow showed the marker that day, all of its detection jobs count as external. Anything still unresolved is reported as `indeterminate_detector_runs`, never as built-in;
- the detection job's `status`/`conclusion` (`success`, `failure`, `cancelled`, `skipped`, `timed_out`, `action_required`, or still `in_progress`) and the names of any failed steps;
- whether the job published a `detection_result.json` artifact and, if so, the `prompt_injection` / `secret_leak` / `malicious_patch` verdict. The published result deliberately carries `reasons: []`, so explanations are not available here — use the [replay workflow](#replay-workflow) when you need them. Any `warnings` the detector recorded *are* present in the published result, since they are detector-authored (see [Warnings vs reasons](#warnings-vs-reasons));
- the `conclusion`/`reason` pairs (`threat_detected`, `agent_failure`, `parse_error`) that gh-aw itself posts to its `[aw] Detection Runs` tracking issue.

A **green** detection job that published no verdict artifact is counted separately as a soft failure: gh-aw marks detection steps `continue-on-error`, so the Actions runner rewrites their `conclusion` to `success` and step conclusions cannot reveal these.

**Pagination.** Runs are enumerated with a server-side `created=<from>..<to>` filter. The Actions API refuses to page past 1000 results per query, so a window holding more than that is recursively bisected on time until every slice fits; results are merged and de-duplicated by run id. Non-agentic runs are then dropped for free, because the run listing already carries `path` and only `*.lock.yml` runs can have a detection job.

**Rate limits.** Every request goes through one helper that runs strictly serially (concurrency is what triggers GitHub's secondary limits), pauses between requests, sleeps until `x-ratelimit-reset` (or honours `retry-after`) on a 403/429 with no quota left, backs off exponentially on 5xx, and proactively pauses when the remaining primary quota drops below a floor. A request budget and a wall-clock deadline bound the whole run; when either is hit the collector **degrades gracefully** — it records a truncation note, marks `collection.complete: false`, and still emits a report rather than failing. Runs it never reached are still counted, as `runs_not_inspected`, so the shortfall stays visible instead of quietly shrinking the population every rate is computed over. Because collection works forward through the day, the inspected subset is the earlier part of it, so `collection.rates_cover_partial_day` marks the rates as a partial-day sample rather than a lower bound. Phases run cheapest-first, so a squeeze costs the most expensive data (verdicts) last.

Give the workflow a token with a generous quota. It prefers `GH_AW_GITHUB_MCP_SERVER_TOKEN`, then `GH_AW_GITHUB_TOKEN`, then `GITHUB_TOKEN`; the built-in `GITHUB_TOKEN` is limited to 1,000 requests/hour and will truncate on a busy day.

The collector is exercised offline by `scripts/test/collect-detection-stats-test.sh` (`make test-scripts`), which stubs the GitHub API and asserts window bisection, retry/backoff, multi-page jobs and artifacts listings, detector classification (including skipped and in-progress jobs), verdict classification and graceful truncation.

### Build

```bash
make build
```

### Test

```bash
make test
```

Shell-script tests (currently the detection-statistics collector) run separately
and need no Go toolchain:

```bash
make test-scripts
```

### Lint

```bash
make lint
```

### Smoke

Build the binary and run a `--version` smoke check:

```bash
make smoke
```

## Architecture

```
cmd/threat-detect/     CLI entry point
pkg/detector/          Core detection logic (prompt building, result parsing)
pkg/engine/            AI engine abstraction (copilot, claude, codex)
pkg/artifacts/         Artifact reading and validation
pkg/detector/prompts/  Embedded AI prompt template
specs/                 W3C-style specifications (detection behavior + usage)
```

## Integration with gh-aw

`gh-aw` references this component via:

```go
const DefaultThreatDetectionRepo    = "github/gh-aw-threat-detection"
const DefaultThreatDetectionVersion = "v0.0.2"
```

The detection job in compiled workflows downloads the pinned `threat-detect`
release asset matching the runner operating system and architecture and runs it
instead of inline AI engine invocation.

## Specification

See [specs/threat-detection-spec.md](specs/threat-detection-spec.md) for the full W3C-style specification of detection behavior, and [specs/usage-spec.md](specs/usage-spec.md) for the W3C-style usage specification covering how a host acquires, invokes, and concludes a detection run.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

## Maintainers

See [CODEOWNERS](CODEOWNERS) for maintainers.

## Support

See [SUPPORT.md](SUPPORT.md) for help, issue reporting, and support scope.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting instructions.

## License

See [LICENSE](LICENSE) for details.
