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

## Usage

### CLI

```bash
threat-detect [flags] <artifacts-dir>
```

**Flags:**
- `--engine` — AI engine to use (`copilot`, `claude`, `codex`). Default: `copilot`
- `--model` — Model override for the engine
- `--prompt-template` — Path to custom prompt template
- `--output` — Path to write JSON result (defaults to stdout)
- `--usage-output` — Path to write JSON AI credit usage (tokens, estimated cost) for the detection pass
- `--retries` — Retries for malformed detection outputs. Default: `1` (env: `THREAT_DETECTION_RETRIES`)
- `--version` — Print version and exit

`threat-detect` runs a single agentic CLI engine pass. The engine reports its
verdict in-session by invoking the `threat_detection_result` tool, which writes
a strict JSON object matching the result contract to an out-of-band result sink;
the detector cancels the engine subprocess as soon as a valid result is written.
The verdict is read exclusively from that sink; if no sink result is produced, a
one-shot self-correction prompt is retried, and retry exhaustion is treated as an
infrastructure error.

#### In-session result reporting (`threat_detection_result`)

On the agentic CLI engine path (`copilot`, `claude`, `codex`), the detector
provisions a `threat_detection_result` command on the model's `PATH` and sets
`THREAT_DETECTION_RESULT_FILE` to a private sink file before each engine
invocation. The model reports its verdict by running the command exactly once:

```bash
threat_detection_result --prompt-injection <true|false> --secret-leak <true|false> --malicious-patch <true|false> --reason "..."
```

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

#### Concluding a run (`conclude`)

In `gh-aw`-compiled workflows the detector runs inside the AWF sandbox, where the
verdict cannot reach the host over stdout. Instead, detection writes its structured
result to `detection_result.json` in a read-write mount, and a host-side step reads
it back with the `conclude` subcommand:

```bash
threat-detect conclude --result-file /tmp/gh-aw/threat-detection/detection_result.json
```

`conclude` reproduces the `gh-aw` job-output contract — it writes `conclusion`,
`reason`, and `success` to `GITHUB_OUTPUT` and exports `GH_AW_DETECTION_CONCLUSION`
and `GH_AW_DETECTION_REASON` to `GITHUB_ENV`. It reads these environment inputs:

- `RUN_DETECTION` — when not `"true"`, the verdict is `skipped`/`success`
- `GH_AW_DETECTION_CONTINUE_ON_ERROR` — anything other than `"false"` is warn mode
- `DETECTION_AGENTIC_EXECUTION_OUTCOME` — `"failure"` makes `agent_failure`/`parse_error` hard-fail

A missing result file reports `agent_failure` ("Detection result file not found
at: <path>"), a malformed file reports `parse_error`, and detected threats report
`threat_detected`. There is no log-scraping fallback: if the file is absent, the
step fails loudly.

### AI Credits and Token Usage

The threat-detection pass is a **separate agentic engine invocation** from the main
agentic run it guards. It builds its own prompt and runs the selected engine
(`copilot`, `claude`, or `codex`) once, so it consumes AI credits/tokens
**independently** — in addition to (not shared with) the workflow's primary run.
The cost is billed to the same engine account/credentials used for detection
(`COPILOT_GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, or `OPENAI_API_KEY`).

**Is there a separate token cap for the detection job?** There is no token-budget
cap enforced by this component. Two mechanisms bound the detection pass's cost:

- **Early termination** — as soon as the model records a verdict through the
  `threat_detection_result` tool, the detector cancels the engine subprocess, so
  the pass stops at the first valid verdict instead of running to the engine's
  own limit.
- **`max-turns`** — `gh-aw`'s `threat-detection.engine` configuration accepts a
  `max-turns` value that bounds the agentic loop (see the [spec](specs/threat-detection-spec.md), TD-14).

**Visibility into token usage.** After a successful run, `threat-detect` parses
best-effort token usage and estimated cost from the engine transcript and reports
them two ways:

1. A single machine-readable line on **stderr** (captured into the detection log):

   ```
   THREAT_DETECTION_USAGE: {"engine":"claude","model":"","tokens":1800,"estimated_cost":0.0123,"available":true}
   ```

2. A JSON file when `--usage-output <path>` is set, with the same object shape:

   ```json
   { "engine": "claude", "tokens": 1800, "estimated_cost": 0.0123, "available": true }
   ```

The figures are **best-effort**:

- `available` is `false` when no usage could be parsed. This happens for engines
  that do not surface usage on stdout (notably `copilot`, which writes usage to
  its own debug log), or when early termination truncates the transcript before
  the engine emits its final usage line.
- Token counts may **undercount** for the same early-termination reason; treat
  them as a lower bound. `estimated_cost` is reported only when the engine emits
  a cost field (for example Claude's `total_cost_usd`).

For authoritative billing, use the engine's own logs (uploaded as the detection
log artifact) together with `gh-aw`'s `logs` tooling, which performs the same
extraction across the full, untruncated transcript.

### Released binary

The `threat-detect` binary is published as a GitHub Release asset
(`threat-detect-linux-amd64`) alongside a `checksums.txt`. Download and run it
directly:

```bash
gh release download --repo github/gh-aw-threat-detection \
  --pattern threat-detect-linux-amd64 --pattern checksums.txt
sha256sum --check --ignore-missing checksums.txt
install -m 0755 threat-detect-linux-amd64 ./threat-detect
./threat-detect /path/to/artifacts
```

Omitting a tag downloads the latest stable (promoted) release. Production
AI-backed detection requires the selected engine CLI and its authentication to
be available on the runner where the binary runs.

### Input (Artifacts Directory)

```
<artifacts-dir>/
├── aw-prompts/
│   ├── prompt.txt          # Expanded workflow prompt file
│   ├── prompt-template.txt # Pre-expansion prompt template (optional)
│   └── prompt-import-tree.json # Runtime-import provenance (optional)
├── agent_output.json       # Agent structured output
├── aw_info.json            # Activation metadata (optional)
├── aw-*.patch              # Git format-patch files (optional)
├── aw-*.bundle             # Git bundle files (optional)
├── experiments/            # Experiment assignment/state files (optional)
└── comment-memory/         # Agent comment memory (optional)
    └── *.md
```

### Output (JSON)

```json
{
  "prompt_injection": false,
  "secret_leak": false,
  "malicious_patch": false,
  "reasons": []
}
```

### Replay workflow

Maintainers can manually run **Replay Threat Detection** from the Actions tab to rerun detection against artifacts from a prior workflow run. Provide the source repository and run ID; the workflow downloads the `agent`, `activation`, optional experiment, and optional original `detection` artifacts, normalizes them into the CLI input contract above, runs `threat-detect`, and uploads a sanitized `replay-detection-<run_id>` artifact with the manifest, file inventory, logs, replay result, and original-result comparison when available.

Replay uses the dispatching repository's `GITHUB_TOKEN`; no extra replay token is required. The selected source run must be accessible to that token.

Common dispatch examples:

- Current checkout, direct CLI replay: set `run_id`, leave `detector_source=current`, `engine=copilot`, and `use_awf=false`.
- Released detector replay: set `detector_source=release` and `detector_ref` to a release tag such as `v0.0.2`. The workflow downloads the `threat-detect-linux-amd64` asset and runs it on the host so the selected engine CLI can be installed there.
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
workflow builds `threat-detect-linux-amd64`, records its sha256 in the release
notes, and attaches it (plus `checksums.txt`) to a GitHub **prerelease** using
the automatic `GITHUB_TOKEN` with `contents: write`.

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
| `WORKFLOW_NAME` | Optional local runs | Included in the generated prompt. |
| `WORKFLOW_DESCRIPTION` | Optional local runs | Included in the generated prompt. |
| `CUSTOM_PROMPT` | Optional local runs | Appended to the default detection prompt. |

## Development

### Prerequisites

- Go 1.23+

### AW Smoke Workflows

This repository includes three Agentic Workflows smoke tests:

- `.github/workflows/smoke-copilot.md`
- `.github/workflows/smoke-claude.md`
- `.github/workflows/smoke-codex.md`

Each runs daily and by `workflow_dispatch`. The top-level `Smoke` workflow can be dispatched manually to start all three compiled smoke workflows and their three containerized siblings. The matching `.lock.yml` files are the compiled AW workflows. The `*-container.lock.yml` siblings are generated from those lock files by `scripts/create-threat-detection-sibling-workflows.py`; they download the released `threat-detect-linux-amd64` binary via `gh release download` and execute it under the same AWF wrapper used by the generated detection job. The script also copies matching `*-container.md` source sidecars from the original smoke markdown files so gh-aw's stale lock-file check can resolve and verify the inherited frontmatter hash.

### Detection-only Workflow

`.github/workflows/detection-only.yml` is a manual iteration workflow for the generated detection job. It keeps the copied detection job body aligned with the `-container` Copilot smoke sibling, while replacing prior activation and agent jobs with stubs that upload local fixtures from `testdata/detection-only/` as the `agent` artifact.

After recompiling the smoke workflows with `gh aw compile`, regenerate and verify the sibling workflows:

```bash
scripts/create-threat-detection-sibling-workflows.py
scripts/create-threat-detection-sibling-workflows.py --check
```

Configure these Actions secrets to enable all smoke workflows:

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
| `GH_AW_MODEL_DETECTION_COPILOT`, `GH_AW_MODEL_DETECTION_CLAUDE`, `GH_AW_MODEL_DETECTION_CODEX` | Override the detection model for each engine. |
| `GH_AW_THREAT_DETECTION_VERSION` | Override the detector release tag downloaded by the `*-container.lock.yml` siblings. Defaults to the latest stable (promoted) release. |

### Build

```bash
make build
```

### Test

```bash
make test
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
specs/                 W3C-style specification
```

## Integration with gh-aw

`gh-aw` references this component via:

```go
const DefaultThreatDetectionRepo    = "github/gh-aw-threat-detection"
const DefaultThreatDetectionVersion = "v0.0.2"
```

The detection job in compiled workflows downloads the pinned `threat-detect-linux-amd64` release asset and runs it instead of inline AI engine invocation.

## Specification

See [specs/threat-detection-spec.md](specs/threat-detection-spec.md) for the full W3C-style specification.

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
