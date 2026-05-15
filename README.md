# gh-aw-threat-detection

Threat Detection component for [GitHub Agentic Workflows](https://github.com/github/gh-aw). Analyzes AI agent output for security threats including prompt injection, secret leaks, and malicious patches.

## Contents

- [Quick Start](#quick-start)
- [Overview](#overview)
- [Guardrails and Security Considerations](#guardrails-and-security-considerations)
- [Usage](#usage)
- [Stage Status and Decisions](#stage-status-and-decisions)
- [Private Container Release Setup](#private-container-release-setup)
- [Release Lifecycle and Emergency Yanks](#release-lifecycle-and-emergency-yanks)
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

This tool runs as a standalone binary or container that analyzes artifacts produced by AI agents before safe outputs are permitted. It supports multiple AI engines (Copilot, Claude, Codex) for detection analysis.

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
- `--triage` — Enable fast Phase 1 structured-output triage. Default: `true`
- `--reflect-url` — `api-proxy` `/reflect` base URL for structured-output calls. Default: `http://127.0.0.1:8080/reflect`
- `--triage-model` — Model override for Phase 1 `/reflect` triage
- `--triage-max-bytes` — Maximum bytes per artifact to inline during triage
- `--triage-retries` — Retries for malformed structured-output responses
- `--version` — Print version and exit

`--reflect-url` can also be supplied with `THREAT_DETECTION_REFLECT_URL`,
`API_PROXY_REFLECT_URL`, or `REFLECT_URL`. By default, `threat-detect` first
tries a non-agentic `/reflect` call with a strict JSON schema matching the result
contract. An all-false valid triage result exits successfully without the full
detector. Threats, uncertainty, unsupported models, proxy errors, or malformed
responses fail safe into the full detector. The full detector preserves the
existing CLI engine behavior and prefers `/reflect` structured output when a
schema-capable model is available.

Set `THREAT_DETECTION_LOG_REFLECT_RESPONSE=true` to print raw `/reflect`
responses to stderr for controlled debugging. Responses may include reflected
artifact content, so leave this disabled outside targeted diagnostic runs.

**Exit codes:**
- `0` — Safe (no threats detected)
- `1` — Threat detected
- `2` — Infrastructure/configuration error

### Container

```bash
docker run --rm \
  -v /path/to/artifacts:/workspace/artifacts \
  ghcr.io/github/gh-aw-threat-detection:v0.0.2 \
  /workspace/artifacts
```

The current image is suitable for CLI packaging and smoke testing.
Production AI-backed detection requires the selected engine CLI and its authentication to be available in the runtime image or installed by a future image variant.

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
- Released detector replay: set `detector_source=release` and `detector_ref` to a release tag such as `v0.0.2`.
- Image detector replay: set `detector_source=image` and optionally set `detector_ref` to an image tag. The workflow extracts the `threat-detect` binary from the image and runs it on the host so the selected engine CLI can be installed there.
- Model comparison: set `model` to the engine-specific model name to pass through `--model`.
- Additional detection instructions: set `custom_prompt`; it is passed as `CUSTOM_PROMPT` and appended to the default detector prompt.
- AWF mode: set `use_awf=true` only on a runner image that already provides the `awf` CLI. Direct mode is the default.

The `run_attempt` input is only safe for the latest attempt of a source run because GitHub artifact downloads are not attempt-scoped. The workflow fails with a clear error if an older attempt is requested.

## Stage Status and Decisions

The extraction staging model is:
- Stage 1: standalone repository
- Stage 2: containerization
- Stage 3: `github/gh-aw` integration

Stage 1 is functionally represented in this repository.
The standalone Go CLI, artifact reader, prompt builder, two-phase `/reflect` triage, result parser, engine abstraction, W3C-style specification, unit tests, CI, Dockerfile, and release workflow are present.
Remaining work involves integration with `github/gh-aw` and production hardening of the container runtime in Stage 2/3, not additional JavaScript porting in this repository.

Decisions for the unresolved extraction questions:

- **JavaScript scripts**: detection setup and result parsing are implemented in Go here; the old GitHub Actions JavaScript scripts should not be needed once `gh-aw` switches to the container contract.
- **Engine CLIs and `/reflect`**: do not bundle Copilot, Claude, or Codex CLIs into the detector image. The detector invokes the selected engine CLI from `PATH` and forwards the `--model` value when full CLI analysis is needed. When `--reflect-url` is configured, the detector can call `api-proxy` directly for structured-output triage and schema-capable full analysis before falling back to CLI behavior. Production `gh-aw` integration should install or provide the selected engine CLI in the detection job, then run the pinned detector binary extracted from the detector image in that same runner/AWF environment. This keeps the image small, avoids runtime installation inside the image, and reuses the existing engine installation/authentication path.
- **Custom steps**: custom `threat-detection.steps` remain orchestrator-owned. They should run before or after the container in the `gh-aw` job rather than being passed into this container as arbitrary scripts.
- **Backward compatibility**: do not ship a long-lived dual-mode compatibility window. Stage 3 should switch `gh-aw` to the pinned detector image path after Stage 4 validation passes; users that need inline detection can pin an older `gh-aw` release. A temporary internal fallback is acceptable during implementation only, but should not become a documented public feature flag unless Stage 4 exposes a blocking compatibility issue.
- **Ollama/LlamaGuard**: keep this as a custom-step pattern unless a dedicated image variant is explicitly required.
- **Version coupling**: use strict, semver-compatible image tags and have `gh-aw` pin a specific `DefaultThreatDetectionVersion`, matching the firewall pattern.
- **Isolation**: the detector should run in the standard detection job initially. Running the detector itself inside an additional firewall/isolation layer can be evaluated later.

## Private Container Release Setup

The repository can move through Stage 2 while remaining private. GitHub Container Registry supports private packages, and the release workflow publishes `ghcr.io/github/gh-aw-threat-detection:<tag>` using the automatic `GITHUB_TOKEN` with `packages: write`.

Maintainers need to configure the following before the image is consumed by `gh-aw`:

1. Keep Actions enabled for this private repository.
2. Ensure the package created under `ghcr.io/github/gh-aw-threat-detection` inherits repository visibility or is explicitly private.
3. Grant the consuming `github/gh-aw` repository access to the private package, or configure the organization package settings so `GITHUB_TOKEN` from `gh-aw` can pull it with `packages: read`.
4. Keep the `release-publish` and `release-promote` environments if manual approval is desired; otherwise update the environment protection rules in repository settings.
5. Tag releases with semantic versions such as `v0.0.2`. The release workflow publishes the version tag; the promote workflow tags the verified digest as `latest`.

No additional secrets are required for unit tests, `make build`, `make test`, or the container smoke test. Engine authentication is only needed when running real AI-backed detection:

| Variable | Required when | Notes |
|----------|---------------|-------|
| `COPILOT_GITHUB_TOKEN` | Running `--engine copilot` in an environment that needs explicit token-based Copilot authentication | Use a fine-grained PAT owned by a user account with **Account permissions → Copilot Requests: Read**. `GITHUB_TOKEN` is not sufficient for Copilot inference. |
| `ANTHROPIC_API_KEY` | Running `--engine claude` with the Claude CLI | Not used by unit tests. |
| `OPENAI_API_KEY` | Running `--engine codex` with the Codex CLI | Not used by unit tests. |
| `WORKFLOW_NAME` | Optional local/container runs | Included in the generated prompt. |
| `WORKFLOW_DESCRIPTION` | Optional local/container runs | Included in the generated prompt. |
| `CUSTOM_PROMPT` | Optional local/container runs | Appended to the default detection prompt. |

## Release Lifecycle and Emergency Yanks

Release lifecycle metadata is recorded in [`releases/threat-detection-lifecycle.json`](releases/threat-detection-lifecycle.json).
The registry supports `active`, `deprecated`, `obsolete`, and `yanked` states.
`yanked` means a release is unsafe to run and is stronger than `obsolete`.

The parent orchestrator (`gh-aw`) must check this registry before pulling or
running a detector image:

- `latest` must not point at a yanked version. Maintainers use the manual
  **Yank Release** workflow to retag `latest` to a safe stable replacement.
- Explicit version or digest pins that match a yanked registry entry must fail
  closed before detector execution.
- Explicit pins must not be silently downgraded or upgraded; the failure message
  should include the yank reason and replacement version.

Yanked release artifacts remain available for audit and forensics unless
maintainers choose separate package removal. See [DEVGUIDE.md](DEVGUIDE.md#emergency-yank-process)
for maintainer approval, communication, and workflow details.

## Development

### Prerequisites

- Go 1.23+
- Docker (for container builds)

### AW Smoke Workflows

This repository includes three Agentic Workflows smoke tests:

- `.github/workflows/smoke-copilot.md`
- `.github/workflows/smoke-claude.md`
- `.github/workflows/smoke-codex.md`

Each runs daily and by `workflow_dispatch`. The top-level `Smoke` workflow can be dispatched manually to start all three compiled smoke workflows and their three containerized siblings. The matching `.lock.yml` files are the compiled AW workflows. The `*-container.lock.yml` siblings are generated from those lock files by `scripts/create-threat-detection-sibling-workflows.py`; they pull the `ghcr.io/github/gh-aw-threat-detection` container, extract its detector binary, and execute it under the same AWF wrapper used by the generated detection job. The script also copies matching `*-container.md` source sidecars from the original smoke markdown files so gh-aw's stale lock-file check can resolve and verify the inherited frontmatter hash.

### Detection-only Workflow

`.github/workflows/detection-only.yml` is a manual iteration workflow for the generated detection job. It keeps the copied detection job body aligned with the containerized Copilot smoke workflow, while replacing prior activation and agent jobs with stubs that upload local fixtures from `testdata/detection-only/` as the `agent` artifact.

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
| `GH_AW_GITHUB_TOKEN` | Recommended for GitHub MCP access, safe outputs, and private GHCR pulls | The generated workflows fall back to `GITHUB_TOKEN` where possible. |
| `GH_AW_GITHUB_MCP_SERVER_TOKEN` | Optional GitHub MCP override | Falls back to `GITHUB_TOKEN` in the compiled workflows. |

Optional Actions variables:

| Variable | Purpose |
|----------|---------|
| `GH_AW_MODEL_AGENT_COPILOT`, `GH_AW_MODEL_AGENT_CLAUDE`, `GH_AW_MODEL_AGENT_CODEX` | Override the agent model for each smoke workflow. |
| `GH_AW_MODEL_DETECTION_COPILOT`, `GH_AW_MODEL_DETECTION_CLAUDE`, `GH_AW_MODEL_DETECTION_CODEX` | Override the detection model for each engine. |
| `GH_AW_THREAT_DETECTION_IMAGE` | Override the detector image used by the `*-container.lock.yml` siblings. Defaults to `ghcr.io/github/gh-aw-threat-detection:v0.0.2`. |

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

### Docker

```bash
make docker-build
```

Run the container smoke test:

```bash
make docker-smoke
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

After containerization, `gh-aw` references this component via:

```go
const DefaultThreatDetectionRegistry = "ghcr.io/github/gh-aw-threat-detection"
const DefaultThreatDetectionVersion  = "v0.0.2"
```

The detection job in compiled workflows uses this container instead of inline AI engine invocation.

`gh-aw` should also fetch or vendor
[releases/threat-detection-lifecycle.json](releases/threat-detection-lifecycle.json)
and evaluate the pinned `DefaultThreatDetectionVersion` before pulling or
running the detector container. Active versions run normally. Deprecated versions
should emit a GitHub Actions warning annotation and job summary text that include
the reason, replacement version, dates, advisory URL, urgency, and upgrade
instructions, then continue. Obsolete versions should fail closed before the
detector runs and print the same remediation guidance. Unknown versions should
follow the registry policy, currently `fail-closed`.

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
