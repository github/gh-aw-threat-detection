# gh-aw-threat-detection

Threat Detection component for [GitHub Agentic Workflows](https://github.com/github/gh-aw). Analyzes AI agent output for security threats including prompt injection, secret leaks, and malicious patches.

## Contents

- [Quick Start](#quick-start)
- [Overview](#overview)
- [Guardrails and Security Considerations](#guardrails-and-security-considerations)
- [Usage](#usage)
- [Stage Status and Decisions](#stage-status-and-decisions)
- [Private Container Release Setup](#private-container-release-setup)
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
- `--version` — Print version and exit

**Exit codes:**
- `0` — Safe (no threats detected)
- `1` — Threat detected
- `2` — Infrastructure/configuration error

### Container

```bash
docker run --rm \
  -v /path/to/artifacts:/workspace/artifacts \
  ghcr.io/github/gh-aw-threat-detection:latest \
  /workspace/artifacts
```

The current image is suitable for CLI packaging and smoke testing. Production AI-backed detection also requires the selected engine CLI and its authentication to be available in the runtime image or installed by a future image variant.

### Input (Artifacts Directory)

```
<artifacts-dir>/
├── aw-prompts/
│   └── prompt.txt          # Workflow prompt file
├── agent_output.json       # Agent structured output
├── aw-*.patch              # Git format-patch files (optional)
├── aw-*.bundle             # Git bundle files (optional)
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

## Stage Status and Decisions

Stage 1 is functionally represented in this repository: the standalone Go CLI, artifact reader, prompt builder, result parser, engine abstraction, W3C-style specification, unit tests, CI, Dockerfile, and release workflow are present. Remaining parity work is integration work with `github/gh-aw` and production hardening of the container runtime in Stage 2/3, not additional JavaScript porting in this repository.

Decisions for the unresolved extraction questions:

- **JavaScript scripts**: detection setup and result parsing are implemented in Go here; the old GitHub Actions JavaScript scripts should not be needed once `gh-aw` switches to the container contract.
- **Engine CLIs**: the detector invokes the selected engine CLI from `PATH` and forwards the `--model` value. Stage 2 should either bundle the supported CLIs into the image or publish an image variant that installs them at runtime before invoking `threat-detect`.
- **Custom steps**: custom `threat-detection.steps` remain orchestrator-owned. They should run before or after the container in the `gh-aw` job rather than being passed into this container as arbitrary scripts.
- **Backward compatibility**: `gh-aw` should pin a specific image tag and may temporarily keep inline detection behind a compatibility flag until the container path is validated.
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
5. Tag releases with semantic versions such as `v1.0.0`. The release workflow publishes the version tag; the promote workflow tags the verified digest as `latest`.

No additional secrets are required for unit tests, `make build`, `make test`, or the container smoke test. Engine authentication is only needed when running real AI-backed detection:

| Variable | Required when | Notes |
|----------|---------------|-------|
| `GH_AW_COPILOT_TOKEN` or equivalent Copilot auth | Running `--engine copilot` in an environment that needs explicit Copilot authentication | Exact variable consumption depends on the Copilot CLI. |
| `ANTHROPIC_API_KEY` | Running `--engine claude` with the Claude CLI | Not used by unit tests. |
| `OPENAI_API_KEY` | Running `--engine codex` with the Codex CLI | Not used by unit tests. |
| `WORKFLOW_NAME` | Optional local/container runs | Included in the generated prompt. |
| `WORKFLOW_DESCRIPTION` | Optional local/container runs | Included in the generated prompt. |
| `CUSTOM_PROMPT` | Optional local/container runs | Appended to the default detection prompt. |

## Development

### Prerequisites

- Go 1.23+
- Docker (for container builds)

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
const DefaultThreatDetectionVersion  = "v1.0.0"
```

The detection job in compiled workflows uses this container instead of inline AI engine invocation.

## Specification

See [specs/threat-detection-spec.md](specs/threat-detection-spec.md) for the full W3C-style specification covering requirements TD-01 through TD-30.

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
