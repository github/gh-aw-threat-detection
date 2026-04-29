# gh-aw-threat-detection

Threat detection component for [GitHub Agentic Workflows](https://github.com/github/gh-aw). Analyzes AI agent output for security threats including prompt injection, secret leaks, and malicious patches.

## Overview

This tool runs as a standalone binary or container that analyzes artifacts produced by AI agents before safe outputs are permitted. It supports multiple AI engines (Copilot, Claude, Codex) for detection analysis.

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

## Development

### Prerequisites

- Go 1.23+
- Docker (for container builds)
- One of the supported AI engine CLIs installed (`copilot`, `claude`, or `codex`)

### Environment Variables

Copy `.env.example` to `.env` and configure as needed:

```bash
cp .env.example .env
```

| Variable | Required For | Purpose |
|----------|-------------|---------|
| `WORKFLOW_NAME` | Runtime | Name of the workflow being analyzed (default: "Unnamed Workflow") |
| `WORKFLOW_DESCRIPTION` | Runtime | Description of the workflow (default: "No description provided") |
| `CUSTOM_PROMPT` | Runtime (optional) | Additional detection instructions appended to prompt |
| `ANTHROPIC_API_KEY` | Claude engine | Authentication for Claude CLI |
| `OPENAI_API_KEY` | Codex engine | Authentication for Codex CLI |

**Note:** No environment variables are required for running tests — all tests use mocked inputs and do not call external AI engines.

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

## Architecture

```
cmd/threat-detect/     CLI entry point
pkg/detector/          Core detection logic (prompt building, result parsing)
pkg/engine/            AI engine abstraction (copilot, claude, codex)
pkg/artifacts/         Artifact reading and validation
specs/                 W3C-style specification
```

## Container Registry (GHCR)

This repository publishes container images to `ghcr.io/github/gh-aw-threat-detection`.

### Private Repository Setup

Container images from private repositories are accessible to other repositories within the same organization. To set up:

1. **GHCR authentication** — The release workflow uses `GITHUB_TOKEN` with `packages:write` permission (already configured in `.github/workflows/release.yml`). No additional secrets are needed.

2. **Package visibility** — After the first image push, go to the package settings (`https://github.com/orgs/github/packages/container/gh-aw-threat-detection/settings`) and grant read access to repositories that need to pull the image (e.g., `github/gh-aw`).

3. **Pulling from `gh-aw`** — The consuming repository uses its `GITHUB_TOKEN` to pull the image. No additional secrets are required for same-org private packages.

4. **Triggering a release** — Push a semver tag to trigger the release workflow:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

### Image Tags

The release workflow produces the following image tags:
- `ghcr.io/github/gh-aw-threat-detection:<version>` (e.g., `v1.0.0`)
- `ghcr.io/github/gh-aw-threat-detection:<major>.<minor>` (e.g., `1.0`)
- `ghcr.io/github/gh-aw-threat-detection:sha-<commit>` (immutable reference)

## Integration with gh-aw

After containerization, `gh-aw` references this component via:

```go
const DefaultThreatDetectionRegistry = "ghcr.io/github/gh-aw-threat-detection"
const DefaultThreatDetectionVersion  = "v1.0.0"
```

The detection job in compiled workflows uses this container instead of inline AI engine invocation.

## Specification

See [specs/threat-detection-spec.md](specs/threat-detection-spec.md) for the full W3C-style specification covering requirements TD-01 through TD-28.

## Design Decisions

The following decisions resolve questions from the original extraction issue:

1. **JS scripts rewritten in Go** — All detection logic (setup, parsing) is implemented in Go for consistency and single-binary deployment. No Node.js runtime dependency.

2. **Engine CLIs are NOT bundled** — The container expects AI engine CLIs to be available at runtime (installed via setup steps or pre-existing on the runner). This keeps the image small and avoids version coupling with CLI releases.

3. **Custom steps run outside the container** — The container handles only AI detection. Custom `steps:` and `post-steps:` from workflow config run as normal GitHub Actions steps before/after the container.

4. **Strict version pinning** — Following the firewall pattern, `gh-aw` pins to an exact version (`DefaultThreatDetectionVersion = "v1.0.0"`) with minimum version checks.

5. **Detection runs independently (not inside AWF)** — The detection job remains a standard GitHub Actions job. Network isolation is handled by the runner environment, not the firewall container.

6. **Ollama/LlamaGuard remains a custom-steps pattern** — Local model installations (Ollama) are configured via `steps:` in the workflow frontmatter, not as container variants.

## License

See [LICENSE](LICENSE) for details.
