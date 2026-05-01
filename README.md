# gh-aw-threat-detection

Threat Detection component for [GitHub Agentic Workflows](https://github.com/github/gh-aw). Analyzes AI agent output for security threats including prompt injection, secret leaks, and malicious patches.

## Contents

- [Quick Start](#quick-start)
- [Overview](#overview)
- [Guardrails and Security Considerations](#guardrails-and-security-considerations)
- [Usage](#usage)
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
prompts/               AI prompt templates
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

See [specs/threat-detection-spec.md](specs/threat-detection-spec.md) for the full W3C-style specification covering requirements TD-01 through TD-28.

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
