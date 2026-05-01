# Developer Guide

This guide is the maintainer-oriented reference for `gh-aw-threat-detection`.

It is intentionally shorter than the parent `gh-aw` guide and only covers the surfaces that exist in this repository.

## Scope

This repository contains the threat detection component used by GitHub Agentic Workflows.

Core responsibilities:

- read agent artifacts from an artifacts directory
- evaluate those artifacts for prompt injection, secret leakage, and malicious patch risk
- produce a machine-readable detection result before downstream `safe-outputs` handling proceeds

The canonical behavior specification for this repository lives in [specs/threat-detection-spec.md](specs/threat-detection-spec.md).

## Development Environment

Preferred setup:

- GitHub Codespaces or the local dev container in [.devcontainer/devcontainer.json](.devcontainer/devcontainer.json)

The dev container keeps model-related tooling available, including GitHub CLI, Docker, Copilot CLI, and optional Vertex-backed Claude setup. Vertex credentials are optional and configured by setting `VERTEX_API_JSON` before container creation.

### Local Setup

```bash
git clone https://github.com/github/gh-aw-threat-detection.git
cd gh-aw-threat-detection
make deps
make build
```

### Full Maintainer Setup

```bash
make deps-dev
make test
make build
```

## Daily Workflow

Common commands:

```bash
make build          # build the CLI
make test           # run Go tests
make lint           # run go vet
make fmt            # format Go code
make security-scan  # run gosec and govulncheck
make agent-finish   # maintainer validation flow
```

What `make agent-finish` currently runs:

- `deps-dev`
- `fmt`
- `lint`
- `build`
- `test`
- `security-scan`

Use `make help` to see the full list of maintained targets.

## Repository Layout

```text
/
├── .devcontainer/       # Codespaces and Dev Container setup
├── .github/workflows/   # CI and release workflows
├── cmd/threat-detect/   # CLI entrypoint
├── pkg/artifacts/       # Artifact loading and validation
├── pkg/detector/        # Threat detection logic and prompt templates
├── pkg/engine/          # AI engine abstraction and adapters
├── scratchpad/          # Design references retained from gh-aw where still relevant
├── skills/              # Small repo-relevant agent skills
├── specs/               # Threat detection specification
└── Makefile             # Build and maintainer commands
```

## Detection-Focused Development Notes

### Inputs To The Detection Module

The detector operates on an artifacts directory. The current expected shape is documented in [README.md](README.md) and [specs/threat-detection-spec.md](specs/threat-detection-spec.md), including:

- `aw-prompts/prompt.txt`
- `agent_output.json`
- optional `aw-*.patch`
- optional `aw-*.bundle`
- optional `comment-memory/*.md`

When changing artifact handling, review:

- [pkg/artifacts](pkg/artifacts)
- [specs/threat-detection-spec.md](specs/threat-detection-spec.md)
- [scratchpad/artifact-naming-compatibility.md](scratchpad/artifact-naming-compatibility.md)

### Safe Outputs Context

Threat detection sits upstream of `safe-outputs`. This repo does not implement the full `safe-outputs` system, but changes here should preserve the assumptions made by downstream consumers.

Useful references:

- [scratchpad/safe-outputs-specification.md](scratchpad/safe-outputs-specification.md)
- [scratchpad/safe-output-environment-variables.md](scratchpad/safe-output-environment-variables.md)
- [scratchpad/safe-output-messages.md](scratchpad/safe-output-messages.md)

## Maintainer Guidance

When changing code in this repository:

- keep behavior aligned with [specs/threat-detection-spec.md](specs/threat-detection-spec.md)
- prefer small, local packages and targeted tests
- update README or spec text when behavior changes
- preserve the JSON result contract unless the spec intentionally changes it

Useful retained references:

- [scratchpad/code-organization.md](scratchpad/code-organization.md)
- [scratchpad/validation-architecture.md](scratchpad/validation-architecture.md)
- [scratchpad/go-type-patterns.md](scratchpad/go-type-patterns.md)
- [scratchpad/styles-guide.md](scratchpad/styles-guide.md)
- [scratchpad/errors.md](scratchpad/errors.md)
- [scratchpad/testing.md](scratchpad/testing.md)
- [skills/console-rendering/SKILL.md](skills/console-rendering/SKILL.md)
- [skills/error-messages/SKILL.md](skills/error-messages/SKILL.md)

## Troubleshooting

Common reset flow:

```bash
make clean
make deps
make build
make test
```

If tooling is missing:

- run `make deps-dev` to install maintainer dependencies
- reopen the dev container if local environment drift is suspected

## Release Process

This section stays in place even though the release flow is still being built out.

### Current State

The repository already has a release workflow in [.github/workflows/release.yml](.github/workflows/release.yml).

Today, pushing a tag matching `v*` triggers a workflow that:

1. checks out the repository
2. runs tests
3. builds the Linux `threat-detect` binary
4. logs into GHCR
5. builds and pushes container images tagged with the version and `latest`

### Current CI Support

The main CI workflow in [.github/workflows/ci.yml](.github/workflows/ci.yml) runs:

- `go vet`
- `go test -race`
- `go build`

### Release Steps For Now

Until the release process is expanded further, maintainers should treat releases as a controlled manual operation:

```bash
git checkout main
git pull
make agent-finish
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

After pushing the tag, verify the workflow run and confirm the container image was published to GHCR.

### Planned Follow-up

Release work is still incomplete and tracked separately in TODOs. Areas still to build out include:

- GitHub release creation and release notes
- release assets and checksums
- any gated/manual promotion flow
- any post-tag synchronization workflow if this repo needs to mirror the parent project’s model more closely

Do not describe the current release flow as fully complete or production-final until those items are addressed.
