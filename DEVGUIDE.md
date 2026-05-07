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

### Threat Detection Version Lifecycle

Maintainers manage the lifecycle for version-tagged threat detection releases in
[releases/threat-detection-lifecycle.json](releases/threat-detection-lifecycle.json).
The registry is the machine-readable source of truth consumed or vendored by the
parent `gh-aw` orchestrator before it pulls or runs the detector container.

Lifecycle statuses:

| Status | Meaning | Expected behavior |
|--------|---------|-------------------|
| `active` | Supported and safe to use | Run normally. |
| `deprecated` | Still supported, but users should migrate | Emit a GitHub Actions warning annotation and job summary text, then continue. |
| `obsolete` | No longer safe or supported | Fail closed before the detector container runs. |

Each lifecycle entry must include the version, status, reason, replacement
guidance, relevant deprecation or obsolescence dates, an advisory or release URL,
urgency, and a maintainer note. Replacement guidance must point to another
registry entry or be explicitly marked as a future or external replacement.

Maintainer responsibilities:

- promoted releases are `active` by default unless the registry says otherwise
- edit the registry during planned deprecations, before marking a version
  obsolete, and when promoting a replacement release
- ensure deprecated versions provide actionable warning text with the reason,
  replacement version, dates, advisory URL, urgency, and remediation steps
- ensure obsolete versions include enough guidance for `gh-aw` to fail before
  invoking the detector container and tell users exactly how to upgrade
- run `make lifecycle-validate` before release or promotion changes that edit
  lifecycle metadata

Lifecycle enforcement must not rely only on code inside old detector binaries.
Previously released detectors cannot learn that they later became obsolete unless
they receive external metadata or network access, and detector runtime egress may
be blocked. The parent `gh-aw` orchestrator or generated workflow should perform
the lifecycle check before pulling or running this container.

### Promotion Model

Releases follow a **prerelease → promote** model:

1. **Create tag (manual)** — a maintainer triggers the
   [Create Release Tag workflow](.github/workflows/create-release-tag.yml) via
   **Actions → Create Release Tag → Run workflow** and selects a patch or minor
   bump. The workflow validates `main` and pushes the next `vX.Y.Z` tag.

2. **Build & Publish (automated)** — pushing a tag matching `v*` triggers the
   [release workflow](.github/workflows/release.yml). It builds artifacts,
   pushes a version-tagged container image (e.g. `ghcr.io/github/gh-aw-threat-detection:v1.2.3`),
   and creates a **prerelease** on GitHub that records the image digest. The `release-publish` environment gate
   pauses the workflow before publishing so maintainers can abort if needed.

3. **Promote (manual)** — after verifying the prerelease, a maintainer triggers
   the [promote-release workflow](.github/workflows/promote-release.yml) via
   **Actions → Promote Release → Run workflow**, entering the tag name. This
   workflow (gated by the `release-promote` environment):
   - verifies the release is still a prerelease
   - pulls the recorded image digest and pushes that exact image as `latest`
   - marks the GitHub release as stable and explicitly selects it as Latest (`--prerelease=false --latest`)

The `latest` container tag and the GitHub "Latest" release badge only move
when a maintainer explicitly promotes. This gives the team time to validate a
release before it becomes the default for users installing with `version: latest`.

### CI Support

The main CI workflow in [.github/workflows/ci.yml](.github/workflows/ci.yml) runs:

- `go vet`
- `go test -race`
- `go build`

### Release Steps

1. Go to **Actions → Create Release Tag → Run workflow**.
2. Select `patch` or `minor`. The visible `major` option may still appear in
   the workflow UI, but it is currently rejected by the workflow until major
   releases are enabled.
3. Run the workflow. It validates `main`, computes the next semantic-version
   tag, and pushes it to trigger the release workflow.

After the tag is pushed:

1. Approve the `release-publish` environment gate when the workflow pauses.
2. Verify the prerelease on the [Releases page](../../releases) and test the
   version-tagged container image.
3. Confirm the lifecycle registry is correct for the release being promoted and
   any versions it replaces; update and validate it with `make lifecycle-validate`
   if statuses changed.
4. When satisfied, go to **Actions → Promote Release**, enter the tag, and run
   the workflow. Approve the `release-promote` environment gate.
5. Confirm `latest` now resolves to the new version.
