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

### Promotion Model

Releases follow a **prerelease → promote** model:

1. **Build & Publish (automated)** — pushing a tag matching `v*` triggers the
   [release workflow](.github/workflows/release.yml). It builds artifacts,
   pushes a version-tagged container image (e.g. `ghcr.io/github/gh-aw-threat-detection:v1.2.3`),
   and creates a **prerelease** on GitHub that records the image digest. The `release-publish` environment gate
   pauses the workflow before publishing so maintainers can abort if needed.

2. **Promote (manual)** — after verifying the prerelease, a maintainer triggers
   the [promote-release workflow](.github/workflows/promote-release.yml) via
   **Actions → Promote Release → Run workflow**, entering the tag name. This
   workflow (gated by the `release-promote` environment):
   - verifies the release is still a prerelease
   - pulls the recorded image digest and pushes that exact image as `latest`
   - marks the GitHub release as stable and explicitly selects it as Latest (`--prerelease=false --latest`)

The `latest` container tag and the GitHub "Latest" release badge only move
when a maintainer explicitly promotes. This gives the team time to validate a
release before it becomes the default for users installing with `version: latest`.

### Lifecycle Registry

Release lifecycle metadata lives in
[releases/threat-detection-lifecycle.json](releases/threat-detection-lifecycle.json).
Maintainers use one registry for all stable lifecycle states:

- `active` — safe for new and pinned use.
- `deprecated` — still allowed to run, but users should plan an upgrade.
- `obsolete` — unsupported and not suitable for new use.
- `yanked` — unsafe because of a security or correctness issue; stronger than
  `obsolete` and must fail closed.

`gh-aw` must check this registry before pulling or running a selected detector.
If a user explicitly pins a yanked version or yanked digest, `gh-aw` must fail
closed with the yank reason and safe replacement. It must not silently downgrade
or upgrade explicit pins. `latest` is floating, so maintainers may retag it to a
safe replacement during a yank.

Validate registry edits with:

```bash
make validate-lifecycle
```

Yanked entries must include the version, image digest, yank date, severity,
reason, replacement version, replacement digest, and any incident or advisory URL
available at the time. Use `no_safe_replacement: true` only when maintainers have
confirmed there is no safe replacement to recommend.

### Emergency Yank Process

Yank only when a released detector is unsafe to run, such as a detector that can
miss high-impact malicious behavior, mishandle secrets, or otherwise produce
unsafe results. A yank requires approval through the `release-yank` environment
by a core maintainer or incident commander.

Before yanking:

1. Identify the bad version and immutable image digest.
2. Select the most recent safe stable replacement.
3. Record the severity, user-facing reason, advisory or incident link when
   available, and any maintainer-only note.
4. Prepare user communication that explains the failure mode and replacement.

To yank a release, run **Actions → Yank Release → Run workflow** from the default
branch. The workflow:

1. verifies the yanked and replacement releases exist and record sha256 image
   digests
2. rejects replacement releases that are prerelease, yanked, or obsolete
3. verifies both images are still pullable
4. records the yanked status in the lifecycle registry
5. retags `latest` to the replacement digest
6. marks the yanked GitHub release title and notes with a warning
7. removes the yanked release from GitHub's Latest selection and marks the
   replacement as Latest

Keep yanked artifacts available for audit and forensics unless legal or security
policy requires package deletion. If branch protection prevents the workflow from
committing the lifecycle registry update directly, create and merge an emergency
PR with the same registry changes before announcing the yank as complete.

### CI Support

The main CI workflow in [.github/workflows/ci.yml](.github/workflows/ci.yml) runs:

- `go vet`
- `go test -race`
- `go build`

### Release Steps

```bash
# 1. Tag and push — triggers the release workflow
git checkout main
git pull
make agent-finish
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

After pushing the tag:

1. Approve the `release-publish` environment gate when the workflow pauses.
2. Verify the prerelease on the [Releases page](../../releases) and test the
   version-tagged container image.
3. When satisfied, go to **Actions → Promote Release**, enter the tag, and run
   the workflow. Approve the `release-promote` environment gate.
4. Confirm `latest` now resolves to the new version.

If a promoted release is later found unsafe, follow the emergency yank process
above instead of deleting tags or relying on GHCR package removal as the primary
control.
