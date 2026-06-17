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

### In-Session Result Reporting (`report-result`)

The agentic CLI engine path (`copilot`, `claude`, `codex`) gives the detection
model an in-session, validated reporting channel instead of relying solely on
post-hoc transcript scraping:

- `threat-detect report-result` is an internal subcommand (dispatched in `main()`
  before global flag parsing; intentionally omitted from `--help`). It validates
  the verdict against the existing result schema, then atomically records
  canonical JSON to the path in `--result-file` / `THREAT_DETECTION_RESULT_FILE`.
  Invalid input prints `THREAT_DETECTION_RESULT_ERROR:` and exits non-zero without
  recording (exit `2`); a missing sink path exits `3`. The first valid write wins
  (idempotent); a later valid call prints "already recorded" without overwriting.
- Before each engine run, `pkg/engine` provisions a `threat_detection_result`
  wrapper script on `PATH` (`provisionResultTool`) that execs `report-result`,
  and sets `THREAT_DETECTION_RESULT_FILE`. `watchResultSink` polls the sink and
  cancels the engine subprocess as soon as a valid result is recorded (early
  termination). A subprocess kill is treated as success when a valid sink result
  exists.
- `analyzeWithRetries` prefers the sink result (`detector.ReadResultFile`) and
  only falls back to `detector.ParseResult` transcript scraping when the sink is
  absent or invalid. Helpers live in `pkg/detector/result.go`
  (`WriteResultFile`, `ReadResultFile`, `BuildResultFromReport`,
  `ValidateReportFields`).
- Claude is invoked with `--allowed-tools Bash` when the sink is enabled so it
  can execute the wrapper; engines that cannot run shell tools fall back to the
  legacy `THREAT_DETECTION_RESULT:{...}` transcript line, which remains supported.

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
parent `gh-aw` orchestrator before it downloads or runs the detector binary.

Lifecycle statuses:

| Status | Meaning | Expected behavior |
|--------|---------|-------------------|
| `active` | Supported and safe to use | Run normally. |
| `deprecated` | Still supported, but users should migrate | Emit a GitHub Actions warning annotation and job summary text, then continue. |
| `obsolete` | No longer safe or supported | Fail closed before the detector runs. |
| `yanked` | Unsafe because of a security or correctness issue | Fail closed before the detector runs. |

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
  invoking the detector and tell users exactly how to upgrade
- run `make lifecycle-validate` before release or promotion changes that edit
  lifecycle metadata

Lifecycle enforcement must not rely only on code inside old detector binaries.
Previously released detectors cannot learn that they later became obsolete unless
they receive external metadata or network access, and detector runtime egress may
be blocked. The parent `gh-aw` orchestrator or generated workflow should perform
the lifecycle check before downloading or running this binary.

### Promotion Model

Releases follow a **prerelease → promote** model:

1. **Create tag (manual)** — a maintainer triggers the
   [Create Release Tag workflow](.github/workflows/create-release-tag.yml) via
   **Actions → Create Release Tag → Run workflow** and selects a patch or minor
   bump. The workflow validates `main` and pushes the next `vX.Y.Z` tag.

2. **Build & Publish (automated)** — pushing a tag matching `v*` triggers the
   [release workflow](.github/workflows/release.yml). It builds the
   `threat-detect-linux-amd64` binary, attaches it (plus `checksums.txt`) to a
   **prerelease** on GitHub, and records the asset sha256 in the release notes.
   The `release-publish` environment gate
   pauses the workflow before publishing so maintainers can abort if needed.

3. **Promote (manual)** — after verifying the prerelease, a maintainer triggers
   the [promote-release workflow](.github/workflows/promote-release.yml) via
   **Actions → Promote Release → Run workflow**, entering the tag name. This
   workflow (gated by the `release-promote` environment):
   - verifies the release is still a prerelease
   - re-downloads the asset and verifies its sha256 against the recorded value
   - marks the GitHub release as stable and explicitly selects it as Latest (`--prerelease=false --latest`)

The GitHub "Latest" release pointer only moves
when a maintainer explicitly promotes. This gives the team time to validate a
release before it becomes the default for users downloading the latest stable asset.

#### Branch builds: the rolling `main` pre-release

In addition to release tags, every push to `main` triggers the
[publish-main workflow](.github/workflows/publish-main.yml), which builds the
binary and republishes a single rolling `main` pre-release:

- The `main` pre-release always carries the `threat-detect-linux-amd64` asset
  built from the most recent successful build from `main`, versioned
  `main-<shortsha>`.

These are **unverified branch builds**. The `main` pre-release does not
appear in [releases/threat-detection-lifecycle.json](releases/threat-detection-lifecycle.json)
and is not eligible for promotion. The **Latest** stable release pointer is
unaffected by this workflow and continues to track the most recently promoted release.

### Lifecycle Registry

Release lifecycle metadata lives in
[releases/threat-detection-lifecycle.json](releases/threat-detection-lifecycle.json).
Maintainers use one registry for all stable lifecycle states:

- `active` — safe for new and pinned use.
- `deprecated` — still allowed to run, but users should plan an upgrade.
- `obsolete` — unsupported and not suitable for new use.
- `yanked` — unsafe because of a security or correctness issue; stronger than
  `obsolete` and must fail closed.

`gh-aw` must check this registry before downloading or running a selected detector.
If a user explicitly pins a yanked version or yanked asset sha256, `gh-aw` must fail
closed with the yank reason and safe replacement. It must not silently downgrade
or upgrade explicit pins. The **Latest** pointer is floating, so maintainers may move it to a
safe replacement during a yank.

Validate registry edits with:

```bash
make lifecycle-validate
```

Yanked entries must include the version, asset sha256, yank date, severity,
reason, advisory or release URL, and maintainer note. Provide replacement version
and replacement asset sha256 when a safe replacement exists. Use
`no_safe_replacement: true` only when maintainers have confirmed there is no safe
replacement to recommend.

### Emergency Yank Process

Yank only when a released detector is unsafe to run, such as a detector that can
miss high-impact malicious behavior, mishandle secrets, or otherwise produce
unsafe results. A yank requires approval through the `release-yank` environment
by a core maintainer or incident commander.

Before yanking:

1. Identify the bad version and its release-asset sha256.
2. Select the most recent safe stable replacement, or confirm that no safe
   replacement exists yet.
3. Record the severity, user-facing reason, advisory or incident link when
   available, and any maintainer-only note.
4. Prepare user communication that explains the failure mode and replacement.

To yank a release, run **Actions → Yank Release → Run workflow** from the default
branch. The workflow:

1. verifies the yanked release exists and records its asset sha256
2. when a replacement is provided, verifies it exists, records its asset
   sha256, and is not prerelease, yanked, or obsolete
3. verifies required release assets are still downloadable and match their sha256
4. records the yanked status in the lifecycle registry
5. moves the **Latest** pointer to the replacement release when a replacement is provided
6. marks the yanked GitHub release title and notes with a warning
7. removes the yanked release from GitHub's Latest selection and marks the
   replacement as Latest when a replacement is provided

Set `no_safe_replacement: true` and leave `replacement_tag` empty only when no
safe replacement exists. In that case the workflow records
`no_safe_replacement: true`, leaves the **Latest** pointer unmoved, and defers replacement
selection until a safe stable release is available.

Keep yanked artifacts available for audit and forensics unless legal or security
policy requires asset deletion. If branch protection prevents the workflow from
committing the lifecycle registry update directly, create and merge an emergency
PR with the same registry changes before announcing the yank as complete.

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
   version-tagged `threat-detect-linux-amd64` asset.
3. Confirm the lifecycle registry is correct for the release being promoted and
   any versions it replaces; update and validate it with `make lifecycle-validate`
   if statuses changed.
4. When satisfied, go to **Actions → Promote Release**, enter the tag, and run
   the workflow. Approve the `release-promote` environment gate.
5. Confirm the **Latest** release now resolves to the new version.

If a promoted release is later found unsafe, follow the emergency yank process
above instead of deleting tags or relying on release-asset removal as the primary
control.
