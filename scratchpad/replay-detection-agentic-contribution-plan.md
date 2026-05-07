# [Plan]: Add replay workflow for gh-aw threat detection runs

## Issue title

[Plan]: Add replay workflow for gh-aw threat detection runs

## Contribution type

Feature request

## What do you want to contribute?

Add a manually dispatched GitHub Actions workflow to this repository that can replay the threat detection phase for any prior GitHub Agentic Workflows (`github/gh-aw`) run.

The workflow should let maintainers provide a source `gh-aw` run ID, download the relevant artifacts, normalize the detection inputs, and rerun this module's detector using either the current repository checkout or a released detector version. It should support command-line-style replay inside Actions, optional AWF wrapping, and overrides such as selecting a different engine/model.

This will make it possible to debug detector behavior, compare detector versions, reproduce historical results, and test new detector changes locally in Actions with maintainer-owned tokens.

## Agent analysis and findings

Research was performed against this repository and the example `github/gh-aw` run:

- Example run: <https://github.com/github/gh-aw/actions/runs/25472644879>
- Example detection job: <https://github.com/github/gh-aw/actions/runs/25472644879/job/74740300338>
- The compiled detection job in `github/gh-aw` downloads the `agent` artifact to `/tmp/gh-aw/`, downloads the experiment artifact, optionally checks out the target repository for patch context, clears MCP config, prepares `/tmp/gh-aw/threat-detection/`, installs Copilot CLI and AWF, runs Copilot through AWF, writes `THREAT_DETECTION_RESULT:{...}` lines to `detection.log`, and uploads a `detection` artifact.
- The example run's artifacts included:
  - `activation`: `aw_info.json`, `aw-prompts/prompt.txt`, `aw-prompts/prompt-template.txt`, and `aw-prompts/prompt-import-tree.json`.
  - `agent`: `agent_output.json`, `aw-prompts/prompt.txt`, `awf-config.json`, logs, optional `comment-memory/`, and possible `aw-*.patch` / `aw-*.bundle` files.
  - `smokecopilot-experiment`: experiment assignments and state.
  - `detection`: original `detection.log`.
- In this repository, `README.md` documents the current artifact contract and CLI flags.
- `cmd/threat-detect/main.go` already supports `--engine`, `--model`, `--prompt-template`, `--output`, and an artifacts directory positional argument.
- `pkg/artifacts/artifacts.go` loads `aw-prompts/prompt.txt`, `aw-prompts/prompt-template.txt`, `aw-prompts/prompt-import-tree.json`, `agent_output.json`, and patch/bundle files.
- `pkg/detector/static.go` can include prompt-template/import-tree analysis when those files exist.
- The current container image only includes the Go detector binary; engine CLIs are not bundled, so the first replay workflow should install required engine CLIs on the runner and run the built/released detector binary directly or under AWF.

## Use case and expected behavior

As a maintainer investigating threat detection behavior, I want to replay detection for an arbitrary historical `gh-aw` run with a chosen detector version and model so that I can compare results, reproduce suspected detector regressions, and safely test improvements before changing `gh-aw` integration.

Expected behavior:

- A maintainer manually dispatches a workflow in this repository with a `gh-aw` run ID.
- The workflow downloads the relevant artifacts from the source run.
- The workflow reconstructs the detector input directory in the format expected by `threat-detect`.
- The workflow runs detection with the requested detector source/version, engine, and model.
- The workflow uploads replay outputs and a sanitized manifest for comparison.
- The workflow fails with clear errors if artifacts are expired, missing, or inaccessible.
- Secrets and tokens are never printed in logs or uploaded artifacts.

## Complete step-by-step agentic plan

1. Read the existing artifact contract and detector behavior:
   - `/home/runner/work/gh-aw-threat-detection/gh-aw-threat-detection/README.md`
   - `/home/runner/work/gh-aw-threat-detection/gh-aw-threat-detection/specs/threat-detection-spec.md`
   - `/home/runner/work/gh-aw-threat-detection/gh-aw-threat-detection/cmd/threat-detect/main.go`
   - `/home/runner/work/gh-aw-threat-detection/gh-aw-threat-detection/pkg/artifacts/artifacts.go`
   - `/home/runner/work/gh-aw-threat-detection/gh-aw-threat-detection/pkg/detector/static.go`
2. Add a new manually dispatched workflow at `/home/runner/work/gh-aw-threat-detection/gh-aw-threat-detection/.github/workflows/replay-detection.yml`.
3. Define workflow inputs for source repository, run ID, run attempt, artifact names, detector source/version, engine, model, AWF usage, custom prompt, workflow metadata overrides, and artifact upload behavior.
4. Use a repository secret such as `GH_AW_REPLAY_TOKEN` for cross-repository artifact downloads; fall back to `github.token` only when the source run is accessible with it.
5. Fetch source run metadata and artifact metadata through the GitHub API or `gh` CLI.
6. Download the selected source artifacts into a temporary workspace.
7. Normalize artifacts into a replay input directory matching the detector contract.
8. Generate a sanitized replay manifest that captures source run metadata, artifact names/digests, original `gh-aw`/AWF/model metadata when known, replay detector source/version, engine/model, and AWF/direct mode.
9. Implement detector selection:
   - `current`: build `threat-detect` from this checkout.
   - `release`: download a release binary for a supplied tag when available.
   - `image`: pull `ghcr.io/github/gh-aw-threat-detection:<tag>` as a follow-up or optional path, noting current image limitations around engine CLIs.
10. Install the selected engine CLI needed for replay.
11. Run direct replay by invoking `threat-detect` against the normalized replay directory with `--engine`, optional `--model`, optional `--prompt-template`, and `--output`.
12. Run AWF replay when requested by installing AWF, preparing a minimal AWF config for the selected engine, mounting the replay directory, and writing outputs to a replay output directory.
13. Parse and summarize replay results in the workflow summary.
14. If the original detection artifact is available, extract the original `THREAT_DETECTION_RESULT` and compare it to the replay output.
15. Upload a `replay-detection` artifact containing the sanitized manifest, file inventory, replay result JSON, replay logs, optional original result summary, and optional AWF log summary.
16. Update documentation in `README.md` or `DEVGUIDE.md` with usage examples for current-version replay, release replay, model override, and AWF/direct modes.
17. Validate workflow YAML syntax and run existing repository checks appropriate to the change.

## Specific implementation details and examples

Suggested workflow path:

- `/home/runner/work/gh-aw-threat-detection/gh-aw-threat-detection/.github/workflows/replay-detection.yml`

Suggested inputs:

- `owner`: source repository owner, default `github`.
- `repo`: source repository name, default `gh-aw`.
- `run_id`: required AW run ID.
- `run_attempt`: optional run attempt.
- `agent_artifact`: default `agent`.
- `activation_artifact`: default `activation`.
- `experiment_artifact`: optional.
- `original_detection_artifact`: optional, default `detection`.
- `detector_source`: `current`, `release`, or `image`.
- `detector_ref`: branch/SHA/tag/release/image tag depending on detector source.
- `engine`: `copilot`, `claude`, or `codex`.
- `model`: optional model override.
- `use_awf`: boolean, default `true`.
- `custom_prompt`: optional additional detection instructions.
- `workflow_name_override`: optional.
- `workflow_description_override`: optional.
- `upload_replay_artifacts`: boolean, default `true`.

Normalized replay directory should include:

```text
<replay-dir>/
├── aw-prompts/
│   ├── prompt.txt
│   ├── prompt-template.txt
│   └── prompt-import-tree.json
├── agent_output.json
├── aw_info.json
├── aw-*.patch
├── aw-*.bundle
├── comment-memory/
└── experiments/
```

Direct replay command shape:

```bash
threat-detect \
  --engine "${ENGINE}" \
  ${MODEL:+--model "${MODEL}"} \
  --output "${RUNNER_TEMP}/replay-output/result.json" \
  "${RUNNER_TEMP}/replay-input"
```

Relevant current code behavior:

- `cmd/threat-detect/main.go` uses exit code `0` for safe, `1` for threat detected, and `2` for infrastructure/configuration errors.
- `pkg/artifacts/artifacts.go` reads workflow metadata from `WORKFLOW_NAME`, `WORKFLOW_DESCRIPTION`, and additional instructions from `CUSTOM_PROMPT`.
- `pkg/artifacts/artifacts.go` already detects `aw-*.patch` and `aw-*.bundle` files at the artifact root.
- `pkg/detector/static.go` includes prompt template/import-tree context when present.

Validation ideas:

- Run `make lint`.
- Run `make test` if Go code or detector behavior changes.
- Validate the workflow YAML with an existing repository-supported tool if available.
- Test the workflow with the example run ID while artifacts are still available.
- Test missing/expired artifact behavior by using an invalid run ID or artifact name.
- Test direct mode with the current checkout.
- Test a model override.
- Test that logs do not include token values or unredacted environment dumps.

## Suggested labels

- enhancement
- agentic-plan
- workflows
- threat-detection

## Contributor checklist

- [x] I read CONTRIBUTING.md and understand that non-core contributors should not open pull requests directly.
- [x] I included a detailed agentic plan for the core team to review and implement.
- [x] I included agent analysis and findings, or explained why they are not applicable.
- [x] I included expected behavior, implementation details, and validation ideas.
