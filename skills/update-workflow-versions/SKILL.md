---
name: update-workflow-versions
description: How to regenerate the compiled agentic workflow .lock.yml files when the gh-aw Version Check workflow reports version drift (standard, standalone smoke, and standalone latest workflows).
---

# Updating Agentic Workflow Versions

Use this skill when the **gh-aw Version Check** workflow
(`.github/workflows/gh-aw-version-check.yml`) opens a *"Workflow version drift"*
issue, or whenever you need to bump the versions the compiled workflow
`.lock.yml` files are pinned to.

## Background

Each agentic workflow source (`.github/workflows/*.md`) is compiled by the
`gh-aw` compiler into a committed `*.lock.yml`. The version baked into a lock is
whatever compiler produced it, and the workflows fall into three categories that
track **different** target versions:

| Category | Lock filename pattern | gh-aw version | detector version |
|----------|-----------------------|---------------|------------------|
| standard | anything else, e.g. `detection-failure-monitor.lock.yml` | latest **stable** `github/gh-aw` release | n/a (gh-aw's built-in default) |
| standalone smoke | `*-standalone.lock.yml` | latest `github/gh-aw` release **or prerelease** | n/a (gh-aw's built-in default) |
| standalone latest | `*-standalone-latest.lock.yml` | latest `github/gh-aw` (pre)release | latest `github/gh-aw-threat-detection` (pre)release |

The **standalone latest** locks are special: their detector version is *not* the
gh-aw built-in constant. They are compiled by a gh-aw whose
`constants.DefaultThreatDetectVersion` has been patched to the newest detector
release, so they exercise the newest detector through the real gh-aw + AWF path.
Running a plain `gh aw compile` over a `*-standalone-latest.md` would revert that
patch — always use the recompile script (or patch the constant) for those.

## Fastest path: use the helper script

`scripts/recompile-workflows.sh` builds the gh-aw compiler from source (patching
the detector constant for the latest workflows) and regenerates every lock.

```bash
# Regenerate everything (resolves target versions via gh):
scripts/recompile-workflows.sh

# Or only one category:
scripts/recompile-workflows.sh --category standard
scripts/recompile-workflows.sh --category smoke
scripts/recompile-workflows.sh --category latest

# Pin exact versions instead of resolving the newest:
scripts/recompile-workflows.sh \
  --gh-aw-stable v0.83.4 \
  --gh-aw-latest v0.84.0-rc1 \
  --detector     v0.3.2
```

Requirements: `git`, `go`, and `gh` (only for resolving the newest tags). Run it
from the repo root.

Then review and commit:

```bash
git status --short -- .github/workflows
git diff -- .github/workflows          # sanity-check the version bumps only
```

## Manual path (if you can't run the script)

1. Confirm the target versions the drift issue lists, or resolve them:
   - stable gh-aw: newest non-prerelease `github/gh-aw` release.
   - latest gh-aw: newest `github/gh-aw` release **or** prerelease.
   - latest detector: newest `github/gh-aw-threat-detection` release **or** prerelease.
2. **standard** and **standalone smoke** — compile with the plain compiler pinned
   to the target gh-aw tag:
   ```bash
   gh extension install github/gh-aw --pin <TARGET_GH_AW>
   gh aw compile --action-mode action --action-tag <TARGET_GH_AW> --no-check-update \
     <the affected .md files>
   ```
   Use the **stable** tag for standard workflows and the **latest** tag for
   `*-standalone.md` smokes.
3. **standalone latest** — build gh-aw from source at the latest gh-aw tag with
   the detector constant patched, then compile only the `*-standalone-latest.md`
   files with it (this is exactly what `scripts/recompile-workflows.sh --category
   latest` automates):
   ```bash
   git clone --depth 1 --branch <TARGET_GH_AW> https://github.com/github/gh-aw /tmp/gh-aw-src
   sed -i -E 's/(DefaultThreatDetectVersion Version = )"[^"]*"/\1"<TARGET_DETECTOR>"/' \
     /tmp/gh-aw-src/pkg/constants/version_constants.go
   ( cd /tmp/gh-aw-src && go build -o /tmp/gh-aw ./cmd/gh-aw )
   /tmp/gh-aw compile --action-mode action --action-tag <TARGET_GH_AW> --no-check-update \
     .github/workflows/*-standalone-latest.md
   ```

## Verify and open a PR

1. Re-run the read-only check to confirm no drift remains:
   ```bash
   scripts/check-workflow-versions.sh
   ```
2. Commit only the regenerated `*.lock.yml` files (and any intended `.md`
   changes). Open a PR describing the version bumps.
3. **Pushing workflow-file changes requires a token with the `workflows`
   permission.** The built-in `GITHUB_TOKEN` (github-actions[bot]) is rejected
   for changes under `.github/workflows/`, so this regeneration is done by a
   maintainer / agent whose credentials carry that permission — not by an
   automated push in the version-check workflow.
4. After merging, dispatch the affected smoke workflows (top-level **Smoke**
   workflow) to confirm the new versions run green.
