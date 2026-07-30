---
name: update-workflow-versions
description: How to manually regenerate the compiled agentic workflow .lock.yml files when the gh-aw Version Check workflow reports version drift (standard, standalone smoke, and standalone latest workflows).
---

# Updating Agentic Workflow Versions

Use this skill when the **gh-aw Version Check** workflow
(`.github/workflows/gh-aw-version-check.yml`) opens a *"Workflow version drift"*
issue, or whenever you need to bump the versions the compiled workflow
`.lock.yml` files are pinned to.

There is no automation for the regeneration itself — it is a deliberate,
human-reviewed step. Pushing changes under `.github/workflows/` requires a token
with the `workflows` permission, which the built-in `GITHUB_TOKEN` lacks, so a
maintainer (or an agent with suitably-permissioned credentials) performs the
recompile locally and opens a PR.

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
patch — for those you must build a patched compiler from source (step 3 below).

## 1. Determine the target versions

The drift issue lists them. To confirm or resolve them yourself (any method
works — `gh`, `curl`, or the GitHub Releases UI). Newest = most recent by publish
date whose tag looks like `v<digit>...`; ignore drafts and rolling refs such as
the detector's `main`:

- **stable gh-aw** — newest **non-prerelease** `github/gh-aw` release.
- **latest gh-aw** — newest `github/gh-aw` release **or** prerelease.
- **latest detector** — newest `github/gh-aw-threat-detection` release **or** prerelease.

For example, with `gh` available:

```bash
# stable gh-aw (newest non-prerelease):
gh api repos/github/gh-aw/releases --paginate \
  --jq '.[] | select(.draft == false and .prerelease == false) | select(.tag_name | test("^v[0-9]")) | [.published_at, .tag_name] | @tsv' \
  | sort | tail -n1 | cut -f2

# latest gh-aw (newest release or prerelease):
gh api repos/github/gh-aw/releases --paginate \
  --jq '.[] | select(.draft == false) | select(.tag_name | test("^v[0-9]")) | [.published_at, .tag_name] | @tsv' \
  | sort | tail -n1 | cut -f2

# latest detector (newest release or prerelease):
gh api repos/github/gh-aw-threat-detection/releases --paginate \
  --jq '.[] | select(.draft == false) | select(.tag_name | test("^v[0-9]")) | [.published_at, .tag_name] | @tsv' \
  | sort | tail -n1 | cut -f2
```

In the steps below, refer to these as `<TARGET_GH_AW_STABLE>`,
`<TARGET_GH_AW_LATEST>`, and `<TARGET_DETECTOR>`.

## 2. Recompile standard and standalone smoke locks

These use the plain `gh aw` compiler pinned to the target gh-aw tag. Use the
**stable** tag for standard workflows and the **latest** tag for `*-standalone.md`
smokes.

```bash
# standard workflows (everything that is not a *-standalone*.md):
gh extension install github/gh-aw --pin <TARGET_GH_AW_STABLE>
gh aw compile --action-mode action --action-tag <TARGET_GH_AW_STABLE> --no-check-update \
  <the affected standard .md files>

# standalone smoke workflows (*-standalone.md, not *-standalone-latest.md):
gh extension install github/gh-aw --pin <TARGET_GH_AW_LATEST> --force
gh aw compile --action-mode action --action-tag <TARGET_GH_AW_LATEST> --no-check-update \
  .github/workflows/*-standalone.md
```

## 3. Recompile the standalone latest locks

The `*-standalone-latest.md` files must be compiled by a gh-aw built from source
at the latest gh-aw tag with the detector constant patched to the target detector
release. A plain `gh aw compile` would revert that patch, so build the compiler
yourself:

```bash
git clone --depth 1 --branch <TARGET_GH_AW_LATEST> https://github.com/github/gh-aw /tmp/gh-aw-src
sed -i -E 's/(DefaultThreatDetectVersion Version = )"[^"]*"/\1"<TARGET_DETECTOR>"/' \
  /tmp/gh-aw-src/pkg/constants/version_constants.go
( cd /tmp/gh-aw-src && go build -o /tmp/gh-aw ./cmd/gh-aw )
/tmp/gh-aw compile --action-mode action --action-tag <TARGET_GH_AW_LATEST> --no-check-update \
  .github/workflows/*-standalone-latest.md
```

## 4. Verify and open a PR

1. Sanity-check that only the intended version bumps changed:
   ```bash
   git status --short -- .github/workflows
   git diff -- .github/workflows
   ```
   Confirm each regenerated lock now carries the target `compiler_version` (and,
   for `*-standalone-latest`, the target `install_threat_detect_binary.sh`
   detector version). Re-running the **gh-aw Version Check** workflow after the PR
   merges should report no drift.
2. Commit only the regenerated `*.lock.yml` files (and any intended `.md`
   changes). Open a PR describing the version bumps.
3. **Pushing workflow-file changes requires a token with the `workflows`
   permission.** The built-in `GITHUB_TOKEN` (github-actions[bot]) is rejected
   for changes under `.github/workflows/`, so this regeneration is done by a
   maintainer / agent whose credentials carry that permission — not by an
   automated push in the version-check workflow.
4. After merging, dispatch the affected smoke workflows (top-level **Smoke**
   workflow) to confirm the new versions run green.
