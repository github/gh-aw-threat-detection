---
name: update-workflow-versions
description: How to manually regenerate the compiled agentic workflow .lock.yml files when the gh-aw Version Check workflow reports version drift (standard and standalone smoke workflows).
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
whatever compiler produced it, and the workflows fall into two categories that
track **different** gh-aw versions:

| Category | Lock filename pattern | gh-aw version |
|----------|-----------------------|---------------|
| standard | anything else, e.g. `detection-failure-monitor.lock.yml` | latest **stable** `github/gh-aw` release |
| standalone smoke | `*-standalone.lock.yml` | latest `github/gh-aw` release **or prerelease** |

**Only the gh-aw version needs bumping.** The detector version is *not* pinned in
the locks: gh-aw emits the literal `latest` to
`install_threat_detect_binary.sh`, which resolves it at runtime from
`GET /repos/github/gh-aw-threat-detection/releases/latest` — the newest
**non-prerelease** release. Promoting a detector release is therefore enough to
put it into the smokes; no recompile is required.

## 1. Determine the target gh-aw versions

The drift issue lists them. To confirm or resolve them yourself (any method
works — `gh`, `curl`, or the GitHub Releases UI). Newest = most recent by publish
date whose tag looks like `v<digit>...`; ignore drafts:

- **stable gh-aw** — newest **non-prerelease** `github/gh-aw` release.
- **latest gh-aw** — newest `github/gh-aw` release **or** prerelease.

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
```

In the steps below, refer to these as `<TARGET_GH_AW_STABLE>` and
`<TARGET_GH_AW_LATEST>`.

## 2. Recompile the locks

Use the **stable** tag for standard workflows and the **latest** tag for
`*-standalone.md` smokes. The released `gh aw` extension is the simplest route:

```bash
# standard workflows (everything that is not a *-standalone.md):
gh extension install github/gh-aw --pin <TARGET_GH_AW_STABLE>
gh aw compile --action-mode action --action-tag <TARGET_GH_AW_STABLE> --no-check-update \
  <the affected standard .md files>

# standalone smoke workflows:
gh extension install github/gh-aw --pin <TARGET_GH_AW_LATEST> --force
gh aw compile --action-mode action --action-tag <TARGET_GH_AW_LATEST> --no-check-update \
  .github/workflows/*-standalone.md
```

### Building the compiler from source instead

If `gh extension install` is unavailable (no `gh` auth, offline, etc.), build
gh-aw from source — but you **must** set both version ldflags:

```bash
git clone --depth 1 --branch <TAG> https://github.com/github/gh-aw /tmp/gh-aw-src
( cd /tmp/gh-aw-src && go build -ldflags "-X main.version=<TAG> -X main.isRelease=true" -o /tmp/gh-aw ./cmd/gh-aw )
```

> [!IMPORTANT]
> `-X main.isRelease=true` is not optional. `cmd/gh-aw/main.go` defaults
> `isRelease` to `"false"` and passes it to `workflow.SetIsRelease()`, which
> normalizes the emitted `compiler_version` / `GH_AW_VERSION` to `dev` and skips
> release-only generation. Locks compiled without it look superficially fine but
> carry `dev` at runtime.

Verify before compiling:

```bash
/tmp/gh-aw version   # must print the target tag, not "dev"
```

## 3. Verify and open a PR

1. Sanity-check that only the intended version bumps changed:
   ```bash
   git status --short -- .github/workflows
   git diff -- .github/workflows
   ```
   Confirm each regenerated lock carries the target version in **both** places —
   they must not say `dev`:
   ```bash
   grep -o '"compiler_version":"[^"]*"' .github/workflows/*.lock.yml
   grep -n 'GH_AW_VERSION:' .github/workflows/*.lock.yml
   ```
   Re-running the **gh-aw Version Check** workflow after the PR merges should
   report no drift.
2. Commit only the regenerated `*.lock.yml` files (and any intended `.md`
   changes). The compiler also refreshes `.github/aw/actions-lock.json` and may
   touch `.gitattributes` — that churn is expected. Open a PR describing the
   version bumps.
3. **Pushing workflow-file changes requires a token with the `workflows`
   permission.** The built-in `GITHUB_TOKEN` (github-actions[bot]) is rejected
   for changes under `.github/workflows/`, so this regeneration is done by a
   maintainer / agent whose credentials carry that permission — not by an
   automated push in the version-check workflow.
4. After merging, dispatch the top-level **Smoke** workflow to confirm the new
   versions run green.

## Testing an unpromoted detector prerelease

The smokes only ever see **promoted** detector releases. To exercise a
prerelease under AWF before promoting it, dispatch
`.github/workflows/replay-detection.yml` with `detector_source=release`,
`detector_ref=<prerelease tag>`, and `use_awf=true`. It downloads that exact
release asset and runs it under AWF against a prior gh-aw run's artifacts.
