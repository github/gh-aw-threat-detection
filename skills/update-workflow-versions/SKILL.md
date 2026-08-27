---
name: update-workflow-versions
description: How to manually regenerate the compiled agentic workflow .lock.yml files when the gh-aw Version Check workflow reports version drift. All workflows track the newest github/gh-aw release or prerelease.
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
whatever compiler produced it, and **every** workflow tracks the same gh-aw
version: the newest `github/gh-aw` release **or prerelease**, whichever was
published most recently. There are no per-workflow categories — a bump
recompiles all the locks together.

**The detector version is baked into the locks.** `gh-aw`'s
`buildInstallThreatDetectStep` unconditionally emits
`constants.DefaultThreatDetectVersion` (a hardcoded tag, e.g. `v0.4.12`) as the
argument to `install_threat_detect_binary.sh`. There is no CLI flag, env var, or
frontmatter field that consults an alternate version at compile time. The
detector pin therefore only moves when either:

1. `github/gh-aw` bumps the constant upstream (typically after a detector
   promotion) and a normal drift-recompile picks up the new tag, or
2. a maintainer does a targeted post-compile edit of the lock (see
   [Testing an unpromoted detector prerelease in the smokes](#testing-an-unpromoted-detector-prerelease-in-the-smokes)
   below).

Promoting a detector release is **not** by itself enough to put it into the
smokes — it takes effect only once the upstream constant is bumped and this
repo's locks are recompiled against that gh-aw tag.

## 1. Determine the target gh-aw version

The drift issue lists it. To confirm or resolve it yourself (any method works —
`gh`, `curl`, or the GitHub Releases UI): newest `github/gh-aw` release **or**
prerelease, i.e. the most recent by publish date whose tag looks like
`v<digit>...`; ignore drafts.

For example, with `gh` available:

```bash
gh api repos/github/gh-aw/releases --paginate \
  --jq '.[] | select(.draft == false) | select(.tag_name | test("^v[0-9]")) | [.published_at, .tag_name] | @tsv' \
  | sort | tail -n1 | cut -f2
```

In the steps below, refer to this as `<TARGET_GH_AW>`.

## 2. Recompile the locks

Recompile every workflow with the same tag. The released `gh aw` extension is
the simplest route:

```bash
gh extension install github/gh-aw --pin <TARGET_GH_AW> --force
gh aw compile --action-mode action --action-tag <TARGET_GH_AW> --no-check-update \
  .github/workflows/*.md
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

There are two sanctioned paths, depending on what you want to exercise.

### Replay path (preferred for most prerelease iteration)

Dispatch `.github/workflows/replay-detection.yml` with
`detector_source=release`, `detector_ref=<prerelease tag>`, and `use_awf=true`.
It downloads that exact release asset and runs it under AWF against a prior
gh-aw run's artifacts. No lock edit needed.

### Smoke path (when you specifically need fresh AWF + fresh artifacts)

The smokes only ever see whatever tag gh-aw's constant currently points at
(promoted, stable). To point them at an unpromoted prerelease, do a targeted
post-compile edit of the smoke locks:

```bash
sed -i 's|install_threat_detect_binary.sh" v0\.[0-9.]*|install_threat_detect_binary.sh" <PRERELEASE_TAG>|' \
  .github/workflows/smoke-copilot-standalone.lock.yml \
  .github/workflows/smoke-claude-standalone.lock.yml \
  .github/workflows/smoke-codex-standalone.lock.yml
```

Commit those three files and open a PR. Do **not** patch
`constants.DefaultThreatDetectVersion` in a `gh-aw` fork to accomplish this:
that route corrupts the compiler-version story (locks would carry a fork tag or
lie about upstream), and it inverts the invariant that the constant tracks the
promoted detector.

Only touch the smoke locks. Leave `detection-stats-daily`,
`detection-failure-monitor`, `gh-aw-issue-digest`, and `gh-aw-parity-monitor` on
the compiler-emitted tag — they are not the test bed for detector prereleases.

The edit is deliberately ephemeral: the next `gh aw compile` run will regenerate
the locks from `constants.DefaultThreatDetectVersion` and revert the pin. That
is intentional — prerelease pins should not survive a routine recompile. Once
the detector is promoted and gh-aw bumps its constant, a normal drift-recompile
picks it up on the standard path.
