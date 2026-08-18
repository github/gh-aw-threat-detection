---
description: Daily scan of github/gh-aw releases and prereleases published since the last run; opens an issue summarizing every threat-detection-related change (with PR links) so this repository stays in parity with the main gh-aw workflow
on:
  workflow_dispatch:
  schedule: daily
permissions:
  contents: read
  issues: read
  pull-requests: read
name: gh-aw Parity Monitor
engine: copilot
strict: false
features:
  gh-aw-detection: true
network:
  allowed:
    - defaults
    - github
tools:
  github:
    toolsets: [repos, pull_requests]
  cache-memory:
    key: gh-aw-parity-monitor-${{ github.repository }}
    allowed-extensions: [".json"]
safe-outputs:
  allowed-domains: [default-safe-outputs]
  create-issue:
    title-prefix: "[gh-aw-parity] "
    labels: [automation, gh-aw-parity]
    max: 1
timeout-minutes: 15
---

# gh-aw Parity Monitor

You watch the upstream **`github/gh-aw`** repository for new releases and
prereleases and surface every change that touches **threat detection**, so the
maintainers of **this** repository (`github/gh-aw-threat-detection`, which ships
the `threat-detect` binary consumed by `gh-aw`) can stay in parity with the main
`gh-aw` workflow.

Keep every output concise and factual. Your only job is to **find** the new
(pre)releases since your last run, **extract** the threat-detection-related
changes from them, and **report** them in a single issue with links.

## State: what "since the last time it ran" means

You have a persistent cache-memory directory at `/tmp/gh-aw/cache-memory/`.
State is kept in a single JSON file:

```
/tmp/gh-aw/cache-memory/last-seen.json
```

with this shape:

```json
{ "last_published_at": "2026-01-01T00:00:00Z", "last_tag": "v1.2.3" }
```

- `last_published_at` — ISO-8601 UTC `published_at` of the newest gh-aw
  (pre)release you have already processed.
- `last_tag` — the tag name of that release (for humans / debugging).

Read this file at the start of the run:

- **If the file does not exist or cannot be parsed (first run / cold cache):**
  do **not** open an issue. Treat this run as a baseline. Find the single newest
  `github/gh-aw` release or prerelease, write its `published_at` and `tag_name`
  into `last-seen.json`, and finish by calling the `noop` safe-output tool with a
  short message such as `Baseline established at <tag>; no issue on first run`.
- **If the file exists:** use `last_published_at` as the low-water mark for
  "new" releases below.

Always overwrite `last-seen.json` at the end of a successful run with the newest
processed release (see Steps step 6), even when no threat-detection changes were
found, so you never re-process the same release.

## Steps

Use the GitHub tools (do not use `gh` — it is not authenticated). All reads
target `owner: github`, `repo: gh-aw`.

1. Read `/tmp/gh-aw/cache-memory/last-seen.json`. Apply the baseline rule above
   if it is missing/unparseable.
2. List releases in `github/gh-aw`, newest first. Include **both** full releases
   and prereleases; **exclude drafts**. Consider a release **new** when its
   `published_at` is strictly greater than `last_published_at` from state. Bound
   your work to at most the 30 most recent releases — do not paginate further
   back than that. If none are new, skip to step 6 (no issue).
3. For each new (pre)release, gather:
   - `tag_name`, whether it is a `prerelease`, its `published_at`, and its
     `html_url`.
   - The release **body/notes**. `gh-aw` release notes contain an auto-generated
     changelog listing merged PRs with their links.
4. From each new release, extract the **threat-detection-related** changes.
   Treat an entry as related if its PR title, release-note line, or referenced
   commit message mentions any of (case-insensitive):
   - `threat detection`, `threat-detection`, `threat detect`, `threat-detect`
   - `detection job`, `detection result`, `detection_result`
   - `prompt injection`, `secret leak`, `malicious patch`
   - `safe-outputs` threat gating, or the `gh-aw-detection` feature
   For each matching entry capture: the PR number and PR URL
   (`https://github.com/github/gh-aw/pull/<n>`), a one-line description (the PR
   title or note text), and the release tag it shipped in. De-duplicate by PR
   number across releases (a PR appears once, attributed to the earliest release
   that contains it).
5. Decide the output:
   - **If one or more threat-detection-related changes were found**, create
     exactly one issue (see Output).
   - **If new releases exist but none contained threat-detection changes**, do
     not open an issue — call the `noop` safe-output tool with a short message
     such as `<N> new gh-aw (pre)releases, no threat-detection changes`.
6. Update state: write `/tmp/gh-aw/cache-memory/last-seen.json` with the
   `published_at` and `tag_name` of the **newest** release you saw this run
   (the first item from step 2's newest-first list), regardless of whether you
   opened an issue. This advances the low-water mark so the next run starts from
   here.

## Output

When you found one or more threat-detection-related changes, create exactly one
issue.

- Title: `gh-aw threat-detection changes to review - <UTC date, YYYY-MM-DD>`
- Body must contain, in this order:
  1. A one-line summary: the count of new (pre)releases scanned, their tag range,
     and the count of threat-detection-related changes found.
  2. A `## Releases` section: one bullet per new (pre)release that contained a
     threat-detection change, formatted
     `- <tag> (<release|prerelease>, <published_at date>) — <release html_url>`.
  3. A `## Threat-detection changes` section: one Markdown bullet per
     de-duplicated change, formatted
     `- [#<pr_number>](<pr_url>) — <one-line description> — shipped in <tag>`.
  4. A short `## Why this matters` line reminding the reader that this repository
     ships the `threat-detect` binary consumed by `gh-aw` and these changes may
     require matching updates here to stay in parity.
  5. A trailing line: `Scanned: <this run's URL>` using
     `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`.

Do not include anything else in the issue body.
