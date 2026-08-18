---
description: Daily statistics on error rates and detection results for the threat-detection jobs of github/gh-aw runs that use this repository's external threat-detect binary; files one report issue per day and can be re-run for any prior UTC date
on:
  workflow_dispatch:
    inputs:
      date:
        description: "UTC day to analyse (YYYY-MM-DD). Defaults to yesterday."
        required: false
        type: string
      target_repo:
        description: "Repository to analyse, in owner/repo form."
        required: false
        type: string
        default: github/gh-aw
      fetch_results:
        description: "Download detection artifacts to classify the verdicts. Set to false for a cheap outcome-only scan."
        required: false
        type: choice
        default: "true"
        options: ["true", "false"]
      max_requests:
        description: "API request budget for the collector. Empty uses the script default (3000)."
        required: false
        type: string
  schedule: daily
permissions:
  contents: read
  actions: read
  issues: read
name: Detection Stats Daily
engine: copilot
strict: false
features:
  gh-aw-detection: true
network:
  allowed:
    - defaults
    - github
tools:
  cache-memory:
    key: detection-stats-daily-${{ github.repository }}
    allowed-extensions: [".json"]
safe-outputs:
  allowed-domains: [default-safe-outputs]
  create-issue:
    title-prefix: "[detection-stats] "
    labels: [automation, detection-stats]
    max: 1
timeout-minutes: 30
jobs:
  # The collector runs in its own job so the token that reads the target
  # repository never enters the agent job's environment.
  collect_detection_stats:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    permissions:
      contents: read
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Collect detection statistics
        id: collect
        env:
          GH_TOKEN: ${{ secrets.GH_AW_GITHUB_MCP_SERVER_TOKEN || secrets.GH_AW_GITHUB_TOKEN || secrets.GITHUB_TOKEN }}
          TARGET_REPO: ${{ inputs.target_repo || 'github/gh-aw' }}
          TARGET_DATE: ${{ inputs.date }}
          FETCH_RESULTS: ${{ inputs.fetch_results || 'true' }}
          MAX_REQUESTS: ${{ inputs.max_requests || '3000' }}
          OUTPUT_DIR: /tmp/gh-aw/detection-stats
          DEADLINE_MINUTES: "18"
        run: bash scripts/collect-detection-stats.sh
      - name: Upload detection statistics
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: detection-stats-${{ github.run_id }}
          path: /tmp/gh-aw/detection-stats/
          if-no-files-found: warn
          retention-days: 30
steps:
  - name: Download detection statistics
    # Tolerated: if the collector produced nothing the agent takes its documented
    # "no summary" path and reports a noop instead of failing the run.
    continue-on-error: true
    uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
    with:
      name: detection-stats-${{ github.run_id }}
      path: /tmp/gh-aw/detection-stats
---

# Detection Stats Daily

You report **daily statistics** on the `detection` job of agentic workflow runs
in a target repository (by default `github/gh-aw`), restricted to the runs that
use the **external detector** — the `threat-detect` binary released by *this*
repository (`github/gh-aw-threat-detection`).

All of the data collection has **already been done for you** by a deterministic
step that ran before you started. **Do not call any GitHub API or `gh` command
to re-gather it** — pagination, time-window bisection and rate-limit backoff are
handled there, and re-doing that work by hand would be slow, incomplete, and
would burn the API budget.

Your job is to **read** the collected numbers, **compare** them with previous
days, and **file one report issue**.

## Inputs on disk

- `/tmp/gh-aw/detection-stats/summary.md` — a pre-rendered, bounded Markdown
  digest. **This is your primary input; read it first.**
- `/tmp/gh-aw/detection-stats/stats.json` — the full machine-readable record
  set. Read it only if you need a specific number that the summary omits (for
  example a workflow beyond the top 25, or a run beyond the notable-runs cap).
  It can be large; never paste it wholesale into the issue.

If `summary.md` does not exist, the collector failed. In that case do not open an
issue: call the `noop` safe-output tool with a short message such as
`detection stats collection produced no summary`.

## What the numbers mean

- **External detector runs** — runs whose `detection` job used the `threat-detect`
  binary. This is decided per **workflow**, not per run: a job that was skipped,
  cancelled, or died during setup reports few or no steps, so the
  `Install threat-detect binary` marker is invisible on exactly the runs that
  matter most. If any run of a workflow showed the marker that day, all of that
  workflow's detection jobs count as external. Everything under "rates" is
  measured over this population. Runs using gh-aw's built-in detection are
  counted separately, and runs the evidence cannot settle are reported as
  **detector could not be determined** — never folded into either bucket.
- **Job outcomes** — the `detection` job's `conclusion` (`success`, `failure`,
  `cancelled`, `skipped`, `timed_out`, `action_required`) or `in_progress` when
  the job had not finished at scan time. The **error rate** counts only
  `failure`, `timed_out` and `action_required`.
- **Verdict availability** — whether the job published a `detection_result.json`
  artifact: `present`, `absent`, `expired` (artifact retention lapsed),
  `malformed`, `unreadable`, `download_failed`, `lookup_failed`, or
  `not_fetched` (the job was `skipped` or still running, so no verdict was ever
  expected).
- **Soft failures** — a **green** `detection` job that published **no** verdict.
  Detection steps are `continue-on-error`, so the Actions runner rewrites their
  `conclusion` to `success`; a missing verdict artifact is therefore the only
  reliable signal that detection did not actually produce a result. Treat this
  as a **detector reliability problem**, not a security finding.
- **Detection results** — the published verdict booleans `prompt_injection`,
  `secret_leak`, `malicious_patch`. A run can carry more than one. The published
  result deliberately carries `reasons: []`, so no explanations are available
  here; point readers at the `replay-detection` workflow when they want reasons.
- **Reasons reported by gh-aw** — harvested from the `[aw] Detection Runs`
  tracking issue, which gh-aw comments on only for `warning`/`failure`
  conclusions. `threat_detected` is a **working** detector reporting a finding;
  `agent_failure` and `parse_error` are **tooling failures**.
- **Truncations** — the collector hit a budget or API limit. When present, say so
  prominently. Counts are lower bounds, and because the collector works forward
  through the day, the **rates describe only the earlier part of the day** — a
  partial-day sample, not a bound. `collection.rates_cover_partial_day` flags
  this; when it is true, do not compare today's rates against history as if they
  were like-for-like.

## State: day-over-day comparison

You have a persistent cache-memory directory at `/tmp/gh-aw/cache-memory/`.
History lives in a single JSON file:

```
/tmp/gh-aw/cache-memory/history.json
```

with this shape (newest last, at most **30** entries):

```json
[
  {
    "date": "2026-08-16",
    "external_detector_runs": 812,
    "error_rate_pct": 1.11,
    "soft_failures": 3,
    "with_verdict": 780,
    "any_threat": 4,
    "threat_rate_pct": 0.51,
    "partial": false
  }
]
```

1. Read `history.json` at the start. If it is missing or unparseable, treat this
   run as the first one: report today's numbers with no comparison and say the
   baseline is being established.
2. Compare today's headline numbers against the **most recent previous entry**
   whose `date` is not today's, and — when at least 7 entries exist — against the
   mean of the previous 7. Skip entries whose `partial` is `true`, and if
   **today** is partial (`collection.rates_cover_partial_day` is true), report
   the numbers without a rate comparison and say why.
3. At the end of the run, append today's entry (setting `partial` from
   `collection.rates_cover_partial_day`, and replacing any existing entry
   with the same `date`, so a re-run for a prior date corrects rather than
   duplicates), keep the array sorted by `date`, trim it to the newest 30
   entries, and write it back. Do this **even if** you open no issue.

## Steps

1. Read `/tmp/gh-aw/detection-stats/summary.md`.
2. Read `/tmp/gh-aw/cache-memory/history.json` (apply the baseline rule above).
3. Consult `stats.json` only for details the summary truncated and that you
   actually need to justify a finding.
4. Decide the report (see Output), then update `history.json`.

Do not speculate about root causes and do not attempt to fix anything. Stay
factual: this workflow reports rates, not diagnoses.

## Output

Always create exactly **one** issue, even on a quiet day — this is a daily
statistics report and the time series matters. The only exception is a failed
collection (no `summary.md`), which uses `noop` as described above.

- Title: `Detection stats for <target repo> - <UTC date, YYYY-MM-DD>`
- Body, in this order:
  1. A one-line headline: the number of external-detector runs analysed, the
     detection-job error rate, the soft-failure count, and the threat rate.
  2. If the collection was truncated, a bolded warning line saying the figures
     are a lower bound, quoting each truncation note.
  3. `## Summary` — the contents of `summary.md`, reproduced faithfully. Do not
     recompute any number; copy them.
  4. `## Change since <previous date>` — a small table with one row per headline
     metric: the previous value, today's value, and the delta. Add the 7-day
     mean column when you have at least 7 history entries. If there is no
     history, say `No history yet; establishing the baseline.` instead.
  5. `## Watch list` — at most 5 bullets naming the workflows with the highest
     count of failed or verdict-less detection jobs, formatted
     `- <workflow> — <n> failed, <m> without a verdict, out of <runs> runs`.
     Write `None` when every workflow was clean.
  6. A trailing line: `Collected by: <this run's URL>` using
     `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`,
     followed by `Full data: the detection-stats-<run id> artifact on that run.`

Do not include anything else in the issue body. Never paste raw `stats.json`.
