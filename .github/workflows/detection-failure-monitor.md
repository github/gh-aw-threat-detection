---
description: Daily scan of github/gh-aw agentic-workflow runs for failing threat-detection jobs; files a basic report issue linking to them for follow-up investigation
on:
  workflow_dispatch:
  schedule: daily
permissions:
  contents: read
  actions: read
  issues: read
  pull-requests: read
name: Detection Failure Monitor
engine: copilot
strict: false
network:
  allowed:
    - defaults
    - github
tools:
  github:
    toolsets: [actions, repos]
safe-outputs:
  allowed-domains: [default-safe-outputs]
  create-issue:
    title-prefix: "[detection-failures] "
    labels: [automation, detection-monitor]
    max: 1
timeout-minutes: 15
---

# Detection Failure Monitor

You monitor the **threat-detection job** of agentic workflows running in the
`github/gh-aw` repository. `github/gh-aw` uses this repository's `threat-detect`
binary, so a failing detection job there is a signal we must triage.

Keep all outputs concise and factual. Do not speculate about root causes — that
is the job of a separate follow-up workflow. Your only job is to **find** failing
detection jobs and **link** to them in a single report issue.

## Definitions

- A **detection job** is a job named exactly `detection` inside a compiled
  agentic workflow run. Ignore every other job.
- A detection job is **failing** when its `conclusion` is any of:
  `failure`, `timed_out`, `cancelled`, or `action_required`. A `success` or
  `skipped` conclusion is NOT a failure.

## Steps

Use the GitHub tools (do not use `gh` — it is not authenticated). All reads
target `owner: github`, `repo: gh-aw`.

1. List recent workflow runs in `github/gh-aw` with `status: failure`, most
   recent first. Only consider runs whose `created_at` (or `updated_at`) is
   within the **last 24 hours**. Bound your work to at most the 50 most recent
   such runs — do not paginate further.
2. For each candidate run, list its jobs and find the job named `detection`.
   - If the run has no job named `detection`, skip the run (it is not an
     agentic-detection workflow, or detection did not run).
   - If a `detection` job exists and its `conclusion` is one of the failing
     values above, record it.
3. For each recorded failing detection job, capture (best effort — never block
   on a single failed read):
   - the workflow display name,
   - the run id and run URL: `https://github.com/github/gh-aw/actions/runs/<run_id>`,
   - the detection job id and job URL: `<run_url>/job/<job_id>`,
   - the job `conclusion`,
   - a one-line `reason`: the name of the first failed step in the detection
     job (for example `Conclude threat detection`). If you cannot determine a
     failed step, use the conclusion value as the reason. Do NOT download job
     logs — step names from the job metadata are sufficient.
4. De-duplicate by run id so each run appears at most once.

## Output

**If you found no failing detection jobs**, do not open an issue — call the
`noop` safe-output tool with a short message such as
`No failing detection jobs in github/gh-aw in the last 24h`.

**If you found one or more failing detection jobs**, create exactly one issue.

- Title: `Detection failures in github/gh-aw - <UTC date, YYYY-MM-DD>`
- Body must contain, in this order:
  1. A one-line summary: the count of failing detection jobs and the scan window.
  2. A `## Failing Detection Jobs` section with one Markdown bullet per failure:
     `- <workflow name> — run <run_url> — job <job_url> — <conclusion> — <reason>`
  3. A machine-readable block so a follow-up workflow can investigate directly.
     Use a fenced ```json block containing an array of objects with exactly these
     keys: `workflow`, `run_id`, `run_url`, `job_id`, `job_url`, `conclusion`,
     `reason`. Use real integers for `run_id` and `job_id`.
  4. A trailing line: `Scanned: <this run's URL>` using
     `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`.

Do not include anything else in the issue body.
