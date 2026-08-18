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
- A detection job **hard-failed** when its `conclusion` is any of:
  `failure`, `timed_out`, or `action_required`. A `success`, `skipped`, or
  `cancelled` job conclusion is NOT a hard failure.
- A detection job **soft-failed** when the job stayed green but detection did
  not actually produce a verdict. This happens because the compiler marks
  detection steps `continue-on-error` in warn mode — since gh-aw v0.86.3
  ([PR #52400](https://github.com/github/gh-aw/pull/52400)) that includes
  `Install threat-detect binary`, so a failed download of this repository's
  released binary leaves the whole job green.
  **Step conclusions cannot be used to find these**: the Actions runner rewrites
  a `continue-on-error` step's result to `success` (it keeps the failure only in
  the workflow-expression `outcome`, which the REST API does not expose), so
  every step of a soft-failed detection job still reports
  `conclusion: "success"`. The evidence lives in the job log instead: the
  conclusion step emits a warning line and a non-`success` reason.
- Both kinds count as **failing** for this report; record which kind applies.

## Steps

Use the GitHub tools (do not use `gh` — it is not authenticated). All reads
target `owner: github`, `repo: gh-aw`.

1. List recent workflow runs in `github/gh-aw` with `status: completed`, most
   recent first, restricted to runs whose `created_at` (or `updated_at`) is
   within the **last 24 hours**. Bound the listing to at most the **80 most
   recent** such runs — do not paginate further. (The MCP `list_workflow_runs`
   tool only accepts lifecycle values — `queued`, `in_progress`, `completed`,
   `requested`, `waiting` — for `status`, so partition on the run's
   `conclusion` yourself: `failure`, `timed_out`, and `action_required` runs
   can hard-fail *or* soft-fail; `success` runs can only soft-fail; skip
   `cancelled` and `skipped` runs and runs still in progress.)
2. For each candidate run, list its jobs and find the job named `detection`.
   - If the run has no job named `detection`, skip the run (it is not an
     agentic-detection workflow, or detection did not run).
   - If the job hard-failed, record it as `failure_kind: job` and do not read
     its log.
   - If the job is `success`, check it for a soft failure as described in step 3.
   - Skip `skipped` and `cancelled` detection jobs.
3. Soft-failure check, applied only to green detection jobs and to **at most 30
   jobs per run of this workflow** (stop checking once you hit that cap and say
   so in the report): fetch only the **last 200 lines** of that job's log and
   look for any of these **tooling-failure** markers, which the conclusion step
   writes only when detection could not run or could not produce a parseable
   verdict (use the job-log tool with the job id and a `tail_lines` of 200 —
   never `failed_only`, which cannot see these):
   - `threat-detect binary not found on PATH` (the binary never installed),
   - `reason=agent_failure` (the agent could not run, or produced no verdict),
   - `reason=parse_error` (the result file was malformed).

   Do NOT match on `reason=threat_detected`, `conclusion=warning`, generic
   `::warning::` lines, or `⚠️` banners: in warn mode `parse_threat_detection_results.cjs`
   emits all four of those for a *legitimate* threat verdict (via
   `setDetectionFailure("threat_detected", ...)` with `mustFail` false), which
   is a working detector doing its job — not something this monitor should
   surface as a detector failure.

   If any tooling-failure marker is present, record the job as
   `failure_kind: step`. Never fetch a full job log, and never fetch logs for
   jobs you already recorded as hard failures.
4. For each recorded failing detection job, capture (best effort — never block
   on a single failed read):
   - the workflow display name,
   - the run id and run URL: `https://github.com/github/gh-aw/actions/runs/<run_id>`,
   - the detection job id and job URL: `<run_url>/job/<job_id>`,
   - the job `conclusion`,
   - the `failure_kind`: `job` for a hard failure, `step` for a soft failure,
   - a one-line `reason`: for a hard failure, the name of the first step whose
     `conclusion` is `failure` or `timed_out` (for example
     `Conclude threat detection`), falling back to the job conclusion; for a
     soft failure, the marker you matched, quoted in at most ~15 words.
5. De-duplicate by run id so each run appears at most once.

## Output

**If you found no failing detection jobs**, do not open an issue — call the
`noop` safe-output tool with a short message such as
`No failing detection jobs in github/gh-aw in the last 24h`.

**If you found one or more failing detection jobs**, create exactly one issue.

- Title: `Detection failures in github/gh-aw - <UTC date, YYYY-MM-DD>`
- Body must contain, in this order:
  1. A one-line summary: the count of failing detection jobs (split into hard and
     soft failures) and the scan window.
  2. A `## Failing Detection Jobs` section with one Markdown bullet per failure:
     `- <workflow name> — run <run_url> — job <job_url> — <conclusion> — <failure_kind> — <reason>`
  3. A machine-readable block so a follow-up workflow can investigate directly.
     Use a fenced ```json block containing an array of objects with exactly these
     keys: `workflow`, `run_id`, `run_url`, `job_id`, `job_url`, `conclusion`,
     `failure_kind`, `reason`. Use real integers for `run_id` and `job_id`.
  4. A trailing line: `Scanned: <this run's URL>` using
     `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`.

Do not include anything else in the issue body.
