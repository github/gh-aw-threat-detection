#!/usr/bin/env bash
#
# Collect daily statistics about the `detection` jobs of agentic workflow runs
# in a target repository (by default github/gh-aw), restricted to the runs that
# use the external detector shipped by this repository.
#
# The script is deliberately deterministic: it does all of the paginated,
# rate-limited data collection so that an agentic workflow only has to read a
# small, pre-aggregated summary.
#
# Outputs (in $OUTPUT_DIR, default /tmp/gh-aw/detection-stats):
#   stats.json  -- full machine-readable record set + aggregates
#   summary.md  -- bounded human/agent-readable digest
#
# Configuration (all via environment):
#   GH_TOKEN              required; token with read access to TARGET_REPO
#   TARGET_REPO           default "github/gh-aw"
#   TARGET_DATE           UTC day "YYYY-MM-DD"; default: yesterday
#   OUTPUT_DIR            default "/tmp/gh-aw/detection-stats"
#   FETCH_RESULTS         "true"/"false"; download detection_result.json artifacts
#   FETCH_REASONS         "true"/"false"; read the "[aw] Detection Runs" issue
#   MAX_REQUESTS          hard API request budget (default 3000)
#   DEADLINE_MINUTES      wall-clock budget (default 25)
#   MAX_RESULT_FETCHES    cap on artifact downloads (default 2000; MAX_REQUESTS normally binds first)
#   RATE_LIMIT_FLOOR      pause when remaining quota drops below this (default 60)
#   REQUEST_PAUSE_SECONDS delay between requests (default 0.1)
#   GITHUB_API_URL        default "https://api.github.com" (also honoured by Actions)
#
# Exit codes: 0 success (possibly truncated), 2 configuration/infrastructure error.

set -euo pipefail

TARGET_REPO="${TARGET_REPO:-github/gh-aw}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/gh-aw/detection-stats}"
API_URL="${GITHUB_API_URL:-https://api.github.com}"
FETCH_RESULTS="${FETCH_RESULTS:-true}"
FETCH_REASONS="${FETCH_REASONS:-true}"
MAX_REQUESTS="${MAX_REQUESTS:-3000}"
DEADLINE_MINUTES="${DEADLINE_MINUTES:-25}"
MAX_RESULT_FETCHES="${MAX_RESULT_FETCHES:-2000}"
RATE_LIMIT_FLOOR="${RATE_LIMIT_FLOOR:-60}"
REQUEST_PAUSE_SECONDS="${REQUEST_PAUSE_SECONDS:-0.1}"

# The Actions "list workflow runs" API refuses to page past 1000 results, so a
# window holding more than this must be bisected.
readonly WINDOW_RESULT_CAP=1000
readonly PER_PAGE=100
# A job step with this name is emitted only when gh-aw installs the external
# `threat-detect` binary released by this repository. Since gh-aw PR #54111
# the `gh-aw-detection` feature defaults to enabled, so the marker is present
# on every compiled workflow that does not explicitly opt out with
# `features: gh-aw-detection: false` in frontmatter.
readonly EXTERNAL_DETECTOR_STEP="Install threat-detect binary"
readonly DETECTION_JOB_NAME="detection"
readonly DETECTION_ARTIFACT_NAME="detection"
readonly DETECTION_RUNS_ISSUE_TITLE="[aw] Detection Runs"

log() { printf '%s\n' "$*" >&2; }

# header_value <header-file> <lowercase-header-name>
#
# Prints the first value for the named header. Matching is explicitly
# case-insensitive: `IGNORECASE` is a gawk extension and the default awk on
# Ubuntu runners is mawk, where it silently does nothing.
header_value() {
  awk -v want="$2" '
    { line = tolower($0); sub(/\r$/, "", line) }
    index(line, want ":") == 1 {
      value = substr($0, length(want) + 2)
      gsub(/\r/, "", value)
      gsub(/^[ \t]+|[ \t]+$/, "", value)
      print value
      exit
    }
  ' "$1" 2>/dev/null || true
}

is_uint() {
  case "${1:-}" in
    "" | *[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

die() {
  printf 'ERR_CONFIG: %s\n' "$*" >&2
  exit 2
}

for tool in curl jq python3 unzip; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found on PATH: $tool"
done

[ -n "${GH_TOKEN:-}" ] || die "GH_TOKEN must be set (needs read access to ${TARGET_REPO})"

case "$TARGET_REPO" in
  */*) : ;;
  *) die "TARGET_REPO must be in owner/repo form, got: ${TARGET_REPO}" ;;
esac

if [ -z "${TARGET_DATE:-}" ]; then
  TARGET_DATE="$(date -u -d 'yesterday' +%Y-%m-%d)"
fi
case "$TARGET_DATE" in
  [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) : ;;
  *) die "TARGET_DATE must be a UTC date in YYYY-MM-DD form, got: ${TARGET_DATE}" ;;
esac
[ "$(date -u -d "${TARGET_DATE}" +%Y-%m-%d 2>/dev/null || true)" = "$TARGET_DATE" ] ||
  die "TARGET_DATE is not a real calendar date: ${TARGET_DATE}"

WINDOW_FROM="${TARGET_DATE}T00:00:00Z"
WINDOW_TO="${TARGET_DATE}T23:59:59Z"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$OUTPUT_DIR"

DEADLINE_EPOCH=$(( $(date -u +%s) + DEADLINE_MINUTES * 60 ))
REQUEST_COUNT=0
RATE_LIMIT_SLEEPS=0
declare -a TRUNCATION_NOTES=()

note_truncation() {
  TRUNCATION_NOTES+=("$1")
  log "TRUNCATED: $1"
}

budget_exhausted() {
  if [ "$REQUEST_COUNT" -ge "$MAX_REQUESTS" ]; then
    return 0
  fi
  if [ "$(date -u +%s)" -ge "$DEADLINE_EPOCH" ]; then
    return 0
  fi
  return 1
}

sleep_until_reset() {
  # $1 = header file. Sleeps until the rate-limit reset instant, bounded so a
  # bogus header can never park the job for the whole timeout.
  local header_file="$1" reset now wait retry_after
  retry_after="$(header_value "$header_file" retry-after)"
  reset="$(header_value "$header_file" x-ratelimit-reset)"
  now="$(date -u +%s)"
  if is_uint "$retry_after"; then
    wait="$retry_after"
  elif is_uint "$reset"; then
    wait=$(( reset - now + 2 ))
  else
    wait=60
  fi
  [ "$wait" -lt 1 ] && wait=1
  [ "$wait" -gt 900 ] && wait=900
  # Never sleep past the deadline; the caller degrades gracefully instead.
  local remaining=$(( DEADLINE_EPOCH - now ))
  if [ "$remaining" -le 0 ]; then
    return 1
  fi
  [ "$wait" -gt "$remaining" ] && wait="$remaining"
  RATE_LIMIT_SLEEPS=$(( RATE_LIMIT_SLEEPS + 1 ))
  log "rate limited; sleeping ${wait}s"
  sleep "$wait"
}

throttle_if_low() {
  # Proactively pause when the primary quota is nearly spent, so the expensive
  # phases later on are not starved by a burst here.
  local header_file="$1" remaining
  remaining="$(header_value "$header_file" x-ratelimit-remaining)"
  if is_uint "$remaining" && [ "$remaining" -lt "$RATE_LIMIT_FLOOR" ]; then
    sleep_until_reset "$header_file" || return 1
  fi
  return 0
}

# api_request <url> <body-output-path>
#
# Performs one GET against the GitHub API with retry, primary/secondary
# rate-limit backoff and budget accounting. Returns 0 on 2xx, 1 otherwise (the
# caller decides whether a miss is fatal). Never aborts the run on a single
# failed read.
api_request() {
  local url="$1" out="$2"
  local header_file="${WORK_DIR}/headers.$$"
  local attempt=0 max_attempts=5 status backoff

  while [ "$attempt" -lt "$max_attempts" ]; do
    if budget_exhausted; then
      return 1
    fi
    attempt=$(( attempt + 1 ))
    REQUEST_COUNT=$(( REQUEST_COUNT + 1 ))

    local -a curl_args=(
      --silent --show-error --location
      --max-time 120 --connect-timeout 20
      --dump-header "$header_file"
      --output "$out"
      --write-out '%{http_code}'
      --header "Authorization: Bearer ${GH_TOKEN}"
      --header "X-GitHub-Api-Version: 2022-11-28"
      --header "User-Agent: gh-aw-threat-detection-stats"
    )
    # Artifact downloads answer with a 302 to a signed blob URL on a different
    # host; --location follows it and curl strips the Authorization header on
    # the cross-host hop, which is exactly what the blob URL needs (it carries
    # its own signature). Do NOT add --no-location-trusted here: despite the
    # name, that flag also disables --location itself, so every artifact fetch
    # would stop at the 302 and be recorded as download_failed.
    curl_args+=(--header "Accept: application/vnd.github+json")

    status="$(curl "${curl_args[@]}" "$url" 2>/dev/null || echo 000)"
    sleep "$REQUEST_PAUSE_SECONDS"

    case "$status" in
      2*)
        throttle_if_low "$header_file" || true
        return 0
        ;;
      403|429)
        # Distinguish "out of quota" / secondary limit from a genuine denial.
        local remaining
        remaining="$(header_value "$header_file" x-ratelimit-remaining)"
        if [ "$status" = "429" ] || [ "${remaining:-1}" = "0" ] ||
          grep -qi 'secondary rate limit\|rate limit' "$out" 2>/dev/null; then
          sleep_until_reset "$header_file" || return 1
          continue
        fi
        log "HTTP ${status} (not rate limited) for ${url}"
        return 1
        ;;
      404|410)
        return 1
        ;;
      5*|000)
        backoff=$(( attempt * attempt * 2 ))
        log "HTTP ${status} for ${url}; retrying in ${backoff}s (attempt ${attempt}/${max_attempts})"
        sleep "$backoff"
        continue
        ;;
      *)
        log "HTTP ${status} for ${url}"
        return 1
        ;;
    esac
  done
  return 1
}

##############################################################################
# Phase 1: enumerate workflow runs created within the target UTC day.
##############################################################################

RUNS_FILE="${WORK_DIR}/runs.jsonl"
: >"$RUNS_FILE"

# collect_window <from-iso> <to-iso> <depth>
#
# The Actions run list is capped at 1000 results per query regardless of
# pagination, so an over-full window is bisected on time until each slice fits.
collect_window() {
  local from="$1" to="$2" depth="$3"
  local page=1 total_count url body

  if budget_exhausted; then
    note_truncation "run listing stopped at ${from}..${to} (request/time budget exhausted)"
    return 0
  fi

  body="${WORK_DIR}/runs-page.json"
  url="${API_URL}/repos/${TARGET_REPO}/actions/runs?per_page=${PER_PAGE}&page=1&exclude_pull_requests=true&created=$(printf '%s' "${from}..${to}" | jq -sRr @uri)"
  if ! api_request "$url" "$body"; then
    note_truncation "failed to list runs for window ${from}..${to}"
    return 0
  fi
  total_count="$(jq -r '.total_count // 0' "$body")"

  if [ "$total_count" -gt "$WINDOW_RESULT_CAP" ]; then
    local from_epoch to_epoch mid
    from_epoch="$(date -u -d "$from" +%s)"
    to_epoch="$(date -u -d "$to" +%s)"
    if [ "$depth" -ge 12 ] || [ $(( to_epoch - from_epoch )) -lt 2 ]; then
      note_truncation "window ${from}..${to} holds ${total_count} runs but cannot be split further; only the first ${WINDOW_RESULT_CAP} are counted"
    else
      mid=$(( from_epoch + (to_epoch - from_epoch) / 2 ))
      log "window ${from}..${to} has ${total_count} runs; bisecting"
      collect_window "$from" "$(date -u -d "@${mid}" +%Y-%m-%dT%H:%M:%SZ)" $(( depth + 1 ))
      collect_window "$(date -u -d "@$(( mid + 1 ))" +%Y-%m-%dT%H:%M:%SZ)" "$to" $(( depth + 1 ))
      return 0
    fi
  fi

  while :; do
    jq -c '.workflow_runs[] | {id, name, path, event, status, conclusion, created_at, updated_at, html_url, run_attempt, head_branch}' "$body" >>"$RUNS_FILE"
    local fetched
    fetched="$(jq -r '.workflow_runs | length' "$body")"
    [ "$fetched" -lt "$PER_PAGE" ] && break
    page=$(( page + 1 ))
    if [ $(( page * PER_PAGE )) -gt "$WINDOW_RESULT_CAP" ]; then
      break
    fi
    if budget_exhausted; then
      note_truncation "run listing for ${from}..${to} stopped at page ${page} (budget exhausted)"
      break
    fi
    url="${API_URL}/repos/${TARGET_REPO}/actions/runs?per_page=${PER_PAGE}&page=${page}&exclude_pull_requests=true&created=$(printf '%s' "${from}..${to}" | jq -sRr @uri)"
    if ! api_request "$url" "$body"; then
      note_truncation "failed to read page ${page} of runs for ${from}..${to}"
      break
    fi
  done
}

log "Collecting ${TARGET_REPO} runs for ${TARGET_DATE} (${WINDOW_FROM}..${WINDOW_TO})"
collect_window "$WINDOW_FROM" "$WINDOW_TO" 0

# Runs can appear in more than one window slice; dedupe on id.
sort -u "$RUNS_FILE" | jq -s 'unique_by(.id)' >"${WORK_DIR}/runs.json"
TOTAL_RUNS="$(jq 'length' "${WORK_DIR}/runs.json")"

# Only compiled agentic workflows (*.lock.yml) can have a detection job. This
# filter is free: `path` is already present in the run listing.
jq -c '[.[] | select(.path | test("\\.lock\\.ya?ml$"))]' "${WORK_DIR}/runs.json" >"${WORK_DIR}/agentic-runs.json"
AGENTIC_RUNS="$(jq 'length' "${WORK_DIR}/agentic-runs.json")"
log "Runs on ${TARGET_DATE}: ${TOTAL_RUNS} total, ${AGENTIC_RUNS} agentic"

##############################################################################
# Phase 2: per agentic run, inspect the `detection` job.
##############################################################################

RECORDS_FILE="${WORK_DIR}/records.jsonl"
: >"$RECORDS_FILE"

# find_detection_job <run-id> <output-file>
#
# Writes the `detection` job object (or `null`) for the run's latest attempt.
# Pages until the job is found or the listing is exhausted: a matrix-heavy run
# can hold more than one page of jobs, and assuming page 1 would misreport the
# detection job as absent.
find_detection_job() {
  local run_id="$1" out="$2" page=1 total=0 seen=0 body found
  body="${WORK_DIR}/jobs-page.json"
  while :; do
    if ! api_request "${API_URL}/repos/${TARGET_REPO}/actions/runs/${run_id}/jobs?per_page=${PER_PAGE}&page=${page}&filter=latest" "$body"; then
      return 1
    fi
    total="$(jq -r '.total_count // 0' "$body")"
    seen=$(( seen + $(jq -r '.jobs | length' "$body") ))
    found="$(jq -c --arg n "$DETECTION_JOB_NAME" \
      '[.jobs[]? | select(.name == $n)] | sort_by(.started_at // "") | last // empty' "$body")"
    if [ -n "$found" ]; then
      printf '%s\n' "$found" >"$out"
      return 0
    fi
    if [ "$seen" -ge "$total" ] || [ "$seen" -eq 0 ]; then
      printf 'null\n' >"$out"
      return 0
    fi
    page=$(( page + 1 ))
    if budget_exhausted; then
      return 1
    fi
  done
}

jobs_scanned=0
inspection_stopped=""
while IFS= read -r run; do
  if [ -z "$inspection_stopped" ] && budget_exhausted; then
    inspection_stopped=1
    note_truncation "detection-job inspection stopped after ${jobs_scanned}/${AGENTIC_RUNS} agentic runs (budget exhausted); the remaining runs are recorded as not_inspected"
  fi
  # Runs past the budget are still recorded, as `not_inspected`, so the
  # shortfall stays visible in the totals instead of silently shrinking the
  # population that every rate is computed over.
  if [ -n "$inspection_stopped" ]; then
    jq -c '. + {detection: {state: "not_inspected"}}' <<<"$run" >>"$RECORDS_FILE"
    continue
  fi

  run_id="$(jq -r '.id' <<<"$run")"
  job_file="${WORK_DIR}/detection-job.json"
  if ! find_detection_job "$run_id" "$job_file"; then
    jq -c '. + {detection: {state: "unknown", error: "jobs listing failed"}}' <<<"$run" >>"$RECORDS_FILE"
    jobs_scanned=$(( jobs_scanned + 1 ))
    continue
  fi
  jq -c --argjson run "$run" --arg marker "$EXTERNAL_DETECTOR_STEP" '
      if . == null then
        $run + {detection: {state: "absent"}}
      else
        . as $job
        | (($job.steps // []) | map(.name)) as $names
        | $run + {detection: {
            state: "present",
            job_id: $job.id,
            job_url: $job.html_url,
            status: $job.status,
            conclusion: $job.conclusion,
            started_at: $job.started_at,
            completed_at: $job.completed_at,
            # Raw evidence only. A job that was skipped, cancelled early or
            # failed during setup reports few or no steps, so the absence of
            # the marker here does NOT mean the run used the built-in
            # detector; the workflow-level rollup below resolves that.
            marker_seen: (($names | index($marker)) != null),
            steps_seen: ($names | length),
            failed_steps: (($job.steps // [])
              | map(select(.conclusion == "failure" or .conclusion == "timed_out" or .conclusion == "cancelled"))
              | map(.name))
          }}
      end
    ' "$job_file" >>"$RECORDS_FILE"
  jobs_scanned=$(( jobs_scanned + 1 ))
done < <(jq -c '.[]' "${WORK_DIR}/agentic-runs.json")

# Resolve which detector each run used.
#
# The marker step is only observable on a detection job that got far enough to
# reach it. Classifying per run would therefore drop exactly the failures this
# report exists to measure (skipped jobs, cancellations, setup failures) into
# the wrong bucket. Roll the evidence up to the workflow path instead, both
# ways: if any run of a workflow path shows the marker that day, every
# detection job of that path used the external detector; if any run shows a
# completed detection job with steps but no marker, the path opted out via
# `features: gh-aw-detection: false` and every detection job used the built-in
# path.
#
# Since gh-aw PR #54111 the external detector is the compile-time default, so
# a `.lock.yml` run with no evidence either way is far more likely external
# than built-in. Anything still unresolved after both rollups defaults to
# external for `.lock.yml` runs (the day-scope filter is already restricted to
# `.lock.yml`, so this covers every agentic run) and is otherwise reported as
# `unknown`; nothing is silently marked built-in.
jq -s '
  . as $records
  | ($records | map(select(.detection.marker_seen == true) | .path) | unique) as $external_paths
  | ($records
      | map(select(
          .detection.state == "present"
          and .detection.marker_seen == false
          and .detection.status == "completed"
          and .detection.conclusion != "skipped"
          and .detection.conclusion != "cancelled"
          and (.detection.steps_seen // 0) > 0)
        | .path)
      | unique) as $builtin_paths
  | ($records
      | map(select(.path | test("\\.lock\\.ya?ml$"))) | map(.path) | unique) as $agentic_paths
  | $records
  | map(
      if .detection.state != "present" then .
      else
        . as $r
        | .detection.detector =
            (if $r.detection.marker_seen then "external"
             elif ($external_paths | index($r.path)) then "external"
             elif ($builtin_paths | index($r.path)) then "builtin"
             # A completed job that ran its steps and never mentioned the
             # marker really did use gh-aw'"'"'s built-in detection.
             elif $r.detection.status == "completed"
               and $r.detection.conclusion != "skipped"
               and $r.detection.conclusion != "cancelled"
               and $r.detection.steps_seen > 0 then "builtin"
             # No evidence either way. External is the compile-time default
             # for `.lock.yml` workflows since gh-aw #54111, so residual
             # agentic runs count as external. Non-agentic paths shouldn'"'"'t
             # reach this branch (they were filtered out earlier), but stay
             # defensive if they do.
             elif ($agentic_paths | index($r.path)) then "external"
             else "unknown" end)
      end)
' "$RECORDS_FILE" >"${WORK_DIR}/records.json"

##############################################################################
# Phase 3: fetch the published detection verdict for external-detector runs.
#
# The detection job uploads `detection_result.json` as an artifact named
# `detection`. Its absence on a job that ran is the reliable signal that
# detection produced no verdict (step conclusions cannot show this: detection
# steps are continue-on-error, so the runner rewrites them to `success`).
##############################################################################

VERDICTS_FILE="${WORK_DIR}/verdicts.jsonl"
: >"$VERDICTS_FILE"

if [ "$FETCH_RESULTS" = "true" ]; then
  # Only runs where an external detection job actually executed can have a
  # verdict; skipped jobs never upload the artifact.
  jq -c '[.[] | select(.detection.state == "present" and .detection.detector == "external" and .detection.status == "completed" and .detection.conclusion != "skipped") | {run_id: .id}]' \
    "${WORK_DIR}/records.json" >"${WORK_DIR}/verdict-targets.json"
  verdict_targets="$(jq 'length' "${WORK_DIR}/verdict-targets.json")"
  log "Fetching detection verdicts for ${verdict_targets} runs"

  # find_detection_artifact <run-id> <output-file>
  #
  # Writes the `detection` artifact object (or `null`). Pages for the same
  # reason the jobs listing does: a run with many artifacts would otherwise be
  # misreported as having published no verdict, which the report would then
  # count as a detector reliability problem.
  find_detection_artifact() {
    local run_id="$1" out="$2" page=1 total=0 seen=0 body found
    body="${WORK_DIR}/artifacts-page.json"
    while :; do
      if ! api_request "${API_URL}/repos/${TARGET_REPO}/actions/runs/${run_id}/artifacts?per_page=${PER_PAGE}&page=${page}" "$body"; then
        return 1
      fi
      total="$(jq -r '.total_count // 0' "$body")"
      seen=$(( seen + $(jq -r '.artifacts | length' "$body") ))
      found="$(jq -c --arg n "$DETECTION_ARTIFACT_NAME" \
        'first(.artifacts[]? | select(.name == $n)) // empty' "$body")"
      if [ -n "$found" ]; then
        printf '%s\n' "$found" >"$out"
        return 0
      fi
      if [ "$seen" -ge "$total" ] || [ "$seen" -eq 0 ]; then
        printf 'null\n' >"$out"
        return 0
      fi
      page=$(( page + 1 ))
      if budget_exhausted; then
        return 1
      fi
    done
  }

  fetched=0
  while IFS= read -r target; do
    run_id="$(jq -r '.run_id' <<<"$target")"
    if [ "$fetched" -ge "$MAX_RESULT_FETCHES" ]; then
      note_truncation "verdict fetching stopped after ${fetched}/${verdict_targets} runs (MAX_RESULT_FETCHES)"
      break
    fi
    if budget_exhausted; then
      note_truncation "verdict fetching stopped after ${fetched}/${verdict_targets} runs (budget exhausted)"
      break
    fi
    fetched=$(( fetched + 1 ))

    artifact_file="${WORK_DIR}/artifact.json"
    if ! find_detection_artifact "$run_id" "$artifact_file"; then
      jq -nc --argjson id "$run_id" '{run_id: $id, result: "lookup_failed"}' >>"$VERDICTS_FILE"
      continue
    fi
    artifact="$(jq -c 'select(. != null)' "$artifact_file")"
    if [ -z "$artifact" ]; then
      jq -nc --argjson id "$run_id" '{run_id: $id, result: "absent"}' >>"$VERDICTS_FILE"
      continue
    fi
    if [ "$(jq -r '.expired' <<<"$artifact")" = "true" ]; then
      jq -nc --argjson id "$run_id" '{run_id: $id, result: "expired"}' >>"$VERDICTS_FILE"
      continue
    fi

    artifact_id="$(jq -r '.id' <<<"$artifact")"
    zip="${WORK_DIR}/detection.zip"
    if ! api_request "${API_URL}/repos/${TARGET_REPO}/actions/artifacts/${artifact_id}/zip" "$zip"; then
      jq -nc --argjson id "$run_id" '{run_id: $id, result: "download_failed"}' >>"$VERDICTS_FILE"
      continue
    fi
    rm -rf "${WORK_DIR}/unzipped"
    mkdir -p "${WORK_DIR}/unzipped"
    if ! unzip -qq -o "$zip" -d "${WORK_DIR}/unzipped" >/dev/null 2>&1; then
      jq -nc --argjson id "$run_id" '{run_id: $id, result: "unreadable"}' >>"$VERDICTS_FILE"
      continue
    fi
    result_json="$(find "${WORK_DIR}/unzipped" -name 'detection_result.json' -type f | head -n1)"
    if [ -z "$result_json" ]; then
      jq -nc --argjson id "$run_id" '{run_id: $id, result: "unreadable"}' >>"$VERDICTS_FILE"
      continue
    fi
    # `reasons` is deliberately empty in the published result; only the three
    # booleans are meaningful here.
    if ! jq -e 'has("prompt_injection") and has("secret_leak") and has("malicious_patch")' "$result_json" >/dev/null 2>&1; then
      jq -nc --argjson id "$run_id" '{run_id: $id, result: "malformed"}' >>"$VERDICTS_FILE"
      continue
    fi
    jq -c --argjson id "$run_id" '{
      run_id: $id,
      result: "present",
      prompt_injection: (.prompt_injection == true),
      secret_leak: (.secret_leak == true),
      malicious_patch: (.malicious_patch == true)
    }' "$result_json" >>"$VERDICTS_FILE"
  done < <(jq -c '.[]' "${WORK_DIR}/verdict-targets.json")
else
  log "FETCH_RESULTS=false; skipping verdict collection"
fi

jq -s '.' "$VERDICTS_FILE" >"${WORK_DIR}/verdicts.json"

##############################################################################
# Phase 4: reasons reported by gh-aw itself.
#
# gh-aw comments on an "[aw] Detection Runs" tracking issue whenever a
# detection conclusion is `warning` or `failure`, recording the reason
# (threat_detected / agent_failure / parse_error) and the run URL. This is the
# only cheap source for the reason string, so it is read last and is optional.
##############################################################################

REASONS_FILE="${WORK_DIR}/reasons.json"
echo '[]' >"$REASONS_FILE"

if [ "$FETCH_REASONS" = "true" ] && ! budget_exhausted; then
  body="${WORK_DIR}/issue-search.json"
  query="repo:${TARGET_REPO} is:issue in:title \"${DETECTION_RUNS_ISSUE_TITLE}\""
  if api_request "${API_URL}/search/issues?per_page=5&q=$(printf '%s' "$query" | jq -sRr @uri)" "$body"; then
    issue_number="$(jq -r --arg t "$DETECTION_RUNS_ISSUE_TITLE" \
      'first(.items[]? | select(.title == $t) | .number) // empty' "$body")"
    if [ -n "$issue_number" ]; then
      # `since` is server-side; the day's tail is then filtered locally.
      page=1
      : >"${WORK_DIR}/reasons.jsonl"
      while :; do
        body="${WORK_DIR}/comments.json"
        if ! api_request "${API_URL}/repos/${TARGET_REPO}/issues/${issue_number}/comments?per_page=${PER_PAGE}&page=${page}&since=${WINDOW_FROM}" "$body"; then
          note_truncation "failed to read detection-runs issue comments (page ${page})"
          break
        fi
        jq -c --arg from "$WINDOW_FROM" --arg to "$WINDOW_TO" '
          .[]? | select(.created_at >= $from and .created_at <= $to)
          | {
              created_at,
              conclusion: ((.body | capture("\\| Conclusion \\| `(?<v>[^`]*)`").v) // null),
              reason: ((.body | capture("\\| Reason \\| `(?<v>[^`]*)`").v) // null),
              run_url: ((.body | capture("\\[View run\\]\\((?<v>[^)]*)\\)").v) // null)
            }
          | . + {run_id: ((.run_url // "") | capture("/actions/runs/(?<v>[0-9]+)").v // null)}
        ' "$body" >>"${WORK_DIR}/reasons.jsonl" || true
        [ "$(jq 'length' "$body")" -lt "$PER_PAGE" ] && break
        page=$(( page + 1 ))
        if budget_exhausted; then
          note_truncation "detection-runs issue comments truncated at page ${page}"
          break
        fi
      done
      jq -s '.' "${WORK_DIR}/reasons.jsonl" >"$REASONS_FILE"
    else
      log "no \"${DETECTION_RUNS_ISSUE_TITLE}\" issue found in ${TARGET_REPO}"
    fi
  else
    note_truncation "failed to locate the detection-runs tracking issue"
  fi
fi

##############################################################################
# Phase 5: aggregate and render.
##############################################################################

printf '%s\n' "${TRUNCATION_NOTES[@]+"${TRUNCATION_NOTES[@]}"}" |
  jq -Rc 'select(length > 0)' | jq -s '.' >"${WORK_DIR}/truncations.json"

jq -n \
  --slurpfile records "${WORK_DIR}/records.json" \
  --slurpfile verdicts "${WORK_DIR}/verdicts.json" \
  --slurpfile reasons "$REASONS_FILE" \
  --slurpfile truncations "${WORK_DIR}/truncations.json" \
  --arg date "$TARGET_DATE" \
  --arg repo "$TARGET_REPO" \
  --arg from "$WINDOW_FROM" \
  --arg to "$WINDOW_TO" \
  --argjson total_runs "$TOTAL_RUNS" \
  --argjson agentic_runs "$AGENTIC_RUNS" \
  --argjson requests "$REQUEST_COUNT" \
  --argjson rate_limit_sleeps "$RATE_LIMIT_SLEEPS" \
  --arg fetch_results "$FETCH_RESULTS" '
  ($records[0] // []) as $records
  | ($verdicts[0] // []) as $verdicts
  | ($reasons[0] // []) as $reasons
  | ($verdicts | map({key: (.run_id | tostring), value: .}) | from_entries) as $vmap
  | ($reasons | map(select(.run_id != null)) | map({key: .run_id, value: .}) | from_entries) as $rmap
  | ($records
      | map(select(.detection.state == "present" and .detection.detector == "external"))
      | map(. + {
          verdict: ($vmap[(.id | tostring)] // null),
          reported: ($rmap[(.id | tostring)] // null)
        })) as $ext
  | ($ext | map(select(.detection.status == "completed" and .detection.conclusion == "success"))) as $green
  | ($ext | map(select(.verdict != null and .verdict.result == "present"))) as $withverdict
  | ($withverdict | map(select(.verdict.prompt_injection or .verdict.secret_leak or .verdict.malicious_patch))) as $threats
  | ((($truncations[0] // []) | length) == 0) as $complete
  | (($ext | length) as $n
     | def pct($k): if $n == 0 then 0 else (($k * 10000 / $n) | round) / 100 end;
     {
      date: $date,
      repository: $repo,
      window: {from: $from, to: $to},
      collection: {
        api_requests: $requests,
        rate_limit_sleeps: $rate_limit_sleeps,
        verdicts_fetched: ($fetch_results == "true"),
        truncations: ($truncations[0] // []),
        complete: $complete,
        # Rates are computed over the inspected subset. When collection was
        # truncated that subset is the earlier part of the day, so the rates
        # describe a partial day rather than being a lower bound.
        rates_cover_partial_day: ($complete | not)
      },
      totals: {
        runs_in_window: $total_runs,
        agentic_runs: $agentic_runs,
        runs_with_detection_job: ($records | map(select(.detection.state == "present")) | length),
        runs_without_detection_job: ($records | map(select(.detection.state == "absent")) | length),
        runs_unknown: ($records | map(select(.detection.state == "unknown")) | length),
        runs_not_inspected: ($records | map(select(.detection.state == "not_inspected")) | length),
        external_detector_runs: $n,
        builtin_detector_runs: ($records | map(select(.detection.detector == "builtin")) | length),
        indeterminate_detector_runs: ($records | map(select(.detection.detector == "unknown")) | length)
      },
      job_outcomes: ($ext
        | map(if .detection.status != "completed" then "in_progress"
              else (.detection.conclusion // "unknown") end)
        | group_by(.) | map({key: .[0], value: length}) | from_entries),
      job_outcome_rates: ($ext
        | map(if .detection.status != "completed" then "in_progress"
              else (.detection.conclusion // "unknown") end)
        | group_by(.) | map({key: .[0], value: pct(length)}) | from_entries),
      error_rate_pct: pct($ext | map(select(.detection.status == "completed"
        and (.detection.conclusion == "failure" or .detection.conclusion == "timed_out"
             or .detection.conclusion == "action_required"))) | length),
      verdict_availability: (if $fetch_results != "true" then {not_fetched: $n}
        else ($ext | map(
          if .verdict.result then .verdict.result
          # Detection jobs that were skipped or were still in progress at
          # collection time were never eligible for verdict fetching — call
          # that out explicitly instead of lumping them into not_fetched,
          # which is reserved for eligible targets the collector never
          # reached (budget exhausted, etc.).
          elif .detection.conclusion == "skipped"
               or .detection.status != "completed" then "skipped"
          else "not_fetched" end)
              | group_by(.) | map({key: .[0], value: length}) | from_entries) end),
      soft_failures: {
        description: "green detection job that published no verdict artifact",
        count: ($green | map(select((.verdict.result // "not_fetched") == "absent")) | length)
      },
      detection_results: {
        with_verdict: ($withverdict | length),
        clean: ($withverdict | map(select((.verdict.prompt_injection or .verdict.secret_leak or .verdict.malicious_patch) | not)) | length),
        any_threat: ($threats | length),
        prompt_injection: ($withverdict | map(select(.verdict.prompt_injection)) | length),
        secret_leak: ($withverdict | map(select(.verdict.secret_leak)) | length),
        malicious_patch: ($withverdict | map(select(.verdict.malicious_patch)) | length),
        threat_rate_pct: (if ($withverdict | length) == 0 then 0
          else ((($threats | length) * 10000 / ($withverdict | length)) | round) / 100 end)
      },
      reported_reasons: ($reasons | map(.reason // "unknown")
        | group_by(.) | map({key: .[0], value: length}) | from_entries),
      by_workflow: ($ext | group_by(.name) | map({
          workflow: .[0].name,
          runs: length,
          failed: (map(select(.detection.conclusion == "failure" or .detection.conclusion == "timed_out"
                             or .detection.conclusion == "action_required")) | length),
          cancelled: (map(select(.detection.conclusion == "cancelled")) | length),
          skipped: (map(select(.detection.conclusion == "skipped")) | length),
          no_verdict: (map(select((.verdict.result // "not_fetched") | . == "absent" or . == "expired")) | length),
          threats: (map(select(.verdict.result == "present" and
            (.verdict.prompt_injection or .verdict.secret_leak or .verdict.malicious_patch))) | length)
        }) | sort_by(-.runs)),
      notable_runs: ($ext
        | map(select(
            (.detection.status == "completed" and (.detection.conclusion == "failure"
              or .detection.conclusion == "timed_out" or .detection.conclusion == "action_required"))
            or ((.verdict.result // "") | . == "absent" or . == "malformed" or . == "unreadable")
            or (.verdict.result == "present" and (.verdict.prompt_injection or .verdict.secret_leak or .verdict.malicious_patch))
            or (.reported != null)))
        | map({
            workflow: .name,
            run_id: .id,
            run_url: .html_url,
            job_url: .detection.job_url,
            conclusion: (.detection.conclusion // .detection.status),
            failed_steps: (.detection.failed_steps // []),
            verdict: (if .verdict != null then .verdict.result
                      elif .detection.conclusion == "skipped"
                           or .detection.status != "completed" then "skipped"
                      else "not_fetched" end),
            threats: (if .verdict.result == "present" then
                ([if .verdict.prompt_injection then "prompt_injection" else empty end,
                  if .verdict.secret_leak then "secret_leak" else empty end,
                  if .verdict.malicious_patch then "malicious_patch" else empty end])
              else [] end),
            reported_conclusion: (.reported.conclusion // null),
            reported_reason: (.reported.reason // null)
          })
        # Most severe first, so a truncated table still shows what matters.
        | map(. + {severity:
            (if (.threats | length) > 0 then 0
             elif (.conclusion | IN("failure", "timed_out", "action_required")) then 1
             elif (.verdict | IN("absent", "malformed", "unreadable")) then 2
             else 3 end)})
        | sort_by(.severity, .workflow, .run_id)
        | map(del(.severity))),
      records: ($ext | map({
          workflow: .name,
          run_id: .id,
          run_url: .html_url,
          event: .event,
          created_at: .created_at,
          job_status: .detection.status,
          job_conclusion: .detection.conclusion,
          failed_steps: (.detection.failed_steps // []),
          verdict: (if .verdict != null then .verdict.result
                    elif .detection.conclusion == "skipped"
                         or .detection.status != "completed" then "skipped"
                    else "not_fetched" end),
          prompt_injection: (.verdict.prompt_injection // null),
          secret_leak: (.verdict.secret_leak // null),
          malicious_patch: (.verdict.malicious_patch // null),
          reported_reason: (.reported.reason // null)
        }))
    })
' >"${OUTPUT_DIR}/stats.json"

python3 - "${OUTPUT_DIR}/stats.json" "${OUTPUT_DIR}/summary.md" <<'PY'
import json
import sys

stats_path, summary_path = sys.argv[1], sys.argv[2]
with open(stats_path, encoding="utf-8") as handle:
    s = json.load(handle)

MAX_WORKFLOW_ROWS = 25
MAX_NOTABLE_ROWS = 60

out = []
w = out.append
t = s["totals"]
d = s["detection_results"]
c = s["collection"]

w(f"# gh-aw detection statistics - {s['date']} (UTC)")
w("")
w(f"Repository: `{s['repository']}`  ")
w(f"Window: `{s['window']['from']}` .. `{s['window']['to']}`  ")
w(f"API requests: {c['api_requests']}, rate-limit pauses: {c['rate_limit_sleeps']}  ")
w(f"Data complete: {'yes' if c['complete'] else 'NO - see Truncations'}")
w("")

w("## Totals")
w("")
w("| Metric | Count |")
w("|---|---|")
w(f"| Workflow runs in window | {t['runs_in_window']} |")
w(f"| Agentic runs (`*.lock.yml`) | {t['agentic_runs']} |")
w(f"| Runs with a `detection` job | {t['runs_with_detection_job']} |")
w(f"| ... using the external detector | {t['external_detector_runs']} |")
w(f"| ... using the built-in detector | {t['builtin_detector_runs']} |")
w(f"| ... detector could not be determined | {t['indeterminate_detector_runs']} |")
w(f"| Agentic runs without a `detection` job | {t['runs_without_detection_job']} |")
if t["runs_unknown"]:
    w(f"| Runs whose jobs could not be read | {t['runs_unknown']} |")
if t["runs_not_inspected"]:
    w(f"| Runs never inspected (budget exhausted) | {t['runs_not_inspected']} |")
w("")
w("All rates below are over the **external detector** population "
  f"({t['external_detector_runs']} runs). Since gh-aw #54111 the external "
  "detector is the compile-time default; a run counts as external when its "
  "`detection` job showed the `Install threat-detect binary` step, when "
  "another run of the same workflow did that day, or when the workflow is "
  "`.lock.yml` and no run showed the built-in shape (a completed detection "
  "job with steps but no marker). Runs on a workflow that opted out with "
  "`features: gh-aw-detection: false` count as built-in.")
if c["rates_cover_partial_day"]:
    w("")
    w("> **The rates below cover only the inspected part of the day.** "
      "Collection was truncated, and the inspected runs are the earlier ones, "
      "so these percentages are a partial-day sample — not a lower bound.")
w("")

w("## Detection job outcomes")
w("")
w("| Outcome | Count | Rate |")
w("|---|---|---|")
rates = s["job_outcome_rates"]
for key, count in sorted(s["job_outcomes"].items(), key=lambda kv: -kv[1]):
    w(f"| `{key}` | {count} | {rates.get(key, 0)}% |")
w("")
w(f"**Error rate (failure/timed_out/action_required): {s['error_rate_pct']}%**")
w("")

w("## Verdict availability")
w("")
w("| State | Meaning | Count |")
w("|---|---|---|")
# Fixed ordering + human-readable descriptions so readers don't have to guess
# what `not_fetched` or `present` mean. Zero-count rows are omitted; unknown
# states (should never happen, but the aggregator is defensive) are appended
# verbatim at the end.
VERDICT_STATE_DESCRIPTIONS = [
    ("present", "detection artifact downloaded and parsed"),
    ("absent", "detection job ran but published no artifact (soft failure)"),
    ("expired", "detection artifact existed but had already expired"),
    ("skipped", "detection job was skipped or was still running (nothing to fetch)"),
    ("not_fetched", "detection job ran but the collector didn't reach it (budget exhausted)"),
    ("download_failed", "artifact zip download failed (HTTP error)"),
    ("lookup_failed", "artifact listing failed (HTTP error)"),
    ("unreadable", "artifact zip could not be unpacked"),
    ("malformed", "detection_result.json was missing required fields"),
]
availability = dict(s["verdict_availability"])
for key, description in VERDICT_STATE_DESCRIPTIONS:
    count = availability.pop(key, 0)
    if count:
        w(f"| `{key}` | {description} | {count} |")
for key, count in sorted(availability.items(), key=lambda kv: -kv[1]):
    w(f"| `{key}` | (unknown state) | {count} |")
w("")
w(f"Green detection jobs that published no verdict: **{s['soft_failures']['count']}** "
  "(detection steps are `continue-on-error`, so a missing verdict artifact is the "
  "only reliable signal for these).")
w("")

w("## Detection results")
w("")
w("| Result | Count |")
w("|---|---|")
w(f"| Runs with a parsed verdict | {d['with_verdict']} |")
w(f"| Clean (no threat) | {d['clean']} |")
w(f"| Any threat | {d['any_threat']} |")
w(f"| `prompt_injection` | {d['prompt_injection']} |")
w(f"| `secret_leak` | {d['secret_leak']} |")
w(f"| `malicious_patch` | {d['malicious_patch']} |")
w("")
w(f"**Threat rate (of runs with a verdict): {d['threat_rate_pct']}%**")
w("")

if s["reported_reasons"]:
    w("## Reasons reported by gh-aw")
    w("")
    w("From the `[aw] Detection Runs` tracking issue (warning/failure conclusions only).")
    w("")
    w("| Reason | Count |")
    w("|---|---|")
    for key, count in sorted(s["reported_reasons"].items(), key=lambda kv: -kv[1]):
        w(f"| `{key}` | {count} |")
    w("")

rows = s["by_workflow"]
w("## By workflow")
w("")
w("| Workflow | Runs | Failed | Cancelled | Skipped | No verdict | Threats |")
w("|---|---|---|---|---|---|---|")
for row in rows[:MAX_WORKFLOW_ROWS]:
    w(f"| {row['workflow']} | {row['runs']} | {row['failed']} | {row['cancelled']} "
      f"| {row['skipped']} | {row['no_verdict']} | {row['threats']} |")
if len(rows) > MAX_WORKFLOW_ROWS:
    w("")
    w(f"_{len(rows) - MAX_WORKFLOW_ROWS} further workflows omitted; see `stats.json`._")
w("")

notable = s["notable_runs"]
w("## Notable runs")
w("")
if not notable:
    w("None: every external-detector run completed and produced a clean verdict.")
else:
    w("| Workflow | Run | Job conclusion | Verdict | Threats | Reported reason |")
    w("|---|---|---|---|---|---|")
    for row in notable[:MAX_NOTABLE_ROWS]:
        threats = ", ".join(row["threats"]) or "-"
        steps = ", ".join(row["failed_steps"])
        conclusion = row["conclusion"] + (f" ({steps})" if steps else "")
        w(f"| {row['workflow']} | [{row['run_id']}]({row['run_url']}) | `{conclusion}` "
          f"| `{row['verdict']}` | {threats} | `{row['reported_reason'] or '-'}` |")
    if len(notable) > MAX_NOTABLE_ROWS:
        w("")
        w(f"_{len(notable) - MAX_NOTABLE_ROWS} further notable runs omitted; see `stats.json`._")
w("")

if c["truncations"]:
    w("## Truncations")
    w("")
    w("The collector hit a budget or API limit; the numbers above are a lower bound.")
    w("")
    for item in c["truncations"]:
        w(f"- {item}")
    w("")

with open(summary_path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(out) + "\n")
PY

log "Wrote ${OUTPUT_DIR}/stats.json and ${OUTPUT_DIR}/summary.md (${REQUEST_COUNT} API requests)"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "${OUTPUT_DIR}/summary.md" >>"$GITHUB_STEP_SUMMARY"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'date=%s\n' "$TARGET_DATE"
    printf 'stats_file=%s\n' "${OUTPUT_DIR}/stats.json"
    printf 'summary_file=%s\n' "${OUTPUT_DIR}/summary.md"
    printf 'api_requests=%s\n' "$REQUEST_COUNT"
    printf 'external_detector_runs=%s\n' "$(jq -r '.totals.external_detector_runs' "${OUTPUT_DIR}/stats.json")"
    printf 'complete=%s\n' "$(jq -r '.collection.complete' "${OUTPUT_DIR}/stats.json")"
  } >>"$GITHUB_OUTPUT"
fi
