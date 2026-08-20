#!/usr/bin/env bash
#
# Offline end-to-end test for scripts/collect-detection-stats.sh.
#
# Spins up a local stub of the GitHub REST API that reproduces the behaviours
# the collector has to survive — >1000 results in a window (forcing time-window
# bisection), multi-page listings, a 403 rate-limit response, a 500, expired and
# missing artifacts — and asserts the aggregated output.
#
# Usage: scripts/test/collect-detection-stats-test.sh

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="${repo_root}/scripts/collect-detection-stats.sh"
work="$(mktemp -d)"
server_pid=""

cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

cat >"${work}/stub_api.py" <<'PY'
"""Minimal stub of the GitHub REST API surface the collector uses."""

import io
import json
import re
import sys
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlparse

TOTAL_RUNS = 1400  # > 1000, so the collector must bisect the day window.


def make_run(i):
    """Every third run is a non-agentic (.yml) run that the free path filter drops."""
    agentic = i % 3 != 0
    hour = ((i - 1) * 24) // TOTAL_RUNS
    return {
        "id": i,
        "name": f"Workflow {i % 4}",
        "path": f".github/workflows/wf{i % 4}." + ("lock.yml" if agentic else "yml"),
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "created_at": f"2026-08-17T{hour:02d}:{(i % 60):02d}:00Z",
        "updated_at": f"2026-08-17T{hour:02d}:{(i % 60):02d}:30Z",
        "html_url": f"https://github.com/github/gh-aw/actions/runs/{i}",
        "run_attempt": 1,
        "head_branch": "main",
    }


RUNS = [make_run(i) for i in range(1, TOTAL_RUNS + 1)]

# Runs whose jobs / artifacts listings span more than one page.
PAGINATED_JOBS_RUN = 11
PAGINATED_ARTIFACTS_RUN = 19


def uses_external_detector(run_id):
    """Detector choice is a property of the workflow, as it is in reality."""
    return run_id % 4 != 1


def detection_job(run_id):
    """Deterministic per-run detection job shape covering every classification.

    Mirrors the real API: a skipped job reports no steps at all, and an
    in-progress or early-failed job reports only the steps reached so far. The
    marker step is therefore invisible on exactly the runs this report cares
    about most, which is what the workflow-level rollup has to repair.
    """
    bucket = run_id % 10
    if bucket == 0:
        return None  # no detection job at all
    external = uses_external_detector(run_id)
    steps = [{"name": "Setup Scripts", "conclusion": "success"}]
    if bucket == 2:
        status, conclusion = "completed", "failure"
    elif bucket == 3:
        status, conclusion = "completed", "cancelled"
    elif bucket == 4:
        status, conclusion = "completed", "skipped"
    elif bucket == 5:
        status, conclusion = "in_progress", None
    elif bucket == 6:
        status, conclusion = "completed", "failure"
    else:
        status, conclusion = "completed", "success"

    if conclusion == "skipped":
        steps = []  # skipped jobs expose no steps
    elif bucket == 6:
        steps = [{"name": "Setup Scripts", "conclusion": "failure"}]  # died before install
    elif status == "in_progress" or conclusion == "cancelled":
        pass  # only the first step is visible
    else:
        if external:
            steps.append({"name": "Install threat-detect binary", "conclusion": "success"})
        steps.append({"name": "Execute threat detection with AWF", "conclusion": "success"})
        if conclusion == "failure":
            steps.append({"name": "Conclude threat detection", "conclusion": "failure"})
    return {
        "id": 900000 + run_id,
        "name": "detection",
        "status": status,
        "conclusion": conclusion,
        "started_at": "2026-08-17T01:00:00Z",
        "completed_at": "2026-08-17T01:05:00Z",
        "html_url": f"https://github.com/github/gh-aw/actions/runs/{run_id}/job/{900000 + run_id}",
        "steps": steps,
    }


def detection_artifact(run_id):
    """None -> no artifact; 'expired' -> expired; else the published verdict."""
    bucket = run_id % 10
    if bucket in (4, 5, 6):
        return None
    if run_id % 100 == 7:
        return "expired"
    if run_id % 50 == 7:
        return None  # green job, no verdict published (soft failure)
    return {
        "prompt_injection": run_id % 77 == 0,
        "secret_leak": run_id % 131 == 0,
        "malicious_patch": False,
        "reasons": [],
    }


class Handler(BaseHTTPRequestHandler):
    injected = {"rate_limit": False, "server_error": False}

    def log_message(self, *args):
        pass

    def _send(self, code, payload, raw=False, headers=None):
        body = payload if raw else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("x-ratelimit-remaining", "4999")
        self.send_header("x-ratelimit-reset", "0")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)

        # Inject one transient rate limit and one 5xx, once each, to prove the
        # retry/backoff paths recover instead of losing data.
        if not self.injected["rate_limit"] and path.endswith("/jobs"):
            self.injected["rate_limit"] = True
            return self._send(
                403,
                {"message": "API rate limit exceeded"},
                headers={"x-ratelimit-remaining": "0", "retry-after": "1"},
            )
        if not self.injected["server_error"] and path.endswith("/artifacts"):
            self.injected["server_error"] = True
            return self._send(500, {"message": "boom"})

        if re.fullmatch(r"/repos/[^/]+/[^/]+/actions/runs", path):
            created = unquote(query.get("created", [""])[0])
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["100"])[0])
            lo, _, hi = created.partition("..")
            matched = [r for r in RUNS if lo <= r["created_at"] <= hi]
            start = (page - 1) * per_page
            return self._send(
                200,
                {
                    "total_count": len(matched),
                    "workflow_runs": matched[start : start + per_page],
                },
            )

        m = re.fullmatch(r"/repos/[^/]+/[^/]+/actions/runs/(\d+)/jobs", path)
        if m:
            run_id = int(m.group(1))
            job = detection_job(run_id)
            # PAGINATED_JOBS_RUN has a wide matrix, so its detection job only
            # appears on page 2. Reading page 1 alone would report it absent.
            filler = 150 if run_id == PAGINATED_JOBS_RUN else 1
            jobs = [
                {
                    "id": 1000 + n,
                    "name": f"agent-{n}",
                    "status": "completed",
                    "conclusion": "success",
                    "steps": [],
                }
                for n in range(filler)
            ]
            if job:
                jobs.append(job)
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["100"])[0])
            start = (page - 1) * per_page
            return self._send(
                200,
                {"total_count": len(jobs), "jobs": jobs[start : start + per_page]},
            )

        m = re.fullmatch(r"/repos/[^/]+/[^/]+/actions/runs/(\d+)/artifacts", path)
        if m:
            run_id = int(m.group(1))
            art = detection_artifact(run_id)
            # PAGINATED_ARTIFACTS_RUN publishes enough artifacts to push
            # `detection` onto page 2.
            filler = 120 if run_id == PAGINATED_ARTIFACTS_RUN else 0
            artifacts = [
                {"id": 800000 + n, "name": f"logs-{n}", "expired": False}
                for n in range(filler)
            ]
            if art is not None:
                artifacts.append(
                    {
                        "id": 700000 + run_id,
                        "name": "detection",
                        "expired": art == "expired",
                    }
                )
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["100"])[0])
            start = (page - 1) * per_page
            return self._send(
                200,
                {
                    "total_count": len(artifacts),
                    "artifacts": artifacts[start : start + per_page],
                },
            )

        m = re.fullmatch(r"/repos/[^/]+/[^/]+/actions/artifacts/(\d+)/zip", path)
        if m:
            # The real API answers with a 302 redirect to a signed blob URL on
            # a different host. Mirror that here so the collector's curl config
            # has to actually follow the redirect (and drop the Authorization
            # header) to succeed — the way production has to.
            self.send_response(302)
            self.send_header(
                "Location", f"/blob/artifacts/{m.group(1)}/download"
            )
            self.end_headers()
            return

        m = re.fullmatch(r"/blob/artifacts/(\d+)/download", path)
        if m:
            # The signed blob URL is unauthenticated in reality; curl strips
            # the Authorization header on the cross-host hop. Our stub is
            # single-host, so we don't reject on Authorization here — the
            # regression we're guarding against is curl not following the
            # 302 at all (--no-location-trusted silently disabled --location).
            verdict = detection_artifact(int(m.group(1)) - 700000)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("detection_result.json", json.dumps(verdict))
            return self._send(200, buf.getvalue(), raw=True)

        if path == "/search/issues":
            return self._send(
                200,
                {
                    "total_count": 1,
                    "items": [{"number": 42, "title": "[aw] Detection Runs"}],
                },
            )

        if re.fullmatch(r"/repos/[^/]+/[^/]+/issues/42/comments", path):
            if int(query.get("page", ["1"])[0]) > 1:
                return self._send(200, [])
            comments = []
            for run_id, reason in (
                (2, "agent_failure"),
                (12, "parse_error"),
                (206, "threat_detected"),
            ):
                comments.append(
                    {
                        "created_at": "2026-08-17T03:00:00Z",
                        "body": (
                            "### Workflow 0\n\n| Field | Value |\n|---|---|\n"
                            "| Conclusion | `warning` |\n"
                            f"| Reason | `{reason}` |\n"
                            "| Run | [View run]"
                            f"(https://github.com/github/gh-aw/actions/runs/{run_id}) |\n"
                        ),
                    }
                )
            return self._send(200, comments)

        self._send(404, {"message": "not found"})


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

port="${STUB_API_PORT:-8731}"
python3 "${work}/stub_api.py" "$port" &
server_pid=$!

ready=""
for _ in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:${port}/search/issues" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
[ -n "$ready" ] || fail "stub API did not start on port ${port}"

out="${work}/out"
GH_TOKEN=stub-token \
  GITHUB_API_URL="http://127.0.0.1:${port}" \
  TARGET_REPO="github/gh-aw" \
  TARGET_DATE="2026-08-17" \
  OUTPUT_DIR="$out" \
  REQUEST_PAUSE_SECONDS=0 \
  DEADLINE_MINUTES=10 \
  MAX_REQUESTS=20000 \
  MAX_RESULT_FETCHES=20000 \
  bash "$script" >"${work}/stderr.log" 2>&1 || {
  cat "${work}/stderr.log" >&2
  fail "collector exited non-zero"
}

stats="${out}/stats.json"
[ -f "$stats" ] || fail "stats.json not written"
[ -f "${out}/summary.md" ] || fail "summary.md not written"

assert_eq() {
  [ "$1" = "$2" ] || fail "${3}: expected ${2}, got ${1}"
}

# --- window bisection: all 1400 runs found despite the 1000-result cap -------
assert_eq "$(jq -r '.totals.runs_in_window' "$stats")" 1400 "runs_in_window"
grep -q "bisecting" "${work}/stderr.log" ||
  fail "expected the collector to bisect the over-full window"

# --- aggregation ------------------------------------------------------------
python3 - "$stats" <<'PY'
import json
import sys

s = json.load(open(sys.argv[1]))
agentic = [i for i in range(1, 1401) if i % 3 != 0]

# Mirror of the fixture, so expectations are derived rather than hand-counted.
def bucket(i):
    return i % 10

def external_wf(i):
    return i % 4 != 1

present = [i for i in agentic if bucket(i) != 0]
ext = [i for i in present if external_wf(i)]
# Workflow wf1 never shows the marker but has completed detection jobs with
# steps every day, so the symmetric built-in path rollup promotes every wf1
# run (including its skipped / cancelled / in-progress ones with zero
# observable steps) to `builtin`. No wf1 run should land in `unknown`.
builtin = [i for i in present if not external_wf(i)]
unknown_detector = []

def outcome(i):
    b = bucket(i)
    if b == 2 or b == 6:
        return "failure"
    if b == 3:
        return "cancelled"
    if b == 4:
        return "skipped"
    if b == 5:
        return "in_progress"
    return "success"

t = s["totals"]
assert t["agentic_runs"] == len(agentic), t
assert t["runs_without_detection_job"] == sum(1 for i in agentic if bucket(i) == 0), t
assert t["external_detector_runs"] == len(ext), t
assert t["builtin_detector_runs"] == len(builtin), t
assert t["indeterminate_detector_runs"] == len(unknown_detector), t
assert t["runs_unknown"] == 0, t
assert t["runs_not_inspected"] == 0, t
assert len(builtin) > 0, len(builtin)

outcomes = s["job_outcomes"]
for name in ("failure", "cancelled", "skipped", "in_progress", "success"):
    expected = sum(1 for i in ext if outcome(i) == name)
    assert outcomes.get(name) == expected, (name, outcomes.get(name), expected)
# Skipped and in-progress detection jobs expose no marker step; they must still
# land in the external population rather than being silently reclassified.
assert outcomes["skipped"] > 0 and outcomes["in_progress"] > 0, outcomes

expected_rate = round(outcomes["failure"] * 10000 / t["external_detector_runs"]) / 100
assert abs(s["error_rate_pct"] - expected_rate) < 0.02, (s["error_rate_pct"], expected_rate)

# Verdicts are fetched only for completed, non-skipped external detection jobs.
targets = [i for i in ext if outcome(i) not in ("skipped", "in_progress")]

def verdict_state(i):
    if bucket(i) == 6:
        return "absent"  # failed before publishing
    if i % 100 == 7:
        return "expired"
    if i % 50 == 7:
        return "absent"
    return "present"

expect_present = sum(1 for i in targets if verdict_state(i) == "present")
expect_expired = sum(1 for i in targets if verdict_state(i) == "expired")
expect_absent = sum(1 for i in targets if verdict_state(i) == "absent")

av = s["verdict_availability"]
assert av.get("present") == expect_present, (av, expect_present)
assert av.get("expired") == expect_expired, (av, expect_expired)
assert av.get("absent") == expect_absent, (av, expect_absent)
# Skipped detection jobs must be reported under `skipped`, distinct from
# `not_fetched` (which is reserved for eligible targets the collector
# didn't reach — e.g. budget exhausted). In the happy-path fixture we
# reach every target so `not_fetched` must be absent entirely.
expect_skipped = sum(1 for i in ext if outcome(i) in ("skipped", "in_progress"))
assert av.get("skipped") == expect_skipped, (av, expect_skipped)
assert "not_fetched" not in av, av

d = s["detection_results"]
assert d["with_verdict"] == expect_present, d
graded = [i for i in targets if verdict_state(i) == "present"]
assert d["prompt_injection"] == sum(1 for i in graded if i % 77 == 0), d
assert d["secret_leak"] == sum(1 for i in graded if i % 131 == 0), d
assert d["prompt_injection"] > 0 and d["secret_leak"] > 0, d
assert d["malicious_patch"] == 0, d
assert d["clean"] + d["any_threat"] == d["with_verdict"], d
assert d["any_threat"] > 0 and d["threat_rate_pct"] > 0, d

# Multi-page jobs / artifacts listings must not be reported as absent.
records = {r["run_id"]: r for r in s["records"]}
assert 11 in records, "detection job on page 2 of the jobs listing was missed"
assert records[11]["verdict"] == "present", records[11]
assert records[19]["verdict"] == "present", (
    "detection artifact on page 2 of the artifacts listing was missed",
    records[19],
)

# Notable runs are ordered most-severe-first so a truncated table stays useful.
assert s["notable_runs"][0]["threats"], s["notable_runs"][0]

assert s["reported_reasons"].get("agent_failure") == 1, s["reported_reasons"]
assert s["reported_reasons"].get("parse_error") == 1, s["reported_reasons"]

by_run = {r["run_id"]: r for r in s["notable_runs"]}
assert by_run[2]["reported_reason"] == "agent_failure", by_run.get(2)
assert by_run[2]["conclusion"] == "failure", by_run[2]
assert "Conclude threat detection" in by_run[2]["failed_steps"], by_run[2]

# The injected 403 and 500 must have been retried, not silently dropped.
assert s["collection"]["complete"] is True, s["collection"]
assert s["collection"]["rates_cover_partial_day"] is False, s["collection"]
assert s["collection"]["rate_limit_sleeps"] >= 1, s["collection"]
print("aggregation assertions OK")
PY

# --- summary is bounded and renders the headline numbers --------------------
summary_bytes="$(wc -c <"${out}/summary.md")"
[ "$summary_bytes" -lt 20000 ] ||
  fail "summary.md is ${summary_bytes} bytes; expected a bounded digest"
grep -q "^# gh-aw detection statistics - 2026-08-17 (UTC)$" "${out}/summary.md" ||
  fail "summary.md is missing its title"
for section in "## Totals" "## Detection job outcomes" "## Verdict availability" \
  "## Detection results" "## Reasons reported by gh-aw" "## By workflow" "## Notable runs"; do
  grep -qF "$section" "${out}/summary.md" || fail "summary.md is missing section: ${section}"
done
# The verdict-availability table must explain each state — the raw keys
# (`present`, `not_fetched`) are opaque to a reader. `not_fetched` in particular
# needs to be tied to skipped detection jobs, not to a fetch failure.
grep -qF "| State | Meaning | Count |" "${out}/summary.md" ||
  fail "summary.md verdict table is missing its Meaning column"
grep -qF "detection job was skipped" "${out}/summary.md" ||
  fail "summary.md must explain that skipped means the detection job was skipped"
grep -qF "detection artifact downloaded and parsed" "${out}/summary.md" ||
  fail "summary.md must describe successful (present) downloads"

# --- budget exhaustion degrades gracefully rather than failing ---------------
out2="${work}/out-budget"
GH_TOKEN=stub-token \
  GITHUB_API_URL="http://127.0.0.1:${port}" \
  TARGET_DATE="2026-08-17" \
  OUTPUT_DIR="$out2" \
  REQUEST_PAUSE_SECONDS=0 \
  MAX_REQUESTS=25 \
  bash "$script" >"${work}/stderr-budget.log" 2>&1 ||
  fail "collector must exit 0 when the request budget is exhausted"
assert_eq "$(jq -r '.collection.complete' "${out2}/stats.json")" false "budget complete flag"
assert_eq "$(jq -r '.collection.rates_cover_partial_day' "${out2}/stats.json")" true "budget partial-day flag"
# Runs the collector never got to must still be counted, so the shortfall is
# visible instead of quietly shrinking the population behind every rate.
[ "$(jq -r '.totals.runs_not_inspected' "${out2}/stats.json")" -gt 0 ] ||
  fail "budget-exhausted run should record not_inspected runs"
grep -qF "Runs never inspected" "${out2}/summary.md" ||
  fail "budget-exhausted summary should report the uninspected runs"
grep -qF "partial-day sample" "${out2}/summary.md" ||
  fail "budget-exhausted summary should flag the rates as partial"
[ "$(jq -r '.collection.truncations | length' "${out2}/stats.json")" -gt 0 ] ||
  fail "budget-exhausted run should record a truncation note"
grep -qF "## Truncations" "${out2}/summary.md" ||
  fail "budget-exhausted summary should carry a Truncations section"

# --- bad configuration is rejected with exit code 2 -------------------------
set +e
GH_TOKEN=stub-token TARGET_DATE="2026-02-30" OUTPUT_DIR="${work}/out3" \
  bash "$script" >/dev/null 2>&1
rc=$?
set -e
assert_eq "$rc" 2 "invalid TARGET_DATE exit code"

set +e
GH_TOKEN="" OUTPUT_DIR="${work}/out4" bash "$script" >/dev/null 2>&1
rc=$?
set -e
assert_eq "$rc" 2 "missing GH_TOKEN exit code"

echo "PASS: scripts/collect-detection-stats.sh"
