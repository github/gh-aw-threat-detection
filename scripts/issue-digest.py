#!/usr/bin/env python3
"""Publish the upstream issue digest without exposing GitHub text to a model."""

import argparse
import datetime
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys

UPSTREAM = "github/gh-aw"
LABEL = "gh-aw-issue-digest"
MARKER = re.compile(r"\n<!-- gh-aw-issue-digest:v1 numbers=([0-9,]+) -->\n?\Z")


class DigestError(Exception):
    """A fixed diagnostic that never echoes untrusted API content."""


def api(endpoint, *, fields=(), payload=None):
    args = ["gh", "api", "--method", "POST" if payload is not None else "GET", endpoint]
    for key, value in fields:
        args.extend(["-f", f"{key}={value}"])
    if payload is not None:
        args.extend(["--input", "-"])
    try:
        result = subprocess.run(
            args, input=json.dumps(payload) if payload is not None else None,
            capture_output=True, text=True, check=True, timeout=60,
        )
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise DigestError("GitHub request failed. State was not advanced; retry the workflow.") from error


def issue_number(value):
    return type(value) is int and value > 0


def load_state(path):
    try:
        state = json.loads(path.read_text())
        numbers = state["reported_issue_numbers"]
        if not isinstance(numbers, list) or not all(issue_number(n) for n in numbers):
            return None
        return set(numbers)
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_state(path, numbers, timestamp):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({
        "reported_issue_numbers": sorted(numbers)[-500:], "last_run_at": timestamp,
    }) + "\n")
    temporary.replace(path)


def metadata(item):
    """Project API results immediately; never retain bodies or comments."""
    if not isinstance(item, dict) or "pull_request" in item or not issue_number(item.get("number")):
        raise DigestError("Invalid issue listing. Expected issue metadata; state was not advanced.")
    try:
        title = item["title"]
        state = item["state"]
        created = item["created_at"]
        author = item["user"]["login"]
        labels = [label["name"] for label in item["labels"]]
        if not all(isinstance(text, str) for text in [title, created, author, *labels]):
            raise ValueError
        if state not in ("open", "closed") or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created):
            raise ValueError
        return dict(number=item["number"], title=title, state=state, created=created[:10], author=author, labels=labels)
    except (KeyError, TypeError, ValueError) as error:
        raise DigestError("Invalid issue metadata. State was not advanced; check the API schema.") from error


def escaped(text):
    # Plain Markdown text: no links, HTML, mentions, headings or multiline content
    # from an issue title/label can become active markup in the published digest.
    text = " ".join("".join(c if c.isprintable() else " " for c in text[:512]).split())
    text = re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", text)
    return html.escape(text, quote=True).replace("@", "&#64;")


def render(issues, run_url):
    closed = sum(item["state"] == "closed" for item in issues)
    lines = [
        f"{len(issues)} new threat-detection issues in {UPSTREAM}; {closed} already closed.",
        "", "## Issues", "",
    ]
    for item in issues:
        number = item["number"]
        labels = [escaped(label) for label in item["labels"] if label != "threat-detection"]
        suffix = f", labels: {', '.join(labels)}" if labels else ""
        lines.append(
            f"- [#{number}](https://github.com/{UPSTREAM}/issues/{number}) — "
            f"{escaped(item['title'])} — {item['state']}, opened {item['created']} "
            f"by &#64;{escaped(item['author'])}{suffix}"
        )
    lines.extend([
        "", "## Why this matters", "",
        "This repository ships the threat-detect binary consumed by gh-aw; these issues may require follow-up here.",
        "", f"Scanned: {run_url}", "",
        "<!-- gh-aw-issue-digest:v1 numbers=" + ",".join(str(item["number"]) for item in issues) + " -->",
    ])
    return "\n".join(lines)


def run(state_path, repository, run_id, request=api):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not run_id.isdecimal():
        raise DigestError("Invalid workflow context. Expected owner/repo and a numeric run ID.")
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    listing = request("search/issues", fields=(
        ("q", f"repo:{UPSTREAM} is:issue label:threat-detection"),
        ("sort", "updated"), ("order", "desc"), ("per_page", "50"),
    ))
    if (not isinstance(listing, dict) or listing.get("incomplete_results") is not False
            or not isinstance(listing.get("items"), list) or len(listing["items"]) > 50):
        raise DigestError("Incomplete issue search. State was not advanced; retry the workflow.")
    issues = [metadata(item) for item in listing["items"]]
    numbers = {item["number"] for item in issues}
    if len(numbers) != len(issues):
        raise DigestError("Duplicate issue metadata. State was not advanced.")
    reported = load_state(state_path)
    if reported is None:
        save_state(state_path, numbers, timestamp)
        return "Baseline established; no digest published."

    # Reconcile confirmed bot-authored reports, including a POST that succeeded
    # before its response or the cache save was lost. Ignore other authors and
    # unrelated digest issues; their existence proves no publication occurred.
    published = request(f"repos/{repository}/issues", fields=(
        ("labels", LABEL), ("state", "all"), ("sort", "created"),
        ("direction", "desc"), ("per_page", "100"),
    ))
    if not isinstance(published, list):
        raise DigestError("Invalid published-digest listing. State was not advanced.")
    for item in published:
        if not isinstance(item, dict) or not isinstance(item.get("user"), dict):
            raise DigestError("Invalid published-digest metadata. State was not advanced.")
        if item.get("user", {}).get("login") != "github-actions[bot]" or "pull_request" in item:
            continue
        body = item.get("body") or ""
        if not isinstance(body, str):
            raise DigestError("Invalid published-digest body. State was not advanced.")
        for match in MARKER.finditer(body):
            reported.update(int(number) for number in match[1].split(","))

    new = [item for item in issues if item["number"] not in reported]
    if new:
        response = request(f"repos/{repository}/issues", payload={
            "title": f"[gh-aw-issues] New gh-aw threat-detection issues - {timestamp[:10]}",
            "body": render(new, f"https://github.com/{repository}/actions/runs/{run_id}"),
            "labels": ["automation", LABEL],
        })
        if not isinstance(response, dict) or not issue_number(response.get("number")):
            raise DigestError("Digest publication was not confirmed. State was not advanced.")
    save_state(state_path, reported | numbers, timestamp)
    return f"Published {len(new)} new issues." if new else "No new issues; no digest published."


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(run(args.state_file, os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_RUN_ID", "")))
    except (DigestError, OSError) as error:
        # Do not echo API payloads, filenames or issue-authored text into logs.
        print(str(error) if isinstance(error, DigestError) else "Could not persist digest state.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
