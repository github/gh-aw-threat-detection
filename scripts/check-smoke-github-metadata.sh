#!/usr/bin/env bash
# Host-side check. Only a fixed boolean crosses into the agent prompt; GitHub
# titles, bodies, comments and API diagnostics are never forwarded to the model.
set -euo pipefail
response="$(mktemp)"
trap 'rm -f "$response"' EXIT
if gh pr list --repo "$GITHUB_REPOSITORY" --limit 2 --state all --json number >"$response" 2>/dev/null &&
  jq -e 'type == "array" and length == 2 and
    all(.[]; keys == ["number"] and
      (.number | type == "number" and . > 0 and floor == .)) and
    (map(.number) | unique | length == 2)' "$response" >/dev/null 2>&1; then
  echo 'passed=true'
else
  echo 'passed=false'
fi
