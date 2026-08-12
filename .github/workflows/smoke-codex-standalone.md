---
description: Smoke test workflow that validates Codex engine execution with the released threat-detect binary
on:
  workflow_dispatch:
  schedule: daily
permissions:
  contents: read
  issues: read
  pull-requests: read
  actions: read
name: Smoke Codex Standalone
engine: codex
strict: false
features:
  gh-aw-detection: true
network:
  allowed:
    - defaults
    - github
tools:
  bash:
    - "*"
  github:
    mode: gh-proxy
  web-fetch:
runtimes:
  go:
    version: "1.26"
checkout:
  fetch-depth: 1
safe-outputs:
  allowed-domains: [default-safe-outputs]
  threat-detection:
    continue-on-error: false
    engine:
      runtime:
        id: codex
      provider:
        model: gpt-5.4-mini
  create-issue:
    expires: 2h
    close-older-issues: true
    close-older-key: "smoke-codex-standalone"
    labels: [automation, testing]
timeout-minutes: 15
---

# Smoke Test: Codex Engine Validation (Standalone Detector)

Keep outputs concise.

This workflow validates the Codex engine while exercising the **native external
threat-detect path** (`features: gh-aw-detection: true`). gh-aw downloads the
published `threat-detect` binary from the `github/gh-aw-threat-detection` releases
and runs it under AWF, replacing the script-generated container sibling.

## Turn Budget

You have a strict turn budget. Run each shell command **once** and do not poll
it in a loop or re-run it in the background.

A long-running command (for example a full build or test run) may exceed the
shell tool's own timeout. In that case you may back it with a single background
run and wait for it **once**, for at most 5 minutes total. If it has not
finished by then, record ❌ for that check and move on to the next
requirement — do not keep waiting.

## Test Requirements

1. Use GitHub tools to read the latest 2 pull requests in `${{ github.repository }}` and record their numbers and titles only.
2. Use bash to run `curl -fsSL https://github.com/github/gh-aw-threat-detection` and verify the command exits `0` **and** its output mentions `gh-aw-threat-detection`. The `-f` flag is required so an HTTP 4xx/5xx response (for example an AWF/Squid denial page, which may itself echo the requested URL) fails instead of counting as a successful fetch. This is an egress check through the AWF firewall: the Codex CLI has no web-fetch tool, so do **not** try to satisfy this with `web-fetch`.
3. Use bash to run `make lint` and `make build` in `${{ github.workspace }}` and verify both succeed.
4. Use bash to create a minimal artifacts directory under `/tmp/gh-aw/smoke-codex-standalone-${{ github.run_id }}` with:
   - `aw-prompts/prompt.txt`
   - `agent_output.json`
5. Use bash to run `./bin/threat-detect --version` and verify it prints a version.
6. Use bash to write a concise status file at `/tmp/gh-aw/agent/smoke-codex-standalone-${{ github.run_id }}.txt`.

## Output

Always create an issue titled `Smoke Test: Codex Standalone - ${{ github.run_id }}` with:
- ✅ or ❌ for each test
- Overall status: PASS or FAIL
- Run URL: `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`
- Timestamp
