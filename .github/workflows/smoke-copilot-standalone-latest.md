---
description: Smoke test workflow that validates Copilot engine execution with the released threat-detect binary
on:
  workflow_dispatch:
permissions:
  contents: read
  issues: read
  pull-requests: read
  actions: read
  copilot-requests: write
name: Smoke Copilot Standalone Latest
engine:
  id: copilot
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
      id: copilot
      model: claude-sonnet-5
  create-issue:
    expires: 2h
    close-older-issues: true
    close-older-key: "smoke-copilot-standalone-latest"
    labels: [automation, testing]
timeout-minutes: 15
---

# Smoke Test: Copilot Engine Validation (Standalone Detector)

> **Generated / latest-detector variant.** This is the *latest* counterpart of
> `smoke-copilot-standalone.md`. Its `.lock.yml` is regenerated per the
> `update-workflow-versions` skill against the newest gh-aw and
> gh-aw-threat-detection (pre)releases. Do **not** run a plain `gh aw compile`
> on it — that would revert the patched detector version. It runs on manual
> dispatch and whenever its `.lock.yml` changes on `main`.

Keep outputs concise.

This workflow validates the Copilot engine while exercising the **native external
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
2. Use `web-fetch` to fetch `https://github.com/github/gh-aw-threat-detection` and verify the response mentions `gh-aw-threat-detection`.
3. Use bash to run `make build` in `${{ github.workspace }}` and verify it succeeds.
4. Use bash to create a minimal artifacts directory under `/tmp/gh-aw/smoke-copilot-standalone-${{ github.run_id }}` with:
   - `aw-prompts/prompt.txt`
   - `agent_output.json`
5. Use bash to run `./bin/threat-detect --version` and verify it prints a version.
6. Use bash to write a concise status file at `/tmp/gh-aw/agent/smoke-copilot-standalone-${{ github.run_id }}.txt`.

## Output

Always create an issue titled `Smoke Test: Copilot Standalone Latest - ${{ github.run_id }}` with:
- ✅ or ❌ for each test
- Overall status: PASS or FAIL
- Run URL: `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`
- Timestamp
