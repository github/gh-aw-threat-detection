---
description: Smoke test workflow that validates Claude engine execution with the released threat-detect binary
on:
  workflow_dispatch:
  schedule: daily
permissions:
  contents: read
  issues: read
  pull-requests: read
  actions: read
name: Smoke Claude Standalone
engine:
  id: claude
  max-turns: 20
  bare: true
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
runtimes:
  go:
    version: "1.26"
checkout:
  fetch-depth: 1
safe-outputs:
  allowed-domains: [default-safe-outputs]
  threat-detection:
    continue-on-error: false
  create-issue:
    expires: 2h
    close-older-issues: true
    close-older-key: "smoke-claude-standalone"
    labels: [automation, testing]
timeout-minutes: 15
---

# Smoke Test: Claude Engine Validation (Standalone Detector)

Keep outputs concise.

This workflow validates the Claude engine while exercising the **native external
threat-detect path** (`features: gh-aw-detection: true`). gh-aw downloads the
published `threat-detect` binary from the `github/gh-aw-threat-detection` releases
and runs it under AWF, replacing the script-generated container sibling.

## Test Requirements

1. Use GitHub tools to read the latest 2 pull requests in `${{ github.repository }}` and record their numbers and titles only.
2. Use bash to run `make test` in `${{ github.workspace }}` and verify it succeeds.
3. Use bash to create a minimal artifacts directory under `/tmp/gh-aw/smoke-claude-standalone-${{ github.run_id }}` with:
   - `aw-prompts/prompt.txt`
   - `agent_output.json`
4. Use bash to run `./bin/threat-detect --version`; if the binary does not exist, run `make build` first.
5. Use bash to write a concise status file at `/tmp/gh-aw/agent/smoke-claude-standalone-${{ github.run_id }}.txt`.

## Output

Always create an issue titled `Smoke Test: Claude Standalone - ${{ github.run_id }}` with:
- ✅ or ❌ for each test
- Overall status: PASS or FAIL
- Run URL: `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`
- Timestamp
