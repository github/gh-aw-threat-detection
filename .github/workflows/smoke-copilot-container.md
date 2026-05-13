---
description: Smoke test workflow that validates Copilot engine execution in this repository
on:
  workflow_dispatch:
  schedule: daily
permissions:
  contents: read
  issues: read
  pull-requests: read
  actions: read
name: Smoke Copilot
engine:
  id: copilot
strict: false
network:
  allowed:
    - defaults
    - github
tools:
  bash:
    - "*"
  github:
  web-fetch:
runtimes:
  go:
    version: "1.23"
checkout:
  fetch-depth: 1
safe-outputs:
  allowed-domains: [default-safe-outputs]
  create-issue:
    expires: 2h
    close-older-issues: true
    close-older-key: "smoke-copilot-threat-detection"
    labels: [automation, testing]
timeout-minutes: 15
---

# Smoke Test: Copilot Engine Validation

Keep outputs concise.

## Test Requirements

1. Use GitHub tools to read the latest 2 pull requests in `${{ github.repository }}` and record their numbers and titles only.
2. Use `web-fetch` to fetch `https://github.com/github/gh-aw-threat-detection` and verify the response mentions `gh-aw-threat-detection`.
3. Use bash to run `make build` in `${{ github.workspace }}` and verify it succeeds.
4. Use bash to create a minimal artifacts directory under `/tmp/gh-aw/smoke-copilot-${{ github.run_id }}` with:
   - `aw-prompts/prompt.txt`
   - `agent_output.json`
5. Use bash to run `./bin/threat-detect --version` and verify it prints a version.
6. Use bash to write a concise status file at `/tmp/gh-aw/agent/smoke-copilot-${{ github.run_id }}.txt`.

## Output

Always create an issue titled `Smoke Test: Copilot - ${{ github.run_id }}` with:
- ✅ or ❌ for each test
- Overall status: PASS or FAIL
- Run URL: `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`
- Timestamp
