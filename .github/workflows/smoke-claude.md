---
description: Smoke test workflow that validates Claude engine execution in this repository
on:
  workflow_dispatch:
  schedule:
    - cron: "37 9 * * *"
permissions:
  contents: read
  issues: write
  actions: read
name: Smoke Claude
engine:
  id: claude
  max-turns: 20
  bare: true
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
    close-older-key: "smoke-claude-threat-detection"
    labels: [automation, testing]
timeout-minutes: 15
---

# Smoke Test: Claude Engine Validation

Keep outputs concise.

## Test Requirements

1. Use GitHub tools to read the latest 2 pull requests in `${{ github.repository }}` and record their numbers and titles only.
2. Use `web-fetch` to fetch `https://github.com/github/gh-aw-threat-detection` and verify the response mentions `gh-aw-threat-detection`.
3. Use bash to run `make test` in `${{ github.workspace }}` and verify it succeeds.
4. Use bash to create a minimal artifacts directory under `/tmp/gh-aw/smoke-claude-${{ github.run_id }}` with:
   - `aw-prompts/prompt.txt`
   - `agent_output.json`
5. Use bash to run `./bin/threat-detect --version`; if the binary does not exist, run `make build` first.
6. Use bash to write a concise status file at `/tmp/gh-aw/agent/smoke-claude-${{ github.run_id }}.txt`.

## Output

Always create an issue titled `Smoke Test: Claude - ${{ github.run_id }}` with:
- ✅ or ❌ for each test
- Overall status: PASS or FAIL
- Run URL: `${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}`
- Timestamp
