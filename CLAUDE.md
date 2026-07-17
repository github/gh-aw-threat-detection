# CLAUDE.md

This file provides guidance to Claude Code (and other coding agents) when working in this repository.

## Project Overview

`gh-aw-threat-detection` is the **threat detection component** for [GitHub Agentic Workflows (`gh-aw`)](https://github.com/github/gh-aw). It is a **Go CLI** (`threat-detect`) that analyzes artifacts produced by AI agents — prompts, agent output, git patches, comment memory — and decides whether to allow or block the downstream `safe-outputs` job.

The component runs in two main contexts:

1. **As a host CLI** (`./bin/threat-detect <artifacts-dir>`) inside a `gh-aw`-generated detection job.
2. **As a published release-asset binary** (`threat-detect-linux-amd64` / `threat-detect-linux-arm64`, downloaded via `gh release download` from [`github/gh-aw-threat-detection` releases](https://github.com/github/gh-aw-threat-detection/releases)) installed on the runner and executed under the AWF firewall (see [AWF section below](#agentic-workflow-firewall-awf)).

It detects three categories: **prompt injection**, **secret leak**, and **malicious patch**, and emits a strict JSON contract.

### Key facts

- **Language**: Go 1.26+ (module `github.com/github/gh-aw-threat-detection`)
- **Binary**: `bin/threat-detect` (built via `make build`)
- **Distribution**: published as GitHub Release assets (`threat-detect-linux-amd64`, `threat-detect-linux-arm64` + `checksums.txt`); no container image
- **Spec**: [`specs/threat-detection-spec.md`](specs/threat-detection-spec.md) — W3C-style normative spec; the source of truth for behavior
- **Engines supported**: `copilot` (default), `claude`, `codex` — invoked from `PATH`, not bundled into the binary
- **Detection**: a single agentic CLI engine pass; the engine reports its verdict in-session via the `threat_detection_result` tool (out-of-band result sink), which is the sole source of the verdict

## Repository Layout

```
cmd/threat-detect/        CLI entry point and flag parsing (main.go)
pkg/artifacts/            Artifact directory loading and validation
pkg/detector/             Core detection logic
  ├── detector.go         BuildPrompt and prompt template handling (//go:embed prompts/)
  ├── result.go           Result struct + JSON Schema + structured sink parser/writer
  ├── static.go           PromptAnalysis: trusted-template vs untrusted-input breakdown
  ├── correction.go       Self-correction retry prompt builders

  └── prompts/            Embedded markdown prompts (threat_detection.md)
pkg/engine/               AI engine abstraction
  ├── engine.go           copilot/claude/codex CLI adapters; Copilot uses runCLIWithPromptFile, Claude uses runCLI with stdin, Codex passes prompts via codexArgs/runCLIEnv
  └── tool.go             threat_detection_result wrapper provisioning + result-sink watcher
pkg/runlog/               Structured JSONL run-log writer (--log-file); nil-safe no-op logger
specs/                    Normative spec (threat-detection-spec.md)
scripts/                  create-threat-detection-sibling-workflows.py (regenerates *-container.lock.yml)
skills/                   Repo-relevant agent skills (console-rendering, error-messages)
scratchpad/               Retained design references inherited from gh-aw
.github/workflows/        CI, release, promote, replay-detection, smoke-{copilot,claude,codex}[-container]
.devcontainer/            Codespaces / devcontainer setup (Go, gh, Copilot CLI, optional Vertex)
Makefile                  All build/test/lint/release targets
```

## Daily Workflow Commands

Run these from the repo root. They are the canonical entry points — prefer them over ad-hoc `go` invocations.

```bash
make deps            # go mod download + tidy
make deps-dev        # + install gosec, govulncheck, golangci-lint v2.8.0
make build           # builds bin/threat-detect with version ldflag
make test            # go test -v -race ./...
make test-coverage   # writes coverage.out + coverage.html
make lint            # go vet ./...
make golint          # golangci-lint (requires deps-dev)
make fmt             # go fmt ./...
make fmt-check       # CI-style gofmt check
make security-scan   # gosec + govulncheck
make smoke           # build + run bin/threat-detect --version
make sbom            # SPDX + CycloneDX SBOMs (requires syft)
make agent-finish    # full maintainer validation: deps-dev, fmt, lint, build, test, security-scan
```

**Always run `make agent-finish` (or at minimum `make fmt lint build test`) before declaring a code change complete.**

## CLI Contract

```
threat-detect [flags] <artifacts-dir>
```

**Important flags** (see [README.md](README.md#cli) for the full list):

- `--engine {copilot|claude|codex}` (default `copilot`)
- `--model <name>` — model override forwarded to the engine
- `--prompt-template <path>` — override the embedded default
- `--output <path>` — write JSON result (defaults to stdout)
- `--log-file <path>` — write structured JSONL run logs; env: `THREAT_DETECTION_LOG_FILE`
- `--retries` (default `1`) — retries for malformed detection outputs; env: `THREAT_DETECTION_RETRIES`

**Exit codes** (defined in `cmd/threat-detect/main.go`):

| Code | Meaning |
|------|---------|
| 0    | Safe (no threats detected) |
| 1    | Threat detected |
| 2    | Infrastructure / configuration error |

**Result contract** (from `pkg/detector/result.go`):

```json
{ "prompt_injection": false, "secret_leak": false, "malicious_patch": false, "reasons": [] }
```

The detector reads the verdict exclusively from the out-of-band result sink. The engine reports its verdict in-session by invoking the `threat_detection_result` tool, which writes the JSON object (`prompt_injection`, `secret_leak`, `malicious_patch`, `reasons`) to the sink (`detector.ReadResultFile` / `detector.ParseStructuredResult`).

**Artifacts directory shape** (validated by `pkg/artifacts/artifacts.go`):

```
<artifacts-dir>/
├── aw-prompts/
│   ├── prompt.txt                # required
│   ├── prompt-template.txt       # optional, pre-expansion
│   └── prompt-import-tree.json   # optional, runtime-import provenance
├── agent_output.json             # required
├── aw_info.json                  # optional, activation metadata
├── aw-*.patch                    # optional, git format-patch
├── aw-*.bundle                   # optional, git bundles
├── experiments/                  # optional
└── comment-memory/*.md           # optional
```

## Detection Flow

- `pkg/detector/detector.go` (`BuildPrompt`) renders `prompts/threat_detection.md` with placeholders substituted from artifacts and `BuildPromptAnalysis` (untrusted-input breakdown).
- The engine CLI is invoked from `PATH` via `pkg/engine/engine.go` (`copilot`, `claude`, and `codex` use engine-specific prompt-passing paths; `runCLIWithPromptFile` is used by Copilot).
- The engine reports its verdict in-session by calling the `threat_detection_result` tool, which writes JSON to an out-of-band result sink (`pkg/engine/tool.go`); the sink is the sole source of the verdict, and the subprocess is cancelled as soon as a valid result is written.
- If no sink result is written, a one-shot self-correction prompt is built (`pkg/detector/correction.go`) and retried (`--retries`, default 1); retry exhaustion is an infrastructure error. The engine transcript is never parsed for the result.

## Release & Promotion Model

Three workflows orchestrate releases:

1. `.github/workflows/create-release-tag.yml` — manual; pushes `vX.Y.Z`.
2. `.github/workflows/release.yml` — triggered by tag push; gated by `release-publish` environment; builds + publishes the `threat-detect-linux-amd64` and `threat-detect-linux-arm64` binaries as GitHub Release assets in a **prerelease**, recording each asset's sha256 in the release notes.
3. `.github/workflows/promote-release.yml` — manual; gated by `release-promote`; re-downloads each per-arch asset, verifies its sha256 against the recorded value, and marks the GitHub release **Latest** (stable).

The `latest` (non-prerelease) GitHub release and "Latest" badge **only move on explicit promotion** — never automatically.

## Smoke Workflows (and Container Siblings)

This repo runs daily AW smoke tests against all three engines:

- `.github/workflows/smoke-{copilot,claude,codex}.md` — AW source files
- `.github/workflows/smoke-{copilot,claude,codex}.lock.yml` — compiled by `gh aw compile`
- `.github/workflows/smoke-{copilot,claude,codex}-container.{md,lock.yml}` — sibling workflows that download the released `threat-detect` binary via `gh release download` and run it under AWF

**To regenerate the container siblings** after recompiling smokes:

```bash
scripts/create-threat-detection-sibling-workflows.py
scripts/create-threat-detection-sibling-workflows.py --check
```

The top-level `smoke.yml` workflow can be dispatched to start all six smokes at once.

Required Actions secrets/variables for smokes are documented in [README.md → Development → AW Smoke Workflows](README.md#aw-smoke-workflows).

## Replay Workflow

`.github/workflows/replay-detection.yml` — manual dispatch to rerun detection against artifacts from a prior `gh-aw` run. Supports two detector sources (`current`, `release`), engine and model overrides, custom prompt injection, and AWF mode (`use_awf=true`). Uploads a sanitized `replay-detection-<run_id>` artifact with manifest, inventory, logs, replay result, and comparison to the original result. Uses the dispatching repo's `GITHUB_TOKEN` — no extra replay token needed. `run_attempt` is only safe for the latest attempt of a run.

## Coding Guidance

When changing this repo:

- **Spec first**: behavior changes must align with [`specs/threat-detection-spec.md`](specs/threat-detection-spec.md). Update the spec when the contract changes.
- **Preserve the JSON result contract**: `prompt_injection`, `secret_leak`, `malicious_patch`, `reasons` — schema enforced by the parser in `pkg/detector/result.go`.
- **Don't bundle engine CLIs into the binary**. Engines (Copilot, Claude, Codex) are invoked from `PATH`. The runner provides the engine.
- **No new JS scripts**. Detection setup and result parsing are Go. Old gh-aw JS detection scripts are being retired.
- **Custom orchestrator steps** (`threat-detection.steps`) belong in the `gh-aw` job, not inside the detector.
- **Prefer small, local packages and targeted tests** (`pkg/<area>/<area>_test.go`).
- **Use the skills** in [`skills/`](skills/) when writing console output (`skills/console-rendering`) or validation errors (`skills/error-messages`).
- **Don't fix unrelated issues** in the same change.

Useful retained design references in [`scratchpad/`](scratchpad/): `code-organization.md`, `validation-architecture.md`, `go-type-patterns.md`, `styles-guide.md`, `errors.md`, `testing.md`, `safe-outputs-specification.md`, `safe-output-environment-variables.md`, `safe-output-messages.md`, `artifact-naming-compatibility.md`, `security_review.md`.

## Engine Authentication

Unit tests, `make build`, `make test`, and `make smoke` need **no secrets**. Real AI-backed detection needs:

| Variable | When |
|----------|------|
| `COPILOT_GITHUB_TOKEN` | `--engine copilot` — fine-grained PAT with **Copilot Requests: Read**; `GITHUB_TOKEN` is not sufficient |
| `ANTHROPIC_API_KEY`    | `--engine claude` |
| `OPENAI_API_KEY`       | `--engine codex` (or `CODEX_API_KEY` depending on CLI setup) |
| `WORKFLOW_NAME`, `WORKFLOW_DESCRIPTION`, `CUSTOM_PROMPT` | Optional — folded into the prompt |

## Debugging GitHub Actions Failures

When a CI workflow fails, **always** follow this order:

1. **Reproduce locally first** — run the same `make` target or script the workflow runs.
2. **Identify the root cause** — read logs, error messages, system state.
3. **Test the fix locally**.
4. **Then update the workflow**.

This avoids trial-and-error CI commits, which waste runner time and rarely fix the real cause.

For workflow-artifact triage there is a generic gh-aw helper (`scripts/download-latest-artifact.sh`) in sibling repos; this repo currently relies on `gh run download <run-id>` directly.

---

# Agentic Workflow Firewall (AWF)

> This section is reference material. AWF is a **separate project** ([`github/gh-aw-firewall`](https://github.com/github/gh-aw-firewall)) — it is **not** built or developed in this repo. It is documented here because the threat detection job runs **inside AWF** in `gh-aw`-compiled workflows, and the `*-container.lock.yml` smoke siblings exercise that path. When debugging detection-job network behavior, reach for these facts.

## Overview

`awf` (Agentic Workflow Firewall) is a Node.js CLI that wraps any command in a sandboxed Docker network. It provides L7 (HTTP/HTTPS) egress control using a Squid proxy, restricting network access to a whitelist of approved domains while giving the agent access to the host workspace and selected system paths via chroot and selective bind mounts.

## Three Container Components

The system is orchestrated by AWF's `src/cli.ts` and managed by `src/docker-manager.ts`. There are three containers — two always required, one optional:

**1. Squid Proxy (always required)** — `containers/squid/`, IP `172.30.0.10`
- Enforces domain ACL filtering for all HTTP/HTTPS traffic
- Config (`squid.conf`) is generated by `src/squid-config.ts` and injected via base64 env var `AWF_SQUID_CONFIG_B64` (not a file bind mount — avoids Docker-in-Docker issues)
- Agent container `depends_on` Squid's healthcheck before starting

**2. Agent (always required)** — `containers/agent/`, IP `172.30.0.20`
- Runs the user's command (e.g., `claude`, `copilot`, `threat-detect`, `curl`)
- An iptables-init init container (`awf-iptables-init`) shares the agent's network namespace and runs `setup-iptables.sh` to redirect all port 80/443 traffic via DNAT to Squid before the user command starts
- `entrypoint.sh` handles UID/GID mapping, DNS config, chroot to `/host`, and capability drop (`SYS_CHROOT`, `SYS_ADMIN` dropped before user code runs)
- **Selective bind mounts** (not a blanket host FS mount): system binaries (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt`, `/sys`, `/dev`) read-only; workspace and `/tmp` read-write; empty home volume with only whitelisted `$HOME` subdirs (`.cache`, `.config`, `.local`, `.anthropic`, `.claude`, `.cargo`, `.rustup`, `.npm`, `.copilot`); select `/etc` files (SSL certs, `passwd`, `group`, `nsswitch.conf`, `ld.so.cache`, `alternatives`, `hosts` — not `/etc/shadow`)
- Sensitive API keys are NOT present in the agent environment when `--enable-api-proxy` is active

**3. API Proxy Sidecar (optional)** — `containers/api-proxy/`, IP `172.30.0.30`
- Enabled via `--enable-api-proxy`
- Injects real API credentials (OpenAI, Anthropic, Copilot) that the agent never sees
- Agent calls the sidecar with no auth (e.g., `http://172.30.0.30:10001` for Anthropic); sidecar injects the real key and forwards via Squid
- Ports: 10000 (OpenAI), 10001 (Anthropic), 10002 (Copilot), 10003 (Gemini), 10004 (OpenCode) — discrete ports, not a contiguous range

## Container Image Strategy

AWF pulls pre-built images from GHCR by default:

- Default: `ghcr.io/github/gh-aw-firewall/{squid,agent,api-proxy}:latest`
- `--build-local` to build from source
- `--image-registry <registry>` and `--image-tag <tag>` for overrides

## Traffic Flow

```
awf <flags> -- <command>
    ↓
CLI generates squid.conf (base64) + docker-compose.yml + seccomp profile in /tmp/awf-<ts>/
    ↓
Docker Compose: Squid (healthcheck) → [API Proxy (optional)] → Agent
                                       → iptables-init runs setup-iptables.sh (writes /ready)
    ↓
User command executes in Agent container (chrooted to /host)
    ↓
HTTPS (proxy-aware tools)  → HTTPS_PROXY → Squid:3128 (CONNECT) → ACL → allowed or blocked
HTTPS (proxy-unaware)      → iptables DNAT → Squid:3128 → TLS handshake rejected
HTTP                       → iptables DNAT → Squid:3128 → ACL → allowed or 403
API calls (optional) → http://172.30.0.30:1000x → API Proxy injects key → Squid → upstream
    ↓
docker compose down -v + rm /tmp/awf-<ts>/
```

## Domain Whitelisting

- `--allow-domains` values are normalized (protocol/trailing slash removed)
- `github.com` matches `github.com` and `.github.com` (subdomains)
- `.github.com` matches all subdomains
- Squid denies anything not on the allowlist

## DNS Configuration

- `--dns-servers <comma-separated IPs>` (default `8.8.8.8,8.8.4.4`); IPv6 supported
- Docker's internal `127.0.0.11` is always allowed
- Host-level iptables block DNS to non-whitelisted servers; container reads `AWF_DNS_SERVERS`

## Proxy Environment Variables Set in the Agent

- `HTTP_PROXY` / `HTTPS_PROXY` — used by curl, wget, pip, npm, etc.
- `SQUID_PROXY_HOST` / `SQUID_PROXY_PORT` — raw values for tools that need them
- `JAVA_TOOL_OPTIONS` — JVM proxy system properties (Maven still needs `~/.m2/settings.xml`)
- `http_proxy` (lowercase) is **intentionally not set** — avoids httpoxy issues and keeps Squid 403 responses returning non-zero exit codes for security tests

## ARC / DinD Split Filesystem Support

- `--docker-host` — override Docker socket path (auto-detected from `DOCKER_HOST`)
- `--docker-host-path-prefix <prefix>` — prefix all bind-mount source paths so a separate Docker daemon can resolve runner filesystem paths (kernel VFS `/dev`, `/sys`, `/proc` and `/dev/null` are passed through unprefixed)
- `--enable-dind` — expose the Docker socket inside the agent container

## Logging (AWF)

- Squid logs (L7): `firewall_detailed` logformat — timestamp, client, host (SNI/Host), dest, method, status, decision (`TCP_TUNNEL` allowed / `TCP_DENIED` blocked), URL, UA. `200`=allowed, `403`=blocked. Logs are Unix timestamps.
- iptables LOG rules (L3/L4): `[FW_BLOCKED_UDP]` and `[FW_BLOCKED_OTHER]` prefixes with `--log-uid`. View via `dmesg`.
- `awf logs stats` and `awf logs summary` (formats: `pretty`, `markdown`, `json`) — pipe `awf logs summary >> $GITHUB_STEP_SUMMARY` in CI.

## Exit Codes & Cleanup

AWF propagates the agent container's exit code via `docker inspect`. Use `--keep-containers` to preserve `/tmp/awf-<ts>/` (squid.conf, docker-compose.yml, agent-logs/, squid-logs/) for debugging.
