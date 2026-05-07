# Agentic Contribution Plan

## Title

[Plan]: Two-phase structured-output threat detection via api-proxy reflect

## Contribution type

Feature request / Security hardening

## What do you want to contribute?

Revamp threat detection in `github/gh-aw-threat-detection` as a two-phase detector implemented in this repository's Go CLI/container, not in the older `github/gh-aw` workflow compiler or JavaScript setup scripts.

The updated design should replace the older AW-specific yes/no triage concept with structured-output triage that returns the existing threat detection result shape:

```json
{
  "prompt_injection": false,
  "secret_leak": false,
  "malicious_patch": false,
  "reasons": []
}
```

Phase 1 should be a fast, non-agentic structured-output LLM call through `api-proxy/reflect`. If Phase 1 returns a valid all-safe result, the CLI can conclude safe without running the existing full detector. If Phase 1 detects any threat, is uncertain, cannot use a schema-capable model, or returns unparseable output after retries, the CLI should fail safe into Phase 2. Phase 2 should preserve the current full threat analysis behavior, but should also prefer structured outputs when the selected model supports them.

## Agent analysis and findings

Repository-specific findings:

- This repository is already a standalone Go detector/container, not the older `gh-aw` inline workflow implementation.
- There is no `pkg/workflow/threat_detection.go`, `actions/setup/js/*`, or `actions/setup/md/*` here. Those parts of the older issue are AW-specific and should not be implemented in this repository.
- Relevant current files:
  - `cmd/threat-detect/main.go`: CLI entry point; loads artifacts, builds one prompt, invokes one engine, parses one result, and exits `0`, `1`, or `2`.
  - `pkg/detector/detector.go`: embeds and builds the default prompt.
  - `pkg/detector/prompts/threat_detection.md`: full reasoning prompt currently asking for `THREAT_DETECTION_RESULT:{...}`.
  - `pkg/detector/result.go`: defines the canonical `Result` shape and parser for `THREAT_DETECTION_RESULT:` text output.
  - `pkg/engine/engine.go`: current engine abstraction invokes CLIs (`copilot`, `claude`, `codex`) via stdin and has no direct API proxy support.
  - `pkg/artifacts/artifacts.go`: discovers prompt, agent output, patch, and bundle artifacts but mostly passes file paths into the full prompt.
  - `specs/threat-detection-spec.md`: defines the JSON result contract and exit-code behavior.
- `README.md` says older JavaScript setup/parsing scripts are not needed once `gh-aw` switches to the container contract, so the revamp belongs in the Go packages and CLI.
- The local `api-proxy/reflect` endpoint should be developed behind an injectable HTTP client/base URL and covered with `httptest` using the published `/reflect` schema, so tests do not depend on live proxy availability.

Structured-output model determination:

- The implementation should not hard-code only one provider. It should call `/reflect` to list available models and choose dynamically based on advertised capabilities.
- Models/providers that can generally support the desired structured JSON result:
  - OpenAI-compatible Responses/Chat models with JSON Schema structured outputs, such as GPT-4o 2024-08-06 or newer, GPT-4.1 family, GPT-5 family, and current o-series models when `/reflect` exposes `response_format: {"type": "json_schema"}` or equivalent.
  - Gemini models that expose `response_schema` plus `response_mime_type: "application/json"` through `/reflect`, such as Gemini 1.5+ / 2.x / 2.5+ families if present in the model list.
  - Anthropic Claude models can use schema-constrained tool calls (`tools[].input_schema` with forced tool choice) and, if `/reflect` exposes native structured-output support, should use that. Treat Anthropic as structured-output-capable only when `/reflect` capability metadata confirms either native JSON schema output or required schema tool-call support.
- Models without confirmed schema/JSON-mode capability should not be used for Phase 1 triage unless no structured-capable model is available. In that fallback case, the detector should retry parsing and then escalate to Phase 2 rather than concluding safe.

## Use case and expected behavior

As a workflow operator using safe outputs, I expect benign runs to complete threat detection quickly and cheaply while suspicious or ambiguous runs still receive the full reasoning-heavy analysis.

Expected behavior after implementation:

- `threat-detect` defaults to two-phase mode.
- Phase 1 sends inline artifact content or bounded summaries to `/reflect` with no tools and a strict JSON schema matching `pkg/detector.Result`.
- Phase 1 safe result (`prompt_injection=false`, `secret_leak=false`, `malicious_patch=false`) exits successfully without Phase 2.
- Phase 1 suspicious result, parse failure, proxy failure, unsupported model, missing capability metadata, or retry exhaustion escalates to Phase 2.
- Phase 2 preserves today's full prompt and CLI behavior but may use `/reflect` structured outputs when configured and supported.
- Existing output JSON and exit codes remain compatible with `specs/threat-detection-spec.md`.

## Complete step-by-step agentic plan

1. Read the current CLI, detector, engine, artifact, result, and spec files listed above.
2. Add a shared JSON Schema representation for `detector.Result` with required boolean fields and a `reasons` string array.
3. Add a triage prompt template in `pkg/detector/prompts/` that embeds bounded artifact content inline and asks for the existing result shape, not yes/no.
4. Add artifact content helpers that safely read text artifacts, summarize or truncate large agent output and patch files, and represent bundles by metadata unless a safe textual summary is available.
5. Extend detector orchestration so `cmd/threat-detect/main.go` can run Phase 1 structured triage, then Phase 2 full analysis only when Phase 1 does not conclusively return all-safe.
6. Introduce a new engine/proxy client for `api-proxy/reflect` with:
   - configurable base URL via flag and/or environment variable,
   - model discovery/capability parsing,
   - provider mode handling for chat, messages, and responses style payloads,
   - structured-output request building for OpenAI-compatible, Gemini-compatible, and Anthropic-compatible capabilities,
   - retry and correction handling for malformed outputs.
7. Update `pkg/engine.Engine` or add a parallel structured interface so engines can return parsed `detector.Result` directly when structured output is supported, while preserving existing CLI-based `Analyze(ctx, prompt)` behavior for compatibility.
8. Add model-selection logic:
   - prefer `/reflect` models advertising strict JSON Schema support,
   - then provider-native schema/tool-call support,
   - then JSON mode if available,
   - otherwise do not allow Phase 1 to conclude safe.
9. Implement Phase 1 fail-safe semantics:
   - safe only when a schema-valid result has all booleans false,
   - suspicious when any boolean is true,
   - escalate to Phase 2 on all errors, unsupported models, malformed responses, or uncertainty.
10. Implement Phase 2 retry/repair:
    - first prefer structured output when supported,
    - otherwise keep the current `THREAT_DETECTION_RESULT:` parser,
    - retry malformed results with a correction prompt,
    - return exit code `2` only after Phase 2 retries fail.
11. Add CLI flags and environment variables without breaking existing usage, for example:
    - `--triage` / `--no-triage` or `--triage=false`,
    - `--reflect-url`,
    - `--triage-model`,
    - `--triage-max-bytes`,
    - `--triage-retries`.
12. Update `specs/threat-detection-spec.md` with the two-phase behavior, structured-output preference, fail-safe escalation, and compatibility guarantees.
13. Update `README.md` usage and stage-status sections to describe `/reflect` direct LLM support and two-phase detection.
14. Add unit tests for prompt construction, schema validation, triage decisions, retry/fallback behavior, model capability selection, and `/reflect` request/response adapters.
15. Add integration-style tests using `httptest` to simulate `/reflect` model lists and provider response shapes for chat/messages/responses.
16. Run repository validation: `make test`, `make lint`, and optionally `make docker-smoke` if container behavior changes.

## Specific implementation details and examples

Suggested package/file changes:

- `pkg/detector/result.go`
  - Keep `Result` as the canonical output type.
  - Add strict validation helpers such as `ValidateResult(Result) error` and `IsSafe() bool` if useful.
  - Add JSON-schema generation or a checked-in schema constant for structured output.
- `pkg/detector/triage.go`
  - Build the Phase 1 prompt from artifact content.
  - Keep this prompt non-agentic: no tool instructions, no file paths requiring reads, no repository exploration.
- `pkg/detector/prompts/threat_detection_triage.md`
  - Ask for exactly the JSON object matching the result schema.
  - State that uncertainty must be represented by setting the relevant boolean to `true` with a short reason.
- `pkg/engine/reflect.go`
  - Add `/reflect` HTTP client, model discovery, request construction, response parsing, and provider adapters.
- `pkg/engine/capabilities.go`
  - Normalize model capabilities, including structured JSON schema, JSON mode, tool-call schema, provider, endpoint style (`responses`, `chat`, `messages`), and token limits.
- `cmd/threat-detect/main.go`
  - Add flags while preserving current defaults and exit codes.
- `specs/threat-detection-spec.md`
  - Add requirements for two-phase detection and structured-output fail-safe behavior.

Suggested structured-output schema:

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["prompt_injection", "secret_leak", "malicious_patch", "reasons"],
  "properties": {
    "prompt_injection": { "type": "boolean" },
    "secret_leak": { "type": "boolean" },
    "malicious_patch": { "type": "boolean" },
    "reasons": {
      "type": "array",
      "items": { "type": "string" }
    }
  }
}
```

Suggested test coverage:

- Phase 1 all-false result skips Phase 2 and exits safe.
- Phase 1 true `prompt_injection` escalates to Phase 2.
- Phase 1 malformed response retries and then escalates.
- Phase 1 model without structured-output capability cannot conclude safe.
- `/reflect` model discovery picks schema-capable OpenAI-compatible responses models over JSON-mode-only models.
- `/reflect` model discovery treats Anthropic models as schema-capable only with advertised native structured output or forced schema tool-call support.
- Gemini adapter sends `response_schema`/JSON MIME configuration when capability metadata indicates support.
- Existing `ParseResult` behavior remains backward-compatible for CLI engines.
- Output file and exit-code semantics stay unchanged.

## Suggested labels

- enhancement
- security hardening
- agentic-plan

## Contributor checklist

- [x] I read `CONTRIBUTING.md` and understand that non-core contributors should not open pull requests directly.
- [x] I included a detailed agentic plan for the core team to review and implement.
- [x] I included agent analysis and findings, or explained why they are not applicable.
- [x] I included expected behavior, implementation details, and validation ideas.
