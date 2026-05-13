# GitHub Agentic Workflows Threat Detection Specification

**Version**: 1.0.0  
**Status**: Draft  
**Latest Version**: https://github.com/github/gh-aw-threat-detection/blob/main/specs/threat-detection-spec.md

---

## 1. Introduction

This specification defines the requirements for the threat detection component of GitHub Agentic Workflows. The threat detection layer analyzes AI agent output for security threats before safe output jobs execute.

### 1.1 Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

### 1.2 Scope

This specification covers:
- Threat detection analysis categories
- Input/output contract for the detection container
- AI engine integration requirements
- Configuration interface
- Version compatibility

---

## 2. Threat Detection Requirements

**TD-01**: A conforming implementation MUST provide automated threat detection.

**TD-02**: Threat detection MUST be automatically enabled when `safe-outputs` is configured.

**TD-03**: The implementation MUST support disabling threat detection via `threat-detection: false`.

---

## 3. Detection Categories

**TD-04**: The implementation MUST detect the following threat categories:

1. **Prompt Injection**: Malicious instructions manipulating AI behavior
2. **Secret Leaks**: Exposed API keys, tokens, passwords, credentials
3. **Malicious Patches**: Code changes introducing vulnerabilities or backdoors

**TD-05**: The implementation MAY support additional threat categories as extensions.

---

## 4. Detection Methods

**TD-06**: The implementation MUST support AI-powered threat detection using configured AI engines.

**TD-06a**: The implementation SHOULD run threat detection in two phases by default:

1. a fast, non-agentic structured-output triage call through `api-proxy` `/reflect`; and
2. the full reasoning-heavy detector when triage is suspicious or inconclusive.

Phase 1 MUST use no tools and MUST provide inline artifact content or bounded
summaries. Phase 1 MAY conclude safe only when a schema-valid result has
`prompt_injection`, `secret_leak`, and `malicious_patch` all set to `false`.
Any detected threat, uncertainty, proxy failure, unsupported model, missing
capability metadata, malformed response, or retry exhaustion MUST fail safe into
Phase 2.

**TD-07**: The implementation SHOULD support custom detection steps for specialized scanning:

```yaml
threat-detection:
  enabled: true
  steps:
    - name: Run TruffleHog
      uses: trufflesecurity/trufflehog@main
```

**TD-07a**: GitHub MCP security scanning SHOULD be an optional
orchestrator-owned pre-validation phase, not a requirement inside the detector
container. Implementations SHOULD run GitHub MCP secret scanning before
AI-backed detection when Secret Protection is enabled and SHOULD fail closed on
confirmed secret findings unless the workflow explicitly configures warn-only
behavior. Implementations MAY run GitHub MCP dependency scanning as an opt-in or
warn-only check while the tool remains in public preview, with a repository
option to make findings blocking.

MCP scanner outputs SHOULD be normalized into optional artifacts under
`mcp-security/` and summarized for the detector prompt. Missing MCP server
support, disabled repository features, or unavailable toolsets SHOULD NOT block
the existing detector unless the scanner is explicitly configured as required.

---

## 5. Detection Output

**TD-08**: Threat detection MUST produce structured JSON output:

```json
{
  "prompt_injection": false,
  "secret_leak": false,
  "malicious_patch": false,
  "reasons": []
}
```

**TD-09**: If any threat is detected (`true`), the workflow MUST fail and safe outputs MUST NOT execute.

**TD-10**: The `reasons` array SHOULD contain human-readable explanations for detected threats.

**TD-10a**: Structured model output MUST use the same JSON object shape as
TD-08 with required boolean `prompt_injection`, `secret_leak`, and
`malicious_patch` fields and a required string-array `reasons` field. Structured
output SHOULD be requested with strict JSON Schema when the selected model
advertises support. Provider-native schema mechanisms such as Gemini
`response_schema` or Anthropic forced tool calls MAY be used when `/reflect`
capability metadata confirms support.

---

## 6. Custom Prompts

**TD-11**: The implementation MUST support custom detection prompts:

```yaml
threat-detection:
  prompt: "Focus on SQL injection vulnerabilities"
```

**TD-12**: Custom prompts MUST be appended to default detection instructions, not replace them.

---

## 7. Engine Configuration

**TD-13**: The implementation MUST support overriding the AI engine for threat detection:

```yaml
threat-detection:
  engine: "copilot"
```

**TD-14**: The implementation MUST support full engine configuration objects:

```yaml
threat-detection:
  engine:
    id: copilot
    model: gpt-4
    max-turns: 5
```

**TD-15**: The implementation MUST support disabling AI-powered detection:

```yaml
threat-detection:
  engine: false
  steps:
    - name: Static Analysis
      run: ./scan.sh
```

**TD-15a**: Implementations that use `/reflect` MUST discover available models
and select dynamically based on advertised capabilities. They SHOULD prefer
strict JSON Schema support, then provider-native schema/tool-call support, then
JSON-mode-only support. Models without confirmed structured-output capability
MUST NOT allow Phase 1 to conclude safe.

---

## 8. Container Interface

### 8.1 Input Contract

**TD-16**: The container MUST accept an artifacts directory as its primary input argument.

**TD-17**: The artifacts directory MUST support the following structure:

```
<artifacts-dir>/
├── aw-prompts/
│   └── prompt.txt          # Workflow prompt file
├── agent_output.json       # Agent structured output
├── aw-*.patch              # Git format-patch files (optional)
├── aw-*.bundle             # Git bundle files (optional)
├── mcp-security/           # GitHub MCP scanner results (optional)
│   ├── secret-scanning.json
│   └── dependency-scanning.json
└── comment-memory/         # Agent comment memory (optional)
    └── *.md
```

**TD-18**: The container MUST NOT require all artifact files to be present. Missing optional files MUST be handled gracefully.

### 8.2 Output Contract

**TD-19**: The container MUST output the structured JSON result (per TD-08) to stdout.

**TD-20**: The container MUST support writing the result to a file via the `--output` flag.

### 8.3 Exit Codes

**TD-21**: The container MUST use the following exit codes:

| Code | Meaning |
|------|---------|
| 0 | Safe — no threats detected |
| 1 | Threat detected |
| 2 | Infrastructure/configuration error |

### 8.4 Environment Variables

**TD-22**: The container MUST support the following environment variables:

| Variable | Purpose |
|----------|---------|
| `WORKFLOW_NAME` | Name of the workflow being analyzed |
| `WORKFLOW_DESCRIPTION` | Description of the workflow |
| `CUSTOM_PROMPT` | Additional detection instructions |

**TD-23**: AI engine authentication variables MUST be treated as runtime-only configuration. They MUST NOT be required for parser, prompt building, unit test, or container smoke test execution.

The implementation MAY pass through engine-specific authentication variables required by the selected CLI, including:

| Variable | Engine |
|----------|--------|
| `COPILOT_GITHUB_TOKEN` | Copilot |
| `ANTHROPIC_API_KEY` | Claude |
| `OPENAI_API_KEY` | Codex |

---

## 9. Version Compatibility

**TD-24**: The container image MUST be tagged with semantic version numbers.

**TD-25**: The parent orchestrator (`gh-aw`) MUST pin to a specific container version.

**TD-26**: Breaking changes to the input/output contract MUST increment the major version.

**TD-27**: Private repository status MUST NOT block container publication or consumption. When the source repository or GHCR package is private, the package MUST be configured so approved consuming repositories can pull pinned image tags with `packages: read`.

**TD-28**: The repository MUST publish a machine-readable threat detection lifecycle registry that identifies each governed version as `active`, `deprecated`, `obsolete`, or `yanked`.

**TD-29**: Promoted versions are `active` by default unless the lifecycle registry explicitly marks them otherwise.

**TD-30**: Deprecated versions MUST be allowed to run, but the parent orchestrator or generated workflow MUST emit warning annotations and job summary text with the reason, replacement guidance, relevant dates, advisory URL, urgency, and remediation steps.

**TD-31**: Obsolete versions MUST NOT run. The parent orchestrator or generated workflow MUST fail closed before pulling or invoking the detector container and MUST print actionable upgrade guidance.

**TD-32**: A `yanked` release indicates unsafe security or correctness behavior and MUST include a severity, reason, yank date, replacement guidance, and the affected image digest. Selected yanked versions or digests MUST fail closed before detector execution.

**TD-33**: Explicitly pinned yanked versions or digests MUST NOT silently fall back to another version. The failure message SHOULD explain that the selected detector was yanked and name the safe replacement when one exists.

**TD-34**: Floating `latest` selection MUST NOT resolve to a yanked version. Maintainers MAY retag `latest` to the newest unyanked stable replacement because `latest` is already a floating selector.

**TD-35**: Lifecycle enforcement SHOULD happen before invoking the detector container and MUST NOT require detector container runtime network access. Implementations MUST NOT rely only on checks inside previously released detector binaries.

---

## 10. Security Considerations

**TD-36**: The detection container SHOULD run with no network access (fully blocked egress).

**TD-37**: The detection container MUST NOT have access to repository secrets beyond what is required for AI engine authentication.

**TD-38**: Detection results MUST NOT be modifiable by the agent being analyzed.
