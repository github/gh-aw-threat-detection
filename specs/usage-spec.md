# GitHub Agentic Workflows Threat Detection Usage Specification

**Version**: 1.0.0
**Status**: Draft
**Latest Version**: https://github.com/github/gh-aw-threat-detection/blob/main/specs/usage-spec.md

---

## 1. Introduction

This specification defines the usage contract for the `threat-detect` CLI — the
threat detection component of GitHub Agentic Workflows. It covers binary
distribution, invocation, artifact input, result output, subcommands, and
integration patterns. Implementors of orchestrators (such as `gh-aw`) and
operators running the detector directly SHOULD use this document as the
authoritative reference for integration.

For detection *behavior* (threat categories, engine configuration, custom
prompts), see the companion
[Threat Detection Specification](threat-detection-spec.md).

### 1.1 Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

### 1.2 Scope

This specification covers:
- Binary distribution and installation
- CLI invocation and flags
- Artifacts directory input contract
- Structured result output contract
- Exit codes and status reporting
- The `report-result` subcommand (in-session verdict recording)
- The `conclude` subcommand (host-side job-output evaluation)
- Integration patterns for orchestrators

This specification does NOT cover:
- Threat detection categories or detection methods (see [threat-detection-spec.md](threat-detection-spec.md))
- AI engine internals or prompt design
- Workflow authoring syntax (`gh-aw` Markdown frontmatter)

---

## 2. Binary Distribution

**US-01**: The detector MUST be published as a platform-specific release asset
(`threat-detect-linux-amd64`) attached to a GitHub Release in the source
repository.

**US-02**: Each release MUST include a `checksums.txt` file containing the
SHA-256 hash of every published binary asset.

**US-03**: Releases MUST use semantic version tags (e.g. `v1.2.3`). Breaking
changes to any contract defined in this specification MUST increment the major
version.

**US-04**: A new release MUST be published as a **prerelease**. Promotion to
the **Latest** (stable) release MUST require explicit manual action and MUST
verify the asset SHA-256 against the value recorded at publish time.

**US-05**: Consumers SHOULD install the binary by downloading the release asset
and verifying its checksum:

```bash
gh release download <tag> \
  --repo github/gh-aw-threat-detection \
  --pattern threat-detect-linux-amd64 \
  --pattern checksums.txt
sha256sum --check --ignore-missing checksums.txt
install -m 0755 threat-detect-linux-amd64 ./threat-detect
```

Omitting `<tag>` downloads the latest stable (promoted) release.

**US-06**: The binary MUST NOT bundle AI engine CLIs. Engine CLIs (`copilot`,
`claude`, `codex`) MUST be available on `PATH` at runtime.

---

## 3. CLI Invocation

### 3.1 Synopsis

```
threat-detect [flags] <artifacts-dir>
threat-detect report-result [flags]
threat-detect conclude [flags]
```

**US-07**: The primary invocation form MUST accept exactly one positional
argument: the path to the artifacts directory. The detector MUST exit with
code 2 when no positional argument is provided.

**US-08**: The detector MUST print its version and exit with code 0 when
invoked with `--version`.

### 3.2 Flags

**US-09**: The detector MUST support the following flags:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--engine` | string | `copilot` | AI engine to use (`copilot`, `claude`, `codex`) |
| `--model` | string | *(none)* | Model override forwarded to the engine |
| `--prompt-template` | string | *(built-in)* | Path to a custom prompt template file |
| `--output` | string | *(stdout)* | Path to write the JSON result file |
| `--retries` | int | `1` | Maximum retries for malformed detection outputs |
| `--version` | bool | `false` | Print version and exit |

**US-10**: The `--retries` flag MUST also be configurable via the
`THREAT_DETECTION_RETRIES` environment variable. The flag value takes
precedence.

### 3.3 Environment Variables

**US-11**: The detector MUST read the following environment variables and
incorporate them into the detection prompt:

| Variable | Default | Purpose |
|----------|---------|---------|
| `WORKFLOW_NAME` | `"Unnamed Workflow"` | Name of the workflow being analyzed |
| `WORKFLOW_DESCRIPTION` | `"No description provided"` | Description of the workflow |
| `CUSTOM_PROMPT` | *(empty)* | Additional detection instructions appended to the prompt |

**US-12**: Engine authentication variables MUST be treated as runtime-only
configuration. They MUST NOT be required for building, testing, or running
`--version`:

| Variable | Engine |
|----------|--------|
| `COPILOT_GITHUB_TOKEN` | `copilot` |
| `ANTHROPIC_API_KEY` | `claude` |
| `OPENAI_API_KEY` | `codex` |

---

## 4. Artifacts Directory

### 4.1 Structure

**US-13**: The artifacts directory MUST conform to the following layout:

```
<artifacts-dir>/
├── aw-prompts/
│   ├── prompt.txt                # Runtime-expanded prompt (REQUIRED)
│   ├── prompt-template.txt       # Pre-expansion template (OPTIONAL)
│   └── prompt-import-tree.json   # Runtime-import provenance (OPTIONAL)
├── agent_output.json             # Agent structured output (REQUIRED)
├── aw_info.json                  # Activation metadata (OPTIONAL)
├── aw-*.patch                    # Git format-patch files (OPTIONAL)
├── aw-*.bundle                   # Git bundle files (OPTIONAL)
├── experiments/                  # Experiment assignment files (OPTIONAL)
└── comment-memory/               # Agent comment memory (OPTIONAL)
    └── *.md
```

**US-14**: The artifacts path MUST be an existing directory. The detector MUST
exit with code 2 if the path does not exist or is not a directory.

**US-15**: The detector MUST NOT require all artifact files to be present.
Missing optional files MUST be handled gracefully — their absence MUST NOT
cause an error.

**US-16**: When `prompt-template.txt` is present, the detector SHOULD use it
to distinguish trusted template content from untrusted runtime-expanded input
in its prompt analysis.

**US-17**: When `prompt-import-tree.json` is present, the detector SHOULD use
it to map runtime-import macros to their source files and content for
provenance tracking.

---

## 5. Result Output

### 5.1 JSON Contract

**US-18**: The detector MUST produce exactly this JSON structure on a
successful detection run:

```json
{
  "prompt_injection": false,
  "secret_leak": false,
  "malicious_patch": false,
  "reasons": []
}
```

**US-19**: The result object MUST contain exactly four fields:

| Field | Type | Description |
|-------|------|-------------|
| `prompt_injection` | boolean | Whether prompt injection was detected |
| `secret_leak` | boolean | Whether secret leaks were detected |
| `malicious_patch` | boolean | Whether malicious patches were detected |
| `reasons` | string array | Human-readable explanations for detected threats |

**US-20**: Results with unexpected fields, missing required fields, or
incorrect types MUST be rejected as invalid.

**US-21**: When any threat field is `true`, the `reasons` array MUST contain
at least one entry explaining the finding.

### 5.2 Output Destination

**US-22**: When `--output` is not specified, the result JSON MUST be written
to stdout.

**US-23**: When `--output <path>` is specified, the result JSON MUST be
written to the given file path with permissions `0600`. No output MUST be
written to stdout in this case.

---

## 6. Exit Codes

**US-24**: The detector MUST use the following exit codes:

| Code | Meaning |
|------|---------|
| 0 | Safe — no threats detected |
| 1 | Threat detected (at least one threat field is `true`) |
| 2 | Infrastructure or configuration error |

**US-25**: The exit code is an out-of-band signal for direct callers. In the
integrated detection job, the verdict is conveyed via the structured result
file and the `conclude` subcommand, not by the detector exit code.

---

## 7. Status Reporting

**US-26**: The detector MUST emit exactly one machine-readable status line to
stderr at the end of every detection run:

```
THREAT_DETECTION_STATUS: reason=<reason> exit=<code>
```

**US-27**: The `reason` field MUST be one of:

| Reason | Exit Code | Meaning |
|--------|-----------|---------|
| `result_recorded` | 0 or 1 | Verdict obtained successfully |
| `config_error` | 2 | Setup or validation failed before the engine ran |
| `engine_error` | 2 | Engine subprocess failed without recording a verdict |
| `invalid_report_exhausted` | 2 | Engine ran but never recorded a valid verdict across all retries |
| `cancelled` | 2 | Run was interrupted before a verdict |
| `output_write_error` | 2 | Verdict obtained but writing the result failed |

**US-28**: Informational modes that exit before running detection (`--help`,
`--version`) MUST NOT emit a status line. Callers MUST NOT treat the absence
of a status line in these modes as a malfunction.

**US-29**: Integration wrappers MUST NOT be stricter than `gh-aw`'s native
engine step: a recorded verdict (`result_recorded`, exit 0 or 1) and an
`invalid_report_exhausted` outcome MUST NOT mark the detection step as failed.
Only genuine failures (`engine_error`, `config_error`, `cancelled`) MAY
surface as a step failure.

---

## 8. In-Session Result Reporting (`report-result`)

### 8.1 Overview

The `report-result` subcommand is the in-session verdict recording mechanism.
The detector provisions a `threat_detection_result` wrapper on the engine's
`PATH` that delegates to this subcommand. The engine model invokes the wrapper
to report its verdict; the detector reads the verdict exclusively from the
resulting sink file.

### 8.2 Synopsis

```
threat-detect report-result [flags]
```

### 8.3 Flags

**US-30**: The `report-result` subcommand MUST require all three boolean flags
to be explicitly provided:

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--prompt-injection` | bool | Yes | Whether prompt injection was detected |
| `--secret-leak` | bool | Yes | Whether secret leaks were detected |
| `--malicious-patch` | bool | Yes | Whether malicious patches were detected |
| `--reason` | string | Repeatable | Reason for a detected threat (one per flag) |
| `--result-file` | string | Env default | Path to result sink file |

**US-31**: The `--result-file` flag MUST default to the value of the
`THREAT_DETECTION_RESULT_FILE` environment variable. The subcommand MUST
exit with code 3 if no result file path is available.

### 8.4 Exit Codes

**US-32**: The `report-result` subcommand MUST use the following exit codes:

| Code | Meaning |
|------|---------|
| 0 | Result successfully recorded (or already recorded) |
| 2 | Invalid or missing required flags, or logic violation |
| 3 | Configuration error (`THREAT_DETECTION_RESULT_FILE` unset) |

### 8.5 Validation

**US-33**: If any threat flag is `true`, at least one `--reason` MUST be
provided. The subcommand MUST exit with code 2 if this constraint is violated.

**US-34**: The subcommand MUST reject results with extra fields, missing
required fields, or incorrect types, exiting with code 2.

### 8.6 Idempotency

**US-35**: Result recording MUST be idempotent. If a valid result has already
been written to the sink file, subsequent invocations MUST exit with code 0
without overwriting the existing result.

### 8.7 Atomic Writes

**US-36**: The result file MUST be written atomically (temporary file then
rename) with permissions `0600` to prevent partial reads.

### 8.8 Console Messages

**US-37**: On successful recording, the subcommand MUST print to stdout:

```
THREAT_DETECTION_RESULT_RECORDED: analysis complete; stop now and produce no further output.
```

**US-38**: On validation or write errors, the subcommand MUST print to both
stdout and stderr:

```
THREAT_DETECTION_RESULT_ERROR: <reason>. Re-run threat_detection_result with corrected values.
```

### 8.9 Tool Provisioning

**US-39**: Before each engine invocation, the detector MUST provision a
`threat_detection_result` executable on the engine's `PATH` and set
`THREAT_DETECTION_RESULT_FILE` to a private sink file path.

**US-40**: The provisioned wrapper MUST delegate to the detector binary's
`report-result` subcommand, forwarding all arguments.

**US-41**: The detector MUST monitor the sink file and cancel the engine
subprocess as soon as a valid result is written (early termination).

---

## 9. Host-Side Conclusion (`conclude`)

### 9.1 Overview

In `gh-aw`-compiled workflows, the detector runs inside the AWF sandbox where
stdout cannot reach the host. The `conclude` subcommand runs on the host to
read the structured result file from a shared mount and emit the job-output
contract consumed by the parent orchestrator.

### 9.2 Synopsis

```
threat-detect conclude [flags]
```

### 9.3 Flags

**US-42**: The `conclude` subcommand MUST support the following flag:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--result-file` | string | `/tmp/gh-aw/threat-detection/detection_result.json` | Path to the verdict file |

### 9.4 Environment Variables

**US-43**: The `conclude` subcommand MUST read the following environment
variables:

| Variable | Purpose |
|----------|---------|
| `RUN_DETECTION` | When not `"true"`, the verdict is `skipped`/`success` |
| `GH_AW_DETECTION_CONTINUE_ON_ERROR` | Anything other than `"false"` enables warn mode |
| `DETECTION_AGENTIC_EXECUTION_OUTCOME` | `"failure"` marks execution as failed |
| `GITHUB_OUTPUT` | Path to append step outputs |
| `GITHUB_ENV` | Path to append exported environment variables |

### 9.5 Exit Codes

**US-44**: The `conclude` subcommand MUST use the following exit codes:

| Code | Meaning |
|------|---------|
| 0 | Proceed — safe, skipped, or warn-only |
| 1 | Fail closed — blocks downstream safe outputs |

### 9.6 Step Outputs

**US-45**: The `conclude` subcommand MUST write the following to
`GITHUB_OUTPUT`:

| Output | Values | Description |
|--------|--------|-------------|
| `conclusion` | `success`, `skipped`, `warning`, `failure` | Final determination |
| `success` | `true`, `false` | Whether the job may proceed |
| `reason` | string or empty | Failure reason key |

### 9.7 Exported Environment Variables

**US-46**: The `conclude` subcommand MUST write the following to
`GITHUB_ENV`:

| Variable | Description |
|----------|-------------|
| `GH_AW_DETECTION_CONCLUSION` | Mirrors the `conclusion` step output |
| `GH_AW_DETECTION_REASON` | Mirrors the `reason` step output |

### 9.8 Failure Semantics

**US-47**: When `RUN_DETECTION` is not `"true"`, the subcommand MUST set
`conclusion=skipped`, `success=true`, and exit with code 0.

**US-48**: A missing result file MUST be reported as `agent_failure`.

**US-49**: A malformed result file MUST be reported as `parse_error`.

**US-50**: A result with any threat field set to `true` MUST be reported as
`threat_detected`.

**US-51**: In warn mode (`GH_AW_DETECTION_CONTINUE_ON_ERROR` is not
`"false"`), non-mandatory failures MUST surface as warnings
(`conclusion=warning`) and exit with code 0, unless the failure is mandatory.

**US-52**: `agent_failure` and `parse_error` MUST hard-fail (exit 1) when
`DETECTION_AGENTIC_EXECUTION_OUTCOME` is `"failure"`, regardless of warn mode.

---

## 10. Self-Correction Retry

**US-53**: If the engine completes without recording a verdict to the sink, the
detector MUST build a self-correction prompt and retry. The number of retries
is bounded by `--retries` (default 1, so two total attempts).

**US-54**: The self-correction prompt MUST instruct the model to invoke the
`threat_detection_result` tool with the required flags.

**US-55**: If all retries are exhausted without a valid verdict, the detector
MUST exit with code 2 and status reason `invalid_report_exhausted`.

---

## 11. Integration Patterns

### 11.1 Direct Invocation

**US-56**: For direct invocation outside of `gh-aw`, the caller MUST:

1. Prepare an artifacts directory conforming to §4.
2. Ensure the selected engine CLI is on `PATH` with valid credentials.
3. Invoke `threat-detect [flags] <artifacts-dir>`.
4. Read the result from stdout (or the `--output` file).
5. Interpret the exit code per §6.

### 11.2 Orchestrated Invocation (gh-aw)

**US-57**: For orchestrated invocation inside `gh-aw`-compiled workflows, the
integration MUST:

1. Download and verify the pinned release-asset binary (§2).
2. Invoke the detector with `--output <shared-mount-path>` so the result
   crosses the AWF sandbox boundary as a file.
3. Run `threat-detect conclude --result-file <shared-mount-path>` on the host
   to evaluate the verdict and set job outputs.
4. Use the `conclusion` and `success` step outputs to gate downstream
   `safe-outputs` jobs.

**US-58**: The orchestrator MUST pin a specific detector version and MUST NOT
rely on the `latest` release tag for production detection.

### 11.3 Replay

**US-59**: The detector MAY be invoked in replay mode against artifacts from a
prior workflow run. Replay uses the same CLI contract; the caller is
responsible for downloading and normalizing artifacts into the expected
directory structure (§4).

---

## 12. Security Considerations

**US-60**: The result sink file MUST be written with restricted permissions
(`0600`) and MUST NOT be accessible to the agent being analyzed.

**US-61**: The `threat_detection_result` wrapper MUST be provisioned in a
temporary directory private to the detector process.

**US-62**: The detector MUST NOT parse the engine transcript for the verdict.
The out-of-band result sink is the sole source of the verdict.

**US-63**: The `conclude` subcommand reads the verdict from a file, not from
log scraping. If the file is absent, the step MUST fail loudly with
`agent_failure`.
