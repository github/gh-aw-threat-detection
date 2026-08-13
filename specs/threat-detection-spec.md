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
- Input/output contract for the detection CLI
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

**TD-06a**: The implementation MUST run threat detection as a single agentic
engine pass using the configured CLI engine. The engine MUST be given the
artifact content and the `threat_detection_result` reporting tool, and MUST
report its verdict in-session by invoking that tool, which writes a schema-valid
result to an out-of-band result sink. The implementation MUST read the verdict
exclusively from that sink; it MUST NOT parse the engine transcript for the
result. When no sink result is produced, the attempt MAY be retried with a
bounded self-correction prompt; retry exhaustion MUST be treated as an
infrastructure error.

**TD-07**: The implementation SHOULD support custom detection steps for specialized scanning:

```yaml
threat-detection:
  enabled: true
  steps:
    - name: Run TruffleHog
      uses: trufflesecurity/trufflehog@main
```

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

**TD-10**: The `reasons` array SHOULD contain human-readable explanations for
detected threats.

**TD-10d**: The default prompt template MUST instruct the detection engine to
write reasons that let a reader of the job log locate and remediate the finding
without access to the artifacts. For each reported finding the reasons MUST be
instructed to identify the artifact and position, quote the triggering content
verbatim, state its provenance (or that it could not be attributed), and give a
remediation. For secret-leak findings the instructions MUST require the
credential value to be masked rather than reproduced, while still requiring
provenance sufficient to locate and rotate it.

**TD-10e**: Because reasons quote attacker-authored artifact content verbatim
(TD-10d) and the engine invokes the `threat_detection_result` tool through a
shell, the implementation MUST provide a transport that carries reason text from
the engine to the tool without passing it through a shell command line, and the
prompt MUST direct the engine to use that transport for any reason quoting
artifact content. The implementation MUST grant the engine the capability that
transport requires (for example, a file-writing tool) whenever it provisions the
reporting tool; an engine that cannot use the transport would be forced back
onto the shell. Malformed transport input MUST be reported to the engine as a
correctable error (TD-10a). Reasons supplied through this transport MUST be
subject to the same bounds as any other transport (TD-10b), and any transport
state left by a previous attempt MUST be discarded before a retry. Prompt-level
quoting guidance MUST NOT be the only protection against shell interpretation of
reason text.

**TD-10a**: The result reported through the `threat_detection_result` tool MUST
use the same JSON object shape as TD-08 with required boolean `prompt_injection`,
`secret_leak`, and `malicious_patch` fields and a required string-array `reasons`
field. The implementation MUST reject results that add unexpected fields, omit a
required field, or use the wrong type for any field.

**TD-10b**: The `reasons` array is model-authored free text and MUST be bounded.
The implementation MUST reject a result whose `reasons` array contains more than
20 entries, or whose individual entry is empty, consists solely of whitespace, or
exceeds 2000 characters. These bounds MUST be enforced identically when a result
is reported through the `threat_detection_result` tool and when a result file is
read back, so no result the implementation accepts on write can be rejected on
read. A rejected report MUST be reported to the model as a correctable error
(TD-10a) rather than recorded.

**TD-10c**: The implementation MUST bound the number of bytes it reads from a
result file before parsing it, and MUST reject a file that exceeds that bound as
a parse error rather than parsing a truncated prefix. The bound MUST be large
enough to admit every result permitted by TD-10a and TD-10b.

**TD-10d**: `reasons` is model-authored text derived from untrusted input, so it
MUST NOT be persisted in any file the host publishes. The implementation MUST
therefore split the verdict across two destinations:

- the **result** (the `--output` path, or standard output) carries the three
  booleans with `reasons` present but always **empty**; and
- the **full result** (the `--full-output` path) carries the identical verdict
  together with the reported `reasons`.

Both files MUST use the same JSON object shape as TD-08 and MUST satisfy TD-10a
through TD-10c, so the redacted result remains schema-valid and every existing
reader parses it unchanged. The implementation MUST NOT drop the `reasons` key
from the redacted result.

The full result MUST NOT be written to the same path as the result. When it
cannot be written, the implementation MUST report the failure as a diagnostic
and MUST NOT fail the detection run: it carries no verdict, so a read-only or
absent detection directory MUST NOT convert a completed detection into an
infrastructure error.

The detector MUST NOT echo `reasons` into any diagnostic it composes on standard
output or standard error, because hosts routinely capture both into files they
publish. The reasons reach a human through the full result, read by `conclude`
and rendered into the job log (TD-20e), which the host masks and expires with
its own log retention.

This requirement governs detector-authored diagnostics only. It does **not**
extend to the engine subprocess's own output, which TD-20a requires the detector
to forward. The model does not pass reasons on the command line — artifact-derived
reason text is written to the file named by `THREAT_DETECTION_REASONS_FILE` and
handed to `threat_detection_result` as `--reasons-file <path>` — but an engine
that renders its own tool activity (the file write that produces that file, or a
subsequent read of it) reproduces the reason text on the forwarded lines. TD-20a's
framing makes those lines identifiable and inert — they cannot forge a workflow
command or a `THREAT_DETECTION_*` marker — but framing does not remove the text.
Consequently a host that tees the detection run's standard error
into a file MUST treat that file as carrying model-authored text and MUST NOT
publish it (see U-09). Suppressing the text entirely would require withholding or
rewriting engine output, which conflicts with the real-time forwarding TD-20a
mandates; it is therefore out of scope for this requirement, which governs only
the files the detector itself writes.


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

---

## 8. CLI Interface

### 8.1 Input Contract

**TD-16**: The detector MUST accept an artifacts directory as its primary input argument.

**TD-17**: The artifacts directory MUST support the following structure:

```
<artifacts-dir>/
├── aw-prompts/
│   ├── prompt.txt                # Expanded workflow prompt file
│   ├── prompt-template.txt       # Pre-expansion template (optional)
│   └── prompt-import-tree.json   # Runtime-import provenance (optional)
├── agent_output.json             # Agent structured output
├── aw_info.json                  # Activation metadata (optional)
├── aw-*.patch                    # Git format-patch files (optional)
├── aw-*.bundle                    # Git bundle files (optional)
├── experiments/                  # Experiment state (optional, inventoried only)
└── comment-memory/               # Agent comment memory (optional, inventoried only)
    └── *.md
```

**TD-17a**: When `aw_info.json` is present, the detector MUST expose only a
bounded, allowlisted subset of activation metadata to the detection model. This
subset MAY include trigger event, actor, engine and model, workflow and repository
identity, ref and commit, run identifiers, and bounded caller-workflow context.
The detector MUST treat every exposed activation value as untrusted runtime data.
Unknown fields and fields outside the allowlist MUST NOT be included in the
detection prompt.

**TD-17b**: The detector MUST recursively inventory every non-directory entry in
the artifacts directory with its relative path, size, entry kind, and whether the
detector consumes it. `experiments/` and `comment-memory/` are supported as
inventory-only inputs; their contents MUST NOT be added to the detection prompt.

**TD-18**: The detector MUST NOT require all artifact files to be present. Missing optional files MUST be handled gracefully.

**TD-18c**: The detector MUST record an `ERR_VALIDATION` finding for each
degraded required input — a missing or empty `aw-prompts/prompt.txt`, a missing,
empty, or unparseable `agent_output.json`, and, when the host declares
`HAS_PATCH=true`, the absence of any readable non-empty `aw-*.patch` or
`aw-*.bundle` file — and MUST follow the host's continue-on-error policy for
them. In warn mode — the default, selected whenever
`GH_AW_DETECTION_CONTINUE_ON_ERROR` is unset or is not case-insensitively equal
to `"false"` — the detector MUST emit each finding as a warning and continue
detection with the inputs that were staged. In strict mode
(`GH_AW_DETECTION_CONTINUE_ON_ERROR` case-insensitively equal to `"false"`) it
MUST emit each finding as an error and terminate as a configuration error
(`config_error`, exit `2`) before invoking the engine. Findings about other
artifacts (for example an unreadable `comment-memory` directory, per TD-18a)
remain advisory warnings in both modes. Each finding MUST identify the artifact
it concerns and whether it is a required input. The detector MUST apply this same mode selection everywhere it
consumes `GH_AW_DETECTION_CONTINUE_ON_ERROR`, including `conclude` (TD-20b).

**TD-18a**: The detector MUST discover comment-memory markdown files
(`<artifacts-dir>/comment-memory/*.md`) and include them in the detection prompt
as untrusted, attacker-influenced input to be analyzed for prompt injection and
secret leakage. When the `comment-memory` directory is absent or contains no
markdown files, the detector MUST proceed and record that no comment-memory
files were found. When the directory is present but cannot be inspected, the
detector MUST emit a non-fatal `ERR_VALIDATION` warning and continue.

**TD-18b**: If `aw-prompts/prompt-template.txt` or
`aw-prompts/prompt-import-tree.json` is absent, unreadable, or empty, the
detector MUST continue with degraded trusted-vs-untrusted prompt analysis and
MUST emit an `ERR_VALIDATION` warning to the job log identifying the
unavailable artifacts.

**TD-18d**: The detector MUST identify the `gh-aw` framework scaffolding
preamble in the rendered workflow prompt — the `<system>...</system>` block that
opens the prompt, ignoring leading whitespace, and ends at the first
`</system>` — and MUST report it to the detection engine as trusted,
framework-authored content that is not prompt injection. This identification
MUST be performed independently of TD-18b, so that it remains available when
`prompt-template.txt` or `prompt-import-tree.json` is unavailable. A `<system>`
marker occurring anywhere after that leading block MUST NOT be treated as
trusted scaffolding, because such markers are reachable from untrusted
interpolated content. The detector MUST NOT grant trusted status to a block
larger than an implementation-defined bound, and MUST convey that runtime values
interpolated inside the preamble remain untrusted input. The detector MUST
deliver this identification to the engine even when a custom prompt template
(`--prompt-template`) omits the `{PROMPT_ANALYSIS}` placeholder.

**TD-18e**: A host MAY remove the framework preamble from the rendered prompt
itself before invoking the detector, replacing it with the marker line
`[gh-aw framework system prompt block removed before analysis]`. The detector
MUST honour the marker only when it occupies the complete first line of the
rendered prompt (ignoring leading whitespace and trailing carriage
returns/spaces); a line that merely begins with the marker text MUST NOT be
treated as host-authored removal. When the rendered prompt opens with that
marker, the detector MUST report to the
detection engine that the trusted preamble was removed by the host and that the
marker itself is never a threat. In that case the detector MUST also locate the
preamble in `aw-prompts/prompt-template.txt` (subject to the same leading-block
and size constraints as TD-18d) and MUST identify it as trusted framework
content, and MUST remove it from the template content it presents to the engine
so the preamble is not re-introduced as unlabelled workflow content and the
trusted-vs-untrusted diff stays aligned with the rendered prompt. A template
that opens with `<system>` MUST NOT be treated as trusted scaffolding when the
rendered prompt carries no such marker and no leading preamble of its own. The
preamble grammar the detector recognizes MUST be at least as permissive as the
host's stripping grammar — a case-insensitive opening `<system>` tag that MAY
carry attributes, and a case-insensitive closing tag that MAY contain internal
whitespace — so that every preamble the host removes is still identified as
trusted framework content in the template copy.

### 8.2 Output Contract

**TD-19**: The detector MUST output the structured JSON result (per TD-08) to
stdout. That result is the redacted one: its `reasons` array is always empty
(per TD-10d).

**TD-20**: The detector MUST support writing the result to a file via the
`--output` flag, and the companion full result via the `--full-output` flag.
When `--full-output` is not given, the full-result path MUST be derived from the
`--output` path by convention, so a host that configures only `--output` still
gets the reasons on disk without any change; an explicitly empty `--full-output`
MUST disable the full result entirely. When the result goes to stdout there is
no path to derive from, so the implementation MUST NOT write a full result
unless `--full-output` supplies an explicit path: the flag remains available as
an escape hatch for a host that wants the reasons on disk somewhere no upload
glob can reach.

**TD-20a**: The detector MUST NOT write diagnostics to any destination other than
standard output, standard error, the result file, and the full result file
(TD-20). It MUST NOT produce a separate run-log artifact. Every diagnostic the detector emits MUST therefore be
observable in the host's captured job log, and MUST be written to standard error
so it cannot corrupt the result JSON on standard output (TD-19).

The detector MUST report on standard error, at minimum: the resolved run
configuration (detector version, engine, model, retry budget); the artifact
inventory defined by TD-17b; the prompt metadata of TD-20c; each degraded-input finding of TD-18c with the
artifact it concerns and whether it is a required input; each detection
attempt and whether it recorded a verdict; the engine subprocess invocation; and
the terminal `THREAT_DETECTION_STATUS:` line (TD-21a).

Untrusted values echoed into a detector-authored diagnostic — model-authored
text, artifact paths, and configuration values such as the engine ID, model, and
process name — MUST be escaped so that each is confined to a single physical
output line and cannot emit a host workflow command, and listings MUST be
bounded so a pathological input cannot flood the job log.

The detector MUST forward the engine subprocess's own standard output and
standard error to its standard error as the subprocess produces them, so harness
lifecycle output and engine errors reach the job log in real time. Because that
output is model-authored and therefore untrusted, the detector MUST frame it: it
MUST emit forwarded output one line at a time, MUST prefix every forwarded line
with a fixed marker that identifies it as engine output, MUST treat both LF and
CR as line terminators, MUST flush a trailing partial line that arrives without a
terminator, and MUST ensure no forwarded line can be interpreted by the host as a
workflow command. A reader MUST therefore be able to distinguish forwarded engine
output from detector-authored diagnostics by inspecting a single line. Hosts and
log consumers MUST NOT treat forwarded engine output as detector-attested text,
and MUST ignore `THREAT_DETECTION_*` markers appearing on forwarded lines.

**TD-20b**: The detector MUST provide a `conclude` subcommand that reads a structured
result file written by a prior detection run and emits the host-side job-output
contract (`conclusion`, `reason`, `success`) consumed by the parent orchestrator.
The verdict crosses the AWF sandbox boundary as a file (written to a read-write
mount), not via log scraping. When the result file is missing, `conclude` MUST
consult the detection run's captured log (`--detection-log <path>`, default
`<result-file-dir>/detection.log`) for the terminal `THREAT_DETECTION_STATUS:`
line (per TD-20a) and map its `reason=` value onto the host-side `reason` per the
following table, defaulting to `agent_failure` when the log is absent, unreadable,
or contains no status line. Status lines appearing on forwarded engine output
(TD-20a) MUST be ignored during this scan:

| status reason | host-side `reason` |
|---|---|
| `invalid_report_exhausted` | `parse_error` |
| `output_write_error` | `parse_error` |
| `engine_error` | `agent_failure` |
| `cancelled` | `agent_failure` |
| `config_error` | `agent_failure` |
| absent / unrecognized | `agent_failure` |

A malformed (readable but unparseable) result file MUST unconditionally report
`parse_error`; detected threats MUST report `threat_detected`. In warn mode
(`GH_AW_DETECTION_CONTINUE_ON_ERROR` not case-insensitively equal to `"false"`,
per TD-18c) non-mandatory failures MUST
surface as warnings without failing the job, except that `agent_failure` and
`parse_error` MUST hard-fail when the detection execution step itself failed.

**TD-20c**: The detector MUST NOT write to the GitHub Actions step summary. The
artifact inventory defined by TD-17b is surfaced on standard error (TD-20a) only,
and the conclusion verdict through the `conclude` diagnostics (TD-20d). The
rendered prompt itself MUST NOT be surfaced: the detector reports only its
metadata (byte count, resolved workflow name/description, custom-prompt
provenance, scaffolding detection). For compatibility with hosts that still pass
the removed `--step-summary <path>` option, the detector MUST accept that option,
ignore its value, note on standard error that it was ignored, and MUST NOT treat
it as a configuration error.

**TD-20d**: The `conclude` subcommand MUST write a human-readable diagnostic
section to standard output that is sufficient, on its own, to explain the
conclusion. It MUST report the environment inputs it consumed (`RUN_DETECTION`,
`GH_AW_DETECTION_CONTINUE_ON_ERROR`, `DETECTION_AGENTIC_EXECUTION_OUTCOME`) and
the resolved result-file, full-result-file, and detection-log paths, and — on
both the safe and the threat path — the per-field verdict (`prompt_injection`,
`secret_leak`, `malicious_patch`) together with an indexed list of reasons
resolved per TD-20e. When the result file
is missing or unusable it MUST additionally emit a recursive listing of the
result directory and, when a detection log is present, its line and byte counts
plus every line containing a `THREAT_DETECTION_STATUS:` or
`THREAT_DETECTION_RESULT:` marker. The detection log MUST NOT be used to derive
the verdict itself — its only non-diagnostic use is the status-line reason
mapping of TD-20b. Diagnostic output MAY be bounded to keep job logs readable,
but when it is bounded the output MUST indicate that it was truncated and MUST
NOT report a bounded prefix as though it were the whole input. A model-authored
reason MAY be rendered across multiple physical lines so its quoted evidence
stays readable and copy-pasteable (TD-10d); when it is, every line after the
first MUST be prefixed with a marker that cannot begin a workflow command.
Untrusted values echoed into the diagnostics (model-authored reasons, artifact
filenames, and detection-log lines) MUST otherwise be escaped so that each
physical output line is confined to one line of the value. Such values MUST NOT
be able to emit a host workflow command in **either** marker form the runner
accepts: the `::command::` form, which the runner honors only at the start of a
line after trimming leading whitespace, and the legacy `##[command]` form, which
the runner locates anywhere within a line. Because line position is no defense
against the latter, the legacy marker MUST be neutralized within the value
itself. These diagnostics
are the sole record of the conclusion; `conclude` MUST NOT write them to any
separate log artifact (TD-20a).

**TD-20e**: Because the result file read by `conclude` carries no reasons
(TD-10d), `conclude` MUST recover them from the companion full result. It MUST
accept a `--full-result-file <path>` option and, when the option is not given,
MUST derive the path from `--result-file` using the same convention the
detection run uses for `--full-output`. An explicitly empty value MUST disable
the lookup, mirroring `--full-output`.

The result file remains the sole source of the verdict. The full result MUST
only ever contribute reasons, and `conclude` MUST therefore:

- treat a missing or unparseable full result as non-fatal, reporting it as a
  diagnostic and concluding from the result file alone;
- ignore a full result whose three booleans disagree with the result file,
  reporting the disagreement, so a stale or planted file can never move,
  contradict, or add to the verdict; and
- fall back to any reasons carried inside the result file itself when no usable
  full result is available, so a result written by a pre-split detector still
  renders its explanations.

Recovered reasons MUST be rendered into the job-log diagnostics under the
escaping and bounding rules of TD-20d. `conclude` MUST NOT copy them into any
file, and hosts MUST NOT upload the full result.

**TD-20i**: Rendered conclusion output MUST distinguish a tooling failure from an
actual security finding, so reviewers do not treat a detection outage as a
threat. A reason of `agent_failure` or `parse_error` is a tooling failure;
`threat_detected` is a security finding. The job-log diagnostics (TD-20d) MUST
state that distinction with the headline matching the reason:

| host-side `reason` | headline |
|---|---|
| `threat_detected` | Agentic threat detected — Manual review is REQUIRED before any follow-up automation. |
| `agent_failure`, `parse_error` | Threat Detection Engine Failure — The analysis engine could not complete. This is a tooling failure, not a security finding. |
| absent (`success`, `skipped`) | none |

### 8.3 Exit Codes

**TD-21**: The detector MUST use the following exit codes:

| Code | Meaning |
|------|---------|
| 0 | Safe — no threats detected |
| 1 | Threat detected |
| 2 | Infrastructure/configuration error |

**TD-21a**: The exit code is an out-of-band signal for direct callers. In the
integrated detection job the verdict is conveyed to the host via the structured
`detection_result.json` file (TD-20b) and concluded by the `conclude` subcommand,
not by the detector exit code. The integration wrapper that maps the detector
exit code to the detection step's success/failure outcome MUST NOT be stricter
than `gh-aw`'s native engine step: a recorded verdict (exit 0 or 1) and an
"engine ran but recorded no verdict" outcome (exit 2 with status reason
`invalid_report_exhausted`) MUST NOT mark the detection step as failed. Only a
genuine engine or configuration failure (e.g. status reason `engine_error`,
`config_error`, `cancelled`) may surface as a step failure. This prevents the
common flaky-output case from blocking safe outputs in warn mode, where `gh-aw`
treats a missing verdict as a recoverable `parse_error` and proceeds.

### 8.4 Environment Variables

**TD-22**: The detector MUST support the following environment variables:

| Variable | Purpose |
|----------|---------|
| `WORKFLOW_NAME` | Name of the workflow being analyzed |
| `WORKFLOW_DESCRIPTION` | Description of the workflow |
| `CUSTOM_PROMPT` | Additional detection instructions |

**TD-22-flags**: The detector MUST also accept the workflow context via explicit
flags so it cannot be silently dropped by environment-variable plumbing:
`--workflow-name` overrides `WORKFLOW_NAME`, `--workflow-description` overrides
`WORKFLOW_DESCRIPTION`, and `--custom-prompt` (or `--custom-prompt-file`, which
reads the instructions from a file) overrides `CUSTOM_PROMPT`. When both a flag
and its environment variable are set, the flag wins (even when empty, so an
explicit empty `--custom-prompt` clears an env-supplied prompt);
`--custom-prompt-file` takes precedence over `--custom-prompt`. A value is
reported as defaulted only when neither its flag nor its environment variable was
provided (not merely because it equals the fallback text). The detector MUST
record the resolved workflow
name and description, whether each fell back to its built-in default, and the
source and byte length of any applied custom prompt (`flag`, `file`, `env`, or
`none`) on a single stderr diagnostic line, so a dropped custom prompt or
missing workflow context is diagnosable.

**TD-22a**: When the model is not set explicitly (via the `--model` flag or engine configuration), the detector MUST resolve the model for the selected engine from environment variables, in the following precedence:

1. the engine-specific detection model variable `GH_AW_MODEL_DETECTION_{COPILOT,CLAUDE,CODEX}`;
2. the engine CLI's native model environment variable (`COPILOT_MODEL` for copilot, `ANTHROPIC_MODEL` for claude).

This keeps the standalone detector consistent with the model `gh-aw` configures for the harness-driven detection path. Codex has no native model environment variable and relies solely on the detection variable.

**TD-22b**: When the Copilot engine runs via the `gh-aw` Copilot harness and the resolved model is a `gh-aw` model alias (e.g. `auto`), the detector MUST make the AWF configuration (which carries the api-proxy model alias map) discoverable by the harness so the alias is resolved to a concrete model before the Copilot CLI is invoked. When `GH_AW_AWF_CONFIG_PATH` is unset and the harness default location (`/tmp/gh-aw/awf-config.json`) is absent, the detector MUST point the harness at the AWF config mounted at `$RUNNER_TEMP/gh-aw/awf-config.json` when that file exists. Without this, the harness forwards the literal alias to the Copilot CLI, which rejects it (`400 The requested model is not supported`).

**TD-23**: AI engine authentication variables MUST be treated as runtime-only configuration. They MUST NOT be required for parser, prompt building, unit test, or binary smoke test execution.

The implementation MAY pass through engine-specific authentication variables required by the selected CLI, including:

| Variable | Engine |
|----------|--------|
| `COPILOT_GITHUB_TOKEN` | Copilot |
| `ANTHROPIC_API_KEY` | Claude |
| `OPENAI_API_KEY` | Codex |

---

## 9. Version Compatibility

**TD-24**: The release-asset binary MUST be published under semantic version tags.

**TD-25**: The parent orchestrator (`gh-aw`) MUST pin to a specific detector version.

**TD-26**: Breaking changes to the input/output contract MUST increment the major version.

**TD-27**: Private repository status MUST NOT block detector publication or consumption. When the source repository is private, approved consuming repositories MUST be able to download pinned release assets with `contents: read`.

---

## 10. Security Considerations

**TD-36**: The detection run SHOULD have no network access (fully blocked egress).

**TD-37**: The detection run MUST NOT have access to repository secrets beyond what is required for AI engine authentication.

**TD-38**: Detection results MUST NOT be modifiable by the agent being analyzed.
