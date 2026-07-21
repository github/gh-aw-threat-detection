# GitHub Agentic Workflows Threat Detection Usage Specification

**Version**: 1.0.0  
**Status**: Draft  
**Latest Version**: https://github.com/github/gh-aw-threat-detection/blob/main/specs/usage-spec.md

---

## 1. Introduction

This specification defines how a consumer integrates and *uses* the
`threat-detect` component of GitHub Agentic Workflows. Where the
[Threat Detection Specification](threat-detection-spec.md) defines *what* the
detector does (its detection behavior and result contract), this document
defines *how* a host — such as [`gh-aw`](https://github.com/github/gh-aw) or a
third-party workflow — acquires, invokes, and concludes a detection run.

Its purpose is to simplify integration by giving integrators a single normative
reference for the acquisition, invocation, sandbox, and conclusion contracts.

### 1.1 Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

A **conforming host** is any system that acquires and invokes the
`threat-detect` binary to gate downstream jobs. A **conforming detector** is any
build of `threat-detect` that satisfies the
[Threat Detection Specification](threat-detection-spec.md).

### 1.2 Scope

This specification covers:

- Acquiring the detector (release-asset binary)
- Invoking the detector CLI
- The integrated detection flow (download → run → conclude)
- Running the detector inside the Agentic Workflow Firewall (AWF) sandbox
- Configuration surface (flags and environment variables) exposed to integrators
- Interpreting exit codes, the status line, and the conclusion contract
- Version pinning and compatibility expectations

This specification does **not** redefine detection categories, the prompt
pipeline, or the result-sink mechanism; those are normative in the
[Threat Detection Specification](threat-detection-spec.md) and are referenced
here as `TD-XX`.

---

## 2. Acquisition

**U-01**: A conforming host MUST acquire the detector as a published GitHub
Release asset from `github/gh-aw-threat-detection`. The host MUST NOT build the
detector from source as part of a production detection job.

**U-02**: The host MUST select the release asset matching the runner
architecture: `threat-detect-linux-amd64` or `threat-detect-linux-arm64`.

**U-03**: The host MUST verify the downloaded asset against the `sha256` value
recorded for that asset (via `checksums.txt` published alongside the assets, or
the sha256 recorded in the release notes) before executing it.

**U-04**: The host MUST pin acquisition to an explicit release tag (per TD-25,
U-24, and U-26). A host that resolves the latest promoted (stable) release MUST
first resolve it to a concrete release tag and then download that pinned tag; it
MUST NOT download an unpinned "latest" reference directly.

**U-05**: Acquisition MUST succeed with only `contents: read` against the
detector repository, including when that repository is private but the consuming
repository is approved (per TD-27).

Example acquisition (informative):

```bash
case "$(uname -m)" in
  x86_64|amd64) asset=threat-detect-linux-amd64 ;;
  aarch64|arm64) asset=threat-detect-linux-arm64 ;;
esac
gh release download v0.0.2 --repo github/gh-aw-threat-detection \
  --pattern "$asset" --pattern checksums.txt
sha256sum --check --ignore-missing checksums.txt
install -m 0755 "$asset" ./threat-detect
```

---

## 3. Invocation

**U-06**: A conforming host MUST invoke the detector as:

```
threat-detect [flags] <artifacts-dir>
```

where `<artifacts-dir>` conforms to the artifacts directory shape (per TD-17)
and the host MUST NOT require all optional artifact files to be present (per
TD-18).

**U-07**: The host MUST ensure the AI engine CLI selected via `--engine` (per
TD-13) and its authentication (per TD-23) are available on `PATH` on the runner
where the detector executes. The detector MUST NOT be expected to bundle the
engine CLI.

**U-08**: The host MUST treat the result JSON (per TD-08) as the authoritative
verdict payload and MUST read it from the location it configured (stdout, or the
`--output` path, or the `detection_result.json` sink used by `conclude`).

**U-09**: The host SHOULD enable the structured JSONL run log via `--log-file`
(or `THREAT_DETECTION_LOG_FILE`) for observability (per TD-20a), and MUST NOT
point `--log-file` and `--output` at the same path.

### 3.1 Flags

**U-10**: A conforming host MAY configure the detector through the following
flags. Hosts MUST tolerate additional, non-conflicting flags on future detector
versions.

| Flag | Purpose |
|------|---------|
| `--engine {copilot\|claude\|codex}` | Select the AI engine (default `copilot`) |
| `--model <name>` | Override the engine model (see U-13) |
| `--prompt-template <path>` | Override the embedded default prompt |
| `--output <path>` | Write the JSON result to a file instead of stdout |
| `--log-file <path>` | Write structured JSONL run logs |
| `--retries <n>` | Retries for malformed detection outputs (default `1`) |
| `--version` | Print version and exit |

---

## 4. Integrated Detection Flow

**U-11**: In an integrated (host-driven) workflow the detection stage MUST follow
this ordered flow:

1. **Acquire** the pinned detector asset and verify its checksum (Section 2).
2. **Prepare** the artifacts directory from the guarded agentic run's outputs
   (per TD-17).
3. **Run** the detector once, writing its verdict to a structured result file
   (`detection_result.json`).
4. **Conclude** the run with the `conclude` subcommand (Section 6) to derive the
   host-side job-output contract.

**U-12**: The host MUST NOT derive the verdict by scraping the detector's stdout
or transcript when running in the integrated flow; the verdict crosses the job
(and sandbox) boundary as the structured result file consumed by `conclude` (per
TD-20b).

### 4.1 Model resolution

**U-13**: When the host does not set `--model` explicitly, it MAY influence the
resolved model through environment variables, in the precedence defined by
TD-22a:

1. `GH_AW_MODEL_DETECTION_{COPILOT,CLAUDE,CODEX}`;
2. the engine CLI's native model variable (`COPILOT_MODEL`, `ANTHROPIC_MODEL`).

Codex has no native model variable and relies solely on the detection variable.

---

## 5. Sandboxed Execution (AWF)

**U-14**: When a host runs the detector inside the Agentic Workflow Firewall
(AWF), it MUST provide the structured result file location on a read-write mount
so the verdict can cross the sandbox boundary (per TD-20b). The host MUST NOT
rely on detector stdout to convey the verdict across the sandbox.

**U-15**: The host SHOULD run detection with network egress restricted to the
domains required by the selected engine, consistent with the security
considerations in TD-36 through TD-38. Repository secrets beyond engine
authentication MUST NOT be exposed to the detection run.

**U-16**: The verdict recorded by the detection run MUST NOT be modifiable by the
agent being analyzed (per TD-38).

---

## 6. Conclusion Contract

**U-17**: A conforming host MUST derive the job-level outcome using the detector's
`conclude` subcommand rather than re-implementing verdict interpretation:

```bash
threat-detect conclude --result-file <path>/detection_result.json
```

**U-18**: `conclude` MUST emit the host-side job-output contract (`conclusion`,
`reason`, `success`) and, in a GitHub Actions context, MUST write these to
`GITHUB_OUTPUT` and export `GH_AW_DETECTION_CONCLUSION` and
`GH_AW_DETECTION_REASON` to `GITHUB_ENV` (per TD-20b).

**U-19**: A conforming host MAY control conclusion behavior through these
environment inputs consumed by `conclude`:

| Variable | Effect |
|----------|--------|
| `RUN_DETECTION` | When not `"true"`, the verdict is `skipped`/`success` |
| `GH_AW_DETECTION_CONTINUE_ON_ERROR` | Anything other than `"false"` selects warn mode |
| `DETECTION_AGENTIC_EXECUTION_OUTCOME` | `"failure"` makes `agent_failure`/`parse_error` hard-fail |

**U-20**: The host MUST honor the `conclude` outcomes: a missing result file
reports `agent_failure`, a malformed result file reports `parse_error`, and a
detected threat reports `threat_detected`. In warn mode, non-mandatory failures
MUST surface as warnings without failing the job, except that `agent_failure`
and `parse_error` MUST hard-fail when the detection execution step itself failed
(per TD-20b).

### 6.1 Exit codes and status line

**U-21**: For direct (non-integrated) callers, the host MUST interpret the
detector exit codes per TD-21: `0` safe, `1` threat detected, `2`
infrastructure/configuration error.

**U-22**: A host that maps the detector exit code onto a detection step's
success/failure outcome MUST NOT be stricter than `gh-aw`'s native engine step
(per TD-21a). Specifically, a recorded verdict (exit `0` or `1`) and an
"engine ran but recorded no verdict" outcome (exit `2` with status reason
`invalid_report_exhausted`) MUST NOT mark the detection step as failed. Only a
genuine engine, configuration, or output failure (status reason `engine_error`,
`config_error`, `cancelled`, or `output_write_error`) MAY surface as a step
failure. In particular `output_write_error` — the verdict was obtained but could
not be written — MUST NOT be treated like a recoverable missing report, because
the unwritten verdict may have contained a threat.

**U-23**: The host MAY parse the terminal stderr status line
`THREAT_DETECTION_STATUS: reason=<reason> exit=<code>` to distinguish outcomes
that share exit code `2`. Informational modes (`--help`, `--version`) emit no
status line, and the host MUST NOT treat its absence in those modes as a
malfunction.

---

## 7. Version Compatibility

**U-24**: A conforming host MUST pin the detector to a specific release version
(per TD-25) and SHOULD record that version in the workflow so detection runs are
reproducible.

**U-25**: A host MUST treat a major-version change of the detector as a
potentially breaking change to the input/output contract (per TD-26) and MUST
re-validate integration before adopting it.

**U-26**: A host MUST NOT depend on the `latest`/promoted release moving
automatically; the stable release moves only on explicit promotion. Hosts that
require the newest stable release MUST re-pin explicitly.

---

## 8. Replay and Diagnostics

**U-27**: A host MAY re-run detection against artifacts from a prior run for
diagnostics. When it does, it MUST normalize the downloaded artifacts into the
input contract of Section 3 before invoking the detector, and SHOULD retain the
detector's JSONL run log (per TD-20a) and structured result for comparison.

**U-28**: Replay MUST NOT require credentials beyond those already needed to read
the source run's artifacts and to authenticate the selected engine.

---

## 9. Conformance Summary

A conforming host satisfies U-01 through U-28. Requirements that reference
`TD-XX` are satisfied jointly with the corresponding requirement in the
[Threat Detection Specification](threat-detection-spec.md); this document does
not weaken or override any `TD-XX` requirement.
