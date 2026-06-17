#!/usr/bin/env python3
"""Create smoke workflow siblings that use this repo's detector container.

The sibling files are derived from gh-aw-generated *.lock.yml files. They keep the
compiled workflow structure intact, but replace the generated detection engine
steps with a detector binary extracted from ghcr.io/github/gh-aw-threat-detection
and executed under the same AWF wrapper as the source workflow. Matching
*-container.md source sidecars are copied from the original smoke workflow sources
so gh-aw's stale lock-file check can verify the inherited frontmatter hash.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
DEFAULT_IMAGE = "ghcr.io/github/gh-aw-threat-detection:latest"
ENGINES = {
    "smoke-copilot.lock.yml": ("copilot", "Smoke Copilot Containerized"),
    "smoke-claude.lock.yml": ("claude", "Smoke Claude Containerized"),
    "smoke-codex.lock.yml": ("codex", "Smoke Codex Containerized"),
}
EXECUTION_STEPS = {
    "copilot": "Execute GitHub Copilot CLI",
    "claude": "Execute Claude Code CLI",
    "codex": "Execute Codex CLI",
}


def indent(text: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line if line else line for line in text.splitlines())


def shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def extract_workflow_description(text: str) -> str:
    match = re.search(r"^          WORKFLOW_DESCRIPTION: (.+)$", text, flags=re.MULTILINE)
    if not match:
        raise ValueError("could not find workflow description in generated detection setup")
    return match.group(1)


def extract_awf_lines(text: str) -> tuple[str, str, str]:
    config_line = ""
    awf_line = ""
    credits_line = ""
    for line in text.splitlines():
        if line.lstrip().startswith("GH_AW_MAX_AI_CREDITS="):
            credits_line = line
        if line.startswith("          printf '%s\\n' ") and "gh-aw-firewall" in line:
            config_line = line
        if line.startswith("          sudo -E awf ") and line.rstrip().endswith("\\"):
            awf_line = line
    if not config_line or not awf_line:
        raise ValueError("could not find generated AWF setup lines")
    return config_line.strip(), awf_line.strip(), credits_line.strip()


def engine_env(engine: str) -> str:
    if engine == "copilot":
        return """COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN }}"""
    if engine == "claude":
        return """ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}"""
    if engine == "codex":
        # The codex CLI authenticates with OPENAI_API_KEY; CODEX_API_KEY alone
        # leaves it without an auth header (401 from api.openai.com). Mirror the
        # gh-aw-generated codex smoke, which sets both.
        return (
            "CODEX_API_KEY: ${{ secrets.CODEX_API_KEY || secrets.OPENAI_API_KEY }}\n"
            "OPENAI_API_KEY: ${{ secrets.CODEX_API_KEY || secrets.OPENAI_API_KEY }}"
        )
    raise ValueError(f"unsupported engine: {engine}")


def detection_model_expr(engine: str) -> str:
    # Mirror the model defaults the gh-aw-generated smokes use for the detection
    # phase. Under AWF token steering the engine CLI runs in BYOK/offline mode,
    # which requires an explicit model (an empty model breaks Copilot/Codex).
    if engine == "copilot":
        return "${{ vars.GH_AW_MODEL_DETECTION_COPILOT || vars.GH_AW_DEFAULT_MODEL_COPILOT || 'claude-sonnet-4.6' }}"
    if engine == "claude":
        return "${{ vars.GH_AW_MODEL_DETECTION_CLAUDE || vars.GH_AW_DEFAULT_MODEL_CLAUDE || '' }}"
    if engine == "codex":
        return "${{ vars.GH_AW_MODEL_DETECTION_CODEX || vars.GH_AW_DEFAULT_MODEL_CODEX || 'gpt-5.4' }}"
    raise ValueError(f"unsupported engine: {engine}")


def replacement_steps(engine: str, workflow_description: str, awf_config_line: str, awf_command_line: str, awf_credits_line: str = "") -> str:
    runner_temp = "${RUNNER_TEMP}"
    credits_block = indent(awf_credits_line, 4) + "\n" if awf_credits_line else ""
    # The verdict crosses the AWF sandbox boundary as a file: the detector writes
    # detection_result.json into /tmp/gh-aw/threat-detection, which is bind-mounted
    # read-write into the sandbox (the rw mount injected below overrides the parent
    # read-only host-access view, mirroring gh-aw's safe-outputs staging pattern).
    # The host-side `threat-detect conclude` step then reads that file directly — no
    # log scraping. The step's success/failure outcome is a *separate* signal that
    # the conclude step escalates (a parse_error only hard-fails when the execution
    # step itself failed). To avoid being stricter than gh-aw, the wrapper must NOT
    # surface an "engine ran but recorded no verdict" outcome
    # (reason=invalid_report_exhausted, exit 2) as a step failure — otherwise the
    # common flaky-output case would block safe outputs even in warn mode, where
    # gh-aw merely warns and proceeds. Only genuine engine/infra failures propagate.
    #
    # Make the threat-detection dir writable inside the sandbox so the detector can
    # persist detection_result.json for the host to read.
    rw_mount = '--mount "/tmp/gh-aw/threat-detection:/tmp/gh-aw/threat-detection:rw"'
    awf_command_line = awf_command_line.rstrip()
    if not awf_command_line.endswith("\\"):
        raise ValueError("awf command line must end with a line continuation")
    awf_command_line = awf_command_line[:-1].rstrip() + f" {rw_mount} \\"
    codex_config_setup = ""
    if engine == "codex":
        # Codex ignores OPENAI_BASE_URL and would otherwise bypass the AWF api-proxy,
        # dialing api.openai.com directly over a websocket
        # (wss://api.openai.com/v1/responses). OpenAI then rejects the injected
        # placeholder key with a 401. Write a CODEX_HOME/config.toml that points
        # Codex at the AWF OpenAI proxy provider and disables websockets (the proxy
        # only speaks plain HTTPS), mirroring the gh-aw-generated codex smoke. The
        # codex subprocess threat-detect spawns inherits CODEX_HOME from this
        # exported environment.
        codex_config_setup = (
            "export CODEX_HOME=/tmp/gh-aw/threat-detection/codex; "
            'mkdir -p "$CODEX_HOME"; '
            "printf 'model_provider = \"openai-proxy\"\\n\\n"
            "[model_providers.openai-proxy]\\n"
            "name = \"OpenAI AWF proxy\"\\n"
            "base_url = \"http://172.30.0.30:10000\"\\n"
            "env_key = \"OPENAI_API_KEY\"\\n"
            "supports_websockets = false\\n' "
            '> "$CODEX_HOME/config.toml"; '
            'chmod 600 "$CODEX_HOME/config.toml"; '
        )
    detector_command = (
        codex_config_setup
        + 'export PATH="$(find /opt/hostedtoolcache /home/runner/work/_tool -maxdepth 4 -type d -name bin '
        '2>/dev/null | paste -sd: -):$PATH"; '
        '[ -n "$GOROOT" ] && export PATH="$GOROOT/bin:$PATH" || true; '
        'result_path="/tmp/gh-aw/threat-detection/detection_result.json"; '
        'status_path="/tmp/gh-aw/threat-detection/detection-status.txt"; '
        f"args=(--engine {engine}); "
        'if [ -n "${THREAT_DETECTION_MODEL:-}" ]; then args+=(--model "$THREAT_DETECTION_MODEL"); fi; '
        'run_status=0; '
        '"${RUNNER_TEMP}/gh-aw/threat-detect-bin/threat-detect" "${args[@]}" --output "$result_path" /tmp/gh-aw/threat-detection 2>"$status_path" || run_status=$?; '
        'cat "$status_path" >&2 || true; '
        'if [ -f "$result_path" ]; then exit 0; fi; '
        'if grep -q "reason=invalid_report_exhausted" "$status_path" 2>/dev/null; then exit 0; fi; '
        'exit "$run_status"'
    )
    shell = f'''- name: Log in to GHCR for detector image
  if: always() && steps.detection_guard.outputs.run_detection == 'true'
  env:
    GHCR_TOKEN: ${{{{ secrets.GH_AW_GITHUB_TOKEN || github.token }}}}
  run: |
    if [ -n "${{GHCR_TOKEN:-}}" ]; then
      echo "$GHCR_TOKEN" | docker login ghcr.io -u "${{{{ github.actor }}}}" --password-stdin
    fi
- name: Pull threat detection container
  if: always() && steps.detection_guard.outputs.run_detection == 'true'
  env:
    THREAT_DETECTION_IMAGE: ${{{{ vars.GH_AW_THREAT_DETECTION_IMAGE || '{DEFAULT_IMAGE}' }}}}
  run: docker pull "$THREAT_DETECTION_IMAGE"
- name: Extract threat detection binary from container
  if: always() && steps.detection_guard.outputs.run_detection == 'true'
  env:
    THREAT_DETECTION_IMAGE: ${{{{ vars.GH_AW_THREAT_DETECTION_IMAGE || '{DEFAULT_IMAGE}' }}}}
  run: |
    mkdir -p "{runner_temp}/gh-aw/threat-detect-bin"
    container_id="$(docker create "$THREAT_DETECTION_IMAGE")"
    trap 'docker rm -f "$container_id" >/dev/null 2>&1 || true' EXIT
    docker cp "$container_id:/usr/local/bin/threat-detect" "{runner_temp}/gh-aw/threat-detect-bin/threat-detect"
    chmod 755 "{runner_temp}/gh-aw/threat-detect-bin/threat-detect"
- name: Execute threat detection with AWF
  if: always() && steps.detection_guard.outputs.run_detection == 'true'
  continue-on-error: true
  id: detection_agentic_execution
  timeout-minutes: 20
  env:
{indent(engine_env(engine), 4)}
    THREAT_DETECTION_MODEL: {detection_model_expr(engine)}
    WORKFLOW_DESCRIPTION: {workflow_description}
    WORKFLOW_NAME: ${{{{ github.workflow }}}}
  run: |
    set -o pipefail
    touch /tmp/gh-aw/agent-step-summary.md
    (umask 177 && touch /tmp/gh-aw/threat-detection/detection.log)
{credits_block}{indent(awf_config_line, 4)}
    # shellcheck disable=SC1003
{indent(awf_command_line, 4)}
      -- /bin/bash -c {shell_single_quote(detector_command)} 2>&1 | tee -a /tmp/gh-aw/threat-detection/detection.log'''
    return indent(shell, 6)


def add_packages_read(text: str) -> str:
    pattern = re.compile(r"(  detection:\n(?:.*?\n)*?    permissions:\n      contents: read\n)", re.MULTILINE)

    def repl(match: re.Match[str]) -> str:
        block = match.group(1)
        if "      packages: read\n" in block:
            return block
        return block + "      packages: read\n"

    updated, count = pattern.subn(repl, text, count=1)
    if count != 1:
        raise ValueError("could not find detection job permissions block")
    return updated


def conclude_steps(runner_temp: str = "${RUNNER_TEMP}") -> str:
    # Upload the structured verdict artifact alongside the diagnostic log, then run
    # the host-side `threat-detect conclude` subcommand to read detection_result.json
    # and emit the gh-aw job-output contract. The detector binary only exists when
    # detection actually ran; when it was skipped the binary was never extracted, so
    # the conclude step short-circuits to the skipped contract. Strict mode
    # (GH_AW_DETECTION_CONTINUE_ON_ERROR=false, matching the gh-aw source smokes and
    # no continue-on-error) lets a non-zero conclude exit fail the detection job and
    # gate safe_outputs (needs.detection.result == 'success').
    bin_path = f"{runner_temp}/gh-aw/threat-detect-bin/threat-detect"
    shell = f'''- name: Upload threat detection artifacts
  if: always() && steps.detection_guard.outputs.run_detection == 'true'
  uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
  with:
    name: detection
    path: |
      /tmp/gh-aw/threat-detection/detection_result.json
      /tmp/gh-aw/threat-detection/detection.log
    if-no-files-found: ignore
- name: Parse and conclude threat detection
  id: detection_conclusion
  if: always()
  env:
    RUN_DETECTION: ${{{{ steps.detection_guard.outputs.run_detection }}}}
    DETECTION_AGENTIC_EXECUTION_OUTCOME: ${{{{ steps.detection_agentic_execution.outcome }}}}
    GH_AW_DETECTION_CONTINUE_ON_ERROR: "false"
  run: |
    bin="{bin_path}"
    if [ ! -x "$bin" ]; then
      {{
        echo "conclusion=skipped"
        echo "success=true"
        echo "reason="
      }} >> "$GITHUB_OUTPUT"
      {{
        echo "GH_AW_DETECTION_CONCLUSION=skipped"
        echo "GH_AW_DETECTION_REASON="
      }} >> "$GITHUB_ENV"
      exit 0
    fi
    "$bin" conclude --result-file /tmp/gh-aw/threat-detection/detection_result.json'''
    return indent(shell, 6)


def transform(source: Path) -> str:
    if source.name not in ENGINES:
        raise ValueError(f"unsupported workflow: {source.name}")
    engine, sibling_name = ENGINES[source.name]
    text = source.read_text()
    output_name = source.name.replace(".lock.yml", "-container.lock.yml")

    text = text.replace(source.name, output_name)
    text = re.sub(r'^name: ".*"$', f'name: "{sibling_name}"', text, count=1, flags=re.MULTILINE)
    text = re.sub(r'^run-name: ".*"$', f'run-name: "{sibling_name}"', text, count=1, flags=re.MULTILINE)
    text = add_packages_read(text)
    workflow_description = extract_workflow_description(text)
    awf_config_line, awf_command_line, awf_credits_line = extract_awf_lines(text)

    end = re.search(r"^      - name: Upload threat detection log\n", text, flags=re.MULTILINE)
    if not end:
        raise ValueError(f"could not find generated detection upload step in {source}")
    step_name = EXECUTION_STEPS[engine]
    starts = [
        match
        for match in re.finditer(rf"^      - name: {re.escape(step_name)}\n", text, flags=re.MULTILINE)
        if match.start() < end.start()
    ]
    start = starts[-1] if starts else None
    if not start or start.start() >= end.start():
        raise ValueError(f"could not find generated detection execution step range in {source}")

    # The gh-aw source's Upload + Parse steps (from end.start() up to the next
    # top-level job, e.g. "  safe_outputs:") are replaced wholesale by this repo's
    # file-based upload + conclude steps. Everything from the next job onward is
    # preserved verbatim.
    tail = text[end.start():]
    next_job = re.search(r"^  [A-Za-z_][\w-]*:\n", tail, flags=re.MULTILINE)
    if not next_job:
        raise ValueError(f"could not find job following detection steps in {source}")
    remainder = tail[next_job.start():]

    header = (
        f"# gh-aw-threat-detection-sibling: generated from {source.name} by "
        "scripts/create-threat-detection-sibling-workflows.py\n"
    )
    body = (
        text[: start.start()]
        + replacement_steps(engine, workflow_description, awf_config_line, awf_command_line, awf_credits_line)
        + "\n"
        + conclude_steps()
        + "\n\n"
        + remainder
    )
    lines = body.splitlines()
    insert_at = 2 if lines and lines[0].startswith("# gh-aw-metadata:") else 0
    lines.insert(insert_at, header.rstrip("\n"))
    return "\n".join(lines) + "\n"


def markdown_source(source: Path) -> Path:
    return source.with_name(source.name.replace(".lock.yml", ".md"))


def markdown_output(source: Path) -> Path:
    return source.with_name(source.name.replace(".lock.yml", "-container.md"))


def generated_outputs(source: Path) -> list[tuple[Path, str]]:
    md_source = markdown_source(source)
    if not md_source.exists():
        raise FileNotFoundError(md_source)
    lock_output = source.with_name(source.name.replace(".lock.yml", "-container.lock.yml"))
    return [
        (lock_output, transform(source)),
        (markdown_output(source), md_source.read_text()),
    ]


def sources() -> list[Path]:
    return [WORKFLOWS_DIR / name for name in ENGINES]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if generated siblings are not up to date")
    args = parser.parse_args()

    failed = False
    for source in sources():
        if not source.exists():
            raise FileNotFoundError(source)
        for output, generated in generated_outputs(source):
            if args.check:
                existing = output.read_text() if output.exists() else ""
                if existing != generated:
                    failed = True
                    diff = difflib.unified_diff(
                        existing.splitlines(keepends=True),
                        generated.splitlines(keepends=True),
                        fromfile=str(output),
                        tofile=f"{output} (expected)",
                    )
                    sys.stderr.writelines(diff)
            else:
                output.write_text(generated)
                print(f"wrote {output.relative_to(REPO_ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
