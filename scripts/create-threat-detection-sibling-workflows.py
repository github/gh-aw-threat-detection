#!/usr/bin/env python3
"""Create smoke workflow siblings that use this repo's detector container.

The sibling files are derived from gh-aw-generated *.lock.yml files. They keep the
compiled workflow structure intact, but replace the generated detection engine
steps with a detector binary extracted from ghcr.io/github/gh-aw-threat-detection
and executed under the same AWF wrapper as the source workflow.
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
    "smoke-copilot.lock.yml": ("copilot", "Smoke Copilot (Container Detection)"),
    "smoke-claude.lock.yml": ("claude", "Smoke Claude (Container Detection)"),
    "smoke-codex.lock.yml": ("codex", "Smoke Codex (Container Detection)"),
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


def extract_awf_lines(text: str) -> tuple[str, str]:
    config_line = ""
    awf_line = ""
    for line in text.splitlines():
        if line.startswith("          printf '%s\\n' ") and "gh-aw-firewall" in line:
            config_line = line
        if line.startswith("          sudo -E awf ") and line.rstrip().endswith("\\"):
            awf_line = line
    if not config_line or not awf_line:
        raise ValueError("could not find generated AWF setup lines")
    return config_line.strip(), awf_line.strip()


def engine_env(engine: str) -> str:
    if engine == "copilot":
        return """COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_GITHUB_TOKEN || secrets.GH_AW_COPILOT_TOKEN || secrets.GH_AW_GITHUB_TOKEN }}"""
    if engine == "claude":
        return """ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}"""
    if engine == "codex":
        return """CODEX_API_KEY: ${{ secrets.CODEX_API_KEY || secrets.OPENAI_API_KEY }}"""
    raise ValueError(f"unsupported engine: {engine}")


def replacement_steps(engine: str, workflow_description: str, awf_config_line: str, awf_command_line: str) -> str:
    detector_command = (
        'export PATH="$(find /opt/hostedtoolcache /home/runner/work/_tool -maxdepth 4 -type d -name bin '
        '2>/dev/null | paste -sd: -):$PATH"; '
        '[ -n "$GOROOT" ] && export PATH="$GOROOT/bin:$PATH" || true; '
        f"args=(--engine {engine}); "
        'if [ -n "${THREAT_DETECTION_MODEL:-}" ]; then args+=(--model "$THREAT_DETECTION_MODEL"); fi; '
        '/tmp/gh-aw/threat-detect-bin/threat-detect "${args[@]}" /tmp/gh-aw/threat-detection'
    )
    shell = f'''- name: Ensure threat-detection directory and log
  if: always() && steps.detection_guard.outputs.run_detection == 'true'
  run: |
    mkdir -p /tmp/gh-aw/threat-detection /tmp/gh-aw/threat-detect-bin
    touch /tmp/gh-aw/threat-detection/detection.log
- name: Log in to GHCR for detector image
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
    container_id="$(docker create "$THREAT_DETECTION_IMAGE")"
    trap 'docker rm -f "$container_id" >/dev/null 2>&1 || true' EXIT
    docker cp "$container_id:/usr/local/bin/threat-detect" /tmp/gh-aw/threat-detect-bin/threat-detect
    chmod 755 /tmp/gh-aw/threat-detect-bin/threat-detect
- name: Setup Node.js
  uses: actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6.4.0
  with:
    node-version: '24'
    package-manager-cache: false
- name: Install AWF binary
  run: bash "${{RUNNER_TEMP}}/gh-aw/actions/install_awf_binary.sh" v0.25.40
- name: Execute threat detection with AWF
  if: always() && steps.detection_guard.outputs.run_detection == 'true'
  continue-on-error: true
  id: detection_agentic_execution
  timeout-minutes: 20
  env:
{indent(engine_env(engine), 4)}
    THREAT_DETECTION_MODEL: ${{{{ vars.GH_AW_MODEL_DETECTION_{engine.upper()} || '' }}}}
    WORKFLOW_DESCRIPTION: {workflow_description}
    WORKFLOW_NAME: ${{{{ github.workflow }}}}
  run: |
    set -o pipefail
    touch /tmp/gh-aw/agent-step-summary.md
    (umask 177 && touch /tmp/gh-aw/threat-detection/detection.log)
{indent(awf_config_line, 4)}
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
    awf_config_line, awf_command_line = extract_awf_lines(text)

    start = re.search(r"^      - name: Setup threat detection\n", text, flags=re.MULTILINE)
    end = re.search(r"^      - name: Upload threat detection log\n", text, flags=re.MULTILINE)
    if not start or not end or start.start() >= end.start():
        raise ValueError(f"could not find generated detection step range in {source}")

    header = (
        f"# gh-aw-threat-detection-sibling: generated from {source.name} by "
        "scripts/create-threat-detection-sibling-workflows.py\n"
    )
    body = text[: start.start()] + replacement_steps(engine, workflow_description, awf_config_line, awf_command_line) + "\n" + text[end.start():]
    lines = body.splitlines()
    insert_at = 2 if lines and lines[0].startswith("# gh-aw-metadata:") else 0
    lines.insert(insert_at, header.rstrip("\n"))
    return "\n".join(lines) + "\n"


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
        output = source.with_name(source.name.replace(".lock.yml", "-container.lock.yml"))
        generated = transform(source)
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
