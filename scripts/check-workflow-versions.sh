#!/usr/bin/env bash
#
# check-workflow-versions.sh — read-only version drift check for the compiled
# agentic workflow lock files in .github/workflows/.
#
# It does NOT build or compile anything. It reads the versions already baked
# into each `*.lock.yml` and compares them against the versions each workflow
# *category* is supposed to track:
#
#   standard          → latest STABLE github/gh-aw release
#   standalone smoke  → latest github/gh-aw release OR prerelease (newest of either)
#   standalone latest → latest github/gh-aw release OR prerelease
#                       AND latest github/gh-aw-threat-detection release OR prerelease
#
# Category is inferred from the lock filename:
#   *-standalone-latest.lock.yml → standalone latest
#   *-standalone.lock.yml        → standalone smoke
#   everything else *.lock.yml    → standard
#
# Target versions are resolved via `gh` unless supplied through the environment
# (handy for local testing / CI without network):
#   GH_AW_STABLE_VERSION    latest stable gh-aw tag       (e.g. v0.83.4)
#   GH_AW_LATEST_VERSION    latest gh-aw tag (pre|stable) (e.g. v0.84.0-rc1)
#   DETECTOR_LATEST_VERSION latest detector tag (pre|stable)
#
# Flags:
#   --output <path>        write the Markdown issue body here (default: none)
#   --workflows-dir <dir>  directory of lock files (default: .github/workflows)
#
# Outputs:
#   * A human-readable report on stdout.
#   * A Markdown issue body to --output (only when drift is detected).
#   * `drift=true|false` appended to $GITHUB_OUTPUT when that env var is set.
#
# Exit codes:
#   0  success (check ran; inspect drift= to know the result)
#   2  infrastructure/configuration error
set -euo pipefail

GH_AW_REPO="github/gh-aw"
DETECTOR_REPO="github/gh-aw-threat-detection"
SKILL_URL="https://github.com/${DETECTOR_REPO}/blob/main/skills/update-workflow-versions/SKILL.md"

workflows_dir=".github/workflows"
output_file=""

die() { echo "::error::$*" >&2; exit 2; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output_file="${2:?--output needs a path}"; shift 2 ;;
    --workflows-dir) workflows_dir="${2:?--workflows-dir needs a path}"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -d "$workflows_dir" ] || die "workflows dir not found: $workflows_dir"

# newest_tag <repo> <include_prereleases:true|false>
# Prints the newest release tag (by publish date) whose name looks like a
# semantic version (v<digit>...), excluding drafts and rolling refs. gh-aw and
# the detector both have >100 releases, so paginate everything.
newest_tag() {
  local repo="$1" include_pre="$2" filter
  if [ "$include_pre" = "true" ]; then
    filter='select(.draft == false)'
  else
    filter='select(.draft == false and .prerelease == false)'
  fi
  gh api "repos/${repo}/releases" --paginate \
    --jq ".[] | ${filter} | select(.tag_name | test(\"^v[0-9]\")) | [.published_at, .tag_name] | @tsv" \
    | sort | tail -n1 | cut -f2
}

resolve_or_die() {
  local val="$1" what="$2"
  if [ -z "$val" ] || [ "$val" = "null" ]; then
    die "could not resolve $what"
  fi
  printf '%s' "$val"
}

gh_aw_stable="${GH_AW_STABLE_VERSION:-}"
gh_aw_latest="${GH_AW_LATEST_VERSION:-}"
detector_latest="${DETECTOR_LATEST_VERSION:-}"

[ -n "$gh_aw_stable" ]    || gh_aw_stable="$(newest_tag "$GH_AW_REPO" false)"
[ -n "$gh_aw_latest" ]    || gh_aw_latest="$(newest_tag "$GH_AW_REPO" true)"
[ -n "$detector_latest" ] || detector_latest="$(newest_tag "$DETECTOR_REPO" true)"

gh_aw_stable="$(resolve_or_die "$gh_aw_stable" "latest stable ${GH_AW_REPO} release")"
gh_aw_latest="$(resolve_or_die "$gh_aw_latest" "latest ${GH_AW_REPO} (pre)release")"
detector_latest="$(resolve_or_die "$detector_latest" "latest ${DETECTOR_REPO} (pre)release")"

echo "Target versions:"
echo "  gh-aw (stable)   : $gh_aw_stable"
echo "  gh-aw (latest)   : $gh_aw_latest"
echo "  detector (latest): $detector_latest"
echo

# Extract the gh-aw compiler version baked into a lock file.
lock_compiler_version() {
  grep -o '"compiler_version":"[^"]*"' "$1" | head -n1 | sed 's/.*:"//;s/"//'
}

# Extract the detector version pinned by install_threat_detect_binary.sh.
lock_detector_version() {
  sed -nE 's/.*install_threat_detect_binary\.sh"[[:space:]]+([vV][0-9][^"[:space:]]*).*/\1/p' "$1" | head -n1
}

# Drift rows, tab-separated: workflow \t category \t field \t current \t target
drift_rows=""
add_row() { drift_rows+="${1}"$'\t'"${2}"$'\t'"${3}"$'\t'"${4}"$'\t'"${5}"$'\n'; }

shopt -s nullglob
lock_files=("$workflows_dir"/*.lock.yml)
shopt -u nullglob
[ "${#lock_files[@]}" -gt 0 ] || die "no *.lock.yml files found in $workflows_dir"

checked=0
for lock in "${lock_files[@]}"; do
  base="$(basename "$lock" .lock.yml)"
  case "$base" in
    *-standalone-latest) category="standalone latest" ;;
    *-standalone)        category="standalone smoke" ;;
    *)                   category="standard" ;;
  esac

  cur_ghaw="$(lock_compiler_version "$lock" || true)"
  [ -n "$cur_ghaw" ] || die "no compiler_version found in $lock"
  checked=$((checked + 1))

  case "$category" in
    standard) want_ghaw="$gh_aw_stable" ;;
    *)        want_ghaw="$gh_aw_latest" ;;
  esac

  if [ "$cur_ghaw" != "$want_ghaw" ]; then
    add_row "$base" "$category" "gh-aw" "$cur_ghaw" "$want_ghaw"
    echo "DRIFT  $base [$category] gh-aw $cur_ghaw -> $want_ghaw"
  else
    echo "ok     $base [$category] gh-aw $cur_ghaw"
  fi

  if [ "$category" = "standalone latest" ]; then
    cur_det="$(lock_detector_version "$lock" || true)"
    [ -n "$cur_det" ] || die "no install_threat_detect_binary.sh version found in $lock"
    if [ "$cur_det" != "$detector_latest" ]; then
      add_row "$base" "$category" "detector" "$cur_det" "$detector_latest"
      echo "DRIFT  $base [$category] detector $cur_det -> $detector_latest"
    else
      echo "ok     $base [$category] detector $cur_det"
    fi
  fi
done

echo
echo "Checked $checked lock file(s)."

if [ -z "$drift_rows" ]; then
  echo "All workflow versions are up to date."
  [ -n "${GITHUB_OUTPUT:-}" ] && echo "drift=false" >> "$GITHUB_OUTPUT"
  exit 0
fi

echo "Version drift detected."
[ -n "${GITHUB_OUTPUT:-}" ] && echo "drift=true" >> "$GITHUB_OUTPUT"

if [ -n "$output_file" ]; then
  {
    echo "## Workflow version drift detected"
    echo
    echo "One or more compiled workflow \`.lock.yml\` files are pinned to an outdated version."
    echo
    echo "### Target versions"
    echo
    echo "| Category | Tracks | Version |"
    echo "|----------|--------|---------|"
    echo "| standard | latest **stable** \`${GH_AW_REPO}\` release | \`${gh_aw_stable}\` |"
    echo "| standalone smoke | latest \`${GH_AW_REPO}\` release **or prerelease** | \`${gh_aw_latest}\` |"
    echo "| standalone latest | latest \`${GH_AW_REPO}\` (pre)release + latest \`${DETECTOR_REPO}\` (pre)release | gh-aw \`${gh_aw_latest}\`, detector \`${detector_latest}\` |"
    echo
    echo "### Workflows needing an update"
    echo
    echo "| Workflow | Category | Field | Current | Target |"
    echo "|----------|----------|-------|---------|--------|"
    printf '%s' "$drift_rows" | while IFS=$'\t' read -r wf cat field cur tgt; do
      [ -n "$wf" ] || continue
      echo "| \`${wf}\` | ${cat} | ${field} | \`${cur}\` | \`${tgt}\` |"
    done
    echo
    echo "### How to fix"
    echo
    echo "Follow the **update-workflow-versions** skill to regenerate the affected locks:"
    echo
    echo "➡️ ${SKILL_URL}"
    echo
    echo "In short: recompile each affected \`.md\` with the target gh-aw version (and, for"
    echo "\`*-standalone-latest\`, the patched detector version), then open a PR with the"
    echo "regenerated \`.lock.yml\` files. A helper script is provided at"
    echo "\`scripts/recompile-workflows.sh\`."
    echo
    echo "<sub>Generated by \`.github/workflows/gh-aw-version-check.yml\`.</sub>"
  } > "$output_file"
  echo "Wrote issue body to $output_file"
fi

exit 0
