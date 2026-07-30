#!/usr/bin/env bash
#
# recompile-workflows.sh — regenerate the compiled agentic workflow `.lock.yml`
# files so each category tracks its intended versions:
#
#   standard          → latest STABLE github/gh-aw release
#   standalone smoke  → latest github/gh-aw release OR prerelease
#   standalone latest → latest github/gh-aw (pre)release, compiled by a gh-aw
#                       whose DefaultThreatDetectVersion constant is patched to
#                       the latest github/gh-aw-threat-detection (pre)release
#
# This is the "do the recompiles" helper referenced by the
# update-workflow-versions skill. It builds the gh-aw compiler from source (no
# gh extension required) so it can patch the detector constant for the *latest*
# workflows exactly as production would embed a newer detector.
#
# Target versions are resolved via `gh` unless overridden:
#   --gh-aw-stable <tag>   latest stable gh-aw tag        (default: resolved)
#   --gh-aw-latest <tag>   latest gh-aw (pre)release tag  (default: resolved)
#   --detector     <tag>   latest detector (pre)release   (default: resolved)
#   --category <standard|smoke|latest|all>  which set to recompile (default: all)
#   --workflows-dir <dir>  default: .github/workflows
#
# Requires: git, go, gh (for version resolution only). Run from the repo root.
# It only rewrites *.lock.yml under the workspace — review and commit the diff
# yourself. Pushing workflow-file changes needs a token with the `workflows`
# permission.
set -euo pipefail

GH_AW_REPO="github/gh-aw"
DETECTOR_REPO="github/gh-aw-threat-detection"

workflows_dir=".github/workflows"
category="all"
gh_aw_stable="${GH_AW_STABLE_VERSION:-}"
gh_aw_latest="${GH_AW_LATEST_VERSION:-}"
detector_latest="${DETECTOR_LATEST_VERSION:-}"

die() { echo "error: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --gh-aw-stable) gh_aw_stable="${2:?}"; shift 2 ;;
    --gh-aw-latest) gh_aw_latest="${2:?}"; shift 2 ;;
    --detector)     detector_latest="${2:?}"; shift 2 ;;
    --category)     category="${2:?}"; shift 2 ;;
    --workflows-dir) workflows_dir="${2:?}"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$category" in standard|smoke|latest|all) ;; *) die "invalid --category: $category" ;; esac
command -v git >/dev/null || die "git is required"
command -v go  >/dev/null || die "go is required"

newest_tag() {
  local repo="$1" include_pre="$2" filter
  if [ "$include_pre" = "true" ]; then filter='select(.draft == false)';
  else filter='select(.draft == false and .prerelease == false)'; fi
  gh api "repos/${repo}/releases" --paginate \
    --jq ".[] | ${filter} | select(.tag_name | test(\"^v[0-9]\")) | [.published_at, .tag_name] | @tsv" \
    | sort | tail -n1 | cut -f2
}

need_stable=false; need_latest=false; need_detector=false
case "$category" in
  standard) need_stable=true ;;
  smoke)    need_latest=true ;;
  latest)   need_latest=true; need_detector=true ;;
  all)      need_stable=true; need_latest=true; need_detector=true ;;
esac

if [ "$need_stable" = true ] && [ -z "$gh_aw_stable" ]; then gh_aw_stable="$(newest_tag "$GH_AW_REPO" false)"; fi
if [ "$need_latest" = true ] && [ -z "$gh_aw_latest" ]; then gh_aw_latest="$(newest_tag "$GH_AW_REPO" true)"; fi
if [ "$need_detector" = true ] && [ -z "$detector_latest" ]; then detector_latest="$(newest_tag "$DETECTOR_REPO" true)"; fi

echo "Recompile plan (category: $category)"
[ "$need_stable" = true ]   && echo "  standard          -> gh-aw $gh_aw_stable"
[ "$need_latest" = true ]   && echo "  standalone smoke  -> gh-aw $gh_aw_latest"
[ "$need_detector" = true ] && echo "  standalone latest -> gh-aw $gh_aw_latest + detector $detector_latest"
echo

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# build_gh_aw <ref> <detector_or_empty> -> echoes path to the built binary.
build_gh_aw() {
  local ref="$1" detector="$2" src bin
  local key="${ref}${detector:+_$detector}"
  src="${workdir}/src-${key//[^A-Za-z0-9_.-]/_}"
  bin="${workdir}/gh-aw-${key//[^A-Za-z0-9_.-]/_}"
  if [ -x "$bin" ]; then echo "$bin"; return; fi

  mkdir -p "$src"
  git -C "$src" init -q
  git -C "$src" remote add origin "https://github.com/${GH_AW_REPO}"
  git -C "$src" fetch -q --depth 1 origin "$ref"
  git -C "$src" checkout -q FETCH_HEAD

  if [ -n "$detector" ]; then
    local constFile="${src}/pkg/constants/version_constants.go"
    grep -q 'DefaultThreatDetectVersion Version =' "$constFile" \
      || die "DefaultThreatDetectVersion not found in $constFile (gh-aw layout changed?)"
    sed -i -E 's/(DefaultThreatDetectVersion Version = )"[^"]*"/\1"'"$detector"'"/' "$constFile"
    echo "  patched detector constant -> $detector" >&2
  fi

  ( cd "$src" && go build -ldflags "-s -w -X main.version=${ref}" -o "$bin" ./cmd/gh-aw ) >&2
  echo "$bin"
}

# compile_set <binary> <action_tag> <source globs...>
compile_set() {
  local bin="$1" action_tag="$2"; shift 2
  local sources=()
  local pat
  for pat in "$@"; do
    while IFS= read -r f; do sources+=("$f"); done < <(find "$workflows_dir" -maxdepth 1 -name "$pat" | sort)
  done
  if [ "${#sources[@]}" -eq 0 ]; then echo "  (no matching sources)"; return; fi
  printf '  compiling: %s\n' "${sources[@]}"
  "$bin" compile --action-mode action --action-tag "$action_tag" --no-check-update "${sources[@]}"
}

# Standard = agentic .md that is not a *-standalone* smoke source.
standard_sources() {
  find "$workflows_dir" -maxdepth 1 -name '*.md' ! -name '*-standalone*.md' -printf '%f\n' | sort
}

if [ "$category" = standard ] || [ "$category" = all ]; then
  echo "== standard =="
  mapfile -t std < <(standard_sources)
  if [ "${#std[@]}" -gt 0 ]; then
    bin="$(build_gh_aw "$gh_aw_stable" "")"
    compile_set "$bin" "$gh_aw_stable" "${std[@]}"
  else
    echo "  (no standard sources)"
  fi
  echo
fi

if [ "$category" = smoke ] || [ "$category" = all ]; then
  echo "== standalone smoke =="
  bin="$(build_gh_aw "$gh_aw_latest" "")"
  compile_set "$bin" "$gh_aw_latest" '*-standalone.md'
  echo
fi

if [ "$category" = latest ] || [ "$category" = all ]; then
  echo "== standalone latest =="
  bin="$(build_gh_aw "$gh_aw_latest" "$detector_latest")"
  compile_set "$bin" "$gh_aw_latest" '*-standalone-latest.md'
  echo
fi

echo "Done. Review the regenerated locks:"
echo "  git status --short -- $workflows_dir"
