#!/usr/bin/env bash
# Validate the release manifest against the platform matrix and actual bytes.
set -euo pipefail
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo 'ERROR: Expected an artifact directory and optional target matrix. Example: bash scripts/validate-release-checksums.sh dist release-targets.txt' >&2
  exit 1
fi
artifact_dir=$1
targets_file=${2:-$repo_root/release-targets.txt}

# Parse the matrix first, including when it is empty (NR == FNR is unsafe then).
awk '
  function fail(message) {
    print "ERROR: " message > "/dev/stderr"
    bad = 1
  }
  FILENAME == ARGV[1] {
    if ($0 ~ /^[[:space:]]*(#|$)/) next
    if (NF != 3 || $3 !~ /^threat-detect-[a-z0-9-]+$/) {
      fail("Invalid release target. Expected <goos> <goarch> <asset>, for example linux amd64 threat-detect-linux-amd64.")
      next
    }
    if (platforms[$1 "/" $2]++) fail("Duplicate release platform: " $1 "/" $2)
    if (assets[$3]++) fail("Duplicate release asset: " $3)
    count++
    next
  }
  {
    # Match the exact sha256sum text-mode format used by release generation.
    if (length($1) != 64 || $1 ~ /[^0-9a-f]/ || NF != 2 || $0 != $1 "  " $2) {
      fail("Invalid checksum line " FNR ". Expected 64 lowercase hexadecimal characters, two spaces, and a release asset name.")
      next
    }
    if (!($2 in assets)) fail("Unexpected checksum asset: " $2)
    if (seen[$2]++) fail("Duplicate checksum asset: " $2)
  }
  END {
    if (!count) fail("Release target matrix is empty. Expected at least one platform asset.")
    for (asset in assets) if (!(asset in seen)) fail("Missing checksum asset: " asset)
    exit bad ? 1 : 0
  }
' "$targets_file" "$artifact_dir/checksums.txt"

if [[ "$(tail -c 1 "$artifact_dir/checksums.txt" | od -An -tu1 | tr -d '[:space:]')" != 10 ]]; then
  echo 'ERROR: Checksum manifest must end with a newline. Regenerate it with sha256sum.' >&2
  exit 1
fi

# Only hash after validating the manifest filenames against the trusted matrix.
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$artifact_dir" && sha256sum --check checksums.txt)
else
  (cd "$artifact_dir" && shasum -a 256 --check checksums.txt)
fi
