#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
targets_file="${RELEASE_TARGETS_FILE:-${repo_root}/release-targets.txt}"
installer_file="${1:-}"
temp_dir=""

if [ -z "$installer_file" ]; then
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' EXIT
  installer_file="${temp_dir}/install_threat_detect_binary.sh"
  curl -fsSL --retry 3 --retry-all-errors \
    "https://raw.githubusercontent.com/github/gh-aw/main/actions/setup/sh/install_threat_detect_binary.sh" \
    -o "$installer_file"
fi

manifest_targets="$(
  awk '
    /^[[:space:]]*(#|$)/ { next }
    NF != 3 {
      printf "invalid release target at line %d: expected <goos> <goarch> <asset>\n", NR > "/dev/stderr"
      exit 1
    }
    {
      platform = $1 "/" $2
      if (platforms[platform]++) {
        printf "duplicate release platform at line %d: %s\n", NR, platform > "/dev/stderr"
        exit 1
      }
      if (assets[$3]++) {
        printf "duplicate release asset at line %d: %s\n", NR, $3 > "/dev/stderr"
        exit 1
      }
      print $1, $2, $3
    }
  ' "$targets_file" | sort
)"

installer_targets="$(
  awk '
    function canonical_arch(pattern) {
      if (pattern ~ /x86_64|amd64/) {
        return "amd64"
      }
      if (pattern ~ /aarch64|arm64/) {
        return "arm64"
      }
      return ""
    }

    /^install_linux_binary\(\)/ {
      function_os = "linux"
      arch = ""
      next
    }
    /^install_darwin_binary\(\)/ {
      function_os = "darwin"
      arch = ""
      next
    }
    function_os != "" && /^}/ {
      function_os = ""
      next
    }
    function_os != "" && /\)/ {
      arch_pattern = $0
      sub(/\).*/, "", arch_pattern)
      sub(/^[[:space:]]*/, "", arch_pattern)
      arch = canonical_arch(arch_pattern)
    }
    function_os != "" && /binary_name="threat-detect-[^"]+"/ {
      if (arch == "") {
        printf "unsupported installer architecture mapping: %s\n", $0 > "/dev/stderr"
        exit 1
      }

      asset = $0
      sub(/.*binary_name="/, "", asset)
      sub(/".*/, "", asset)
      print function_os, arch, asset
      mapped[function_os] = 1
    }

    /^[[:space:]]*install_linux_binary([[:space:]]|$)/ {
      reachable["linux"] = 1
    }
    /^[[:space:]]*install_darwin_binary([[:space:]]|$)/ {
      reachable["darwin"] = 1
    }

    END {
      for (os in mapped) {
        if (!reachable[os]) {
          printf "installer does not call the %s install function. Check upstream platform dispatch before publishing this mapping.\n", os > "/dev/stderr"
          exit 1
        }
      }
    }
  ' "$installer_file" | sort -u
)"

if [ -z "$manifest_targets" ]; then
  echo "ERROR: no release targets found in ${targets_file}" >&2
  exit 1
fi
if [ -z "$installer_targets" ]; then
  echo "ERROR: no supported platform mappings found in ${installer_file}" >&2
  exit 1
fi

# gh-aw may support fewer platforms than the standalone detector. Every asset
# it requests must exist, but standalone-only assets (such as macOS) are valid.
missing_targets="$(comm -23 <(printf '%s\n' "$installer_targets") <(printf '%s\n' "$manifest_targets"))"
if [ -n "$missing_targets" ]; then
  echo "ERROR: gh-aw installer requests unpublished release targets:" >&2
  printf '%s\n' "$missing_targets" >&2
  echo "Add these mappings to release-targets.txt and publish the corresponding assets, or correct the upstream installer." >&2
  exit 1
fi

echo "All gh-aw installer platform mappings are published release targets:"
while IFS= read -r target; do
  printf '  %s\n' "$target"
done <<< "$installer_targets"
