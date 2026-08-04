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
      next
    }
    /^install_darwin_binary\(\)/ {
      function_os = "darwin"
      next
    }
    function_os != "" && /^}/ {
      function_os = ""
      next
    }
    function_os != "" && /binary_name="threat-detect-[^"]+"/ {
      arch_pattern = $0
      sub(/\).*/, "", arch_pattern)
      sub(/^[[:space:]]*/, "", arch_pattern)
      arch = canonical_arch(arch_pattern)
      if (arch == "") {
        printf "unsupported installer architecture mapping: %s\n", $0 > "/dev/stderr"
        exit 1
      }

      asset = $0
      sub(/.*binary_name="/, "", asset)
      sub(/".*/, "", asset)
      print function_os, arch, asset
    }

    /^case "\$OS" in/ {
      in_os_dispatch = 1
      next
    }
    in_os_dispatch && /^[[:space:]]*Linux\)/ {
      dispatch_os = "linux"
      next
    }
    in_os_dispatch && /^[[:space:]]*Darwin\)/ {
      dispatch_os = "darwin"
      next
    }
    in_os_dispatch && dispatch_os == "linux" && /^[[:space:]]*install_linux_binary/ {
      reachable["linux"] = 1
      dispatch_os = ""
      next
    }
    in_os_dispatch && dispatch_os == "darwin" && /^[[:space:]]*install_darwin_binary/ {
      reachable["darwin"] = 1
      dispatch_os = ""
      next
    }

    END {
      if (!reachable["linux"] || !reachable["darwin"]) {
        print "installer does not dispatch both Linux and Darwin install functions" > "/dev/stderr"
        exit 1
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

if ! diff -u \
  <(printf '%s\n' "$installer_targets") \
  <(printf '%s\n' "$manifest_targets"); then
  echo "ERROR: gh-aw installer platform mappings and release targets differ" >&2
  exit 1
fi

echo "Release targets match gh-aw installer platform mappings:"
while IFS= read -r target; do
  printf '  %s\n' "$target"
done <<< "$manifest_targets"
