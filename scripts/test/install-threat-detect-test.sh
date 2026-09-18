#!/usr/bin/env bash
# Offline acquisition tests: real hashing and filesystem operations, stub network.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/tools" "$fixture/bin"
export fixture
cat > "$fixture/tools/uname" <<'SH'
#!/usr/bin/env bash
case "$1" in
  -s) printf '%s\n' "$TEST_OS" ;;
  -m) printf '%s\n' "$TEST_ARCH" ;;
esac
SH
cat > "$fixture/tools/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >> "$fixture/network"
[[ "$1 $2 $3" == 'release download v1.2.3' ]]
[[ "$4 $5 $6" == '--repo github/gh-aw-threat-detection --pattern' ]]
[[ "$7" == "$TEST_ASSET" && "$8" == --dir && $# == 9 ]]
[[ "${TEST_DOWNLOAD_FAIL:-0}" == 0 ]] || exit 1
cp "$fixture/payload" "$9/$7"
SH
cat > "$fixture/tools/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >> "$fixture/network"
[[ "$*" == *"--proto =https --proto-redir =https"* ]]
while [[ $# -gt 3 ]]; do shift; done
[[ "$1" == "https://mirror.example/detector/v1.2.3/$TEST_ASSET" && "$2" == -o ]]
[[ "${TEST_DOWNLOAD_FAIL:-0}" == 0 ]] || exit 1
cp "$fixture/payload" "$3"
SH
chmod +x "$fixture/tools/"*
export PATH="$fixture/tools:$PATH"
unset THREAT_DETECT_ARTIFACT_BASE_URL
printf '#!/bin/sh\nexit 99\n' > "$fixture/payload"
if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum "$fixture/payload")
else
  digest=$(shasum -a 256 "$fixture/payload")
fi
digest=${digest%% *}
while read -r os arch asset; do
  [[ "$os" == \#* || -z "$os" ]] && continue
  printf '%s  %s\n' "$digest" "$asset"
done < "$repo_root/release-targets.txt" > "$fixture/pins"

run_install() {
  bash "$repo_root/scripts/install-threat-detect.sh" "$@" > "$fixture/log" 2>&1
}
reject() {
  printf 'existing installation\n' > "$fixture/bin/threat-detect"
  if run_install "$@"; then
    printf 'FAIL: unexpectedly accepted %s\n' "$*" >&2
    exit 1
  fi
  [[ "$(cat "$fixture/bin/threat-detect")" == 'existing installation' ]]
  [[ -z "$(find "$fixture/bin" -name '.threat-detect.*' -print)" ]]
}

while read -r TEST_OS TEST_ARCH TEST_ASSET; do
  export TEST_OS TEST_ARCH TEST_ASSET
  run_install v1.2.3 "$fixture/pins" "$fixture/bin"
  cmp "$fixture/payload" "$fixture/bin/threat-detect"
  [[ -x "$fixture/bin/threat-detect" ]]
done <<'PLATFORMS'
Linux x86_64 threat-detect-linux-amd64
Linux amd64 threat-detect-linux-amd64
Linux aarch64 threat-detect-linux-arm64
Linux arm64 threat-detect-linux-arm64
Darwin x86_64 threat-detect-darwin-x64
Darwin amd64 threat-detect-darwin-x64
Darwin arm64 threat-detect-darwin-arm64
Darwin aarch64 threat-detect-darwin-arm64
PLATFORMS

export TEST_OS=Darwin TEST_ARCH=arm64 TEST_ASSET=threat-detect-darwin-arm64
export THREAT_DETECT_ARTIFACT_BASE_URL=https://mirror.example/detector/
run_install v1.2.3 "$fixture/pins" "$fixture/bin"
cmp "$fixture/payload" "$fixture/bin/threat-detect"
export TEST_DOWNLOAD_FAIL=1
reject v1.2.3 "$fixture/pins" "$fixture/bin"
unset THREAT_DETECT_ARTIFACT_BASE_URL
reject v1.2.3 "$fixture/pins" "$fixture/bin"
unset TEST_DOWNLOAD_FAIL

printf 'tampered binary\n' > "$fixture/payload"
reject v1.2.3 "$fixture/pins" "$fixture/bin"
export THREAT_DETECT_ARTIFACT_BASE_URL=https://mirror.example/detector
reject v1.2.3 "$fixture/pins" "$fixture/bin"
unset THREAT_DETECT_ARTIFACT_BASE_URL

# Validation failures must not even attempt a download.
: > "$fixture/network"
reject latest "$fixture/pins" "$fixture/bin"
reject v1.2.3 "$fixture/missing" "$fixture/bin"
: > "$fixture/bad-pins"
reject v1.2.3 "$fixture/bad-pins" "$fixture/bin"
printf '%s  %s\n%s  %s\n' "$digest" "$TEST_ASSET" "$digest" "$TEST_ASSET" > "$fixture/bad-pins"
reject v1.2.3 "$fixture/bad-pins" "$fixture/bin"
printf 'invalid  %s\n' "$TEST_ASSET" > "$fixture/bad-pins"
reject v1.2.3 "$fixture/bad-pins" "$fixture/bin"
printf '%s  other-asset\n' "$digest" > "$fixture/bad-pins"
reject v1.2.3 "$fixture/bad-pins" "$fixture/bin"
printf '%s  %s extra-field\n' "$digest" "$TEST_ASSET" > "$fixture/bad-pins"
reject v1.2.3 "$fixture/bad-pins" "$fixture/bin"
reject v1.2.3
export THREAT_DETECT_ARTIFACT_BASE_URL=http://mirror.example
reject v1.2.3 "$fixture/pins" "$fixture/bin"
unset THREAT_DETECT_ARTIFACT_BASE_URL
export TEST_ARCH=riscv64
reject v1.2.3 "$fixture/pins" "$fixture/bin"
export TEST_OS=Windows TEST_ARCH=x86_64
reject v1.2.3 "$fixture/pins" "$fixture/bin"
[[ ! -s "$fixture/network" ]]
printf 'PASS: independently pinned installation\n'
