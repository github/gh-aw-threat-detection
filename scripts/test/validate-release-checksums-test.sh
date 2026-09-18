#!/usr/bin/env bash
# Offline contract tests use real hashes and no engine or network access.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir "$fixture/dist"
cp "$repo_root/release-targets.txt" "$fixture/targets"
if command -v sha256sum >/dev/null 2>&1; then
  hash=(sha256sum)
else
  hash=(shasum -a 256)
fi
while read -r os arch asset; do
  [[ -z "$os" || "$os" == \#* ]] && continue
  printf 'fixture for %s/%s\n' "$os" "$arch" > "$fixture/dist/$asset"
done < "$fixture/targets"
(cd "$fixture/dist" && "${hash[@]}" threat-detect-*) > "$fixture/valid"
cp "$fixture/valid" "$fixture/dist/checksums.txt"

validate() {
  bash "$repo_root/scripts/validate-release-checksums.sh" "$fixture/dist" "$fixture/targets" > "$fixture/log" 2>&1
}
reject() {
  if validate; then
    printf 'FAIL: accepted %s\n' "$1" >&2
    exit 1
  fi
  if ! grep -q "$2" "$fixture/log"; then
    cat "$fixture/log" >&2
    printf 'FAIL: wrong diagnostic for %s\n' "$1" >&2
    exit 1
  fi
}
validate
# The default matrix path works independently of the caller's working directory.
(cd "$fixture" && bash "$repo_root/scripts/validate-release-checksums.sh" dist) > "$fixture/log"
sort -r "$fixture/valid" > "$fixture/dist/checksums.txt"
validate

: > "$fixture/dist/checksums.txt"
reject 'empty manifest' 'Missing checksum asset'
sed '1d' "$fixture/valid" > "$fixture/dist/checksums.txt"
reject 'missing platform' 'Missing checksum asset'
cat "$fixture/valid" "$fixture/valid" > "$fixture/dist/checksums.txt"
reject 'duplicate platform' 'Duplicate checksum asset'
sed '1s/threat-detect-/unexpected-/' "$fixture/valid" > "$fixture/dist/checksums.txt"
reject 'unexpected asset' 'Unexpected checksum asset'
sed '1s/^./g/' "$fixture/valid" > "$fixture/dist/checksums.txt"
reject 'nonhex digest' 'Invalid checksum line'
sed '1s/^.//' "$fixture/valid" > "$fixture/dist/checksums.txt"
reject 'short digest' 'Invalid checksum line'
tr 'abcdef' 'ABCDEF' < "$fixture/valid" > "$fixture/dist/checksums.txt"
reject 'uppercase digest' 'Invalid checksum line'
sed '1s/  / /' "$fixture/valid" > "$fixture/dist/checksums.txt"
reject 'wrong separator' 'Invalid checksum line'
sed '1s/$/ extra/' "$fixture/valid" > "$fixture/dist/checksums.txt"
reject 'extra field' 'Invalid checksum line'
sed '1s|  |  ../|' "$fixture/valid" > "$fixture/dist/checksums.txt"
reject 'path traversal' 'Unexpected checksum asset'
printf '%s' "$(cat "$fixture/valid")" > "$fixture/dist/checksums.txt"
reject 'missing final newline' 'must end with a newline'

cp "$fixture/valid" "$fixture/dist/checksums.txt"
: > "$fixture/targets"
reject 'empty matrix' 'Release target matrix is empty'
cat "$repo_root/release-targets.txt" "$repo_root/release-targets.txt" > "$fixture/targets"
reject 'duplicate matrix' 'Duplicate release'
printf 'linux amd64 ../binary\n' > "$fixture/targets"
reject 'malformed matrix' 'Invalid release target'
cp "$repo_root/release-targets.txt" "$fixture/targets"
printf 'tampered\n' > "$fixture/dist/threat-detect-linux-amd64"
reject 'digest mismatch' 'FAILED'
printf 'fixture for linux/amd64\n' > "$fixture/dist/threat-detect-linux-amd64"
mv "$fixture/dist/threat-detect-linux-arm64" "$fixture/absent"
reject 'missing binary' 'threat-detect-linux-arm64'
mv "$fixture/dist/checksums.txt" "$fixture/absent-checksums"
reject 'missing manifest' 'checksums.txt'
printf 'PASS: release checksum contract\n'
