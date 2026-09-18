#!/usr/bin/env bash
# Install a release asset using a checksum file supplied by the trusted caller.
set -euo pipefail

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

if [[ $# != 3 ]]; then
  fail 'Expected a release tag, trusted checksum file, and install directory. Example: bash scripts/install-threat-detect.sh v1.2.3 pins/v1.2.3.txt ./bin'
fi
version=$1
pins=$2
destination=$3
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$ ]] ||
  fail 'Invalid release tag. Expected an explicit version, for example v1.2.3; latest is not supported.'
[[ -f "$pins" && -r "$pins" ]] || fail 'Cannot read trusted checksum file. Supply a reviewed local file, for example pins/v1.2.3.txt.'
[[ -n "$destination" ]] || fail 'Install directory is empty. Supply a directory, for example ./bin.'

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64|Linux/amd64) asset=threat-detect-linux-amd64 ;;
  Linux/aarch64|Linux/arm64) asset=threat-detect-linux-arm64 ;;
  Darwin/x86_64|Darwin/amd64) asset=threat-detect-darwin-x64 ;;
  Darwin/aarch64|Darwin/arm64) asset=threat-detect-darwin-arm64 ;;
  *) fail 'Unsupported platform. Expected Linux or macOS on amd64 or arm64.' ;;
esac

# Reject missing, duplicate, and malformed entries before any network request.
# Never fetch the pins from the binary's release or mirror at install time.
digest=$(awk -v asset="$asset" '
  /^[[:space:]]*(#|$)/ { next }
  {
    name = $2
    sub(/^\*/, "", name)
    if (NF != 2 || length($1) != 64 || $1 ~ /[^[:xdigit:]]/) bad = 1
    if (name == asset) { count++; digest = tolower($1) }
  }
  END {
    if (bad || count != 1) exit 1
    print digest
  }
' "$pins") || fail 'Invalid trusted checksum file: require exactly one SHA-256 entry for the selected asset and valid checksum lines. See README.md, Independently pinned installation.'

if command -v sha256sum >/dev/null 2>&1; then
  hash=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash=(shasum -a 256)
else
  fail 'SHA-256 tool missing. Install sha256sum or shasum before installing the detector.'
fi

# A mirror base contains version directories with the original asset names.
if [[ -n "${THREAT_DETECT_ARTIFACT_BASE_URL:-}" ]]; then
  [[ "$THREAT_DETECT_ARTIFACT_BASE_URL" == https://?* && "$THREAT_DETECT_ARTIFACT_BASE_URL" != *[\?\#]* ]] ||
    fail 'Invalid artifact base URL. Expected HTTPS without query or fragment, for example https://artifacts.example.org/threat-detect.'
fi
mkdir -p "$destination"
[[ ! -d "$destination/threat-detect" ]] || fail 'Install target is a directory. Expected a file at <install-directory>/threat-detect.'
# Stage on the destination filesystem for atomic replacement; never execute it.
staging=$(mktemp -d "$destination/.threat-detect.XXXXXXXX")
trap 'rm -rf "$staging"' EXIT
if [[ -n "${THREAT_DETECT_ARTIFACT_BASE_URL:-}" ]]; then
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --retry 3 --connect-timeout 30 --max-time 300 \
    "${THREAT_DETECT_ARTIFACT_BASE_URL%/}/$version/$asset" -o "$staging/$asset"
else
  gh release download "$version" --repo github/gh-aw-threat-detection \
    --pattern "$asset" --dir "$staging"
fi
actual=$("${hash[@]}" "$staging/$asset")
actual=${actual%% *}
[[ "$actual" == "$digest" ]] || fail 'Checksum mismatch. Installation refused; verify the release and independently reviewed checksum pin before retrying.'
chmod 0755 "$staging/$asset"
mv -f "$staging/$asset" "$destination/threat-detect"
printf 'Installed %s (%s) with independently supplied SHA-256 verification.\n' "$version" "$asset" >&2
