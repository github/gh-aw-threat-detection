#!/usr/bin/env bash
# Offline fixtures cover both the legacy cross-platform and Linux-only installers.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
cp "$repo_root/release-targets.txt" "$fixture/targets"

check() {
  RELEASE_TARGETS_FILE="$fixture/targets" bash "$repo_root/scripts/check-release-platforms.sh" "$fixture/installer" >"$fixture/log" 2>&1
}
reject() {
  if check; then
    echo "FAIL: accepted $1" >&2
    exit 1
  fi
  if ! grep -q "$2" "$fixture/log"; then
    cat "$fixture/log" >&2
    echo "FAIL: wrong diagnostic for $1" >&2
    exit 1
  fi
}

cat >"$fixture/installer" <<'EOF'
install_linux_binary() {
  case "$ARCH" in
    x86_64|amd64)
      binary_name="threat-detect-linux-amd64"
      ;;
    aarch64|arm64)
      binary_name="threat-detect-linux-arm64"
      ;;
  esac
}
case "$OS" in
  Linux) ;;
  Darwin) exit 1 ;;
  *) exit 1 ;;
esac
install_linux_binary
EOF
# Current installer: Linux-only, multiline mappings, direct call after OS guard.
check
cp "$fixture/installer" "$fixture/current"
sed '/^install_linux_binary$/d' "$fixture/current" >"$fixture/installer"
reject 'uncalled installer function' 'does not call the linux install function'
sed 's/threat-detect-linux-arm64/threat-detect-linux-missing/' "$fixture/current" >"$fixture/installer"
reject 'unpublished asset' 'requests unpublished release targets'
sed 's/aarch64|arm64/riscv64/' "$fixture/current" >"$fixture/installer"
reject 'unknown architecture' 'unsupported installer architecture mapping'

cp "$fixture/current" "$fixture/installer"
sed '/linux arm64/d' "$repo_root/release-targets.txt" >"$fixture/targets"
reject 'missing release platform' 'requests unpublished release targets'
cat "$repo_root/release-targets.txt" "$repo_root/release-targets.txt" >"$fixture/targets"
reject 'duplicate release platform' 'duplicate release platform'
: >"$fixture/targets"
reject 'empty release matrix' 'no release targets found'
cp "$repo_root/release-targets.txt" "$fixture/targets"
: >"$fixture/installer"
reject 'empty installer' 'no supported platform mappings found'

cat >"$fixture/installer" <<'EOF'
install_linux_binary() {
  case "$ARCH" in
    x86_64|amd64) binary_name="threat-detect-linux-amd64" ;;
    aarch64|arm64) binary_name="threat-detect-linux-arm64" ;;
  esac
}
install_darwin_binary() {
  case "$ARCH" in
    x86_64|amd64) binary_name="threat-detect-darwin-x64" ;;
    aarch64|arm64) binary_name="threat-detect-darwin-arm64" ;;
  esac
}
case "$OS" in
  Linux)
    install_linux_binary
    ;;
  Darwin)
    install_darwin_binary
    ;;
esac
EOF
# Legacy installer: same-line mappings and per-OS dispatch.
check
sed '/^[[:space:]]*install_darwin_binary$/d' "$fixture/installer" >"$fixture/no-darwin-call"
cp "$fixture/no-darwin-call" "$fixture/installer"
reject 'uncalled Darwin function' 'does not call the darwin install function'
echo 'PASS: release platform checks'
