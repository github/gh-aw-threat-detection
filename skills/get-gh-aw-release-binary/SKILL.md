---
name: get-gh-aw-release-binary
description: How to fetch the latest github/gh-aw release binary — either as the gh CLI extension (gh aw ...) or as a raw platform binary downloaded from GitHub Releases — including how to resolve the latest tag, pick the right asset, and verify its checksum.
---

# Getting the latest `github/gh-aw` release binary

Use this skill whenever you need the `gh-aw` compiler binary — for example to
recompile agentic workflow `.lock.yml` files (see the
[`update-workflow-versions`](../update-workflow-versions/SKILL.md) skill), to
reproduce a compiled workflow locally, or to run `gh aw` in CI.

`github/gh-aw` publishes two kinds of consumable artifacts on each GitHub
Release:

- **The `gh` CLI extension** — installed with `gh extension install github/gh-aw`
  and invoked as `gh aw ...`. This is the normal way to *use* the tool.
- **Raw platform binaries** — bare release assets named by GOOS/GOARCH
  (`linux-amd64`, `darwin-arm64`, …) plus a `checksums.txt`. Use these when you
  need the executable directly (no `gh`, or a pinned standalone binary).

No authentication is required to download from a **public** repository's
releases. In this environment TLS is already trusted (system CA bundle), so
`curl`, `gh`, and `go` work without extra flags.

## 1. Decide what "latest" means

`gh-aw` ships both **stable** releases and **prereleases**. Pick deliberately:

- **Latest stable** — the release GitHub marks as *Latest* (never a prerelease).
- **Latest overall** — the newest release *or* prerelease by publish date.

Resolve the tag (`vX.Y.Z`). Any method works; ignore drafts and rolling refs and
only accept tags matching `^v[0-9]`.

```bash
# Latest STABLE tag (the GitHub "Latest" release, excludes prereleases):
gh release view --repo github/gh-aw --json tagName --jq .tagName
# ...or without gh:
curl -fsSL https://api.github.com/repos/github/gh-aw/releases/latest \
  | grep -m1 '"tag_name"' | cut -d'"' -f4

# Latest OVERALL tag (newest release OR prerelease):
gh api repos/github/gh-aw/releases --paginate \
  --jq '.[] | select(.draft == false) | select(.tag_name | test("^v[0-9]")) | [.published_at, .tag_name] | @tsv' \
  | sort | tail -n1 | cut -f2
```

Refer to the chosen value below as `<TAG>` (e.g. `v0.83.4`).

> [!NOTE]
> `/releases/latest` and `gh release view` (no tag) return only the release
> flagged **Latest** — i.e. the newest **stable** one. To include prereleases you
> must list all releases and sort, as shown above.

## 2a. Install as the `gh` CLI extension (to run `gh aw`)

This is the right choice when you want to *run* the compiler.

```bash
# Latest available (stable) extension:
gh extension install github/gh-aw

# Pin to a specific tag (repeat with --force to switch versions):
gh extension install github/gh-aw --pin <TAG> --force

# Verify:
gh aw version        # -> "gh aw version <TAG>"

# Later, upgrade to the newest published extension:
gh extension upgrade gh-aw
```

The compiler baked-in version is what stamps `compiler_version` into generated
`.lock.yml` files, so pin the extension to the exact `<TAG>` you intend the
locks to track.

## 2b. Download the raw platform binary

Use this when you need the executable directly. Release assets are **bare**
GOOS/GOARCH names (no `gh-aw-` prefix):

| Platform            | Asset name           |
|---------------------|----------------------|
| Linux x86_64        | `linux-amd64`        |
| Linux arm64         | `linux-arm64`        |
| macOS Intel         | `darwin-amd64`       |
| macOS Apple Silicon | `darwin-arm64`       |
| Windows x86_64      | `windows-amd64.exe`  |
| Windows arm64       | `windows-arm64.exe`  |

Also published: `checksums.txt`, a WASM tarball (`gh-aw-wasm-<TAG>.tar.gz`), and
assorted `freebsd-*` / `android-*` builds.

Pick the asset for the current machine:

```bash
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)   ASSET=linux-amd64 ;;
  Linux-aarch64)  ASSET=linux-arm64 ;;
  Darwin-x86_64)  ASSET=darwin-amd64 ;;
  Darwin-arm64)   ASSET=darwin-arm64 ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
```

Download with `gh` (resolves the tag for you) …

```bash
gh release download <TAG> --repo github/gh-aw \
  --pattern "$ASSET" --pattern checksums.txt --dir /tmp/gh-aw-dl --clobber
```

… or with plain `curl` against the predictable asset URL:

```bash
BASE="https://github.com/github/gh-aw/releases/download/<TAG>"
mkdir -p /tmp/gh-aw-dl
curl -fsSL "$BASE/$ASSET"        -o /tmp/gh-aw-dl/"$ASSET"
curl -fsSL "$BASE/checksums.txt" -o /tmp/gh-aw-dl/checksums.txt
```

## 3. Verify the checksum

`checksums.txt` has one `sha256␠␠asset-name` line per asset.

```bash
cd /tmp/gh-aw-dl
# Verify just the asset you downloaded:
grep " $ASSET\$" checksums.txt | sha256sum -c -
# -> "<asset>: OK"
```

## 4. Make it executable and use it

```bash
install -m 0755 /tmp/gh-aw-dl/"$ASSET" /tmp/gh-aw
/tmp/gh-aw version        # confirm it matches <TAG>

# Example: compile workflows with the pinned binary
/tmp/gh-aw compile --action-mode action --action-tag <TAG> --no-check-update \
  .github/workflows/<file>.md
```

## Notes

- **Extension vs raw binary** produce the same compiler; use the extension to run
  `gh aw`, the raw binary when you need a standalone, pinnable executable.
- **Don't confuse repos.** This skill is about the **`github/gh-aw`** compiler.
  The **`threat-detect`** binary this repository ships is released separately from
  **`github/gh-aw-threat-detection`** (assets `threat-detect-linux-amd64` /
  `threat-detect-linux-arm64`); the same tag-resolution and checksum steps apply,
  only the repo and asset names differ.
- **Compiler version matters.** Whatever binary you compile with stamps its
  version into `.lock.yml` (`compiler_version`), which the **gh-aw Version Check**
  workflow validates — so match `<TAG>` to the version the locks should track.
