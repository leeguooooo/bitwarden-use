#!/bin/sh
# bitwarden-use installer — downloads a prebuilt binary from the latest GitHub
# Release (no npm, no token). Usage:
#   curl -fsSL https://raw.githubusercontent.com/leeguooooo/bitwarden-use/main/install.sh | sh
# Override install dir:  BITWARDEN_INSTALL_DIR=/usr/local/bin sh install.sh
# Pin a version:         BITWARDEN_VERSION=v0.2.0 sh install.sh
set -eu

REPO="leeguooooo/bitwarden-use"
BIN="bitwarden-use"
AGENT="bitwarden-use-agent"
INSTALL_DIR="${BITWARDEN_INSTALL_DIR:-$HOME/.local/bin}"

err() { printf 'install: %s\n' "$1" >&2; exit 1; }

os="$(uname -s)"
arch="$(uname -m)"
case "$os-$arch" in
  Darwin-arm64)        target="aarch64-apple-darwin" ;;
  Darwin-x86_64)       target="x86_64-apple-darwin" ;;
  Linux-x86_64)        target="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64|Linux-arm64) target="aarch64-unknown-linux-gnu" ;;
  *) err "unsupported platform: $os-$arch" ;;
esac

ver="${BITWARDEN_VERSION:-latest}"
if [ "$ver" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$ver"
fi
asset="$BIN-$target.tar.gz"
url="$base/$asset"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

printf 'install: downloading %s\n' "$url" >&2
curl -fsSL "$url" -o "$tmp/$asset" || err "download failed ($url)"

# A missing checksum is a failed install, never permission to skip verification.
curl -fsSL "$url.sha256" -o "$tmp/$asset.sha256" || err "checksum download failed"
want="$(awk 'NR == 1 {print $1}' "$tmp/$asset.sha256")"
[ "${#want}" -eq 64 ] || err "invalid checksum file"
case "$want" in *[!0-9a-fA-F]*) err "invalid checksum file" ;; esac
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
else
  got="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
fi
[ "$want" = "$got" ] || err "checksum mismatch"
printf 'install: checksum ok\n' >&2

tar xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$INSTALL_DIR"
# Validate the entire pair before replacing either executable. Rename avoids
# modifying an executable inode that another process is currently running.
[ -f "$tmp/$BIN-$target/$BIN" ] && [ ! -L "$tmp/$BIN-$target/$BIN" ] || err "CLI missing from archive"
[ -f "$tmp/$BIN-$target/$AGENT" ] && [ ! -L "$tmp/$BIN-$target/$AGENT" ] || err "agent missing from archive"
"$tmp/$BIN-$target/$BIN" --version >/dev/null || err "downloaded CLI cannot run"
"$tmp/$BIN-$target/$BIN" set --help >/dev/null || err "downloaded CLI lacks field updates"
stage="$(mktemp -d "$INSTALL_DIR/.bwu-install.XXXXXX")"
trap 'rm -rf "$tmp" "$stage"' EXIT
install -m 0755 "$tmp/$BIN-$target/$BIN" "$stage/$BIN"
install -m 0755 "$tmp/$BIN-$target/$AGENT" "$stage/$AGENT"
mv -f "$stage/$AGENT" "$INSTALL_DIR/$AGENT"
mv -f "$stage/$BIN" "$INSTALL_DIR/$BIN"
# short alias `bwu` -> bitwarden-use (typing the full name gets old)
ln -sf "$BIN" "$INSTALL_DIR/bwu"

printf 'install: installed %s + %s (+ alias bwu) to %s\n' "$BIN" "$AGENT" "$INSTALL_DIR" >&2
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf 'install: add %s to your PATH\n' "$INSTALL_DIR" >&2 ;;
esac
"$INSTALL_DIR/$BIN" --version || true
