#!/bin/sh
# bitvault-use installer — downloads a prebuilt binary from the latest GitHub
# Release (no npm, no token). Usage:
#   curl -fsSL https://raw.githubusercontent.com/leeguooooo/bitvault-use/main/install.sh | sh
# Override install dir:  BITVAULT_INSTALL_DIR=/usr/local/bin sh install.sh
# Pin a version:         BITVAULT_VERSION=v1.15.0 sh install.sh
set -eu

REPO="leeguooooo/bitvault-use"
BIN="bitvault-use"
AGENT="bitvault-use-agent"
INSTALL_DIR="${BITVAULT_INSTALL_DIR:-$HOME/.local/bin}"

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

ver="${BITVAULT_VERSION:-latest}"
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

# verify checksum if the .sha256 is published alongside
if curl -fsSL "$url.sha256" -o "$tmp/$asset.sha256" 2>/dev/null; then
  want="$(awk '{print $1}' "$tmp/$asset.sha256")"
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
  else
    got="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
  fi
  [ "$want" = "$got" ] || err "checksum mismatch (want $want, got $got)"
  printf 'install: checksum ok\n' >&2
fi

tar xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/$BIN-$target/$BIN" "$INSTALL_DIR/$BIN"
install -m 0755 "$tmp/$BIN-$target/$AGENT" "$INSTALL_DIR/$AGENT"

printf 'install: installed %s + %s to %s\n' "$BIN" "$AGENT" "$INSTALL_DIR" >&2
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf 'install: add %s to your PATH\n' "$INSTALL_DIR" >&2 ;;
esac
"$INSTALL_DIR/$BIN" --version || true
