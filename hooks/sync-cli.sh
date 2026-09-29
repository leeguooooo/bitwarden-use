#!/bin/sh
# SessionStart hook of the bitwarden-use Claude Code plugin: keep the CLI at the plugin's version.
# Claude Code auto-updates the plugin (SKILL.md); this makes the CLI follow. When the installed
# bitwarden-use is older than the plugin (the version in the Cargo.toml next to this script), it
# installs exactly that release: `bitwarden-use upgrade --tag vX.Y.Z`, or install.sh into the same
# directory for CLIs from before `upgrade` (0.4.x). It never touches the vault; the next command
# replaces a running agent, so the vault asks to unlock once. Silent when nothing needs doing.
# The hook is declared inline in the leeguooooo/plugins marketplace entry.
# Off with BITWARDEN_USE_NO_AUTO_UPGRADE, USE_NO_AUTO_UPGRADE or CI.
PATH="$PATH:$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin"
[ -n "${BITWARDEN_USE_NO_AUTO_UPGRADE:-}${USE_NO_AUTO_UPGRADE:-}${CI:-}" ] && exit 0

root=${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
want=$(sed -n 's/^version = "\([0-9]*\.[0-9]*\.[0-9]*\)"$/\1/p' "$root/Cargo.toml" 2>/dev/null | head -n 1)
[ -n "$want" ] || exit 0
# Not installed: installing is the user's call (SKILL.md and the use-family check say how).
bin=$(command -v bitwarden-use) || exit 0
version_of() { BITWARDEN_USE_NO_UPDATE_CHECK=1 "$1" --version 2>/dev/null | awk '{print $NF}'; }
have=$(version_of "$bin")
case $have in [0-9]*.[0-9]*.[0-9]*) ;; *) exit 0 ;; esac

# older A B: version A sorts strictly before version B
older() {
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1)" = "$1" ]
}
older "$have" "$want" || exit 0

state="${XDG_CACHE_HOME:-$HOME/.cache}/bitwarden-use"
mkdir -p "$state" || exit 0
log="$state/auto-upgrade.log"
# A version that could not be installed (install not ours to upgrade, no such release, network)
# is retried once an hour, not on every session start.
skip="$state/auto-upgrade.skip"
if [ "$(cat "$skip" 2>/dev/null)" = "$want" ] && [ -z "$(find "$skip" -mmin +60 2>/dev/null)" ]; then
  exit 0
fi
# One upgrade at a time across sessions; a lock older than 10 minutes is stale.
lock="$state/auto-upgrade.lock"
find "$lock" -maxdepth 0 -mmin +10 -exec rmdir {} \; 2>/dev/null
mkdir "$lock" 2>/dev/null || exit 0
trap 'rmdir "$lock" 2>/dev/null' EXIT

dir=$(dirname "$bin")
echo "$(date '+%F %T') $bin $have -> $want" >> "$log"
if "$bin" --help 2>/dev/null | grep -qE '^[[:space:]]+upgrade([[:space:]]|$)'; then
  # Refuses (exit 1, nothing changed) when cargo, Homebrew or a source build owns the binary.
  BITWARDEN_USE_NO_UPDATE_CHECK=1 "$bin" upgrade --tag "v$want" >> "$log" 2>&1 < /dev/null
elif [ -x "$dir/bitwarden-use-agent" ] && [ ! -L "$bin" ]; then
  t=$(mktemp) &&
    curl -fsSL --max-time 30 "https://raw.githubusercontent.com/leeguooooo/bitwarden-use/v$want/install.sh" -o "$t" &&
    BITWARDEN_INSTALL_DIR=$dir BITWARDEN_VERSION=v$want sh "$t" >> "$log" 2>&1 < /dev/null
  rm -f "$t"
fi

now=$(version_of "$bin")
echo "$(date '+%F %T') installed ${now:-?}" >> "$log"
if [ "$now" = "$want" ]; then
  rm -f "$skip"
  echo "bitwarden-use: upgraded the CLI $have -> $want to match the plugin. The next bitwarden-use command restarts the agent, so the vault asks to unlock once."
else
  echo "$want" > "$skip"
  echo "bitwarden-use: the CLI is $have but the plugin is $want, and upgrading it failed (see $log). Tell the user; manual upgrade: curl -fsSL https://raw.githubusercontent.com/leeguooooo/bitwarden-use/main/install.sh | sh"
fi
