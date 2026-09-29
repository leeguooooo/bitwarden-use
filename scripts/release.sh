#!/bin/sh
# Release bitwarden-use: bump Cargo.toml/Cargo.lock (skipped when a feature commit already did),
# run the fast checks, commit "chore(release): vX.Y.Z", push main and the tag, wait for
# release.yml to build and publish the GitHub Release, then sync the plugin marketplace so
# Claude Code plugin installs pick the new version up right away.
#   scripts/release.sh [--dry-run] 0.5.1
# --dry-run: preflight + checks + show the bump diff, then revert. Nothing is committed or pushed.
set -eu
DRY=0 V=
for a in "$@"; do
  case $a in --dry-run) DRY=1 ;; -*) V= ; break ;; *) V=${a#v} ;; esac
done
[ -n "$V" ] || { echo "usage: scripts/release.sh [--dry-run] <version>" >&2; exit 2; }
MARKETPLACE=leeguooooo/plugins PLUGIN=bitwarden-use
die() { echo "error: $*" >&2; exit 1; }
cd "$(dirname "$0")/.."

echo "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || die "bad version: $V"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "not on main"
[ -z "$(git status --porcelain)" ] || die "working tree not clean"
git fetch -q origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main is not in sync with origin/main"
git rev-parse -q --verify "refs/tags/v$V" >/dev/null && die "v$V already exists"
grep -q "^# $V\$" CHANGELOG.md || echo "warn: CHANGELOG.md has no '# $V' section"

# release.yml refuses a tag that differs from Cargo.toml's version and builds with --locked.
trap 'git checkout -q -- Cargo.toml Cargo.lock' EXIT  # undo the bump on --dry-run or a failed check
sed -i.bak "1,/^version = /s/^version = \".*\"/version = \"$V\"/" Cargo.toml && rm Cargo.toml.bak
sed -i.bak "/^name = \"bitwarden-use\"\$/{n;s/^version = \".*\"/version = \"$V\"/;}" Cargo.lock && rm Cargo.lock.bak
cargo metadata --locked -q --format-version 1 >/dev/null || die "Cargo.lock out of sync"

# The fast part of check.yml; the cargo tests run in release.yml before anything is built.
python3 tools/test_install.py >/dev/null 2>&1 || die "tools/test_install.py failed"
cargo fmt --all --check || die "cargo fmt --check failed"
echo "checks passed"

if [ "$DRY" = 1 ]; then
  git --no-pager diff -U0 -- Cargo.toml Cargo.lock
  git diff --quiet && echo "Cargo.toml is already at $V: only the tag would be pushed"
  echo "dry run: would commit the bump (if any), tag and push main + v$V, wait for release.yml, sync $MARKETPLACE"
  exit 0
fi

git diff --quiet || git commit -qm "chore(release): v$V" -- Cargo.toml Cargo.lock
trap - EXIT
git tag "v$V"
git push -q origin main "v$V"

# release.yml builds four targets and publishes the Release on the tag push; the plugin must not
# update before its binaries exist.
RUN='' i=0
while [ -z "$RUN" ]; do
  i=$((i + 1)); [ $i -le 30 ] || die "no release.yml run for v$V after 5 min"
  sleep 10
  RUN=$(gh run list -w release.yml -b "v$V" -e push -L 1 --json databaseId -q '.[0].databaseId')
done
echo "waiting for release build: $(gh run view "$RUN" --json url -q .url)"
gh run watch "$RUN" --interval 30 --exit-status >/dev/null || die "release build failed: gh run view $RUN --log-failed"
gh release view "v$V" --json url -q .url

gh workflow run auto-sync-versions.yml -R "$MARKETPLACE"
sleep 5
RUN=$(gh run list -R "$MARKETPLACE" -w auto-sync-versions.yml -e workflow_dispatch -L 1 --json databaseId -q '.[0].databaseId')
gh run watch "$RUN" -R "$MARKETPLACE" --exit-status >/dev/null && echo "marketplace synced" || echo "warn: marketplace sync run $RUN failed; the hourly run will retry"
gh api "repos/$MARKETPLACE/contents/.claude-plugin/marketplace.json" -q .content | base64 -d \
  | python3 -c "import json,sys; print('marketplace $PLUGIN:', next(p['version'] for p in json.load(sys.stdin)['plugins'] if p['name']=='$PLUGIN'))"
