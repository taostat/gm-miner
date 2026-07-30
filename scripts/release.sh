#!/usr/bin/env bash
# Tag a release at whatever version Cargo.toml already carries.
#
# The version is READ, never passed in. cargo-dist refuses a tag that does not
# match the workspace version, and every failed release in this repo has been a
# hand-typed tag that drifted from the bump: v0.3.11-dev, v0.3.12-dev,
# v0.3.13-dev, v0.3.14 and v0.3.14-dev were all tagged against a stale
# Cargo.toml and published nothing. Deriving the tag makes that unrepresentable.
#
# Bumping the version is a normal reviewed PR; this script only does the tagging
# that follows it, so nothing here pushes to main.
#
#   scripts/release.sh              # tag + push the version on main
#   scripts/release.sh --dry-run    # print what it would do
set -euo pipefail

DRY_RUN=0
case "${1:-}" in
  --dry-run) DRY_RUN=1 ;;
  "") ;;
  *)
    echo "usage: scripts/release.sh [--dry-run]" >&2
    echo "the version comes from Cargo.toml — bump it in a PR first" >&2
    exit 2
    ;;
esac

die() {
  echo "error: $*" >&2
  exit 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
[[ -n "$VERSION" ]] || die "could not read version from [workspace.package] in Cargo.toml"
TAG="v$VERSION"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[[ "$BRANCH" == "main" ]] || die "on '$BRANCH'; releases are cut from main"

[[ -z "$(git status --porcelain)" ]] || die "working tree is dirty; commit or stash first"

git fetch --quiet origin main
LOCAL="$(git rev-parse @)"
REMOTE="$(git rev-parse origin/main)"
[[ "$LOCAL" == "$REMOTE" ]] || die "main is not in sync with origin/main; pull or push first"

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  die "$TAG already exists locally — bump the version in a PR rather than reusing a tag"
fi
if git ls-remote --exit-code --tags origin "$TAG" >/dev/null 2>&1; then
  die "$TAG already exists on origin — bump the version in a PR rather than reusing a tag"
fi

echo "Release $TAG"
echo "  commit:  $(git rev-parse --short HEAD) $(git log -1 --format=%s)"
echo "  version: $VERSION (from Cargo.toml)"

if [[ "$DRY_RUN" == 1 ]]; then
  echo "dry run: would tag $TAG and push it to origin"
  exit 0
fi

read -r -p "Tag and push $TAG? This publishes a GitHub Release. [y/N] " reply
[[ "$reply" == "y" || "$reply" == "Y" ]] || die "aborted"

git tag "$TAG"
git push origin "$TAG"

echo "Pushed $TAG. Watch the release run:"
echo "  gh run list --workflow=release.yml --limit 1"
