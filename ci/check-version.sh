#!/usr/bin/env bash
# Assert the release tag matches the version in package.json, so a `vX.Y.Z` tag can
# never ship a binary built from a mismatched package version. Called by ts-release.yml
# with the tag as $1 (e.g. "v0.1.0"). Dependency-free (no jq/node/bun required).
set -euo pipefail

tag="${1:?usage: check-version.sh <tag>}"
want="${tag#v}"                 # strip a leading 'v'
have="$(grep -m1 '"version"' package.json | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"

if [ "$want" != "$have" ]; then
  echo "Version mismatch: tag ${tag} (-> ${want}) != package.json version ${have}" >&2
  exit 1
fi
echo "Version OK: package.json ${have} matches tag ${tag}"
