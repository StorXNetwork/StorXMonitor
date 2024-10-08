#!/usr/bin/env bash
# usage: $0 vMAJOR.MINOR.PATCH[-rc[-*]] PATH/TO/BINARIES

set -euo pipefail

# apps="identity uplink storagenode multinode"
apps="identity" # for now we just need identity so we can comment out the rest

TAG="${1-}"

if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc+(-.*)?)?$ ]]; then
  echo "No tag detected, skipping release drafting" + $TAG
  exit 0
fi

FOLDER="${2-}"

git config --global --add safe.directory /go/src/storj.io/storj

echo "Drafting release"
current_release_version=$(echo "$TAG" | cut -d '.' -f 1-2)
previous_release_version=$(git describe --tags $(git rev-list --exclude='*rc*' --exclude=$current_release_version* --tags --max-count=1))
changelog=$(python3 -W "ignore" scripts/changelog.py "$previous_release_version" "$TAG" 2>&1)
echo "creating release for $TAG with changelog: $changelog"
github-release release --user StorXNetwork --repo StorXMonitor --tag "$TAG" --description "$changelog" --draft

echo "Sleep 10 seconds in order to wait for release propagation"
sleep 10

echo "Uploading binaries to release draft"
for app in $apps; do
  for file in "$FOLDER/$app"*.zip; do
    github-release upload --user StorXNetwork --repo StorXMonitor --tag "$TAG" --name $(basename "$file") --file "$file"
  done
done
echo "Drafting release done"
