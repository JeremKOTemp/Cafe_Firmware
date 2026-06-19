#!/usr/bin/env bash
set -euo pipefail

TAG="${WAVE_TAG:?WAVE_TAG is required}"
UPDATE_DATFILE="${UPDATE_DATFILE:-false}"

ITEM=$(echo "${QUEUE_JSON:-[]}" | jq -c --arg tag "$TAG" '.[] | select(.tag == $tag)')
M_IDX=$(echo "$ITEM" | jq -r '.m_idx // empty')
M_IDX="${M_IDX:-999}"

if [ ! -s release_notes.md ] || [ ! -s release_title.txt ]; then
  echo "ERROR: Missing or empty release_notes.md / release_title.txt for $TAG"
  exit 1
fi
FINAL_RELEASE_TITLE=$(head -n 1 release_title.txt | tr -d '\r')

ASSETS=()
for archive in Firmware.*.zip Extracted.Firmware.*.zip; do
  if [ -f "$archive" ]; then
    ASSETS+=("$archive")
  fi
done
if [ ${#ASSETS[@]} -eq 0 ]; then
  echo "ERROR: No archives were generated for $TAG"
  exit 1
fi

if [ "$M_IDX" -ge 999 ] 2>/dev/null; then
  FAKE_DATE=$(date +"%Y-%m-%dT%H:%M:%S%z")
else
  DAYS_AGO=$((200 - M_IDX))
  FAKE_DATE=$(date -d "$DAYS_AGO days ago" +"%Y-%m-%dT%H:%M:%S%z")
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

commit_paths() {
  local message="$1"
  shift
  local stage
  stage=$(mktemp -d)
  local path
  for path in "$@"; do
    mkdir -p "$stage/$(dirname "$path")"
    cp "$path" "$stage/$path"
  done
  for _ in $(seq 1 25); do
    git fetch origin main
    git reset --hard origin/main
    cp -r "$stage"/. .
    git add -f -- "$@"
    if git diff --staged --quiet; then
      break
    fi
    git commit -m "$message" || true
    if git push origin HEAD:main > /dev/null 2>&1; then
      break
    fi
    sleep $((2 + RANDOM % 6))
  done
  rm -rf "$stage"
}

if [ "$UPDATE_DATFILE" = "true" ] && [ -f ".dat_cache/${TAG}.json" ]; then
  commit_paths "Cache Wii U DAT metadata for $TAG [skip ci]" ".dat_cache/${TAG}.json"
fi

if ls build_manifests/*.json > /dev/null 2>&1; then
  commit_paths "Record build manifests for $TAG [skip ci]" build_manifests/*.json
fi

gh release delete "$TAG" -R "$GITHUB_REPOSITORY" -y --cleanup-tag 2>/dev/null || true
git push origin --delete "$TAG" 2>/dev/null || true
git tag -d "$TAG" 2>/dev/null || true

export GIT_AUTHOR_DATE="$FAKE_DATE"
export GIT_COMMITTER_DATE="$FAKE_DATE"

git rm -rf --cached .github/workflows 2>/dev/null || true
NEW_TREE=$(git write-tree)
NEW_COMMIT=$(git commit-tree "$NEW_TREE" -m "Release $TAG")
git reset HEAD .github/workflows 2>/dev/null || true

git tag -a "$TAG" "$NEW_COMMIT" -m "$FINAL_RELEASE_TITLE"
git push origin "$TAG"

sleep 2

gh release create "$TAG" "${ASSETS[@]}" \
  --draft \
  --title "$FINAL_RELEASE_TITLE" \
  --notes-file release_notes.md \
  -R "$GITHUB_REPOSITORY"

echo "Staged draft release $TAG -> $FINAL_RELEASE_TITLE (${#ASSETS[@]} assets)."
rm -f Firmware.*.zip Extracted.Firmware.*.zip release_notes.md release_title.txt
