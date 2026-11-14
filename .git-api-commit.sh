#!/usr/bin/env bash
# Create one commit on a (fork) branch through the GitHub Git Data API.
# Used when `git push` from this machine returns HTTP 403 while the API works.
#
# Usage: .git-api-commit.sh <owner/repo> <branch> <message-file> <path>...
set -euo pipefail

REPO="$1"; shift
BRANCH="$1"; shift
MSGFILE="$1"; shift

PARENT=$(gh api "repos/$REPO/branches/$BRANCH" -q '.commit.sha')
BASE_TREE=$(gh api "repos/$REPO/git/commits/$PARENT" -q '.tree.sha')
echo "parent=$PARENT base_tree=$BASE_TREE"

TREE_ITEMS=""
for f in "$@"; do
  BLOB=$(gh api "repos/$REPO/git/blobs" -X POST \
    -f content="$(base64 < "$f" | tr -d '\n')" -f encoding=base64 -q '.sha')
  echo "  blob $BLOB  $f"
  TREE_ITEMS="${TREE_ITEMS}{\"path\":\"$f\",\"mode\":\"100644\",\"type\":\"blob\",\"sha\":\"$BLOB\"},"
done
TREE_ITEMS="[${TREE_ITEMS%,}]"

TREE=$(gh api "repos/$REPO/git/trees" -X POST --input - <<EOF | jq -r '.sha'
{"base_tree":"$BASE_TREE","tree":$TREE_ITEMS}
EOF
)
echo "tree=$TREE"

COMMIT=$(jq -n --arg m "$(cat "$MSGFILE")" --arg t "$TREE" --arg p "$PARENT" \
  '{message:$m, tree:$t, parents:[$p]}' \
  | gh api "repos/$REPO/git/commits" -X POST --input - -q '.sha')
echo "commit=$COMMIT"

gh api "repos/$REPO/git/refs/heads/$BRANCH" -X PATCH -F sha="$COMMIT" -F force=false -q '.object.sha'
