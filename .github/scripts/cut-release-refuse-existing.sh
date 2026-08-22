#!/usr/bin/env bash
# cs-13: refuses every tag in the list that already exists, checked for ALL
# entries before cut-release-create-tags.sh creates ANY of them. Tags are
# immutable here -- no force-move, ever.
set -euo pipefail
tags_json="${1:?usage: cut-release-refuse-existing.sh <tags.json>}"

jq -r '.[].tag' "$tags_json" | while IFS= read -r tag; do
  if git rev-parse "refs/tags/${tag}" >/dev/null 2>&1; then
    echo "FAIL: ${tag} already exists -- tags are immutable here, cut a new version" >&2
    exit 1
  fi
  echo "ok: ${tag} does not exist yet"
done
