#!/usr/bin/env bash
# cs-13: pushes every tag in the list in one atomic `git push`. GitHub's git
# servers support atomic push transactions: either every ref in this push
# lands, or none do. Nothing before this step touches the remote, so a
# failure at any earlier step (bad input, an existing tag, a signing
# failure) already leaves zero tags pushed; a failure inside this push also
# leaves zero tags pushed. This workflow can therefore promise: never some
# tags pushed and others not -- never the git-data REST API, `git push` only.
set -euo pipefail
tags_json="${1:?usage: cut-release-push.sh <tags.json> [remote]}"
remote="${2:-origin}"

mapfile -t tags < <(jq -r '.[].tag' "$tags_json")
git push --atomic "$remote" "${tags[@]}"
