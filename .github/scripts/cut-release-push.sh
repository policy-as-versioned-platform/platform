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

# The BRANCH goes with the tags, in the same atomic push.
#
# 2026-08-31: this pushed the tags alone. But the steps before it COMMIT the
# signed release-gate evidence onto the checked-out branch and then point
# versions.yaml at that commit -- so those commits were reachable only from the
# tag, and were never ancestors of the branch. The next release cut from that
# branch inherited the hole: platform v2.0.0, cut minutes after policy/v4.0.0,
# carried evidence/4.0.0.json with no 4.0.0.json.bundle beside it, and every
# adopter pinned to it refused, correctly. It took two releases in one day to
# show, which is why it sat here unseen.
#
# Committing to a branch and not pushing it is not a decision, it is a dropped
# half. The atomicity promise in this header is what makes adding it safe:
# either the branch and every tag land, or none of them do.
branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "$branch" = "HEAD" ]; then
  echo "cut-release-push.sh: detached HEAD, refusing to guess which branch the evidence belongs on" >&2
  exit 1
fi
git push --atomic "$remote" "HEAD:refs/heads/${branch}" "${tags[@]}"
