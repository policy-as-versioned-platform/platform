#!/usr/bin/env bash
# cs-27: commits the signed evidence + bundle from cut-release-gate.py into
# the release commit, BEFORE cut-release-create-tags.sh runs -- "one tag
# then reaches both the release content and its evidence, forever, from any
# clone" (spec.md, "Signing and verification"). Runs only after
# cut-release-gate.py has already exited 0 (every policy tag in this
# dispatch passed); a workflow `run:` step stops the job on the gate's
# non-zero exit, so this step is simply never reached on a refusal -- no
# separate "did it pass" check needed here.
#
# A no-op, not an error, when this dispatch cut no policy tags at all (a
# pure platform `v*` tag, cs-07's own line) -- cut-release-gate.py wrote
# nothing under computed-semver/evidence/ in that case, so there is nothing
# to stage.
set -euo pipefail
tags_json="${1:?usage: cut-release-commit-evidence.sh <tags.json>}"

if git status --porcelain -- computed-semver/evidence | grep -q .; then
  tags=$(jq -r '[.[].tag] | join(", ")' "$tags_json")
  git add computed-semver/evidence
  git -c user.name="policy-as-versioned release bot" \
      -c user.email="releases@${GITHUB_REPOSITORY_OWNER:-platform}.invalid" \
      commit -q -m "cs-27: signed release-gate evidence for ${tags}"
  echo "committed: signed release-gate evidence for ${tags}"
else
  echo "no evidence changes to commit (no policy tags in this dispatch)"
fi
