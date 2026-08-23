#!/usr/bin/env bash
# cs-27: closes the tag/array disagreement an adversarial review found --
# without this step, `distribution/versions.yaml`'s `commit` field for a
# version being cut still names whatever commit rendered its tree (set by
# the earlier PR that added it), while the real tag ends up on the LATER
# evidence commit `cut-release-commit-evidence.sh` just made. Ticket 15's
# own acceptance criterion ("both array elements carry the resolved commit
# SHA") regresses permanently the moment that happens, and ticket 28's
# adopter gate is built to verify exactly this field against the tag it
# trusts (ADR-0001).
#
# The fix reuses ticket 15's own two-commit, non-circular pattern (a commit
# cannot contain its own SHA): commit A (the evidence commit, already made
# by cut-release-commit-evidence.sh, real and known now) is what THIS commit
# -- commit B -- points the array at. Commit B then becomes the tag target:
# it is cumulative, so it carries the evidence from A plus this correction,
# and the tag's resolved commit and the array's `commit` field disagree by
# exactly one commit, on purpose, in the same direction cs-15 already
# established (the array names an ANCESTOR of the tag, never the tag's own
# commit).
#
# A no-op, not an error, when this dispatch cut no policy tags -- same
# condition cut-release-commit-evidence.sh already treats as a no-op (a pure
# platform `v*` tag names no distribution/versions.yaml element).
set -euo pipefail
tags_json="${1:?usage: cut-release-update-array-commit.sh <tags.json>}"

mapfile -t policy_versions < <(jq -r '.[].tag' "$tags_json" | sed -E -n 's#^policy/v([0-9]+\.[0-9]+\.[0-9]+)$#\1#p')

if [ "${#policy_versions[@]}" -eq 0 ]; then
  echo "no policy tags in this dispatch -- no versions.yaml element to point at the evidence commit"
  exit 0
fi

evidence_commit=$(git rev-parse HEAD)

python3 - "$evidence_commit" "${policy_versions[@]}" <<'PY'
import re
import sys
from pathlib import Path

evidence_commit = sys.argv[1]
versions = sys.argv[2:]

path = Path("distribution/versions.yaml")
text = path.read_text()

for version in versions:
    pattern = re.compile(
        r'(\{\s*version:\s*"' + re.escape(version) + r'"\s*,\s*tag:\s*"[^"]*"\s*,\s*commit:\s*")'
        r'[^"]*("\s*\})'
    )
    text, n = pattern.subn(lambda m: m.group(1) + evidence_commit + m.group(2), text)
    if n != 1:
        sys.exit(f"FAIL: expected exactly one versions.yaml array element for version {version!r}, matched {n}")

path.write_text(text)
PY

git add distribution/versions.yaml
joined=$(IFS=,; echo "${policy_versions[*]}")
git -c user.name="policy-as-versioned release bot" \
    -c user.email="releases@${GITHUB_REPOSITORY_OWNER:-platform}.invalid" \
    commit -q -m "cs-27: point versions.yaml commit field(s) at the evidence commit ${evidence_commit} (${joined})"
echo "committed: versions.yaml array element(s) for ${joined} now point at evidence commit ${evidence_commit}"
