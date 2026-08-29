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

mapfile -t policy_tags < <(jq -r '.[].tag' "$tags_json" | grep -E '^policy/v[0-9]+\.[0-9]+\.[0-9]+' || true)

if [ "${#policy_tags[@]}" -eq 0 ]; then
  echo "no policy tags in this dispatch -- no versions.yaml element to point at the evidence commit"
  exit 0
fi

evidence_commit=$(git rev-parse HEAD)

python3 - "$evidence_commit" "${policy_tags[@]}" <<'PYEOF'
import json
import re
import sys
from pathlib import Path

evidence_commit = sys.argv[1]
tags = sys.argv[2:]

path = Path("distribution/versions.yaml")
text = path.read_text()

# Ticket 43. Three things this rewrite now does that it did not:
#   * an element with NO `commit:` key at all -- the shape the ResourceSet
#     template makes legal for a version DECLARED but not yet cut, which is
#     exactly where 4.0.0 sat -- gains one, instead of matching zero elements
#     and failing the very release this step exists to keep honest;
#   * the element's `tag:` is set to the tag actually cut, which for a
#     DEGRADED publish carries a prerelease suffix the reviewed element could
#     not have known in advance (ticket 18 Answer 1);
#   * a degraded publish adds `tier: "quarantine"` to the element (18 Answer
#     1). The element's `version` stays the BASE number -- that is what pods
#     claim and what the orphan guard allow-lists -- so `tier` is the field
#     that tells a consumer it is on a degraded line.
# Every other key on the element (`bump` above all) is preserved verbatim.
ELEMENT = re.compile(r'\{\s*version:\s*"(?P<version>[^"]+)"(?P<rest>[^}]*)\}')
KEY = re.compile(r'(\w+):\s*"([^"]*)"')

for tag in tags:
    version = tag[len("policy/v"):]
    base = version.split("-", 1)[0]
    degraded = version != base
    evidence = Path("computed-semver/evidence") / f"{version}.json"
    if evidence.exists():
        degraded = json.loads(evidence.read_text())["outcome"]["result"] == "degraded"

    found = []

    def rewrite(m):
        if m.group("version") != base:
            return m.group(0)
        found.append(m.group(0))
        fields = dict(KEY.findall(m.group("rest")))
        fields["tag"] = tag
        fields["commit"] = evidence_commit
        if degraded:
            fields["tier"] = "quarantine"
        order = ["tag", "commit", "bump", "tier"]
        keys = [k for k in order if k in fields] + [k for k in fields if k not in order]
        inner = ", ".join('%s: "%s"' % (k, fields[k]) for k in keys)
        return '{ version: "%s", %s }' % (base, inner)

    text = ELEMENT.sub(rewrite, text)
    if len(found) != 1:
        sys.exit("FAIL: expected exactly one versions.yaml array element for version %r, matched %d"
                 % (base, len(found)))

path.write_text(text)
PYEOF

git add distribution/versions.yaml
joined=$(IFS=,; echo "${policy_tags[*]}")
git -c user.name="policy-as-versioned release bot" \
    -c user.email="releases@${GITHUB_REPOSITORY_OWNER:-platform}.invalid" \
    commit -q -m "cs-27: point versions.yaml commit field(s) at the evidence commit ${evidence_commit} (${joined})"
echo "committed: versions.yaml array element(s) for ${joined} now point at evidence commit ${evidence_commit}"
