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
#
# Ticket 146. "Verbatim" was not true of a NESTED value. The element was matched with
# `[^}]*` and rebuilt from its quoted scalar keys only, so an element that carried
# `tested_engines: { scope: ..., kyverno: [...] }` before its cut lost the field and left its own
# closing brace behind as a stray `}`. Hub ADR-0033 point 4 puts that field on every element from
# the moment it is declared, so every cut would have hit it. The element is now found by its
# balanced braces, split at its top-level commas, and every value this step does not own is
# written back as the exact text it read.
START = re.compile(r'\{\s*version:\s*"(?P<version>[^"]+)"')


def flow_end(text, start):
    """The index just past the `}` that closes the flow mapping opening at text[start]."""
    depth, quote, i = 0, None, start
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    sys.exit("FAIL: a versions.yaml array element has unbalanced braces")


def items(inner):
    """The element's top-level `key: value` pairs, each value as the exact text it was written as."""
    parts, buf, depth, quote, i = [], "", 0, None, 0
    while i < len(inner):
        c = inner[i]
        if quote:
            if c == "\\" and quote == '"':
                buf += inner[i:i + 2]
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(buf)
            buf = ""
            i += 1
            continue
        buf += c
        i += 1
    if buf.strip():
        parts.append(buf)
    pairs = []
    for part in parts:
        key, sep, value = part.partition(":")
        if not sep or not key.strip():
            sys.exit("FAIL: a versions.yaml array element carries a part that is not key: value: %r" % part)
        pairs.append((key.strip(), value.strip()))
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        sys.exit("FAIL: a versions.yaml array element names a key twice: %r" % keys)
    return pairs


for tag in tags:
    version = tag[len("policy/v"):]
    base = version.split("-", 1)[0]
    degraded = version != base
    evidence = Path("computed-semver/evidence") / f"{version}.json"
    if evidence.exists():
        degraded = json.loads(evidence.read_text())["outcome"]["result"] == "degraded"

    found, out, pos = [], [], 0
    for m in START.finditer(text):
        if m.start() < pos or m.group("version") != base:
            continue
        end = flow_end(text, m.start())
        pairs = items(text[m.start() + 1:end - 1])
        found.append(text[m.start():end])
        fields = dict(pairs)
        fields["version"] = '"%s"' % base
        fields["tag"] = '"%s"' % tag
        fields["commit"] = '"%s"' % evidence_commit
        if degraded:
            fields["tier"] = '"quarantine"'
        order = ["version", "tag", "commit", "bump", "tier"]
        keys = [k for k in order if k in fields] + [k for k, _ in pairs if k not in order]
        out.append(text[pos:m.start()])
        out.append("{ " + ", ".join("%s: %s" % (k, fields[k]) for k in keys) + " }")
        pos = end
    out.append(text[pos:])
    text = "".join(out)
    if len(found) != 1:
        sys.exit("FAIL: expected exactly one versions.yaml array element for version %r, matched %d"
                 % (base, len(found)))

# The rewrite is read back before it is written: the file still parses and each cut element
# carries the fields this step owns. PyYAML is installed by cut-release.yml's first step.
try:
    import yaml
except ImportError:
    yaml = None
if yaml is not None:
    elements = {str(e["version"]): e for e in yaml.safe_load(text)["spec"]["inputs"][0]["versions"]}
    for tag in tags:
        e = elements[tag[len("policy/v"):].split("-", 1)[0]]
        if e.get("tag") != tag or e.get("commit") != evidence_commit:
            sys.exit("FAIL: the rewritten element for %s does not read back: %r" % (tag, e))

path.write_text(text)
PYEOF

git add distribution/versions.yaml
joined=$(IFS=,; echo "${policy_tags[*]}")
git -c user.name="policy-as-versioned release bot" \
    -c user.email="releases@${GITHUB_REPOSITORY_OWNER:-platform}.invalid" \
    commit -q -m "cs-27: point versions.yaml commit field(s) at the evidence commit ${evidence_commit} (${joined})"
echo "committed: versions.yaml array element(s) for ${joined} now point at evidence commit ${evidence_commit}"
