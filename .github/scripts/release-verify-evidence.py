#!/usr/bin/env python3
"""release-verify-evidence.py -- ticket cs-27: release.yml's own cheap check
that the signed evidence matches the tag it is attached to.

Runs AFTER `cosign verify-blob` has already confirmed the bundle's signature
is real and identity-pinned (release.yml's own step, same identity gitsign
verified) -- this only checks the CONTENT of the evidence file that bundle
signs: it was recorded as a pass, and it names the version this tag claims.
Never recomputes the bump -- "the adopter computes its own composed bump and
does not recompute the publisher's" (spec.md).

Usage:
    release-verify-evidence.py <evidence.json> <version> <tag>
"""
import json
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: release-verify-evidence.py <evidence.json> <version> <tag>", file=sys.stderr)
        return 2
    evidence_path, version, tag = argv[1:4]
    doc = json.loads(open(evidence_path).read())
    # Ticket 43 (18 Answer 1): `degraded` is a real, published outcome, not a
    # refusal -- the declared bump was weaker than the computed one, so the
    # release publishes under a prerelease suffix at tier quarantine and the
    # ADOPTER prices the tier. A refusal never reaches a tag at all, so
    # anything here that is neither passed nor degraded is a tag that should
    # not exist.
    if doc["outcome"]["result"] not in ("passed", "degraded"):
        print(f"FAIL: {tag}: evidence outcome is {doc['outcome']!r}, not passed or degraded",
              file=sys.stderr)
        return 1
    # For a degraded publish the tag carries the suffix and `declared` keeps
    # the untouched base number, so the field to match the tag against is
    # `published_as` -- the number actually published.
    published = doc.get("published_as", doc["declared"])
    if published != version:
        print(f"FAIL: {tag}: evidence published {published!r} != tag version {version!r}",
              file=sys.stderr)
        return 1
    if doc["outcome"]["result"] == "degraded":
        print(f"ok  {tag}: cosign signature identity-pinned, evidence outcome DEGRADED at tier "
              f"{doc['degraded']['tier']} (declared {doc['bump']['declared']!r} < computed "
              f"{doc['bump']['computed']!r}), published number matches the tag")
        return 0
    print(f"ok  {tag}: cosign signature identity-pinned, evidence outcome passed, declared matches the tag")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
