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
    if doc["outcome"]["result"] != "passed":
        print(f"FAIL: {tag}: evidence outcome is {doc['outcome']!r}, not passed", file=sys.stderr)
        return 1
    if doc["declared"] != version:
        print(f"FAIL: {tag}: evidence declared {doc['declared']!r} != tag version {version!r}", file=sys.stderr)
        return 1
    print(f"ok  {tag}: cosign signature identity-pinned, evidence outcome passed, declared matches the tag")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
