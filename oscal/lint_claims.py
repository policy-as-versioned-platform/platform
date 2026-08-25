#!/usr/bin/env python3
"""lint_claims.py — resolves every OSCAL control claim in component-definition.json
against what platform actually ships.

Two directions, both exact-string (no case-folding, no prefix-stripping,
ADR-0013):

  1. The claimed POLICY NAME (each `Check_Id` prop) against the identity the
     shipped version trees actually carry — `distribution/policies/v*/*.yaml`,
     name with the trailing `-N-N-N` version suffix stripped, same identity
     result2oscal.py keys on.
  2. The claimed CONTROL ID against the pinned `nist` catalogue, walking
     nested (enhancement) controls.

A claim whose policy resolves nowhere is a component-definition that has
rotted past the policy trees it once described (ADR-0017): it belongs to
whoever ships the implementation, and an implementation that stopped
existing does not un-claim itself. A claim whose control id resolves
nowhere in the catalogue is not even a hole — it is a hard failure.

Two dangling claims exist in component-definition.json TODAY: `cm-6` claims
`require-policy-version` and `ac-6` claims `may-run-root-if-attested`.
Neither policy is shipped. Fixing that is a different platform defect, not
this ticket's (policy-composition ticket 10) — this ticket's job is only to
make sure that defect has a red check instead of silence. Run plainly, this
script names both, tags them EXPECTED-RED, and still exits non-zero: it
never skips the check to reach green, and it will go green on its own the
moment that other defect is fixed.

Usage:
    lint_claims.py                 # the real check; exit 0 clean, 1 if any claim fails
    lint_claims.py --selfcheck     # runnable asserts that this tool resolves correctly
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
PLATFORM_ROOT = HERE.parent
COMP_DEF = HERE / "component-definition.json"
VERSION_TREES = PLATFORM_ROOT / "distribution" / "policies"
# Sibling-checkout convention this estate already uses (see driftwood/scripts/
# up.sh's NIST_DIR="${HERE}/../nist") — platform has no runtime pin on nist,
# only this offline lint does, so it reads the same local layout.
DEFAULT_NIST_CATALOG_DIR = PLATFORM_ROOT.parent / "nist" / "catalog"

POLICY_KINDS = {"ValidatingPolicy", "MutatingPolicy", "GeneratingPolicy"}
_SUFFIX = re.compile(r"-\d+-\d+-\d+$")  # the slugified-semver suffix result2oscal.py also strips

# The two claims ticket 10 names as dangling today. A DIFFERENT platform
# defect fixes them; naming them here lets this lint tell "still exactly the
# known defect" from "something new broke".
KNOWN_DANGLING: set[tuple[str, str]] = {
    ("cm-6", "require-policy-version"),
    ("ac-6", "may-run-root-if-attested"),
}


def shipped_policy_names(version_trees: Path = VERSION_TREES) -> set[str]:
    """Every policy identity (name, version suffix stripped) the version
    trees ship — the same identity the engine and result2oscal.py key on."""
    names: set[str] = set()
    for path in sorted(version_trees.glob("v*/*.yaml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if not doc or doc.get("kind") not in POLICY_KINDS:
                continue
            names.add(_SUFFIX.sub("", doc["metadata"]["name"]))
    return names


def claimed_policy_names(comp_def: dict) -> list[tuple[str, str]]:
    """(control-id, claimed policy name) for every Check_Id prop, in order."""
    out: list[tuple[str, str]] = []
    for comp in comp_def["component-definition"]["components"]:
        for ci in comp.get("control-implementations", []):
            for ir in ci.get("implemented-requirements", []):
                control = ir["control-id"]
                for p in ir.get("props", []):
                    if p.get("name") == "Check_Id":
                        out.append((control, p["value"]))
    return out


def claimed_control_ids(comp_def: dict) -> list[str]:
    return [
        ir["control-id"]
        for comp in comp_def["component-definition"]["components"]
        for ci in comp.get("control-implementations", [])
        for ir in ci.get("implemented-requirements", [])
    ]


def catalog_control_ids(catalog_doc: dict) -> set[str]:
    """Every control id in the catalogue, walking nested (enhancement)
    controls — same walk as nist/scripts/verify_baselines.py. Duplicated on
    purpose: each party's own offline check stays self-contained."""
    ids: set[str] = set()

    def walk(controls):
        for c in controls:
            ids.add(c["id"])
            walk(c.get("controls", []))

    for group in catalog_doc["catalog"].get("groups", []):
        walk(group.get("controls", []))
    return ids


def load_nist_catalog(catalog_dir: Path = DEFAULT_NIST_CATALOG_DIR) -> dict:
    meta = json.loads((catalog_dir / "CATALOG_VERSION.json").read_text())
    return json.loads((catalog_dir / meta["file"]).read_bytes())


def lint_policy_names(comp_def: dict, shipped: set[str]) -> list[tuple[str, str]]:
    """Claims whose policy name resolves against nothing shipped."""
    return [(c, p) for c, p in claimed_policy_names(comp_def) if p not in shipped]


def lint_control_ids(comp_def: dict, catalog_ids: set[str]) -> list[str]:
    """Claimed control ids absent from the catalogue, exact-string — a hard
    failure, never a hole (ADR-0013: no case-fold, no prefix-strip)."""
    return [c for c in claimed_control_ids(comp_def) if c not in catalog_ids]


def run(comp_def_path: Path = COMP_DEF, version_trees: Path = VERSION_TREES,
        nist_catalog_dir: Path = DEFAULT_NIST_CATALOG_DIR) -> int:
    comp_def = json.loads(comp_def_path.read_text())
    shipped = shipped_policy_names(version_trees)
    catalog_ids = catalog_control_ids(load_nist_catalog(nist_catalog_dir))

    dangling = lint_policy_names(comp_def, shipped)
    unknown = lint_control_ids(comp_def, catalog_ids)

    for control, policy in dangling:
        tag = "EXPECTED-RED" if (control, policy) in KNOWN_DANGLING else "FAIL"
        print(f"{tag}: {control} claims {policy!r}, which no shipped policy provides")
    for control in unknown:
        print(f"FAIL: control id {control!r} is absent from the nist catalogue")

    if not dangling and not unknown:
        print("OK: every control claim resolves to a shipped policy and a catalogued control id")
        return 0

    unexpected = (set(dangling) - KNOWN_DANGLING) or unknown
    if not unexpected:
        print(f"EXPECTED-RED: {len(dangling)} known dangling claim(s) — a platform defect this "
              "lint names but does not fix; see .scratch/policy-composition/issues/"
              "10-platform-control-claims-use-bare-ids.md")
    return 1


def selfcheck() -> None:
    comp_def = json.loads(COMP_DEF.read_text())
    shipped = shipped_policy_names()

    # 1. the dangling claims today are EXACTLY the two ticket 10 names — proves
    #    the lint goes green the moment that other defect is fixed, and red if
    #    a genuinely new one appears.
    dangling = set(lint_policy_names(comp_def, shipped))
    assert dangling == KNOWN_DANGLING, f"dangling claims changed: {dangling}"

    # 2. bare ids only (ADR-0013's resolution rule): no upper case, no prefix.
    for control in claimed_control_ids(comp_def):
        assert control == control.lower() and ":" not in control, control

    # 3. the source href names the nist party and a path, not a bare local
    #    path with no version (ticket 10 acceptance).
    for comp in comp_def["component-definition"]["components"]:
        for ci in comp.get("control-implementations", []):
            src = ci["source"]
            assert "nist" in src and "/" in src, src
            assert not src.startswith("estate/"), f"still a bare local path: {src}"

    # 4. every claimed control id DOES resolve against the real catalogue —
    #    bare ids fixed this half already, so it is expected green.
    catalog_ids = catalog_control_ids(load_nist_catalog())
    unknown = lint_control_ids(comp_def, catalog_ids)
    assert not unknown, f"claimed control id(s) absent from the catalogue: {unknown}"

    # 5. an unknown control id IS a hard failure — proved on a fixture, not by
    #    inspection ("fails on an unknown id", ticket 10 acceptance).
    fixture = json.loads(
        (HERE / "fixtures" / "component-definition-unknown-control.json").read_text()
    )
    fixture_unknown = lint_control_ids(fixture, catalog_ids)
    assert fixture_unknown == ["zz-999"], fixture_unknown

    # 6. the real run is red today, for exactly the known reason and nothing
    #    else — "mark the beat as expected-red", proved rather than stated.
    rc = run()
    assert rc == 1, "expected the real run to stay red until the other platform defect is fixed"

    print(f"selfcheck ok: {len(KNOWN_DANGLING)} known dangling claim(s), all other claims "
          "resolve, unknown-id fixture fails as required")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--component-definition", type=Path, default=COMP_DEF)
    ap.add_argument("--version-trees", type=Path, default=VERSION_TREES)
    ap.add_argument("--nist-catalog-dir", type=Path, default=DEFAULT_NIST_CATALOG_DIR)
    args = ap.parse_args(argv[1:])
    if args.selfcheck:
        selfcheck()
        return 0
    return run(args.component_definition, args.version_trees, args.nist_catalog_dir)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
