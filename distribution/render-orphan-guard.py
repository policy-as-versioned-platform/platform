#!/usr/bin/env python3
"""render-orphan-guard.py — the orphan-guard, rendered from the version array.

flux-operator's ResourceSet (versions.yaml) renders the orphan-guard live by
ranging `spec.inputs[0].versions[]`. This is its offline twin: the verify-*.sh
beats and the shift-left check (ticket 12) run without flux-operator in the loop,
so they need to derive the SAME allow-list from the SAME array deterministically.

There is exactly one array (in versions.yaml). Both renderers read it; neither
hand-maintains an allow-list, so the runnable-version set cannot drift from the
declared-version set. That is the whole point of the orphan-guard.

Usage:
    render-orphan-guard.py [versions.yaml]        # print the ValidatingPolicy
    render-orphan-guard.py --retire 2.0.0 [file]  # simulate retiring a version
    render-orphan-guard.py --selfcheck            # runnable asserts
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
LABEL = "policy-as-versioned.dev/policy-version"

# cs-22: the identity FAMILY label (never the version-pin label above). The
# orphan guard has no per-policy version of its own -- it is numbered by the
# platform release tag, not a policy tag -- so it is legitimately unversioned.
# `platform-machinery` is a real label value the pairing rule
# (computed-semver/pairing.py) recognises as a CLASS, exactly like any other
# identity family, never as a name-based exclusion.
IDENTITY_LABEL = "policy-as-versioned.dev/policy"
IDENTITY = "platform-machinery"


def elements(path: Path) -> list[dict]:
    """The declared version array's raw elements — version, tag, commit and
    all. The one parse point `versions()` below reuses, and cs-26's
    empty-commit gate rule reuses too (computed-semver/release_integrity.py)
    — nothing else re-parses versions.yaml for the array's own shape."""
    doc = yaml.safe_load(path.read_text())
    return doc["spec"]["inputs"][0]["versions"]


def versions(path: Path, retire: str | None = None) -> list[str]:
    """The declared version array — the single source of truth."""
    return [v["version"] for v in elements(path) if v["version"] != retire]


def orphan_guard(allowed: list[str]) -> dict:
    """A ValidatingPolicy that denies any pod claiming a version not in `allowed`.

    Unlabeled pods are out of scope (they claim no version); a pod that claims a
    version the array doesn't declare is denied. Allow-list ranged from the array.
    """
    if not allowed:
        raise SystemExit("refusing to render an orphan-guard with an empty allow-list")
    return {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "ValidatingPolicy",
        "metadata": {
            "name": "policy-version-orphan-guard",
            "labels": {IDENTITY_LABEL: IDENTITY},
        },
        "spec": {
            "validationActions": ["Deny"],
            "matchConstraints": {
                "resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"],
                    "operations": ["CREATE", "UPDATE"], "resources": ["pods"],
                }]
            },
            "matchConditions": [{
                "name": "has-policy-version-label",
                "expression": f"object.metadata.?labels['{LABEL}'].orValue('') != ''",
            }],
            "variables": [
                {"name": "allowed",
                 "expression": "[" + ", ".join(f"'{v}'" for v in allowed) + "]"},
                {"name": "claimed",
                 "expression": f"object.metadata.labels['{LABEL}']"},
            ],
            "validations": [{
                "expression": "variables.allowed.exists(v, v == variables.claimed)",
                "message": "policy-version not in the platform-declared version array (orphan): "
                           "no ResourceSet element declares it, so it cannot run.",
            }],
        },
    }


def selfcheck() -> None:
    vs = versions(HERE / "versions.yaml")
    assert vs == ["1.0.0", "2.0.0"], vs
    # elements() carries the raw dicts (commit field and all) versions()
    # itself is built from -- one parse point, not two.
    els = elements(HERE / "versions.yaml")
    assert [e["version"] for e in els] == vs, els
    assert all("commit" in e for e in els), els
    # allow-list is exactly the array — no drift
    og = orphan_guard(vs)
    assert og["spec"]["variables"][0]["expression"] == "['1.0.0', '2.0.0']"
    # cs-22: carries the platform-machinery identity, so the pairing rule
    # recognises it as a class rather than needing a by-name exclusion.
    assert og["metadata"]["labels"][IDENTITY_LABEL] == IDENTITY, og["metadata"]
    # retiring a version drops it from the allow-list
    assert versions(HERE / "versions.yaml", retire="2.0.0") == ["1.0.0"]
    assert orphan_guard(["1.0.0"])["spec"]["variables"][0]["expression"] == "['1.0.0']"
    # the rendered dirs on disk match the array (the fan-out cannot orphan a dir)
    dirs = sorted(p.name[1:] for p in (HERE / "policies").glob("v*") if p.is_dir())
    assert dirs == vs, f"policies/ dirs {dirs} != array {vs}"
    print("selfcheck ok: allow-list == array == policies/ dirs; retire drops a version")


def main(argv: list[str]) -> int:
    retire = None
    args = argv[1:]
    if args and args[0] == "--selfcheck":
        selfcheck()
        return 0
    if args and args[0] == "--retire":
        retire, args = args[1], args[2:]
    path = Path(args[0]) if args else HERE / "versions.yaml"
    print(yaml.safe_dump(orphan_guard(versions(path, retire)), sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
