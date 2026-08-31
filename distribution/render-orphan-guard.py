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


def _allow_expr(vs: list[str]) -> str:
    return "[" + ", ".join(f"'{v}'" for v in vs) + "]"


def selfcheck() -> None:
    # Asserts derive from whatever versions.yaml currently declares, not a
    # hardcoded literal -- the array grows and shrinks over real releases
    # (cs-15 replaced 1.0.0/2.0.0 with 2.0.0/3.0.0), and this selfcheck must
    # not need editing on every one.
    vs = versions(HERE / "versions.yaml")
    # >= 1, not >= 2: on 2026-08-29 the whole 2.x/3.x fan-out was retired and the
    # array legitimately declares one line. An array with NO element would render
    # an empty allow-list, which orphan_guard() refuses outright.
    assert len(vs) >= 1, f"the version array declares nothing, so nothing can run: {vs}"
    # elements() carries the raw dicts (commit field and all) versions()
    # itself is built from -- one parse point, not two.
    els = elements(HERE / "versions.yaml")
    assert [e["version"] for e in els] == vs, els
    # Uncut elements are a TAIL, never a hole. An element is added when the
    # policy body changes and cut-release.yml fills its commit in when it
    # cuts the signed tag (the ResourceSet template already makes `commit`
    # optional, and computed-semver/release_integrity.py's empty-commit rule
    # refuses a RELEASE whose array still has one). One release event may cut
    # more than one version -- 2026-08-29 briefly queued 2.0.2, 3.0.1 and 4.0.0 at
    # once (two patch backports plus the cage release) -- so the check is
    # that no CUT element sits after an uncut one, not that only the last is
    # uncut. A cut element following an uncut one is the real hole.
    cut = ["commit" in e for e in els]
    assert cut == sorted(cut, reverse=True), \
        f"a cut element sits after an uncut one -- an uncut element is a pending tail, not a hole: {els}"
    # allow-list is exactly the array — no drift
    og = orphan_guard(vs)
    assert og["spec"]["variables"][0]["expression"] == _allow_expr(vs)
    # cs-22: carries the platform-machinery identity, so the pairing rule
    # recognises it as a class rather than needing a by-name exclusion.
    assert og["metadata"]["labels"][IDENTITY_LABEL] == IDENTITY, og["metadata"]
    # retiring a version drops it from the allow-list
    retired = vs[-1]
    remaining = versions(HERE / "versions.yaml", retire=retired)
    assert remaining == [v for v in vs if v != retired], remaining
    if remaining:
        assert orphan_guard(remaining)["spec"]["variables"][0]["expression"] == _allow_expr(remaining)
    else:
        # Retiring the ONLY declared version leaves nothing runnable, and an
        # empty allow-list is not a policy anyone should ship -- orphan_guard()
        # refuses it outright, and this asserts that it does.
        try:
            orphan_guard(remaining)
        except SystemExit as e:
            assert "empty allow-list" in str(e), e
        else:
            raise AssertionError("an empty allow-list rendered instead of being refused")
    # every declared version has a rendered dir (the fan-out cannot orphan a
    # dir the array still points at). NOT the other direction: cs-15 retired
    # 1.0.0/2.0.0 from the array while deliberately leaving their rendered
    # dirs on disk as historical/reference trees (nothing a tag ever pointed
    # at, per that release's own reasoning) -- extra dirs the array no
    # longer names are harmless and honest, only a MISSING one is a bug.
    dirs = {p.name[1:] for p in (HERE / "policies").glob("v*") if p.is_dir()}
    assert set(vs) <= dirs, f"array {vs} names a version with no policies/ dir, got dirs {sorted(dirs)}"
    print("selfcheck ok: allow-list == array; every array version has a policies/ dir; retire drops a version")


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
