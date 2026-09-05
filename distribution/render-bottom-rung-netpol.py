#!/usr/bin/env python3
"""render-bottom-rung-netpol.py -- the reach cage for the population no served version reaches.

Eco-system ticket 89, finding F8. `cage-netpol` generates the three `cage-reach-*`
NetworkPolicies in a namespace when a caged pod is admitted there. Every SERVED copy of it is
version-scoped -- `distribution/policies/v4.0.0/cage-netpol.yaml` carries
`only-this-policy-version`, as does each adopter's composed copy -- so it fires only for pods
claiming that version.

The two policies this ticket adds cage a population that claims nothing (an unclaimed pod in a
governed namespace) or claims a version no served line carries (an orphan claim). Neither can
trigger a version-scoped generator. So in a namespace with no pod claiming a served version,
those pods were labelled `posture.acme.io/tier: isolated` with NO NetworkPolicy behind the
label -- and "the bottom rung is a running cage with no ingress and no egress" (ADR-0022) would
have been false of exactly the population this ticket creates. A label that promises a cage
nothing enforces is worse than no label.

This GeneratingPolicy closes that. It is the same body as `graded/policies/cage-netpol.yaml`,
read from that file so the reach table cannot be forked, with the version scoping replaced by
the population that has no version: a caged pod whose tier is not `baseline` and whose claim is
either absent or absent from the platform's declared array.

The generated objects are byte-identical to the versioned generator's -- same names, same
namespace, same podSelector, same rules -- so where both fire the second `generator.Apply` is a
no-op over the first. Two generators, one set of objects, no contention: `generate` writes
cluster objects by name, not a field of the pod, which is why this pairs safely where a second
MUTATION would not.

Usage:
    render-bottom-rung-netpol.py [versions.yaml]   # print the GeneratingPolicy
    render-bottom-rung-netpol.py --selfcheck
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cage_body as cb  # noqa: E402

CAGE_NETPOL = HERE.parent / "graded" / "policies" / "cage-netpol.yaml"
NAME = "cage-netpol-bottom-rung"
LABEL = cb.CLAIM_LABEL


def _allow_expr(vs: list[str]) -> str:
    return "[" + ", ".join(f"'{v}'" for v in vs) + "]"


def source_spec(path: Path | None = None) -> dict:
    doc = yaml.safe_load((path or CAGE_NETPOL).read_text())
    if doc.get("kind") != "GeneratingPolicy":
        raise SystemExit(f"{path or CAGE_NETPOL} is not a GeneratingPolicy; refusing to copy it")
    return doc["spec"]


def bottom_rung_netpol(allowed: list[str], spec: dict | None = None) -> dict:
    """`cage-netpol`'s own body, scoped to the population no served version reaches."""
    if not allowed:
        raise SystemExit("refusing to render a bottom-rung reach cage with an empty allow-list")
    src = copy.deepcopy(spec if spec is not None else source_spec())
    # `is-caged` and `tier-restricts-reach` are kept verbatim: they read cage-tier's OUTPUT
    # labels, which is exactly what this ticket's two mutations write. The third condition is
    # this policy's whole difference -- the pods no served, version-scoped generator can see.
    # R5 (review, 2026-09-05): its OWN downstream names. The served cage-netpol-<v> generates
    # `cage-reach-<tier>` into the same namespace, and two generators owning one downstream name
    # has never been driven through a real API server. cage-netpol.yaml's own header records
    # what a mis-owned downstream cost on 2026-08-28: Kyverno's dynamic watcher called
    # DeleteDownstreams for a whole policy and wiped every other namespace's reach cage, which
    # `synchronize: false` is what closed. Distinct names with the SAME podSelector are additive
    # for a pod they both select -- NetworkPolicy unions what it allows, and the bottom rung
    # allows nothing on either -- so the reach is identical and neither generator can delete the
    # other's objects.
    gen = src["generate"][0]["expression"]
    assert '"cage-reach-" + t' in gen, gen
    src = dict(src, generate=[{"expression": gen.replace('"cage-reach-" + t',
                                                         '"cage-reach-bottom-rung-" + t')}])
    # S5 (review, 2026-09-05): only the BOTTOM RUNG. cage-netpol generates all three restricting
    # rungs up front so a tier move needs no create and no delete -- but this policy's population
    # is pinned to `isolated` by both cages, so the restricted and quarantine objects it also
    # emitted were byte-identical duplicates of the served generator's, two more downstream names
    # with two owners for no benefit. One rung, one object per namespace.
    src["variables"] = [dict(v, expression=f"['{cb.BOTTOM_RUNG}']") if v["name"] == "rungs" else v
                        for v in src["variables"]]
    src["matchConditions"] = list(src.get("matchConditions", [])) + [{
        "name": "claims-no-served-version",
        "expression": (f"object.metadata.?labels['{LABEL}'].orValue('') == '' || "
                       f"!({_allow_expr(allowed)}.exists(v, "
                       f"v == object.metadata.labels['{LABEL}']))"),
    }]
    return {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "GeneratingPolicy",
        "metadata": {"name": NAME, "labels": {cb.IDENTITY_LABEL: cb.IDENTITY}},
        "spec": src,
    }


def selfcheck() -> None:
    import importlib.util
    og_path = HERE / "render-orphan-guard.py"
    s = importlib.util.spec_from_file_location("render_orphan_guard", og_path)
    og = importlib.util.module_from_spec(s)
    sys.modules["render_orphan_guard"] = og
    s.loader.exec_module(og)
    vs = og.served_versions(HERE / "versions.yaml")

    doc = bottom_rung_netpol(vs)
    assert doc["kind"] == "GeneratingPolicy", doc["kind"]
    assert doc["metadata"]["labels"][cb.IDENTITY_LABEL] == cb.IDENTITY, doc["metadata"]
    assert "Deny" not in yaml.safe_dump(doc), "a refusal survived in a generator"
    names = [c["name"] for c in doc["spec"]["matchConditions"]]
    assert names[-1] == "claims-no-served-version", names
    # The two conditions that read cage-tier's output labels are carried VERBATIM: this
    # generator must key on exactly what the versioned one keys on, or the two would disagree
    # about which pods are caged.
    src = source_spec()
    assert doc["spec"]["matchConditions"][:len(src["matchConditions"])] == src["matchConditions"], \
        "the match conditions drifted from graded/policies/cage-netpol.yaml"
    # The generated objects are cage-netpol's own, except the downstream NAME (R5).
    want = source_spec()["generate"][0]["expression"].replace(
        '"cage-reach-" + t', '"cage-reach-bottom-rung-" + t')
    assert doc["spec"]["generate"][0]["expression"] == want, \
        "the generated objects drifted from graded/policies/cage-netpol.yaml"
    assert "cage-reach-bottom-rung-" in doc["spec"]["generate"][0]["expression"], doc["spec"]
    assert '"cage-reach-" + t' not in doc["spec"]["generate"][0]["expression"], \
        "the bottom-rung generator writes the served generator's downstream names"
    # Every variable is cage-netpol's own except `rungs`, which is pinned to the bottom rung.
    for want, got in zip(src["variables"], doc["spec"]["variables"], strict=True):
        if want["name"] == "rungs":
            assert got["expression"] == f"['{cb.BOTTOM_RUNG}']", got
        else:
            assert got == want, ("the reach table drifted from "
                                 "graded/policies/cage-netpol.yaml", want, got)
    assert _allow_expr(vs) in doc["spec"]["matchConditions"][-1]["expression"], doc["spec"]
    # The SERVED generator really is version-scoped -- the fact this policy exists for. Read
    # off the real served copy, never the authoring one graded/up.sh says it never applies.
    served = HERE / "policies" / f"v{vs[0]}" / "cage-netpol.yaml"
    if served.exists():
        conds = yaml.safe_load(served.read_text())["spec"]["matchConditions"]
        assert any(c["name"] == "only-this-policy-version" for c in conds), \
            f"{served} is no longer version-scoped; this policy's reason for existing is gone"
    try:
        bottom_rung_netpol([])
    except SystemExit as e:
        assert "empty allow-list" in str(e), e
    else:
        raise AssertionError("a bottom-rung reach cage rendered from an empty allow-list")
    from resourceset import guard_docs  # noqa: E402
    live = guard_docs(HERE / "versions.yaml", og._allow_expr(vs))
    assert NAME in live, sorted(live)
    assert live[NAME] == doc, f"versions.yaml's {NAME} has drifted from this twin"
    print("selfcheck ok: cage-netpol-bottom-rung carries cage-netpol's own reach table, keys on "
          "the same caged/tier output labels, adds only the no-served-version condition ranged "
          "from the same array, and versions.yaml renders it identically")


def main(argv: list[str]) -> int:
    import importlib.util
    if len(argv) > 1 and argv[1] == "--selfcheck":
        selfcheck()
        return 0
    s = importlib.util.spec_from_file_location("render_orphan_guard",
                                               HERE / "render-orphan-guard.py")
    og = importlib.util.module_from_spec(s)
    sys.modules["render_orphan_guard"] = og
    s.loader.exec_module(og)
    path = Path(argv[1]) if len(argv) > 1 else HERE / "versions.yaml"
    print(yaml.safe_dump(bottom_rung_netpol(og.served_versions(path)), sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
