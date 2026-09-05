#!/usr/bin/env python3
"""render-orphan-guard.py — the orphan-guard, rendered from the version array.

## It was a Deny, and it is a REPORT and a CAGE now (eco-system ticket 89)

The owner, 2026-09-02 (ticket 75 Q5): "something could find itself unable to run, but that's
only because it doesn't fit the cage, not because we deliberately deny it. So, in Kubernetes
Parlance, we've built a Mutating admission controller more than a Approving admission and
control." This rule shipped `validationActions: [Deny]` with the message "so it cannot run".
Nothing in this estate is deliberately denied, so it is a PAIR now:

  * `orphan_guard()` -- the same ValidatingPolicy, `Audit`. It refuses nothing and it still
    reports the orphan claim by name.
  * `orphan_cage()` -- a `MutatingPolicy` that puts the same pod on the BOTTOM RUNG.

## The cage is not optional, and the first attempt at this ticket got that wrong

The demotion was first shipped ALONE, on the reasoning that "every claiming pod is already
caged by `cage-tier`". That is false of the served estate, and the review caught it. Every
SERVED copy of `cage-tier` carries an `only-this-policy-version` matchCondition -- see
`distribution/policies/v4.0.0/cage-tier.yaml` and each adopter's
`composed/policies/v4.0.0/cage-tier.yaml`. An orphan claim is BY DEFINITION a version no
served line carries, so it matches no `cage-tier` anywhere. Demoted alone, the pod ran with no
tier, no caged marker, no PriorityClass, no limits, no hardening and no NetworkPolicy: the
"Namespace fell closed, pod fell open" hole ADR-0022 promoted the other guard to `Deny` to
close, re-opened through this one. Worse, it was attacker-selectable -- any pod opted out of
every versioned rule by claiming a bogus version, which is a self-service exemption and
principle 1 bans those.

The measurement that produced the wrong reasoning was taken against
`graded/policies/cage-tier.yaml`, which matches ANY claim -- and which `graded/up.sh` says in
its own header is never applied: it "applies ONLY the rendered, versioned copies -- never the
graded/policies/ authoring copies". So it measured a configuration that exists nowhere.

Re-measured against the SERVED bodies, the same fact makes the pair SAFE: the served
`cage-tier` matches only claims IN the array and `orphan_cage()` matches only claims NOT in
it, from the same array. The two populations are disjoint by construction, so the two
mutations never contend for a field, and the label-and-dials incoherence that ruled out a
second writer does not arise. `verify-orphan-guard.sh` proves the disjointness by running both
bodies over the same three pods.

## What the Audit report is FOR

An orphan claim is a claim no served policy version self-scopes to, so the pod is governed by
none of the versioned rules even though it is caged. Under the doctrine that is a PRICED HOLE
(ADR-0026: a hole is priced, never refused), and this report is the observation the price is
computed from. It is not an exemption ledger and it is not a count that decides anything: it
is the fact. A report and a mutation do not contend for a field, so the pair is safe where two
mutations would not be.

## What is still NOT done here

An orphan claim gets the bottom rung from a policy BESIDE `cage-tier`, not from `cage-tier`'s
own `tier` expression. Folding it in there -- with the allow-list ranged in from this same
array -- is the tidier answer and remains ticket 84's, because `cage-tier` is a versioned
policy body and that is a new declared line with the engine's computed bump.

flux-operator's ResourceSet (versions.yaml) renders the orphan-guard live by
ranging `spec.inputs[0].versions[]`. This is its offline twin: the verify-*.sh
beats and the shift-left check (ticket 12) run without flux-operator in the loop,
so they need to derive the SAME allow-list from the SAME array deterministically.

There is exactly one array (in versions.yaml). Both renderers read it; neither
hand-maintains an allow-list, so the runnable-version set cannot drift from the
declared-version set. That is the whole point of the orphan-guard.

Usage:
    render-orphan-guard.py [versions.yaml]        # print the Audit ValidatingPolicy
    render-orphan-guard.py --cage [versions.yaml] # print the bottom-rung MutatingPolicy
    render-orphan-guard.py --hold [versions.yaml] # print the UPDATE labels-only policy
    render-orphan-guard.py --retire 2.0.0 [file]  # simulate retiring a version
    render-orphan-guard.py --selfcheck            # runnable asserts
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cage_body as cb  # noqa: E402

LABEL = "policy-as-versioned.dev/policy-version"
CAGE_NAME = "policy-version-orphan-cage"

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


def partition(els: list[dict]) -> tuple[list[str], list[str]]:
    """(cut, uncut) by the `commit` field, exactly as verify-declared-versions-admit.sh
    partitions it and for exactly the same reason: `cut-release.yml` fills `commit` in when it
    cuts the signed tag, so an element without one is an UNCUT TAIL -- no tag exists, Flux has
    nothing to deliver, and NO `cage-tier-<version>` is installed anywhere."""
    return ([e["version"] for e in els if e.get("commit")],
            [e["version"] for e in els if not e.get("commit")])


def served_versions(path: Path, retire: str | None = None) -> list[str]:
    """The versions a pod can actually be CAGED under: declared AND cut.

    This is what the orphan pair's allow-list ranges over, and the distinction is not
    cosmetic. `versions()` returns everything the array declares, uncut tails included. Ranging
    the allow-list over that put `5.0.0` -- declared, no `commit`, no tag, no served
    `cage-tier-5-0-0` anywhere -- inside the allow-list, so the orphan cage SKIPPED a pod
    claiming it and the report did not report it, while no versioned cage matched it either.
    That pod ran uncaged, and it was selectable by anyone who read `versions.yaml`: the round-1
    defect's exact shape, found again by the review of 2026-09-05.

    Ranging over CUT elements only puts an uncut declared version in the orphan population, so
    a pod claiming it is caged on the bottom rung until its tag exists — and falls out of that
    population by itself on the day `cut-release.yml` fills the commit in."""
    els = [e for e in elements(path) if e["version"] != retire]
    cut, _ = partition(els)
    return cut


#: Not `Deny`, and not a knob (eco-system ticket 89). See the module docstring: an orphan claim
#: is admitted and caged on the BOTTOM RUNG by `policy-version-orphan-cage`, because no served
#: `cage-tier` matches it -- every one is scoped to its own version. The escape it makes from
#: every versioned rule is a priced hole, and this report is the observation that price rests on.
#: (An earlier draft of this line said `cage-tier` caged it at its Namespace's tier. That was
#: the round-1 premise the review overturned; it is false, and the docstring above says why.)
ACTION = "Audit"


def orphan_guard(allowed: list[str]) -> dict:
    """A ValidatingPolicy that REPORTS any pod claiming a version not in `allowed`.

    Unlabeled pods are out of scope (they claim no version); a pod that claims a
    version the array doesn't declare is admitted, caged and reported. Allow-list
    ranged from the array. Nothing here refuses anything.
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
            "validationActions": [ACTION],
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
                           "no ResourceSet element declares it, so no served policy version "
                           "governs this pod -- every served cage-tier is scoped to its own "
                           "version. It runs, caged on the bottom rung by "
                           f"{CAGE_NAME}, and the rules it escapes are a priced hole "
                           "(ADR-0026). Nothing is denied.",
            }],
        },
    }


def _allow_expr(vs: list[str]) -> str:
    return "[" + ", ".join(f"'{v}'" for v in vs) + "]"


def _undeclared_condition(allowed: list[str]) -> dict:
    """Claims a version, and not one this array declares. The one condition both halves share."""
    return {"name": "claims-an-undeclared-version",
            "expression": (f"object.metadata.?labels['{LABEL}'].orValue('') != '' && "
                           f"!({_allow_expr(allowed)}.exists(v, "
                           f"v == object.metadata.labels['{LABEL}']))")}


def orphan_cage(allowed: list[str], spec: dict | None = None) -> dict:
    """A MutatingPolicy that puts a pod claiming an undeclared version on the bottom rung.

    Disjoint from every SERVED `cage-tier` by construction: those match only claims IN this
    same array (`only-this-policy-version`), this matches only claims NOT in it. So the two
    mutations never see the same pod and never contend for a field.

    `CREATE` only, for the same reason as the governed-namespace cage: on an `UPDATE` this body
    appends a `waf-sidecar` to a running pod's immutable container list and rewrites
    `priorityClassName` and `priority`, which the API server refuses. `orphan_cage_hold()`
    takes `UPDATE` and re-asserts the two labels and nothing else."""
    if not allowed:
        raise SystemExit("refusing to render an orphan cage with an empty allow-list")
    return cb.bottom_rung_policy(
        CAGE_NAME,
        [{"apiGroups": [""], "apiVersions": ["v1"],
          "operations": ["CREATE"], "resources": ["pods"]}],
        [_undeclared_condition(allowed)],
        spec=spec,
    )


def orphan_cage_hold(allowed: list[str]) -> dict:
    """`UPDATE`: re-assert the bottom rung's two labels on an orphan-claiming pod, nothing else.

    Without it a caged orphan pod could `kubectl label` its way out of `cage-reach-isolated`.
    With the full body on `UPDATE` it could not be patched at all. See `cage_body.hold_policy`."""
    if not allowed:
        raise SystemExit("refusing to render an orphan hold with an empty allow-list")
    return cb.hold_policy(
        CAGE_NAME + "-holds",
        [{"apiGroups": [""], "apiVersions": ["v1"],
          "operations": ["UPDATE"], "resources": ["pods"]}],
        [_undeclared_condition(allowed)],
    )


def selfcheck() -> None:
    # Asserts derive from whatever versions.yaml currently declares, not a
    # hardcoded literal -- the array grows and shrinks over real releases
    # (cs-15 replaced 1.0.0/2.0.0 with 2.0.0/3.0.0), and this selfcheck must
    # not need editing on every one.
    declared = versions(HERE / "versions.yaml")
    vs = served_versions(HERE / "versions.yaml")
    # >= 1, not >= 2: on 2026-08-29 the whole 2.x/3.x fan-out was retired and the
    # array legitimately declares one line. An array with NO element would render
    # an empty allow-list, which orphan_guard() refuses outright.
    assert len(declared) >= 1, f"the version array declares nothing: {declared}"
    assert vs, ("the array declares versions but none is CUT, so nothing is served and "
                "the allow-list would be empty")
    # elements() carries the raw dicts (commit field and all) versions()
    # itself is built from -- one parse point, not two.
    els = elements(HERE / "versions.yaml")
    assert [e["version"] for e in els] == declared, els
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
    # eco-system ticket 89: this rule refuses nothing, and its message may not say it does.
    assert og["spec"]["validationActions"] == ["Audit"], og["spec"]
    msg = og["spec"]["validations"][0]["message"]
    assert "cannot run" not in msg, msg
    assert "Nothing is denied" in msg, msg
    assert CAGE_NAME in msg, "the report must name the policy that actually cages the pod"

    # ...and the cage that makes the demotion safe. The report alone left an orphan claim
    # uncaged, because every SERVED cage-tier is scoped to its own version.
    oc = orphan_cage(vs)
    assert oc["kind"] == "MutatingPolicy", oc["kind"]
    assert "validationActions" not in oc["spec"] and "validations" not in oc["spec"], oc["spec"]
    assert "Deny" not in yaml.safe_dump(oc), "a refusal survived in the cage body"
    assert oc["metadata"]["labels"][IDENTITY_LABEL] == IDENTITY, oc["metadata"]
    tier = next(v for v in oc["spec"]["variables"] if v["name"] == "tier")
    assert tier["expression"] == f"'{cb.BOTTOM_RUNG}'", tier
    # The allow-list is the SAME array, in both halves of the pair, so the population the
    # report names and the population the cage cages can never differ.
    assert _allow_expr(vs) in oc["spec"]["matchConditions"][0]["expression"], oc["spec"]
    assert og["spec"]["variables"][0]["expression"] == _allow_expr(vs)
    # Disjoint from the served cage-tier by construction: it matches claims IN the array,
    # this matches claims NOT in it. Asserted for EVERY version the array declares, on the real
    # served bodies, never on the authoring copy graded/up.sh says it never applies. Driven by
    # the array rather than by a fixture: a version added to the array without a version-scoped
    # cage would break the disjointness argument silently, and this is what catches that.
    checked = 0
    for v in vs:
        served = HERE / "policies" / f"v{v}" / "cage-tier.yaml"
        if not served.exists():
            continue
        conds = yaml.safe_load(served.read_text())["spec"]["matchConditions"]
        scoped = [c for c in conds if c["name"] == "only-this-policy-version"]
        assert scoped, f"{served} lost its version scoping; the disjointness argument is gone"
        assert f"== '{v}'" in scoped[0]["expression"], (v, scoped)
        # ...and that scoping is what makes this cage's condition its exact complement: the
        # served body takes this version, this cage's allow-list contains it, so this cage
        # cannot.
        assert f"'{v}'" in oc["spec"]["matchConditions"][0]["expression"], (v, oc["spec"])
        checked += 1
    assert checked == len(vs), (
        f"only {checked} of {len(vs)} declared versions have a served, version-scoped "
        f"cage-tier; a declared version without one is a population this pair does not cover")
    cb.assert_priorityclass_is_rendered(oc)
    assert oc["spec"]["matchConstraints"]["resourceRules"][0]["operations"] == ["CREATE"], oc["spec"]
    och = orphan_cage_hold(vs)
    cb.assert_labels_only(och)
    assert och["spec"]["matchConditions"] == oc["spec"]["matchConditions"], \
        "the hold and the cage must cover the same population"
    # The dial table is cage-tier's own, plus the initContainer extension and nothing else.
    cage_spec = cb.cage_tier_spec()
    assert oc["spec"]["mutations"][:len(cage_spec["mutations"])] == cage_spec["mutations"], \
        "the cage body drifted from graded/policies/cage-tier.yaml"
    # An empty allow-list renders no cage, exactly as it renders no guard.
    try:
        orphan_cage([])
    except SystemExit as e:
        assert "empty allow-list" in str(e), e
    else:
        raise AssertionError("an orphan cage rendered from an empty allow-list")
    # retiring a version drops it from the allow-list
    retired = vs[-1]
    remaining = served_versions(HERE / "versions.yaml", retire=retired)
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
    assert set(declared) <= dirs, \
        f"array {declared} names a version with no policies/ dir, got dirs {sorted(dirs)}"
    # R3 (review, 2026-09-05): an UNCUT declared version has no tag, so no cage-tier-<v> is
    # installed anywhere. If it sat in the allow-list, the orphan cage would skip a pod claiming
    # it and the report would not report it, while no versioned cage matched it either -- a pod
    # running uncaged, selectable by anyone who read versions.yaml. It must be in the ORPHAN
    # population instead, and this is what says so.
    _, uncut = partition(elements(HERE / "versions.yaml"))
    for u in uncut:
        assert u not in vs, (u, vs)
        assert f"'{u}'" not in oc["spec"]["matchConditions"][0]["expression"], \
            f"uncut {u} is in the orphan cage's allow-list, so a pod claiming it is caged by nothing"
    # The LIVE ResourceSet template and this offline twin render the SAME document. Nothing
    # asserted that until eco-system ticket 89, and they had already drifted: the twin carried
    # the platform-machinery identity label and the template's copy did not.
    sys.path.insert(0, str(HERE))
    from resourceset import guard_docs  # noqa: E402
    live = guard_docs(HERE / "versions.yaml", _allow_expr(vs))
    for want in (og, oc, och):
        n = want["metadata"]["name"]
        assert n in live, sorted(live)
        assert live[n] == want, f"versions.yaml's {n} has drifted from this twin"
    print("selfcheck ok: allow-list == array; every array version has a policies/ dir; retire drops a version; the action is Audit and the message refuses nothing; versions.yaml renders the same document this twin does")


def main(argv: list[str]) -> int:
    retire = None
    args = argv[1:]
    if args and args[0] == "--selfcheck":
        selfcheck()
        return 0
    cage = False
    # `--cage` and `--retire` in either order: verify-retirement.sh asks for the cage rendered
    # from a SHRUNK array, which is the whole point of retiring a version.
    hold = False
    while args and args[0] in ("--cage", "--hold", "--retire"):
        if args[0] == "--cage":
            cage, args = True, args[1:]
        elif args[0] == "--hold":
            hold, args = True, args[1:]
        else:
            retire, args = args[1], args[2:]
    path = Path(args[0]) if args else HERE / "versions.yaml"
    vs = served_versions(path, retire)
    doc = orphan_cage_hold(vs) if hold else (orphan_cage(vs) if cage else orphan_guard(vs))
    print(yaml.safe_dump(doc, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
