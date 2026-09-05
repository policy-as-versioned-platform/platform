#!/usr/bin/env python3
"""render-governed-namespace-guard.py -- ADR-0014's fifth named gap, as a CAGE and a REPORT.

`distribution/versions.yaml` renders both of these live, beside the orphan-guard pair and not
inside it (ADR-0014). A workload created inside a namespace labelled
`policy-as-versioned.dev/governed: "true"` that carries no
`policy-as-versioned.dev/policy-version` claim is:

  * put on the BOTTOM RUNG by `governed_namespace_guard()`, a `MutatingPolicy`. It runs,
    isolated, and reaches nothing. It is not denied.
  * REPORTED by `governed_namespace_report()`, an `Audit` `ValidatingPolicy`, so the unclaimed
    population is still observed. A mutation and a report do not contend for a field, so the
    pair is safe where two mutations would not be.

## It was a Deny, and it is not any more (eco-system ticket 89)

ADR-0022's addendum of 2026-08-28 promoted this rule from `Audit` to `Deny` and called it "the
one refusal the doctrine allows". The reason it gave was real and observed live: under `Audit`
a claim-less pod ran COMPLETELY UNCAGED -- no tier, no PriorityClass, no limits, no hardening,
no reach cage -- inside a Namespace whose declared tier was `isolated`. The Namespace fell
closed and the pod fell open.

The owner overruled the shape, not the reason (2026-09-02, ticket 75 Q5): "something could find
itself unable to run, but that's only because it doesn't fit the cage, not because we
deliberately deny it. So, in Kubernetes Parlance, we've built a Mutating admission controller
more than a Approving admission and control."

The mutation answers the reason without the refusal, and the report gives back the observation
the Deny used to produce. Silence is no longer an exemption and no longer a refusal either:
silence is the bottom rung, and it is written down.

ADR-0020's "missing instrument" defence does not survive the same answer: a missing instrument
refuses to emit a PRICE, it never refuses a workload. The claim selects which SERVED VERSION
cages the pod; the BOTTOM RUNG needs no version to select it.

## Why the bottom rung and not the Namespace's declared tier

`cage-tier` renders the Namespace's declared tier onto pods that CLAIM a version -- and only
onto pods claiming ITS version, because every served copy carries an
`only-this-policy-version` matchCondition. This population claims nothing, so no served
policy version reaches it at all. The same fail-closed rule that gives an untiered Namespace
`isolated` gives this pod `isolated`: what the ladder cannot place goes to the bottom.

## Why the mutation body is COPIED (see cage_body.py)

There is one dial table (`graded/cage.py` TIERS) and one CEL expansion of it
(`graded/policies/cage-tier.yaml`), cross-checked by `verify-graded.sh`. `cage_body.py` reads
that expansion rather than writing a third copy, pins `tier` to the bottom rung, and extends
the same hardening to `initContainers`, which `cage-tier` does not touch.

## `CREATE` for the cage; `UPDATE` for the LABELS, in a separate policy

ADR-0014 excluded `UPDATE` because the Deny would have refused the currency controller's
re-cage patch. The refusal is gone, but the exclusion stands, and ticket 91 restated why in
this file's own words: `recage_patch()` is an `UPDATE` that strips the claim and writes
`tier: isolated` + `caged: "true"` in one merge patch, and it is the only way a running pod
admitted under a since-retired version reaches the bottom rung. This guard must not refuse it.

Round 2 of ticket 89 put `UPDATE` on THIS policy, gated on the pod already carrying
`posture.acme.io/caged: "true"`, in the belief that the marker meant "caged by this policy". It
does not -- `cage-tier` writes it for its whole population at every rung -- so the gate matched
a pod caged at `baseline`, and on `UPDATE` the full body appends a `waf-sidecar` to an
immutable container list and rewrites `priorityClassName` and `priority`. The API server
refuses that. It is a refusal by another name, in the ticket about refusals by another name,
and it would have refused `recage_patch()` exactly, whose patched object carries a stripped
claim and both those labels.

So the two jobs are split. This policy keeps `CREATE` and the full bottom-rung body.
`governed_namespace_hold()` beside it takes `UPDATE` and re-asserts the two LABELS and nothing
else -- which is all `UPDATE` was ever wanted for: `CREATE` alone leaves a caged pod
permanently relabelable, and `kubectl label --overwrite posture.acme.io/tier=baseline` would
drop it out of `cage-reach-isolated`'s podSelector for good. Two label writes restore that,
append nothing, rewrite no immutable field, and are byte-identical on top of `recage_patch()`,
which writes the same two values.

## What is still not caged

`cage-netpol` is version-scoped in every served copy, so it does not generate a NetworkPolicy
for this population. `render-bottom-rung-netpol.py` beside this file closes that; without it
"a running cage with no ingress and no egress" would not be true of exactly the population
this ticket creates.

This is platform machinery (cs-22's identity), not a per-release policy. Kyverno's
`matchConstraints.namespaceSelector` does not evaluate through the pinned CLI
(kyverno/kyverno#13605, confirmed against 1.18.2); it is the correct runtime mechanism and the
gap is CLI-offline evaluation only. `verify-governed-namespace-guard.sh` proves the mutation
with the selector stripped from a throwaway copy and proves the scoping structurally.

Usage:
    render-governed-namespace-guard.py             # print the MutatingPolicy
    render-governed-namespace-guard.py --report    # print the paired Audit ValidatingPolicy
    render-governed-namespace-guard.py --hold      # print the UPDATE labels-only policy
    render-governed-namespace-guard.py --selfcheck
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cage_body as cb  # noqa: E402

GOVERNED_LABEL = "policy-as-versioned.dev/governed"
CLAIM_LABEL = cb.CLAIM_LABEL
IDENTITY_LABEL = cb.IDENTITY_LABEL
IDENTITY = cb.IDENTITY
NAME = "governed-namespace-requires-claim"
REPORT_NAME = "governed-namespace-unclaimed-report"
BOTTOM_RUNG = cb.BOTTOM_RUNG

_UNCLAIMED = {
    "name": "claims-no-policy-version",
    "expression": f"object.metadata.?labels['{CLAIM_LABEL}'].orValue('') == ''",
}
_NS_SELECTOR = {"matchLabels": {GOVERNED_LABEL: "true"}}
HOLD_NAME = "governed-namespace-cage-holds"


def governed_namespace_guard(spec: dict | None = None) -> dict:
    """A MutatingPolicy that puts an unclaimed pod in a governed namespace on the bottom rung."""
    return cb.bottom_rung_policy(
        NAME,
        [{"apiGroups": [""], "apiVersions": ["v1"],
          "operations": ["CREATE"], "resources": ["pods"]}],
        [dict(_UNCLAIMED)],
        namespace_selector=dict(_NS_SELECTOR),
        spec=spec,
    )


def governed_namespace_hold() -> dict:
    """`UPDATE`: re-assert the bottom rung's two labels on an unclaimed pod, and nothing else.

    Same population as the cage, same rung, no container and no immutable field touched -- so
    the currency controller's `recage_patch()` stays admissible. See `cage_body.hold_policy`."""
    return cb.hold_policy(
        HOLD_NAME,
        [{"apiGroups": [""], "apiVersions": ["v1"],
          "operations": ["UPDATE"], "resources": ["pods"]}],
        [dict(_UNCLAIMED)],
        namespace_selector=dict(_NS_SELECTOR),
    )


def governed_namespace_report() -> dict:
    """The paired `Audit` ValidatingPolicy: the unclaimed population, observed, never refused.

    `CREATE` only, deliberately, while the cage pair spans `CREATE` (the body) and `UPDATE` (the
    labels-only hold). The three are not meant to observe the same events: the report's subject
    is ARRIVAL -- an unclaimed pod entered a governed namespace -- and that happens once. An
    `UPDATE`-scoped report would fire on every `kubectl label`, on every controller resync, and
    loudest of all on the currency controller's `recage_patch()`, which is the estate working
    correctly. That is noise about a fact already recorded, and PolicyReports are what the
    priced hole is computed from, so repeating one event would be double-counting it."""
    return {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "ValidatingPolicy",
        "metadata": {"name": REPORT_NAME, "labels": {IDENTITY_LABEL: IDENTITY}},
        "spec": {
            "validationActions": ["Audit"],
            "matchConstraints": {
                "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                   "operations": ["CREATE"], "resources": ["pods"]}],
                "namespaceSelector": dict(_NS_SELECTOR),
            },
            "validations": [{
                "expression": f"object.metadata.?labels['{CLAIM_LABEL}'].orValue('') != ''",
                "message": (
                    f'this namespace is governed ({GOVERNED_LABEL}: "true") and this pod carries '
                    f"no {CLAIM_LABEL} claim, so no served policy version governs it. It runs, "
                    f"caged on the bottom rung by {NAME}, and reaches nothing. Silence is not an "
                    f"exemption (ADR-0014); it is the bottom rung. Nothing is denied."
                ),
            }],
        },
    }


def selfcheck() -> None:
    doc = governed_namespace_guard()
    report = governed_namespace_report()
    assert doc["metadata"]["name"] == NAME, doc["metadata"]
    assert doc["metadata"]["labels"][IDENTITY_LABEL] == IDENTITY, doc["metadata"]
    # The whole point of eco-system ticket 89: this rule refuses nothing. A MutatingPolicy has
    # no `validationActions` field at all, so the assertion is that the kind changed and that
    # no refusal survived anywhere in the rendered document.
    assert doc["kind"] == "MutatingPolicy", doc["kind"]
    assert "validationActions" not in doc["spec"], doc["spec"]
    assert "validations" not in doc["spec"], doc["spec"]
    assert "Deny" not in yaml.safe_dump(doc), "a refusal survived in the rendered body"
    rule = doc["spec"]["matchConstraints"]["resourceRules"][0]
    # CREATE only, and it must STAY that way: on an UPDATE this body appends a waf-sidecar to a
    # running pod's immutable container list and rewrites priorityClassName and priority, which
    # the API server refuses -- and which would refuse ticket 91's recage_patch() in particular.
    assert rule["operations"] == ["CREATE"], rule
    assert rule["resources"] == ["pods"], rule
    assert doc["spec"]["matchConstraints"]["namespaceSelector"]["matchLabels"] == \
        {GOVERNED_LABEL: "true"}, doc["spec"]["matchConstraints"]
    names = [c["name"] for c in doc["spec"]["matchConditions"]]
    assert names == ["claims-no-policy-version"], names
    # ...and the UPDATE half is the labels-only hold, over the SAME population.
    hold = governed_namespace_hold()
    cb.assert_labels_only(hold)
    assert hold["spec"]["matchConditions"] == doc["spec"]["matchConditions"], \
        "the hold and the cage must cover the same population"
    assert hold["spec"]["matchConstraints"]["namespaceSelector"] == \
        doc["spec"]["matchConstraints"]["namespaceSelector"], hold["spec"]["matchConstraints"]
    # The rung is the bottom one, pinned to a literal so no Namespace label can move it.
    tier = next(v for v in doc["spec"]["variables"] if v["name"] == "tier")
    assert tier["expression"] == f"'{BOTTOM_RUNG}'", tier
    assert not any(v["name"] == "nsTier" for v in doc["spec"]["variables"]), doc["spec"]["variables"]
    assert "namespaceObject" not in yaml.safe_dump(doc["spec"]["variables"]), \
        "a namespaceObject read survives with nothing to read it for"
    # The dials are the shipped cage's own, plus the initContainer extension and nothing else.
    cage = cb.cage_tier_spec()
    assert doc["spec"]["mutations"][:len(cage["mutations"])] == cage["mutations"], \
        "the mutation body drifted from graded/policies/cage-tier.yaml"
    extra = doc["spec"]["mutations"][len(cage["mutations"]):]
    assert len(extra) == 2 and all("initContainers" in yaml.safe_dump(m) for m in extra), extra
    # The eviction class the bottom rung names must be one the machinery actually renders:
    # every SERVED PriorityClass is version-suffixed, so `cage-isolated` exists only because
    # this machinery ships it. A pod naming a class that does not exist is refused outright.
    cb.assert_priorityclass_is_rendered(doc)
    sys.path.insert(0, str(HERE.parent / "graded"))
    import cage  # noqa: E402
    assert cage.ORDER[-1] == BOTTOM_RUNG, cage.ORDER
    assert cage.TIERS[BOTTOM_RUNG]["priorityClass"] == "cage-isolated", cage.TIERS[BOTTOM_RUNG]
    # The report observes the same population and refuses nothing.
    assert report["kind"] == "ValidatingPolicy", report["kind"]
    assert report["spec"]["validationActions"] == ["Audit"], report["spec"]
    msg = report["spec"]["validations"][0]["message"]
    assert "cannot run" not in msg and "Nothing is denied" in msg, msg
    assert NAME in msg, "the report must name the policy that actually cages the pod"
    # The LIVE ResourceSet template renders both of these, identically to these twins. Nothing
    # asserted that before eco-system ticket 89, and they had already drifted: this twin
    # carried the platform-machinery identity label and the template's copy did not.
    from resourceset import guard_docs  # noqa: E402
    live = guard_docs(HERE / "versions.yaml", "unused-here")
    for want in (doc, report, hold):
        n = want["metadata"]["name"]
        assert n in live, sorted(live)
        assert live[n] == want, f"versions.yaml's {n} has drifted from this twin"
    print("selfcheck ok: governed-namespace-requires-claim is platform-machinery, a "
          "MutatingPolicy with no refusal in it, scoped to governed:true namespaces, CREATE plus "
          "UPDATE-when-already-caged, and it cages an unclaimed pod on the bottom rung using "
          "cage-tier's own mutation body extended to initContainers; the paired hold policy takes "
          "UPDATE and writes the two labels and nothing else, so the currency controller's "
          "recage patch stays admissible; the paired report is Audit "
          "and names the cage; versions.yaml renders both identically")


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        selfcheck()
        return 0
    if len(argv) > 1 and argv[1] == "--report":
        print(yaml.safe_dump(governed_namespace_report(), sort_keys=False))
        return 0
    if len(argv) > 1 and argv[1] == "--hold":
        print(yaml.safe_dump(governed_namespace_hold(), sort_keys=False))
        return 0
    print(yaml.safe_dump(governed_namespace_guard(), sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
