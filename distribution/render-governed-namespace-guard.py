#!/usr/bin/env python3
"""render-governed-namespace-guard.py -- ADR-0014's fifth named gap, as a CAGE.

`distribution/versions.yaml` renders this policy live, BESIDE
`policy-version-orphan-guard` and not inside it (ADR-0014): a workload created inside a
namespace labelled `policy-as-versioned.dev/governed: "true"` that carries no
`policy-as-versioned.dev/policy-version` claim is put on the BOTTOM RUNG. It runs, isolated,
and reaches nothing. It is not denied.

## It was a Deny, and it is not any more (eco-system ticket 89)

ADR-0022's addendum of 2026-08-28 promoted this rule from `Audit` to `Deny` and called it
"the one refusal the doctrine allows". The reason it gave was real and observed live: under
`Audit` a claim-less pod ran COMPLETELY UNCAGED -- no tier, no PriorityClass, no limits, no
hardening, no reach cage -- inside a Namespace whose declared tier was `isolated`. The
Namespace fell closed and the pod fell open.

The owner overruled the shape, not the reason (2026-09-02, ticket 75 Q5): "something could
find itself unable to run, but that's only because it doesn't fit the cage, not because we
deliberately deny it. So, in Kubernetes Parlance, we've built a Mutating admission controller
more than a Approving admission and control."

A mutation answers the reason without the refusal. The pod is admitted and CAGED: it comes
out of admission carrying `posture.acme.io/tier: isolated`, `posture.acme.io/caged: "true"`,
the isolated dials, host namespaces clobbered shut and all capabilities dropped -- so the
Namespace falls closed AND the pod falls closed. Silence is no longer an exemption and it is
no longer a refusal either: silence is the bottom rung.

ADR-0020's "missing instrument" defence does not survive the same answer, and it is worth
saying why rather than dropping it: a missing instrument refuses to emit a PRICE, it never
refuses a workload. The claim selects which SERVED VERSION cages the pod; the BOTTOM RUNG
needs no version to select it, because it is where everything the ladder cannot place ends
up. So there was a cage to put the workload in all along.

## Why the bottom rung and not the Namespace's declared tier

`cage-tier` renders the Namespace's declared tier onto every pod that CLAIMS a version. This
population claims nothing, so it is governed by no served policy version at all -- none of
the versioned rules self-scope to it. The same fail-closed rule that gives an untiered
Namespace `isolated` gives this pod `isolated`: what the ladder cannot place goes to the
bottom. CONTEXT.md's Cage entry already says so ("an unknown or unlabelled tier fails closed
to `isolated`").

## Why the mutation body is COPIED from cage-tier rather than written again

There is exactly one dial table in this estate (`graded/cage.py` TIERS) and exactly one CEL
expansion of it (`graded/policies/cage-tier.yaml`), and `verify-graded.sh` cross-checks that
the two never drift. A second hand-written expansion here would be a third copy nobody
cross-checks. So this renderer READS `graded/policies/cage-tier.yaml` and reuses its
`mutations` verbatim, with the `tier` variable pinned to the literal `'isolated'` and the
now-unread `nsTier` variable dropped. A change to the cage's dials reaches this policy in the
same commit that makes it, or not at all.

## Why `CREATE` only, still -- for a NEW reason

ADR-0014 excluded `UPDATE` because the Deny would have refused the currency controller's
de-posture patch (an `UPDATE` that strips the claim from a running workload). That reason is
void: a mutation refuses nothing. The exclusion stands on a different fact, observed live on
2026-08-28 during ticket 26: a mutation that is not byte-identical on `UPDATE` is a refusal by
another name. On the de-posture `UPDATE` this policy would begin matching a pod `cage-tier`
had been caging, and the isolated rung's mutation injects a `waf-sidecar` container. A pod's
container list is immutable after creation, so the API server would reject that `UPDATE`
outright -- the cage becoming the refusal, which is exactly the failure ticket 26 found and
fixed. `CREATE` only keeps the de-posture patch legal, and a de-postured pod is caged when
its controller recreates it, which is what CONTEXT.md's **De-postured** entry already says.

This is platform machinery (cs-22's identity), not a per-release policy -- it does not evolve
with `require-nonroot` and friends, so it is not versioned under `distribution/policies/v*/`.
Same placement as the orphan guard, and the same offline-twin split, for the same reason:
`verify-*.sh` and the shift-left check run without flux-operator in the loop.

Kyverno's `matchConstraints.namespaceSelector` does not evaluate through the pinned CLI
(kyverno/kyverno#13605, confirmed against kyverno 1.18.2) -- it is still the correct, standard
runtime mechanism, and the gap is CLI-offline evaluation only. `verify-governed-namespace-guard.sh`
proves the MUTATION itself with the selector stripped from a throwaway copy, and proves the
namespace-scoping shape structurally instead of functionally -- see that script's own docstring.

Usage:
    render-governed-namespace-guard.py             # print the MutatingPolicy
    render-governed-namespace-guard.py --selfcheck
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CAGE_TIER = HERE.parent / "graded" / "policies" / "cage-tier.yaml"

GOVERNED_LABEL = "policy-as-versioned.dev/governed"
CLAIM_LABEL = "policy-as-versioned.dev/policy-version"
IDENTITY_LABEL = "policy-as-versioned.dev/policy"
IDENTITY = "platform-machinery"
NAME = "governed-namespace-requires-claim"
#: The rung a pod the ladder cannot place lands on. Not a knob: `graded/cage.py` ORDER[-1].
BOTTOM_RUNG = "isolated"


def cage_tier_body(path: Path | None = None) -> dict:
    """The shipped cage's own `variables` and `mutations`. One dial table, one expansion."""
    doc = yaml.safe_load((path or CAGE_TIER).read_text())
    if doc.get("kind") != "MutatingPolicy":
        raise SystemExit(f"{path or CAGE_TIER} is not a MutatingPolicy; refusing to copy its body")
    return doc["spec"]


def governed_namespace_guard(cage_spec: dict | None = None) -> dict:
    """A MutatingPolicy that puts a CREATE-only, unclaimed pod inside a governed namespace on
    the bottom rung. Nothing is denied.

    `UPDATE` stays out of scope so a de-posture patch (which strips the claim on an already
    running pod) never reaches a mutation that would inject a sidecar into an immutable
    container list -- see the module docstring."""
    spec = copy.deepcopy(cage_spec if cage_spec is not None else cage_tier_body())
    variables = [v for v in spec.get("variables", []) if v["name"] != "nsTier"]
    for v in variables:
        if v["name"] == "tier":
            # The whole of the difference from `cage-tier`: this population is placed at the
            # bottom of the ladder rather than at the tier its Namespace declares, because no
            # served policy version reaches it at all.
            v["expression"] = f"'{BOTTOM_RUNG}'"
    return {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "MutatingPolicy",
        "metadata": {
            "name": NAME,
            "labels": {IDENTITY_LABEL: IDENTITY},
        },
        "spec": {
            "matchConstraints": {
                "resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"],
                    "operations": ["CREATE"], "resources": ["pods"],
                }],
                "namespaceSelector": {"matchLabels": {GOVERNED_LABEL: "true"}},
            },
            "matchConditions": [{
                "name": "claims-no-policy-version",
                "expression": f"object.metadata.?labels['{CLAIM_LABEL}'].orValue('') == ''",
            }],
            "variables": variables,
            "mutations": spec["mutations"],
        },
    }


def selfcheck() -> None:
    doc = governed_namespace_guard()
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
    assert rule["operations"] == ["CREATE"], rule  # UPDATE excluded -- see the docstring
    assert rule["resources"] == ["pods"], rule
    ns_sel = doc["spec"]["matchConstraints"]["namespaceSelector"]["matchLabels"]
    assert ns_sel == {GOVERNED_LABEL: "true"}, ns_sel
    expr = doc["spec"]["matchConditions"][0]["expression"]
    assert CLAIM_LABEL in expr and "== ''" in expr, expr
    # The rung is the bottom one, and it is pinned to a literal so no Namespace label can move
    # it: this population is not on the selectable ladder.
    tier = next(v for v in doc["spec"]["variables"] if v["name"] == "tier")
    assert tier["expression"] == f"'{BOTTOM_RUNG}'", tier
    assert not any(v["name"] == "nsTier" for v in doc["spec"]["variables"]), doc["spec"]["variables"]
    assert "namespaceObject" not in yaml.safe_dump(doc["spec"]["variables"]), \
        "a namespaceObject read survives with nothing to read it for"
    # The dials are the shipped cage's own, not a second copy: every mutation is `cage-tier`'s
    # byte for byte. If that body changes, this policy changes in the same commit.
    assert doc["spec"]["mutations"] == cage_tier_body()["mutations"], \
        "the mutation body drifted from graded/policies/cage-tier.yaml"
    # ...and the bottom rung really is the tightest thing the dial table knows.
    # The LIVE ResourceSet template and this offline twin render the SAME document -- the
    # drift nothing checked until eco-system ticket 89 (see resourceset.py).
    sys.path.insert(0, str(HERE))
    from resourceset import guard_docs  # noqa: E402
    live = guard_docs(HERE / "versions.yaml", "unused-here")
    assert NAME in live, sorted(live)
    assert live[NAME] == doc, "versions.yaml's governed-namespace cage has drifted from this twin"
    sys.path.insert(0, str(HERE.parent / "graded"))
    import cage  # noqa: E402
    assert cage.ORDER[-1] == BOTTOM_RUNG, cage.ORDER
    assert cage.TIERS[BOTTOM_RUNG]["priorityClass"] == "cage-isolated", cage.TIERS[BOTTOM_RUNG]
    print("selfcheck ok: governed-namespace-requires-claim is platform-machinery, a "
          "MutatingPolicy with no refusal in it, CREATE-only, scoped to governed:true "
          "namespaces, and it cages an unclaimed pod on the bottom rung using cage-tier's own "
          "mutation body, which versions.yaml renders identically")


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        selfcheck()
        return 0
    print(yaml.safe_dump(governed_namespace_guard(), sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
