#!/usr/bin/env python3
"""render-governed-namespace-guard.py -- ADR-0014's fifth named gap, built.

`estate/platform/distribution/versions.yaml` renders this ValidatingPolicy live,
BESIDE `policy-version-orphan-guard` and not inside it (ADR-0014): a workload
created inside a namespace labelled `policy-as-versioned.dev/governed: "true"`
must carry a `policy-as-versioned.dev/policy-version` claim. `CREATE` only --
`UPDATE` is excluded on purpose, so the currency-controller's de-posture patch
(an `UPDATE` that strips the claim to cage a retired workload) keeps working.
Starts in `Audit`: ADR-0014's own consequence is that a brownfield estate
promotes by editorial PR, exactly like the orphan guard's own entry already
allows.

This is platform machinery (cs-22's identity), not a per-release policy -- it
does not evolve with `require-nonroot` and friends, so it is not versioned
under `distribution/policies/v*/`. Same placement as the orphan guard, and
the same offline-twin split, for the same reason: `verify-*.sh` and the
shift-left check run without flux-operator in the loop.

Kyverno's CEL `namespaceObject` (and `matchConstraints.namespaceSelector`,
offline) do not evaluate through the pinned CLI (kyverno/kyverno#9975,
kyverno/kyverno#13605 -- confirmed against kyverno 1.18.2, the version pinned
here) -- `namespaceSelector` is still the correct, standard runtime mechanism
(it works against a real API server; the gap is CLI-offline evaluation only),
so the manifest below still uses it. `verify-governed-namespace-guard.sh`
proves the `validations` expression itself (the claim check) with the
selector stripped from a throwaway copy, and proves the namespace-scoping
shape structurally instead of functionally -- see that script's own
docstring.

Usage:
    render-governed-namespace-guard.py             # print the ValidatingPolicy
    render-governed-namespace-guard.py --selfcheck
"""
from __future__ import annotations

import sys

GOVERNED_LABEL = "policy-as-versioned.dev/governed"
CLAIM_LABEL = "policy-as-versioned.dev/policy-version"
IDENTITY_LABEL = "policy-as-versioned.dev/policy"
IDENTITY = "platform-machinery"
NAME = "governed-namespace-requires-claim"


def governed_namespace_guard() -> dict:
    """A ValidatingPolicy that denies a CREATE-only, unclaimed pod inside a
    governed namespace. `UPDATE` stays out of scope so a de-posture patch
    (which strips the claim on an already-running pod) is never this
    policy's business -- the orphan guard's own absence-is-not-the-trigger
    rule, applied to a namespace boundary instead of a version array."""
    return {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "ValidatingPolicy",
        "metadata": {
            "name": NAME,
            "labels": {IDENTITY_LABEL: IDENTITY},
        },
        "spec": {
            "validationActions": ["Audit"],
            "matchConstraints": {
                "resourceRules": [{
                    "apiGroups": [""], "apiVersions": ["v1"],
                    "operations": ["CREATE"], "resources": ["pods"],
                }],
                "namespaceSelector": {"matchLabels": {GOVERNED_LABEL: "true"}},
            },
            "validations": [{
                "expression": f"object.metadata.?labels['{CLAIM_LABEL}'].orValue('') != ''",
                "message": (
                    f'this namespace is governed ({GOVERNED_LABEL}: "true"); a pod created '
                    f"here must carry a {CLAIM_LABEL} claim. Silence is not an exemption "
                    f"(ADR-0014)."
                ),
            }],
        },
    }


def selfcheck() -> None:
    doc = governed_namespace_guard()
    assert doc["metadata"]["name"] == NAME, doc["metadata"]
    assert doc["metadata"]["labels"][IDENTITY_LABEL] == IDENTITY, doc["metadata"]
    assert doc["spec"]["validationActions"] == ["Audit"], doc["spec"]
    rule = doc["spec"]["matchConstraints"]["resourceRules"][0]
    assert rule["operations"] == ["CREATE"], rule  # UPDATE excluded -- de-posture stays legal
    assert rule["resources"] == ["pods"], rule
    ns_sel = doc["spec"]["matchConstraints"]["namespaceSelector"]["matchLabels"]
    assert ns_sel == {GOVERNED_LABEL: "true"}, ns_sel
    expr = doc["spec"]["validations"][0]["expression"]
    assert CLAIM_LABEL in expr and "!= ''" in expr, expr
    print("selfcheck ok: governed-namespace-requires-claim is platform-machinery, Audit, "
          "CREATE-only, scoped to governed:true namespaces, denies an unclaimed pod")


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        selfcheck()
        return 0
    import yaml
    print(yaml.safe_dump(governed_namespace_guard(), sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
