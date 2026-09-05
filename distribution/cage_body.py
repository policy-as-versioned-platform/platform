#!/usr/bin/env python3
"""cage_body.py -- the bottom rung's mutation, built from the shipped cage and nothing else.

Eco-system ticket 89. Two policies here put a workload on the bottom rung rather than refusing
it: `governed-namespace-requires-claim` (a pod with no claim, inside a governed Namespace) and
`policy-version-orphan-cage` (a pod claiming a version the platform's array does not declare).
Both need the same dials, and the estate already has exactly one expansion of the dial table:
`graded/policies/cage-tier.yaml`, which `verify-graded.sh` cross-checks against `graded/cage.py`
TIERS so the two can never drift.

So this module READS that body and reuses it, with two changes:

  * `tier` is pinned to the literal bottom rung and the now-unread `nsTier` variable is dropped.
    Neither population is on the selectable ladder: one claims nothing, the other claims a
    version no served policy carries, so no Namespace tier applies to either.

  * the container hardening is extended to `initContainers`. `cage-tier` maps
    `object.spec.containers` only. For its own population that is a gap somebody else owns
    (the versioned body, ticket 84); for THIS population it would be a hole this ticket dug,
    because a privileged `runAsUser: 0` initContainer used to be refused outright and would
    now run. Measured on kyverno 1.18.2 before it was written, not assumed.

## What the initContainer extension does NOT do

It cannot remove `runAsUser: 0`. `runAsNonRoot: true` is written beside it, and the kubelet
refuses to START a container that declares both -- so such a pod is admitted, caged, and does
not run. That is the doctrine's own permitted outcome ("unable to run because it does not fit
the cage"), not a refusal, and it is named here rather than left for a reader to discover.

Library only; the renderers import it.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CAGE_TIER = HERE.parent / "graded" / "policies" / "cage-tier.yaml"
PRIORITYCLASSES = HERE.parent / "graded" / "policies" / "priorityclasses.yaml"

#: The rung a pod the ladder cannot place lands on. Not a knob: `graded/cage.py` ORDER[-1].
BOTTOM_RUNG = "isolated"
CLAIM_LABEL = "policy-as-versioned.dev/policy-version"
CAGED_LABEL = "posture.acme.io/caged"
IDENTITY_LABEL = "policy-as-versioned.dev/policy"
IDENTITY = "platform-machinery"
#: The eviction class the bottom rung names. `graded/cage.py` TIERS[BOTTOM_RUNG]["priorityClass"].
TIERS_PC = "cage-isolated"

#: The bottom rung's own securityContext, ORed with whatever the initContainer declared, in the
#: same shape and with the same tighten-only reasoning `cage-tier` uses for `containers`.
_INIT_MUTATION = {
    "patchType": "ApplyConfiguration",
    "applyConfiguration": {
        "expression": (
            "Object{\n"
            "  spec: Object.spec{\n"
            "    initContainers: object.spec.?initContainers.orValue([]).map(c,"
            " Object.spec.initContainers{\n"
            "      name: c.name,\n"
            "      resources: Object.spec.initContainers.resources{\n"
            "        limits: {\n"
            "          \"cpu\": (has(c.resources) && c.resources.?limits[\"cpu\"].hasValue() &&\n"
            "                  quantity(string(c.resources.limits[\"cpu\"]))"
            ".isLessThan(quantity(variables.dial.cpu)))\n"
            "                   ? string(c.resources.limits[\"cpu\"]) : variables.dial.cpu,\n"
            "          \"memory\": (has(c.resources) && c.resources.?limits[\"memory\"].hasValue() &&\n"
            "                  quantity(string(c.resources.limits[\"memory\"]))"
            ".isLessThan(quantity(variables.dial.mem)))\n"
            "                   ? string(c.resources.limits[\"memory\"]) : variables.dial.mem\n"
            "        }\n"
            "      },\n"
            "      securityContext: Object.spec.initContainers.securityContext{\n"
            "        readOnlyRootFilesystem: variables.dial.harden == 'true' ||\n"
            "          (has(c.securityContext) &&"
            " c.securityContext.?readOnlyRootFilesystem.orValue(false)),\n"
            "        runAsNonRoot: variables.dial.harden == 'true' ||\n"
            "          (has(c.securityContext) && c.securityContext.?runAsNonRoot.orValue(false)),\n"
            "        allowPrivilegeEscalation: false,\n"
            "        privileged: false\n"
            "      }\n"
            "    })\n"
            "  }\n"
            "}"
        )
    },
}

#: Drop ALL capabilities on every initContainer, the JSONPatch half, exactly as `cage-tier`
#: does for `containers` and for the same reason: `capabilities.drop` is an atomic list SSA
#: may not merge. Empty when the pod declares no initContainers, so nothing is invented.
_INIT_CAPS = {
    "patchType": "JSONPatch",
    "jsonPatch": {
        "expression": (
            "variables.dial.harden == 'true'\n"
            "  ? object.spec.?initContainers.orValue([]).map(c,\n"
            "      JSONPatch{\n"
            "        op: \"add\",\n"
            "        path: \"/spec/initContainers/\""
            " + string(object.spec.initContainers.indexOf(c)) + \"/securityContext/capabilities\",\n"
            "        value: {\"drop\": [\"ALL\"]}\n"
            "      })\n"
            "  : []"
        )
    },
}


def bottom_rung_priorityclass(path: Path | None = None) -> dict:
    """The eviction PriorityClass the bottom rung names, rendered UNSUFFIXED for the machinery.

    Found by running the beat, not by reading the code (2026-09-05): every SERVED
    PriorityClass is version-suffixed -- `distribution/policies/v4.0.0/priorityclasses.yaml`
    ships `cage-isolated-4-0-0` and nothing called `cage-isolated`, because the version tree is
    the only thing applied. `cage-tier`'s body is rewritten to match by the same render. The
    machinery cages here copy the AUTHORING body, which names `cage-isolated`, and there is no
    version whose suffix they could borrow: they exist precisely for pods no version reaches,
    and a class named for a version that later retires would vanish under them.

    Left alone, that is a REFUSAL BY ANOTHER NAME and the worst kind -- the Priority admission
    plugin rejects a pod naming a PriorityClass that does not exist, so this ticket's own cage
    would have made every pod it caged inadmissible. So the machinery ships the unsuffixed
    class beside its policies, read from the same authoring file the dial table is read from.

    Only the bottom rung's class is rendered, because `tier` is pinned to the bottom rung and
    no other `pc` value can be reached. `selfcheck` in each renderer asserts exactly that, so
    unpinning the tier without rendering the rest of the ladder cannot pass silently.
    """
    docs = [d for d in yaml.safe_load_all((path or PRIORITYCLASSES).read_text()) if d]
    want = TIERS_PC
    for d in docs:
        if d.get("kind") == "PriorityClass" and d.get("metadata", {}).get("name") == want:
            out = copy.deepcopy(d)
            out.setdefault("metadata", {}).setdefault("labels", {})[IDENTITY_LABEL] = IDENTITY
            return out
    raise SystemExit(f"no PriorityClass named {want} in {path or PRIORITYCLASSES}")


def assert_priorityclass_is_rendered(policy: dict) -> None:
    """The only eviction class this policy can name is the one the machinery renders.

    The dial map carries all four rungs, but `tier` is pinned, so exactly one `pc` value is
    reachable. This ties the two together: unpinning the tier, or renaming the class, fails
    here rather than on a cluster as an inadmissible pod.
    """
    tier = next(v for v in policy["spec"]["variables"] if v["name"] == "tier")
    assert tier["expression"] == f"'{BOTTOM_RUNG}'", tier
    dial = next(v for v in policy["spec"]["variables"] if v["name"] == "dial")
    row = re.search(rf"'{BOTTOM_RUNG}':\s*\{{([^}}]*)\}}", dial["expression"])
    assert row, dial["expression"]
    pc = re.search(r"'pc'\s*:\s*'([^']+)'", row.group(1))
    prio = re.search(r"'prio'\s*:\s*'(-?\d+)'", row.group(1))
    assert pc and prio, row.group(1)
    assert pc.group(1) == TIERS_PC, (
        f"the bottom rung names PriorityClass {pc.group(1)!r} but the machinery renders "
        f"{TIERS_PC!r}; a pod naming a class that does not exist is refused by the Priority "
        f"admission plugin, which is a refusal by another name")
    cls = bottom_rung_priorityclass()
    assert cls["metadata"]["name"] == TIERS_PC, cls["metadata"]
    assert int(cls["value"]) == int(prio.group(1)), (
        f"the dial writes priority {prio.group(1)} and {TIERS_PC} is {cls['value']}; the "
        f"Priority admission plugin recomputes the class's value and refuses the pod if the "
        f"two disagree")


#: The two labels the bottom rung is recognised by. `cage-netpol`'s podSelector keys on both,
#: so re-asserting them is the whole of what keeps a caged pod inside its reach cage.
TIER_LABEL = "posture.acme.io/tier"


def hold_policy(name: str, resource_rules: list[dict], match_conditions: list[dict],
                namespace_selector: dict | None = None) -> dict:
    """UPDATE-only: re-assert the bottom rung's two LABELS and touch nothing else.

    ## Why this is a separate policy and not an extra operation on the cage

    Eco-system ticket 89 round 2 put `UPDATE` on the cages themselves, gated on the pod already
    carrying `posture.acme.io/caged: "true"`. That marker does not mean "caged by this policy":
    `cage-tier` writes it for its whole population at every rung. So on `UPDATE` the bottom-rung
    cage matched a pod `cage-tier` had caged at `baseline`, and applying the full body to a
    RUNNING pod appends a `waf-sidecar` to an immutable container list and rewrites
    `priorityClassName` and `priority`, which the API server refuses. A refusal by another name,
    in the ticket about refusals by another name, and the third instance in this estate.

    It is not theoretical. `currency-controller/currency.py`'s `recage_patch()` is an `UPDATE`
    that strips the claim and writes `tier: isolated` + `caged: "true"` in one merge patch --
    the estate's only mechanism for moving a running pod off a retired version (ticket 91), and
    an object that matches those gates exactly. Breaking it would strand every stale pod.

    ## What this does instead

    `UPDATE` needs the LABELS re-asserted, not the cage re-applied. The reason `UPDATE` was
    wanted at all is that `CREATE`-only leaves a caged pod permanently relabelable: a
    `kubectl label --overwrite posture.acme.io/tier=baseline` after admission drops it out of
    `cage-reach-isolated`'s podSelector for good, and `cage-netpol`'s own comment claims a pod
    cannot buy itself looser reach -- true of `cage-tier`'s population only because `cage-tier`
    matches `UPDATE`. Two label writes restore that and nothing else: no container appended, no
    immutable field rewritten, byte-identical for a pod already carrying them, and admissible on
    top of `recage_patch()`, which writes the same two values.

    ## RE-assert, never assert (review, 2026-09-05)

    The caller adds `was-on-the-bottom-rung` and this is why. The hold's predicate matched the
    cage's, but its extension did not: on `UPDATE` it matched any pod of that population whether
    or not the cage had ever caged it. Measured -- a pod `cage-tier` caged at `baseline` whose
    claim was later removed came out labelled `tier: isolated` with a baseline SPEC underneath
    (`cage-baseline-4-0-0`, cpu 500m, no hardening, no sidecar), and a pod nothing had ever caged
    gained both labels with no dials at all. Reach only tightens, so it was not a safety
    regression -- but it inverts the invariant `cage-tier`'s own header states, "the pod label is
    an OUTPUT only", and it is the same label-and-dials incoherence this ticket's own D5 gives as
    the reason a second mutating writer was rejected. Writing a label that promises dials the pod
    does not carry is the thing the estate refuses to do.

    So the gate reads `oldObject`: the pod must ALREADY have been on the bottom rung. That still
    delivers the relabel protection in full, because the relabel case starts from a pod the cage
    put at `isolated` -- and `oldObject` is what sees through the relabel, since the incoming
    `object` is the one carrying the forged `baseline`. Populations it deliberately no longer
    touches, each reachable: a Namespace that gains `governed: "true"` after its pods exist, a
    pod created while the webhook was down, and a claim stripped by anything other than the
    currency controller. Those are `CREATE`-time or recreate problems, and inventing a label for
    them here would be asserting a cage nothing applied.
    """
    constraints: dict = {"resourceRules": resource_rules}
    if namespace_selector is not None:
        constraints["namespaceSelector"] = namespace_selector
    # The pod must ALREADY be on the bottom rung -- read off `oldObject`, so a relabel is caught
    # (the incoming object carries the forged value) while a pod nothing caged is left alone.
    conditions = list(match_conditions) + [{
        "name": "was-on-the-bottom-rung",
        "expression": (f"oldObject.?metadata.?labels['{TIER_LABEL}'].orValue('') "
                       f"== '{BOTTOM_RUNG}'"),
    }]
    return {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "MutatingPolicy",
        "metadata": {"name": name, "labels": {IDENTITY_LABEL: IDENTITY}},
        "spec": {
            "matchConstraints": constraints,
            "matchConditions": conditions,
            "mutations": [{
                "patchType": "ApplyConfiguration",
                "applyConfiguration": {
                    "expression": (
                        "Object{\n"
                        "  metadata: Object.metadata{ labels: {\n"
                        f'    "{CAGED_LABEL}": "true",\n'
                        f'    "{TIER_LABEL}": "{BOTTOM_RUNG}"\n'
                        "  } }\n"
                        "}"
                    )
                },
            }],
        },
    }


def assert_labels_only(policy: dict) -> None:
    """A hold policy may write the two labels and nothing else, ever."""
    assert policy["kind"] == "MutatingPolicy", policy["kind"]
    assert "validationActions" not in policy["spec"], policy["spec"]
    assert len(policy["spec"]["mutations"]) == 1, policy["spec"]["mutations"]
    expr = policy["spec"]["mutations"][0]["applyConfiguration"]["expression"]
    for banned in ("containers", "priorityClassName", "priority", "preemptionPolicy",
                   "securityContext", "resources", "hostNetwork", "JSONPatch"):
        assert banned not in expr, (
            f"a hold policy wrote {banned!r}; on a running pod that is a refusal by another name")
    assert CAGED_LABEL in expr and TIER_LABEL in expr and BOTTOM_RUNG in expr, expr
    rule = policy["spec"]["matchConstraints"]["resourceRules"][0]
    assert rule["operations"] == ["UPDATE"], rule
    # It must RE-assert, never assert: the last condition reads oldObject, so a pod the cage
    # never caged is not given a label promising dials it does not carry.
    gate = policy["spec"]["matchConditions"][-1]
    assert gate["name"] == "was-on-the-bottom-rung", gate
    assert "oldObject" in gate["expression"] and BOTTOM_RUNG in gate["expression"], gate


def cage_tier_spec(path: Path | None = None) -> dict:
    """The shipped cage's own `variables` and `mutations`. One dial table, one expansion."""
    p = path or CAGE_TIER
    doc = yaml.safe_load(p.read_text())
    if doc.get("kind") != "MutatingPolicy":
        raise SystemExit(f"{p} is not a MutatingPolicy; refusing to copy its body")
    return doc["spec"]


def bottom_rung_variables(spec: dict) -> list[dict]:
    """`cage-tier`'s variables with `tier` pinned to the bottom rung and `nsTier` dropped."""
    out = [copy.deepcopy(v) for v in spec.get("variables", []) if v["name"] != "nsTier"]
    for v in out:
        if v["name"] == "tier":
            v["expression"] = f"'{BOTTOM_RUNG}'"
    return out


def bottom_rung_mutations(spec: dict) -> list[dict]:
    """`cage-tier`'s mutations, then the two that extend the same hardening to initContainers."""
    return copy.deepcopy(spec["mutations"]) + [copy.deepcopy(_INIT_MUTATION),
                                               copy.deepcopy(_INIT_CAPS)]


def bottom_rung_policy(name: str, resource_rules: list[dict], match_conditions: list[dict],
                       namespace_selector: dict | None = None,
                       spec: dict | None = None) -> dict:
    """A MutatingPolicy that puts its matched population on the bottom rung. No refusal in it."""
    cage = spec if spec is not None else cage_tier_spec()
    constraints: dict = {"resourceRules": resource_rules}
    if namespace_selector is not None:
        constraints["namespaceSelector"] = namespace_selector
    return {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "MutatingPolicy",
        "metadata": {"name": name, "labels": {IDENTITY_LABEL: IDENTITY}},
        "spec": {
            "matchConstraints": constraints,
            "matchConditions": match_conditions,
            "variables": bottom_rung_variables(cage),
            "mutations": bottom_rung_mutations(cage),
        },
    }
