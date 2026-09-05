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
