#!/usr/bin/env python3
"""The other half of the fan-out on the demo path: delete what a retirement retires.

flux-operator's ResourceSet delivers each declared version through a Kustomization
with `prune: true`, so deleting an element from distribution/versions.yaml deletes
that version's objects from the cluster. graded/up.sh -- the offline twin of that
delivery -- only ever APPLIED, so a retired version's cage stayed installed forever.

On 2026-08-29 policy versions 2.0.0, 2.0.1 and 3.0.0 were retired for being unable
to admit a single pod (their cage-tier wrote priorityClassName without the priority
integer the API server's Priority admission plugin derives from the same class).
Every one of their MutatingPolicies was still live on kind-driftwood afterwards,
still mutating anything that claimed them -- so a pod claiming a retired version
was refused by that version's own defect rather than by the orphan guard, which is
the wrong refuser for the right answer.

Every object this path applies carries `policy-as-versioned.dev/policy-version`, so
the label is the selector and the declared array is the allow-list. Nothing without
that label is ever touched.

Second job, same principle. A Kyverno GeneratingPolicy's downstream object -- the
`cage-egress-lockdown` NetworkPolicy the cage generates into a caged pod's namespace
-- outlives the pod that triggered it. Kyverno stamps every downstream with its
trigger's kind, namespace and name and does NOT collect one whose trigger has simply
gone away. Observed live on 2026-08-29: tuppence-reset's workloads moved off the
retired 2.0.0 (which caged nothing) onto 4.0.0, whose cage-netpol deliberately does
not restrict the `baseline` rung -- and a lockdown generated in passing by a pod that
briefly claimed 2.0.2 stayed behind, kept selecting every caged pod in the namespace,
and held the Istio sidecars off istiod (503 on every call) long after the policy that
made it had no pod to match. A downstream whose named trigger no longer exists is
pruned here, for the same reason a retired version's policy is: the cluster must hold
what the declared policy set actually generates, and nothing else.

    prune-retired.py <kube-context> <declared version> [<declared version> ...]

ponytail: cluster-scoped kinds only for the version sweep (that is everything the
versioned trees carry today), and NetworkPolicy only for the downstream sweep (the
one kind the cage generates). If a version tree ever ships another object, add its
kind here or -- better -- put the demo path behind the real Kustomization and let
Flux prune it.
"""
from __future__ import annotations

import json
import subprocess
import sys

KINDS = "mutatingpolicy,validatingpolicy,generatingpolicy,priorityclass"
LABEL = "policy-as-versioned.dev/policy-version"


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        sys.exit(__doc__)
    ctx, declared = argv[1], set(argv[2:])

    listed = subprocess.run(
        ["kubectl", "--context", ctx, "get", KINDS, "-l", LABEL, "-o", "json"],
        capture_output=True, text=True)
    if listed.returncode != 0:
        # Kyverno's CRDs may not be installed; up.sh already says so for the
        # applies. Never turn that into a silent success story.
        print(f"  (could not list versioned objects, nothing pruned: "
              f"{listed.stderr.strip().splitlines()[-1][:160] if listed.stderr.strip() else 'no output'})")
        return 0

    stale = [(item["kind"], item["metadata"]["name"],
              item["metadata"]["labels"][LABEL])
             for item in json.loads(listed.stdout)["items"]
             if item["metadata"]["labels"][LABEL] not in declared]
    if not stale:
        print(f"  ok   nothing stale: every installed version is one of {sorted(declared)}")
        return prune_orphaned_downstreams(ctx)

    for kind, name, _version in stale:
        subprocess.run(["kubectl", "--context", ctx, "delete", kind.lower(), name,
                        "--ignore-not-found"], check=True)
    retired = sorted({v for _, _, v in stale})
    print(f"  pruned {len(stale)} object(s) of undeclared version(s) {retired}; "
          f"declared now {sorted(declared)}")
    return prune_orphaned_downstreams(ctx)


def prune_orphaned_downstreams(ctx: str) -> int:
    """Delete every cage-generated NetworkPolicy whose trigger pod is gone."""
    listed = subprocess.run(
        ["kubectl", "--context", ctx, "get", "networkpolicy", "-A",
         "-l", "generate.kyverno.io/policy-name", "-o", "json"],
        capture_output=True, text=True)
    if listed.returncode != 0:
        print("  (could not list generated NetworkPolicies; none pruned)")
        return 0
    orphans = []
    for item in json.loads(listed.stdout)["items"]:
        labels = item["metadata"].get("labels", {})
        if labels.get("generate.kyverno.io/trigger-kind") != "Pod":
            continue
        trigger_ns = labels.get("generate.kyverno.io/trigger-namespace", "")
        trigger = labels.get("generate.kyverno.io/trigger-name", "")
        if not trigger:
            continue
        alive = subprocess.run(["kubectl", "--context", ctx, "-n", trigger_ns,
                                "get", "pod", trigger, "-o", "name"],
                               capture_output=True, text=True)
        if alive.returncode == 0:
            continue  # the trigger is still there; the downstream is real
        orphans.append((item["metadata"]["namespace"], item["metadata"]["name"],
                        labels.get("generate.kyverno.io/policy-name", "?"), trigger))
    if not orphans:
        print("  ok   no generated NetworkPolicy has lost its trigger pod")
        return 0
    for ns, name, _policy, _trigger in orphans:
        subprocess.run(["kubectl", "--context", ctx, "-n", ns, "delete",
                        "networkpolicy", name, "--ignore-not-found"], check=True)
    for ns, name, policy, trigger in orphans:
        print(f"  pruned {ns}/{name}: generated by {policy} for pod "
              f"{trigger}, which no longer exists")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
