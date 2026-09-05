#!/usr/bin/env python3
"""currency.py -- the currency controller: the estate's only post-admission re-cage.

THE SENTENCE THIS EXISTS TO MAKE TRUE (eco-system ticket 91 item 3):

    a pod admitted under a version that is later retired is re-caged to
    `isolated` on the next controller pass.

Admission is a snapshot. `cage-tier` (graded/policies/cage-tier.yaml) reads the
pod's governed Namespace and stamps a rung onto every pod that claims a policy
version; the orphan guard judges the claim against the array. Both fire at
admission and never again. When the platform later retires a version from
`distribution/versions.yaml`, every pod already running under it keeps the rung
it was admitted with. Nothing else in the estate re-evaluates it. This does.

  supported := the versions still declared in the ResourceSet array -- the SAME
               array the orphan guard allow-lists. One source of truth.
  stale pod := a running pod whose `policy-as-versioned.dev/policy-version`
               CLAIM is not in `supported`: it was admitted under a version that
               has since been retired.

For each stale pod, one bounded pass re-cages it to the bottom rung, `isolated`.
It is not evicted, not denied and not deleted: it keeps running, in a cage with
no ingress and no egress, first in line for eviction (ADR-0022). Nothing in the
estate is ever refused; the £ and the ladder are the whole response.

WHY THE PATCH HAS THE SHAPE IT HAS (the crux, and it is not the old one).

`cage-tier` CLOBBERS `posture.acme.io/tier` from the Namespace on every CREATE
*and* UPDATE, for every pod that claims a version. So writing the tier alone is
undone by the very admission the write triggers. There is exactly one durable
patch, and it does three things in one JSON merge:

  * removes the CLAIM (`null` deletes the key), which takes the pod out of
    scope for cage-tier -- so the tier this patch writes is not clobbered back
    -- and out of scope for the orphan guard, so the UPDATE is not refused;
  * removes the identity substrate's POSTURE label in the same breath. The
    UNVERSIONED `posture/policies/posture-trust-boundary.yaml` -- the copy
    installed on the demo cluster -- Denies a posture that does not equal its
    claim and is NOT gated on a version, and the line above has just removed the
    claim, so leaving the posture label behind gets the whole patch refused at
    admission there. Every SERVED copy adds `only-this-policy-version`, so for an
    adopter running only the composed set a claimless pod is out of its scope and
    there is no Deny. Removing it is required against the first and harmless
    against the second, so the patch does it unconditionally;
  * writes `posture.acme.io/tier: isolated`, the bottom rung. This is the half
    the old de-posture patch did not have, and its absence was the defect:
    removing the claim without naming a rung FREEZES the pod at whatever rung
    it was admitted with, permanently, because nothing can ever clobber it
    again. A retired 2.0.0 pod sat on at `restricted` for the rest of its life;
  * asserts `posture.acme.io/caged: "true"`, so that the `cage-reach-isolated`
    NetworkPolicy -- deny-all ingress and egress -- selects the pod, since every
    generated reach policy selects on caged AND tier.

THE PRECONDITION, AND IT IS NOT A DETAIL. Every SERVED copy of `cage-netpol`
(`distribution/policies/v<declared>/`, and each adopter's `composed/`) carries an
`only-this-policy-version` matchCondition that the authoring copy in
`graded/policies/` does not. This patch removes the claim, so the re-caged pod
does NOT fire that policy and CANNOT generate its own reach cage. It can only be
SELECTED by a `cage-reach-isolated` the namespace ALREADY has -- generated when
some pod claiming a currently-served version was admitted there at a rung above
baseline. In a namespace with none, re-caging writes `isolated` as a LABEL and
changes nothing the pod can reach. verify-currency.sh derives that from the
served bodies and checks the NetworkPolicy exists on the cluster BEFORE it runs
a pass, so a namespace without one is a could-not-look and not a red left behind
after a live pod's claim has already been stripped.

The claim it removes is preserved as the annotation
`policy-as-versioned.dev/retired-claim`, so the record of which retired version
the pod was admitted under survives the patch. Annotations are read by no
matchCondition in the estate, so keeping it costs nothing at admission.

TIGHTEN-ONLY, AND WHY IT IS STRUCTURAL RATHER THAN CHECKED. The ladder is
`baseline < restricted < quarantine < isolated` (graded/cage.py ORDER, mirrored
below and cross-checked by verify-currency.sh, which FAILs if the two drift).
`recage_patch()` takes the retired claim and nothing else: it cannot read the
pod's current rung, so it cannot echo one back, and the only tier it can write
is the last element of that ladder. `is_tighten()` is applied to every pod
before it is patched anyway -- a belt to the structural brace -- and the RBAC
grant carries no `delete` on pods, so the controller has no verb with which to
remove a workload even if it wanted one.

A MISSING INSTRUMENT REFUSES, AND RE-CAGES NOTHING (ADR-0020; eco-system ticket
32 scoped this and never built it). A version array the controller cannot read
is not an empty array: an empty `supported` set would make every pod in the
estate stale and re-cage the lot. Both cases raise `MissingInstrument`, the
pass exits non-zero with the reason named, and no pod is touched.

Runtime: pure stdlib. In-cluster (the CronJob) it talks to the API server with
urllib and the mounted ServiceAccount token -- no kubectl, no pip deps, so it
runs in a bare `python:3-slim` from a ConfigMap. `select_stale`,
`plan_actions`, `is_tighten` and `recage_patch` are pure and graded offline by
verify-currency.sh; the urllib glue is thin.

Usage:
    currency.py selfcheck                      # runnable asserts (no cluster)
    currency.py plan   < pods.json             # offline: print the reconcile plan
    currency.py reconcile [--dry-run]          # in-cluster: one bounded pass
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

# The claim a workload makes about which policy version admitted it. The same
# label cage-tier, the orphan guard and the governed-namespace guard all key on.
CLAIM_LABEL = "policy-as-versioned.dev/policy-version"
# The cage the pod is in. cage-tier writes it from the Namespace at admission;
# cage-netpol's generated NetworkPolicies select on it.
TIER_LABEL = "posture.acme.io/tier"
CAGED_LABEL = "posture.acme.io/caged"
# The identity substrate's own stamp (posture/policies/stamp-posture.yaml).
# Identity is shelved for this build (eco-system ticket 90) but the policies
# still ship. The UNVERSIONED `posture-trust-boundary` -- installed on the demo
# cluster -- DENIES any pod carrying this label without a matching claim, so a
# patch that removes the claim and leaves this behind is REFUSED AT ADMISSION
# there. (Every SERVED copy is additionally gated on the version, so for an
# adopter running only the composed set a claimless pod is out of its scope and
# there is no Deny; the reason is the unversioned copy, not those.) It goes in
# the same patch either way. Dropping it is itself a tightening: the pod stops
# matching the posture ClusterSPIFFEID, its posture SVID stops renewing, and it
# falls back to the plain base-mesh identity, losing posture-gated reach and its
# OpenBao secret.
POSTURE_LABEL = "posture.acme.io/version"
# Where the retired claim goes, so the patch destroys no record.
RETIRED_CLAIM_ANNOTATION = "policy-as-versioned.dev/retired-claim"

# Mirror of graded/cage.py ORDER. `infra` is deliberately absent: it is a role
# declaration on a platform-owned Namespace, never a rung a price or a
# controller selects (ADR-0022). This module cannot import cage.py -- it runs
# from a ConfigMap in a bare image with no siblings on disk -- so the mirror is
# a declaration here and a DERIVED assertion in verify-currency.sh, which reads
# cage.py's own ORDER and FAILs if the two ever drift.
ORDER = ["baseline", "restricted", "quarantine", "isolated"]
BOTTOM_RUNG = ORDER[-1]


class MissingInstrument(Exception):
    """The controller cannot see what it needs to judge, so it judges nothing.

    ADR-0020: the only refusal in the estate is a missing instrument. A version
    array that cannot be read is NOT an empty array -- reading it as one would
    make every pod stale and re-cage the whole estate on an outage.
    """


# ---------------------------------------------------------------------------
# Pure core (no cluster; this is the graded logic)
# ---------------------------------------------------------------------------
def is_tighten(current: str | None, target: str) -> bool:
    """True when moving a pod from `current` to `target` tightens its cage.

    A rung this ladder does not know -- absent, forged, or `infra` on a pod that
    should never carry it -- fails closed: any move to a known rung counts as a
    tighten from it, because the estate has no idea how loose it was. A move
    between two known rungs is a tighten only when the target sits no earlier in
    the ladder.
    """
    if target not in ORDER:
        return False
    if current not in ORDER:
        return True
    return ORDER.index(target) >= ORDER.index(current)


def recage_patch(claimed: str) -> dict:
    """The one durable patch: out of cage-tier's scope, into the bottom rung.

    A JSON merge patch -- a null value deletes the key. See the module docstring
    for why all three label writes have to happen in ONE update. `claimed` is
    the retired version the pod was admitted under; it is the only input, which
    is what makes the tier this writes structurally incapable of being looser
    than the pod's current one.
    """
    return {
        "metadata": {
            "labels": {
                CLAIM_LABEL: None,
                POSTURE_LABEL: None,
                TIER_LABEL: BOTTOM_RUNG,
                CAGED_LABEL: "true",
            },
            "annotations": {RETIRED_CLAIM_ANNOTATION: claimed},
        }
    }


def select_stale(supported: set[str], pods: list[dict]) -> list[dict]:
    """The pods whose admitted version is no longer in the array.

    `pods` is the trimmed shape {namespace, name, claim, tier, caged}. A pod
    with no claim is not our concern: it is the COTS/system population cage-tier
    does not match either. A pod whose claim IS supported is in currency.
    """
    return [p for p in pods if p.get("claim") and p["claim"] not in supported]


def plan_actions(supported: set[str], pods: list[dict]) -> list[dict]:
    """One bounded pass, as data: what would be done to which pod, and why.

    Refuses outright on an empty `supported` set -- see MissingInstrument.
    Each entry is `recage` (with the patch) or `hold` (with the reason).
    """
    if not supported:
        raise MissingInstrument(
            "the supported-version set is empty: every claiming pod would read as "
            "stale and the whole estate would be re-caged. Refusing the pass."
        )
    actions = []
    for p in select_stale(supported, pods):
        entry = {"namespace": p["namespace"], "name": p["name"],
                 "claim": p["claim"], "tier": p.get("tier"), "caged": p.get("caged")}
        if p.get("tier") == BOTTOM_RUNG and p.get("caged") == "true":
            # Already at the bottom rung AND already inside the caged
            # population, so a reach policy already selects it. Patching would
            # remove its claim for no gain in tightness, and the smallest
            # tighten-only action is no action.
            #
            # BOTH halves are required. `cage-reach-<rung>` selects on
            # caged AND tier, so a pod at `isolated` whose caged label is absent
            # or false is selected by NOTHING: holding on the tier alone left it
            # outside every reach cage forever, which is the opposite of what
            # holding was for. It is re-caged like any other stale pod, and the
            # patch asserts the caged label.
            actions.append({**entry, "action": "hold",
                            "reason": f"already at the bottom rung `{BOTTOM_RUNG}` and caged"})
        elif not is_tighten(p.get("tier"), BOTTOM_RUNG):
            # Unreachable while BOTTOM_RUNG is the last element of ORDER. Kept
            # so that a future edit to the ladder cannot make this controller
            # loosen a pod in silence: it would hold, and say why.
            actions.append({**entry, "action": "hold",
                            "reason": f"re-caging to `{BOTTOM_RUNG}` would not tighten "
                                      f"a pod at `{p.get('tier')}`"})
        else:
            actions.append({**entry, "action": "recage",
                            "patch": recage_patch(p["claim"])})
    return actions


# ---------------------------------------------------------------------------
# Live I/O -- in-cluster only (urllib + ServiceAccount token). Thin glue.
# ---------------------------------------------------------------------------
SA = "/var/run/secrets/kubernetes.io/serviceaccount"
RESOURCESET_PATH = ("/apis/fluxcd.controlplane.io/v1/namespaces/flux-system/"
                    "resourcesets/policy-versions")


def _api():
    """(call) for the in-cluster API server, or raise if not in a pod."""
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        raise SystemExit("reconcile runs in-cluster only (no KUBERNETES_SERVICE_HOST); "
                         "use `plan` for an offline dry-run, or trigger the CronJob for a live pass")
    with open(f"{SA}/token") as fh:
        token = fh.read().strip()
    ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")
    base = f"https://{host}:{port}"

    def call(method: str, path: str, body: dict | None = None, content_type: str | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/json")
        if content_type:
            req.add_header("Content-Type", content_type)
        with urllib.request.urlopen(req, context=ctx) as resp:
            return json.load(resp)

    return call


def get_supported(call) -> set[str]:
    """Supported versions = the ResourceSet array (one source of truth with the
    orphan guard).

    Every failure to read it is a MissingInstrument, named. Before eco-system
    ticket 91 this call was unguarded: on a cluster with no flux-operator the
    GET 404'd, the pass crashed with a stack trace every minute, and the module
    was written off as "it 404s" (ticket 13 item 2) rather than repaired.

    `SUPPORTED_VERSIONS` (comma-list) overrides -- the escape hatch for demo
    paths where flux-operator is not installed. An override that parses to
    nothing is itself a missing instrument, not an empty array.
    """
    override = os.environ.get("SUPPORTED_VERSIONS", "").strip()
    if override:
        versions = {v.strip() for v in override.split(",") if v.strip()}
        if not versions:
            raise MissingInstrument(
                f"SUPPORTED_VERSIONS is set to {override!r} but names no version")
        return versions
    try:
        rs = call("GET", RESOURCESET_PATH)
    except Exception as exc:                                   # noqa: BLE001
        raise MissingInstrument(
            f"cannot read the version array at {RESOURCESET_PATH}: {exc}. "
            "The ResourceSet `policy-versions` is the one source of truth for what is "
            "supported; without it this pass knows nothing and re-cages nothing.") from exc
    try:
        versions = {v["version"] for v in rs["spec"]["inputs"][0]["versions"]}
    except (KeyError, IndexError, TypeError) as exc:
        raise MissingInstrument(
            f"the ResourceSet at {RESOURCESET_PATH} carries no readable version array: {exc}") from exc
    if not versions:
        raise MissingInstrument(
            f"the ResourceSet at {RESOURCESET_PATH} declares an empty version array")
    return versions


def list_claiming_pods(call) -> list[dict]:
    """Every pod that claims a policy version -- the population cage-tier matches."""
    sel = urllib.parse.quote(CLAIM_LABEL)
    body = call("GET", f"/api/v1/pods?labelSelector={sel}")
    out = []
    for item in body.get("items", []):
        meta = item["metadata"]
        labels = meta.get("labels", {})
        out.append({"namespace": meta["namespace"], "name": meta["name"],
                    "claim": labels.get(CLAIM_LABEL), "tier": labels.get(TIER_LABEL),
                    "caged": labels.get(CAGED_LABEL)})
    return out


def reconcile(dry_run: bool = False) -> dict:
    """ONE bounded pass -- no watch, nothing that blocks (a CronJob runs this)."""
    call = _api()
    supported = get_supported(call)
    actions = plan_actions(supported, list_claiming_pods(call))
    for a in actions:
        if a["action"] != "recage" or dry_run:
            a["applied"] = False
            continue
        call("PATCH", f"/api/v1/namespaces/{a['namespace']}/pods/{a['name']}",
             body=a["patch"], content_type="application/merge-patch+json")
        a["applied"] = True
    summary = {"supported": sorted(supported),
               "recaged": sum(1 for a in actions if a["action"] == "recage"),
               "held": sum(1 for a in actions if a["action"] == "hold"),
               "rung": BOTTOM_RUNG, "dry_run": dry_run, "actions": actions}
    print(json.dumps(summary))
    return summary


# ---------------------------------------------------------------------------
def selfcheck() -> None:
    supported = {"4.0.0"}
    pods = [
        {"namespace": "tuppence", "name": "reset-current", "claim": "4.0.0",
         "tier": "restricted", "caged": "true"},
        {"namespace": "tuppence", "name": "reset-retired", "claim": "2.0.0",
         "tier": "restricted", "caged": "true"},
        {"namespace": "ludlow", "name": "reset-bottom", "claim": "2.0.0",
         "tier": "isolated", "caged": "true"},
        {"namespace": "ludlow", "name": "reset-bottom-uncaged", "claim": "2.0.0",
         "tier": "isolated", "caged": None},
        {"namespace": "driftwood", "name": "cots", "claim": None,
         "tier": "baseline", "caged": None},
    ]
    stale = {p["name"] for p in select_stale(supported, pods)}
    assert stale == {"reset-retired", "reset-bottom", "reset-bottom-uncaged"}, stale
    # ...retiring 4.0.0 as well makes the current pod stale too, and re-declaring
    # it brings it back into currency. Retirement is the whole trigger.
    assert {p["name"] for p in select_stale(set(), [])} == set()
    assert {p["name"] for p in select_stale({"2.0.0", "4.0.0"}, pods)} == set()

    acts = {a["name"]: a for a in plan_actions(supported, pods)}
    assert acts["reset-retired"]["action"] == "recage", acts["reset-retired"]
    assert acts["reset-bottom"]["action"] == "hold", acts["reset-bottom"]
    # ...but a pod AT the bottom rung with no caged label is selected by no reach
    # policy at all, so holding it would leave it uncaged forever. It is patched.
    assert acts["reset-bottom-uncaged"]["action"] == "recage", acts["reset-bottom-uncaged"]
    assert acts["reset-bottom-uncaged"]["patch"]["metadata"]["labels"][CAGED_LABEL] == "true"
    assert "reset-current" not in acts and "cots" not in acts, sorted(acts)

    # THE crux: one patch, three label writes, the claim kept as a record.
    patch = acts["reset-retired"]["patch"]["metadata"]
    assert patch["labels"][CLAIM_LABEL] is None, patch
    assert patch["labels"][POSTURE_LABEL] is None, patch
    assert patch["labels"][TIER_LABEL] == BOTTOM_RUNG == "isolated", patch
    assert patch["labels"][CAGED_LABEL] == "true", patch
    assert patch["annotations"][RETIRED_CLAIM_ANNOTATION] == "2.0.0", patch
    assert set(patch["labels"]) == {CLAIM_LABEL, POSTURE_LABEL, TIER_LABEL, CAGED_LABEL}, patch

    # Tighten-only, over the whole ladder and off both ends of it.
    assert all(is_tighten(r, BOTTOM_RUNG) for r in ORDER), ORDER
    assert is_tighten(None, BOTTOM_RUNG) and is_tighten("infra", BOTTOM_RUNG)
    assert not is_tighten("isolated", "baseline")
    assert not is_tighten("quarantine", "restricted")
    assert not is_tighten("baseline", "infra"), "infra is a role declaration, not a rung to move to"
    # The patch cannot vary with the pod's rung: it never sees one.
    assert {recage_patch(v)["metadata"]["labels"][TIER_LABEL] for v in ("1.0.0", "9.9.9")} \
        == {BOTTOM_RUNG}

    # A missing instrument re-cages nothing.
    try:
        plan_actions(set(), pods)
        raise AssertionError("an empty supported set must refuse the pass")
    except MissingInstrument:
        pass

    def boom(*a, **k):
        raise OSError("HTTP Error 404: Not Found")
    old = os.environ.pop("SUPPORTED_VERSIONS", None)
    try:
        try:
            get_supported(boom)
            raise AssertionError("an unreadable ResourceSet must refuse the pass")
        except MissingInstrument as exc:
            assert "404" in str(exc), exc
        assert get_supported(lambda *a, **k: {
            "spec": {"inputs": [{"versions": [{"version": "4.0.0"}]}]}}) == {"4.0.0"}
        try:
            get_supported(lambda *a, **k: {"spec": {"inputs": [{"versions": []}]}})
            raise AssertionError("an empty ResourceSet array must refuse the pass")
        except MissingInstrument:
            pass
    finally:
        if old is not None:
            os.environ["SUPPORTED_VERSIONS"] = old

    print(f"currency selfcheck: all asserts passed (stale = claim not in the array; "
          f"one patch drops the claim, keeps it as an annotation and writes `{BOTTOM_RUNG}`; "
          f"a missing instrument re-cages nothing)")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selfcheck", help="run the asserts (no cluster)")
    pl = sub.add_parser("plan", help="offline: read a pod list JSON on stdin, print the plan")
    pl.add_argument("--supported", default=os.environ.get("SUPPORTED_VERSIONS", ""),
                    help="comma-list of the versions the array still declares. Required: "
                         "there is no default, because a wrong one re-cages the estate")
    rc = sub.add_parser("reconcile", help="in-cluster: one bounded reconcile pass")
    rc.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    if args.cmd == "selfcheck":
        selfcheck()
        return 0
    try:
        if args.cmd == "plan":
            supported = {v.strip() for v in args.supported.split(",") if v.strip()}
            if not supported:
                raise MissingInstrument(
                    "`plan` needs --supported (or SUPPORTED_VERSIONS): the set of versions the "
                    "array still declares. There is no default -- a stale literal here would "
                    "re-cage every pod in the estate")
            pods = json.load(sys.stdin)
            print(json.dumps({"supported": sorted(supported), "rung": BOTTOM_RUNG,
                              "actions": plan_actions(supported, pods)}, indent=2))
            return 0
        reconcile(dry_run=args.dry_run)
    except MissingInstrument as exc:
        print(f"MISSING INSTRUMENT: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
