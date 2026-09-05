#!/usr/bin/env bash
# The sentence this script grades (eco-system ticket 91 item 3, CONTEXT.md
# "Currency controller"):
#
#   a pod admitted under a version that is later retired is re-caged to
#   `isolated` on the next controller pass.
#
# That is a statement about a LIVE CLUSTER, and this script is honest about
# which half of it a runner without one can see.
#
# WHAT THE OFFLINE HALF OBSERVES (always, on any runner with python3+PyYAML).
# It grades the controller's LOGIC against PLANTED state, and it grades the seam
# between that logic and the policy bodies THE ESTATE ACTUALLY SERVES. Every
# fact is derived from a shipped file, never restated as a literal:
#   1. the pure core's own asserts (`currency.py selfcheck`);
#   2. a planted pod list: the pod whose CLAIM is retired is selected; a current
#      pod and a pod claiming nothing are not; a stale pod already at the bottom
#      rung AND caged is held; one at the bottom rung with no caged label is not,
#      because no reach policy would select it;
#   3. TIGHTEN-ONLY at the seam: the tier the patch writes IS the last element of
#      graded/cage.py's own ORDER, is_tighten() holds from every rung and from an
#      unknown one, and refuses a loosening move so the predicate is measured;
#   4. what the patch survives and what it lands in -- read off the SERVED bodies
#      (`distribution/policies/v<declared>/` plus any adopter `composed/`), NOT
#      off `graded/policies/`, which is the authoring copy no Kustomization
#      serves. The difference is load-bearing: every served copy carries an
#      `only-this-policy-version` matchCondition the authoring copy lacks, and it
#      changes the answer for cage-netpol. What is derived there: served cage-tier
#      fires on UPDATE, clobbers the tier and scopes on the claim the patch
#      removes; the orphan guard scopes on the same claim; governed-namespace-
#      requires-claim is CREATE-only; the UNVERSIONED posture-trust-boundary
#      Denies a posture without a claim while every served copy does not; and
#      the served cage-netpol selectors pick cage-reach-<bottom rung> for the
#      patched label set -- but are themselves claim-gated, SO THE PATCH CANNOT
#      GENERATE THAT POLICY. It can only be selected by one the namespace
#      already has. That precondition is asserted, printed, and checked on the
#      cluster BEFORE any pass is run;
#   5. the regression this repair closes, as a property: a claim-removing patch
#      that names no rung leaves the pod at its admitted rung with nothing left
#      that could ever move it; and the two residual softenings it costs;
#   6. a missing instrument re-cages nothing (ADR-0020);
#   7. the RBAC grant holds no verb that can loosen or remove a workload;
#   8. the module is OWNED: party.yaml declares it, its objects carry the same
#      platform-machinery identity the orphan guard uses;
#   9. the could-not-look branch is RUN, not assumed (lib.sh selfcheck_absent).
#
# WHAT THE OFFLINE HALF CANNOT OBSERVE, and never claims. No pod exists here.
# Nothing here observes that the CronJob fired, that the API server accepted the
# patch, that admission did not clobber it, that a reach policy exists in the
# namespace, or that it cut the pod's reach. Those are facts about a running
# cluster. The live tail is the only thing that can see them, and when it cannot
# look it says so and the whole script exits 3 (lib.sh pass_line): this script
# has no PASS that does not rest on an observed pod.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line / selfcheck_absent
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
# This script takes NO arguments. It used to ignore them silently, so
# `verify-currency.sh --selfcheck` -- a mode several sibling scripts do have --
# ran the ordinary script and looked like it had done something else. An
# unrecognised argument is a fault, not a no-op.
[ "$#" -eq 0 ] || fail "verify-currency.sh takes no arguments (got: $*). The offline half always runs; the live half runs when the cluster is there"
# sha256 of stdin, printed on stdout; returns 1 and prints NOTHING when neither
# spelling is installed. Two traps live here and both were shipped once:
#   * `fail` inside this function CANNOT stop the script when it is called from
#     inside `$( )` in a `[` comparison -- `exit 1` ends the subshell and `set -e`
#     does not propagate out of a command substitution used in a comparison. Both
#     sides then evaluate to "" and compare EQUAL, so a missing tool became a
#     silent live pass over two completely different files. It returns a status
#     now, and the caller checks it.
#   * hashing the two sides differently. See the caller: `$( )` strips trailing
#     newlines, so a value read through it can never equal a file hashed off
#     disk. Both sides go through the same normalisation there, not here.
sha256_of() {
  if have sha256sum; then sha256sum | cut -d' ' -f1
  elif have shasum;    then shasum -a 256 | cut -d' ' -f1
  else return 1
  fi
}

say "1. offline: currency.py selfcheck (the pure core's own asserts)"
python3 "$HERE/currency.py" selfcheck || fail "selfcheck failed"

say "2. offline: the plan selects the retired-claim pod, and holds only what is already caged at the bottom"
PLAN=$(printf '%s' '[
  {"namespace":"tuppence","name":"reset-current","claim":"4.0.0","tier":"restricted","caged":"true"},
  {"namespace":"tuppence","name":"reset-retired","claim":"2.0.0","tier":"restricted","caged":"true"},
  {"namespace":"ludlow","name":"reset-bottom","claim":"2.0.0","tier":"isolated","caged":"true"},
  {"namespace":"ludlow","name":"reset-bottom-uncaged","claim":"2.0.0","tier":"isolated","caged":null},
  {"namespace":"driftwood","name":"cots","claim":null,"tier":"baseline","caged":null}
]' | python3 "$HERE/currency.py" plan --supported 4.0.0) || fail "plan exited non-zero"
python3 - <<PY || fail "the plan did not select what the sentence says it selects"
import json, sys
plan = json.loads('''$PLAN''')
acts = {a["name"]: a for a in plan["actions"]}
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)
check(acts.get("reset-retired", {}).get("action") == "recage",
      "the pod whose CLAIM is no longer in the array is planned for re-cage")
check("reset-current" not in acts,
      "a pod whose claim is still in the array is not touched")
check("cots" not in acts,
      "a pod that claims no version at all is not touched (COTS/system population)")
check(acts.get("reset-bottom", {}).get("action") == "hold",
      "a stale pod already at the bottom rung AND already caged is HELD, not patched again")
check(acts.get("reset-bottom-uncaged", {}).get("action") == "recage",
      "a stale pod at the bottom rung with NO caged label is re-caged, not held: every reach policy "
      "selects on caged AND tier, so holding on the rung alone leaves it selected by nothing")
check(acts.get("reset-bottom-uncaged", {}).get("patch", {}).get("metadata", {})
      .get("labels", {}).get("posture.acme.io/caged") == "true",
      "...and the patch asserts the caged label rather than assuming the pod already carries it")
p = acts.get("reset-retired", {}).get("patch", {}).get("metadata", {})
check(p.get("labels", {}).get("posture.acme.io/tier") == "isolated",
      "the planned patch writes the bottom rung onto the pod")
check("policy-as-versioned.dev/policy-version" in p.get("labels", {})
      and p["labels"]["policy-as-versioned.dev/policy-version"] is None,
      "the planned patch removes the version claim (JSON-merge null deletes the key)")
check(p.get("annotations", {}).get("policy-as-versioned.dev/retired-claim") == "2.0.0",
      "the retired claim survives as an annotation, so the record of what it was admitted under is kept")
if fails: sys.exit(f"{len(fails)} broken")
PY

say "3. offline: TIGHTEN-ONLY at the seam, derived from graded/cage.py's own ladder"
python3 - <<'PY' || fail "the controller is not tighten-only against the shipped ladder"
import importlib.util, os, sys
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
cur  = load("currency", "currency.py")
cage = load("cage", os.path.join("..", "graded", "cage.py"))
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)

# The ladder is not restated here: it is read off the module that owns it.
check(cur.ORDER == cage.ORDER,
      f"the controller's ladder IS graded/cage.py's ORDER {cage.ORDER}")
check(cur.BOTTOM_RUNG == cage.ORDER[-1],
      f"the rung the controller writes IS the last (tightest) element of that ORDER: {cage.ORDER[-1]}")
check(cur.BOTTOM_RUNG not in ("infra",) and cur.BOTTOM_RUNG in cage.LADDER,
      "the rung it writes is a selectable rung, never the platform-only `infra` role declaration")
# The property itself, over every rung the ladder has plus the two off-ladder cases.
for rung in cage.ORDER:
    check(cur.is_tighten(rung, cur.BOTTOM_RUNG),
          f"re-caging a pod at `{rung}` to `{cur.BOTTOM_RUNG}` is a tighten")
check(cur.is_tighten(None, cur.BOTTOM_RUNG) and cur.is_tighten("nonsense", cur.BOTTOM_RUNG),
      "an absent or unrecognised tier fails closed to the bottom rung, which is still a tighten")
# ...and the converse, so `is_tighten` is a real predicate and not a constant `True`.
check(not cur.is_tighten("isolated", "baseline") and not cur.is_tighten("quarantine", "restricted"),
      "is_tighten REFUSES a loosening move, so the property above is measured and not assumed")
# The patch takes the pod's RETIRED CLAIM and nothing else: the tier it writes
# cannot vary with the pod's current rung, which is why there is no code path
# that can emit a looser one.
import inspect
check(list(inspect.signature(cur.recage_patch).parameters) == ["claimed"],
      "the patch is a function of the retired claim alone -- it cannot read, and so cannot echo, a looser current tier")
check({cur.recage_patch(v)["metadata"]["labels"][cur.TIER_LABEL] for v in ("1.0.0", "2.0.0", "9.9.9")}
      == {cage.ORDER[-1]},
      f"every patch it can emit writes exactly one tier, {cage.ORDER[-1]}")
if fails: sys.exit(f"{len(fails)} broken")
PY

say "4. offline: the patch survives admission, and what it lands in -- read off the SERVED bodies"
python3 - <<'PY' || fail "the re-cage patch does not land where the sentence says it lands"
import glob, importlib.util, os, re, sys, yaml
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
cur = load("currency", "currency.py")
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)
def note(m):
    print("  --   " + m)

patch = cur.recage_patch("2.0.0")["metadata"]
labels_after = {k: v for k, v in patch["labels"].items() if v is not None}
removed = {k for k, v in patch["labels"].items() if v is None}

def doc(p):
    with open(p) as fh: return list(yaml.safe_load_all(fh))[0]
def conds(d):
    return {c["name"]: c["expression"] for c in d["spec"]["matchConditions"]}

# THE SERVED BODIES ARE THE AUTHORITY, NOT graded/. `graded/policies/` is the
# AUTHORING copy: no gitops Kustomization serves it and it is installed on no
# cluster. What an adopter actually runs is `distribution/policies/v*/` -- the
# ResourceSet renders one Kustomization per declared version -- and its own
# `composed/policies/v*/`. Those copies carry a matchCondition the authoring
# copy does not, `only-this-policy-version`, and it CHANGES THE ANSWER for
# cage-netpol: grading graded here would have graded a body nobody runs.
#
# "Served" is not "present on disk" either. The version array in
# distribution/versions.yaml is what the ResourceSet ranges: an element that
# leaves it has its Kustomization pruned and its bodies exist on no cluster.
# So the set graded here is DERIVED from that array -- the same array the orphan
# guard allow-lists and this controller reads -- plus any adopter's composed
# copy, which is served to that adopter whatever the platform declares today.
guard = load("guard", os.path.join("..", "distribution", "render-orphan-guard.py"))
import pathlib
declared = guard.versions(pathlib.Path(os.path.join("..", "distribution", "versions.yaml")))
def platform_copies(name):
    out = []
    for v in declared:
        f = os.path.join("..", "distribution", "policies", f"v{v}", name)
        if os.path.exists(f):
            out.append(f)
    return out
on_disk = {os.path.basename(os.path.dirname(f))[1:]
           for f in glob.glob(os.path.join("..", "distribution", "policies", "v*", "cage-tier.yaml"))}
served_tier = platform_copies("cage-tier.yaml")
served_netpol = platform_copies("cage-netpol.yaml")
composed_tier = sorted(glob.glob(os.path.join("..", "..", "*", "composed", "policies", "v*", "cage-tier.yaml")))
composed_netpol = sorted(glob.glob(os.path.join("..", "..", "*", "composed", "policies", "v*", "cage-netpol.yaml")))
served_tier += composed_tier
served_netpol += composed_netpol
check(bool(served_tier) and bool(served_netpol),
      f"served policy bodies to grade against, derived from the declared array {declared}: "
      f"{len(served_tier)} cage-tier, {len(served_netpol)} cage-netpol")
skipped = sorted(on_disk - set(declared))
if skipped:
    note(f"trees present on disk but NOT in the array, so served on no cluster and not graded: "
         f"{skipped} (2.x/3.x are the retired pre-ADR-0022 shapes; vselfcheck is a fixture)")
if composed_netpol:
    note(f"{len(composed_netpol)} of them are an adopter's own composed copy")
else:
    note("no adopter composed copy is reachable from this checkout, so the platform's own served "
         "copies under distribution/policies/v*/ are what is graded")
if not served_tier or not served_netpol:
    sys.exit("no served body to grade")

# --- cage-tier, EVERY served copy: the CLOBBER this patch gets out from under -
for f in served_tier:
    d = doc(f); mc = conds(d)
    ops = d["spec"]["matchConstraints"]["resourceRules"][0]["operations"]
    joined = " ".join(mc.values())
    mutation = yaml.dump(d["spec"]["mutations"])
    ok = ("UPDATE" in ops and cur.TIER_LABEL in mutation
          and cur.CLAIM_LABEL in joined and cur.CLAIM_LABEL in removed)
    check(ok, f"{f}: fires on UPDATE and clobbers the tier from the Namespace, and scopes on the "
              "CLAIM this patch removes -- so the rung the patch writes is not clobbered back")

# --- the orphan guard: the DENY this patch has to not trip -------------------
gpol = guard.orphan_guard(["4.0.0"])
gmc = " ".join(c["expression"] for c in gpol["spec"]["matchConditions"])
check(guard.LABEL == cur.CLAIM_LABEL and guard.LABEL in gmc and guard.LABEL in removed,
      "the orphan guard scopes on the same claim, so this UPDATE is out of its scope and is not refused")

# --- the governed-namespace guard: the one Deny whose subject IS a claimless pod
# This patch makes one. The guard is CREATE-only on purpose; derive that, so a
# future promotion to UPDATE breaks this check rather than breaking the estate.
gn = load("gnguard", os.path.join("..", "distribution", "render-governed-namespace-guard.py"))
gnops = gn.governed_namespace_guard()["spec"]["matchConstraints"]["resourceRules"][0]["operations"]
check(gnops == ["CREATE"],
      f"governed-namespace-requires-claim is CREATE-only ({gnops}); it Denies a claimless pod and "
      "this patch makes one -- promote it to UPDATE and every re-cage in the estate is refused")

# --- posture-trust-boundary, and its scope is narrower than it looks ---------
# The UNVERSIONED body in platform/posture/policies/ has ONE matchCondition and
# Denies any pod carrying the posture label without a matching claim -- and that
# is the copy installed on the demo cluster. Every SERVED and composed copy adds
# `only-this-policy-version`, so for an adopter running only the composed set a
# claimless pod is never matched and there is no Deny there. Removing the
# posture label in the same patch is REQUIRED against the first and harmless
# against the second, so the patch does it unconditionally -- and the reason is
# recorded with its scope rather than as a fact about the whole estate.
ptb = os.path.join("..", "posture", "policies", "posture-trust-boundary.yaml")
if os.path.exists(ptb):
    d = doc(ptb); mc = conds(d)
    gated = any(cur.CLAIM_LABEL in e for e in mc.values())
    check(d["spec"]["validationActions"] == ["Deny"]
          and cur.POSTURE_LABEL in " ".join(mc.values())
          and not gated and cur.POSTURE_LABEL in removed,
          "the UNVERSIONED posture-trust-boundary -- the copy installed on the demo cluster -- Denies "
          "a posture that does not equal its claim and is NOT gated on a version, so a patch that "
          "removed the claim and left the posture label would be refused there; both go in one patch")
else:
    note("the unversioned posture-trust-boundary is not in this checkout; that leg is not graded")
for f in platform_copies("posture-trust-boundary.yaml"):
    check(any(cur.CLAIM_LABEL in e for e in conds(doc(f)).values()),
          f"{f}: the SERVED copy IS gated on the claim, so for an adopter running only the composed "
          "set a claimless pod is out of its scope -- the reason the posture label is removed is the "
          "unversioned copy, not this one")

# --- cage-netpol, EVERY served copy: where the re-caged pod LANDS ------------
pairs = None; rungs = None
for f in served_netpol:
    d = doc(f); mc = conds(d)
    gen = " ".join(d["spec"]["generate"][0]["expression"].split())
    rr = [v["expression"] for v in d["spec"]["variables"] if v["name"] == "rungs"][0]
    rr = [r.strip().strip("'\"") for r in rr.strip("[] \n").split(",")]
    sel = re.search(r'"podSelector":\s*dyn\(\{"matchLabels":\s*dyn\(\{(.*?)\}\)\}\)', gen)
    pp = re.findall(r'"([^"]+)":\s*dyn\(([^)]*)\)', sel.group(1)) if sel else []
    reach = " ".join([v["expression"] for v in d["spec"]["variables"] if v["name"] == "reach"][0].split())
    joined = " ".join(mc.values())
    ok = (cur.CAGED_LABEL in joined and cur.TIER_LABEL in joined
          and {k for k, _ in pp} == {cur.CAGED_LABEL, cur.TIER_LABEL}
          and cur.BOTTOM_RUNG in rr
          and "'isolated': {'ingress': dyn([]), 'egress': dyn([])}" in reach
          and '"policyTypes": dyn(["Ingress", "Egress"])' in gen)
    check(ok, f"{f}: generates one cage-reach-<rung> per rung, each selecting exactly caged+tier, and "
              f"the `{cur.BOTTOM_RUNG}` one has EMPTY ingress and EMPTY egress under both policyTypes")
    # THE PRECONDITION, derived rather than assumed. Every SERVED copy gates on
    # the claim; the patch removes the claim; therefore a re-caged pod does NOT
    # fire this policy and CANNOT generate its own reach cage. It can only be
    # SELECTED by one the namespace already has.
    check(any(cur.CLAIM_LABEL in e for e in mc.values()),
          f"{f}: the served copy is gated on the claim, so a re-caged pod (claim removed) does NOT "
          f"fire it -- the patch cannot GENERATE cage-reach-{cur.BOTTOM_RUNG}, only be selected by "
          "one already in the namespace. That is this mechanism's precondition, not a detail")
    if pairs is None:
        pairs, rungs = pp, rr

# The AUTHORING copy, as a cross-check only -- and the difference is named.
gp = os.path.join("..", "graded", "policies", "cage-netpol.yaml")
if os.path.exists(gp):
    gc = conds(doc(gp))
    note("graded/policies/cage-netpol.yaml is the AUTHORING copy: no Kustomization serves it and it "
         "is installed on no cluster. It is " +
         ("also gated on the claim" if any(cur.CLAIM_LABEL in e for e in gc.values())
          else "NOT gated on the claim, unlike every served copy -- which is exactly why the verdict "
               "above is taken from the served bodies and never from it"))

# The selector semantics, built from a SERVED copy's own key/value pairs.
def selector_for(rung):
    return {k: (rung if v.strip() == "t" else v.strip().strip('"')) for k, v in pairs}
def selected_by(labels):
    return [r for r in rungs if all(labels.get(k) == v for k, v in selector_for(r).items())]
def merge(labels, annotations, p):
    la, an = dict(labels), dict(annotations)
    for k, v in p.get("labels", {}).items():
        la.pop(k, None) if v is None else la.__setitem__(k, v)
    for k, v in p.get("annotations", {}).items():
        an.pop(k, None) if v is None else an.__setitem__(k, v)
    return la, an

# No pod exists here. `before` is a PLANTED label set in the shape cage-tier
# leaves a pod in, and `selected_by` is the served selectors applied to it.
before = {cur.CAGED_LABEL: "true", cur.TIER_LABEL: "restricted", cur.CLAIM_LABEL: "2.0.0"}
after, notes = merge(before, {}, patch)
check(selected_by(before) == ["restricted"],
      "on a PLANTED pod labelled as cage-tier leaves one at `restricted`, the SERVED selectors pick "
      "cage-reach-restricted")
check(selected_by(after) == [cur.BOTTOM_RUNG],
      f"apply the patch to that planted label set and the SERVED selectors pick "
      f"cage-reach-{cur.BOTTOM_RUNG}, and nothing else: {selected_by(after)} -- IF the namespace "
      "already carries that NetworkPolicy, which the patch cannot create")
check(notes.get(cur.RETIRED_CLAIM_ANNOTATION) == "2.0.0",
      "...and the retired version is still readable off the patched label set, as an annotation")
check(cur.CLAIM_LABEL not in after,
      "the claim is gone from the labels, which is what stops cage-tier clobbering the rung back")

# --- 5. THE REGRESSION THIS REPAIR CLOSES, as a property, not a memory -------
# Removing the claim takes the pod PERMANENTLY out of cage-tier's scope (proved
# from every served cage-tier's own matchCondition above), so the rung the pod
# carries when this patch lands is the rung it keeps for the rest of its life. A
# patch that removes the claim and does NOT write the rung therefore freezes the
# pod where it was admitted -- which is what the shipped de-posture patch did: it
# removed the claim and the identity posture label and never touched the tier.
frozen, _ = merge(before, {}, {"labels": {cur.CLAIM_LABEL: None, cur.POSTURE_LABEL: None}})
check(selected_by(frozen) == ["restricted"] and selected_by(frozen) != [cur.BOTTOM_RUNG],
      "on the same planted label set, a claim-removing patch that names no rung still selects "
      "cage-reach-restricted -- and with the claim gone nothing can ever move it again, so the "
      "retirement would change nothing. That is the defect this repair closes")
check(cur.TIER_LABEL not in removed and labels_after.get(cur.TIER_LABEL) == cur.BOTTOM_RUNG,
      "the re-cage patch names the rung, so a bottom-rung reach cage already in the namespace "
      "selects the pod")

# --- 5b. THE TWO RESIDUAL SOFTENINGS, recorded rather than hidden ------------
# Tighten-only holds. These are not counter-examples to it; they are what the
# patch costs, and neither was written down before ticket 91 round 2.
check(all(cur.CLAIM_LABEL in " ".join(conds(doc(f)).values()) for f in served_tier),
      "AFTER the patch the pod is outside every served cage-tier's scope, so its rung is held by a "
      "label no admission will re-assert: a re-caged pod's cage is softer against a hand edit than a "
      "claiming pod's, and only RBAC -- workloads cannot patch pods -- still holds it")
check(not cur.is_tighten("baseline", "infra") and "infra" not in cur.ORDER,
      "`infra` is not a rung on this ladder (ADR-0022: a platform role declaration), so a pod that "
      "somehow carries it reads as UNKNOWN and is OVERWRITTEN with the bottom rung -- fail-closed, "
      "and an overwrite of a declaration rather than a move along the ladder")
if fails: sys.exit(f"{len(fails)} broken")
PY

say "6. offline: a missing instrument re-cages nothing (ADR-0020)"
python3 - <<'PY' || fail "the controller does not refuse on a missing or empty version array"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("currency", "currency.py")
cur = importlib.util.module_from_spec(spec); spec.loader.exec_module(cur)
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)

class Boom:
    def __call__(self, method, path, **kw):
        raise OSError("HTTP Error 404: Not Found")
try:
    cur.get_supported(Boom())
    check(False, "an unreadable version array raises MissingInstrument")
except cur.MissingInstrument as e:
    check("404" in str(e) or "resourceset" in str(e).lower(),
          f"an unreadable version array is a NAMED missing instrument, not an empty set: {e}")
except Exception as e:
    check(False, f"an unreadable version array raised {type(e).__name__}, not MissingInstrument: {e}")

try:
    cur.plan_actions(set(), [{"namespace": "n", "name": "p", "claim": "2.0.0", "tier": "baseline"}])
    check(False, "an EMPTY supported set is refused rather than re-caging the whole estate")
except cur.MissingInstrument:
    check(True, "an EMPTY supported set is refused rather than re-caging the whole estate")
if fails: sys.exit(f"{len(fails)} broken")
PY

say "7. offline: the grant holds no verb that can loosen or remove a workload"
python3 - <<'PY' || fail "the RBAC grant is wider than re-cage"
import sys, yaml
docs = [d for d in yaml.safe_load_all(open("manifests/rbac.yaml")) if d]
roles = [d for d in docs if d["kind"] == "ClusterRole"]
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)
check(len(roles) == 1, "exactly one ClusterRole: the single audited grant")
verbs = {}
for r in roles:
    for rule in r["rules"]:
        for res in rule["resources"]:
            verbs.setdefault(res, set()).update(rule["verbs"])
check(verbs.get("pods") == {"get", "list", "patch"},
      f"on pods the grant is get/list/patch and nothing else: {sorted(verbs.get('pods', []))}")
check("delete" not in verbs.get("pods", set()),
      "it CANNOT delete a pod: eviction was the blunt lever, and a workload is never removed, only caged")
check("create" not in verbs.get("pods", set()) and "update" not in verbs.get("pods", set()),
      "it cannot create or wholesale-replace a pod either")
check(verbs.get("resourcesets") == {"get"},
      f"it reads the version array and nothing else: {sorted(verbs.get('resourcesets', []))}")
check(set(verbs) == {"pods", "resourcesets"},
      f"and it touches no other resource: {sorted(verbs)}")
if fails: sys.exit(f"{len(fails)} broken")
PY

say "8. offline: the module is owned -- party.yaml declares it, its objects carry the platform identity"
python3 - <<'PY' || fail "the module is not declared by an owner"
import importlib.util, os, sys, yaml
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
guard = load("guard", os.path.join("..", "distribution", "render-orphan-guard.py"))
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)

party = yaml.safe_load(open(os.path.join("..", "party.yaml")))
entries = [p for p in party.get("publishes", []) if p["name"] == "currency-controller"]
check(len(entries) == 1, "platform's party.yaml declares the currency controller in publishes[]")
if entries:
    e = entries[0]
    check(e["kind"] == "implementations",
          f"it is declared as an implementations member, like the policy line: {e['kind']}")
    check(os.path.isdir(os.path.join("..", e["path"])),
          f"the path it declares is this directory: {e['path']}")
    check(e.get("revoked") == [], "nothing published from it is withdrawn")
check("platform" in party.get("roles", []) and "publisher" in party.get("roles", []),
      "the declaring party holds the publisher and platform roles")

# Numbered by the platform's own tag, not a policy tag: the same identity the
# orphan guard already wears, read off the renderer that owns the value.
for f in ("manifests/rbac.yaml", "manifests/cronjob.yaml"):
    objs = [d for d in yaml.safe_load_all(open(f)) if d]
    for o in objs:
        labels = o["metadata"].get("labels", {})
        check(labels.get(guard.IDENTITY_LABEL) == guard.IDENTITY,
              f"{f}: {o['kind']}/{o['metadata']['name']} is labelled {guard.IDENTITY}, "
              "platform machinery numbered by the platform's own tag")
if fails: sys.exit(f"{len(fails)} broken")
PY

say "9. offline: the could-not-look branch is run, not assumed"
selfcheck_absent "$HERE/${BASH_SOURCE##*/}" kind

# --- live tail: the sentence itself, or a named could-not-look ---------------
# Nothing below this line is simulated. Either a real pod on a real cluster is
# observed re-caged, or the script says what it needed and exits 3. Every
# precondition is checked BEFORE the reconcile pass, because the pass strips a
# live pod's claim and there is no undo: a precondition discovered afterwards
# would be a red left behind as damage.
if ! have kubectl; then
  live_tail_skip "kubectl is not on PATH, so no cluster can be asked whether a pod was re-caged"
elif ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif ! timeout 10 kubectl --context "$CTX" -n currency-system get cronjob currency-controller >/dev/null 2>&1; then
  live_tail_skip "no currency-controller CronJob on $CTX (run currency-controller/up.sh)"
elif ! ON_CLUSTER=$(timeout 20 kubectl --context "$CTX" -n currency-system get configmap currency-controller-src \
       -o jsonpath='{.data.currency\.py}' 2>/dev/null) || [ -z "$ON_CLUSTER" ]; then
  live_tail_skip "the currency-controller CronJob on $CTX mounts no readable currency-controller-src ConfigMap, so it is unknown which controller would run"
elif ! CM_SHA=$(printf '%s' "$ON_CLUSTER" | sha256_of) \
   || ! FILE_SHA=$(printf '%s' "$(cat "$HERE/currency.py")" | sha256_of); then
  # A missing instrument is a could-not-look here, not a pass and not a red --
  # the same rule the controller itself follows (ADR-0020).
  live_tail_skip "neither sha256sum nor shasum is on PATH, so the copy of currency.py running on $CTX cannot be compared with the one this run graded"
elif [ "$CM_SHA" != "$FILE_SHA" ]; then
  # The offline half graded THIS file. The cluster runs whatever is in the
  # ConfigMap. Grading a pass taken by a different copy would be a claim about
  # code this run never read, so it is a could-not-look and says which copy.
  # BOTH sides are hashed the same way: the ConfigMap arrives through `$( )`,
  # which strips trailing newlines, so the file is put through `$( )` too. The
  # first shipped version hashed the file straight off disk and could therefore
  # never compare equal -- not even against a byte-identical file.
  live_tail_skip "the currency-controller on $CTX runs a different copy of currency.py than this checkout ships (ConfigMap sha256 ${CM_SHA:0:12}, file ${FILE_SHA:0:12}); run currency-controller/up.sh to install this one"
else
  # The supported set is read off the SAME ResourceSet the controller reads, on
  # the cluster itself -- not off this checkout's versions.yaml, which is what
  # the array is declared to be rather than what this cluster is running. If it
  # cannot be read, that is the controller's own missing instrument (ADR-0020)
  # and this tail says so; it never falls back to "then nothing is stale".
  SUPPORTED=$(timeout 20 kubectl --context "$CTX" -n flux-system get resourceset policy-versions \
                -o jsonpath='{range .spec.inputs[0].versions[*]}{.version}{"\n"}{end}' 2>/dev/null || true)
  if [ -z "$SUPPORTED" ]; then
    live_tail_skip "the ResourceSet policy-versions is not readable on $CTX, so the supported-version set the controller judges against cannot be established"
  else
  POD_LINES=$(timeout 20 kubectl --context "$CTX" get pods -A \
            -l policy-as-versioned.dev/policy-version --field-selector status.phase=Running \
            -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}/{.metadata.labels.policy-as-versioned\.dev/policy-version}{"\n"}{end}' 2>/dev/null || true)
  STALE=$(SUPPORTED="$SUPPORTED" POD_LINES="$POD_LINES" python3 -c '
import os
sup = set(os.environ["SUPPORTED"].split())
for line in os.environ["POD_LINES"].splitlines():
    line = line.strip()
    if not line: continue
    ns, name, claim = line.rsplit("/", 2)
    if claim and claim not in sup:
        print(f"{ns} {name} {claim}"); break
')
  say "   supported on $CTX: $(echo $SUPPORTED); claiming pods: $(printf '%s' "$POD_LINES" | grep -c . || true)"
  if [ -z "$STALE" ]; then
    live_tail_skip "the currency-controller CronJob is installed on $CTX but no running pod claims a version the array has retired, so there is nothing to observe being re-caged"
  else
    set -- $STALE; NS="$1"; POD="$2"; CLAIM="$3"
    # THE PRECONDITION, CHECKED FIRST. The re-cage patch removes the claim, and
    # every served cage-netpol is gated on the claim, so the patched pod cannot
    # generate its own reach cage: it can only be selected by one the namespace
    # already has. A namespace with none is a could-not-look, and it has to be
    # discovered BEFORE the pass, not after it has stripped a live pod's claim.
    SELECTOR=$(timeout 20 kubectl --context "$CTX" -n "$NS" get networkpolicy cage-reach-isolated \
                 -o jsonpath='{.spec.podSelector.matchLabels}' 2>/dev/null || true)
    if [ -z "$SELECTOR" ]; then
      live_tail_skip "namespace $NS carries no cage-reach-isolated NetworkPolicy, so re-caging $NS/$POD would write a label and change nothing it reaches; the pass was not run"
    else
    say "5. live: $NS/$POD claims retired version $CLAIM, and $NS already carries cage-reach-isolated -- running one bounded pass"
    timeout 20 kubectl --context "$CTX" -n currency-system delete job currency-verify --ignore-not-found >/dev/null 2>&1 || true
    if ! timeout 20 kubectl --context "$CTX" -n currency-system create job --from=cronjob/currency-controller currency-verify >/dev/null 2>&1; then
      live_tail_skip "could not create the reconcile job on $CTX (image pull or RBAC; see README)"
    elif ! timeout 180 kubectl --context "$CTX" -n currency-system wait --for=condition=complete job/currency-verify --timeout=170s >/dev/null 2>&1; then
      live_tail_skip "the reconcile job on $CTX did not complete inside 170s, so no pass was observed"
    else
      AFTER=$(timeout 20 kubectl --context "$CTX" -n "$NS" get pod "$POD" \
        -o jsonpath='{.metadata.labels.posture\.acme\.io/tier}|{.metadata.labels.posture\.acme\.io/caged}|{.metadata.labels.policy-as-versioned\.dev/policy-version}|{.metadata.annotations.policy-as-versioned\.dev/retired-claim}|{.status.phase}' 2>/dev/null || true)
      IFS='|' read -r TIER CAGED STILL NOTE PHASE <<<"$AFTER"
      [ "$TIER" = "isolated" ] || fail "after the pass $NS/$POD carries tier '$TIER', not isolated"
      [ "$CAGED" = "true" ]    || fail "after the pass $NS/$POD carries caged '$CAGED', not true"
      [ -z "$STILL" ]          || fail "after the pass $NS/$POD still claims '$STILL'"
      [ "$NOTE" = "$CLAIM" ]   || fail "after the pass $NS/$POD does not record its retired claim ('$NOTE' != '$CLAIM')"
      [ "$PHASE" = "Running" ] || fail "after the pass $NS/$POD is $PHASE, not Running -- it was removed, not caged"
      # ...and the NetworkPolicy really does select THIS pod: its podSelector is
      # compared against the pod's own labels, rather than the object merely
      # being observed to exist. "inside cage-reach-isolated" is a claim about
      # selection, so selection is what is checked.
      SELECTOR="$SELECTOR" TIER="$TIER" CAGED="$CAGED" python3 -c '
import json, os, sys
sel = json.loads(os.environ["SELECTOR"])
pod = {"posture.acme.io/tier": os.environ["TIER"], "posture.acme.io/caged": os.environ["CAGED"]}
missing = {k: v for k, v in sel.items() if pod.get(k) != v}
if missing:
    sys.exit(f"cage-reach-isolated selects {sel} and the pod does not match on {missing}")
print(f"  ok   cage-reach-isolated podSelector {sel} matches the re-caged pod\x27s own labels")
' || fail "the cage-reach-isolated NetworkPolicy in $NS does not select the re-caged pod"
      echo "  ok   $NS/$POD is Running, tier=isolated, caged=true, claim removed, retired claim recorded as $CLAIM"
      LIVE_OBSERVED="$NS/$POD (was $CLAIM, still Running, now tier=isolated and selected by cage-reach-isolated, which $NS already carried)"
    fi
    fi
  fi
  fi
fi

pass_line "a pod admitted under a version that is later retired is re-caged to isolated on the next controller pass -- observed: ${LIVE_OBSERVED:-none}"
