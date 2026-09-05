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
# It grades the controller's LOGIC against PLANTED state, and it grades the
# seam between that logic and the policy bodies this repo actually ships. It
# derives every fact it asserts from those files -- cage.py's own ladder,
# cage-tier.yaml's own matchConditions, cage-netpol.yaml's own podSelectors,
# render-orphan-guard.py's own identity label, rbac.yaml's own verbs -- rather
# than restating a literal:
#   1. the pure core's own asserts (`currency.py selfcheck`);
#   2. a planted pod list: the pod whose CLAIM is retired is selected, the
#      current pod and the un-claiming pod are not, and a pod already at the
#      bottom rung is held rather than patched;
#   3. TIGHTEN-ONLY at the seam: the tier the patch writes IS the last element
#      of graded/cage.py's own ORDER, and is_tighten() holds from every rung on
#      that ladder and from an unknown one;
#   4. the patch SURVIVES admission and LANDS in the bottom rung's reach cage:
#      cage-tier scopes on the claim the patch removes (so the tier it writes is
#      not clobbered back), the orphan guard scopes on the same claim (so the
#      UPDATE is not refused), cage-netpol's own matchConditions still fire on
#      the labels the patch leaves, and the `cage-reach-isolated` NetworkPolicy
#      it generates selects exactly the label pair the patch produces, with
#      empty ingress AND egress rule lists under both policyTypes;
#   5. the LEGACY de-posture patch (remove BOTH labels) matched NO generated
#      reach policy -- a LOOSENING to full reach -- derived from the same
#      podSelectors, so the repair cannot silently regress;
#   6. a missing instrument re-cages nothing: a version array the controller
#      cannot read, or an empty one, refuses the pass by name (ADR-0020);
#   7. the RBAC grant holds no verb that can loosen or remove a workload;
#   8. the module is OWNED: party.yaml declares it in `publishes[]`, and its
#      objects carry the same platform-machinery identity the orphan guard uses;
#   9. the could-not-look branch is RUN, not assumed (lib.sh selfcheck_absent).
#
# WHAT THE OFFLINE HALF CANNOT OBSERVE, and never claims. No pod exists here.
# Nothing here observes that the CronJob fired, that the API server accepted the
# patch, that admission did not clobber it, or that the generated NetworkPolicy
# actually cut the pod's reach. Those are facts about a running cluster. The
# live tail below is the only thing that can see them, and when it cannot look
# it says so and the whole script exits 3 (lib.sh pass_line): this script has no
# PASS that does not rest on an observed pod.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line / selfcheck_absent
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

say "1. offline: currency.py selfcheck (the pure core's own asserts)"
python3 "$HERE/currency.py" selfcheck || fail "selfcheck failed"

say "2. offline: the plan selects the retired-claim pod, holds one already at the bottom rung"
PLAN=$(printf '%s' '[
  {"namespace":"tuppence","name":"reset-current","claim":"4.0.0","tier":"restricted"},
  {"namespace":"tuppence","name":"reset-retired","claim":"2.0.0","tier":"restricted"},
  {"namespace":"ludlow","name":"reset-bottom","claim":"2.0.0","tier":"isolated"},
  {"namespace":"driftwood","name":"cots","claim":null,"tier":"baseline"}
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
      "a stale pod already at the bottom rung is HELD, not patched again")
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

say "4. offline: the patch survives admission and lands in the bottom rung's reach cage"
python3 - <<'PY' || fail "the re-cage patch does not land where the sentence says it lands"
import importlib.util, os, re, sys, yaml
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
cur = load("currency", "currency.py")
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)

patch = cur.recage_patch("2.0.0")["metadata"]
labels_after = {k: v for k, v in patch["labels"].items() if v is not None}
removed = {k for k, v in patch["labels"].items() if v is None}

def doc(p):
    with open(p) as fh: return list(yaml.safe_load_all(fh))[0]

# --- cage-tier: the CLOBBER this patch has to get out from under -------------
tier_pol = doc(os.path.join("..", "graded", "policies", "cage-tier.yaml"))
mc = " ".join(c["expression"] for c in tier_pol["spec"]["matchConditions"])
ops = tier_pol["spec"]["matchConstraints"]["resourceRules"][0]["operations"]
mutation = yaml.dump(tier_pol["spec"]["mutations"])
check("UPDATE" in ops,
      "cage-tier fires on UPDATE, so a naive label patch WOULD be re-decided at admission")
check(cur.TIER_LABEL in mutation,
      "cage-tier CLOBBERS the tier label from the Namespace -- writing the pod's tier is not enough on its own")
check(cur.CLAIM_LABEL in mc and cur.CLAIM_LABEL in removed,
      "cage-tier scopes on the CLAIM this patch removes, so the tier the patch writes is not clobbered back")

# --- the orphan guard: the DENY this patch has to not trip -------------------
guard = load("guard", os.path.join("..", "distribution", "render-orphan-guard.py"))
gpol = guard.orphan_guard(["4.0.0"])
gmc = " ".join(c["expression"] for c in gpol["spec"]["matchConditions"])
check(guard.LABEL == cur.CLAIM_LABEL and guard.LABEL in gmc and guard.LABEL in removed,
      "the orphan guard scopes on the same claim, so this UPDATE is out of its scope and is not refused")

# --- posture-trust-boundary: the DENY that catches a HALF-DONE patch ---------
# It scopes on the identity substrate's posture label and refuses any pod whose
# posture does not equal its claim. Removing the claim and leaving the posture
# behind is exactly that shape, so the posture label has to go in the same patch
# or the whole UPDATE is refused at admission. Identity is shelved (ticket 90),
# so this is graded only where the policy body is still shipped.
ptb = os.path.join("..", "posture", "policies", "posture-trust-boundary.yaml")
if os.path.exists(ptb):
    p = doc(ptb)
    pmc = " ".join(c["expression"] for c in p["spec"]["matchConditions"])
    pval = " ".join(v["expression"] for v in p["spec"]["validations"])
    check(p["spec"]["validationActions"] == ["Deny"] and cur.POSTURE_LABEL in pmc,
          "posture-trust-boundary Denies, and scopes on the identity posture label")
    check("variables.posture == variables.claimed" in pval and cur.POSTURE_LABEL in removed,
          "it refuses a posture that does not equal its claim, so the patch removes the posture "
          "label in the SAME update as the claim -- otherwise the whole re-cage is refused")
else:
    print("  --   posture-trust-boundary is not shipped in this checkout; that leg is not graded")

# --- cage-netpol: where the re-caged pod LANDS ------------------------------
np = doc(os.path.join("..", "graded", "policies", "cage-netpol.yaml"))
nmc = {c["name"]: c["expression"] for c in np["spec"]["matchConditions"]}
check(cur.CAGED_LABEL in nmc["is-caged"] and labels_after.get(cur.CAGED_LABEL) == "true",
      "cage-netpol fires only on a caged pod, and the patch asserts the caged label rather than assuming it")
check(cur.TIER_LABEL in nmc["tier-restricts-reach"]
      and labels_after.get(cur.TIER_LABEL) != "baseline",
      "cage-netpol's own condition excludes `baseline`; the tier the patch writes is not baseline, so it fires")

# The generated NetworkPolicies' podSelectors, DERIVED from the generate
# expression rather than restated: the rung list and the selector's own key/value
# pairs are read out of the shipped body, and `t` is the rung being generated.
gen = " ".join(np["spec"]["generate"][0]["expression"].split())
rungs = [v["expression"] for v in np["spec"]["variables"] if v["name"] == "rungs"][0]
rungs = [r.strip().strip("'\"") for r in rungs.strip("[] \n").split(",")]
sel = re.search(r'"podSelector":\s*dyn\(\{"matchLabels":\s*dyn\(\{(.*?)\}\)\}\)', gen)
check(sel is not None, "cage-netpol's generated podSelector is readable from the shipped body")
pairs = re.findall(r'"([^"]+)":\s*dyn\(([^)]*)\)', sel.group(1)) if sel else []
check({k for k, _ in pairs} == {cur.CAGED_LABEL, cur.TIER_LABEL},
      f"each cage-reach-<rung> selects on exactly caged+tier: {sorted(k for k, _ in pairs)}")
check(cur.BOTTOM_RUNG in rungs,
      f"`{cur.BOTTOM_RUNG}` is one of the rungs cage-netpol generates a reach policy for")
check(re.search(r'"metadata":\s*dyn\(\{"name":\s*dyn\("cage-reach-"\s*\+\s*t"?\)?', gen) is not None
      or '"cage-reach-" + t' in gen,
      "each generated policy is named cage-reach-<rung>, one per rung")
reach = [v["expression"] for v in np["spec"]["variables"] if v["name"] == "reach"][0]
check("'isolated': {'ingress': dyn([]), 'egress': dyn([])}" in " ".join(reach.split()),
      "the bottom rung's reach table is EMPTY ingress and EMPTY egress -- nothing in, nothing out")
check('"policyTypes": dyn(["Ingress", "Egress"])' in gen,
      "...under both policyTypes, which is what makes the empty lists a deny-all rather than a no-op")

# The selector semantics, built from those pairs: `t` is the rung, anything else
# is the literal the body carries.
def selector_for(rung):
    return {k: (rung if v.strip() == "t" else v.strip().strip('"')) for k, v in pairs}
def selected_by(labels):
    return [r for r in rungs
            if all(labels.get(k) == v for k, v in selector_for(r).items())]
def merge(labels, annotations, p):
    la, an = dict(labels), dict(annotations)
    for k, v in p.get("labels", {}).items():
        la.pop(k, None) if v is None else la.__setitem__(k, v)
    for k, v in p.get("annotations", {}).items():
        an.pop(k, None) if v is None else an.__setitem__(k, v)
    return la, an

# A pod as cage-tier leaves it: caged, at its Namespace's rung, claiming 2.0.0.
before = {cur.CAGED_LABEL: "true", cur.TIER_LABEL: "restricted", cur.CLAIM_LABEL: "2.0.0"}
after, notes = merge(before, {}, patch)
# No pod exists here. `before` is a PLANTED label set in the shape cage-tier
# leaves a pod in, and `selected_by` is the shipped selectors applied to it.
# What this grades is the patch against those selectors, not a workload.
check(selected_by(before) == ["restricted"],
      "on a PLANTED pod labelled as cage-tier leaves one at `restricted`, the shipped selectors "
      "pick cage-reach-restricted")
check(selected_by(after) == [cur.BOTTOM_RUNG],
      f"apply the patch to that planted label set and the shipped selectors pick "
      f"cage-reach-{cur.BOTTOM_RUNG}, and nothing else: {selected_by(after)}")
check(notes.get(cur.RETIRED_CLAIM_ANNOTATION) == "2.0.0",
      "...and the retired version is still readable off the patched label set, as an annotation")
check(cur.CLAIM_LABEL not in after,
      "the claim is gone from the labels, which is what stops cage-tier clobbering the rung back")

# --- 5. THE REGRESSION THIS REPAIR CLOSES, as a property, not a memory -------
# Removing the claim takes the pod PERMANENTLY out of cage-tier's scope (proved
# from cage-tier's own matchCondition above), so the rung the pod carries when
# this patch lands is the rung it keeps for the rest of its life. A patch that
# removes the claim and does NOT write the rung therefore freezes the pod where
# it was admitted -- which is exactly what the shipped de-posture patch did: it
# removed the claim and the identity posture label and never touched the tier.
frozen, _ = merge(before, {}, {"labels": {cur.CLAIM_LABEL: None,
                                          "posture.acme.io/version": None}})
check(selected_by(frozen) == ["restricted"] and selected_by(frozen) != [cur.BOTTOM_RUNG],
      "on the same planted label set, a claim-removing patch that names no rung still selects "
      "cage-reach-restricted -- and with the claim gone nothing can ever move it again, so the "
      "retirement would change nothing. That is the defect this repair closes")
check(cur.TIER_LABEL not in removed and labels_after.get(cur.TIER_LABEL) == cur.BOTTOM_RUNG,
      "the re-cage patch names the rung, so the pod lands in the bottom rung's reach cage")
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
# observed re-caged, or the script says which cluster it needed and exits 3.
if ! have kubectl; then
  live_tail_skip "kubectl is not on PATH, so no cluster can be asked whether a pod was re-caged"
elif ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif ! timeout 10 kubectl --context "$CTX" -n currency-system get cronjob currency-controller >/dev/null 2>&1; then
  live_tail_skip "no currency-controller CronJob on $CTX (run currency-controller/up.sh)"
elif ! ON_CLUSTER=$(timeout 20 kubectl --context "$CTX" -n currency-system get configmap currency-controller-src \
       -o jsonpath='{.data.currency\.py}' 2>/dev/null) || [ -z "$ON_CLUSTER" ]; then
  live_tail_skip "the currency-controller CronJob on $CTX mounts no readable currency-controller-src ConfigMap, so it is unknown which controller would run"
elif [ "$(printf '%s' "$ON_CLUSTER" | shasum -a 256 | cut -d' ' -f1)" \
     != "$(shasum -a 256 < "$HERE/currency.py" | cut -d' ' -f1)" ]; then
  # The offline half above graded THIS file. The cluster runs whatever is in the
  # ConfigMap. Grading a pass taken by a different copy would be a claim about
  # code this run never read, so it is a could-not-look and says which copy.
  live_tail_skip "the currency-controller on $CTX runs a different copy of currency.py than this checkout ships (ConfigMap sha256 $(printf '%s' "$ON_CLUSTER" | shasum -a 256 | cut -c1-12), file $(shasum -a 256 < "$HERE/currency.py" | cut -c1-12)); run currency-controller/up.sh to install this one"
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
    say "5. live: $NS/$POD claims retired version $CLAIM -- running one bounded pass"
    timeout 20 kubectl --context "$CTX" -n currency-system delete job currency-verify --ignore-not-found >/dev/null 2>&1 || true
    if ! timeout 20 kubectl --context "$CTX" -n currency-system create job --from=cronjob/currency-controller currency-verify >/dev/null 2>&1; then
      live_tail_skip "could not create the reconcile job on $CTX (image pull or RBAC; see README)"
    elif ! timeout 180 kubectl --context "$CTX" -n currency-system wait --for=condition=complete job/currency-verify --timeout=170s >/dev/null 2>&1; then
      live_tail_skip "the reconcile job on $CTX did not complete inside 170s, so no pass was observed"
    else
      AFTER=$(timeout 20 kubectl --context "$CTX" -n "$NS" get pod "$POD" \
        -o jsonpath='{.metadata.labels.posture\.acme\.io/tier}|{.metadata.labels.policy-as-versioned\.dev/policy-version}|{.metadata.annotations.policy-as-versioned\.dev/retired-claim}|{.status.phase}' 2>/dev/null || true)
      TIER="${AFTER%%|*}"; REST="${AFTER#*|}"; STILL="${REST%%|*}"
      REST="${REST#*|}"; NOTE="${REST%%|*}"; PHASE="${REST##*|}"
      [ "$TIER" = "isolated" ] || fail "after the pass $NS/$POD carries tier '$TIER', not isolated"
      [ -z "$STILL" ]          || fail "after the pass $NS/$POD still claims '$STILL'"
      [ "$NOTE" = "$CLAIM" ]   || fail "after the pass $NS/$POD does not record its retired claim ('$NOTE' != '$CLAIM')"
      [ "$PHASE" = "Running" ] || fail "after the pass $NS/$POD is $PHASE, not Running -- it was removed, not caged"
      timeout 20 kubectl --context "$CTX" -n "$NS" get networkpolicy cage-reach-isolated \
        -o jsonpath='{.spec.podSelector.matchLabels}' >/dev/null 2>&1 \
        || fail "no cage-reach-isolated NetworkPolicy exists in $NS to hold the re-caged pod"
      echo "  ok   $NS/$POD is Running, tier=isolated, claim removed, retired claim recorded as $CLAIM"
      LIVE_OBSERVED="$NS/$POD (was $CLAIM, still Running, now tier=isolated inside cage-reach-isolated)"
    fi
  fi
  fi
fi

pass_line "a pod admitted under a version that is later retired is re-caged to isolated on the next controller pass -- observed: ${LIVE_OBSERVED:-none}"
