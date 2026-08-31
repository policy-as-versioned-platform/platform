#!/usr/bin/env bash
# Beat: "every policy version the platform DECLARES can actually admit a pod,
# and the cage that version ships actually ran on it."
#
# The orphan guard makes distribution/versions.yaml's array the definition of
# what may run: a pod claiming a version in the array is allowed, a pod claiming
# anything else is refused. This script asks the other half of that question,
# which nothing asked before 2026-08-28: of the versions the array DOES allow,
# which ones can a workload actually be created under?
#
# Found by the review that day, live on kind-driftwood: 2.0.0, 2.0.1 and 3.0.0 —
# every released line, including the one adopters were pinned to — refused every
# pod outright:
#   pods "..." is forbidden: the integer value of priority (0) must not be
#   provided in pod spec; priority admission controller computed -10 from the
#   given PriorityClass name
# because their cage-tier writes `spec.priorityClassName` from a mutating webhook
# without the `spec.priority` and `spec.preemptionPolicy` the built-in Priority
# admission plugin re-derives from that same class. All three lines are now
# RETIRED from the array (versions.yaml says why, in full); this script is what
# keeps the question asked of whatever the array declares next.
#
# 2026-08-29 review, second defect: asking only "did kubectl print an error?"
# turns ABSENCE into a pass. A declared version whose cage-tier MutatingPolicy is
# not installed at all admits trivially — proven live by deleting cage-tier-2-0-2
# and watching this beat go green. So the pod is now READ BACK and the mutation
# itself asserted, and a version whose cage is not on the cluster is a SKIP with
# its name, never a 0.
#
# 2026-08-29 review, third defect: one probe on the baseline rung cannot see a
# mismatch on restricted, quarantine or isolated — and the whole defect class is
# "the pod's priority fields disagree with the class the cage named", one class
# per rung. So the probe now loops the ladder as well as the array: one governed
# Namespace per tier, one pod per (declared version, tier).
#
# Definition of green: every declared version admits a real pod on every rung of
# the ladder, and every one of those pods came back wearing that rung's own cage.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / skip
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# ponytail: `infra` is off the probe ladder on purpose — only a platform-role
# party may declare it (ADR-0022) and this Namespace is not one. Add it here the
# day the probe runs under the platform's own party artefact.
TIERS="baseline restricted quarantine isolated"

command -v python3 >/dev/null || fail "python3 required"
require_substrate "$CLUSTER"
timeout 10 kubectl --context "$CTX" get mutatingpolicy >/dev/null 2>&1 \
  || skip "Kyverno MutatingPolicy CRD not installed on $CTX (run engine/up.sh then graded/up.sh)"

VERSIONS="$(python3 - "$HERE" <<'PY'
import sys, importlib.util
from pathlib import Path
dist = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("rog", dist / "render-orphan-guard.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
print("\n".join(mod.versions(dist / "versions.yaml")))
PY
)"
[ -n "$VERSIONS" ] || fail "distribution/versions.yaml declares no versions"

# Absence is not a pass: a version whose own cage-tier policy is not on the
# cluster would admit trivially, so it is a could-not-look with its name.
UNINSTALLED=()
while IFS= read -r v; do
  [ -n "$v" ] || continue
  timeout 10 kubectl --context "$CTX" get mutatingpolicy "cage-tier-${v//./-}" >/dev/null 2>&1 \
    || UNINSTALLED+=("$v")
done <<<"$VERSIONS"
if [ ${#UNINSTALLED[@]} -gt 0 ]; then
  skip "$(printf '%s ' "${UNINSTALLED[@]}")— declared by distribution/versions.yaml but the version's own cage-tier MutatingPolicy is not installed on $CTX, so a pod admitting here would prove nothing about its cage"
fi

NSPREFIX="version-admit-probe"
cleanup() {
  for t in $TIERS; do
    timeout 180 kubectl --context "$CTX" delete ns "$NSPREFIX-$t" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
cleanup
for t in $TIERS; do
  timeout 20 kubectl --context "$CTX" create ns "$NSPREFIX-$t" >/dev/null \
    || fail "could not create the probe namespace $NSPREFIX-$t on $CTX"
  # Governed, and the rung declared on the NAMESPACE — which is where ADR-0022
  # puts it. The pod carries no tier label at all; the cage writes it.
  timeout 20 kubectl --context "$CTX" label ns "$NSPREFIX-$t" \
    policy-as-versioned.dev/governed=true "posture.acme.io/tier=$t" >/dev/null
done

say "one REAL pod per (declared version x ladder rung), read back, on $CTX"
BROKEN=()
while IFS= read -r v; do
  [ -n "$v" ] || continue
  slug="${v//./-}"
  for t in $TIERS; do
    ns="$NSPREFIX-$t"; name="admit-$slug"
    err="$(timeout 30 kubectl --context "$CTX" -n "$ns" run "$name" \
           --image=registry.k8s.io/pause:3.9 --restart=Never \
           --labels="policy-as-versioned.dev/policy-version=$v" 2>&1 >/dev/null || true)"
    if [ -n "$err" ]; then
      BROKEN+=("$v/$t: $(head -1 <<<"$err")")
      echo "  FAIL $v $t: $(head -1 <<<"$err")"
      continue
    fi
    # The class the cage was supposed to name, and that class's OWN fields — the
    # three the Priority admission plugin re-derives and refuses a pod over.
    want_pc="cage-$t-$slug"
    pcfields="$(timeout 10 kubectl --context "$CTX" get priorityclass "$want_pc" \
                -o jsonpath='{.value}|{.preemptionPolicy}' 2>/dev/null || true)"
    if [ -z "$pcfields" ]; then
      BROKEN+=("$v/$t: PriorityClass $want_pc absent, so the version ships no cage for this rung")
      echo "  FAIL $v $t: PriorityClass $want_pc absent"
      continue
    fi
    want_prio="${pcfields%%|*}"; want_preempt="${pcfields##*|}"
    [ -n "$want_preempt" ] || want_preempt="PreemptLowerPriority"   # the API default
    got="$(timeout 10 kubectl --context "$CTX" -n "$ns" get pod "$name" \
           -o jsonpath='{.spec.priorityClassName}|{.spec.priority}|{.spec.preemptionPolicy}|{.metadata.labels.posture\.acme\.io/caged}|{.metadata.labels.posture\.acme\.io/tier}')"
    IFS='|' read -r got_pc got_prio got_preempt got_caged got_tier <<<"$got"
    [ -n "$got_preempt" ] || got_preempt="PreemptLowerPriority"
    if [ "$got_pc" = "$want_pc" ] && [ "$got_prio" = "$want_prio" ] \
       && [ "$got_preempt" = "$want_preempt" ] && [ "$got_caged" = "true" ] \
       && [ "$got_tier" = "$t" ]; then
      echo "  ok   $v $t: ADMITTED and caged — pc=$got_pc prio=$got_prio preempt=$got_preempt tier=$got_tier"
    else
      BROKEN+=("$v/$t: admitted but the cage did not run — want pc=$want_pc prio=$want_prio preempt=$want_preempt caged=true tier=$t, got pc=$got_pc prio=$got_prio preempt=$got_preempt caged=$got_caged tier=$got_tier")
      echo "  FAIL $v $t: admitted UNCAGED — got pc=$got_pc prio=$got_prio preempt=$got_preempt caged=$got_caged tier=$got_tier"
    fi
  done
done <<<"$VERSIONS"

if [ ${#BROKEN[@]} -gt 0 ]; then
  fail "$(printf '%s; ' "${BROKEN[@]}")— declared by distribution/versions.yaml and allowed by the orphan guard. A version that cannot admit a pod, or admits one its own cage never touched, is not runnable. The repair is a patch release of the line (cut-release.yml, gitsign) or a retirement of the array element plus an adopter recompose; a released tree cannot be edited in place."
fi
echo "PASS: every version distribution/versions.yaml declares admits a real pod on every rung of the ladder on $CTX, and every pod came back wearing that rung's own cage"
