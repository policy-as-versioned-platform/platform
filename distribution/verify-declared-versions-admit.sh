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
# 2026-09-04 (ticket 63), fourth defect: an UNCUT TAIL took the whole beat down
# with it. Adding 5.0.0 to the array made every version skip, because the loop
# below is all-or-nothing and 5.0.0's cage-tier is not on any cluster. It cannot
# be: an element with no `commit` has not been released, its signed tag does not
# exist, so Flux has nothing to deliver. Absence of a release nobody has cut is
# not a defect and not an observation — but it must not be allowed to hide a
# real one on a line that IS cut, which is what a blanket skip did. So the array
# is partitioned: a CUT version (commit present) is probed for real and a
# missing cage on it is still a could-not-look by name; an UNCUT version is
# excluded from the probe and NAMED, in the output and in the PASS line, so the
# green says exactly what it did and did not look at. `--selfcheck` pins the
# partition.
#
# Definition of green: every CUT declared version admits a real pod on every
# rung of the ladder, every one of those pods came back wearing that rung's own
# cage, and any uncut tail is named rather than counted either way.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / skip
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# The one reader of the array, shared by the real run and the selfcheck. Prints
# two lines: `CUT: <versions>` and `UNCUT: <versions>`. With --selfcheck it runs
# the pure asserts on the partition instead and touches no disk.
declared_state() {
python3 - "$HERE" "${1:-}" <<'PY'
import importlib.util, sys
from pathlib import Path

dist, mode = Path(sys.argv[1]), sys.argv[2]
spec = importlib.util.spec_from_file_location("rog", dist / "render-orphan-guard.py")
rog = importlib.util.module_from_spec(spec); spec.loader.exec_module(rog)


def partition(els):
    """(cut, uncut) by the `commit` field. An element with no commit -- absent
    or empty -- is an UNCUT TAIL: cut-release.yml fills that field in when it
    cuts the signed tag, so until then the tag does not exist, Flux cannot
    deliver the version and no cluster can be carrying it. Nothing else in this
    file may decide what 'released' means: this is the whole definition."""
    cut = [e["version"] for e in els if e.get("commit")]
    uncut = [e["version"] for e in els if not e.get("commit")]
    return cut, uncut


if mode == "--selfcheck":
    assert partition([{"version": "4.0.0", "commit": "abc"}]) == (["4.0.0"], []), \
        "a released element is cut and must be probed"
    assert partition([{"version": "5.0.0", "tag": "policy/v5.0.0"}]) == ([], ["5.0.0"]), \
        "an element with NO commit key at all is an uncut tail"
    assert partition([{"version": "5.0.0", "commit": ""}]) == ([], ["5.0.0"]), \
        "an EMPTY commit is an uncut tail too, not a cut one"
    # The defect this partition exists for: a cut line and an uncut one
    # together must still probe the cut line, or the tail hides a real fault.
    cut, uncut = partition([{"version": "4.0.0", "commit": "abc"},
                            {"version": "5.0.0", "tag": "policy/v5.0.0"}])
    assert (cut, uncut) == (["4.0.0"], ["5.0.0"]), (cut, uncut)
    print("ok   selfcheck: cut/uncut partition -- a commit-less element is an uncut tail, "
          "named and not probed, and never suppresses the probe of a cut line")
    sys.exit(0)

cut, uncut = partition(rog.elements(dist / "versions.yaml"))
print("CUT: " + " ".join(cut))
print("UNCUT: " + " ".join(uncut))
PY
}

command -v python3 >/dev/null || fail "python3 required"

# Run the selfcheck from the no-argument path, BEFORE the substrate check, so a
# regression in the partition cannot hide behind a machine with no cluster.
if [ -z "${1:-}" ]; then
  say "0. selfcheck: the cut/uncut partition bites"
  bash "$0" --selfcheck || fail "the selfcheck did not bite -- the checker itself has regressed"
elif [ "${1:-}" = "--selfcheck" ]; then
  declared_state --selfcheck
  exit 0
fi

# ponytail: `infra` is off the probe ladder on purpose — only a platform-role
# party may declare it (ADR-0022) and this Namespace is not one. Add it here the
# day the probe runs under the platform's own party artefact.
TIERS="baseline restricted quarantine isolated"

require_substrate "$CLUSTER"
timeout 10 kubectl --context "$CTX" get mutatingpolicy >/dev/null 2>&1 \
  || skip "Kyverno MutatingPolicy CRD not installed on $CTX (run engine/up.sh then graded/up.sh)"

STATE="$(declared_state)"
VERSIONS="$(sed -n 's/^CUT: //p' <<<"$STATE" | tr ' ' '\n')"
UNCUT="$(sed -n 's/^UNCUT: //p' <<<"$STATE")"
if [ -n "$UNCUT" ]; then
  say "uncut tail, NOT probed: $UNCUT — declared by distribution/versions.yaml with no \`commit\`, so cut-release.yml has not cut its signed tag, Flux has nothing to deliver and no cluster can be carrying it"
fi
if [ -z "$(tr -d '[:space:]' <<<"$VERSIONS")" ]; then
  skip "every version distribution/versions.yaml declares is an uncut tail ($UNCUT) — none has a \`commit\`, so none has been released and there is nothing on any cluster to probe"
fi

# Absence is not a pass: a version whose own cage-tier policy is not on the
# cluster would admit trivially, so it is a could-not-look with its name.
UNINSTALLED=()
while IFS= read -r v; do
  [ -n "$v" ] || continue
  timeout 10 kubectl --context "$CTX" get mutatingpolicy "cage-tier-${v//./-}" >/dev/null 2>&1 \
    || UNINSTALLED+=("$v")
done <<<"$VERSIONS"
if [ ${#UNINSTALLED[@]} -gt 0 ]; then
  skip "$(printf '%s ' "${UNINSTALLED[@]}")— CUT (released, tag and commit exist) and declared by distribution/versions.yaml, but the version's own cage-tier MutatingPolicy is not installed on $CTX, so a pod admitting here would prove nothing about its cage"
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

say "one REAL pod per (CUT declared version x ladder rung), read back, on $CTX"
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
echo "PASS: every CUT version distribution/versions.yaml declares admits a real pod on every rung of the ladder on $CTX, and every pod came back wearing that rung's own cage${UNCUT:+ (not looked at, uncut and unreleasable: $UNCUT)}"
