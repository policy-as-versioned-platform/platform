#!/usr/bin/env bash
# Beat: "every policy version the platform DECLARES can actually admit a pod."
#
# The orphan guard makes distribution/versions.yaml's array the definition of
# what may run: a pod claiming a version in the array is allowed, a pod claiming
# anything else is refused. This script asks the other half of that question,
# which nothing asked before 2026-08-28: of the versions the array DOES allow,
# which ones can a workload actually be created under?
#
# Found by the review that day, live on kind-driftwood: 2.0.0, 2.0.1 and 3.0.0 —
# every released line, including the one adopters are pinned to — refuse every
# pod outright:
#   pods "..." is forbidden: the integer value of priority (0) must not be
#   provided in pod spec; priority admission controller computed -10 from the
#   given PriorityClass name
# because their cage-tier writes `spec.priorityClassName` from a mutating webhook
# without the `spec.priority` the built-in Priority admission plugin has already
# stamped. Ticket 26 fixed that (the PRIORITY PAIR note in graded/policies/
# cage-tier.yaml) but a fix only reaches a version by being RELEASED into it, and
# those three trees are frozen behind signed tags (policy/v2.0.0, policy/v2.0.1,
# policy/v3.0.0). So the repair is a patch release of each line, cut by
# cut-release.yml with gitsign — it cannot be made locally, and editing a
# released tree in place would make the cluster disagree with what Flux delivers.
#
# This script is therefore the place that red belongs. verify-graded.sh proves
# the CAGE (ticket 26, v4.0.0); this proves the DISTRIBUTION contract, and it is
# honest about which declared versions are unusable until their repair ships.
# Definition of green: every declared version admits a real pod.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / skip
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

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

NS="version-admit-probe"
cleanup() { timeout 180 kubectl --context "$CTX" delete ns "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
timeout 20 kubectl --context "$CTX" create ns "$NS" >/dev/null \
  || fail "could not create the probe namespace on $CTX"
# Governed and baseline: the loosest cage there is, so nothing below is a
# by-product of a strict rung. Every declared version must admit here.
timeout 20 kubectl --context "$CTX" label ns "$NS" \
  policy-as-versioned.dev/governed=true posture.acme.io/tier=baseline >/dev/null

say "one REAL pod per version distribution/versions.yaml declares, into a governed baseline Namespace on $CTX"
BROKEN=()
while IFS= read -r v; do
  [ -n "$v" ] || continue
  name="admit-${v//./-}"
  err="$(timeout 30 kubectl --context "$CTX" -n "$NS" run "$name" \
         --image=registry.k8s.io/pause:3.9 --restart=Never \
         --labels="policy-as-versioned.dev/policy-version=$v" 2>&1 >/dev/null || true)"
  if [ -z "$err" ]; then
    echo "  ok   $v: a pod claiming it was ADMITTED"
  else
    BROKEN+=("$v")
    echo "  FAIL $v: $(head -1 <<<"$err")"
  fi
done <<<"$VERSIONS"

if [ ${#BROKEN[@]} -gt 0 ]; then
  fail "$(printf '%s ' "${BROKEN[@]}")— declared by distribution/versions.yaml and allowed by the orphan guard, but no pod can be created under them. An adopter pinned to one cannot deploy at all. The repair is a patch release of each line (cut-release.yml, gitsign) or a retirement of the array element plus an adopter recompose; a released tree cannot be edited in place."
fi
echo "PASS: every version distribution/versions.yaml declares admits a real pod on $CTX"
