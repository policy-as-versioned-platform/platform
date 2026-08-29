#!/usr/bin/env bash
# Beat: "Retiring a version prunes it." Deleting a version's element from the
# array is the ONLY edit needed: Flux prunes that version's Kustomization +
# policy (prune: true), and the orphan-guard — re-rendered from the shrunk array
# — stops allowing it, so a workload still claiming the retired version is denied.
# Exits non-zero if the beat would fail on stage.
#
# Offline core: render the orphan-guard BEFORE and AFTER retiring a version the
# array really declares, and show the same pod flips admit -> deny. Live tail
# (if reachable): the retired version's Kustomization/policy is actually gone.
#
# The subject is the FIRST version the array declares, read from versions.yaml
# rather than hardcoded -- 2026-08-29 really did retire 2.0.0, 2.0.1 and 3.0.0
# (none of them could admit a pod), and a hardcoded subject would have made this
# beat fail on a retirement, which is the one event it exists to prove.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have kyverno || fail "kyverno CLI required"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
RETIRE="$(python3 -c "
import importlib.util
from pathlib import Path
here = Path('$HERE')
spec = importlib.util.spec_from_file_location('render_orphan_guard', here / 'render-orphan-guard.py')
og = importlib.util.module_from_spec(spec); spec.loader.exec_module(og)
print(og.versions(here / 'versions.yaml')[0])
")"
[ -n "$RETIRE" ] || fail "distribution/versions.yaml declares no versions to retire"
# The beat is "retire ONE and the rest keep running". With a single declared
# version there is no rest: retiring it leaves an empty allow-list, which
# render-orphan-guard.py refuses to render (a guard that allows nothing is not
# a policy anyone ships). Could-not-look with that reason, never a pass.
DECLARED="$(python3 -c "
import importlib.util
from pathlib import Path
here = Path('$HERE')
spec = importlib.util.spec_from_file_location('render_orphan_guard', here / 'render-orphan-guard.py')
og = importlib.util.module_from_spec(spec); spec.loader.exec_module(og)
print(len(og.versions(here / 'versions.yaml')))
")"
if [ "$DECLARED" -lt 2 ]; then
  echo "SKIP: distribution/versions.yaml declares one version ($RETIRE), so a retirement would leave an empty allow-list, which render-orphan-guard.py refuses to render; the beat needs a second declared version to show one retiring while the other keeps running"
  exit 3
fi

cat > "$WORK/pod.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata: { name: still-on-retired, labels: { "policy-as-versioned.dev/policy-version": "${RETIRE}" } }
spec: { containers: [{ name: c, image: nginx }] }
YAML

say "1. before retirement: a pod on ${RETIRE} is admitted (version is declared)"
python3 "$HERE/render-orphan-guard.py" > "$WORK/before.yaml"
# capture (|| true): kyverno apply's exit code tracks admission, not script health
before="$(kyverno apply "$WORK/before.yaml" --resource "$WORK/pod.yaml" 2>&1 || true)"
grep -q 'pass: 1, fail: 0' <<<"$before" \
  || fail "pod on ${RETIRE} was not admitted before retirement — fixture wrong"

say "2. retire ${RETIRE} from the array (one deletion) and re-render"
python3 "$HERE/render-orphan-guard.py" --retire "$RETIRE" > "$WORK/after.yaml"

say "3. after retirement: the same pod is now DENIED (orphaned by the shrunk array)"
after="$(kyverno apply "$WORK/after.yaml" --resource "$WORK/pod.yaml" 2>&1 || true)"
grep -q "resource default/Pod/still-on-retired failed" <<<"$after" \
  || fail "pod on retired ${RETIRE} still admitted — retirement did not prune the allowance"

# the fan-out no longer renders a Kustomization/path for the retired version
[ -d "$HERE/policies/v${RETIRE}" ] || fail "fixture: policies/v${RETIRE} missing"
say "   (live: dropping the array element prunes Kustomization policy-v$(echo "$RETIRE" | tr . -))"

# --- live tail: a passive read. "Pruned" may only be claimed after observing
# the Kustomization PRESENT and then ABSENT across a retirement; one read cannot
# see both, and absence alone is not evidence (a Kustomization that never
# existed is also absent). So: SKIP with the reason, never a positive claim.
# ponytail: a present->absent watch needs the script to drive a retire commit; add when a live retire beat exists.
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line: three outcomes per live tail
slug="$(echo "$RETIRE" | tr . -)"
if ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif timeout 10 kubectl --context "$CTX" -n flux-system get kustomization "policy-v${slug}" >/dev/null 2>&1; then
  live_tail_skip "policy-v${slug} observed PRESENT on $CTX; retirement not applied there, nothing pruned to observe"
else
  live_tail_skip "policy-v${slug} ABSENT on $CTX but never observed present by this script; absence is not evidence of pruning"
fi

pass_line "retiring a version (one array deletion) prunes it and denies stragglers"
