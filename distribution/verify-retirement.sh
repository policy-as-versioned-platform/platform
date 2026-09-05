#!/usr/bin/env bash
# Beat: "Retiring a version prunes it, and moves a straggler out of every served
# policy version onto the bottom rung." Deleting a version's element from the
# array is the ONLY edit needed: Flux prunes that version's Kustomization +
# policy (prune: true), the orphan-guard — re-rendered from the shrunk array —
# starts REPORTING a workload still claiming it, and the orphan CAGE — ranged
# from the same array — starts putting that workload on the bottom rung.
# Exits non-zero if the beat would fail on stage.
#
# ECO-SYSTEM TICKET 89 (2026-09-05) rewrote the subject. This beat used to say
# "the same pod is now DENIED" and made the denial its pass condition. Nothing in
# this estate is deliberately denied (the owner, 2026-09-02, ticket 75 Q5), so a
# straggler is now reported and caged instead — and the beat has to say which,
# because the pinned kyverno CLI reports a rule failure identically for Audit and
# for Deny, so the old wording would have gone on reading green over a policy
# that no longer refuses anything. That is why this file changed with the guard
# and not after it.
#
# Offline core: render BOTH halves BEFORE and AFTER retiring a version the array
# really declares, and show the same pod flip from ungoverned-by-this-machinery
# to reported-and-caged-on-the-bottom-rung. Live tail (if reachable): the retired
# version's Kustomization/policy is actually gone.
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
print(og.served_versions(here / 'versions.yaml')[0])
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
print(len(og.served_versions(here / 'versions.yaml')))
")"
ALL_DECLARED="$(python3 -c "
import importlib.util
from pathlib import Path
here = Path('$HERE')
spec = importlib.util.spec_from_file_location('render_orphan_guard', here / 'render-orphan-guard.py')
og = importlib.util.module_from_spec(spec); spec.loader.exec_module(og)
print(len(og.versions(here / 'versions.yaml')))
")"
if [ "$DECLARED" -lt 2 ]; then
  echo "SKIP: distribution/versions.yaml declares $ALL_DECLARED version(s) of which one CUT version ($RETIRE) -- an uncut element has no tag and no served cage, so the orphan pair allow-lists CUT elements only (ticket 89 R3) and retiring the only cut one would leave an empty allow-list, which render-orphan-guard.py refuses to render. It lifts when cut-release.yml cuts a SECOND tag, not when a second version is declared"
  exit 3
fi

cat > "$WORK/pod.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata: { name: still-on-retired, labels: { "policy-as-versioned.dev/policy-version": "${RETIRE}" } }
spec: { containers: [{ name: c, image: nginx }] }
YAML

say "1. before retirement: a pod on ${RETIRE} is unremarkable to the machinery (version is declared)"
python3 "$HERE/render-orphan-guard.py" > "$WORK/before.yaml"
python3 "$HERE/render-orphan-guard.py" --cage > "$WORK/before-cage.yaml"
# capture (|| true): kyverno apply's exit code tracks rule outcome, not script health
before="$(kyverno apply "$WORK/before.yaml" --resource "$WORK/pod.yaml" 2>&1 || true)"
grep -q 'pass: 1, fail: 0' <<<"$before" \
  || fail "pod on ${RETIRE} was reported before retirement — fixture wrong"
kyverno apply "$WORK/before-cage.yaml" --resource "$WORK/pod.yaml" -o "$WORK/before-out" \
  >/dev/null 2>&1 || fail "the orphan cage refused a pod"
if [ -f "$WORK/before-out/still-on-retired-mutated.yaml" ] \
   && grep -q 'posture.acme.io/tier' "$WORK/before-out/still-on-retired-mutated.yaml"; then
  fail "the orphan cage caged a pod claiming a DECLARED version — the cage is not disjoint"
fi

say "2. retire ${RETIRE} from the array (one deletion) and re-render BOTH halves"
python3 "$HERE/render-orphan-guard.py" --retire "$RETIRE" > "$WORK/after.yaml"
python3 "$HERE/render-orphan-guard.py" --cage --retire "$RETIRE" > "$WORK/after-cage.yaml"

say "3. after retirement: the same pod is REPORTED (no served version governs it)"
after="$(kyverno apply "$WORK/after.yaml" --resource "$WORK/pod.yaml" 2>&1 || true)"
grep -q "resource default/Pod/still-on-retired failed" <<<"$after" \
  || fail "pod on retired ${RETIRE} not reported — retirement did not shrink the allow-list"
grep -q "Nothing is denied" <<<"$after" \
  || fail "the straggler's report claims a refusal; nothing is deliberately denied"

say "4. ...and CAGED on the bottom rung by the same shrunk array"
kyverno apply "$WORK/after-cage.yaml" --resource "$WORK/pod.yaml" -o "$WORK/after-out" \
  >"$WORK/after-cage.log" 2>&1 \
  || fail "the orphan cage refused the straggler: $(tail -3 "$WORK/after-cage.log")"
grep -qE 'fail: 0, ' "$WORK/after-cage.log" \
  || fail "a refusal appeared when the straggler was caged: $(tail -1 "$WORK/after-cage.log")"
straggler="$WORK/after-out/still-on-retired-mutated.yaml"
[ -f "$straggler" ] || fail "retirement left the straggler uncaged — no mutated pod at $straggler"
for want in 'posture.acme.io/tier: isolated' 'posture.acme.io/caged: "true"' \
            'priorityClassName: cage-isolated'; do
  grep -q -- "$want" "$straggler" || fail "the retired straggler is missing: $want"
done
echo "  ok   retiring ${RETIRE} moved the straggler onto the bottom rung, running and unreachable"

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

pass_line "retiring a version (one array deletion) prunes it and moves a straggler out of every served policy version: reported by name, caged on the bottom rung by the same shrunk array, and refused by nothing"
