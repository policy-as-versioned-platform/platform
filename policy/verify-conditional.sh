#!/usr/bin/env bash
# Beat: "Exemptions dissolve into conditional policy." One versioned CEL rule —
# "run non-root, OR run root IF attested AND hardened" — admits ANYONE meeting C,
# uniformly, with no named team and no carve-out. And the root-but-hardened branch
# still carries residual risk, which fair.py prices in £ (the residual feeds the £).
#
# Offline core (always on, kyverno only): the pass/fail matrix + the residual £.
# Live tail (only if a cluster is reachable): the same admit/deny live.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/.." && pwd)"    # estate/platform — fair.py is a sibling area
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have kyverno || fail "kyverno CLI required"
# cs-16: policy/policies/v1.0.0/ is deleted -- this rule folded into
# distribution/policies/v2.0.1/require-nonroot.yaml as a patch widening on
# the 2.0.0 line. Lineage follows content, not the old directory-name
# coincidence.
POL="$PLATFORM/distribution/policies/v2.0.1/require-nonroot.yaml"

say "1. the conditional matrix: C admits uniformly, non-C fails, unversioned skips"
out="$(kyverno apply "$POL" --resource "$HERE/tests/conditional/resources.yaml" 2>&1 || true)"
grep -q 'pass: 2, fail: 2' <<<"$out" \
  || { echo "$out"; fail "expected 2 pass (nonroot + root-attested-hardened) / 2 fail"; }
grep -q 'Pod/root-attested-hardened' <<<"$out" \
  && fail "root-attested-hardened was denied — the conditional branch did not admit"
grep -q 'Pod/root-bare failed' <<<"$out" \
  || fail "root-bare was not denied — condition C is not being enforced"
say "   root-attested-hardened ADMITS (met C); root-bare + attested-unhardened FAIL"

say "2. kyverno test — the full pass/fail/skip matrix"
timeout 120 kyverno test "$HERE/tests/conditional" >/dev/null 2>&1 \
  || fail "kyverno test tests/conditional did not pass"

say "3. the residual of the conditional branch is priced in £ (fair.py)"
have python3 || fail "python3 required for the £"
warn_ale="$(python3 "$PLATFORM/fair/fair.py" summary "$HERE/scenarios/driftwood-root-residual.json" --mode warn \
  | python3 -c 'import json,sys; print(round(json.load(sys.stdin)["ale"]))')"
[ "$warn_ale" -gt 0 ] || fail "residual ALE is not positive — nothing to carry"
say "   residual ALE with condition C unmet = £${warn_ale}/yr (the £ a cage prices and retains)"

# --- live tail: substrate first, then the 2.0.1 policy must be installed, then each verdict ---
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line: three outcomes per live tail
if ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif ! timeout 10 kubectl --context "$CTX" get validatingpolicy require-nonroot-2-0-1 >/dev/null 2>&1; then
  live_tail_skip "require-nonroot-2-0-1 ValidatingPolicy not installed on $CTX (fan-out not reconciled there)"
else
  say "4. live: each pod against '$CTX' (server dry-run) — admit/deny must match the offline matrix"
  # one dry-run per pod so each verdict is observed on its own, not inferred from a batch
  for want in nonroot=admit root-attested-hardened=admit root-bare=deny root-attested-unhardened=deny; do
    pod="${want%=*}"; verdict="${want#*=}"
    if python3 -c 'import sys,yaml; [print("---"),print(yaml.safe_dump(d)) for d in yaml.safe_load_all(open(sys.argv[1])) if d and d["metadata"]["name"]==sys.argv[2]]' \
         "$HERE/tests/conditional/resources.yaml" "$pod" \
       | timeout 30 kubectl --context "$CTX" apply --dry-run=server -f - >/dev/null 2>&1; then got=admit; else got=deny; fi
    [ "$got" = "$verdict" ] && say "   $pod: $got (as offline)" || fail "live: $pod was ${got}, offline matrix says $verdict"
  done
fi

pass_line "one conditional rule admits everyone meeting C, and its residual is priced"
