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

# --- live tail: substrate first, then find which currently-declared version (if
# any) actually carries this beat's conditional root-attested branch, instead of
# hardcoding a version that may since have retired. 2.0.1 is a PATCH backport on
# the 2.0.0 line (cs-16); 3.0.0 and 4.0.0 are separate minor/major lines that
# never inherited it -- both just tighten to a flat non-root+read-only-fs rule,
# no root-if-attested branch (checked: no "root-attestation" anywhere under
# distribution/policies/v3.0.0 or v4.0.0). So redirecting this live tail to
# 4.0.0 while keeping the same admit verdicts would assert root-attested-hardened
# ADMITS on 4.0.0, which is false -- 4.0.0 has no such branch and would deny it
# for missing runAsNonRoot. That would be the exact false-pass this project
# forbids, not an honest look, so this check looks for whichever CURRENTLY
# DECLARED version actually carries the branch, computed from versions.yaml the
# same way render-orphan-guard.py does, never a hardcoded literal.
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line: three outcomes per live tail
DIST="$PLATFORM/distribution"
conditional_version="$(python3 -c '
import sys, importlib.util
from pathlib import Path
dist = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("g", dist / "render-orphan-guard.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
for v in m.versions(dist / "versions.yaml"):
    body = (dist / "policies" / f"v{v}" / "require-nonroot.yaml").read_text()
    if "root-attestation" in body:
        print(v)
        break
' "$DIST")"
if [ -z "$conditional_version" ]; then
  live_tail_skip "the root-attested conditional branch this beat proves lives only in require-nonroot-2-0-1, and 2.0.1 is retired (not in distribution/versions.yaml, 2026-08-29); the only currently-declared version (4.0.0) replaced it with a flat non-root+read-only-fs rule that has no root-if-attested branch, so no currently-declared version's live install can observe this claim"
elif ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif [ "$conditional_version" != "2.0.1" ]; then
  live_tail_skip "distribution/versions.yaml now declares a version ($conditional_version) whose require-nonroot carries the conditional branch, but this script's live fixtures (tests/conditional/resources.yaml) still claim policy-version 2.0.1 -- relabel the fixtures to $conditional_version before trusting this tail"
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
