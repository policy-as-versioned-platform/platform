#!/usr/bin/env bash
# verify-tier-binding.sh -- the enacted tier is bound to the priced tier
# (ticket 78; ADR-0022). tier_binding.py reads `proposed_tier` off every
# prices[] line in an adopter's composed/evidence.json and `posture.acme.io/tier`
# off the adopter's governed Namespace manifest, and refuses a declaration
# looser than the strictest priced line (clamped to the party's own floor).
# Each adopter's shift-left.yml runs it on every pull request through the
# pinned platform dependency, the same shape ci-check.py rides.
#
# This wrapper is platform's own proof that the check BITES: the selfcheck
# plants a loose declaration, a tight one, a missing one, a floor, an
# off-ladder tier and a premium-only evidence document, and requires each
# verdict. Platform never reads an adopter's repository (NORTH-STAR §2); the
# hub's verify/tier-binding/ runs the same module over the real adopters.
# Offline, stdlib only. Exit 0 true; 1 false.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -f "$here/tier_binding.py" ] || fail "$here/tier_binding.py is missing -- no binding check to run"

echo "== the binding check's planted cases each grade as they must =="
python3 "$here/tier_binding.py" selfcheck || fail "tier_binding.py selfcheck -- a planted loose declaration was not refused, or a bound one was"

echo
echo "PASS: the tier binding check refuses a governed Namespace declared looser than its strictest priced tier (or its floor), accepts one at least as tight, treats no declaration as isolated, and refuses an off-ladder tier"
