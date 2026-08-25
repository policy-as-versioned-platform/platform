#!/usr/bin/env bash
# Beat: every OSCAL control claim resolves — the claimed policy name against
# the shipped version trees, the claimed control id against the pinned
# `nist` catalogue. ADR-0013 / ADR-0017 (policy-composition ticket 10).
#
# EXPECTED-RED today: `cm-6` claims `require-policy-version` and `ac-6`
# claims `may-run-root-if-attested`, and neither policy is shipped. That is
# a platform defect a DIFFERENT ticket fixes — this beat exists to give it a
# red check instead of silence, and it is deliberately not silenced or
# skipped to get to green. It goes green on its own once that defect lands.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || fail "python3 required"

say "1. lint_claims.py's own asserts (the lint itself resolves correctly)"
python3 "$HERE/lint_claims.py" --selfcheck || fail "lint_claims.py --selfcheck"

say "2. the real check against component-definition.json"
python3 "$HERE/lint_claims.py"
rc=$?

if [ "$rc" -eq 0 ]; then
  say "PASS: every control claim resolves"
else
  say "this beat is EXPECTED-RED: known dangling claim(s) named above are a platform defect"
  say "tracked outside this ticket (.scratch/policy-composition/issues/10-platform-control-claims-use-bare-ids.md) — not silenced, not skipped"
fi
exit "$rc"
