#!/usr/bin/env bash
# Beat: "how do I know the number is honest today rather than the day it was written?"
# The honesty layer, end to end, offline:
#   1. CALIBRATION  — real incidents/near-misses back-test the £ and Bühlmann-recalibrate it.
#   2. FEED-INTEGRITY — feeds are signed (openssl verify + tamper-rejection), sourced, bounded.
#   3. PROPOSER-BOUNDS — the AI proposer is confidence/rate-limited + learns from rejections,
#                        with the PR gate as the HARD backstop (no merge() by construction).
#   4. REFLEXIVE    — the apparatus prices + governs ITSELF under the same engine, and passes.
# No cluster, no network. Needs python3 + openssl (both stdlib-adjacent, always present here).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
platform="$here/.."
fail() { echo "FAIL: $*" >&2; exit 1; }
say() { echo; echo "== $* =="; }

command -v python3 >/dev/null || fail "python3 not found"
command -v openssl >/dev/null || fail "openssl not found"

say "1. calibration — back-test the £ against real incidents, Bühlmann-recalibrate"
python3 "$here/calibration.py" selfcheck || fail "calibration selfcheck failed"
python3 "$here/calibration.py" backtest >/dev/null || fail "backtest did not run"

say "2. feed-integrity — signed (real openssl verify) + sourced + bounded"
# Reuse the feeds org's own verifier for a real signature check on a live feed.
"$platform/feeds/verify.sh" threat-register v1 register.json >/dev/null \
  || fail "threat-register v1 signature did not verify"
# Tamper-rejection: a forged feed must NOT verify (integrity is load-bearing).
key="$platform/feeds/keys/feeds-signing-key.pub.pem"
src="$platform/feeds/threat-register/v1/register.json"
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
python3 - "$src" "$tmp" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for inst in d.get("institutions", {}).values():
    inst["lef"] = [99, 99, 99]   # forge the risk
json.dump(d, open(sys.argv[2], "w"))
PY
if openssl pkeyutl -verify -pubin -inkey "$key" -rawin -in "$tmp" \
     -sigfile "$src.sig" >/dev/null 2>&1; then
  fail "a tampered feed still verified — feed-integrity is broken"
fi
echo "ok  live feed signature verifies; a forged feed is rejected"
# sourced + bounded are asserted inside reflexive.feed_integrity (step 4).

say "3. proposer-bounds — confidence + rate-limit + a DERIVED rejection ledger; gate is the backstop"
python3 "$here/proposer_bounds.py" selfcheck || fail "proposer-bounds selfcheck failed"
python3 "$platform/wargamer/rejection_ledger.py" selfcheck || fail "rejection-ledger selfcheck failed"
# ADR-0024: the ledger is derived from closed-unmerged proposal PRs, never a
# committed fixture. Offline it comes back EMPTY with the reason on stderr --
# which is exactly the behaviour this step is here to observe.
ledger="$(mktemp)"; trap 'rm -f "$tmp" "$ledger"' EXIT
python3 "$platform/wargamer/rejection_ledger.py" derive > "$ledger" \
  || fail "rejection-ledger derive did not run"
echo "-- live dispositions (against the derived ledger above) --"
python3 "$here/proposer_bounds.py" dispositions --rejections "$ledger"

say "4. reflexive — the apparatus governs itself under the same engine, and passes"
python3 "$here/reflexive.py" selfcheck || fail "reflexive selfcheck failed"

echo
echo "ALL OK — the £ is falsifiable (back-tested + recalibrated), the feeds are"
echo "signed/sourced/bounded, the AI proposer is bounded with the gate as the hard"
echo "backstop, and the apparatus passes its own test."
