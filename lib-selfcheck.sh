#!/usr/bin/env bash
# Runnable checks for lib.sh: a missing cluster must SKIP with exit 3, and a
# skipped live tail must make pass_line SKIP with exit 3 (never PASS / exit 0).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$(bash -c "source '$HERE/lib.sh'; require_substrate no-such-cluster-$$; echo NOT-REACHED")"; rc=$?
[ "$rc" = 3 ] && grep -q '^SKIP: ' <<<"$out" && ! grep -q NOT-REACHED <<<"$out" \
  || { echo "FAIL: require_substrate rc=$rc out=$out"; exit 1; }
out="$(bash -c "source '$HERE/lib.sh'; live_tail_skip 'no look'; pass_line 'claim'" | tail -1)"; rc=${PIPESTATUS[0]}
[ "$rc" = 3 ] && [ "$out" = "SKIP: offline proof holds; live tail could not look: no look — claim" ] \
  || { echo "FAIL: pass_line after skip rc=$rc out=$out"; exit 1; }
out="$(bash -c "source '$HERE/lib.sh'; pass_line 'claim'")"; rc=$?
[ "$rc" = 0 ] && [ "$out" = "PASS: claim" ] || { echo "FAIL: pass_line observed rc=$rc out=$out"; exit 1; }
echo "PASS: lib.sh skips with exit 3 on a missing cluster and on a skipped live tail; exit 0 only when every tail was observed"
