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

# selfcheck_absent (ecosystem ticket 76): planted scripts grade as planted. The false green --
# a SKIP printed and then exit 0 -- is the shape seven computed-semver scripts carried; this is
# the leg that turns red if selfcheck_absent stops catching it.
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
for t in pav-fake-tool pav-fake-neighbour; do
  printf '#!/bin/sh\nexit 0\n' >"$work/bin/$t"; chmod +x "$work/bin/$t"
done
# both scripts need the NEIGHBOUR, so a farm that hid the whole directory would fail them for
# the wrong reason; only pav-fake-tool is the instrument being taken away.
for shape in honest false-green; do
  { echo '#!/usr/bin/env bash'
    echo 'command -v pav-fake-neighbour >/dev/null || { echo "FAIL: the neighbour was hidden too"; exit 1; }'
    printf 'command -v pav-fake-tool >/dev/null || { echo "SKIP: pav-fake-tool absent"; exit %s; }\n' \
      "$([ "$shape" = honest ] && echo 3 || echo 0)"
    echo 'echo "PASS: the tool was there and was used"'
  } >"$work/$shape.sh"
  chmod +x "$work/$shape.sh"
done

out="$(PATH="$work/bin:$PATH" bash -c "source '$HERE/lib.sh'; selfcheck_absent '$work/honest.sh' pav-fake-tool")"; rc=$?
[ "$rc" = 0 ] && grep -q '^  ok   selfcheck: with pav-fake-tool unreachable' <<<"$out" \
  || { echo "FAIL: selfcheck_absent rejected an honest exit-3 branch rc=$rc out=$out"; exit 1; }

out="$(PATH="$work/bin:$PATH" bash -c "source '$HERE/lib.sh'; selfcheck_absent '$work/false-green.sh' pav-fake-tool; echo NOT-REACHED")"; rc=$?
[ "$rc" = 1 ] && grep -q '^FAIL: selfcheck: with pav-fake-tool unreachable false-green.sh exited 0' <<<"$out" \
  && ! grep -q NOT-REACHED <<<"$out" \
  || { echo "FAIL: selfcheck_absent let a SKIP-then-exit-0 branch through rc=$rc out=$out"; exit 1; }

echo "PASS: lib.sh skips with exit 3 on a missing cluster and on a skipped live tail; exit 0 only when every tail was observed; and selfcheck_absent runs a script's could-not-look branch, passing an exit 3 and refusing a SKIP-then-exit-0"
