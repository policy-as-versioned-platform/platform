#!/usr/bin/env bash
# One runnable check for lib.sh: a cluster name that does not exist must SKIP with exit 3.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$(bash -c "source '$HERE/lib.sh'; require_substrate no-such-cluster-$$; echo NOT-REACHED")"; rc=$?
[ "$rc" = 3 ] && grep -q '^SKIP: ' <<<"$out" && ! grep -q NOT-REACHED <<<"$out" \
  && echo "PASS: lib.sh require_substrate skips with exit 3 on a missing cluster ($out)" \
  || { echo "FAIL: rc=$rc out=$out"; exit 1; }
