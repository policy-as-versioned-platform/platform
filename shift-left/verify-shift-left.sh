#!/usr/bin/env bash
# verify-shift-left.sh -- the offline proof behind the "CI catches an
# Audit->Deny flip pre-merge" beat (ticket 12). Runs the REAL kyverno CLI,
# needs no cluster. Exits non-zero if the beat would fail on stage.
#
# 2026-08-29: the whole 2.x/3.x fan-out was retired from
# distribution/versions.yaml, so the declared array holds ONE major line. The
# flip beat is about a NEIGHBOUR's tightened rule; with one line there is no
# neighbour, so that beat is graded could-not-look with its reason rather than
# passed on a technicality (it would "pass" today only because ci-check.py
# refuses the retired target the fixture used to claim, which is the right
# answer to the wrong question).
#
# 2026-09-24: 4.0.0 retired too (owner-instructed), after 5.0.0 had made the
# array two majors for a while. One major line again, and the fixtures claim
# 5.0.0. .github/workflows/release.yml runs this script as its release gate,
# so a could-not-look here failed every release. The flip beat now reads the
# served array first. With two or more majors it runs there. With one it says
# NOTHING-TO-FLIP for the served array, by name, and runs against the planted
# two-line window fixtures/flip-window.yaml. That window reuses the real
# signed 4.0.0 and 5.0.0 bodies still on disk, so the beat still proves what
# it proves: the +/-1 window catches, with the real kyverno CLI, a workload
# that passes its own target and fails a neighbour's rule. The beat also now
# insists the failure IS a flip. A workload that fails its own target is a
# failure, not a caught flip, and the beat says so instead of passing on it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v kyverno >/dev/null; then
  echo "SKIP: kyverno CLI not found -- shift-left check needs it (offline, no cluster)"
  exit 3
fi

echo "== a compliant change passes across its ±1 supported window =="
python3 ci-check.py --resource fixtures/workload-compliant.yaml

echo
echo "== an unversioned workload is out of scope, passes trivially =="
python3 ci-check.py --resource fixtures/workload-unversioned.yaml

echo
echo "== a version the array doesn't declare is refused, not silently skipped =="
if python3 ci-check.py --resource fixtures/workload-compliant.yaml --target 9.9.9 2>/tmp/shift-left-orphan.err; then
  echo "FAIL: ci-check.py did not reject an orphan target version" >&2
  exit 1
fi
grep -q "not in the platform-declared array" /tmp/shift-left-orphan.err

# The flip beat needs two major lines in a window: the target's own, and a
# neighbour whose rule the workload fails. flip_window.py reads the served array
# first and falls back to the planted window only when it declares one major,
# printing NOTHING-TO-FLIP by name when it does.
echo
echo "== an Audit->Deny flip is caught pre-merge (must fail CI) =="
FLIP_VERSIONS="$(python3 flip_window.py)"
echo "window read from: ${FLIP_VERSIONS#"$(cd .. && pwd)/"}"
FLIP_OUT="$(mktemp)"
if python3 ci-check.py --resource fixtures/workload-flip.yaml --versions-file "$FLIP_VERSIONS" >"$FLIP_OUT" 2>&1; then
  cat "$FLIP_OUT"
  echo "FAIL: ci-check.py passed a workload that fails a neighbour's real rule in its window" >&2
  exit 1
fi
cat "$FLIP_OUT"
# Non-zero is not enough. It must be a FLIP: the target passes, a neighbour fails.
FLIP_TARGET="$(sed -n 's/^.*: targets \([0-9][0-9.]*\), checking supported window .*$/\1/p' "$FLIP_OUT")"
if [ -z "$FLIP_TARGET" ]; then
  echo "FAIL: ci-check.py stopped before it checked a window, so no flip was caught" >&2
  exit 1
fi
if grep -qx "FAIL @ v${FLIP_TARGET}" "$FLIP_OUT"; then
  echo "FAIL: fixtures/workload-flip.yaml fails its own target ${FLIP_TARGET}; that is a plain failure, not a caught flip" >&2
  exit 1
fi
if ! grep -q '^FAIL @ v[0-9.]* (Audit->Deny flip' "$FLIP_OUT"; then
  echo "FAIL: ci-check.py failed the flip fixture, but at no neighbour of ${FLIP_TARGET}" >&2
  exit 1
fi
echo "(non-zero above is expected -- the flip was caught at a neighbour of ${FLIP_TARGET})"

echo
echo "shift-left: all offline proofs passed"
