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

# The flip beat needs two major lines in the DECLARED array: the target's own,
# and a neighbour whose tightened rule the workload fails.
MAJORS="$(python3 - <<'PY'
import importlib.util
from pathlib import Path
dist = Path("../distribution")
spec = importlib.util.spec_from_file_location("rog", dist / "render-orphan-guard.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
declared = mod.versions(dist / "versions.yaml")
print(len({v.split(".")[0] for v in declared}), " ".join(declared))
PY
)"
COUNT="${MAJORS%% *}"; DECLARED="${MAJORS#* }"
echo
if [ "$COUNT" -lt 2 ]; then
  echo "== an Audit->Deny flip is caught pre-merge =="
  echo "SKIP: distribution/versions.yaml declares one major line ($DECLARED), so a target has no ±1 neighbour and there is no tightened rule for the window to catch a workload against; the flip beat has nothing to observe until a second major is declared again"
  exit 3
fi

echo "== an Audit->Deny flip is caught pre-merge (must fail CI) =="
if python3 ci-check.py --resource fixtures/workload-flip.yaml; then
  echo "FAIL: ci-check.py passed a workload that fails its target version's real rule" >&2
  exit 1
fi
echo "(non-zero above is expected -- the flip was caught)"

echo
echo "shift-left: all offline proofs passed"
