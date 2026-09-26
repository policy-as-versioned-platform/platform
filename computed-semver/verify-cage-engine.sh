#!/usr/bin/env bash
# verify-cage-engine.sh -- ticket cs-21. The classification engine's own
# selfcheck: Track 1 (ValidatingPolicy admission, reusing
# rederive_bumps.classify_policy directly) needs the real kyverno CLI --
# SKIPs (exit 3, could not look) if it is absent, same convention as
# verify-rederive-bumps.sh, verify-gate.sh and verify-corpus-generator.sh.
# Track 2 (the cage-spec permissiveness lattice) is pure python and runs
# either way, inside the same --selfcheck call.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# Ticket 76 (every green rests on an observation): the kyverno-absent branch below used to
# print SKIP and exit 0, which talk/verify-all.sh grades PASS -- a green on the absence of the
# instrument. A could-not-look is exit 3 (lib.sh's `skip`). And because that branch only runs on
# a machine without the CLI, it was never itself tested: `selfcheck_absent` re-runs this script
# with kyverno unreachable and requires exit 3 with a SKIP: last line, so every run observes the
# branch. `--selfcheck` runs that leg alone.
. ../lib.sh
SELF="$PWD/${BASH_SOURCE##*/}"
if [ "${1:-}" = "--selfcheck" ]; then selfcheck_absent "$SELF" kyverno; exit 0; fi

if ! command -v kyverno >/dev/null; then
  skip "kyverno CLI not found -- cage_engine's Track 1 (ValidatingPolicy admission) needs it"
fi
selfcheck_absent "$SELF" kyverno

python3 cage_engine.py --selfcheck
# Ticket 71: grade the actual published policy trees under the declared CLI.
# Kept in this registered check: no second discovery/manifest entry is needed.
python3 -m unittest discover -s . -p test_engine_compatibility.py
# Ticket 146: one grader run grades every cell, one binary per engine. The hub's truth.yml
# installs every row of engine/kyverno/engine-table.yaml by checksum into
# KYVERNO_ENGINE_DIR/<version>/kyverno and names that directory here. With no such directory
# (a local run) the grader is handed the kyverno on PATH alone, and every listed cell it cannot
# fill reads could-not-look by name. The grader identifies each binary by running it.
if [ -n "${KYVERNO_ENGINE_DIR:-}" ]; then
  [ -d "$KYVERNO_ENGINE_DIR" ] || { echo "FAIL: KYVERNO_ENGINE_DIR=$KYVERNO_ENGINE_DIR is not a directory"; exit 1; }
  python3 engine_compatibility.py --engine-dir "$KYVERNO_ENGINE_DIR"
else
  python3 engine_compatibility.py --engine "$(command -v kyverno)"
fi
