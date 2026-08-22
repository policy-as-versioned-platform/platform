#!/usr/bin/env bash
# verify-cage-engine.sh -- ticket cs-21. The classification engine's own
# selfcheck: Track 1 (ValidatingPolicy admission, reusing
# rederive_bumps.classify_policy directly) needs the real kyverno CLI --
# SKIPs (exit 0) if it is absent, same convention as
# verify-rederive-bumps.sh, verify-gate.sh and verify-corpus-generator.sh.
# Track 2 (the cage-spec permissiveness lattice) is pure python and runs
# either way, inside the same --selfcheck call.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v kyverno >/dev/null; then
  echo "SKIP: kyverno CLI not found -- cage_engine's Track 1 (ValidatingPolicy admission) needs it"
  exit 0
fi

python3 cage_engine.py --selfcheck
