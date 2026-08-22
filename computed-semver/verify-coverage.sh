#!/usr/bin/env bash
# verify-coverage.sh -- ticket cs-23. Pure python throughout (classify_state
# is a text-regex reader, never a CEL engine; no kyverno CLI needed for any
# of this), so no SKIP convention is needed here, unlike the tickets that
# shell out to `kyverno apply`.
#
# 1. coverage.py's own --selfcheck: cells/pairs/pairwise-gap have no ratio
#    anywhere, the real committed generated-corpus/ has zero unreached cells
#    for the live subject, static_proof/declared-holes/proved-exclusions and
#    the new/carried_over/closed baseline diff all round-trip correctly, and
#    an attempted "proved: true" promotion through the exclusion file is
#    refused.
# 2. gate.py's own --selfcheck, since this ticket wires coverage's two new
#    binary gates (unreached predicate, missing witness shape) directly into
#    run_gate -- the seam itself, not just coverage.py in isolation.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "== 1. coverage.py --selfcheck =="
python3 coverage.py --selfcheck

echo
echo "== 2. gate.py --selfcheck (coverage's two gates wired through the seam) =="
python3 gate.py --selfcheck

echo
echo "PASS: coverage selfcheck ok, wired correctly through the gate seam"
