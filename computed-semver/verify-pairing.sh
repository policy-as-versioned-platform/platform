#!/usr/bin/env bash
# verify-pairing.sh -- ticket cs-22. pairing.py's own selfcheck: pure
# python (dial_table/YAML parsing, no kyverno CLI needed for any of it --
# the one real-content proof it runs, a tightened graded/policies/cage-tier.yaml
# baseline classifying major, goes through cage_engine.py's Track 2, which is
# pure python too).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

python3 pairing.py --selfcheck
