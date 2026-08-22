#!/usr/bin/env bash
# verify-generator-standing-check.sh -- ticket cs-25. The generator's one
# standing check, not a per-function test suite (spec.md, "Testing
# Decisions"): the three known-good bumps must still rederive (refuses,
# non-zero exit, if any stops), the committed generated-corpus/manifest.yaml
# must still match the live generator version, and the most recent evidence
# record on disk (none yet -- see generator_standing_check.py's own
# docstring) is re-run under the current generator, printing rather than
# failing on a differing classification.
#
# Needs the real kyverno CLI (offline, no cluster) -- the known-good bumps
# and the real old/new subject pair in --selfcheck both call it. SKIPs
# (exit 0) when absent, same convention as verify-rederive-bumps.sh,
# verify-gate.sh, verify-corpus-generator.sh and verify-cage-engine.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v kyverno >/dev/null; then
  echo "SKIP: kyverno CLI not found -- the generator standing check needs it"
  exit 0
fi

echo "== generator_standing_check.py --selfcheck =="
python3 generator_standing_check.py --selfcheck

echo
echo "== the standing check itself =="
python3 generator_standing_check.py
