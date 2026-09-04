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
# (exit 3) when absent, same convention as verify-rederive-bumps.sh,
# verify-gate.sh, verify-corpus-generator.sh and verify-cage-engine.sh.
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
  skip "kyverno CLI not found -- the generator standing check needs it"
fi
selfcheck_absent "$SELF" kyverno

echo "== generator_standing_check.py --selfcheck =="
python3 generator_standing_check.py --selfcheck

echo
echo "== the standing check itself =="
python3 generator_standing_check.py
