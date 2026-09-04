#!/usr/bin/env bash
# verify-gate.sh -- ticket cs-18. The seam's offline twin: `gate.py --selfcheck`
# runs entirely offline (no cluster, no kyverno) since this ticket's scope is
# the evidence-document shape and version legality, not movement -- but this
# script keeps the same kyverno-absent SKIP convention as
# verify-rederive-bumps.sh, because tickets 19+ hang real kyverno-driven
# movement checks off this same seam and this is the beat that will run them.
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
  skip "kyverno CLI not found -- the gate's seam needs it for ticket 19+'s movement checks"
fi
selfcheck_absent "$SELF" kyverno

python3 gate.py --selfcheck
