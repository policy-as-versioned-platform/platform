#!/usr/bin/env bash
# verify-gate.sh -- ticket cs-18. The seam's offline twin: `gate.py --selfcheck`
# runs entirely offline (no cluster, no kyverno) since this ticket's scope is
# the evidence-document shape and version legality, not movement -- but this
# script keeps the same kyverno-absent SKIP convention as
# verify-rederive-bumps.sh, because tickets 19+ hang real kyverno-driven
# movement checks off this same seam and this is the beat that will run them.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v kyverno >/dev/null; then
  echo "SKIP: kyverno CLI not found -- the gate's seam needs it for ticket 19+'s movement checks"
  exit 0
fi

python3 gate.py --selfcheck
