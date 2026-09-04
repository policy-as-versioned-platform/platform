#!/usr/bin/env bash
# verify-rederive-bumps.sh -- ticket cs-01. Runs the REAL kyverno CLI, offline,
# against the old faithful-floor's real, signed release line (fixed input
# copied into corpus/). Exits non-zero if the engine fails to rederive any of
# the three known-good bumps that release proved live.
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
  skip "kyverno CLI not found -- rederive-bumps check needs it (offline, no cluster)"
fi
selfcheck_absent "$SELF" kyverno

python3 rederive_bumps.py
