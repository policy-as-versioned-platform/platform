#!/usr/bin/env bash
# verify-comparison-window.sh -- ticket cs-24. The comparison window and the
# per-institution matrix's own selfcheck: strictest-of-the-whole-window,
# retirement, backport narrowing and the matrix all run through real
# cage_engine.classify_repo calls (Track 1 needs the real kyverno CLI, same
# as verify-cage-engine.sh/verify-pairing.sh), so this SKIPs (exit 3) when
# the CLI is absent, matching every other verify-*.sh in this directory.
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
  skip "kyverno CLI not found -- comparison_window's per-line classification needs it"
fi
selfcheck_absent "$SELF" kyverno

python3 comparison_window.py --selfcheck
