#!/usr/bin/env bash
# verify-comparison-window.sh -- ticket cs-24. The comparison window and the
# per-institution matrix's own selfcheck: strictest-of-the-whole-window,
# retirement, backport narrowing and the matrix all run through real
# cage_engine.classify_repo calls (Track 1 needs the real kyverno CLI, same
# as verify-cage-engine.sh/verify-pairing.sh), so this SKIPs (exit 0) when
# the CLI is absent, matching every other verify-*.sh in this directory.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v kyverno >/dev/null; then
  echo "SKIP: kyverno CLI not found -- comparison_window's per-line classification needs it"
  exit 0
fi

python3 comparison_window.py --selfcheck
