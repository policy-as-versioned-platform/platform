#!/usr/bin/env bash
# Beat: the composition seam (policy-composition tickets 12-15). ADR-0012
# (self-signed, pinned SHA) / ADR-0013 (baselines, control ids, holes) /
# ADR-0014 (the governed namespace) / ADR-0016 (kind-aware render, the
# resolver key) / ADR-0017 (claim ownership) / ADR-0018 (the Namespace
# manifest is the governed declaration).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || fail "python3 required"

say "1. composition.py's own asserts (compose, render faithfulness, verify, the CLI, refusal)"
python3 "$HERE/composition.py" --selfcheck || fail "composition.py --selfcheck"

say "PASS: the composition seam holds"
