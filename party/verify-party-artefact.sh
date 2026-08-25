#!/usr/bin/env bash
# Beat: the party artefact schema and its check (policy-composition ticket
# 11). ADR-0012 (self-signed, pinned SHA) / ADR-0013 (regulator publishes
# baselines, adopter selects).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || fail "python3 required"

say "1. party_artefact.py's own asserts (schema.json + the tag/baseline checks)"
python3 "$HERE/party_artefact.py" --selfcheck || fail "party_artefact.py --selfcheck"

say "PASS: the party artefact schema and its check both hold"
