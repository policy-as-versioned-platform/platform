#!/usr/bin/env bash
# Beat: the party artefact schema and its check (policy-composition ticket
# 11, widened by eco-system ticket 21). ADR-0012 (self-signed, pinned SHA) /
# ADR-0013 (regulator publishes baselines, adopter selects) /
# ADR-0019 (one feed envelope; publishes[] is the discovery record).
#
# Offline: every fact here is a file in this checkout. Nothing here reaches
# the network, so there is no could-not-look case and no exit 3.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || fail "python3 required"

say "1. party_artefact.py's own asserts (schema.json + the tag/baseline/publish checks)"
python3 "$HERE/party_artefact.py" --selfcheck || fail "party_artefact.py --selfcheck"

# The platform is a party like any other, so its own artefact is checked by
# its own checker -- not exempted from the format it ships (ticket 21).
say "2. the platform's own party artefact checks out"
[ -f "$REPO/party.yaml" ] || fail "$REPO/party.yaml does not exist -- the platform must declare itself"
python3 "$HERE/party_artefact.py" check "$REPO/party.yaml" --adopter-dir "$REPO" \
  || fail "the platform's own party.yaml does not check out"

# can_publish is an OBSERVED fact, not a claim in the file: it is false unless
# the publisher role is declared AND cut-release.yml exists to cut the tag.
# The platform publishes, so a false here means the release path went missing.
say "3. the platform can actually publish what it advertises"
python3 "$HERE/party_artefact.py" check "$REPO/party.yaml" --adopter-dir "$REPO" \
  | grep -qx "FACT: can_publish=true" \
  || fail "platform declares publishes[] but can_publish is false -- no signed release path"

say "PASS: the party artefact schema, its check, and the platform's own artefact all hold"
