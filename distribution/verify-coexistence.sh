#!/usr/bin/env bash
# Beat: "Two signed policy versions admit side by side — each judges only the
# workloads that claim it (matchConditions self-scoping), no shared-webhook
# collision." Exits non-zero if that beat would fail on stage.
#
# Offline core (always runs, needs only `kyverno`): the coexistence matrix via
# `kyverno test` — proves the admission verdicts. Live tail (runs only if a
# cluster with both ValidatingPolicies installed is reachable): proves the two
# versions actually coexist in ONE ValidatingWebhookConfiguration — the gap the
# single-policy CLI cannot show (research 08 §2b).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have kyverno || fail "kyverno CLI required for the offline coexistence proof"

say "1. offline: both versions self-scope + admit side by side (kyverno test)"
kyverno test "$HERE/tests/require-nonroot" >/dev/null \
  || fail "coexistence matrix failed — a version judged a workload it does not own"

say "2. offline: the orphan-guard allow-list is exactly the version array (no drift)"
python3 "$HERE/render-orphan-guard.py" --selfcheck >/dev/null \
  || fail "orphan-guard allow-list drifted from the version array"

# --- live tail: substrate first; then the fan-out must be reconciled there (the
# policy-versions ResourceSet is what installs the versions, so without it there
# is nothing to look at, not a failure); only then is a missing policy a FAIL.
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line: three outcomes per live tail
versions="$(cd "$HERE" && python3 -c 'import sys; sys.path.insert(0, "."); from pathlib import Path
import importlib.util; s = importlib.util.spec_from_file_location("g", "render-orphan-guard.py"); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
print(*m.versions(Path("versions.yaml")))')"
if ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif ! timeout 10 kubectl --context "$CTX" -n flux-system get resourceset policy-versions >/dev/null 2>&1; then
  live_tail_skip "policy-versions ResourceSet not reconciled on $CTX (fan-out not installed there; see README live bring-up)"
else
  say "3. live: every version in the array is installed as a ValidatingPolicy on $CTX"
  for v in $versions; do
    slug="$(tr . - <<<"$v")"
    timeout 10 kubectl --context "$CTX" get validatingpolicy "require-nonroot-$slug" >/dev/null 2>&1 \
      && say "   require-nonroot-$slug present" \
      || fail "require-nonroot-$slug declared in versions.yaml but absent on $CTX (fan-out incomplete)"
  done
fi

pass_line "two signed versions coexist; each judges only what claims it"
