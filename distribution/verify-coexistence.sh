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
#
# 2026-09-04 (ticket 63). The array declares two lines again -- 4.0.0 and the
# isolated-default cut 5.0.0, the second declared line (ticket 58 Q1a) -- so
# this beat has a subject for the first time since the 2026-08-29 retirement.
# Getting there exposed two ways it was passing about nothing, both fixed here:
#
#   * THE OFFLINE MATRIX WAS RUNNING OVER RETIRED BODIES. tests/require-nonroot
#     loaded policies/v2.0.0 and v3.0.0, whose array elements were deleted on
#     2026-08-29. Those trees are frozen behind their signed tags and Flux
#     delivers them to nobody, so "two versions coexist" was true of two things
#     that do not run. The fixture now loads 4.0.0 and 5.0.0, and step 1b
#     asserts its `policies:` list is EXACTLY the declared array -- if the array
#     moves and the fixture does not, this fails instead of drifting.
#   * AN UNCUT TAIL WOULD HAVE FAILED THE LIVE TAIL. A declared element with no
#     `commit` has not been released: cut-release.yml fills that field when it
#     cuts the signed tag, so until then the tag does not exist, Flux cannot
#     deliver it and no cluster can be carrying its ValidatingPolicy. Calling
#     that "declared in versions.yaml but absent on the cluster -- fan-out
#     incomplete" would be a red for an unmade release. The live tail now looks
#     only at CUT versions, needs two of them to have anything to prove, and
#     could-not-looks by name for the tail.
#
# The threshold stays TWO declared lines here. Ticket 84 supplies the third and
# raises it to three (ticket 75 Q3: at least three coexisting versions, forward
# and back by one, in the owner's own 2022 words).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || fail "python3 required"

# The one reader of the array and of the fixture, shared by the real run and the
# selfcheck. Prints three lines -- `DECLARED:`, `CUT:` and `FIXTURE:` -- each a
# space-separated version list. `--selfcheck` runs the pure asserts instead and
# touches only its own temp files.
array_state() {
python3 - "$HERE" "${1:-}" <<'PY'
import importlib.util, os, re, sys, tempfile
from pathlib import Path

here, mode = Path(sys.argv[1]), sys.argv[2]
spec = importlib.util.spec_from_file_location("rog", here / "render-orphan-guard.py")
rog = importlib.util.module_from_spec(spec); spec.loader.exec_module(rog)

FIXTURE_RE = re.compile(r"policies/v(\d+\.\d+\.\d+)/require-nonroot\.yaml")


def cut(els):
    """The versions that have actually been RELEASED. `commit` is filled in by
    cut-release.yml when it cuts the signed tag, so an element without one is an
    uncut tail: no tag, nothing for Flux to deliver, nothing on any cluster."""
    return [e["version"] for e in els if e.get("commit")]


def fixture_versions(text):
    """The versions the offline matrix actually loads, read off its own
    `policies:` paths. This is what went stale: the fixture named two trees the
    array had stopped declaring, and nothing compared the two.

    SORTED, and so is the declared list it is compared against: which version a
    fixture lists first is not a fact about the estate, and failing over it
    would be a red with nothing behind it."""
    return sorted(set(FIXTURE_RE.findall(text)))


if mode == "--selfcheck":
    assert cut([{"version": "4.0.0", "commit": "abc"},
                {"version": "5.0.0", "tag": "policy/v5.0.0"}]) == ["4.0.0"], \
        "an element with no commit is an uncut tail, not a released version"
    assert cut([{"version": "5.0.0", "commit": ""}]) == [], \
        "an empty commit is uncut too"
    assert fixture_versions(
        "policies:\n  - ../../policies/v4.0.0/require-nonroot.yaml\n"
        "  - ../../policies/v5.0.0/require-nonroot.yaml\n") == ["4.0.0", "5.0.0"], \
        "the fixture's loaded versions must be read off its own policies list"
    # THE DRIFT THIS EXISTS TO CATCH: the fixture left pointing at retired
    # trees while the array declares different ones. Green over frozen bodies
    # is the false pass this project forbids.
    assert fixture_versions(
        "policies:\n  - ../../policies/v2.0.0/require-nonroot.yaml\n"
        "  - ../../policies/v3.0.0/require-nonroot.yaml\n") != ["4.0.0", "5.0.0"], \
        "a fixture on retired trees must not compare equal to the declared array"
    assert fixture_versions("policies:\n  - ../../policies/vselfcheck/cage-tier.yaml\n") == [], \
        "a non-version path contributes no version"
    print("ok   selfcheck: cut/uncut partition, and the fixture's loaded versions read off "
          "its own policies list so drift onto retired trees is visible")
    sys.exit(0)

els = rog.elements(here / "versions.yaml")
print("DECLARED: " + " ".join(sorted(e["version"] for e in els)))
print("CUT: " + " ".join(cut(els)))
print("FIXTURE: " + " ".join(
    fixture_versions((here / "tests" / "require-nonroot" / "kyverno-test.yaml").read_text())))
PY
}

if [ "${1:-}" = "--selfcheck" ]; then
  array_state --selfcheck
  exit 0
fi

say "0. selfcheck: the array reader and the fixture reader bite"
bash "$0" --selfcheck || fail "the selfcheck did not bite -- the checker itself has regressed"

have kyverno || fail "kyverno CLI required for the offline coexistence proof"

STATE="$(array_state)"
DECLARED="$(sed -n 's/^DECLARED: //p' <<<"$STATE")"
CUT="$(sed -n 's/^CUT: //p' <<<"$STATE")"
FIXTURE="$(sed -n 's/^FIXTURE: //p' <<<"$STATE")"

say "1. offline: both versions self-scope + admit side by side (kyverno test)"
kyverno test "$HERE/tests/require-nonroot" >/dev/null \
  || fail "coexistence matrix failed — a version judged a workload it does not own"

say "1b. offline: the matrix's subjects are exactly the DECLARED array ($DECLARED)"
[ "$FIXTURE" = "$DECLARED" ] \
  || fail "tests/require-nonroot loads [$FIXTURE] but distribution/versions.yaml declares [$DECLARED] — a coexistence proof over versions the array does not declare is a green about bodies Flux delivers to nobody (it ran over the retired 2.0.0/3.0.0 trees from 2026-08-29 to 2026-09-04). Point the fixture at the declared array."
say "   the fixture and the array agree"

say "2. offline: the orphan-guard allow-list is exactly the version array (no drift)"
python3 "$HERE/render-orphan-guard.py" --selfcheck >/dev/null \
  || fail "orphan-guard allow-list drifted from the version array"

# --- live tail: substrate first; then the fan-out must be reconciled there (the
# policy-versions ResourceSet is what installs the versions, so without it there
# is nothing to look at, not a failure); only then is a missing policy a FAIL.
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line: three outcomes per live tail
# The live tail looks at CUT versions only. A declared-but-uncut element has no
# signed tag, so its ValidatingPolicy cannot be on any cluster and its absence
# is not a fan-out fault -- see the header.
versions="$CUT"
n_versions=$(wc -w <<<"$versions")
uncut="$(tr ' ' '\n' <<<"$DECLARED" | grep -vxF -f <(tr ' ' '\n' <<<"$CUT") | tr '\n' ' ' | sed 's/ *$//')" || true
if [ "$n_versions" -lt 2 ]; then
  # Two reasons this can happen, and the message names which. Either the
  # retirement verify-retirement.sh already describes -- 2.0.0, 2.0.1 and 3.0.0
  # retired 2026-08-29 (none could admit a pod) -- left the array with one
  # element; or the second element is declared but not yet released. Either way
  # "two versions coexist side by side, no shared-webhook collision" has no
  # second subject: reconciling the fan-out would install exactly one
  # ValidatingPolicy, and looping a one-element list to claim coexistence would
  # be the false pass this project forbids. Do not invent a second version, and
  # do not fake a tag, to keep the beat alive.
  live_tail_skip "distribution/versions.yaml declares [$DECLARED] but only [$CUT] has been cut${uncut:+ (uncut, no signed tag yet: $uncut)}; coexistence needs two RELEASED versions to show side by side, and there is no second one on any cluster to prove against"
elif ! substrate_ok "$CLUSTER"; then
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
