#!/usr/bin/env bash
# Beat: "every party that runs a cluster has its own trust domain, and the
# domains federate pairwise" (ticket 32; ticket 12 answer 1).
#
# OFFLINE (always): the twelve ClusterFederatedTrustDomain objects in
# federation/ are a complete, symmetric, self-federation-free pairing over
# exactly the four cluster-running parties, each with a className the
# controller-manager will actually reconcile.
#
# LIVE: nothing to look at. No peer trust domain serves a bundle endpoint, so
# federation is DECLARED, not observed, and this script exits 3 rather than
# passing on a structural proof. That is the whole point of the exit-3 rung:
# absence is never a pass.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== offline: the federation set is complete and symmetric =="
python3 - "$HERE/federation" <<'PY'
import sys, os, glob
try:
    import yaml
except ImportError:
    sys.exit("PyYAML not available; `pip install pyyaml` to run the offline check")

root = sys.argv[1]
PARTIES = {"platform", "driftwood", "tuppence", "ludlow"}
fails = []
def check(cond, msg):
    if not cond: fails.append(msg)
    print(("  ok   " if cond else "  FAIL ") + msg)

files = sorted(glob.glob(os.path.join(root, "*.yaml")))
check({os.path.basename(f)[:-5] for f in files} == PARTIES,
      f"one federation file per cluster-running party ({sorted(PARTIES)}) and no others")

# party -> the set of trust domains it declares it federates with
declared: dict[str, set[str]] = {}
for f in files:
    me = os.path.basename(f)[:-5]
    with open(f) as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d]
    peers = set()
    check(all(d.get("kind") == "ClusterFederatedTrustDomain" for d in docs),
          f"{me}: every object is a ClusterFederatedTrustDomain "
          f"({sorted({d.get('kind') for d in docs})})")
    for d in docs:
        spec = d.get("spec", {})
        td = spec.get("trustDomain", "")
        peers.add(td)
        # ticket 11's lesson, applied before it can bite again: the spire chart
        # scopes its controller-manager to <ns>-<release> and ignores objects
        # with no className -- silently, forever.
        check(spec.get("className") == "spire-system-spire",
              f"{me}/{td}: className set, so spire-controller-manager reconciles it")
        check(spec.get("bundleEndpointURL", "").startswith("https://"),
              f"{me}/{td}: bundle endpoint is https (SPIRE refuses anything else)")
        prof = spec.get("bundleEndpointProfile", {})
        check(prof.get("type") == "https_spiffe",
              f"{me}/{td}: https_spiffe profile (the peer's own SPIRE authenticates itself)")
        check(prof.get("endpointSPIFFEID", "").startswith(f"spiffe://{td}/"),
              f"{me}/{td}: endpoint SPIFFE ID is inside the peer's own trust domain")
    declared[me] = peers

for me, peers in sorted(declared.items()):
    mine = f"{me}.acme.internal"
    check(mine not in peers, f"{me} does not federate with itself")
    check(peers == {f"{p}.acme.internal" for p in PARTIES - {me}},
          f"{me} declares exactly its three peers, got {sorted(peers)}")

# Symmetry: a pair is federated only if BOTH sides say so. This is what makes
# "remove the line from your own artefact" a real revocation rather than a
# request.
for a in sorted(PARTIES):
    for b in sorted(PARTIES - {a}):
        check(f"{b}.acme.internal" in declared.get(a, set())
              and f"{a}.acme.internal" in declared.get(b, set()),
              f"pair {a}<->{b} is declared on both sides")

if fails:
    sys.exit(f"\n{len(fails)} invariant(s) broken")
print("  -- the declared federation set is complete and symmetric --")
PY

# ---- live: there is nothing to observe, and saying so is the answer ----
if ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif ! timeout 10 kubectl --context "$CTX" get crd clusterfederatedtrustdomains.spire.spiffe.io >/dev/null 2>&1; then
  live_tail_skip "the ClusterFederatedTrustDomain CRD is not installed on $CTX (run identity/up.sh)"
else
  # The CRD is there. Is a counterparty? 2026-08-29 review: every branch of this
  # tail called live_tail_skip, the `else` unconditionally, so pass_line below
  # was unreachable -- the script could never report the good news on the day a
  # second trust domain appeared. SKIP is still the truthful answer today, but
  # it is now the answer to an OBSERVATION rather than a foregone conclusion.
  TD=$(timeout 10 kubectl --context "$CTX" -n spire-system get cm spire-server \
    -o jsonpath='{.data.server\.conf}' 2>/dev/null \
    | tr -d ' "' | grep -o 'trust_domain:[^,}]*' | head -1 || true)
  # A federated peer exists on this cluster when SPIRE has been told about one:
  # a ClusterFederatedTrustDomain object naming a bundle endpoint.
  PEERS=$(timeout 10 kubectl --context "$CTX" get clusterfederatedtrustdomains.spire.spiffe.io \
    -o jsonpath='{range .items[*]}{.spec.trustDomain}{" "}{end}' 2>/dev/null || true)
  if [ -z "${PEERS// /}" ]; then
    live_tail_skip "no peer trust domain serves a bundle endpoint: this cluster carries no \
ClusterFederatedTrustDomain object at all, driftwood still runs the single estate-wide domain \
(${TD:-trust_domain unreadable}) rather than driftwood.acme.internal, tuppence and ludlow run no \
SPIRE at all, and spire-server.federation is disabled here so this cluster serves no endpoint \
either. Federation is declared in identity/federation/, not observed"
  else
    echo "  ok  live: ${TD:-this cluster} federates with declared peer trust domain(s): ${PEERS% }"
  fi
fi

pass_line "each cluster-running party has its own trust domain and the four domains federate pairwise"
