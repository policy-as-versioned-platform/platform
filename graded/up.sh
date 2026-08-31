#!/usr/bin/env bash
# DEMO PATH, not delivery (ticket cs-17). This is the offline twin of what
# flux-operator's ResourceSet (distribution/versions.yaml) would deliver for
# the graded enforcement policies: it renders each declared version the way
# ticket 12's renderer (distribution/render-version-tree.py) renders a
# released tree, grounds that render in the REAL committed
# distribution/policies/v<version>/ tree, PROVES with `kubectl kustomize`
# (the real, independent builder -- not render-version-tree.py judging
# itself) that the result is a Kustomization the ResourceSet could actually
# deliver, and applies ONLY the rendered, versioned copies -- never the
# graded/policies/ authoring copies -- onto the EXISTING driftwood KinD
# cluster. No Flux, no live ResourceSet, in the loop. See
# distribution/render-and-prove.py for the honesty note on what is proven
# today vs. what ticket cs-15 (not yet landed) still owes.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
CTX="${CTX:-kind-driftwood}"
say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

command -v kubectl >/dev/null || { echo "MISSING cli: kubectl" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

say "rendering distribution/versions.yaml's declared versions, grounded in the real committed trees, and proving the result with kubectl kustomize"
python3 "$REPO/distribution/render-and-prove.py" "$REPO" "$WORK"

kubectl --context "$CTX" version >/dev/null 2>&1 || {
  echo "driftwood cluster not reachable ($CTX); run estate/driftwood/scripts/up.sh first" >&2; exit 1; }

# The WAF sidecar image. cage-tier injects `ghcr.io/acme/coraza-waf:cage` at
# every hardened rung; that repository does not exist, so without this the
# sidecar sits in ErrImagePull and the caged workload never runs -- a cage that
# is a refusal. Build the placeholder stand-in and load it into the node.
# See waf-placeholder/Dockerfile. ponytail: skipped, loudly, when docker/kind
# are absent -- the cage still applies, its hardened rungs just cannot run.
WAF_IMAGE="ghcr.io/acme/coraza-waf:cage"
if command -v docker >/dev/null && command -v kind >/dev/null; then
  say "building and loading the placeholder WAF sidecar image ($WAF_IMAGE)"
  docker build -q -t "$WAF_IMAGE" "$HERE/waf-placeholder" >/dev/null
  kind load docker-image "$WAF_IMAGE" --name "${CTX#kind-}"
else
  echo "  (docker/kind absent: $WAF_IMAGE not loaded — pods at restricted/quarantine/isolated will not start)" >&2
fi

while IFS= read -r v; do
  say "v$v: eviction PriorityClasses (cage-baseline / cage-restricted / cage-quarantine, versioned)"
  kubectl --context "$CTX" apply -f "$WORK/v$v/priorityclasses.yaml"

  say "v$v: cage-tier MutatingPolicy (behind-posture pod -> its cage, by degree)"
  kubectl --context "$CTX" apply -f "$WORK/v$v/cage-tier.yaml" \
    || echo "  (Kyverno MutatingPolicy CRD not ready — install Kyverno, then re-run up.sh)"

  say "v$v: cage-netpol GeneratingPolicy (caged pod -> egress-lockdown NetworkPolicy)"
  kubectl --context "$CTX" apply -f "$WORK/v$v/cage-netpol.yaml" \
    || echo "  (Kyverno GeneratingPolicy CRD not ready — install Kyverno, then re-run up.sh)"
done < "$WORK/versions.txt"

# Prune what the array no longer declares -- the other half of the fan-out.
# The ResourceSet's Kustomizations carry `prune: true`; this demo path only ever
# applied, so a retired version's cage stayed installed forever. See
# graded/prune-retired.py for what that cost on 2026-08-29.
say "pruning versions distribution/versions.yaml no longer declares (Flux's prune: true, offline)"
# shellcheck disable=SC2046  # word splitting is the argv this wants
python3 "$HERE/prune-retired.py" "$CTX" $(cat "$WORK/versions.txt")

# The two CLUSTER-WIDE guards. Both are rendered by flux-operator's ResourceSet in
# distribution/versions.yaml, which is NOT in the loop on this demo path -- so
# until now a cluster that had the cage did not have its guards, and the review of
# 2026-08-28 found both holes live: a pod claiming an UNDECLARED version
# (`9.9.9`) and a pod claiming NOTHING were each admitted completely uncaged
# inside a governed `isolated` namespace, and each reached the API server and the
# internet. An offline-only proof of an admission control is not a proof.
say "cluster-wide guards: the orphan guard (an undeclared version is not runnable) and the governed-namespace claim guard"
python3 "$REPO/distribution/render-orphan-guard.py" | kubectl --context "$CTX" apply -f - \
  || echo "  (Kyverno ValidatingPolicy CRD not ready -- install Kyverno, then re-run up.sh)"
python3 "$REPO/distribution/render-governed-namespace-guard.py" | kubectl --context "$CTX" apply -f - \
  || echo "  (Kyverno ValidatingPolicy CRD not ready -- install Kyverno, then re-run up.sh)"

say "done. verify with estate/platform/graded/verify-graded.sh"
