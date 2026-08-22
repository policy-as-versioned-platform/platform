#!/usr/bin/env bash
# DEMO PATH, not delivery (ticket cs-17). This is the offline twin of what
# flux-operator's ResourceSet (distribution/versions.yaml) would deliver for
# the posture projection policies: it renders each declared version the way
# ticket 12's renderer (distribution/render-version-tree.py) renders a
# released tree, grounds that render in the REAL committed
# distribution/policies/v<version>/ tree, PROVES with `kubectl kustomize`
# (the real, independent builder -- not render-version-tree.py judging
# itself) that the result is a Kustomization the ResourceSet could actually
# deliver, and applies ONLY the rendered, versioned copies -- never the
# posture/policies/ authoring copies -- onto the EXISTING driftwood KinD
# cluster. No Flux, no live ResourceSet, in the loop. See
# distribution/render-and-prove.py for the honesty note on what is proven
# today vs. what ticket cs-15 (not yet landed) still owes. The posture
# ClusterSPIFFEID is not one of the renderer's seven mandatory members (it
# is not per-policy-version), so it is still applied straight from its
# authoring copy, as before.
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

while IFS= read -r v; do
  say "v$v: Kyverno posture policies (stamp-posture mutate + posture-trust-boundary validate)"
  kubectl --context "$CTX" apply -f "$WORK/v$v/stamp-posture.yaml" \
    || echo "  (Kyverno MutatingPolicy CRD not ready — install Kyverno, then re-run up.sh)"
  kubectl --context "$CTX" apply -f "$WORK/v$v/posture-trust-boundary.yaml" \
    || echo "  (Kyverno ValidatingPolicy CRD not ready — install Kyverno, then re-run up.sh)"
done < "$WORK/versions.txt"

say "posture ClusterSPIFFEID (bakes posture/<vN> into the SVID path; not part of the versioned tree)"
kubectl --context "$CTX" apply -f "$HERE/spire/clusterspiffeid-posture.yaml" \
  || echo "  (SPIRE ClusterSPIFFEID CRD not ready — run identity/up.sh first, then re-run up.sh)"

say "done. verify with estate/platform/posture/verify-posture-projection.sh"
