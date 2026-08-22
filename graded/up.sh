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

say "done. verify with estate/platform/graded/verify-graded.sh"
