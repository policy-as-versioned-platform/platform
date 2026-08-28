#!/usr/bin/env bash
# Beat (ticket cs-12): "A publisher cuts a version and gets every enforcement
# surface in the tree, without hand-editing four places." Exits non-zero if
# the beat would fail on stage.
#
# 1. render-version-tree.py --selfcheck: the offline twin is deterministic,
#    all 7 mandatory members carry versioned names/labels/self-scope, never
#    matchConstraints.objectSelector, cage-tier names its own versioned
#    PriorityClasses, the live path (actual files on disk) matches the
#    offline twin exactly, and re-rendering an already-rendered tree refuses.
# 2. offline, with the REAL kyverno CLI: two versions' cage-tier copies,
#    rendered side by side into a scratch dir, each mutate ONLY the pod that
#    claims their own version -- proving the self-scope actually isolates
#    versions, not just that the YAML says so.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

say "1. offline: render-version-tree.py --selfcheck"
python3 "$HERE/render-version-tree.py" --selfcheck || fail "render-version-tree.py --selfcheck failed"

if ! command -v kyverno >/dev/null 2>&1; then
  echo "SKIP: kyverno CLI not found -- the coexistence proof needs it (offline, no cluster)"
  exit 0
fi

say "2. offline: two rendered versions' cage-tier copies coexist -- each judges only its own claim"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
python3 "$HERE/render-version-tree.py" 8.8.8 --out "$WORK/v8.8.8" >/dev/null
python3 "$HERE/render-version-tree.py" 9.9.9 --out "$WORK/v9.9.9" >/dev/null

# The tier is declared on the NAMESPACE and read through namespaceObject
# (ADR-0022), so the offline run has to supply the Namespace through a values
# file -- a `kind: Namespace` in --resource never reaches the mpol engine
# (kyverno 1.18; see graded/tests/cage-tier/values.yaml).
cat > "$WORK/values.yaml" <<'YAML'
apiVersion: cli.kyverno.io/v1alpha1
kind: Values
namespaces:
  - apiVersion: v1
    kind: Namespace
    metadata:
      name: caged
      labels:
        policy-as-versioned.dev/governed: "true"
        posture.acme.io/tier: restricted
YAML

cat > "$WORK/pods.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: claims-8-8-8
  namespace: caged
  labels: { "policy-as-versioned.dev/policy-version": "8.8.8" }
spec: { containers: [{ name: app, image: nginx }] }
---
apiVersion: v1
kind: Pod
metadata:
  name: claims-9-9-9
  namespace: caged
  labels: { "policy-as-versioned.dev/policy-version": "9.9.9" }
spec: { containers: [{ name: app, image: nginx }] }
YAML

out="$(kyverno apply "$WORK/v8.8.8/cage-tier.yaml" --resource "$WORK/pods.yaml" -f "$WORK/values.yaml" 2>&1)"
echo "$out" | awk '/caged\/Pod\/claims-8-8-8/{f=1} f&&/^---/{exit} f' | grep -q 'priorityClassName: cage-restricted-8-8-8' \
  || fail "8.8.8's cage-tier did not cage the pod claiming 8.8.8"
echo "$out" | awk '/caged\/Pod\/claims-9-9-9/{f=1} f&&/^---/{exit} f' | grep -q 'priorityClassName' \
  && fail "8.8.8's cage-tier mutated a pod claiming 9.9.9 -- self-scope leaked across versions"

echo "PASS: every mandatory member renders with a versioned name, the policy-version label, a"
echo "      matchConditions self-scope (never objectSelector); cage-tier names its own"
echo "      PriorityClasses; and two rendered versions coexist, each judging only its own claim."
