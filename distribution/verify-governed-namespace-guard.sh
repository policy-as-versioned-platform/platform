#!/usr/bin/env bash
# Beat: "a governed namespace requires a claim at CREATE" (ADR-0014).
#
# Two proofs, not one, because the pinned kyverno CLI (1.18.2) cannot
# evaluate `matchConstraints.namespaceSelector` offline -- it silently
# matches zero resources instead of erroring, which would make a naive
# `kyverno apply` test a false pass (kyverno/kyverno#13605 is the open
# upstream bug; `namespaceObject` in a CEL expression fares worse and
# errors outright, kyverno/kyverno#9975). Neither is a runtime limitation:
# a real API server resolves both correctly. It is this offline CLI only.
#
#   1. STRUCTURAL: render-governed-namespace-guard.py --selfcheck asserts the
#      manifest shape directly (Audit, CREATE-only, the namespaceSelector's
#      match label) -- no kyverno CLI involved, so the CLI's gap cannot hide
#      a shape regression.
#   2. FUNCTIONAL: the validations EXPRESSION -- "must carry a policy-version
#      claim" -- proved for real via `kyverno apply`, against a throwaway
#      copy of the SAME policy with namespaceSelector removed (the one field
#      the CLI can't evaluate). The expression under test is copied
#      verbatim from the real render, so a change to the real wording is
#      caught here; only the namespace-scoping boundary itself goes
#      unproved by a runnable admission test.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have kyverno || fail "kyverno CLI required"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

say "1. render-governed-namespace-guard.py --selfcheck (structural: shape, Audit, CREATE-only, namespaceSelector)"
python3 "$HERE/render-governed-namespace-guard.py" --selfcheck

say "2. the validations expression itself, functionally, namespaceSelector stripped (kyverno CLI cannot evaluate it offline -- see this script's docstring)"
python3 - "$WORK/policy.yaml" <<'PY'
import sys, yaml
sys.path.insert(0, "distribution")
import importlib.util
spec = importlib.util.spec_from_file_location("g", "distribution/render-governed-namespace-guard.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
doc = g.governed_namespace_guard()
del doc["spec"]["matchConstraints"]["namespaceSelector"]  # the CLI-untestable half; see docstring
with open(sys.argv[1], "w") as f:
    yaml.safe_dump(doc, f)
PY

cat > "$WORK/pods.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata: { name: unclaimed }
spec: { containers: [{ name: c, image: nginx }] }
---
apiVersion: v1
kind: Pod
metadata: { name: claimed, labels: { "policy-as-versioned.dev/policy-version": "3.0.0" } }
spec: { containers: [{ name: c, image: nginx }] }
YAML

out="$(kyverno apply "$WORK/policy.yaml" --resource "$WORK/pods.yaml" 2>&1 || true)"
grep -q "resource default/Pod/unclaimed failed" <<<"$out" \
  || fail "an unclaimed pod was NOT denied -- the claim requirement doesn't fire: $out"
if grep -q "resource default/Pod/claimed failed" <<<"$out"; then
  fail "a CLAIMED pod was wrongly denied"
fi
grep -qE 'pass: 1, fail: 1, warn: 0, error: 0, skip: 0' <<<"$out" \
  || fail "unexpected verdict spread: $(tail -1 <<<"$out")"

echo "PASS: a governed namespace requires a claim at CREATE; the claim check itself is proved, and the namespace-scoping shape is proved structurally (kyverno CLI cannot evaluate namespaceSelector offline)."
