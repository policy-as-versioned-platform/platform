#!/usr/bin/env bash
# Beat: "a pod that claims nothing, inside a governed namespace, lands on the bottom rung."
#
# Eco-system ticket 89 turned this beat over. It used to assert that an unclaimed pod was
# DENIED, and made the denial its pass condition. The owner's words (2026-09-02, ticket 75 Q5)
# rule that shape out: something can be unable to run only because it does not fit the cage,
# never because it is deliberately denied. So the rule is a `MutatingPolicy` now, and this
# script proves the mutation instead of the refusal.
#
# Two proofs, not one, because the pinned kyverno CLI (1.18.2) cannot evaluate
# `matchConstraints.namespaceSelector` offline -- it silently matches zero resources instead of
# erroring, which would make a naive `kyverno apply` test a false pass (kyverno/kyverno#13605 is
# the open upstream bug). Neither is a runtime limitation: a real API server resolves it
# correctly. It is this offline CLI only.
#
#   1. STRUCTURAL: render-governed-namespace-guard.py --selfcheck asserts the manifest shape
#      directly -- a MutatingPolicy with no `validationActions`, no `validations` and no `Deny`
#      anywhere in it; CREATE-only; the namespaceSelector's match label; the rung pinned to the
#      bottom of `graded/cage.py`'s own ladder; and the mutation body byte-equal to
#      `graded/policies/cage-tier.yaml`'s, so there is no third copy of the dial table.
#   2. FUNCTIONAL: the MUTATION -- proved for real via `kyverno apply`, against a throwaway
#      copy of the SAME policy with namespaceSelector removed (the one field the CLI can't
#      evaluate). An unclaimed pod comes out carrying the bottom rung's tier, its
#      PriorityClass, its dials, the caged marker, host namespaces shut and ALL capabilities
#      dropped; a pod that DOES claim is skipped, because `cage-tier` owns that population and
#      two writers on one field is the label-and-dials incoherence H8-03 exists to prevent.
#      Nothing is refused: the run reports `fail: 0`.
#
# Only the namespace-scoping boundary itself goes unproved by a runnable admission test; that
# is the cluster tail of ../graded/verify-graded.sh, not this script's claim.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have kyverno || fail "kyverno CLI required"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

say "1. render-governed-namespace-guard.py --selfcheck (structural: a MutatingPolicy with no refusal in it, CREATE-only, namespaceSelector, the bottom rung, cage-tier's own body)"
python3 "$HERE/render-governed-namespace-guard.py" --selfcheck

say "2. the mutation itself, functionally, namespaceSelector stripped (the kyverno CLI cannot evaluate it offline -- see this script's docstring)"
python3 - "$WORK/policy.yaml" "$HERE/render-governed-namespace-guard.py" <<'PY'
import sys, yaml
import importlib.util
spec = importlib.util.spec_from_file_location("g", sys.argv[2])  # resolved from the script's own dir, cwd-independent
g = importlib.util.module_from_spec(spec)
sys.modules["g"] = g
spec.loader.exec_module(g)
doc = g.governed_namespace_guard()
del doc["spec"]["matchConstraints"]["namespaceSelector"]  # the CLI-untestable half; see docstring
with open(sys.argv[1], "w") as f:
    yaml.safe_dump(doc, f)
PY
grep -q 'Deny' "$WORK/policy.yaml" && fail "a Deny survived in the rendered policy -- ticket 89 removed it"

cat > "$WORK/pods.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata: { name: unclaimed, namespace: governed-ns }
spec: { containers: [{ name: c, image: nginx, securityContext: { privileged: true } }] }
---
apiVersion: v1
kind: Pod
metadata: { name: claimed, namespace: governed-ns, labels: { "policy-as-versioned.dev/policy-version": "3.0.0" } }
spec: { containers: [{ name: c, image: nginx }] }
YAML

out="$(kyverno apply "$WORK/policy.yaml" --resource "$WORK/pods.yaml" -o "$WORK/out" 2>&1)" \
  || fail "kyverno apply exited non-zero -- a mutation must never make a workload inadmissible: $out"
# Nothing refused, and the claiming pod is somebody else's business: two mutations writing one
# field is what produces a pod labelled `isolated` carrying baseline's PriorityClass.
grep -qE 'pass: 2, fail: 0, warn: 0, error: 0, skip: 2' <<<"$out" \
  || fail "unexpected verdict spread (want two mutations applied, nothing failed, the claiming pod skipped): $(tail -1 <<<"$out")"

caged="$WORK/out/unclaimed-mutated.yaml"
[ -f "$caged" ] || fail "no mutated pod at $caged -- the unclaimed pod was not caged at all"
want_absent() { grep -q "$1" "$caged" && fail "$2"; return 0; }
grep -q 'posture.acme.io/tier: isolated' "$caged" \
  || fail "the unclaimed pod did not land on the bottom rung"
grep -q 'posture.acme.io/caged: "true"' "$caged" \
  || fail "the unclaimed pod is not marked caged, so the reach projection would not key on it"
grep -q 'priorityClassName: cage-isolated' "$caged" \
  || fail "the unclaimed pod carries no first-eviction PriorityClass"
grep -q 'priority: -10000' "$caged" \
  || fail "the unclaimed pod carries no integer priority -- the Priority admission plugin refuses that pod"
grep -q 'preemptionPolicy: Never' "$caged" \
  || fail "the unclaimed pod carries no preemptionPolicy -- the Priority admission plugin refuses that pod"
grep -q 'cpu: 100m' "$caged" || fail "the bottom rung's cpu dial is missing"
grep -q 'memory: 64Mi' "$caged" || fail "the bottom rung's memory dial is missing"
grep -q 'privileged: false' "$caged" \
  || fail "the pod declared privileged: true and the cage did not clobber it"
grep -q 'readOnlyRootFilesystem: true' "$caged" || fail "the bottom rung is not hardened"
grep -q 'hostNetwork: false' "$caged" \
  || fail "hostNetwork was not clobbered shut, so the reach projection is no bar on this pod"
grep -q 'name: waf-sidecar' "$caged" || fail "the bottom rung's WAF sidecar was not injected"
grep -q -- '- ALL' "$caged" || fail "capabilities were not dropped"
# The claiming pod is untouched by THIS policy: cage-tier owns it. Whether the CLI writes a
# file for a skipped resource is its business, so both outcomes are handled explicitly rather
# than through a && || chain whose precedence would fail the beat when the file is absent.
if [ -f "$WORK/out/claimed-mutated.yaml" ] \
   && grep -q 'posture.acme.io/tier' "$WORK/out/claimed-mutated.yaml"; then
  fail "this policy mutated a pod that claims a version -- cage-tier owns that population, and two writers on one field is the label-and-dials incoherence H8-03 exists to prevent"
fi

echo "PASS: a governed namespace's unclaimed pod is CAGED on the bottom rung, not denied -- isolated tier, cage-isolated PriorityClass with its integer priority and preemptionPolicy, 100m/64Mi, hardened, host namespaces shut, all capabilities dropped, a WAF sidecar, and privileged: true clobbered false; a pod that claims is left to cage-tier; nothing in the run was refused. The mutation body is cage-tier's own and the namespace-scoping shape is proved structurally (the kyverno CLI cannot evaluate namespaceSelector offline)."
