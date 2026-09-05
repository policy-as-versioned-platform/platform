#!/usr/bin/env bash
# Beat: "a version not in the array is REPORTED and CAGED, never denied."
#
# Eco-system ticket 89 turned this beat over. It used to read "a version not in the array
# cannot run", and it made the DENIAL its pass condition: `kyverno apply` exiting non-zero on
# the orphan pod was the proof. The owner's words (2026-09-02, ticket 75 Q5) rule that shape
# out -- something can be unable to run only because it does not fit the cage, never because
# it is deliberately denied -- so the orphan guard is `Audit` now and this script proves the
# three things that replace the denial:
#
#   1. the allow-list is still ranged from the SAME array, so the runnable-version set cannot
#      drift from the declared-version set (unchanged, and still the point of the guard);
#   2. the ACTION is `Audit` and no `Deny` survives anywhere in the rendered body, and the rule
#      still fires on the orphan and not on the declared version -- the report being the
#      observation the priced hole rests on (ADR-0026);
#   3. the orphan pod is CAGED all the same: `graded/policies/cage-tier.yaml` matches every
#      pod that claims a version, so the same pod comes out of admission carrying its
#      Namespace's declared tier and the dials that go with it. There is no admitted-and-
#      uncaged outcome, which is what makes the demotion safe rather than a hole.
#
# Exits non-zero if the beat would fail on stage. OFFLINE (python3 + the kyverno CLI).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have kyverno || fail "kyverno CLI required"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

declared_version="$(python3 -c "
import importlib.util
from pathlib import Path
here = Path('$HERE')
spec = importlib.util.spec_from_file_location('render_orphan_guard', here / 'render-orphan-guard.py')
og = importlib.util.module_from_spec(spec)
spec.loader.exec_module(og)
print(og.versions(here / 'versions.yaml')[0])
")"
say "1. render the orphan-guard from the version array (declares $declared_version, ...)"
python3 "$HERE/render-orphan-guard.py" --selfcheck
python3 "$HERE/render-orphan-guard.py" > "$WORK/orphan-guard.yaml"
grep -q 'Audit' "$WORK/orphan-guard.yaml" || fail "the rendered orphan-guard is not Audit"
if grep -q 'Deny' "$WORK/orphan-guard.yaml"; then
  fail "the rendered orphan-guard still carries a Deny -- eco-system ticket 89 removed it"
fi

cat > "$WORK/pods.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata: { name: declared, namespace: governed-ns, labels: { "policy-as-versioned.dev/policy-version": "$declared_version" } }
spec: { containers: [{ name: c, image: nginx }] }
---
apiVersion: v1
kind: Pod
metadata: { name: orphan, namespace: governed-ns, labels: { "policy-as-versioned.dev/policy-version": "9.9.9" } }
spec: { containers: [{ name: c, image: nginx }] }
---
apiVersion: v1
kind: Pod
metadata: { name: unversioned, namespace: governed-ns }
spec: { containers: [{ name: c, image: nginx }] }
YAML

say "2. an undeclared version (9.9.9) is REPORTED; a declared one ($declared_version) is clean"
# THE CEILING, MEASURED, NOT ASSUMED (kyverno 1.18.2, 2026-09-05). The pinned CLI evaluates a
# CEL ValidatingPolicy the same way whether `validationActions` says Audit or Deny: the same
# body under either value gives the identical `pass: 1, fail: 1, ... skip: 1` spread and the
# identical exit code 1, and `--audit-warn` changes neither (it only reaches the 2022
# ClusterPolicy type). So this step proves the RULE functionally -- it fires on the orphan and
# not on the declared version -- and the ACTION structurally, in step 1. Whether the API
# server ADMITS the orphan pod is a live fact, and it belongs to the cluster tail of
# ../graded/verify-graded.sh; this script does not claim to have observed it.
#
# Which is why the old shape of this beat has to go rather than be inverted: it read the
# denial off the exit code, and the exit code never carried it.
out="$(kyverno apply "$WORK/orphan-guard.yaml" --resource "$WORK/pods.yaml" 2>&1 || true)"
grep -q "resource governed-ns/Pod/orphan failed" <<<"$out" \
  || fail "the orphan pod (9.9.9) was not reported -- the observation the priced hole rests on is gone"
grep -q "Nothing is denied" <<<"$out" \
  || fail "the orphan report no longer says what it does; the message must not claim a refusal"
if grep -q "resource governed-ns/Pod/declared failed" <<<"$out"; then
  fail "a DECLARED version ($declared_version) was wrongly reported by the orphan-guard"
fi
# exactly one report (the orphan), one skip (unversioned, out of scope)
grep -qE 'pass: 1, fail: 1, warn: 0, error: 0, skip: 1' <<<"$out" \
  || fail "unexpected verdict spread: $(tail -1 <<<"$out")"

say "3. the SAME orphan pod is caged all the same -- cage-tier matches every claiming pod"
# The declaration is the Namespace (ADR-0022) and kyverno 1.18 populates `namespaceObject`
# only from a CLI values file's `namespaces:` list, so the governed Namespace goes there.
cat > "$WORK/values.yaml" <<'YAML'
apiVersion: cli.kyverno.io/v1alpha1
kind: Values
namespaces:
  - apiVersion: v1
    kind: Namespace
    metadata:
      name: governed-ns
      labels:
        policy-as-versioned.dev/governed: "true"
        posture.acme.io/tier: quarantine
YAML
kyverno apply "$HERE/../graded/policies/cage-tier.yaml" --resource "$WORK/pods.yaml" \
  -f "$WORK/values.yaml" -o "$WORK/caged" >/dev/null 2>&1 \
  || fail "the cage refused a pod -- cage-tier must never make a workload inadmissible"
caged="$WORK/caged/orphan-mutated.yaml"
[ -f "$caged" ] || fail "cage-tier produced no mutated orphan pod at $caged"
grep -q 'posture.acme.io/tier: quarantine' "$caged" \
  || fail "the orphan pod came out of the cage without its Namespace's declared tier"
grep -q 'priorityClassName: cage-quarantine' "$caged" \
  || fail "the orphan pod came out of the cage without the quarantine PriorityClass"
grep -q 'posture.acme.io/caged: "true"' "$caged" \
  || fail "the orphan pod is not marked caged, so the reach projection would not key on it"

echo "PASS: the orphan-guard renders Audit with no Deny left in its body, it reports the undeclared version by name and leaves the declared one alone, and the same orphan pod comes out of cage-tier carrying its Namespace's declared tier, its PriorityClass and the caged marker. The allow-list is still the array; the rules an orphan claim escapes are a priced hole, not a refusal. Whether the API server admits it is the cluster tail of ../graded/verify-graded.sh, not this run."
