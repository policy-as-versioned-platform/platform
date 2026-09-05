#!/usr/bin/env bash
# Beat: "a version not in the array is REPORTED and CAGED on the bottom rung, never denied."
#
# Eco-system ticket 89 turned this beat over twice, and the second turn is the one that
# matters. It used to make the DENIAL its pass condition. The owner's words (2026-09-02,
# ticket 75 Q5) rule that shape out, so the guard is `Audit` -- but the first cut of this
# ticket shipped the demotion ALONE, on the reasoning that "every claiming pod is already
# caged by cage-tier". That is FALSE of the served estate, and this script now proves why:
# every served cage-tier carries an `only-this-policy-version` matchCondition, and an orphan
# claim is by definition a version no served line carries. So the demotion alone left the pod
# running with no tier, no limits, no hardening and no reach cage -- opt-out-able by any pod
# that claimed a bogus version.
#
# What this proves, in order, against the SERVED bodies and never the authoring copies (which
# graded/up.sh's own header says it never applies):
#
#   1. the allow-list is still ranged from the SAME array, in BOTH halves of the pair, so the
#      population the report names and the population the cage cages cannot differ;
#   2. the report is `Audit`, no `Deny` survives in either body, and the report fires on the
#      orphan and not on the declared version;
#   3. THE SERVED cage-tier does not match the orphan pod AT ALL -- the fact the cage exists
#      for -- while it does mutate the declared-version pod;
#   4. the orphan cage puts that same pod on the bottom rung: isolated tier, caged marker,
#      cage-isolated PriorityClass and its integer priority, the isolated dials, hardened
#      containers AND initContainers, host namespaces shut, all capabilities dropped;
#   5. run TOGETHER, driven by the ARRAY: one pod per version the array declares plus one
#      claiming a version it does not, against every served version's cage-tier and the
#      orphan cage at once. Each pod comes out written by exactly one body, its label
#      agreeing with its dials. That is the disjointness the pair rests on, proved from the
#      array rather than asserted: two mutations writing one field is the label-and-dials
#      incoherence H8-03 exists to prevent. A version declared with no served, version-scoped
#      cage-tier fails the beat, because it would be a population neither body covers.
#
# Exits non-zero if the beat would fail on stage. OFFLINE (python3 + the kyverno CLI).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have kyverno || fail "kyverno CLI required"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

declared_versions="$(python3 -c "
import importlib.util, sys
from pathlib import Path
here = Path('$HERE')
spec = importlib.util.spec_from_file_location('render_orphan_guard', here / 'render-orphan-guard.py')
og = importlib.util.module_from_spec(spec)
sys.modules['render_orphan_guard'] = og
spec.loader.exec_module(og)
print(' '.join(og.versions(here / 'versions.yaml')))
")"
declared_version="$(python3 -c "
import importlib.util, sys
from pathlib import Path
here = Path('$HERE')
spec = importlib.util.spec_from_file_location('render_orphan_guard', here / 'render-orphan-guard.py')
og = importlib.util.module_from_spec(spec)
sys.modules['render_orphan_guard'] = og
spec.loader.exec_module(og)
print(og.versions(here / 'versions.yaml')[0])
")"
say "1. render the pair from the version array (declares $declared_version, ...)"
python3 "$HERE/render-orphan-guard.py" --selfcheck
python3 "$HERE/render-orphan-guard.py"        > "$WORK/orphan-guard.yaml"
python3 "$HERE/render-orphan-guard.py" --cage > "$WORK/orphan-cage.yaml"
grep -q 'Audit' "$WORK/orphan-guard.yaml" || fail "the rendered orphan-guard is not Audit"
for f in "$WORK/orphan-guard.yaml" "$WORK/orphan-cage.yaml"; do
  if grep -q 'Deny' "$f"; then fail "$f still carries a Deny -- eco-system ticket 89 removed it"; fi
done
grep -q 'kind: MutatingPolicy' "$WORK/orphan-cage.yaml" || fail "the orphan cage is not a MutatingPolicy"

SERVED="$HERE/policies/v$declared_version/cage-tier.yaml"
[ -f "$SERVED" ] || fail "no served cage-tier at $SERVED"
grep -q 'only-this-policy-version' "$SERVED" \
  || fail "the served cage-tier is no longer version-scoped, so this beat's whole argument is stale"

cat > "$WORK/pods.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata: { name: declared, namespace: governed-ns, labels: { "policy-as-versioned.dev/policy-version": "$declared_version" } }
spec: { containers: [{ name: c, image: nginx }] }
---
apiVersion: v1
kind: Pod
metadata: { name: orphan, namespace: governed-ns, labels: { "policy-as-versioned.dev/policy-version": "9.9.9" } }
spec:
  initContainers: [{ name: setup, image: busybox, securityContext: { privileged: true } }]
  containers: [{ name: c, image: nginx }]
---
apiVersion: v1
kind: Pod
metadata: { name: unversioned, namespace: governed-ns }
spec: { containers: [{ name: c, image: nginx }] }
YAML
# The declaration is the Namespace (ADR-0022) and kyverno 1.18 populates `namespaceObject`
# only from a CLI values file's `namespaces:` list.
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

say "2. the report fires on the undeclared version (9.9.9) and not on the declared one"
# THE CEILING, MEASURED, NOT ASSUMED (kyverno 1.18.2, 2026-09-05). The pinned CLI evaluates a
# CEL ValidatingPolicy the same way whether `validationActions` says Audit or Deny: the same
# body under either value gives the identical verdict spread and the identical exit code, and
# `--audit-warn` changes neither (it only reaches the 2022 ClusterPolicy type). Platform's own
# shift-left/ci-check.py docstring states the same fact. So this step proves the RULE
# functionally and the ACTION structurally, in step 1; whether the API server ADMITS the pod is
# a live fact belonging to ../graded/verify-graded.sh's cluster tail. The old shape of this
# beat read the denial off the exit code, and the exit code never carried it.
out="$(kyverno apply "$WORK/orphan-guard.yaml" --resource "$WORK/pods.yaml" 2>&1 || true)"
grep -q "resource governed-ns/Pod/orphan failed" <<<"$out" \
  || fail "the orphan pod (9.9.9) was not reported -- the observation the priced hole rests on is gone"
grep -q "Nothing is denied" <<<"$out" \
  || fail "the orphan report no longer says what it does; the message must not claim a refusal"
grep -q "policy-version-orphan-cage" <<<"$out" \
  || fail "the report does not name the policy that cages the pod"
if grep -q "resource governed-ns/Pod/declared failed" <<<"$out"; then
  fail "a DECLARED version ($declared_version) was wrongly reported by the orphan-guard"
fi
grep -qE 'pass: 1, fail: 1, warn: 0, error: 0, skip: 1' <<<"$out" \
  || fail "unexpected verdict spread: $(tail -1 <<<"$out")"

say "3. the SERVED cage-tier does not reach the orphan pod at all -- why the cage exists"
kyverno apply "$SERVED" --resource "$WORK/pods.yaml" -f "$WORK/values.yaml" -o "$WORK/served" \
  >"$WORK/served.log" 2>&1 || fail "the served cage refused a pod: $(tail -3 "$WORK/served.log")"
[ -f "$WORK/served/declared-mutated.yaml" ] \
  || fail "the served cage-tier did not mutate the pod claiming its own version"
if [ -f "$WORK/served/orphan-mutated.yaml" ] \
   && grep -q 'posture.acme.io/tier' "$WORK/served/orphan-mutated.yaml"; then
  fail "the served cage-tier mutated the ORPHAN pod; the disjointness this pair rests on is gone"
fi
echo "  ok   the served $declared_version cage mutates its own claimant and skips 9.9.9 entirely"

say "4. the orphan cage puts that same pod on the bottom rung"
kyverno apply "$WORK/orphan-cage.yaml" --resource "$WORK/pods.yaml" -o "$WORK/caged" \
  >"$WORK/caged.log" 2>&1 || fail "the orphan cage refused a pod: $(tail -3 "$WORK/caged.log")"
grep -qE 'fail: 0, ' "$WORK/caged.log" || fail "the orphan cage reported a refusal: $(tail -1 "$WORK/caged.log")"
caged="$WORK/caged/orphan-mutated.yaml"
[ -f "$caged" ] || fail "the orphan cage produced no mutated pod at $caged"
for want in 'posture.acme.io/tier: isolated' 'posture.acme.io/caged: "true"' \
            'priorityClassName: cage-isolated' 'priority: -10000' 'preemptionPolicy: Never' \
            'cpu: 100m' 'memory: 64Mi' 'readOnlyRootFilesystem: true' 'privileged: false' \
            'hostNetwork: false' 'name: waf-sidecar' '- ALL'; do
  grep -q -- "$want" "$caged" || fail "the caged orphan pod is missing: $want"
done
# The initContainer is hardened too. cage-tier maps `containers` only, so without the
# extension in cage_body.py a privileged initContainer -- refused outright before this ticket
# -- would have run untouched inside the cage.
python3 - "$caged" <<'PY' || fail "the orphan pod's initContainer was not hardened"
import sys, yaml
for doc in yaml.safe_load_all(open(sys.argv[1])):
    if not doc or doc["metadata"]["name"] != "orphan":
        continue
    init = doc["spec"]["initContainers"][0]
    sc = init["securityContext"]
    assert sc["privileged"] is False, sc
    assert sc["allowPrivilegeEscalation"] is False, sc
    assert sc["readOnlyRootFilesystem"] is True and sc["runAsNonRoot"] is True, sc
    assert sc["capabilities"]["drop"] == ["ALL"], sc
    assert init["resources"]["limits"]["cpu"] == "100m", init["resources"]
    break
else:
    raise SystemExit("no mutated orphan pod found")
PY
if [ -f "$WORK/caged/declared-mutated.yaml" ] \
   && grep -q 'posture.acme.io/tier' "$WORK/caged/declared-mutated.yaml"; then
  fail "the orphan cage mutated the DECLARED-version pod; that population is the served cage's"
fi

say "5. run together over one pod per DECLARED version plus an orphan: each is touched once"
# Driven by the ARRAY, not by a fixture. One pod per version the array declares, plus one
# claiming a version it does not, and every served version's cage-tier applied beside the
# orphan cage. If the two populations ever overlapped, a pod would come out carrying one
# body's label and the other's dials -- the label-and-dials incoherence H8-03 exists to
# prevent, which is the reason a second mutating writer was ruled out in the first place.
: > "$WORK/all-pods.yaml"
SERVED_ALL=()
for v in $declared_versions; do
  slug="$(echo "$v" | tr . -)"
  cat >> "$WORK/all-pods.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata: { name: claims-$slug, namespace: governed-ns, labels: { "policy-as-versioned.dev/policy-version": "$v" } }
spec: { containers: [{ name: c, image: nginx }] }
---
YAML
  [ -f "$HERE/policies/v$v/cage-tier.yaml" ] \
    || fail "the array declares $v with no served cage-tier; that version's pods are covered by neither body"
  SERVED_ALL+=("$HERE/policies/v$v/cage-tier.yaml")
done
cat >> "$WORK/all-pods.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata: { name: claims-nothing-declared, namespace: governed-ns, labels: { "policy-as-versioned.dev/policy-version": "9.9.9" } }
spec: { containers: [{ name: c, image: nginx }] }
YAML
kyverno apply "${SERVED_ALL[@]}" "$WORK/orphan-cage.yaml" --resource "$WORK/all-pods.yaml" \
  -f "$WORK/values.yaml" -o "$WORK/array" >"$WORK/array.log" 2>&1 \
  || fail "the cages together refused a pod: $(tail -3 "$WORK/array.log")"
grep -qE 'fail: 0, ' "$WORK/array.log" \
  || fail "a refusal appeared with every served cage and the orphan cage together: $(tail -1 "$WORK/array.log")"
python3 - "$WORK/array" "$declared_versions" <<'PY' || fail "the two populations are not disjoint"
import pathlib, sys, yaml
seen = {}
for f in pathlib.Path(sys.argv[1]).glob("*-mutated.yaml"):
    for doc in yaml.safe_load_all(f.read_text()):
        if doc:
            seen[doc["metadata"]["name"]] = doc
versions = sys.argv[2].split()
for v in versions:
    name = "claims-" + v.replace(".", "-")
    d = seen.get(name)
    assert d is not None, f"{name} was not caged by any body"
    labels = d["metadata"]["labels"]
    pc = d["spec"]["priorityClassName"]
    # Its NAMESPACE's tier, from its own version's cage, and the PriorityClass that version
    # ships. Never the bottom rung: a declared version is not the orphan cage's business.
    assert labels["posture.acme.io/tier"] == "quarantine", (name, labels)
    assert pc == "cage-quarantine-" + v.replace(".", "-"), (name, pc)
for name in ("claims-nothing-declared",):
    d = seen[name]
    assert d["metadata"]["labels"]["posture.acme.io/tier"] == "isolated", d["metadata"]["labels"]
    assert d["spec"]["priorityClassName"] == "cage-isolated", d["spec"]["priorityClassName"]
print(f"    {len(versions)} declared version(s) {versions} each caged by their own served body "
      f"at the Namespace's tier; the one undeclared claim caged at the bottom rung; every pod's "
      f"label agrees with its dials, so no pod was written by both")
PY

say "5b. and on the original three-pod fixture, for the same reason"
kyverno apply "$SERVED" "$WORK/orphan-cage.yaml" --resource "$WORK/pods.yaml" \
  -f "$WORK/values.yaml" -o "$WORK/both" >"$WORK/both.log" 2>&1 \
  || fail "the two cages together refused a pod: $(tail -3 "$WORK/both.log")"
grep -qE 'fail: 0, ' "$WORK/both.log" || fail "a refusal appeared when both cages ran: $(tail -1 "$WORK/both.log")"
python3 - "$WORK/both" "$declared_version" <<'PY' || fail "the two cages are not disjoint"
import pathlib, sys, yaml
seen = {}
for f in pathlib.Path(sys.argv[1]).glob("*-mutated.yaml"):
    for doc in yaml.safe_load_all(f.read_text()):
        if doc:
            seen[doc["metadata"]["name"]] = doc
# The declared pod takes its NAMESPACE's tier (quarantine); the orphan takes the bottom rung.
# If the two bodies contended, one of these would carry the other's dials -- the pod labelled
# `isolated` while carrying `cage-baseline`'s PriorityClass that ruled out a second writer.
d, o = seen["declared"], seen["orphan"]
assert d["metadata"]["labels"]["posture.acme.io/tier"] == "quarantine", d["metadata"]["labels"]
# The SERVED class is version-suffixed (cage-quarantine-4-0-0); the machinery's is not, and
# the machinery renders its own unsuffixed cage-isolated for exactly that reason.
assert d["spec"]["priorityClassName"] == f"cage-quarantine-{sys.argv[2]}".replace(".", "-"), \
    d["spec"]["priorityClassName"]
assert o["metadata"]["labels"]["posture.acme.io/tier"] == "isolated", o["metadata"]["labels"]
assert o["spec"]["priorityClassName"] == "cage-isolated", o["spec"]["priorityClassName"]
assert "unversioned" not in seen or "posture.acme.io/tier" not in (
    seen["unversioned"]["metadata"].get("labels") or {}), "an unversioned pod was caged here"
print("    declared -> quarantine/cage-quarantine (its Namespace's tier); "
      "orphan -> isolated/cage-isolated (the bottom rung); label and dials agree in both")
PY

echo "PASS: the orphan pair refuses nothing and leaves nothing uncaged. The guard is Audit and reports 9.9.9 by name; the SERVED $declared_version cage-tier does not match that pod at all, which is why the cage exists; the cage puts it on the bottom rung with the isolated dials, hardened containers AND initContainers, host namespaces shut and all capabilities dropped; and run together over one pod per declared version plus an undeclared claim, every pod is written by exactly one body with its label agreeing with its dials -- disjointness proved from the array, not asserted. The allow-list is still the array, in both halves. Whether the API server admits any of it is the cluster tail of ../graded/verify-graded.sh, not this run."
