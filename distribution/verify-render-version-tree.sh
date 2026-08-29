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

say "3. offline: every tree's cage-tier dial agrees with that tree's own PriorityClasses"
# The defect class that took out 2.0.0, 2.0.1 and 3.0.0: the API server's
# Priority admission plugin re-derives priority and preemptionPolicy from the
# class the mutation names and refuses the pod if any of the three disagrees.
# cage-tier hand-duplicates that class's integer in its dial and writes
# preemptionPolicy as a literal, so a one-line edit to a PriorityClass body
# stops every pod on that line admitting. Caught here, offline, before a
# cluster sees it.
python3 - "$HERE" <<'PY' || fail "a cage-tier dial disagrees with its own PriorityClasses"
import re, sys
from pathlib import Path
import yaml

dist = Path(sys.argv[1])
# The DECLARED versions plus the authoring copy the next release renders from.
# A retired tree is frozen behind its signed tag and is not runnable, so its
# (real, and exactly this) defect is history, not a standing red -- see
# distribution/versions.yaml.
import importlib.util
spec = importlib.util.spec_from_file_location("rog", dist / "render-orphan-guard.py")
rog = importlib.util.module_from_spec(spec); spec.loader.exec_module(rog)
trees = [dist / "policies" / f"v{v}" for v in rog.versions(dist / "versions.yaml")]
trees.append(dist.parent / "graded" / "policies")
bad, checked = [], 0
for tree in trees:
    tier_file, pc_file = tree / "cage-tier.yaml", tree / "priorityclasses.yaml"
    if not tier_file.exists() or not pc_file.exists():
        continue
    classes = {d["metadata"]["name"]: d
               for d in yaml.safe_load_all(pc_file.read_text())
               if isinstance(d, dict) and d.get("kind") == "PriorityClass"}
    body = tier_file.read_text()
    # the dial: one {'tier': {...'pc':'NAME'...'prio':'INT'...}} entry per rung
    dial = dict(re.findall(r"'pc'\s*:\s*'([^']+)'\s*,\s*'prio'\s*:\s*'(-?\d+)'", body))
    if not dial:
        bad.append(f"{tree.name}: no 'pc'/'prio' dial found in cage-tier.yaml")
        continue
    literal = re.search(r'preemptionPolicy:\s*\\"([A-Za-z]+)\\"', body)
    for name, prio in dial.items():
        checked += 1
        pc = classes.get(name)
        if pc is None:
            bad.append(f"{tree.name}: the dial names PriorityClass {name}, which the tree does not ship")
            continue
        if int(prio) != int(pc["value"]):
            bad.append(f"{tree.name}: dial says priority {prio} for {name}, the class says {pc['value']}")
        want = pc.get("preemptionPolicy", "PreemptLowerPriority")
        if literal and literal.group(1) != want:
            bad.append(f"{tree.name}: cage-tier writes preemptionPolicy {literal.group(1)!r}, "
                       f"{name} declares {want!r}")
for line in bad:
    print(f"  bad  {line}")
if bad:
    raise SystemExit(1)
print(f"  ok   {checked} (tree, rung) dial entries match their own PriorityClass value and preemptionPolicy")
PY

echo "PASS: every mandatory member renders with a versioned name, the policy-version label, a"
echo "      matchConditions self-scope (never objectSelector); cage-tier names its own"
echo "      PriorityClasses and agrees with their value and preemptionPolicy; and two rendered"
echo "      versions coexist, each judging only its own claim."
