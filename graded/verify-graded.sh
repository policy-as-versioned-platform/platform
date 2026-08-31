#!/usr/bin/env bash
# Beat: "A workload keeps running but CAGED BY DEGREE, never denied — the tier is
# declared on its NAMESPACE and rendered onto every pod, the cage only ever
# tightens, the bottom rung `isolated` runs and reaches nothing, and the cage's
# run-cost is booked to TCoR." Exits non-zero if the beat would fail on stage;
# exits 3 if a live half genuinely could not be looked at.
#
# OFFLINE core (always; needs `kyverno` + python3):
#   1. cage.py selfcheck: tiers->dials deterministic over the whole ladder; the £
#      picks the tier and clamps to the adopter's floor; the bottom rung is
#      `isolated`, never Deny; TCoR is booked as residual (R'>0) +
#      cost-of-controls (C_cage>0).
#   2. cage-tier MUTATE test, with the Namespace supplied through a CLI values
#      file: one governed namespace per rung renders that rung's dials; a
#      governed namespace with NO tier renders `isolated`, never `baseline`; a
#      pod that FORGED a tier label has it clobbered from the Namespace; a pod
#      that declared readOnlyRootFilesystem TRUE keeps it at baseline. A pod
#      claiming NO policy version at all (system/COTS) is out of scope, skipped.
#   3. cage-netpol GENERATE test: per-tier reach. baseline generates nothing
#      (normal reach); restricted/quarantine get DNS-only egress; isolated gets
#      policyTypes Ingress AND Egress with no rules — nothing in, nothing out.
#   4. drift guard: the Kyverno tier->dials map mirrors cage.py's TIERS table
#      exactly, over the WHOLE ladder, and every tier's `prio` equals its
#      PriorityClass's real `value:` — the pair without which the API server's
#      Priority admission plugin refuses every caged pod outright.
#   5. the eviction PriorityClasses are valid, ordered tighter = lower, and every
#      one is `preemptionPolicy: Never` (the third field that plugin derives).
#   6. TIGHTEN-ONLY at every rung: a pod that declared readOnlyRootFilesystem and
#      runAsNonRoot TRUE keeps both TRUE at baseline, restricted, quarantine and
#      isolated; a pod that declared a cpu/memory ceiling TIGHTER than its tier's
#      dial keeps its own (the dials are a MIN); `privileged` is written false in
#      the same securityContext as allowPrivilegeEscalation; the host namespaces
#      are clobbered shut. Before ticket 26 baseline wrote `false` over a pod's
#      `true`; before the 2026-08-28 review the cage raised a declared 50m/32Mi
#      ceiling tenfold and left hostNetwork alone.
#   7. the reach table agrees with cage.py's own `reach` column; every rung that
#      does not reach the cluster is generated on every trigger, and synchronize
#      is off, so a tier move creates and deletes nothing.
# LIVE tail (only if a cluster with the policies is reachable; bounded):
#   8. cage-tier + cage-netpol installed for every declared version; a REAL pod
#      (not a dry-run) is created in a caged Namespace, is ADMITTED, reaches
#      Running, and carries the tier's PriorityClass, the tier's dials, the tier
#      clobbered from its Namespace, and its own declared hardening untouched;
#      a governed Namespace with no tier renders `isolated`, RUNS, and CANNOT
#      CONNECT to the API server or to the internet (an exec and a TCP connect,
#      never a read of the NetworkPolicy's own YAML), while the baseline pod
#      reaches both normally; an UPDATE to a running isolated pod is accepted;
#      both cluster-wide guards are installed and really refuse an undeclared
#      version and an unclaimed pod; and every rung's reach cage is still there
#      at the end of the run.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${CLUSTER:-driftwood}"; CTX="${CTX:-kind-$CLUSTER}"
. "$HERE/../lib.sh"   # substrate_ok / live_tail_skip / pass_line: three outcomes per live tail
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have python3 || fail "python3 required"
have kyverno || fail "kyverno CLI required for the offline cage proofs"

say "1. offline: the £ engine — the whole ladder, £ picks the tier, floor clamps, TCoR booked"
python3 "$HERE/cage.py" selfcheck || fail "cage.py selfcheck failed"

say "2. offline: the NAMESPACE declares the tier; a governed ns with no tier falls closed to isolated; a forged pod label is clobbered; a declared 'true' survives"
kyverno test "$HERE/tests/cage-tier" >/dev/null || fail "cage-tier mutate matrix failed"

say "3. offline: reach is generated PER TIER (baseline normal, restricted/quarantine DNS-only, isolated nothing)"
kyverno test "$HERE/tests/cage-netpol" >/dev/null || fail "cage-netpol per-tier reach matrix failed"

say "4. offline: the Kyverno tier->dials map mirrors cage.py's TIERS (no drift), priority pair included"
python3 - "$HERE" <<'PY'
import sys, os, re, yaml
here = sys.argv[1]
sys.path.insert(0, here)
import cage
pol_text = open(os.path.join(here, "policies/cage-tier.yaml")).read()
pcs = {o["metadata"]["name"]: o
       for o in yaml.safe_load_all(open(os.path.join(here, "policies/priorityclasses.yaml"))) if o}
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)

for tier in cage.ORDER:
    d = cage.TIERS[tier]
    # The map row for this tier, e.g. "'restricted':{'cpu':'250m','mem':'128Mi','pc':'cage-restricted',...}"
    m = re.search(r"'%s':\s*\{([^}]*)\}" % tier, pol_text)
    check(m is not None, f"{tier}: present in the Kyverno dial map")
    if not m: continue
    row = m.group(1)
    check(f"'cpu':'{d['cpu']}'" in row, f"{tier}: cpu {d['cpu']} matches cage.py")
    check(f"'mem':'{d['mem']}'" in row, f"{tier}: mem {d['mem']} matches cage.py")
    check(f"'pc':'{d['priorityClass']}'" in row, f"{tier}: PriorityClass {d['priorityClass']} matches cage.py")
    # harden flag = dropAll && readOnlyRootFs; the map encodes it as 'harden':'true'|'false'
    harden = "true" if (d["dropAll"] and d["readOnlyRootFs"]) else "false"
    check(f"'harden':'{harden}'" in row, f"{tier}: harden={harden} matches cage.py dropAll/readOnlyRootFs")
    # WAF present iff cage.py waf != none; map uses wafCpu '0' as the no-WAF sentinel
    waf_off = "'wafCpu':'0'" in row
    check(waf_off == (d["waf"] == "none"), f"{tier}: WAF presence matches cage.py waf={d['waf']}")
    # THE PRIORITY PAIR. The mutation writes spec.priority alongside
    # priorityClassName because the API server's Priority admission plugin
    # refuses a pod whose two disagree. `prio` must therefore be the class's
    # OWN value, read from the real priorityclasses.yaml -- never a literal
    # anyone can retype.
    prio = re.search(r"'prio':'(-?\d+)'", row)
    check(prio is not None, f"{tier}: dial map carries a 'prio' (the priority pair's other half)")
    pc = pcs.get(d["priorityClass"])
    check(pc is not None, f"{tier}: PriorityClass {d['priorityClass']} is defined in priorityclasses.yaml")
    if prio and pc:
        check(int(prio.group(1)) == pc["value"],
              f"{tier}: prio {prio.group(1)} == PriorityClass {d['priorityClass']} value {pc['value']}")

# The third field the same plugin derives from the class.
check('preemptionPolicy: "Never"' in pol_text,
      "the mutation writes preemptionPolicy: Never (the plugin derives it from the class too)")

# The bottom rung's own dials, straight off cage.py: `isolated` IS quarantine
# plus no reach and first eviction, and the policy must name its PriorityClass.
check(cage.TIERS["isolated"]["reach"] == "none" and cage.TIERS["isolated"]["evictFirst"],
      "cage.py: isolated reaches nothing and is evicted first")
check("'pc':'cage-isolated'" in pol_text, "the dial map names the isolated rung's PriorityClass")

if fails: sys.exit(f"\n{len(fails)} drift(s) between cage.py and cage-tier.yaml")
print("  -- cage.py and the Kyverno cage are in step, priority pair included --")
PY

say "5. offline: eviction PriorityClasses valid, ordered (tighter tier = lower value), never preempting"
python3 - "$HERE" <<'PY'
import sys, os, yaml
here = sys.argv[1]
sys.path.insert(0, here)
import cage
pcs = {o["metadata"]["name"]: o
       for o in yaml.safe_load_all(open(os.path.join(here, "policies/priorityclasses.yaml"))) if o}
order = [cage.TIERS[t]["priorityClass"] for t in cage.ORDER]  # loosest -> tightest, from cage.py
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)
for n in order:
    check(n in pcs, f"{n} PriorityClass defined")
vals = [pcs[n]["value"] for n in order if n in pcs]
check(all(v < 0 for v in vals), "every cage sits below the default priority (0)")
check(vals == sorted(vals, reverse=True),
      "tighter tier = lower value (baseline > restricted > quarantine > isolated)")
check(all(pcs[n].get("preemptionPolicy") == "Never" for n in order if n in pcs),
      "every cage PriorityClass is preemptionPolicy: Never (what the mutation writes)")
if fails: sys.exit(f"\n{len(fails)} PriorityClass invariant(s) broken")
print(f"  -- eviction ordering holds: {' > '.join(f'{n}({v})' for n, v in zip(order, vals))} --")
PY

say "6. offline: TIGHTEN-ONLY at every rung — a pod that declared readOnlyRootFilesystem/runAsNonRoot true keeps them"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
python3 - "$HERE" "$WORK" <<'PY'
import sys, os, yaml
here, work = sys.argv[1], sys.argv[2]
sys.path.insert(0, here)
import cage
ns, pods = [], []
for tier in cage.ORDER:
    ns.append({"apiVersion": "v1", "kind": "Namespace",
               "metadata": {"name": f"tighten-{tier}",
                            "labels": {"policy-as-versioned.dev/governed": "true",
                                       "posture.acme.io/tier": tier}}})
    pods.append({"apiVersion": "v1", "kind": "Pod",
                 "metadata": {"name": f"declared-strict-{tier}", "namespace": f"tighten-{tier}",
                              "labels": {"policy-as-versioned.dev/policy-version": "1.0.0"}},
                 "spec": {"containers": [{"name": "app", "image": "nginx",
                          "resources": {"limits": {"cpu": "5m", "memory": "8Mi"}},
                          "securityContext": {"readOnlyRootFilesystem": True,
                                              "runAsNonRoot": True}}]}})
open(os.path.join(work, "values.yaml"), "w").write(yaml.safe_dump(
    {"apiVersion": "cli.kyverno.io/v1alpha1", "kind": "Values", "namespaces": ns}))
open(os.path.join(work, "pods.yaml"), "w").write(yaml.safe_dump_all(pods))
PY
OUT="$(kyverno apply "$HERE/policies/cage-tier.yaml" --resource "$WORK/pods.yaml" -f "$WORK/values.yaml" 2>&1)" \
  || fail "kyverno apply refused the tighten-only fixture: $OUT"
printf '%s\n' "$OUT" > "$WORK/out.txt"
python3 - "$HERE" "$WORK/out.txt" <<'PY'
import sys, re, yaml
here, out_file = sys.argv[1], sys.argv[2]
sys.path.insert(0, here)
import cage
txt = open(out_file).read()
blocks = re.split(r"^policy cage-tier applied to .*?:$", txt, flags=re.M)[1:]
seen = {}
for b in blocks:
    d = yaml.safe_load(b.split("\n---\n")[0])
    if d: seen[d["metadata"]["name"]] = d
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)
for tier in cage.ORDER:
    d = seen.get(f"declared-strict-{tier}")
    check(d is not None, f"{tier}: the declared-strict pod was mutated (not refused)")
    if not d: continue
    sc = d["spec"]["containers"][0].get("securityContext", {})
    check(sc.get("readOnlyRootFilesystem") is True,
          f"{tier}: readOnlyRootFilesystem stayed true (declared true, cage did not loosen it)")
    check(sc.get("runAsNonRoot") is True,
          f"{tier}: runAsNonRoot stayed true (declared true, cage did not loosen it)")
    check(sc.get("allowPrivilegeEscalation") is False,
          f"{tier}: allowPrivilegeEscalation written false (the tight end of that field)")
    check(sc.get("privileged") is False,
          f"{tier}: privileged written false in the SAME securityContext (the pair the API server validates)")
    lim = d["spec"]["containers"][0].get("resources", {}).get("limits", {})
    check(lim.get("cpu") == "5m" and lim.get("memory") == "8Mi",
          f"{tier}: the pod's own 5m/8Mi ceiling survived (the dials are a MIN, not an overwrite); got {lim}")
    check(d["spec"].get("hostNetwork") is False and d["spec"].get("hostPID") is False
          and d["spec"].get("hostIPC") is False,
          f"{tier}: hostNetwork/hostPID/hostIPC are all clobbered shut")
if fails: sys.exit(f"\n{len(fails)} tighten-only violation(s): the cage wrote a field LOOSER than the pod declared")
print("  -- the cage is tighten-only at every rung --")
PY

say "7. offline: per-tier reach agrees with cage.py's own reach column"
python3 - "$HERE" <<'PY'
import sys, os, re, yaml
here = sys.argv[1]
sys.path.insert(0, here)
import cage
np = yaml.safe_load(open(os.path.join(here, "policies/cage-netpol.yaml")))
spec = np["spec"]
gate = next(c["expression"] for c in spec["matchConditions"] if c["name"] == "tier-restricts-reach")
m = re.search(r"orValue\('([a-z]+)'\)\s*!=\s*'([a-z]+)'", gate)
gen = " ".join(g["expression"] for g in spec["generate"])
reach_var = next(v["expression"] for v in spec["variables"] if v["name"] == "reach")
fails = []
def check(c, m):
    if not c: fails.append(m)
    print(("  ok   " if c else "  FAIL ") + m)

# baseline: cage.py says reach 'cluster' -> nothing is generated for it at all.
check(cage.TIERS["baseline"]["reach"] == "cluster", "cage.py: baseline reaches the cluster normally")
check(m is not None, "the reach gate excludes one named tier (a probeable != predicate)")
unrestricted = {t for t in cage.ORDER if cage.TIERS[t]["reach"] == "cluster"}
check(m is not None and {m.group(2)} == unrestricted,
      f"the ONLY rung excluded from reach generation is the one cage.py gives full "
      f"cluster reach: {sorted(unrestricted)}")
check(m is not None and m.group(1) == m.group(2),
      "an absent tier label defaults to that same rung, so a label-less pod is not "
      "silently given a cage it was never assigned")
# isolated: cage.py says reach 'none' -> empty ingress AND empty egress, both policyTypes set.
check(cage.TIERS["isolated"]["reach"] == "none", "cage.py: isolated reaches nothing")
check("'ingress': dyn([]), 'egress': dyn([])" in reach_var,
      "isolated generates EMPTY ingress and EMPTY egress rule lists (deny-all both ways)")
check('"policyTypes": dyn(["Ingress", "Egress"])' in gen,
      "both policyTypes are set, so empty rule lists really are a deny-all")
# restricted/quarantine: cage.py says namespace-scoped -> DNS-only egress, same-ns ingress.
for t in ("restricted", "quarantine"):
    check(cage.TIERS[t]["reach"].startswith("namespace"), f"cage.py: {t} reach is namespace-scoped")
check('"port": dyn(53)' in reach_var and '"kubernetes.io/metadata.name": dyn("kube-system")' in reach_var,
      "the non-isolated rungs egress to DNS (UDP/53, kube-system) and nothing else")
check(spec["evaluation"]["synchronize"]["enabled"] is False,
      "synchronize is OFF: all three restricting rungs are generated up front, so a tier "
      "move creates and deletes nothing (leaving it on deleted OTHER namespaces' reach cages)")
rungs = next(v["expression"] for v in spec["variables"] if v["name"] == "rungs")
check(sorted(t for t in cage.ORDER if cage.TIERS[t]["reach"] != "cluster") ==
      sorted(x.strip().strip("'") for x in rungs.strip("[] \n").split(",")),
      "every rung cage.py says does NOT reach the cluster is generated on every trigger, "
      "so a tier move is a label change with no create and no delete in its path")
if fails: sys.exit(f"\n{len(fails)} reach mismatch(es) between cage.py and cage-netpol.yaml")
print("  -- reach is generated from the tier and matches cage.py --")
PY
cat <<'GAP'
  CLOSED 2026-08-28 (was: the synchronize delete-then-regenerate gap). All three
  restricting rungs are now generated into the namespace at once and synchronize
  is off, so a TIER MOVE is a label change on the pod: the NetworkPolicy for the
  rung it moves to is already there, and nothing is deleted. That also closes the
  much worse bug the review found live -- Kyverno 1.18's GeneratingPolicy watcher
  deleted every cage-reach-* NetworkPolicy in EVERY namespace whenever one caged
  pod was created anywhere, and regenerated only the trigger's own.
  WHAT IS LEFT, named not closed: generation is a BACKGROUND controller, so the
  reach cage lands one round-trip AFTER the pod is admitted (about 10s on KinD).
  A brand-new governed namespace's first caged pod therefore has full reach for
  that window. Upgrade path: render the three NetworkPolicies per governed
  Namespace from the composed artefact, so Flux has them in place before any pod
  is admitted (tickets 40/42).
GAP

# ---- live tail: only if a cluster actually has the cage policies installed ----
# up.sh only ever applies VERSIONED copies (cage-tier-1-0-0, ...), never the
# unversioned authoring name -- so the gate and the existence checks below
# must look for the versioned names too, the same way
# distribution/verify-coexistence.sh checks require-nonroot-$v. Versions come
# from render-orphan-guard.py's versions() (distribution/versions.yaml), the
# one array, reused -- never re-parsed here.
if ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif ! timeout 10 kubectl --context "$CTX" get mutatingpolicy >/dev/null 2>&1; then
  live_tail_skip "Kyverno MutatingPolicy CRD not installed on $CTX (run engine/up.sh then graded/up.sh)"
else
  say "8. live: a REAL pod in a caged Namespace is admitted, RUNS, and wears its Namespace's cage"
  while IFS= read -r v; do
    timeout 10 kubectl --context "$CTX" get mutatingpolicy "cage-tier-$v" >/dev/null 2>&1 \
      || fail "cage-tier-$v MutatingPolicy not installed live"
    timeout 10 kubectl --context "$CTX" get generatingpolicy "cage-netpol-$v" >/dev/null 2>&1 \
      || fail "cage-netpol-$v GeneratingPolicy not installed live"
  done < <(python3 - "$HERE" <<'PY'
import sys
from pathlib import Path
import importlib.util
dist = Path(sys.argv[1]).parent / "distribution"
spec = importlib.util.spec_from_file_location("render_orphan_guard", dist / "render-orphan-guard.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for v in mod.versions(dist / "versions.yaml"):
    print(v.replace(".", "-"))
PY
)
  # The newest declared version is the one the current authoring copy rendered
  # to, so it is the copy whose behaviour this tail is entitled to assert.
  #
  # 2026-08-29 review: that is a correct statement about AUTHORSHIP and a wrong
  # one about RISK. Every version in the array is installed and selectable by
  # any pod, so the array's weakest member is the estate's actual cage -- and
  # the behavioural probes below (forged tier clobbered, untiered falls closed,
  # tighten-only, host namespaces) only ever ran against NEWEST. The array
  # holds exactly one version today, so NEWEST IS the whole array and the gap
  # is closed by arithmetic; if a second is ever declared, this says so rather
  # than quietly grading a quarter of the surface.
  # ponytail: the honest upgrade is a per-version expectation table and a loop.
  # Add it the day a second line is declared; until then it would be untestable
  # code with no second line to run against.
  DECLARED_COUNT="$(python3 - "$HERE" <<'PY'
import sys
from pathlib import Path
import importlib.util
dist = Path(sys.argv[1]).parent / "distribution"
spec = importlib.util.spec_from_file_location("render_orphan_guard", dist / "render-orphan-guard.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(len(mod.versions(dist / "versions.yaml")))
PY
)"
  if [ "$DECLARED_COUNT" -gt 1 ]; then
    live_tail_skip "distribution/versions.yaml declares $DECLARED_COUNT versions and the behavioural probes below only exercise the newest; every declared version is installed and selectable by any pod, so the others are ungraded here and this tail may not claim the cage holds for them"
  fi
  NEWEST="$(python3 - "$HERE" <<'PY'
import sys
from pathlib import Path
import importlib.util
dist = Path(sys.argv[1]).parent / "distribution"
spec = importlib.util.spec_from_file_location("render_orphan_guard", dist / "render-orphan-guard.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(mod.versions(dist / "versions.yaml")[-1])
PY
)"
  echo "  -- the live copy under test is cage-tier-${NEWEST//./-}, applied by graded/up.sh from"
  echo "     distribution/policies/v$NEWEST (render-and-prove.py). Flux is NOT in the loop on"
  echo "     this path, so 'in force' below means installed and enforcing, never 'reconciled'."

  BASE_NS="cage-verify-baseline"; UNTIERED_NS="cage-verify-untiered"
  # --wait=true, not --wait=false: two runs inside one namespace-deletion window
  # made the SECOND run fail with "namespace is being terminated" and blame the
  # Priority admission plugin, which it had not observed (review, 2026-08-28).
  cleanup_live() {
    timeout 180 kubectl --context "$CTX" delete ns "$BASE_NS" "$UNTIERED_NS" \
      --ignore-not-found --wait=true >/dev/null 2>&1 || true
  }
  trap 'rm -rf "$WORK"; cleanup_live' EXIT
  cleanup_live

  # A governed Namespace that declares `baseline`, and one that declares NOTHING.
  timeout 20 kubectl --context "$CTX" apply -f - >/dev/null <<YAML || fail "could not create the probe namespaces on $CTX"
apiVersion: v1
kind: Namespace
metadata:
  name: $BASE_NS
  labels: { "policy-as-versioned.dev/governed": "true", "posture.acme.io/tier": "baseline" }
---
apiVersion: v1
kind: Namespace
metadata:
  name: $UNTIERED_NS
  labels: { "policy-as-versioned.dev/governed": "true" }
YAML

  # The pod FORGES `quarantine` on itself and declares readOnlyRootFilesystem
  # true. Both matter: the forged tier must be clobbered to `baseline` from the
  # Namespace, and the declared `true` must survive the loosest rung.
  # The probe image is the WAF placeholder graded/up.sh builds and `kind load`s:
  # a busybox with a shell, so the reach assertions below are a CONNECTION and
  # not a read of the NetworkPolicy's own YAML (review, 2026-08-28).
  PROBE_IMAGE="ghcr.io/acme/coraza-waf:cage"
  cat > "$WORK/probes.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: cage-probe
  namespace: $BASE_NS
  labels:
    policy-as-versioned.dev/policy-version: "$NEWEST"
    posture.acme.io/tier: quarantine
spec:
  containers:
    - name: app
      image: $PROBE_IMAGE
      securityContext: { readOnlyRootFilesystem: true }
---
apiVersion: v1
kind: Pod
metadata:
  name: cage-probe-untiered
  namespace: $UNTIERED_NS
  labels:
    policy-as-versioned.dev/policy-version: "$NEWEST"
spec:
  containers:
    - name: app
      image: $PROBE_IMAGE
YAML
  ERR="$(timeout 30 kubectl --context "$CTX" apply -f "$WORK/probes.yaml" 2>&1 >/dev/null || true)"
  [ -z "$ERR" ] || fail "a pod was REFUSED in a caged Namespace on $CTX — the cage denied a workload: $ERR"
  echo "  ok   both pods were ADMITTED (created for real, not a dry-run) — nothing was denied"

  timeout 120 kubectl --context "$CTX" -n "$BASE_NS" wait --for=condition=Ready pod/cage-probe >/dev/null 2>&1 \
    || fail "the caged pod was admitted but never became Ready on $CTX"
  echo "  ok   the caged pod is RUNNING — a cage is not a refusal"

  # A here-string, not a process substitution: `kubectl -o jsonpath` emits no
  # trailing newline, so `read` would return non-zero and `set -e` would kill the
  # script mid-tail with no message at all.
  read -r PHASE PC PRIO PREEMPT TIER CAGED ROFS <<<"$(timeout 20 kubectl --context "$CTX" -n "$BASE_NS" \
    get pod cage-probe -o jsonpath='{.status.phase} {.spec.priorityClassName} {.spec.priority} {.spec.preemptionPolicy} {.metadata.labels.posture\.acme\.io/tier} {.metadata.labels.posture\.acme\.io/caged} {.spec.containers[0].securityContext.readOnlyRootFilesystem}')"
  [ "$PHASE" = "Running" ] || fail "the caged pod is $PHASE, not Running"
  [ "$PC" = "cage-baseline-${NEWEST//./-}" ] \
    || fail "the caged pod carries PriorityClass '$PC', not its tier's cage-baseline-${NEWEST//./-}"
  [ "$PRIO" = "-10" ] || fail "the caged pod carries priority '$PRIO', not the class's own -10"
  [ "$PREEMPT" = "Never" ] || fail "the caged pod carries preemptionPolicy '$PREEMPT', not Never"
  echo "  ok   it wears its tier's PriorityClass and the matching priority: $PC / $PRIO / $PREEMPT"
  [ "$TIER" = "baseline" ] \
    || fail "the pod forged 'quarantine' and came out '$TIER' — the Namespace's tier did not clobber the pod label"
  [ "$CAGED" = "true" ] || fail "the caged label was not stamped (caged='$CAGED')"
  echo "  ok   the forged pod label was CLOBBERED to the Namespace's tier: $TIER (caged=$CAGED)"
  [ "$ROFS" = "true" ] \
    || fail "the pod declared readOnlyRootFilesystem=true and the baseline cage wrote '$ROFS' over it — a loosening"
  echo "  ok   the pod's own readOnlyRootFilesystem=true survived the loosest rung (tighten-only)"

  read -r ITIER IPC <<<"$(timeout 20 kubectl --context "$CTX" -n "$UNTIERED_NS" \
    get pod cage-probe-untiered -o jsonpath='{.metadata.labels.posture\.acme\.io/tier} {.spec.priorityClassName}')"
  [ "$ITIER" = "isolated" ] \
    || fail "a governed Namespace with NO tier rendered '$ITIER', not 'isolated' — the cage failed OPEN"
  [ "$IPC" = "cage-isolated-${NEWEST//./-}" ] \
    || fail "the isolated pod carries PriorityClass '$IPC', not the first-eviction cage-isolated-${NEWEST//./-}"
  echo "  ok   a governed Namespace with no tier fell CLOSED to $ITIER on the first-eviction class $IPC"

  # The isolated rung's reach, generated live. GeneratingPolicy runs through a
  # background controller, so poll rather than read once.
  for _ in $(seq 1 30); do
    timeout 10 kubectl --context "$CTX" -n "$UNTIERED_NS" get networkpolicy cage-reach-isolated >/dev/null 2>&1 && break
    sleep 2
  done
  REACH="$(timeout 20 kubectl --context "$CTX" -n "$UNTIERED_NS" get networkpolicy cage-reach-isolated \
           -o jsonpath='{.spec.policyTypes}|{.spec.ingress}|{.spec.egress}' 2>/dev/null || true)"
  [ -n "$REACH" ] || fail "no cage-reach-isolated NetworkPolicy was generated in $UNTIERED_NS — the bottom rung has no reach projection"
  [ "$REACH" = '["Ingress","Egress"]||' ] \
    || fail "the isolated reach is not a deny-all: policyTypes|ingress|egress = '$REACH'"
  echo "  ok   the isolated rung reaches NOTHING: policyTypes Ingress+Egress, no rules either way"

  BASE_NP="$(timeout 20 kubectl --context "$CTX" -n "$BASE_NS" get networkpolicy -o name 2>/dev/null | tr -d '\n')"
  [ -z "$BASE_NP" ] \
    || fail "baseline reaches normally, but a NetworkPolicy was generated for it: $BASE_NP"
  echo "  ok   baseline reaches normally — no NetworkPolicy generated for it at all"

  # ---- the bottom rung, OBSERVED as a connection and not as a YAML shape ----
  # Until 2026-08-28 the two lines above were the whole reach proof: a jsonpath
  # read of the policy's own spec, compared to a literal. That shape passed while
  # a host-network pod walked out of the cage and while the reach policies of
  # every OTHER namespace had just been deleted by this very run.
  timeout 180 kubectl --context "$CTX" -n "$UNTIERED_NS" wait --for=condition=Ready \
    pod/cage-probe-untiered >/dev/null 2>&1 \
    || fail "the ISOLATED pod never became Ready on $CTX — the bottom rung must RUN, not just be admitted (is $PROBE_IMAGE loaded? graded/up.sh builds and kind-loads it)"
  echo "  ok   the ISOLATED pod is RUNNING too — the bottom rung runs, observed and not assumed"

  reach_rc() {  # <ns> <pod> <host> <port> -> 0 reachable, non-zero not
    timeout 30 kubectl --context "$CTX" -n "$1" exec "$2" -c app -- \
      sh -c "nc -w 4 -z $3 $4" >/dev/null 2>&1
  }
  APISERVER_IP="$(timeout 20 kubectl --context "$CTX" -n default get svc kubernetes \
    -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
  [ -n "$APISERVER_IP" ] || fail "could not read the kubernetes Service ClusterIP on $CTX"
  # The NetworkPolicy is GENERATED by a background controller and then has to be
  # programmed by the CNI, so poll for "cannot reach" rather than reading once —
  # a single early read would observe the admission-to-reach-cage window (named
  # in the GAP block above) and call it a failure of the cage.
  caged_off() {  # <host> <port>: 0 once the isolated pod can no longer connect
    local i; for i in $(seq 1 20); do
      reach_rc "$UNTIERED_NS" cage-probe-untiered "$1" "$2" || return 0
      sleep 3
    done
    return 1
  }
  caged_off "$APISERVER_IP" 443 \
    || fail "the isolated pod still REACHED the API server at $APISERVER_IP:443 after 60s — the bottom rung is not a cage"
  caged_off 1.1.1.1 80 \
    || fail "the isolated pod still REACHED 1.1.1.1:80 after 60s — the bottom rung is not a cage" 
  echo "  ok   the isolated pod CANNOT connect to the API server or to the internet (a connection, not a YAML read)"
  if ! reach_rc "$BASE_NS" cage-probe "$APISERVER_IP" 443; then
    fail "the BASELINE pod could not reach the API server — baseline is a nudge and must reach normally"
  fi
  echo "  ok   the BASELINE pod reaches the API server normally — the tier, not the cage, decides reach"

  # ---- the cage may never be a refusal on UPDATE either --------------------
  # Every update to a pod at a hardened rung used to fail admission with
  # `.spec.containers: duplicate entries for key [name="waf-sidecar"]`.
  UERR="$(timeout 30 kubectl --context "$CTX" -n "$UNTIERED_NS" label pod cage-probe-untiered \
          cage-verify=update 2>&1 >/dev/null || true)"
  [ -z "$UERR" ] || fail "an UPDATE to a running isolated pod was REFUSED — the cage denied a workload: $UERR"
  echo "  ok   a running isolated pod accepts an UPDATE (kubectl label) — the mutation is idempotent"

  # ---- neither guard may be offline-only (review, 2026-08-28) -------------
  for g in policy-version-orphan-guard governed-namespace-requires-claim; do
    timeout 10 kubectl --context "$CTX" get validatingpolicy "$g" >/dev/null 2>&1 \
      || fail "$g is not installed on $CTX — an offline-only proof of an admission control is not a proof (graded/up.sh applies it)"
  done
  OERR="$(timeout 30 kubectl --context "$CTX" -n "$UNTIERED_NS" run cage-probe-orphan \
          --image="$PROBE_IMAGE" --restart=Never \
          --labels="policy-as-versioned.dev/policy-version=9.9.9" 2>&1 >/dev/null || true)"
  grep -q "policy-version-orphan-guard" <<<"$OERR" \
    || fail "a pod claiming the UNDECLARED version 9.9.9 was not refused by the orphan guard: ${OERR:-it was admitted}"
  echo "  ok   a pod claiming an undeclared version is refused live by the orphan guard"
  CERR="$(timeout 30 kubectl --context "$CTX" -n "$UNTIERED_NS" run cage-probe-noclaim \
          --image="$PROBE_IMAGE" --restart=Never 2>&1 >/dev/null || true)"
  grep -q "governed-namespace-requires-claim" <<<"$CERR" \
    || fail "a pod with NO policy-version claim was admitted uncaged in a governed Namespace: ${CERR:-it was admitted}"
  echo "  ok   a pod with no claim at all is refused live in a governed Namespace — silence is not an exemption"

  # ---- the regression guard for the bug this run used to CAUSE -------------
  for ns in "$UNTIERED_NS"; do
    for rung in restricted quarantine isolated; do
      timeout 10 kubectl --context "$CTX" -n "$ns" get networkpolicy "cage-reach-$rung" >/dev/null 2>&1 \
        || fail "cage-reach-$rung is missing from $ns at the END of the run — a reach cage was deleted while the run was in progress"
    done
  done
  echo "  ok   all three rungs' reach cages are still present at the end of the run (nothing deleted them)"
fi

pass_line "the Namespace declares the tier and the pod wears it; the cage only tightens; the bottom rung runs and reaches nothing; TCoR booked"
