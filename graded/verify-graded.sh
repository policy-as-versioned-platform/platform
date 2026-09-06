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

# The one reader the live tail uses, shared by the real run and the selfcheck --
# the same shape as distribution/verify-declared-versions-admit.sh and
# distribution/verify-coexistence.sh. Modes:
#   (none)       prints `CUT: <versions>` and `UNCUT: <versions>`, read off the array
#   --installed  argv[3] is `kubectl get mutatingpolicy -o name` output; prints the
#                versions whose cage-tier copy is really ON THE CLUSTER, one per line
#   --selfcheck  runs the pure asserts; touches no disk and no cluster
graded_state() {
python3 - "$HERE" "${1:-}" "${2:-}" <<'PY'
import importlib.util, re, sys
from pathlib import Path

here, mode, raw = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
dist = here.parent / "distribution"


def partition(els):
    """(cut, uncut) by the `commit` field -- absent or empty is UNCUT.
    cut-release.yml fills that field in when it cuts the SIGNED tag, so until
    then the tag does not exist and Flux has nothing to fetch. Nothing else in
    this file may decide what 'released' means; these are the same words as
    distribution/verify-declared-versions-admit.sh."""
    return ([e["version"] for e in els if e.get("commit")],
            [e["version"] for e in els if not e.get("commit")])


def installed(names):
    """The versions whose cage-tier MutatingPolicy is ON THE CLUSTER, read off
    `kubectl get mutatingpolicy -o name`.

    This is a fact about the CLUSTER and it may not be inferred from the array.
    distribution/render-and-prove.py writes EVERY declared element to
    versions.txt and graded/up.sh applies each one's cage-tier.yaml and
    cage-netpol.yaml, cut or not -- so after one up.sh run from an array that
    declares an uncut 5.0.0, cage-tier-5-0-0 is installed and selectable by any
    pod even though no tag was ever cut. Counting the array would say one; the
    cluster says two."""
    out = set()
    for line in names.splitlines():
        name = line.strip().rsplit("/", 1)[-1]
        m = re.fullmatch(r"cage-tier-(\d+)-(\d+)-(\d+)", name)
        if m:
            out.add(".".join(m.groups()))
    return sorted(out, key=lambda v: [int(x) for x in v.split(".")])


if mode == "--selfcheck":
    # the cut/uncut partition, pinned the same way as its four siblings
    assert partition([{"version": "4.0.0", "commit": "abc"}]) == (["4.0.0"], []), \
        "a released element is cut and its cage must be looked for by name"
    assert partition([{"version": "5.0.0", "tag": "policy/v5.0.0"}]) == ([], ["5.0.0"]), \
        "an element with NO commit key at all is an uncut tail"
    assert partition([{"version": "5.0.0", "commit": ""}]) == ([], ["5.0.0"]), \
        "an EMPTY commit is an uncut tail too, not a cut one"
    assert partition([{"version": "4.0.0", "commit": "abc"},
                      {"version": "5.0.0", "tag": "policy/v5.0.0"}]) == (["4.0.0"], ["5.0.0"]), \
        "a cut line beside an uncut one is still probed: the tail never suppresses it"

    # the installed-cage reader: versioned cage-tier copies only
    assert installed("mutatingpolicy.policies.kyverno.io/cage-tier-4-0-0\n"
                     "mutatingpolicy.policies.kyverno.io/cage-tier-5-0-0\n"
                     "mutatingpolicy.policies.kyverno.io/stamp-posture-4-0-0\n"
                     "mutatingpolicy.policies.kyverno.io/cage-tier\n") == ["4.0.0", "5.0.0"], \
        "only versioned cage-tier copies count: not another policy, not the authoring name"
    assert installed("") == [], "an empty listing is no installed cage"
    assert installed("x/cage-tier-10-0-0\nx/cage-tier-9-0-0\n") == ["9.0.0", "10.0.0"], \
        "installed versions sort numerically, so the newest is the last"

    # The defect of 2026-09-04 (round 2). The count that decides whether the
    # behavioural probes may speak for the whole live surface must be asked of
    # the CLUSTER, because up.sh's fan-out ranges the whole array: one CUT
    # element and two INSTALLED cages is exactly the state that bought a PASS
    # where a could-not-look is the honest grade.
    cut, uncut = partition([{"version": "4.0.0", "commit": "abc"}, {"version": "5.0.0"}])
    live = installed("x/cage-tier-4-0-0\nx/cage-tier-5-0-0\n")
    assert (len(cut), len(uncut), len(live)) == (1, 1, 2), (cut, uncut, live)
    assert len(live) > 1, "two cages live: the behavioural probes exercise one, so this tail skips"
    assert len(installed("x/cage-tier-4-0-0\n")) == 1, \
        "one cage live: the probes ARE the whole live surface, so the tail may speak"

    # The third state, which the count must never swallow: a CUT version with no
    # cage on the cluster is missing BY NAME, and that is a FAIL, not a skip.
    cut, _ = partition([{"version": "6.0.0", "commit": "deadbeef"}])
    assert cut == ["6.0.0"] and "6.0.0" not in installed("x/cage-tier-4-0-0\n"), \
        "a cut version whose policy is genuinely missing is named, never skipped over"

    print("ok   selfcheck: cut/uncut partition; installed cages read off the CLUSTER, not the "
          "array, so two live cages skip the tail, one lets it speak, and a cut version with no "
          "cage still fails by name")
    sys.exit(0)

if mode == "--installed":
    print("\n".join(installed(raw)))
    sys.exit(0)

spec = importlib.util.spec_from_file_location("rog", dist / "render-orphan-guard.py")
rog = importlib.util.module_from_spec(spec); spec.loader.exec_module(rog)
cut, uncut = partition(rog.elements(dist / "versions.yaml"))
print("CUT: " + " ".join(cut))
print("UNCUT: " + " ".join(uncut))
PY
}

# Run the selfcheck from the no-argument path, BEFORE the tool and substrate
# checks, so a regression in the partition or in the installed-cage count cannot
# hide behind a machine with no kyverno CLI and no cluster.
if [ "${1:-}" = "--selfcheck" ]; then
  graded_state --selfcheck
  exit 0
fi
say "0. selfcheck: the cut/uncut partition and the installed-cage count bite"
bash "$0" --selfcheck || fail "the selfcheck did not bite -- the checker itself has regressed"

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
#
# 2026-09-04 (ticket 63): CUT versions only, keyed on the array element's
# `commit` field -- the same rule, the same words, as
# distribution/verify-declared-versions-admit.sh, distribution/verify-coexistence.sh
# and posture/verify-posture-projection.sh. An element with no `commit` has not
# been released: cut-release.yml fills that field in when it cuts the SIGNED
# tag, so until then the tag does not exist, Flux has nothing to fetch, and the
# version's policies cannot be DELIVERED BY FLUX to any cluster. Calling that
# "not installed live" was a FAIL for an unmade release -- declaring 5.0.0 here
# on 2026-09-04 turned this whole beat red the same minute, on a cluster where
# nothing had regressed. The uncut tail is NAMED in the output instead of being
# looked for, and it is named rather than skipped over: a blanket live_tail_skip
# would have hidden the cut line's genuine green, which is the fault this rule
# exists to avoid.
#
# 2026-09-04, round 2: what the array says is CUT is the right subject for
# "which cage must be there by name", and the WRONG subject for "how many cages
# a pod can select". This DEMO path is not Flux: render-and-prove.py writes
# every declared element to versions.txt and up.sh applies each one's
# cage-tier.yaml and cage-netpol.yaml, so one up.sh run from this branch
# installs cage-tier-5-0-0 too -- uncut, ungraded, and selectable by any pod.
# The count below therefore asks the CLUSTER what is installed. Keying it on the
# cut list bought a PASS from an array whose second cage was live but unprobed.
if ! substrate_ok "$CLUSTER"; then
  live_tail_skip "$SUBSTRATE_REASON"
elif ! timeout 10 kubectl --context "$CTX" get mutatingpolicy >/dev/null 2>&1; then
  live_tail_skip "Kyverno MutatingPolicy CRD not installed on $CTX (run engine/up.sh then graded/up.sh)"
else
  say "8. live: a REAL pod in a caged Namespace is admitted, RUNS, and wears its Namespace's cage (CUT versions only)"
  ARRAY_STATE="$(graded_state)"
  CUT_VERSIONS="$(printf '%s\n' "$ARRAY_STATE" | sed -n 's/^CUT: //p')"
  UNCUT_TAIL="$(printf '%s\n' "$ARRAY_STATE" | sed -n 's/^UNCUT: //p')"
  if [ -n "$UNCUT_TAIL" ]; then
    say "   uncut tail, not looked for BY NAME: $UNCUT_TAIL (declared with no commit, so no signed tag and nothing for Flux to deliver)"
    cat <<'UNCUT'
  NAMED, NOT CLOSED (2026-09-04, ticket 63): the orphan guard's allow-list is
  ranged from the WHOLE array, cut or not, while FLUX only ever delivers a
  cage-tier/cage-netpol pair for a version whose tag was actually cut. So on the
  DELIVERY path, between the moment the array declares a version and the moment
  cut-release.yml cuts its tag, a pod may CLAIM that version, pass the orphan
  guard, and find no MutatingPolicy self-scoped to its claim -- admitted,
  uncaged. Not reachable until the branch is pushed and the ResourceSet is
  reconciling it. On THIS demo path the window does not exist for the opposite
  reason, and it is not a comfort: up.sh applies every declared element, so the
  uncut version's cage IS installed here -- ungraded, and counted live below.
  The honest repair for both is to range the allow-list AND the fan-out over CUT
  elements only, which is a change to the ResourceSet, render-orphan-guard.py,
  render-and-prove.py and up.sh, not to this beat.
UNCUT
  fi
  # Every CUT version must be installed, BY NAME: a released version whose cage
  # is missing from the cluster is the fault this loop exists to catch, and no
  # count below may swallow it.
  for v in $CUT_VERSIONS; do
    timeout 10 kubectl --context "$CTX" get mutatingpolicy "cage-tier-${v//./-}" >/dev/null 2>&1 \
      || fail "cage-tier-${v//./-} MutatingPolicy not installed live"
    timeout 10 kubectl --context "$CTX" get generatingpolicy "cage-netpol-${v//./-}" >/dev/null 2>&1 \
      || fail "cage-netpol-${v//./-} GeneratingPolicy not installed live"
  done
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
  #
  # 2026-09-04 (ticket 63, round 2): ASK THE CLUSTER. The sentence this count
  # defends is "every installed version is SELECTABLE by any pod", which is a
  # fact about the cluster, and the array cannot stand in for it on this path:
  # render-and-prove.py writes every declared element to versions.txt and up.sh
  # applies each one's cage-tier.yaml and cage-netpol.yaml, so an UNCUT element
  # gets its cage installed here too -- ungraded, and selectable the moment it
  # is applied. Counting the CUT list (the first fix, same day) said one where
  # the cluster said two and bought a PASS where a could-not-look is honest.
  # Counting the WHOLE array would be wrong the other way, on a cluster that
  # simply has not been up.sh'd since the array grew. Neither file is the
  # subject. The cluster is.
  INSTALLED_NAMES="$(timeout 10 kubectl --context "$CTX" get mutatingpolicy -o name 2>/dev/null)" \
    || fail "could not list MutatingPolicies on $CTX to count the installed cages"
  INSTALLED_CAGES="$(graded_state --installed "$INSTALLED_NAMES")"
  INSTALLED_COUNT="$(printf '%s\n' "$INSTALLED_CAGES" | grep -c . || true)"
  INSTALLED_LINE="$(printf '%s\n' "$INSTALLED_CAGES" | tr '\n' ' ' | sed 's/ *$//')"
  say "   cage-tier copies installed on $CTX: ${INSTALLED_LINE:-none} ($INSTALLED_COUNT)"
  if [ "$INSTALLED_COUNT" -gt 1 ]; then
    live_tail_skip "$CTX carries $INSTALLED_COUNT installed cage-tier MutatingPolicies ($INSTALLED_LINE) and the behavioural probes below only exercise the newest CUT one; every installed cage is selectable by any pod, so the others are ungraded here and this tail may not claim the cage holds for them"
  fi
  NEWEST="$(printf '%s' "$CUT_VERSIONS" | tr ' ' '\n' | tail -1)"
  [ -n "$NEWEST" ] || fail "no CUT version in distribution/versions.yaml: nothing released is installed live to probe"
  echo "  -- the live copy under test is cage-tier-${NEWEST//./-} (newest CUT version), applied by graded/up.sh from"
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

  # ---- eco-system ticket 98: the one refusal by another name the estate ACCEPTS ----
  # A mutation carries no Deny-shaped text and can stop a workload just as dead. The hub's
  # verify/refusal-by-another-name/ grades that offline in four legs; the half that needs an API
  # SERVER is this one, and it is the half that has never had a cluster on a citable run
  # (P2-6). Nothing is simulated here: the refusal below is the API server's own, or this step
  # fails.
  #
  # Ticket 89 (S3, 2026-09-05) decided this refusal is CORRECT and left it in place: a pod's
  # cage is written at admission from what it declared then, so a workload cannot move itself
  # off its rung by asserting a label afterwards, and the remediation is a RECREATE. It is on
  # the hub's register.yaml as an accepted refusal. This step is what keeps that record honest:
  # if the API server ever ACCEPTS the edit, the row describes something the estate no longer
  # does, and this goes red rather than the record going quietly stale.
  say "8b. live (ticket 98): a running pod whose rung changes under it — the refusal the estate accepts"
  T98_NS="cage-verify-t98"
  cleanup_t98() {
    timeout 180 kubectl --context "$CTX" delete ns "$T98_NS" --ignore-not-found --wait=true \
      >/dev/null 2>&1 || true
  }
  trap 'rm -rf "$WORK"; cleanup_live; cleanup_t98' EXIT
  cleanup_t98
  timeout 20 kubectl --context "$CTX" apply -f - >/dev/null <<YAML || fail "could not create the ticket-98 probe namespace on $CTX"
apiVersion: v1
kind: Namespace
metadata:
  name: $T98_NS
  labels: { "policy-as-versioned.dev/governed": "true", "posture.acme.io/tier": "quarantine" }
YAML
  T98ERR="$(timeout 30 kubectl --context "$CTX" -n "$T98_NS" run t98-probe \
            --image="$PROBE_IMAGE" --restart=Never \
            --labels="policy-as-versioned.dev/policy-version=$NEWEST" 2>&1 >/dev/null || true)"
  [ -z "$T98ERR" ] || fail "the ticket-98 probe pod was REFUSED at admission, so the refusal this step exists to observe could not be reached: $T98ERR"
  read -r T98PC T98PRIO <<<"$(timeout 20 kubectl --context "$CTX" -n "$T98_NS" get pod t98-probe \
    -o jsonpath='{.spec.priorityClassName} {.spec.priority}')"
  [ "$T98PC" = "cage-quarantine-${NEWEST//./-}" ] \
    || fail "the ticket-98 probe was admitted carrying '$T98PC', not its Namespace's cage-quarantine-${NEWEST//./-} — nothing to move"
  echo "  ok   admitted and caged at quarantine: $T98PC / $T98PRIO"
  # Move the DECLARATION, not the pod: the Namespace is where the tier is declared (ADR-0022),
  # so this is the same rung change ticket 89's live instance produces by adding a claim, and it
  # is reachable on a cluster that does not yet carry ticket 89's machinery.
  timeout 20 kubectl --context "$CTX" label ns "$T98_NS" posture.acme.io/tier=baseline \
    --overwrite >/dev/null || fail "could not move the Namespace's declared tier"
  T98UPD="$(timeout 30 kubectl --context "$CTX" -n "$T98_NS" label pod t98-probe \
            t98=moved --overwrite 2>&1 >/dev/null || true)"
  if [ -z "$T98UPD" ]; then
    fail "the API server ACCEPTED an UPDATE that rewrites priorityClassName and priority on a running pod. Either the cage stopped rewriting them or Kubernetes stopped refusing: the hub's verify/refusal-by-another-name/register.yaml records this refusal as accepted-and-correct, and that row now describes something this estate does not do"
  fi
  grep -qi "pod updates may not change fields other than" <<<"$T98UPD" \
    || fail "the UPDATE was refused for some other reason than pod-spec immutability, so this is not the refusal the register records: $T98UPD"
  grep -qi "priorityclassname" <<<"$T98UPD" \
    || fail "the refusal does not name priorityClassName, so the field the cage rewrote is not the field the API server objected to: $T98UPD"
  echo "  ok   OBSERVED, on this API server: a mutation with no Deny in it refused the update —"
  printf '       %s\n' "$(tr '\n' ' ' <<<"$T98UPD" | cut -c1-300)"
  echo "  ok   this is the ACCEPTED refusal (ticket 89 S3): the remediation is to RECREATE the pod with"
  echo "       the rung it should have, never to edit a running one. Recorded in the hub's"
  echo "       verify/refusal-by-another-name/register.yaml, which is graded in both directions."
  # The API server names its own mutable-field list in that message. The hub's offline table
  # (refusal_scan.MUTABLE_ON_UPDATE) is the same five, and this is where the two are compared:
  # the offline check's central constant is graded by the API server rather than by belief.
  for f in 'spec.containers\[\*\].image' 'spec.initContainers\[\*\].image' \
           'spec.activeDeadlineSeconds' 'spec.tolerations' 'spec.terminationGracePeriodSeconds'; do
    grep -q "$f" <<<"$T98UPD" \
      || fail "the API server's own list of fields a pod update MAY change no longer includes $f, so the hub's refusal_scan.MUTABLE_ON_UPDATE table is out of date: $T98UPD"
  done
  echo "  ok   the API server's own mutable-on-update list is the five fields the hub's offline table carries"
  # The exact instance ticket 89 measured needs ticket 89's machinery on the cluster. Named, not
  # skipped over: the refusal above is the same mechanism, observed, so this tail does not go
  # dark while the machinery is in flight.
  if timeout 10 kubectl --context "$CTX" get mutatingpolicy governed-namespace-cage >/dev/null 2>&1; then
    echo "  -- ticket 89's bottom-rung cage IS installed; the claim route (label an unclaimed pod with a"
    echo "     served version) is the same refusal by the same mechanism and is not probed twice."
  else
    echo "  ??   NOT LOOKED AT: the claim route of ticket 89's S3 instance (label a bottom-rung pod with a"
    echo "       served version) needs governed-namespace-cage on $CTX, and this cluster carries the"
    echo "       pre-ticket-89 ValidatingPolicy instead. The rung change was observed by moving the"
    echo "       Namespace's declaration, which is the same mechanism on the same fields."
  fi
  cleanup_t98

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
