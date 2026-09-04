#!/usr/bin/env bash
# verify-first-gate-determined-release.sh -- ticket 43 (H9-04).
#
# The claim: the number of the next policy release is DETERMINED BY THE GATE
# before the tag exists. Every evidence document under computed-semver/evidence
# for a version the array still declares was produced by a real gate run; the
# bump it records is the bump the reviewed array element declares; and the
# outcome (passed, or degraded with a prerelease suffix and tier: quarantine)
# is the one the gate reached.
#
# Everything a release needs is real here EXCEPT the signature. A gitsign tag
# and a keyless cosign bundle need a live GitHub Actions identity, which no
# local run has and no local run may fake (ADR-0001, and this estate's own
# rule that only CI holds the signing identity). So where a real signature is
# required, this script exits 3 and NAMES THE TAG the owner must let
# cut-release.yml cut. It flips to a pass, with no edit, the moment that tag
# exists and resolves where the array says it does.
#
# Exit 0 observed true, 3 could-not-look, non-zero observed false.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

fail() { echo "FAIL: $*" >&2; exit 1; }

# 2026-09-04 (ticket 63). A newly DECLARED element -- reviewed, in the array,
# not yet dispatched -- has no evidence document, because the gate that writes
# one runs inside cut-release.yml at cut time (step 1 below asserts that
# ordering). Step 2 refused every such element outright, so adding 5.0.0 to the
# array made this beat observe FALSE about a release nobody had asked for yet.
# Nothing false had been observed: the gate had not run. The distinction the
# refusal was missing is the TAG. Evidence missing and NO tag is a could-not-
# look -- the state every release passes through between review and dispatch.
# Evidence missing and a RELEASED element is the real defect: something was
# released without the gate determining its number, which is the whole claim of
# this beat, and that still FAILS by name.
#
# 2026-09-04, review fix: "released" is keyed on the array element's `commit`
# field, not on a local tag. cut-release.yml fills `commit` in at the same
# moment it cuts the signed tag, so the two say the same thing about a healthy
# repo -- but only `commit` is committed CONTENT. On a tagless or shallow
# checkout (`--depth`, `--no-tags`, an archive export) refs/tags is empty, and a
# tag-keyed rule let a release cut with no gate evidence read as "not yet
# gated" and skip. The tag is kept as a second signal so a tag that appears
# without a commit still refuses; the KEY is the commit, exactly as in the four
# cut/uncut checks named in step 2.
#
# `--selfcheck` pins that decision on its own, with no repo state.
if [ "${1:-}" = "--selfcheck" ]; then
python3 - <<'PYEOF'
def verdict(has_evidence, is_cut, has_tag):
    """The states an array element can be in, and the only one that is a
    refusal. Ordering, from cut-release.yml: gate -> evidence -> array -> tag.
    `is_cut` is the element's own `commit` field; `has_tag` is what THIS
    checkout can see, which is not the same question."""
    if has_evidence:
        return "check"            # compare declared vs computed, as before
    if is_cut or has_tag:
        return "refuse"           # released with no gate evidence: the real defect
    return "not-yet-gated"        # reviewed, declared, dispatch not run: cannot look


assert verdict(True, True, True) == "check"
assert verdict(True, False, False) == "check", "evidence written, signature pending -- step 3's case"
assert verdict(False, True, True) == "refuse", "a cut tag with no evidence must never be tolerated"
assert verdict(False, True, False) == "refuse", (
    "the shallow/tagless checkout: the array element records a commit, so the release WAS cut; "
    "that this clone cannot see refs/tags is a fact about the clone, never an excuse to skip")
assert verdict(False, False, True) == "refuse", (
    "a tag with no commit on its element is still a release with no gate evidence")
assert verdict(False, False, False) == "not-yet-gated", (
    "a declared element with no evidence, no commit and no tag is the pre-dispatch state, "
    "not an observation that anything is wrong")
print("ok  selfcheck: evidence+no tag is a could-not-look; NO evidence with a RELEASED element "
      "(commit on the array, or a tag) is still a refusal, tagless checkout included; the "
      "gate-determines-the-number claim is not weakened")
PYEOF
  exit 0
fi

# `$here/<name>`, never `$0`: this script cd's to $here above, so a relative $0
# no longer resolves (the same reason verify-corpus-generator.sh keeps $SELF).
echo "== 0. selfcheck: the evidence/tag decision bites =="
bash "$here/${BASH_SOURCE##*/}" --selfcheck \
  || fail "the selfcheck did not bite -- the checker itself has regressed"

echo
echo "== 1. the workflow is wired: the gate runs BEFORE the tag, and the evidence commit lands first =="
python3 - <<'PYEOF' || fail "cut-release.yml no longer runs the gate before the tag"
import yaml
steps = yaml.safe_load(open(".github/workflows/cut-release.yml"))["jobs"]["cut"]["steps"]
runs = [s.get("run", "") for s in steps]
def index(needle):
    for i, r in enumerate(runs):
        if needle in r:
            return i
    raise SystemExit(f"FAIL: no step runs {needle}")
gate = index("cut-release-gate.py")
evidence = index("cut-release-commit-evidence.sh")
array = index("cut-release-update-array-commit.sh")
tag = index("cut-release-create-tags.sh")
push = index("cut-release-push.sh")
assert gate < evidence < array < tag < push, (gate, evidence, array, tag, push)
print("ok  gate -> commit evidence -> correct the array -> tag -> push, in that order")
PYEOF

echo
echo "== 2. every declared bump agrees with the gate's own evidence =="
python3 - <<'PYEOF' || fail "a declared bump and its evidence disagree"
import json, subprocess, sys
from pathlib import Path
sys.path.insert(0, "computed-semver")
import comparison_window
sys.path.insert(0, "distribution")
import importlib.util
spec = importlib.util.spec_from_file_location("rog", "distribution/render-orphan-guard.py")
rog = importlib.util.module_from_spec(spec); spec.loader.exec_module(rog)

elements = rog.elements(Path("distribution/versions.yaml"))
# 2026-08-29 review: this used to FILTER the array on `bump`, so an element
# with no declared bump was invisible here -- no evidence demanded, no
# declared-vs-computed check, not even a "waiting for" SKIP. ico and nist
# cannot do that (their bump.yaml is mandatory), so neither may the platform:
# an element with no bump is observed false, by name.
undeclared = [e["version"] for e in elements if not e.get("bump")]
if undeclared:
    raise SystemExit(f"FAIL: distribution/versions.yaml declares {undeclared} with no `bump` "
                     "field -- ticket 18 Answer 5 puts the declared bump on the array element, "
                     "and an element without one can never disagree with itself")
declared = [e for e in elements if e.get("bump")]
if not declared:
    raise SystemExit("FAIL: no versions.yaml array element declares a bump -- ticket 18 Answer 5 "
                     "puts the declared bump on the element, and nothing declares one")
for element in declared:
    version = element["version"]
    tag = element["tag"]
    published = tag[len("policy/v"):]
    path = Path("computed-semver/evidence") / f"{published}.json"
    if not path.exists():
        # Evidence missing: refuse if this element was RELEASED, and only then.
        # "Released" is keyed on the array element's own `commit` field -- the
        # same key distribution/verify-declared-versions-admit.sh,
        # verify-coexistence.sh, posture/verify-posture-projection.sh and
        # graded/verify-graded.sh use, because cut-release.yml fills `commit`
        # in at the same moment it cuts the signed tag. The local tag is kept
        # as a second, weaker signal, not as the key: a tagless or shallow
        # checkout (`clone --depth`, `fetch --no-tags`, an archive export)
        # carries no refs/tags at all, and keying on it alone let a release cut
        # with NO gate evidence read as "not yet dispatched" and skip -- the one
        # direction this beat must never be wrong in. `commit` is committed
        # content, so it survives every fetch depth.
        cut = bool(element.get("commit"))
        tagged = subprocess.run(["git", "rev-parse", "-q", "--verify",
                                 f"refs/tags/{tag}"], capture_output=True).returncode == 0
        if cut or tagged:
            seen = "EXISTS as a tag" if tagged else (
                "is recorded as released by the array element's commit "
                f"{element['commit']} (this checkout carries no refs/tags/{tag}, "
                "so the tag itself was not observed here)")
            raise SystemExit(f"FAIL: {tag} {seen} but there is no {path} -- that "
                             "release was cut without the gate determining its number, which is "
                             "exactly what this beat exists to refuse")
        print(f"..  {tag}: declared {element['bump']!r}; no evidence, no commit on the array "
              "element and no tag -- the gate runs inside cut-release.yml, so this element has "
              "not been dispatched")
        continue
    doc = json.loads(path.read_text())
    assert doc["bump"]["declared"] == element["bump"], (
        f"{version}: the array declares {element['bump']!r}, the evidence records "
        f"{doc['bump']['declared']!r}")
    assert doc["outcome"]["result"] in ("passed", "degraded"), doc["outcome"]
    assert doc["bump"]["computed"] is not None, f"{version}: the evidence records no computed bump"
    assert doc["matrix"] == {} and "adopter" in doc.get("matrix_note", ""), (
        f"{version}: the publisher's matrix must be empty AND say the adopter fills it "
        f"(ticket 18 Answer 4)")
    if doc["outcome"]["result"] == "degraded":
        assert comparison_window.is_prerelease(published), (
            f"{version}: a degraded publish must carry a prerelease suffix on the declared number")
        assert comparison_window.base_version(published) == version, (
            f"{version}: a degraded publish never rewrites the BASE number")
        assert comparison_window.parse_semver(published) < comparison_window.parse_semver(version), (
            f"{version}: the degraded number must sort BELOW the clean one")
        assert element.get("tier") == "quarantine", (
            f"{version}: a degraded publish's array element must carry tier: quarantine")
        assert doc["degraded"]["computed_bump"] == doc["bump"]["computed"], doc["degraded"]
    else:
        assert "tier" not in element, f"{version}: passed, so the element must carry no tier"
    print(f"ok  {tag}: declared {element['bump']!r} == evidence {doc['bump']['declared']!r}, "
          f"computed {doc['bump']['computed']!r}, outcome {doc['outcome']['result']}")
PYEOF

echo
echo "== 3. the signature: only cut-release.yml, in Actions, can produce it =="
# 2026-09-04, review fix: the element's `commit` says whether the release was
# cut; refs/tags says whether THIS checkout can see the tag. A cut element whose
# tag is not in this clone is not "waiting for the owner" -- it is a shallow or
# tagless checkout, and saying otherwise would put a false wait in front of a
# release that already happened. Named separately, still a could-not-look.
uncut=""
unseen=""
while read -r cut tag; do
  [ -n "$tag" ] || continue
  if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    if [ "$cut" = "cut" ]; then unseen="${unseen} ${tag}"; else uncut="${uncut} ${tag}"; fi
  fi
done < <(python3 - <<'PYEOF'
import sys
from pathlib import Path
sys.path.insert(0, "distribution")
import importlib.util
spec = importlib.util.spec_from_file_location("rog", "distribution/render-orphan-guard.py")
rog = importlib.util.module_from_spec(spec); spec.loader.exec_module(rog)
for e in rog.elements(Path("distribution/versions.yaml")):
    if e.get("bump"):
        print("cut" if e.get("commit") else "uncut", e["tag"])
PYEOF
)

# 2026-09-04, round 2: both reasons are REPORTED, then one SKIP line carries
# both. The first draft exited 3 inside the `unseen` branch, so a shallow
# checkout that also held an uncut element never printed the wait on the owner
# at all -- the reader was told to fetch tags and never told a release was still
# uncut. They are different facts about different versions and both are true at
# once; neither may silence the other.
if [ -n "${unseen}" ] || [ -n "${uncut}" ]; then
  skip_reason=""
  if [ -n "${unseen}" ]; then
    echo "The array records a commit for:${unseen}"
    echo "so cut-release.yml already cut those tags -- but this checkout has no refs/tags entry"
    echo "for them, which is a fact about the clone (shallow, --no-tags, or an archive export)"
    echo "and not about the release. Step 2 has already checked their gate evidence by name."
    skip_reason="this checkout cannot see the signed tag(s)${unseen}; fetch tags and re-run"
  fi
  if [ -n "${uncut}" ]; then
    echo "No signed tag exists for:${uncut}"
    echo "Where evidence is already written, the gate has run and the array element is correct,"
    echo "and only the signature is outstanding. Where step 2 printed '..' for a tag, the gate"
    echo "has not run for it either -- it runs inside the same dispatch, before the tag."
    echo "A gitsign tag can only be cut by .github/workflows/"
    echo "cut-release.yml inside GitHub Actions, with that run's own ambient OIDC identity."
    echo "Nothing here may fake one, so this check cannot look at the last step of the release."
    if [ -n "${skip_reason}" ]; then
      skip_reason="${skip_reason}; AND waiting for the owner to let cut-release.yml cut${uncut} in Actions"
    else
      skip_reason="waiting for the owner to let cut-release.yml cut${uncut} in Actions"
    fi
  fi
  echo "SKIP: ${skip_reason}"
  exit 3
fi

echo "== 4. the tag exists: it must resolve to the array-update commit, one ahead of the array =="
python3 - <<'PYEOF' || fail "a cut tag does not resolve where the array says it does"
import subprocess, sys
from pathlib import Path
sys.path.insert(0, "distribution")
import importlib.util
spec = importlib.util.spec_from_file_location("rog", "distribution/render-orphan-guard.py")
rog = importlib.util.module_from_spec(spec); spec.loader.exec_module(rog)

def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()

for element in rog.elements(Path("distribution/versions.yaml")):
    if not element.get("bump"):
        continue
    tag_commit = git("rev-parse", f"refs/tags/{element['tag']}^{{commit}}")
    assert element.get("commit"), f"{element['tag']}: the array element records no commit"
    assert git("rev-parse", f"{tag_commit}^") == element["commit"], (
        f"{element['tag']}: the array's commit is not the tag commit's parent")
    print(f"ok  {element['tag']} -> {tag_commit}, array names its parent {element['commit']}")
PYEOF

echo
echo "PASS: the release's number was determined by the gate before the tag -- the declared bump on"
echo "the reviewed array element, the computed bump in the signed evidence and the outcome all"
echo "agree, and the signed tag resolves one commit ahead of the commit the array names."
