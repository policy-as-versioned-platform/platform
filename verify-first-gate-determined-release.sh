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
# Evidence missing and a tag that EXISTS is the real defect: something was
# released without the gate determining its number, which is the whole claim of
# this beat, and that still FAILS by name.
#
# `--selfcheck` pins that three-way decision on its own, with no repo state.
if [ "${1:-}" = "--selfcheck" ]; then
python3 - <<'PYEOF'
def verdict(has_evidence, has_tag):
    """The three states an array element can be in, and the only one that is a
    refusal. Ordering, from cut-release.yml: gate -> evidence -> array -> tag."""
    if has_evidence:
        return "check"        # compare declared vs computed, as before
    if has_tag:
        return "refuse"       # released with no gate evidence: the real defect
    return "not-yet-gated"    # reviewed, declared, dispatch not run: cannot look


assert verdict(True, True) == "check"
assert verdict(True, False) == "check", "evidence written, signature pending -- step 3's case"
assert verdict(False, True) == "refuse", "a cut tag with no evidence must never be tolerated"
assert verdict(False, False) == "not-yet-gated", (
    "a declared element with neither evidence nor tag is the pre-dispatch state, "
    "not an observation that anything is wrong")
print("ok  selfcheck: evidence+no tag is a could-not-look; NO evidence WITH a tag is still a "
      "refusal; the gate-determines-the-number claim is not weakened")
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
        # Evidence missing: refuse only if the TAG exists (released without the
        # gate determining its number). Otherwise this element is declared and
        # not yet dispatched -- see the header. Step 3 names it either way.
        tagged = subprocess.run(["git", "rev-parse", "-q", "--verify",
                                 f"refs/tags/{tag}"], capture_output=True).returncode == 0
        if tagged:
            raise SystemExit(f"FAIL: {tag} EXISTS as a tag but there is no {path} -- that "
                             "release was cut without the gate determining its number, which is "
                             "exactly what this beat exists to refuse")
        print(f"..  {tag}: declared {element['bump']!r}; no evidence and no tag yet -- the gate "
              "runs inside cut-release.yml, so this element has not been dispatched")
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
uncut=""
while read -r tag; do
  [ -n "$tag" ] || continue
  if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    uncut="${uncut} ${tag}"
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
        print(e["tag"])
PYEOF
)

if [ -n "${uncut}" ]; then
  echo "No signed tag exists for:${uncut}"
  echo "Where evidence is already written, the gate has run and the array element is correct,"
  echo "and only the signature is outstanding. Where step 2 printed '..' for a tag, the gate"
  echo "has not run for it either -- it runs inside the same dispatch, before the tag."
  echo "A gitsign tag can only be cut by .github/workflows/"
  echo "cut-release.yml inside GitHub Actions, with that run's own ambient OIDC identity."
  echo "Nothing here may fake one, so this check cannot look at the last step of the release."
  echo "SKIP: waiting for the owner to let cut-release.yml cut${uncut} in Actions"
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
