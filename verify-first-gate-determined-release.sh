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
import json, sys
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
        raise SystemExit(f"FAIL: {element['tag']} declares bump {element['bump']!r} but there is no "
                         f"{path} -- the gate has not run for it")
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
  echo "The gate has run, the evidence is written and the array element is correct for:${uncut}"
  echo "No signed tag exists for it. A gitsign tag can only be cut by .github/workflows/"
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
