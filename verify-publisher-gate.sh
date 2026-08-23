#!/usr/bin/env bash
# verify-publisher-gate.sh -- ticket cs-27's offline twin. Runs the SAME code
# `cut-release.yml` runs -- `gate.run_gate()` and `.github/scripts/
# cut-release-gate.py` -- locally, before a publisher ever dispatches.
# Everything except the actual `cosign sign-blob` keyless signature: that
# needs a live GitHub Actions identity (ambient OIDC, no interactive
# browser), so CUT_RELEASE_TEST_MODE=1 swaps it for a clearly-marked
# non-signature (see cut-release-gate.py's own `sign_evidence` docstring) --
# exactly the same CI-only boundary ticket cs-13's own offline twin
# (verify-cut-release-tags.sh) already draws for gitsign, and this repo's
# own review of that ticket already stated honestly: local, un-signed,
# everything else real.
#
# Part A is the ticket's own required proof: "the gate cannot ship before
# the repair -- prove it" (spec.md via the ticket) -- a REAL refusal and a
# REAL pass, computed by `gate.run_gate()` against the REAL, live, tagged
# `distribution/policies/v2.0.0` and `v3.0.0` trees (not a fixture, not a
# fabricated scenario). It calls the real `kyverno` CLI once per corpus
# fixture per ValidatingPolicy (rederive_bumps.cel_pass, unchanged) against
# the full ~100-pod generated spine those two real trees produce, so this
# part alone takes several minutes -- that cost is the real engine running
# for real, not padding.
#
# Part B proves the WIRING: cut-release-gate.py's own tag-set parsing
# (policy tags gated, a platform's own `v*` tag skipped), the
# commit-before-tag order, and refusal blocking both the commit and the
# tag -- against a real (if throwaway) git clone of this repo, so
# `distribution/versions.yaml`'s real array and real `policy/v*` tag history
# are genuinely read, not mocked.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
say() { echo; echo "== $* =="; }

say "Part A: gate.run_gate() against the REAL v2.0.0 -> v3.0.0 predecessor (several minutes -- real kyverno apply per corpus fixture)"
python3 - "$here" "$scratch" <<'PY'
import sys, json, tempfile
from pathlib import Path

repo, scratch = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(repo / "computed-semver"))
import yaml, gate, comparison_window, corpus_generator  # noqa: E402

DIST = corpus_generator.DISTRIBUTION
assert DIST == repo / "distribution", f"corpus_generator resolved the wrong repo: {DIST}"


def subject_with(real_version: str, legal_history: list[str]) -> Path:
    real_tree = DIST / "policies" / f"v{real_version}"
    d = Path(tempfile.mkdtemp(dir=scratch))
    for f in real_tree.glob("*.yaml"):
        if f.name != "kustomization.yaml":
            (d / f.name).write_text(f.read_text())
    (d / "versions.yaml").write_text(yaml.safe_dump({"versions": legal_history}))
    return d


def run(declared: str) -> dict:
    subject = subject_with("3.0.0", ["2.0.0"])
    corpus_dir = Path(tempfile.mkdtemp(dir=scratch))
    # inside_pin stays '3.0.0' -- the literal v3.0.0's own self-scope
    # matchConditions actually carries (render-version-tree.py baked it in
    # when that tree was rendered and committed for real) -- never the
    # hypothetical `declared` under test here. Varying `declared` alone
    # against the SAME real committed body is exactly what proves the gate's
    # bump-comparison rule, isolated from corpus generation's own pin axis.
    corpus_generator.build_manifest(DIST / "policies" / "v2.0.0", DIST / "policies" / "v3.0.0",
                                     inside_pin="3.0.0", out_dir=corpus_dir)
    window = comparison_window.ComparisonWindow(
        old_window=["2.0.0"], new_window=["2.0.0"],
        subject_tree_for=lambda v: DIST / "policies" / f"v{v}",
    )
    repo_state = gate.RepoState(subject_dir=subject, corpus_dir=corpus_dir, window=window)
    return gate.run_gate(repo_state, declared)


print("-- declared 3.0.0 (the real tag's own number) --")
doc_pass = run("3.0.0")
assert doc_pass["outcome"]["result"] == "passed", doc_pass["outcome"]
assert doc_pass["bump"] == {"declared": "major", "computed": "major"}, doc_pass["bump"]
assert any(m["policy"] == "posture-trust-boundary.yaml" and m["verdict"] == "major"
           for m in doc_pass["movement"]), "expected posture-trust-boundary.yaml to carry the real major movement"
print(json.dumps({"outcome": doc_pass["outcome"], "bump": doc_pass["bump"],
                   "movement_policies": [m["policy"] for m in doc_pass["movement"]]}, indent=2))
(scratch / "evidence-pass-3.0.0.json").write_text(json.dumps(doc_pass, indent=2))
print(f"ok  PASS proved for real: declared major == computed major, against the real "
      f"v2.0.0->v3.0.0 predecessor (posture-trust-boundary.yaml genuinely narrowed)")

print()
print("-- declared 2.1.0 (legal, but weaker than the SAME real content's computed bump) --")
doc_refused = run("2.1.0")
assert doc_refused["outcome"]["result"] == "refused", doc_refused["outcome"]
assert doc_refused["bump"] == {"declared": "minor", "computed": "major"}, doc_refused["bump"]
assert "posture-trust-boundary.yaml" in doc_refused["outcome"]["reason"], doc_refused["outcome"]["reason"]
assert "weaker than the computed bump" in doc_refused["outcome"]["reason"], doc_refused["outcome"]["reason"]
print(json.dumps({"outcome": doc_refused["outcome"], "bump": doc_refused["bump"]}, indent=2))
(scratch / "evidence-refused-2.1.0.json").write_text(json.dumps(doc_refused, indent=2))
print(f"ok  REFUSAL proved for real: declared minor < computed major, same real predecessor, "
      f"reason names posture-trust-boundary.yaml")
PY

say "Part B: cut-release-gate.py's own wiring, against a real (throwaway) clone of this repo"
clone="$scratch/clone"
git clone --local --quiet "$here" "$clone" 2>/dev/null || git clone --quiet "$here" "$clone"
cd "$clone"
git config user.email test@example.invalid
git config user.name test
export CUT_RELEASE_TEST_MODE=1
export GITHUB_REPOSITORY_OWNER=scratch

echo "B1. a policy tag with no real tree yet is refused cleanly (release_integrity, no kyverno needed) -- no commit, no tag"
before_head=$(git rev-parse HEAD)
echo '[{"tag":"policy/v9.0.0","message":"B1: never rendered"}]' > tags-b1.json
set +e
python3 .github/scripts/cut-release-gate.py tags-b1.json > b1.out 2>&1
b1_code=$?
set -e
cat b1.out
[ "$b1_code" -ne 0 ] || fail "B1 should have refused (exit non-zero)"
grep -q "re-render check refused" b1.out || fail "B1: expected a re-render (missing tree) refusal, got: $(cat b1.out)"
[ "$(git rev-parse HEAD)" = "$before_head" ] || fail "B1: HEAD moved on a refusal -- no commit must happen"
[ -z "$(git tag -l 'policy/v9.0.0')" ] || fail "B1: a tag exists after a refusal"
[ -f computed-semver/evidence/9.0.0.json ] || fail "B1: no evidence file written for the run-artifact/summary path"
python3 -c "import json; d=json.load(open('computed-semver/evidence/9.0.0.json')); assert d['outcome']['result']=='refused', d['outcome']"
echo "ok  B1: refused, HEAD unmoved, no tag, signed evidence still on disk for the artifact/summary steps"
rm -rf computed-semver/evidence

echo
echo "B2. a bare platform tag (no policy/ prefix) is not this gate's subject -- skipped, exit 0, nothing written"
echo '[{"tag":"v1.0.1","message":"platform only"}]' > tags-b2.json
python3 .github/scripts/cut-release-gate.py tags-b2.json > b2.out 2>&1
grep -q "not this gate's subject, skipped" b2.out || fail "B2: expected the skip line, got: $(cat b2.out)"
[ ! -d computed-semver/evidence ] || fail "B2: evidence dir should not exist -- nothing was gated"
echo "ok  B2: platform's own tag skipped outright, no evidence, no error"

echo
echo "B3. a real, legal, first-release (empty predecessor window) policy tag passes end to end -- gate, then a real commit BEFORE a real tag"
python3 - <<'PY'
import sys
sys.path.insert(0, "distribution")
import importlib.util
spec = importlib.util.spec_from_file_location("rvt", "distribution/render-version-tree.py")
rvt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rvt)
from pathlib import Path
target = Path("distribution/policies/v9.0.0")
rvt.write_tree("9.0.0", target)
(target / "require-nonroot.yaml").write_text(
    Path("distribution/policies/v3.0.0/require-nonroot.yaml").read_text()
    .replace("3-0-0", "9-0-0").replace("'3.0.0'", "'9.0.0'")
)
PY
git add distribution/policies/v9.0.0
git commit -q -m "scratch: render v9.0.0 tree"
tree_sha=$(git rev-parse HEAD)
python3 - "$tree_sha" <<'PY'
import sys
sha = sys.argv[1]
p = "distribution/versions.yaml"
text = open(p).read()
old = '''    - versions:
        - { version: "2.0.0", tag: "policy/v2.0.0", commit: "fa862b710fe34b475aba54f926a95164f003b0c1" }
        - { version: "3.0.0", tag: "policy/v3.0.0", commit: "fa862b710fe34b475aba54f926a95164f003b0c1" }
'''
new = f'''    - versions:
        - {{ version: "9.0.0", tag: "policy/v9.0.0", commit: "{sha}" }}
'''
assert old in text, "versions.yaml array block not found verbatim -- has the real array's shape changed?"
open(p, "w").write(text.replace(old, new))
PY
git add distribution/versions.yaml
git commit -q -m "scratch: array now [9.0.0] only -- an empty predecessor window for this candidate"
before_tag_head=$(git rev-parse HEAD)

echo '[{"tag":"policy/v9.0.0","message":"B3: real first-release pass"}]' > tags-b3.json
python3 .github/scripts/cut-release-gate.py tags-b3.json
python3 -c "import json; d=json.load(open('computed-semver/evidence/9.0.0.json')); \
assert d['outcome']['result']=='passed', d['outcome']; \
assert d['bump']['computed']=='no predecessor', d['bump']"
./.github/scripts/cut-release-commit-evidence.sh tags-b3.json
after_commit_head=$(git rev-parse HEAD)
[ "$after_commit_head" != "$before_tag_head" ] || fail "B3: no new commit landed for the evidence"
./.github/scripts/cut-release-create-tags.sh tags-b3.json
tag_commit=$(git rev-parse refs/tags/policy/v9.0.0^{commit})
[ "$tag_commit" = "$after_commit_head" ] || fail "B3: tag does not resolve to the evidence commit ($tag_commit != $after_commit_head)"
git show --stat "$after_commit_head" | grep -q "computed-semver/evidence/9.0.0.json" || fail "B3: evidence file not in the commit the tag points at"
echo "ok  B3: gate passed for real, evidence committed BEFORE the tag, and the tag resolves to that exact commit"

echo
echo "PASS: run_gate() refuses a real declared bump weaker than the real computed one and passes"
echo "a legal-or-stronger one, against the real v2.0.0/v3.0.0 predecessor; cut-release-gate.py's"
echo "wiring skips a platform-only tag, refuses cleanly with no commit and no tag when a policy"
echo "tag's tree is missing, and -- on a real pass -- commits the signed evidence before creating"
echo "the tag, which then resolves to that exact commit."
