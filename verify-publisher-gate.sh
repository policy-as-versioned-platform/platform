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
# part alone costs several minutes of CPU -- that cost is the real engine
# running for real, not padding. It is now spent CONCURRENTLY rather than
# serially (see the `ponytail:` note above the parts for exactly what that
# did, and did not, change).
#
# cs-16 update: the real v2.0.0 -> v3.0.0 PASS case used to compute "major"
# via posture-trust-boundary.yaml -- proven, while chasing a genuine patch
# backport's own false refusal, to have been a vacuous self-scope match, not
# a real narrowing (posture-trust-boundary.yaml's body is byte-identical
# between v2.0.0 and v3.0.0 modulo the version literal; cage_engine.py's own
# module docstring and selfcheck #15 carry the full mechanism and the real
# `kyverno apply skip:1 vs fail:1` proof). Now that cage_engine.py neutralizes
# only the named self-scope matchCondition before comparing, this real pair
# honestly computes "none" -- there is no other modeled real content
# movement between v2.0.0 and v3.0.0 either (require-nonroot's real widening
# there is Audit-only, which never registers movement by CONTEXT.md's own
# admitted/refused rule). The PASS case below asserts that honest "none",
# not the old "major". The REFUSAL case can no longer be demonstrated from
# the unmodified real v2.0.0/v3.0.0 pair -- there is no genuine narrowing in
# it -- so it now applies ONE disclosed, real mutation on top of the real
# v3.0.0 tree: require-nonroot's own file comment already names this
# transition as planned future work ("Audit->Deny promotion is a separate,
# editorial PR"), so promoting it here is not an invented scenario, just an
# early, explicit instance of a change this repo already intends to make.
# Everything else about the tree, the corpus, and the gate stays real.
#
# Part B proves the WIRING: cut-release-gate.py's own tag-set parsing
# (policy tags gated, a platform's own `v*` tag skipped), the two-commit
# (evidence, then array-correction) order before the tag, refusal blocking
# every commit and the tag, and -- B3 -- that versions.yaml's `commit` field
# for the cut version ends up naming the evidence commit exactly, the tag's
# resolved commit's direct parent, never the tag's own commit and never the
# stale pre-dispatch value -- against a real (if throwaway) git clone of
# this repo, so `distribution/versions.yaml`'s real array and real
# `policy/v*` tag history are genuinely read, not mocked.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
say() { echo; echo "== $* =="; }

# ponytail: Part A's two cases, Part B's real cut and Part C's real backport
# are four INDEPENDENT real classifications -- each builds its own corpus in
# its own temp tree (or its own throwaway clone) and runs its own real
# kyverno passes -- so they run one process each, concurrently, and every
# part's output is printed, in the original order, once all four have
# finished. Same code, same real engine, same assertions, same evidence:
# only the wall clock changes. Run serially this script took 332s, past
# talk/verify-all.sh's own 300s per-script budget. Upgrade path if it creeps
# back over: the real cost is the kyverno CLI itself, invoked once per corpus
# fixture per policy by rederive_bumps.cel_pass, never batched.

cat > "$scratch/part-a.py" <<'PY'
import sys, json, tempfile
from pathlib import Path

repo, scratch, case = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, str(repo / "computed-semver"))
import yaml, gate, comparison_window, corpus_generator  # noqa: E402

DIST = corpus_generator.DISTRIBUTION
assert DIST == repo / "distribution", f"corpus_generator resolved the wrong repo: {DIST}"


def subject_with(tree: Path, legal_history: list[str]) -> Path:
    # gate.RepoState.subject_dir doubles as comparison_window.evaluate's own
    # `new_subject_dir` (gate.py passes it straight through) -- it must
    # reflect the REAL tree actually under test, mutated copy included, or
    # the movement computed below silently compares against the wrong body.
    d = Path(tempfile.mkdtemp(dir=scratch))
    for f in tree.glob("*.yaml"):
        if f.name != "kustomization.yaml":
            (d / f.name).write_text(f.read_text())
    (d / "versions.yaml").write_text(yaml.safe_dump({"versions": legal_history}))
    return d


def run(declared: str, new_tree: Path) -> dict:
    subject = subject_with(new_tree, ["2.0.0"])
    corpus_dir = Path(tempfile.mkdtemp(dir=scratch))
    # inside_pin stays '3.0.0' -- the literal v3.0.0's own self-scope
    # matchConditions actually carries (render-version-tree.py baked it in
    # when that tree was rendered and committed for real) -- never the
    # hypothetical `declared` under test here. Varying `declared` alone
    # against the SAME real committed body is exactly what proves the gate's
    # bump-comparison rule, isolated from corpus generation's own pin axis.
    corpus_generator.build_manifest(DIST / "policies" / "v2.0.0", new_tree,
                                     inside_pin="3.0.0", out_dir=corpus_dir)
    window = comparison_window.ComparisonWindow(
        old_window=["2.0.0"], new_window=["2.0.0"],
        subject_tree_for=lambda v: new_tree if v == "3.0.0" else DIST / "policies" / f"v{v}",
    )
    repo_state = gate.RepoState(subject_dir=subject, corpus_dir=corpus_dir, window=window)
    return gate.run_gate(repo_state, declared)


if case == "pass":
    print("-- declared 3.0.0 (the real tag's own number), against the REAL, unmodified v3.0.0 tree --")
    doc_pass = run("3.0.0", DIST / "policies" / "v3.0.0")
    assert doc_pass["outcome"]["result"] == "passed", doc_pass["outcome"]
    # cs-16: posture-trust-boundary.yaml's real body is byte-identical between
    # v2.0.0 and v3.0.0 modulo the version literal (see cage_engine.py's module
    # docstring and selfcheck #15) -- the "major" this used to compute was the
    # self-scope vacuous-match artifact, not real movement. require-nonroot's
    # real widening there is Audit-only, which never registers movement either
    # (CONTEXT.md's own admitted/refused rule). Honestly, this real pair has no
    # modeled content movement at all -- "none" -- and a declared "major" is
    # simply stronger than required, which the gate allows (over-declaring never
    # refuses).
    assert doc_pass["bump"] == {"declared": "major", "computed": "none"}, doc_pass["bump"]
    assert all(m["verdict"] == "none" for m in doc_pass["movement"]), doc_pass["movement"]
    print(json.dumps({"outcome": doc_pass["outcome"], "bump": doc_pass["bump"],
                       "movement": [(m["policy"], m["verdict"]) for m in doc_pass["movement"]]}, indent=2))
    (scratch / "evidence-pass-3.0.0.json").write_text(json.dumps(doc_pass, indent=2))
    print(f"ok  PASS proved for real: declared major (over-declared) >= computed none, against the "
          f"real, UNMODIFIED v2.0.0->v3.0.0 predecessor -- honestly no real content movement there")
else:
    print("-- declared 2.1.0, against v3.0.0 with ONE disclosed real mutation: require-nonroot promoted Audit->Deny --")
    # require-nonroot.yaml's own real v3.0.0 comment already names this as
    # planned future work ("Audit->Deny promotion is a separate, editorial PR");
    # applying it here is an early, explicit instance of a change this repo
    # already intends, not a fabricated scenario. The CEL body is untouched --
    # only validationActions changes -- so this is a genuine narrowing: a pod
    # that already fails require-nonroot's real "must run as non-root" check
    # (the corpus generates one on purpose) flips from Audit-admitted to
    # Deny-refused.
    mutated_v3 = Path(tempfile.mkdtemp(dir=scratch))
    for f in (DIST / "policies" / "v3.0.0").glob("*.yaml"):
        if f.name == "kustomization.yaml":
            continue
        text = f.read_text()
        if f.name == "require-nonroot.yaml":
            assert "validationActions: [Audit]" in text, "require-nonroot.yaml's real shape changed"
            text = text.replace("validationActions: [Audit]", "validationActions: [Deny]")
        (mutated_v3 / f.name).write_text(text)

    doc_refused = run("2.1.0", mutated_v3)
    assert doc_refused["outcome"]["result"] == "refused", doc_refused["outcome"]
    assert doc_refused["bump"] == {"declared": "minor", "computed": "major"}, doc_refused["bump"]
    assert "require-nonroot.yaml" in doc_refused["outcome"]["reason"], doc_refused["outcome"]["reason"]
    assert "weaker than the computed bump" in doc_refused["outcome"]["reason"], doc_refused["outcome"]["reason"]
    print(json.dumps({"outcome": doc_refused["outcome"], "bump": doc_refused["bump"]}, indent=2))
    (scratch / "evidence-refused-2.1.0.json").write_text(json.dumps(doc_refused, indent=2))
    print(f"ok  REFUSAL proved for real: declared minor < computed major, real v2.0.0 predecessor plus "
          f"the one disclosed require-nonroot Audit->Deny mutation, reason names require-nonroot.yaml")
PY

part_a() {  # part_a <pass|refused> -- one real gate.run_gate() case per process
python3 "$scratch/part-a.py" "$here" "$scratch" "$1"
}

part_b() {
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
echo "B3. a real, legal, first-release (empty predecessor window) policy tag passes end to end -- gate, then TWO real commits BEFORE a real tag"
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
import re
p = "distribution/versions.yaml"
text = open(p).read()
# Locate the array block by shape (the `- versions:` key and the run of
# element AND COMMENT lines under it), never by its verbatim content: the
# real array grows with every release and the template around it changes too.
#
# The comment alternative is load-bearing, not decoration. Ticket 26 added
# the 4.0.0 element behind an eight-line comment block; an elements-only run
# stopped at that comment and left 4.0.0 sitting in the array AFTER the
# rewrite, so this case -- which exists to prove an EMPTY predecessor window
# -- was silently gating 9.0.0 against a real predecessor. The claim is
# unchanged and now actually held: the assertion below re-reads the file and
# demands the array really is [9.0.0] before the gate is asked anything.
block = re.compile(
    r'^(?P<indent>[ ]+)- versions:\n'
    r'(?P<elems>(?:(?P=indent)    (?:- \{ version:|#).*\n)+)', re.M)
matches = block.findall(text)
assert len(matches) == 1, f"expected exactly one versions.yaml array block, found {len(matches)}"
m = block.search(text)
new = f'{m.group("indent")}- versions:\n{m.group("indent")}    - {{ version: "9.0.0", tag: "policy/v9.0.0", commit: "{sha}" }}\n'
open(p, "w").write(text[:m.start()] + new + text[m.end():])

import yaml
elements = yaml.safe_load(open(p).read())["spec"]["inputs"][0]["versions"]
assert [e["version"] for e in elements] == ["9.0.0"], (
    f"the array rewrite left {[e['version'] for e in elements]} -- B3 needs a genuinely "
    f"EMPTY predecessor window, and a leftover element makes its 'no predecessor' "
    f"assertion untestable"
)
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
# after_commit_head is commit A (the evidence commit) -- it is NOT tree_sha
# (the commit that rendered the tree, and the value versions.yaml's `commit`
# field carried going INTO this dispatch). This is exactly the disagreement
# an adversarial review found: left uncorrected, the array would go on
# naming tree_sha for ever while the eventual tag resolves somewhere later.
[ "$after_commit_head" != "$tree_sha" ] || fail "B3: evidence commit unexpectedly equals the tree-render commit -- test no longer isolates the bug this ticket fixes"

./.github/scripts/cut-release-update-array-commit.sh tags-b3.json
after_array_commit_head=$(git rev-parse HEAD)
[ "$after_array_commit_head" != "$after_commit_head" ] || fail "B3: no new commit landed for the versions.yaml array update"
[ "$(git rev-parse "${after_array_commit_head}^")" = "$after_commit_head" ] || fail "B3: the array-update commit is not the evidence commit's direct child"

./.github/scripts/cut-release-create-tags.sh tags-b3.json
tag_commit=$(git rev-parse refs/tags/policy/v9.0.0^{commit})
[ "$tag_commit" = "$after_array_commit_head" ] || fail "B3: tag does not resolve to the array-update commit ($tag_commit != $after_array_commit_head)"
git show --stat "$after_commit_head" | grep -q "computed-semver/evidence/9.0.0.json" || fail "B3: evidence file not in the evidence commit"

# THE invariant ticket 28's adopter gate (and cs-15's own acceptance
# criterion) needs to hold forever: versions.yaml's `commit` field for the
# cut version equals the EVIDENCE commit's real SHA (commit A) -- one commit
# BEHIND the tag it actually resolves to (commit B) -- and commit A is
# commit B's direct parent, so "the array's commit field" and "the tag's
# resolved commit" relate by exactly one well-defined, documented hop, never
# by accident and never by disagreement.
recorded_commit=$(python3 -c "
import yaml
doc = yaml.safe_load(open('distribution/versions.yaml').read())
els = {e['version']: e['commit'] for e in doc['spec']['inputs'][0]['versions']}
print(els['9.0.0'])
")
[ "$recorded_commit" = "$after_commit_head" ] || fail "B3: versions.yaml commit field ($recorded_commit) != the evidence commit ($after_commit_head)"
[ "$recorded_commit" != "$tag_commit" ] || fail "B3: versions.yaml commit field equals the tag's resolved commit -- should be its parent (one commit behind), not the same commit"
echo "ok  B3: gate passed for real; evidence committed (A), then versions.yaml's commit field corrected to A in a second commit (B); the tag resolves to B, and versions.yaml's commit field for 9.0.0 equals A -- B's direct parent, one commit behind the tag, on purpose"

cd "$here"
}

part_c() {
say "Part C: cs-16 regression -- a BACKPORT's corpus/classification basis is the LOWER neighbor, never the higher one"
echo "distribution/versions.yaml's REAL array right now is [2.0.0, 2.0.1, 3.0.0] (cs-16's own real"
echo "backport, prepared but not yet tagged) -- exactly the three-element, cut-in-the-middle shape"
echo "this bug needs: cutting 2.0.1 with 3.0.0 already sitting above it in the array. Before the fix,"
echo "gate_one()'s old_for_corpus picked max(old_window) = 3.0.0 (the highest version ANYWHERE in the"
echo "array, unrelated and already shipped) instead of 2.0.0 (the real, lower predecessor) -- this"
echo "proves the corpus is now built against 2.0.0, not 3.0.0."
python3 - "$here" <<'PY'
import sys, importlib.util
from pathlib import Path

repo = Path(sys.argv[1])
sys.path.insert(0, str(repo / "computed-semver"))
import corpus_generator  # noqa: E402

spec = importlib.util.spec_from_file_location("cut_release_gate", repo / ".github/scripts/cut-release-gate.py")
crg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crg)

array = corpus_generator._orphan_guard.elements(crg.DISTRIBUTION / "versions.yaml")
array_versions = {e["version"] for e in array}
assert {"2.0.0", "2.0.1", "3.0.0"} <= array_versions, (
    f"cs-16's real backport array shape is gone from distribution/versions.yaml ({array_versions}) -- "
    f"this regression test needs the real cut-in-the-middle case, not a fixture"
)
legal_history = crg.real_tag_history(repo)

record = crg.gate_one("2.0.1", ["2.0.1"], array, legal_history)
assert record["old_subject_dir"] == "distribution/policies/v2.0.0", (
    f"cs-16 regression: old_for_corpus picked {record['old_subject_dir']!r}, "
    f"not v2.0.0 -- the backport's corpus basis is the higher, unrelated 3.0.0 line again"
)
print(f"ok  Part C: gate_one('2.0.1', ...) built its corpus against {record['old_subject_dir']} "
      f"(the real lower neighbor), not distribution/policies/v3.0.0")

# cs-16's SECOND, deeper bug (found while proving the backport passes for
# real): even against the correct predecessor, gate_one('2.0.1', ...) used
# to REFUSE -- major, driven entirely by posture-trust-boundary.yaml, a
# self-scoped ValidatingPolicy whose real body is byte-identical between
# v2.0.0 and v2.0.1 modulo the version literal. The corpus's `inside_pin`
# pins every generated pod to the CANDIDATE version only, so the OLD body's
# own `only-this-policy-version` matchCondition vacuously skipped almost
# every corpus pod (kyverno `skip`, read as trivially "admitted") while the
# NEW body evaluated the same pods for real -- a spurious major with nothing
# to do with the real release content. cage_engine.py now neutralizes only
# that named matchCondition before comparing (see its module docstring and
# selfcheck #15 for the full mechanism and the real kyverno proof); this is
# the regression guard against it recurring at the real, live seam.
assert record["outcome"]["result"] == "passed", (
    f"cs-16 regression: gate_one('2.0.1', ...) refused a genuine patch backport -- "
    f"{record['outcome']}"
)
assert record["bump"] == {"declared": "patch", "computed": "none"}, record["bump"]
ptb = next(m for m in record["movement"] if m["policy"] == "posture-trust-boundary.yaml")
assert ptb["verdict"] == "none", (
    f"cs-16 regression: posture-trust-boundary.yaml classified {ptb['verdict']!r}, "
    f"not 'none' -- the self-scope vacuous-match artifact is back"
)
print("ok  Part C: gate_one('2.0.1', ...) PASSES against the real, correct predecessor -- "
      "posture-trust-boundary.yaml honestly classifies 'none', not the old spurious 'major'")
PY
}

say "Part A: gate.run_gate() against the REAL v2.0.0 -> v3.0.0 predecessor (minutes of real kyverno CPU, one real apply per corpus fixture -- spent concurrently with Parts B and C)"
echo "(Parts A, B and C all start now, one process each -- every part's output is printed, in order, below.)"
part_a pass    > "$scratch/a-pass.log"    2>&1 & a_pass=$!
part_a refused > "$scratch/a-refused.log" 2>&1 & a_refused=$!
part_b         > "$scratch/b.log"         2>&1 & b_pid=$!
part_c         > "$scratch/c.log"         2>&1 & c_pid=$!

rc=0
for spec in "a-pass:$a_pass" "a-refused:$a_refused" "b:$b_pid" "c:$c_pid"; do
  wait "${spec#*:}" || rc=1
  cat "$scratch/${spec%%:*}.log"
done
[ "$rc" -eq 0 ] || fail "a part above failed -- its own FAIL/assert line names which"

echo
echo "PASS: run_gate() refuses a real declared bump weaker than the real computed one (a disclosed,"
echo "real Audit->Deny mutation on top of v3.0.0) and passes a legal-or-stronger one against the"
echo "real, UNMODIFIED v2.0.0/v3.0.0 predecessor -- which honestly computes 'none', not the old"
echo "spurious 'major' (cs-16); cut-release-gate.py's wiring skips a platform-only tag, refuses"
echo "cleanly with no commit and no tag when a policy tag's tree is missing, and -- on a real pass --"
echo "commits the signed evidence, then commits a correction pointing versions.yaml's commit field at"
echo "that evidence commit, and only then tags -- so the tag resolves to the array-update commit, one"
echo "ahead of the commit the array names; a real backport (cs-16's own 2.0.1, cut between 2.0.0 and"
echo "the already-shipped 3.0.0) builds its corpus against the real lower neighbor, never the higher,"
echo "unrelated line, AND now genuinely PASSES the gate end to end."
