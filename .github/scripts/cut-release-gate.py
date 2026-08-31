#!/usr/bin/env python3
"""cut-release-gate.py -- ticket cs-27: the publisher gate, wired into
cut-release.yml, BEFORE `git tag` -- and the same code an offline twin runs
locally (verify-publisher-gate.sh), before signing.

Which tags does the gate apply to, when one dispatch carries several?
--------------------------------------------------------------------------
cut-release.yml's `tags` input can carry more than one tag in one dispatch --
the real repair release (cs-15) cut `v1.0.0` (platform's own tag) alongside
`policy/v2.0.0` and `policy/v3.0.0` (the policy version array) off a single
commit. `gate.run_gate()` takes exactly ONE declared version, so this module
decides how the seam applies to a multi-tag dispatch:

  * The gate's subject is `distribution/versions.yaml`'s policy line (spec.md,
    "Where the gate runs" -- coverage, movement, the comparison window, the
    four cs-26 structural rules, all of it is about THAT array). Platform's
    own tag (`v1.0.0`, no `policy/` prefix) names no element of that array --
    cs-15's own tags.json split is the precedent: `v1.0.0` on one line,
    `policy/v2.0.0`/`policy/v3.0.0` on the other. This module keeps that
    split: only `policy/v<semver>` tags enter the gate. A bare `vX.Y.Z` tag
    (platform's own line, cs-07's job) is not this ticket's subject and is
    skipped outright -- never silently gated as if it were a policy release.
  * **Once per policy tag**, not once per dispatch. Two policy tags cut
    together are still two independent array elements, each with its own
    declared bump and its own movement against the window -- collapsing them
    into one combined check would let one line's real major hide behind the
    other line's patch, exactly the "strictest result wins" rule spec.md
    already states for the comparison window, just at a coarser grain.
  * **The window used for every tag in the dispatch is the array as it stood
    BEFORE this dispatch** -- every element already in `versions.yaml` MINUS
    every version being cut in THIS dispatch, whether that is one tag or
    several. Two versions cut together therefore do NOT see each other as
    predecessors (matches spec.md, "the window as it stood before this
    release" -- a multi-tag dispatch is one release event, exactly as cs-15's
    own commit message treats its two lines: "one hand-classified release,
    one commit, three tags"). A version cut alone, with an already-tagged
    predecessor sitting in the array, sees that predecessor normally.
  * **A refusal on any policy tag in the dispatch blocks the whole dispatch**
    -- no partial commit, no partial tag set. `cut-release-push.sh`'s own
    atomicity promise ("never some tags pushed and others not") would be
    hollow if this gate let a dispatch through half-refused.

No override, at any scope
--------------------------------------------------------------------------
There is no flag, secret, environment variable, or dispatch input anywhere
in this file that changes a `run_gate()` verdict. `CUT_RELEASE_TEST_MODE`
(the SAME switch `cut-release-create-tags.sh` already defines) only swaps
`cosign sign-blob` for a clearly-marked non-signature stand-in when no live
Actions signing identity exists (this machine, a laptop) -- it never touches
`run_gate()`, `comparison_window.evaluate()` or `release_integrity.refusal()`.
Grep this file for the string if in doubt: it appears exactly once, wrapping
the `cosign` subprocess call and nothing else.

Usage:
    cut-release-gate.py <tags.json>

Exit 0 and the evidence files sit under computed-semver/evidence/, staged
for the next workflow step to commit -- exit non-zero and nothing is staged;
the caller uploads computed-semver/evidence/ as a run artifact regardless.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
COMPUTED_SEMVER = REPO / "computed-semver"
sys.path.insert(0, str(COMPUTED_SEMVER))

import yaml  # noqa: E402

import comparison_window  # noqa: E402
import corpus_generator  # noqa: E402
import gate  # noqa: E402
import release_integrity  # noqa: E402

DISTRIBUTION = corpus_generator.DISTRIBUTION
# Ticket 43 (18 Answer 1): prerelease-aware, because a DEGRADED publish is
# tagged `policy/v4.0.1-quarantine.1` -- the declared base number plus a
# suffix. `release.yml`'s own `policy/v*.*.*` glob already matched that
# shape; this regexp and cut-release-normalize.py's TAG_RE did not.
POLICY_TAG_RE = re.compile(r"^policy/v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")
EVIDENCE_DIR = COMPUTED_SEMVER / "evidence"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True)


def real_tag_history(repo: Path) -> list[str]:
    """Every version this repo has EVER really tagged `policy/v<version>` --
    tags are immutable here (cut-release-refuse-existing.sh's own docstring),
    so this is the full legal-version history gate.py's version-legality
    rule needs its base from (gate.py's own `existing_versions` docstring:
    "Not the same array as distribution/versions.yaml, which is the
    currently-SUPPORTED window -- a subset")."""
    out = _git(repo, "tag", "-l", "policy/v*").stdout.split()
    versions = [t[len("policy/v"):] for t in out]
    return sorted(versions, key=comparison_window.parse_semver)


def build_current_subject(version: str, legal_versions: list[str]) -> Path:
    """RepoState.subject_dir for `version`: a temp copy of the real,
    already-committed `distribution/policies/v<version>/` tree (the release
    commit that adds it lands before this dispatch runs -- release_integrity's
    own rule 2/3 read that real directory directly) plus a `versions.yaml`
    carrying the full legal history minus `version` itself, which
    `gate.existing_versions()` reads for the legality rule. `versions.yaml`
    sitting alongside real policy bodies is the pattern pairing.py's own
    docstring already documents as safe ("Non-policy documents... are
    skipped, not guessed at")."""
    real_tree = DISTRIBUTION / "policies" / f"v{version}"
    d = Path(tempfile.mkdtemp(prefix=f"gate-subject-{version}-"))
    if real_tree.exists():
        for f in real_tree.glob("*.yaml"):
            if f.name != "kustomization.yaml":
                (d / f.name).write_text(f.read_text())
    history = [v for v in legal_versions if v != version]
    (d / "versions.yaml").write_text(yaml.safe_dump({"versions": history}))
    return d


def _has_predicates(tree_dir: Path) -> bool:
    """Cheap existence guard, never raises: `corpus_generator.predicates()`
    itself tolerates a directory with zero matching yaml but
    `generate_spine` refuses to build against zero PREDICATE expressions --
    this checks the same condition ahead of that call, so a missing/empty
    tree degrades to "skip corpus generation" instead of an exception."""
    if not tree_dir.exists():
        return False
    return bool(corpus_generator.predicates(tree_dir))


def declared_bump(array: list[dict], version: str) -> str | None:
    """Ticket 43 (18 Answer 5): the bump the release DECLARES, off the
    reviewed `versions.yaml` array element -- "the array element is already
    the reviewed unit and the gate already parses it". Absent -> None, and
    run_gate keeps deriving the bump from the number exactly as before, so
    every element cut before this field existed still gates."""
    for element in array:
        if element.get("version") == version:
            bump = element.get("bump")
            return str(bump) if bump else None
    return None


def degraded_tag(version: str, legal_history: list[str]) -> str:
    """The number a DEGRADED release publishes under: the declared BASE
    number, untouched, plus `-quarantine.N` (ADR-0011's superseding note).
    N counts past degraded publishes of the same base number, so a second
    degraded attempt at 4.0.1 is `4.0.1-quarantine.2`, which sorts above
    `.1` and still below the clean `4.0.1`."""
    base = comparison_window.base_version(version)
    prefix = f"{base}-{gate.DEGRADED_TIER}."
    n = 1 + sum(1 for v in legal_history if v.startswith(prefix))
    return f"{base}-{gate.DEGRADED_TIER}.{n}"


def gate_one(version: str, cut_versions: list[str], array: list[dict], legal_history: list[str]) -> dict:
    """Builds the real RepoState for `version` and runs it through the one
    seam. `cut_versions` is every policy version in THIS dispatch (so the
    window excludes all of them, not just `version` -- see module docstring,
    "one release event")."""
    array_versions = [e["version"] for e in array]
    old_window = [v for v in array_versions if v not in cut_versions]
    new_window = array_versions  # the array as already committed at HEAD -- the post-release state

    subject_dir = build_current_subject(version, legal_history)

    # A backport lands BELOW an already-existing higher version (e.g. 2.0.1
    # cut into [2.0.0, 2.0.1, 3.0.0] with 3.0.0 already shipped) -- one
    # determination, reused for BOTH the comparison window's own backport
    # narrowing (movement/classification, below) and the corpus-generation
    # predecessor here, so the two can never disagree about which line sits
    # directly below `version` (this is exactly the bug this comment block
    # replaces: `max(old_window)` picked the highest version ANYWHERE in the
    # array, not the highest one BELOW `version`, so a backport's corpus was
    # built against an unrelated, already-shipped higher line).
    is_backport = any(comparison_window.parse_semver(v) > comparison_window.parse_semver(version)
                       for v in old_window)
    below_declared = comparison_window.window_below(old_window, version, backport=is_backport)
    # 2026-08-29: the declared array can legitimately hold ONE line. The whole
    # 2.x/3.x fan-out was retired (unable to admit a pod, and reading the tier
    # from the pod's own label), so cutting 4.0.0 left `old_window` empty and
    # the computed bump came out "no predecessor" -- the gate could not compute
    # anything to compare the declaration against, which is the one thing it
    # exists to do. A RETIRED version is still a RELEASED one: it is what the
    # world was pinned to before this release, its tree is on disk behind its
    # signed tag, and retiring it from the window is itself a major (see
    # comparison_window._retirement_movement). So the predecessor falls back to
    # the real tag history, never to nothing. This is gap 2 of the two
    # distribution/README.md named.
    if not below_declared:
        released_trees = [v for v in legal_history
                          if (DISTRIBUTION / "policies" / f"v{v}").is_dir()]
        below_declared = comparison_window.window_below(released_trees, version)[-1:]
        # `old_window` is deliberately NOT reassigned here. It is the window as
        # DECLARED before this release, and the retirement rule reads it: any
        # version in it and not in `new_window` is reported retired, a major.
        # Writing the fallback into it fabricates a retirement of a version the
        # array never declared -- a release that moves nothing then classifies
        # major, naming a "retirement" that never happened (observed 2026-08-29
        # in tuppence's adopter-gate Scenario A). The fallback exists to give
        # the BODY diff a basis when the declared window is empty, and
        # `old_for_corpus` below is the only thing that should read it. A real
        # retirement still surfaces: the adopter gate compares the arrays at
        # the two pins it is given, which is where a consumer actually feels it.
    old_for_corpus = below_declared[-1] if below_declared else version
    old_tree = DISTRIBUTION / "policies" / f"v{old_for_corpus}"
    new_tree = DISTRIBUTION / "policies" / f"v{version}"
    corpus_dir = Path(tempfile.mkdtemp(prefix=f"gate-corpus-{version}-"))
    # A declared version whose real tree does not exist yet (or is empty) is
    # a release_integrity refusal (rerender_refusal names it "(missing)"),
    # never a crash here -- generate_spine raises on zero predicates, so
    # corpus generation is skipped rather than attempted; run_gate() still
    # reaches release_integrity.refusal() first (it runs before any
    # corpus-manifest read) and refuses with the real, useful reason instead
    # of an unhandled traceback.
    if _has_predicates(new_tree) and _has_predicates(old_tree):
        corpus_generator.build_manifest(old_tree, new_tree, inside_pin=version, out_dir=corpus_dir)

    window = comparison_window.ComparisonWindow(
        old_window=old_window,
        new_window=new_window,
        subject_tree_for=lambda v: DISTRIBUTION / "policies" / f"v{v}",
        backport=is_backport,
    )
    # release_integrity's four rules are about RELEASED versions: rule 1 reads a
    # prior version's frozen tree from its git TAG, and rule 4 refuses a released
    # element whose `commit` is empty. An array element for a version that has
    # never been tagged is not a released version -- it is a version DECLARED and
    # not yet cut (the ResourceSet template makes `commit` optional for exactly
    # that state, and cut-release fills it when it cuts the tag). Reading a tag
    # that does not exist yet, or demanding a commit for a release that has not
    # happened, is a refusal about the future, not about the shipped estate. So
    # the release-integrity subject is the array filtered to `legal_history` --
    # this module's own "every version this repo has EVER really tagged".
    released = [e for e in array if e["version"] in legal_history]
    prior_versions = {e["version"]: e["tag"] for e in released if e["version"] in old_window}
    release = release_integrity.ReleaseIntegrity(
        git_repo=REPO, policies_dir=DISTRIBUTION / "policies",
        prior_versions=prior_versions, version_array=released,
    )
    repo_state = gate.RepoState(subject_dir=subject_dir, corpus_dir=corpus_dir, window=window,
                                release=release, declared_bump=declared_bump(array, version))
    doc = gate.run_gate(repo_state, version)

    # cs-25's generator_standing_check.py evidence-record convention
    # (computed-semver/evidence/*.json, {declared, subject_dir,
    # old_subject_dir, computed_bump, generator_version}) -- extended here
    # with cs-27's own full run_gate() document, not replaced by it, per that
    # module's own docstring: "cs-27 owns the FULL signed evidence commit and
    # is free to relocate/extend this; only the fields this check reads are
    # pinned here."
    record = dict(doc)
    record["declared"] = version
    record["subject_dir"] = str(new_tree.relative_to(REPO))
    record["old_subject_dir"] = str(old_tree.relative_to(REPO)) if below_declared else None
    record["computed_bump"] = doc["bump"]["computed"]
    return record


def sign_evidence(path: Path) -> Path:
    """`cosign sign-blob` keyless, using this run's own ambient GitHub
    Actions identity (the same one gitsign already uses in this workflow --
    see cut-release.yml's own header comment). `CUT_RELEASE_TEST_MODE` (the
    same switch cut-release-create-tags.sh defines) swaps this for a
    clearly-marked non-signature so the offline twin can exercise everything
    around it -- the evidence shape, the pass/refuse branching, the
    commit-before-tag order -- without a live Actions identity. It changes
    nothing about what `run_gate()` decided; the gate ran to completion
    before this function is ever called."""
    bundle = path.with_name(path.name + ".bundle")
    if os.environ.get("CUT_RELEASE_TEST_MODE") == "1":
        bundle.write_text(json.dumps({
            "test_mode": True,
            "note": (
                "CUT_RELEASE_TEST_MODE=1 -- no real cosign signature. Keyless "
                "signing needs a live Actions signing identity this offline "
                "run does not have; nothing here is presented as verification "
                "material (release.yml's own check reads this flag and "
                "refuses to treat it as a real bundle)."
            ),
        }, indent=2))
        return bundle
    subprocess.run(["cosign", "sign-blob", "--yes", f"--bundle={bundle}", str(path)], check=True)
    return bundle


def write_summary(records: list[tuple[str, dict]]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = ["## Publisher gate\n", "| tag | declared | computed | outcome | reason |", "| --- | --- | --- | --- | --- |"]
    for tag, record in records:
        outcome = record["outcome"]
        reason = (outcome.get("reason") or "").replace("|", "\\|")
        lines.append(f"| `{tag}` | {record['bump']['declared']} | {record['bump']['computed']} | "
                     f"{outcome['result']} | {reason} |")
    text = "\n".join(lines) + "\n"
    print(text)
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(text)


def main(argv: list[str]) -> int:
    # `--dry-run`: run the whole gate, write the evidence, print the tag CI
    # would cut -- and sign nothing. Ticket 43's own rule: everything a
    # release needs is real except the signature, because a gitsign tag and a
    # keyless cosign bundle can only be produced by cut-release.yml inside
    # Actions. A dry run that wrote a stand-in bundle would be faking the one
    # thing that cannot be faked, so it writes none at all.
    dry_run = "--dry-run" in argv
    argv = [a for a in argv if a != "--dry-run"]
    if len(argv) != 2:
        print("usage: cut-release-gate.py [--dry-run] <tags.json>", file=sys.stderr)
        return 2
    tags_path = Path(argv[1])
    entries = json.loads(tags_path.read_text())

    cut: list[tuple[str, str]] = []  # (tag, version)
    for e in entries:
        m = POLICY_TAG_RE.match(e["tag"])
        if m:
            cut.append((e["tag"], m.group(1)))
        else:
            print(f"ok  {e['tag']!r} is not a policy tag -- not this gate's subject, skipped")

    if not cut:
        print("no policy tags in this dispatch -- the gate's subject is distribution/versions.yaml's "
              "policy line; nothing to check, nothing to sign, nothing to commit")
        return 0

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    array = corpus_generator._orphan_guard.elements(DISTRIBUTION / "versions.yaml")
    cut_versions = [v for _, v in cut]
    legal_history = real_tag_history(REPO)

    records: list[tuple[str, dict]] = []
    retag: dict[str, str] = {}  # declared tag -> the tag actually cut
    for tag, version in sorted(cut, key=lambda tv: comparison_window.parse_semver(tv[1])):
        record = gate_one(version, cut_versions, array, legal_history)
        published = version
        if record["outcome"]["result"] == "degraded":
            # Ticket 18 Answer 1: a degraded publish carries a prerelease
            # suffix on the DECLARED number. The base number is untouched --
            # this is the one rewrite ADR-0011 did not consider, and it is a
            # rewrite of the suffix, never of the number the publisher
            # declared. The evidence is filed under the number actually
            # published, so evidence file and tag always name the same thing.
            published = degraded_tag(version, legal_history)
            record["published_as"] = published
            retag[tag] = f"policy/v{published}"
            print(f"DEGRADED {tag}: {record['outcome']['reason']}")
            print(f"         publishing as policy/v{published} (tier "
                  f"{record['degraded']['tier']}), array element carries tier: "
                  f"{record['degraded']['tier']}")
        evidence_path = EVIDENCE_DIR / f"{published}.json"
        evidence_path.write_text(json.dumps(record, indent=2, sort_keys=False))
        if dry_run:
            print(f"dry run: wrote {evidence_path.relative_to(REPO)}, signed nothing")
        else:
            bundle_path = sign_evidence(evidence_path)
            print(f"signed: {bundle_path}")
        records.append((retag.get(tag, tag), record))

    write_summary(records)

    refused = [(tag, r) for tag, r in records if r["outcome"]["result"] not in ("passed", "degraded")]
    if refused:
        for tag, r in refused:
            print(f"REFUSED {tag}: {r['outcome']['reason']}", file=sys.stderr)
        print("GATE: refused -- no commit, no tag. Signed evidence uploaded as a run artifact.", file=sys.stderr)
        return 1

    if retag and not dry_run:
        # The later steps (create-tags, push, the array correction) all read
        # tags.json, so the suffix is applied once, here, where the gate
        # decided it -- never re-derived by three separate scripts.
        for e in entries:
            if e["tag"] in retag:
                e["message"] = f"{e['message']} [degraded: published at tier {gate.DEGRADED_TIER}]"
                e["tag"] = retag[e["tag"]]
        tags_path.write_text(json.dumps(entries))

    for tag, _ in records:
        print(f"GATE: cut-release.yml must cut {tag} in Actions -- a gitsign tag and a keyless "
              f"cosign bundle need a live Actions signing identity, which no local run has")
    print(f"GATE: passed for {', '.join(tag for tag, _ in records)}"
          + (" (some DEGRADED -- see above)" if retag else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
