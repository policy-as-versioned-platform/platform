#!/usr/bin/env python3
"""generator_standing_check.py -- ticket cs-25: the generator's own standing
check. Needs ticket cs-21.

spec.md, "Signing and verification": "Evidence is pinned to its generator
version and never recomputed. A pull request that changes the generator
re-runs the previous release under the new generator and prints a line if
the classification would differ. It does not fail." And "Testing Decisions":
"A change to the generator re-runs the three known-good bumps and is
refused if any stops re-deriving. That is the map's own rule applied to the
tool." One standing check, like verify-rederive-bumps.sh -- not a
per-function test suite.

Two halves, two different failure disciplines:

  1. The three known-good bumps (rederive_bumps.PAIRS -- ticket cs-01's own
     "major", "patch", "minor" reproductions from the real historical release
     line) MUST still rederive. Refuses (non-zero exit) if any stops.

     Honesty note: these three specific fixtures are, by cage_engine.py's own
     documented design (module docstring, the "ponytail: a genuine, disclosed
     gap" paragraph), INDEPENDENT of corpus_generator.py -- the historical
     policy bodies predate the `.orValue(...)` CEL idiom `probe_for`
     recognizes, so corpus_generator cannot generate a spine for them at all;
     gate.py's own selfcheck bypasses it with a hand-built manifest for
     exactly this reason, and `check_known_good_bumps` below does the same.
     A change to corpus_generator.py cannot, by construction, move this
     particular result -- `check_generator_pinning` below is the other half
     of "the generator" that a corpus_generator.py change CAN move, and is
     the one this ticket's regression proof (see its own docstring) breaks
     for real.

  2. The most recent evidence record on disk (if one exists yet -- ticket
     cs-15/cs-27's job, not landed anywhere as of this ticket) is re-run
     under the CURRENT generator and gate code. A differing computed bump
     PRINTS a line and does not fail the build -- "a human decides whether a
     past release was mislabelled." The record on disk is never written to;
     comparison happens entirely in memory (`rerun_under_new_generator`
     never opens its `record` file for writing).

Evidence-record file shape (this ticket's own minimal convention -- ticket
cs-27 owns the FULL signed evidence commit and is free to relocate/extend
this; only the fields this check reads are pinned here):

    {
      "declared": "1.2.0",
      "subject_dir": "distribution/policies/v1.2.0",       # repo-relative
      "old_subject_dir": "distribution/policies/v1.1.0",    # repo-relative, null for a first release
      "computed_bump": "major",
      "generator_version": "0.1.2"
    }

one per file, glob `computed-semver/evidence/*.json`, most recent = highest
`declared` semver (comparison_window.parse_semver, reused rather than
re-parsed).

Usage:
    generator_standing_check.py           # the standing check itself
    generator_standing_check.py --selfcheck
"""
from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import yaml

import cage_engine
import comparison_window
import corpus_generator
import gate
import rederive_bumps

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

EVIDENCE_DIR = HERE / "evidence"
GENERATED_MANIFEST = HERE / "generated-corpus" / "manifest.yaml"


# ---------------------------------------------------------------------------
# 1. The three known-good bumps
# ---------------------------------------------------------------------------

def _check_pair(pair: rederive_bumps.Pair) -> list[str]:
    """Every `expected_per_policy` verdict `pair` names, reproduced through
    cage_engine.classify_validating (ticket cs-21's own Track-1 wrapper,
    reused rather than re-derived) against the fixed ALL_FIXTURES corpus.
    Returns the mismatches (empty == every named verdict rederived exactly)."""
    mismatches: list[str] = []
    for name, expected in pair.expected_per_policy.items():
        old_file = rederive_bumps.CORPUS / pair.old[name] if name in pair.old else None
        new_file = rederive_bumps.CORPUS / pair.new[name] if name in pair.new else None
        m = cage_engine.classify_validating(name, old_file, new_file, rederive_bumps.ALL_FIXTURES)
        if m.verdict != expected:
            mismatches.append(
                f"{pair.name} {name}: expected {expected!r}, got {m.verdict!r} -- {m.detail}"
            )
    return mismatches


def check_known_good_bumps() -> list[str]:
    """The three known-good bumps -- major (require-department-label,
    1.0.0->2.0.0), patch (require-known-department-label, 2.0.1->2.1.1) and
    minor (require-owner-annotation, absent->2.1.1) -- plus the unchanged
    baseline (require-department-label staying "none" across 2.0.1->2.1.1)
    they are compared against. Non-empty return == refuse."""
    out: list[str] = []
    for pair in rederive_bumps.PAIRS:
        out.extend(_check_pair(pair))
    return out


# ---------------------------------------------------------------------------
# 1b. The generator's own version pinning -- the half of "the generator"
#     that a corpus_generator.py change genuinely does move.
# ---------------------------------------------------------------------------

def check_generator_pinning(manifest_path: Path = GENERATED_MANIFEST) -> list[str]:
    """The committed generated-corpus/manifest.yaml must have been produced
    by the generator AS IT STANDS TODAY -- corpus_generator.py's own
    documented convention ("Bumped by hand when this module's own logic
    changes... regenerate generated-corpus/"). A hand-bumped
    GENERATOR_VERSION with no regeneration to match -- an easy, real mistake
    -- fails here immediately. Absent manifest (a repo state that has never
    generated a corpus at all) is not a failure, same placeholder convention
    gate.py's own _read_corpus_manifest uses."""
    if not manifest_path.exists():
        return []
    committed = yaml.safe_load(manifest_path.read_text()).get("generator_version")
    if committed != corpus_generator.GENERATOR_VERSION:
        return [
            f"{manifest_path}: generator_version={committed!r} but the live "
            f"corpus_generator.GENERATOR_VERSION is {corpus_generator.GENERATOR_VERSION!r} -- "
            f"regenerate generated-corpus/ (corpus_generator.py's own documented convention)"
        ]
    return []


# ---------------------------------------------------------------------------
# 2. The most recent evidence record, re-run under the new generator
# ---------------------------------------------------------------------------

def load_evidence_records(evidence_dir: Path = EVIDENCE_DIR) -> list[dict]:
    """Every `*.json` evidence record under `evidence_dir`. An absent
    directory -- true of this repo today, since ticket cs-15/cs-27 have not
    landed a real release yet -- degrades to an empty list, not an error
    (Path.glob on a missing directory yields nothing; no existence check
    needed)."""
    return [json.loads(f.read_text()) for f in sorted(evidence_dir.glob("*.json"))]


def most_recent_evidence(records: list[dict]) -> dict | None:
    """The record with the highest `declared` version -- releases are
    declared in increasing order by construction (gate.py's own version-
    legality rule), so "most recent" and "highest declared" agree."""
    if not records:
        return None
    return max(records, key=lambda r: comparison_window.parse_semver(r["declared"]))


def rerun_under_new_generator(record: dict, repo_root: Path = REPO) -> str | None:
    """Recomputes `record`'s classification with the CURRENT generator and
    cage_engine code. Returns a human-readable line if the computed bump now
    differs from what is recorded, else None. NEVER writes to `record` or
    any file it names -- "evidence is pinned to its generator version and
    never recomputed" means the FILE keeps the number it was produced with;
    this function only compares a fresh, in-memory result against it."""
    if not record.get("old_subject_dir"):
        return None  # a first release has no predecessor to re-derive against

    subject_dir = repo_root / record["subject_dir"]
    old_subject_dir = repo_root / record["old_subject_dir"]
    declared = record["declared"]
    recorded_bump = record["computed_bump"]
    recorded_gen = record["generator_version"]

    with tempfile.TemporaryDirectory() as td:
        corpus_dir = Path(td)
        manifest = corpus_generator.build_manifest(
            old_subject_dir, subject_dir, inside_pin=declared, out_dir=corpus_dir
        )
        pods = gate._corpus_pod_paths(corpus_dir, manifest)
        fresh_bump = cage_engine.classify_repo(old_subject_dir, subject_dir, pods).computed_bump

    if fresh_bump != recorded_bump:
        return (
            f"{declared}: recorded computed bump {recorded_bump!r} (generator {recorded_gen}) "
            f"now recomputes as {fresh_bump!r} under generator {corpus_generator.GENERATOR_VERSION} "
            f"-- a human decides whether the past release was mislabelled"
        )
    return None


# ---------------------------------------------------------------------------
# selfcheck
# ---------------------------------------------------------------------------

_NONROOT_AUDIT = """\
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: require-nonroot-demo
spec:
  validationActions: [Audit]
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: "object.spec.?securityContext.?runAsNonRoot.orValue(true) == true"
      message: "containers must not run as root"
"""
_NONROOT_DENY = _NONROOT_AUDIT.replace("[Audit]", "[Deny]")


def selfcheck() -> None:
    # 1. the three known-good bumps rederive exactly, today, for real.
    assert check_known_good_bumps() == [], check_known_good_bumps()

    # 1 regression proof: the COMPARISON itself (not the underlying
    # rederivation, already proved by tickets cs-01/cs-21's own selfchecks)
    # genuinely flags a mismatch when the expectation is wrong.
    wrong = replace(rederive_bumps.PAIRS[0], expected_per_policy={"require-department-label": "minor"})
    mismatches = _check_pair(wrong)
    assert mismatches, "a deliberately wrong expectation must be caught, not pass silently"
    assert "expected 'minor'" in mismatches[0] and "got 'major'" in mismatches[0], mismatches

    # 2. generator pinning: the real committed corpus matches the live
    # generator today.
    assert check_generator_pinning() == [], check_generator_pinning()

    # 2 regression proof: a manifest recorded against a stale generator
    # version is caught, by name; a manifest that was never generated at
    # all (absent file) is not a failure.
    with tempfile.TemporaryDirectory() as td:
        stale = Path(td) / "manifest.yaml"
        stale.write_text(yaml.safe_dump({"generator_version": "0.0.0-stale"}))
        mismatches = check_generator_pinning(stale)
        assert mismatches and "0.0.0-stale" in mismatches[0], mismatches
        assert corpus_generator.GENERATOR_VERSION in mismatches[0], mismatches

        missing = Path(td) / "never-generated.yaml"
        assert check_generator_pinning(missing) == []

    # 3. evidence loading degrades gracefully when the directory does not
    # exist yet -- true of this repo today (no ticket has landed a real
    # release).
    assert load_evidence_records(Path(td) / "does-not-exist") == []
    assert most_recent_evidence([]) is None

    # 4. "most recent" picks the highest declared version, not file order.
    records = [
        {"declared": "1.0.2", "old_subject_dir": None, "computed_bump": "patch", "generator_version": "x"},
        {"declared": "2.0.1", "old_subject_dir": None, "computed_bump": "major", "generator_version": "x"},
        {"declared": "1.5.0", "old_subject_dir": None, "computed_bump": "minor", "generator_version": "x"},
    ]
    assert most_recent_evidence(records)["declared"] == "2.0.1", most_recent_evidence(records)

    # 5. a first release (no old_subject_dir) has no predecessor to re-derive
    # against -- skipped, not a crash, not a spurious "differs" line.
    assert rerun_under_new_generator({"declared": "1.0.0", "old_subject_dir": None}) is None

    # 6. the real coupling to corpus_generator.py, end to end: build a real
    # old/new subject pair (an Audit -> Deny promotion, the same shape as
    # the real 1.0.0->2.0.0 known-good major), run it once through the
    # CURRENT generator to get the "recorded" bump, then prove
    # rerun_under_new_generator (a) reports no difference when nothing
    # changed, (b) never mutates the record, and (c) DOES report a
    # difference when corpus_generator.py's own probe logic breaks --
    # the collapse-violated-into-satisfied defect class ticket cs-20's real
    # _CONTAINER_BOOL_RE regression belongs to.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        old_dir, new_dir = td / "old", td / "new"
        old_dir.mkdir(); new_dir.mkdir()
        (old_dir / "p.yaml").write_text(_NONROOT_AUDIT)
        (new_dir / "p.yaml").write_text(_NONROOT_DENY)

        manifest = corpus_generator.build_manifest(old_dir, new_dir, inside_pin="9.9.9", out_dir=td / "corpus")
        pods = gate._corpus_pod_paths(td / "corpus", manifest)
        recorded_bump = cage_engine.classify_repo(old_dir, new_dir, pods).computed_bump
        assert recorded_bump == "major", recorded_bump  # sanity: the promotion narrows, as expected

        record = {
            "declared": "9.9.9", "subject_dir": "new", "old_subject_dir": "old",
            "computed_bump": recorded_bump, "generator_version": corpus_generator.GENERATOR_VERSION,
        }
        record_before = dict(record)

        line = rerun_under_new_generator(record, repo_root=td)
        assert line is None, line
        assert record == record_before, "must never mutate the recorded evidence"

        real_probe = corpus_generator._spec_bool_probe

        def broken_probe(field, want):
            p = real_probe(field, want)
            # violated collapses into satisfied -- no pod anywhere in the
            # generated corpus can ever demonstrate the predicate's
            # violated state again.
            return corpus_generator.Probe(satisfied=p.satisfied, violated=p.satisfied, absent=p.absent)

        corpus_generator._spec_bool_probe = broken_probe
        try:
            line = rerun_under_new_generator(record, repo_root=td)
        finally:
            corpus_generator._spec_bool_probe = real_probe
        assert line is not None, "a broken generator that erases the violated state must be caught"
        assert "'major'" in line and "'none'" in line, line
        assert record == record_before, "must never mutate the recorded evidence, even when it differs"

    print(
        "selfcheck ok: the three known-good bumps rederive exactly, and a deliberately "
        "wrong expectation is caught, not passed silently; generator pinning matches "
        "the committed corpus today, and a stale recorded generator_version is caught "
        "by name while an ungenerated corpus is not a failure; evidence loading "
        "degrades gracefully with no evidence directory yet; most-recent picks the "
        "highest declared version; a first release has no predecessor to re-derive "
        "against; a real old/new subject pair re-derives identically under an "
        "unchanged generator with the record left byte-for-byte untouched, and a real "
        "generator regression that erases the violated state is caught as a differing "
        "line -- never a failure -- with the record still left untouched"
    )


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        selfcheck()
        return 0

    ok = True

    mismatches = check_known_good_bumps()
    if mismatches:
        ok = False
        print("REFUSED: a known-good bump stopped rederiving:")
        for m in mismatches:
            print(f"  - {m}")
    else:
        print("ok  the three known-good bumps rederive exactly")

    pinning = check_generator_pinning()
    if pinning:
        ok = False
        print("REFUSED: generator pinning check failed:")
        for m in pinning:
            print(f"  - {m}")
    else:
        print("ok  generated-corpus/manifest.yaml matches the live generator version")

    records = load_evidence_records()
    if not records:
        print(
            "no prior evidence to compare -- no committed evidence record exists yet "
            "(ticket cs-15/cs-27's job); this half of the check degrades gracefully "
            "until then"
        )
    else:
        record = most_recent_evidence(records)
        line = rerun_under_new_generator(record)
        if line:
            print(f"NOTE: {line}")
        else:
            print(f"ok  {record['declared']}: recomputes identically under the current generator")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
