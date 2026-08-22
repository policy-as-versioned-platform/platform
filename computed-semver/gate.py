#!/usr/bin/env python3
"""gate.py -- ticket cs-18: the seam, the evidence document and version legality.

One seam. A publisher runs one command with a repository state and a
declared version and gets back the evidence document -- a dict carrying
every field in spec.md's table, on pass and on refusal. Everything reports
through `run_gate`; a test that reaches past it into the corpus generator,
the pairing helper or the renderer (tickets 19+) is asserting on an
implementation detail those tickets will move (spec.md, "Testing Decisions").

This ticket builds the shape and one gate rule: version legality. The other
fields (movement, counts, coverage, the matrix, ...) stay empty/placeholder
until the corpus generator (ticket 19) and what it feeds exist to fill them.

The CLI is a thin wrapper: it prints the document and exits non-zero on
refusal. Signing happens outside the seam -- it needs an identity CI holds
and a test does not (spec.md, "Signing and verification").

Repository state splits into two directories the OLD `computed-semver/corpus/`
conflated (spec.md, "Module shape"):

  * `subject_dir`  -- the policy bodies and the version array: what the
    release actually ships. Ticket 19 fills this with real per-version policy
    trees; for now it need only carry a `versions.yaml` (`versions: [...]`,
    every version this repository state has ever legally released) for the
    version-legality rule below.
  * `corpus_dir`   -- the generated pods plus their manifest (checksum, entry
    count, per-witness provenance). Ticket 19 builds the generator that
    writes here; this ticket does not read it.

Version legality (spec.md, "Version legality"; semver 2.0.0, nothing added):

  1. The base is the highest existing tag lower than the declared version.
  2. Find the leftmost component that increased against that base.
  3. Every component to the right of it must be zero.
  4. The declared version must not already exist.
  5. A gap is legal.

Usage:
    gate.py --subject-dir DIR --corpus-dir DIR <declared-version>
    gate.py --selfcheck              # runnable asserts, no kyverno needed
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

import cage_engine
import corpus_generator
import coverage
import pairing
import rederive_bumps
import witness_set

HERE = Path(__file__).resolve().parent

# cs-19: the corpus generator owns its own version -- it is not part of the
# subject, so it cannot itself bump a policy version (spec.md, "The corpus":
# "The generator is versioned and is not part of the subject"). Re-exported
# here so existing callers of gate.GENERATOR_VERSION keep working.
GENERATOR_VERSION = corpus_generator.GENERATOR_VERSION

COMPONENTS = ("major", "minor", "patch")


@dataclass
class RepoState:
    """A repository state -- the seam's first argument. See module docstring
    for the subject/corpus split.

    `old_subject_dir` -- cs-21: the prior subject tree to compute the bump
    against (real policy bodies, canonical unversioned filenames -- the same
    shape corpus_generator._materialize_subject and render_tree already
    write). Optional and defaults to None: version-legality-only callers
    (ticket 18's own selfcheck, and any RepoState that hasn't wired a real
    prior tree yet) get no regression -- `bump.computed` and `movement` stay
    at empty_document()'s placeholders exactly as before this ticket. Only
    the immediate base version (the same one check_version_legality already
    computes) is compared -- comparing every supported version lower than
    declared, and the per-institution matrix, is spec.md's "Where the gate
    runs" section, out of this ticket's scope."""
    subject_dir: Path
    corpus_dir: Path
    old_subject_dir: Path | None = None


def existing_versions(subject_dir: Path) -> list[str]:
    """The version array out of the subject directory -- every version this
    repository state has ever legally released. Not the same array as
    distribution/versions.yaml, which is the currently-SUPPORTED window (a
    subset -- versions retire out of it); this is the full history the
    version-legality rule needs its base from."""
    doc = yaml.safe_load((subject_dir / "versions.yaml").read_text())
    return list(doc["versions"])


def _parse_semver(v: str) -> tuple[int, int, int]:
    parts = v.split(".")
    if len(parts) != 3:
        raise ValueError(f"not a plain major.minor.patch version: {v!r}")
    try:
        return tuple(int(p) for p in parts)  # type: ignore[return-value]
    except ValueError:
        raise ValueError(f"not a plain major.minor.patch version: {v!r}") from None


@dataclass
class Legality:
    legal: bool
    reason: str | None
    base: str | None
    bump_class: str | None  # "major" | "minor" | "patch" | None


def check_version_legality(existing: list[str], declared: str) -> Legality:
    """The five-rule version-legality check. Pure function: no disk I/O, so
    the seam and its tests can drive it with any existing-versions list."""
    if declared in existing:
        return Legality(False, f"declared version {declared} already exists", None, None)

    try:
        dv = _parse_semver(declared)
    except ValueError as e:
        return Legality(False, str(e), None, None)
    lower = [v for v in existing if _parse_semver(v) < dv]
    base = max(lower, key=_parse_semver) if lower else None
    bv = _parse_semver(base) if base is not None else (0, 0, 0)

    leftmost = next(i for i in range(3) if dv[i] != bv[i])
    assert dv[leftmost] > bv[leftmost]  # guaranteed: base is the highest tag BELOW declared
    bump_class = COMPONENTS[leftmost]

    tail = range(leftmost + 1, 3)
    if any(dv[i] != 0 for i in tail):
        got = ".".join(str(dv[i]) for i in tail)
        want = ".".join(COMPONENTS[i] for i in tail)
        return Legality(
            False,
            f"declared version {declared} illegal: base {base or '0.0.0'} increased "
            f"{bump_class}, so {want} must reset to 0 (got {got})",
            base,
            bump_class,
        )
    return Legality(True, None, base, bump_class)


def empty_document() -> dict:
    """Every field spec.md's table names, present and empty/placeholder.
    Later tickets (19+) fill movement, counts, not_looked_at, limits and the
    matrix once the corpus generator and its comparisons exist."""
    return {
        "outcome": {"result": None, "reason": None},
        "bump": {"declared": None, "computed": None},
        "movement": [],
        "counts": {"old": None, "new": None, "union": None},
        "generator_version": GENERATOR_VERSION,
        "corpus_checksum": None,
        "wall_clock": None,
        # cs-23: cells/pairs are plain counts, never a percentage or a
        # whole-space ratio (spec.md, "Coverage and evidence"). None until a
        # real pairwise-generated spine exists to measure -- the same
        # placeholder convention counts/corpus_checksum already use.
        "coverage": {"cells": None, "pairs": None, "pairwise_gap": None},
        "not_looked_at": [],
        "limits": [],
        "matrix": {},
    }


def _corpus_pod_paths(corpus_dir: Path, manifest: dict) -> list[Path]:
    """cs-21: the generated spine's pod files, as real paths -- what
    cage_engine.classify_repo walks to compute the bump."""
    spine = manifest.get("populations", {}).get("generated-spine", {})
    return [corpus_dir / rec["file"] for rec in spine.get("entries", [])]


def _read_corpus_manifest(corpus_dir: Path) -> dict | None:
    """cs-19: if corpus_dir holds a generated manifest
    (corpus_generator.build_manifest's output), surface its counts and
    checksum into the evidence document -- "a reviewer sees the entry count,
    the checksum and the wall-clock in the evidence document" (spec.md, "The
    corpus"). Absent (e.g. ticket 18's placeholder corpus-unused dirs, or a
    corpus_dir that hasn't been generated into yet) -> the caller's
    placeholder fields stay None, no regression from before this ticket."""
    manifest_file = corpus_dir / "manifest.yaml"
    if not manifest_file.exists():
        return None
    return yaml.safe_load(manifest_file.read_text())


def run_gate(repo: RepoState, declared: str) -> dict:
    """The one seam. Repository state + declared version -> the evidence
    document. Every field of `empty_document()` is present on every return,
    passed or refused (spec.md: "A refusal still populates every field the
    run reached")."""
    start = time.monotonic()
    doc = empty_document()

    legality = check_version_legality(existing_versions(repo.subject_dir), declared)
    doc["bump"]["declared"] = legality.bump_class

    if not legality.legal:
        doc["outcome"] = {"result": "refused", "reason": legality.reason}
        doc["wall_clock"] = time.monotonic() - start
        # cs-23: limits are derived, never omitted -- present even on the
        # earliest possible refusal (spec.md: "the three named-open limits
        # must always print").
        doc["limits"] = coverage.compute_limits(doc["movement"])
        return doc

    # Legal version. Read the corpus manifest for counts/checksum (cs-19;
    # generation itself is a separate, out-of-band step -- see
    # corpus_generator.py -- so the gate only reads, never regenerates).
    # Movement and the computed bump are filled in below, from a prior
    # subject tree, when one is available (cs-21). The coverage matrix
    # remains later tickets' job.
    doc["outcome"] = {"result": "passed", "reason": None}
    manifest = _read_corpus_manifest(repo.corpus_dir)
    if manifest is not None:
        spine = manifest.get("populations", {}).get("generated-spine", {})
        if "counts" in spine:
            doc["counts"] = spine["counts"]
        if "checksum" in spine:
            doc["corpus_checksum"] = spine["checksum"]
        if "generator_version" in manifest:
            doc["generator_version"] = manifest["generator_version"]

        # cs-23: coverage and its first binary gate -- an unreached
        # predicate fails the build, naming the expression. Only applicable
        # against a real pairwise-generated spine (coverage.evaluate's own
        # guard); a hand-built historical manifest (no old_subject_dir case
        # further below) is simply not applicable, same None-placeholder
        # convention as counts/checksum above.
        coverage_result = coverage.evaluate(repo.subject_dir, repo.corpus_dir, repo.old_subject_dir)
        if coverage_result.applicable:
            doc["coverage"] = {
                "cells": coverage_result.cells,
                "pairs": coverage_result.pairs,
                "pairwise_gap": coverage_result.pairwise_gap,
            }
            doc["not_looked_at"] = coverage_result.not_looked_at

            if coverage_result.build_failures:
                doc["outcome"] = {
                    "result": "refused",
                    "reason": coverage.unreached_reason(coverage_result.build_failures),
                }
                doc["wall_clock"] = time.monotonic() - start
                doc["limits"] = coverage.compute_limits(doc["movement"])
                return doc

            # cs-23's second binary gate, ticket 20's own check reused
            # directly, never reimplemented: a witness shape absent from the
            # generated spine fails the build.
            missing = witness_set.check_witness_shapes(repo.subject_dir, repo.corpus_dir)
            if missing:
                named = "; ".join(f"{m.witness} ({m.kind})" for m in missing)
                doc["outcome"] = {
                    "result": "refused",
                    "reason": (
                        f"witness shape(s) missing from the generated spine, the repair is "
                        f"always the generator -- {named}"
                    ),
                }
                doc["wall_clock"] = time.monotonic() - start
                doc["limits"] = coverage.compute_limits(doc["movement"])
                return doc

        # cs-21: with a real prior subject tree to compare against, compute
        # the bump instead of only accepting the declared one -- the gate
        # measures the release rather than trusting the publisher's number.
        if repo.old_subject_dir is not None:
            # cs-22: pair old against new correctly before trusting ANY
            # computed bump out of it -- "a wrong pairing produces a
            # confident wrong bump." Refuses and names the file on movement
            # traced to an unversioned member, on two trees disagreeing over
            # the same declared version, per pairing.py's own docstring.
            pairing_check = pairing.check_pairing(repo.old_subject_dir, repo.subject_dir)
            if not pairing_check.ok:
                doc["outcome"] = {"result": "refused", "reason": pairing_check.reason}
                doc["wall_clock"] = time.monotonic() - start
                doc["limits"] = coverage.compute_limits(doc["movement"])
                return doc

            pods = _corpus_pod_paths(repo.corpus_dir, manifest)
            result = cage_engine.classify_repo(repo.old_subject_dir, repo.subject_dir, pods)
            doc["bump"]["computed"] = result.computed_bump
            doc["movement"] = [m.as_dict() for m in result.movement]

            declared_rank = cage_engine.RANK[legality.bump_class]
            computed_rank = cage_engine.RANK.get(result.computed_bump, 0)
            if declared_rank < computed_rank:
                # Refusal is the bottom rung of the cage ladder, not a
                # separate verdict class (spec.md) -- but the reviewer still
                # needs to see exactly what moved: the corpus entries and
                # the CEL expression responsible, never a bare "refused".
                worst = [m for m in result.movement if cage_engine.RANK.get(m.verdict, 0) == computed_rank]
                named = "; ".join(
                    f"{m.policy}: {', '.join(m.entries) or '(structural, no fixture moved)'} "
                    f"via `{'; '.join(m.expressions) or 'n/a'}`"
                    for m in worst
                )
                doc["outcome"] = {
                    "result": "refused",
                    "reason": (
                        f"declared bump {legality.bump_class!r} is weaker than the computed bump "
                        f"{result.computed_bump!r} -- {named}"
                    ),
                }
                doc["wall_clock"] = time.monotonic() - start
                doc["limits"] = coverage.compute_limits(doc["movement"])
                return doc
            if declared_rank > computed_rank:
                # A stronger declared bump still passes -- the gate never
                # rewrites the declared number -- but prints the discrepancy
                # (spec.md: "It permits a stronger one and prints the
                # discrepancy"), one sentence, no viability estimate.
                doc["outcome"]["reason"] = (
                    f"declared bump {legality.bump_class!r} is stronger than the computed bump "
                    f"{result.computed_bump!r} -- no movement required it"
                )
    doc["wall_clock"] = time.monotonic() - start
    doc["limits"] = coverage.compute_limits(doc["movement"])
    return doc


def selfcheck() -> None:
    import tempfile

    def subject_with(versions: list[str]) -> RepoState:
        d = Path(tempfile.mkdtemp())
        (d / "versions.yaml").write_text(yaml.safe_dump({"versions": versions}))
        return RepoState(subject_dir=d, corpus_dir=d / "corpus-unused")

    # every field present on a legal (passing) run
    repo = subject_with(["1.0.0"])
    doc = run_gate(repo, "1.1.0")
    assert set(doc) == {
        "outcome", "bump", "movement", "counts", "generator_version",
        "corpus_checksum", "wall_clock", "coverage", "not_looked_at", "limits", "matrix",
    }, sorted(doc)
    assert doc["outcome"] == {"result": "passed", "reason": None}
    assert doc["bump"] == {"declared": "minor", "computed": None}
    assert doc["wall_clock"] is not None and doc["wall_clock"] >= 0
    assert doc["generator_version"] == GENERATOR_VERSION
    assert doc["coverage"] == {"cells": None, "pairs": None, "pairwise_gap": None}, doc["coverage"]
    # cs-23: the three named limits always print, even here -- no manifest,
    # no movement, still all three, still never a percentage.
    assert {l["name"] for l in doc["limits"]} == {
        "cage-ratchet-one-way", "cage-removal-scores-patch", "cage-not-priced-residual",
    }, doc["limits"]

    # a version gap (1.0.0 -> 3.0.0, nothing in between) is legal
    repo = subject_with(["1.0.0"])
    doc = run_gate(repo, "3.0.0")
    assert doc["outcome"]["result"] == "passed", doc["outcome"]
    assert doc["bump"]["declared"] == "major"

    # a declared version that already exists refuses
    repo = subject_with(["1.0.0", "2.0.0"])
    doc = run_gate(repo, "2.0.0")
    assert doc["outcome"]["result"] == "refused", doc["outcome"]
    assert "already exists" in doc["outcome"]["reason"]
    # every field still present on refusal, even placeholder ones
    assert set(doc) == {
        "outcome", "bump", "movement", "counts", "generator_version",
        "corpus_checksum", "wall_clock", "coverage", "not_looked_at", "limits", "matrix",
    }
    assert doc["movement"] == [] and doc["not_looked_at"] == []
    # cs-23: limits are never omitted, not even here -- the three named ones
    # still print, at whatever count applies with zero movement to look at.
    assert {l["name"] for l in doc["limits"]} == {
        "cage-ratchet-one-way", "cage-removal-scores-patch", "cage-not-priced-residual",
    }, doc["limits"]
    assert doc["coverage"] == {"cells": None, "pairs": None, "pairwise_gap": None}, doc["coverage"]
    assert doc["counts"] == {"old": None, "new": None, "union": None}

    # the historical release line: policy-as-versioned-flux/policy's real
    # v1.0.0 / v2.0.0 / v2.0.1 tags (the same tags computed-semver/corpus/
    # carries fixed policy-body copies of) -- declaring the real next tag,
    # 2.1.1, must REFUSE: base 2.0.1, minor increased 0->1, so the rule
    # requires patch to reset to 0, but the real tag kept patch=1.
    repo = subject_with(["1.0.0", "2.0.0", "2.0.1"])
    doc = run_gate(repo, "2.1.1")
    assert doc["outcome"]["result"] == "refused", doc["outcome"]
    assert "2.0.1" in doc["outcome"]["reason"], doc["outcome"]["reason"]
    assert "minor" in doc["outcome"]["reason"], doc["outcome"]["reason"]

    # legality is pure and reusable directly, too (not just through the seam)
    legal = check_version_legality(["1.0.0", "2.0.0", "2.0.1"], "2.1.1")
    assert legal == Legality(
        False,
        "declared version 2.1.1 illegal: base 2.0.1 increased minor, "
        "so patch must reset to 0 (got 1)",
        "2.0.1",
        "minor",
    ), legal
    assert check_version_legality(["1.0.0"], "3.0.0") == Legality(True, None, "1.0.0", "major")

    # a malformed declared version refuses through the seam instead of
    # crashing -- _parse_semver's ValueError is real user input (a publisher
    # fat-fingering a tag), not a programming error, so run_gate must return
    # a refused document, not raise.
    repo = subject_with(["1.0.0"])
    for bad in ("1.0", "1.0.a", "not-a-version"):
        doc = run_gate(repo, bad)
        assert doc["outcome"]["result"] == "refused", (bad, doc["outcome"])
        assert "not a plain major.minor.patch version" in doc["outcome"]["reason"], doc["outcome"]
        assert doc["bump"] == {"declared": None, "computed": None}, doc["bump"]

    # cs-19: when corpus_dir already holds a generated manifest, run_gate
    # surfaces its counts/checksum into the document -- "a reviewer sees the
    # entry count, the checksum and the wall-clock in the evidence document."
    fixture = (
        "apiVersion: policies.kyverno.io/v1alpha1\n"
        "kind: ValidatingPolicy\n"
        "metadata: {name: p}\n"
        "spec:\n"
        "  validationActions: [Audit]\n"
        "  matchConditions:\n"
        "    - name: has-team\n"
        "      expression: \"object.metadata.?labels['team'].orValue('') != ''\"\n"
    )
    old_dir = Path(tempfile.mkdtemp())
    new_dir = Path(tempfile.mkdtemp())
    corpus_dir = Path(tempfile.mkdtemp())
    (old_dir / "p.yaml").write_text(fixture)
    (new_dir / "p.yaml").write_text(fixture)
    corpus_generator.build_manifest(old_dir, new_dir, inside_pin="1.0.0", out_dir=corpus_dir)
    repo = RepoState(subject_dir=subject_with(["1.0.0"]).subject_dir, corpus_dir=corpus_dir)
    doc = run_gate(repo, "1.1.0")
    assert doc["outcome"]["result"] == "passed", doc["outcome"]
    assert doc["counts"]["old"] is not None and doc["counts"]["union"] is not None, doc["counts"]
    assert doc["corpus_checksum"] is not None and doc["corpus_checksum"].startswith("sha256:"), doc["corpus_checksum"]
    assert doc["generator_version"] == corpus_generator.GENERATOR_VERSION
    # cs-23: coverage surfaces too -- subject_dir here carries no policy
    # files of its own (0 predicates), so cells is 0, never omitted or
    # negative; pairs mirrors the real union count. No ratio anywhere.
    assert doc["coverage"]["cells"] == 0, doc["coverage"]
    assert doc["coverage"]["pairs"] == doc["counts"]["union"], doc["coverage"]
    assert "pairwise" in doc["coverage"]["pairwise_gap"] and "%" not in doc["coverage"]["pairwise_gap"]

    # ... and when corpus_dir carries no manifest (the placeholder shape
    # every earlier case in this selfcheck uses), counts/checksum stay the
    # None placeholder -- no regression from before this ticket.
    repo = subject_with(["1.0.0"])
    doc = run_gate(repo, "1.1.0")
    assert doc["counts"] == {"old": None, "new": None, "union": None}, doc["counts"]
    assert doc["corpus_checksum"] is None

    # cs-23's own required before/after proof, run through the SEAM itself
    # (not just inside coverage.py/witness_set.py's own selfchecks): build a
    # real subject + spine that passes cleanly, then shrink the spine and
    # confirm each new gate actually refuses through run_gate.
    def write_spine(entries, out_dir: Path) -> None:
        spine_dir = out_dir / "spine"
        spine_dir.mkdir(parents=True, exist_ok=True)
        for e in entries:
            (spine_dir / e.filename).write_text(yaml.safe_dump(e.pod, sort_keys=True))
        man = {
            "generator_version": corpus_generator.GENERATOR_VERSION,
            "populations": {"generated-spine": {
                "checksum": "sha256:selfcheck",
                "counts": {"old": len(entries), "new": 0, "union": len(entries)},
                "axes": ["predicate-expression", "version-pin", "tier-label"],
                "combination": "pairwise",
                "entries": [{"file": f"spine/{e.filename}", "source": e.source, "pair": e.pair} for e in entries],
            }},
        }
        (out_dir / "manifest.yaml").write_text(yaml.safe_dump(man, sort_keys=False))

    cov_subject = subject_with(["1.0.0"]).subject_dir
    (cov_subject / "p.yaml").write_text(fixture)
    full_entries = corpus_generator.generate_spine(cov_subject, inside_pin="1.0.0", source_tag="old")

    full_corpus = Path(tempfile.mkdtemp())
    write_spine(full_entries, full_corpus)
    doc = run_gate(RepoState(subject_dir=cov_subject, corpus_dir=full_corpus), "1.1.0")
    assert doc["outcome"]["result"] == "passed", doc["outcome"]
    assert doc["coverage"]["cells"] == 3, doc["coverage"]  # 1 predicate x 3 states
    assert doc["coverage"]["pairs"] == len(full_entries), doc["coverage"]

    # gate 1: drop every entry that puts has-team into "violated" -- that
    # cell becomes genuinely unreached, undeclared (no exclusions file entry
    # names it) -- run_gate must now refuse and name the expression.
    shrunk = [e for e in full_entries if "has-team@violated" not in e.axis_detail]
    assert len(shrunk) < len(full_entries), "fixture setup broken: nothing dropped"
    shrunk_corpus = Path(tempfile.mkdtemp())
    write_spine(shrunk, shrunk_corpus)
    doc = run_gate(RepoState(subject_dir=cov_subject, corpus_dir=shrunk_corpus), "1.1.0")
    assert doc["outcome"]["result"] == "refused", doc["outcome"]
    assert "labels['team']" in doc["outcome"]["reason"], doc["outcome"]["reason"]
    assert "violated" in doc["outcome"]["reason"], doc["outcome"]["reason"]

    # gate 2: drop every pin=outside entry -- has-team's own 3 states stay
    # reached via pin=inside (expr-tier is pin=inside by construction, so
    # gate 1 stays quiet), but every rederive-fixture witness (none carry a
    # version-pin label at all, so all classify pin_inside=False) loses its
    # only matching shape from the spine -- run_gate must refuse and name a
    # witness.
    no_outside = [e for e in full_entries if "pin=outside" not in e.axis_detail]
    assert len(no_outside) < len(full_entries)
    no_outside_corpus = Path(tempfile.mkdtemp())
    write_spine(no_outside, no_outside_corpus)
    doc = run_gate(RepoState(subject_dir=cov_subject, corpus_dir=no_outside_corpus), "1.1.0")
    assert doc["outcome"]["result"] == "refused", doc["outcome"]
    assert "witness shape" in doc["outcome"]["reason"], doc["outcome"]["reason"]

    # cs-21: the computed bump, wired through the seam. A hand-built manifest
    # pointing straight at rederive_bumps.ALL_FIXTURES -- corpus_generator's
    # own probe_for cannot generate a spine for these historical policy
    # bodies (they predate the `.orValue(...)` CEL idiom probe_for's regexes
    # recognize; that is exactly why ticket cs-01 hand-curated PAIRS/fixtures
    # in the first place), so the manifest is built directly rather than
    # through corpus_generator.build_manifest -- ticket 19's own SHAPE is
    # what run_gate reads, not its generation path.
    def manual_manifest(corpus_dir: Path, pod_files: list[Path]) -> None:
        spine_dir = corpus_dir / "spine"
        spine_dir.mkdir(parents=True, exist_ok=True)
        entries = []
        for f in pod_files:
            (spine_dir / f.name).write_text(f.read_text())
            entries.append({"file": f"spine/{f.name}", "source": "old", "pair": "manual"})
        manifest = {
            "generator_version": "selfcheck",
            "wall_clock": 0.0,
            "populations": {
                "generated-spine": {
                    "checksum": "sha256:selfcheck",
                    "counts": {"old": len(entries), "new": 0, "union": len(entries)},
                    "entries": entries,
                },
            },
        }
        (corpus_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))

    fixtures = rederive_bumps.ALL_FIXTURES

    # 1.0.0 -> 2.0.0: the known-good MAJOR bump (Audit -> Deny promotion).
    old1 = Path(tempfile.mkdtemp())
    (old1 / "require-department-label.yaml").write_text(
        (rederive_bumps.CORPUS / "department-label-1.0.0.yaml").read_text())
    new1 = subject_with(["1.0.0"]).subject_dir
    (new1 / "require-department-label.yaml").write_text(
        (rederive_bumps.CORPUS / "department-label-2.0.0.yaml").read_text())
    corpus1 = Path(tempfile.mkdtemp())
    manual_manifest(corpus1, fixtures)

    # declared == computed: passes, no discrepancy.
    repo = RepoState(subject_dir=new1, corpus_dir=corpus1, old_subject_dir=old1)
    doc = run_gate(repo, "2.0.0")
    assert doc["outcome"] == {"result": "passed", "reason": None}, doc["outcome"]
    assert doc["bump"] == {"declared": "major", "computed": "major"}, doc["bump"]
    assert {m["policy"] for m in doc["movement"]} == {"require-department-label.yaml"}, doc["movement"]
    dept_movement = doc["movement"][0]
    assert dept_movement["verdict"] == "major", dept_movement
    assert dept_movement["entries"], "a major admission narrowing must name the fixtures that moved"
    assert dept_movement["expressions"] == [
        "has(object.metadata.labels) && 'department' in object.metadata.labels"
    ], dept_movement["expressions"]

    # declared WEAKER than computed: refuses, and names the moved corpus
    # entries and the CEL expression -- "the gate never estimates viability.
    # It prints one sentence instead" -- one sentence, no viability language.
    doc = run_gate(repo, "1.1.0")
    assert doc["outcome"]["result"] == "refused", doc["outcome"]
    assert doc["bump"]["declared"] == "minor" and doc["bump"]["computed"] == "major", doc["bump"]
    reason = doc["outcome"]["reason"]
    assert "require-department-label.yaml" in reason, reason
    for stem in dept_movement["entries"]:
        assert stem in reason, (stem, reason)
    assert "department" in reason and "labels" in reason, reason  # the CEL expression itself
    assert "\n" not in reason, reason
    for word in ("viable", "viability", "%", "estimate"):
        assert word not in reason.lower(), (word, reason)

    # 2.0.1 -> 2.1.1: the known-good whole-body MINOR bump (a patch widening
    # on one policy plus a brand-new Audit-only policy bundled into one
    # release -- minor dominates, per rederive_bumps.py's own finding, now
    # rederived through THIS module and this seam instead).
    old2 = Path(tempfile.mkdtemp())
    (old2 / "require-department-label.yaml").write_text(
        (rederive_bumps.CORPUS / "department-label-2.0.0.yaml").read_text())
    (old2 / "require-known-department-label.yaml").write_text(
        (rederive_bumps.CORPUS / "known-department-label-2.0.1.yaml").read_text())
    new2 = subject_with(["2.0.1"]).subject_dir
    (new2 / "require-department-label.yaml").write_text(
        (rederive_bumps.CORPUS / "department-label-2.0.0.yaml").read_text())
    (new2 / "require-known-department-label.yaml").write_text(
        (rederive_bumps.CORPUS / "known-department-label-2.1.1.yaml").read_text())
    (new2 / "require-owner-annotation.yaml").write_text(
        (rederive_bumps.CORPUS / "owner-annotation-2.1.1.yaml").read_text())
    corpus2 = Path(tempfile.mkdtemp())
    manual_manifest(corpus2, fixtures)

    # declared 2.1.0, not the real tag's own 2.1.1 -- 2.1.1 itself fails
    # version LEGALITY (reset-on-bump: base 2.0.1, minor increased, so patch
    # must reset to 0), a separate, already-covered gate rule above. This
    # case is about the COMPUTED-bump rule, so it declares a legal version
    # that carries the same minor bump class instead.
    repo2 = RepoState(subject_dir=new2, corpus_dir=corpus2, old_subject_dir=old2)
    doc = run_gate(repo2, "2.1.0")
    assert doc["outcome"] == {"result": "passed", "reason": None}, doc["outcome"]
    assert doc["bump"] == {"declared": "minor", "computed": "minor"}, doc["bump"]
    per_policy = {m["policy"]: m["verdict"] for m in doc["movement"]}
    assert per_policy == {
        "require-department-label.yaml": "none",
        "require-known-department-label.yaml": "patch",
        "require-owner-annotation.yaml": "minor",
    }, per_policy

    # declared STRONGER than computed: passes, and prints the discrepancy --
    # nothing rewrites the declared number.
    doc = run_gate(repo2, "3.0.0")
    assert doc["outcome"]["result"] == "passed", doc["outcome"]
    assert doc["bump"] == {"declared": "major", "computed": "minor"}, doc["bump"]
    assert doc["outcome"]["reason"] is not None
    assert "major" in doc["outcome"]["reason"] and "minor" in doc["outcome"]["reason"], doc["outcome"]["reason"]

    # cs-22: pairing is wired into the seam itself, not just its own module.
    # Movement traced to an unversioned member refuses through run_gate and
    # names the file -- before cage_engine ever runs, so this needs no
    # kyverno CLI.
    old_dir3 = Path(tempfile.mkdtemp())
    new_dir3 = subject_with(["1.0.0"]).subject_dir
    (old_dir3 / "labeled.yaml").write_text(pairing._policy_yaml(
        "labeled-1-0-0", "posture", "1.0.0", ["x == 1"]))
    (new_dir3 / "labeled.yaml").write_text(pairing._policy_yaml(
        "labeled-1-0-0", "posture", "1.0.0", ["x == 1"]))
    (old_dir3 / "rogue.yaml").write_text(pairing._policy_yaml(
        "rogue", None, None, ["y == 1"]))
    (new_dir3 / "rogue.yaml").write_text(pairing._policy_yaml(
        "rogue", None, None, ["y == 2"]))  # real movement, no identity, no version
    corpus3 = Path(tempfile.mkdtemp())
    manual_manifest(corpus3, fixtures)
    repo3 = RepoState(subject_dir=new_dir3, corpus_dir=corpus3, old_subject_dir=old_dir3)
    doc = run_gate(repo3, "1.1.0")
    assert doc["outcome"]["result"] == "refused", doc["outcome"]
    assert "rogue.yaml" in doc["outcome"]["reason"], doc["outcome"]["reason"]
    assert "unversioned" in doc["outcome"]["reason"], doc["outcome"]["reason"]

    # ... but a platform-machinery member's movement does not block the
    # gate -- it is numbered by the platform release tag, not a
    # policy-version label. A MutatingPolicy with no `dial` variable is
    # skipped by cage_engine (ticket cs-21's own modeled-kinds rule), so
    # this needs no kyverno CLI either -- purely proving the PAIRING
    # decision passes it through.
    old_dir4 = Path(tempfile.mkdtemp())
    new_dir4 = subject_with(["1.0.0"]).subject_dir
    for d, allowed in ((old_dir4, "['1.0.0']"), (new_dir4, "['1.0.0', '2.0.0']")):
        (d / "orphan-guard.yaml").write_text(yaml.safe_dump({
            "apiVersion": "policies.kyverno.io/v1alpha1", "kind": "MutatingPolicy",
            "metadata": {"name": "policy-version-orphan-guard",
                         "labels": {pairing.IDENTITY_LABEL: pairing.PLATFORM_MACHINERY}},
            "spec": {"matchConditions": [{"name": "n", "expression": f"'1.0.0' in {allowed}"}]},
        }, sort_keys=False))
    corpus4 = Path(tempfile.mkdtemp())
    manual_manifest(corpus4, fixtures)
    repo4 = RepoState(subject_dir=new_dir4, corpus_dir=corpus4, old_subject_dir=old_dir4)
    doc = run_gate(repo4, "1.1.0")
    assert doc["outcome"]["result"] == "passed", doc["outcome"]

    print(
        "selfcheck ok: every document field present on pass and on refusal; "
        "a version gap is legal; a declared version that already exists "
        "refuses; the real 2.1.1 refuses under reset-on-bump and names base "
        "2.0.1; a malformed declared version refuses instead of crashing; a "
        "generated corpus manifest surfaces counts/checksum/generator_version "
        "into the document, and their absence leaves the None placeholder; the "
        "two historical known-good bumps (1.0.0->2.0.0 major, 2.0.1->2.1.1 "
        "whole-body minor) rederive exactly through cage_engine and this seam; "
        "a declared bump weaker than computed refuses, naming the moved "
        "corpus entries and the CEL expression in one sentence with no "
        "viability language; a stronger declared bump passes and prints the "
        "discrepancy; the declared number is never rewritten; cs-22: movement "
        "traced to an unversioned member refuses through the seam itself and "
        "names the file, while a platform-machinery member's movement does "
        "not block the gate; cs-23: coverage (cells/pairs, never a "
        "percentage) surfaces into the document; the three named limits "
        "always print; shrinking a real generated spine so a predicate's "
        "state is genuinely unreached makes run_gate itself refuse and name "
        "the expression, and shrinking it so a witness's own shape goes "
        "missing makes run_gate itself refuse and name the witness -- both "
        "proved through the seam, not just inside coverage.py/witness_set.py"
    )


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args and args[0] == "--selfcheck":
        selfcheck()
        return 0

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject-dir", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--old-subject-dir", type=Path, default=None,
                         help="cs-21: the prior subject tree to compute the bump against")
    parser.add_argument("declared_version")
    parsed = parser.parse_args(args)

    repo = RepoState(subject_dir=parsed.subject_dir, corpus_dir=parsed.corpus_dir,
                      old_subject_dir=parsed.old_subject_dir)
    doc = run_gate(repo, parsed.declared_version)
    print(json.dumps(doc, indent=2))
    return 0 if doc["outcome"]["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
