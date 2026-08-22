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

HERE = Path(__file__).resolve().parent

# The generator's own version. Bumped by hand when this module's logic
# changes. It is not part of the subject, so it cannot itself bump a policy
# version (spec.md, "The corpus": "The generator is versioned and is not
# part of the subject").
GENERATOR_VERSION = "0.1.0"

COMPONENTS = ("major", "minor", "patch")


@dataclass
class RepoState:
    """A repository state -- the seam's first argument. See module docstring
    for the subject/corpus split."""
    subject_dir: Path
    corpus_dir: Path


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
        "not_looked_at": [],
        "limits": [],
        "matrix": {},
    }


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
        return doc

    # Legal version. Nothing past this point is built yet (movement, counts,
    # coverage, the matrix -- tickets 19+); this ticket's scope is the shape
    # and the version-legality rule, not full computation.
    doc["outcome"] = {"result": "passed", "reason": None}
    doc["wall_clock"] = time.monotonic() - start
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
        "corpus_checksum", "wall_clock", "not_looked_at", "limits", "matrix",
    }, sorted(doc)
    assert doc["outcome"] == {"result": "passed", "reason": None}
    assert doc["bump"] == {"declared": "minor", "computed": None}
    assert doc["wall_clock"] is not None and doc["wall_clock"] >= 0
    assert doc["generator_version"] == GENERATOR_VERSION

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
        "corpus_checksum", "wall_clock", "not_looked_at", "limits", "matrix",
    }
    assert doc["movement"] == [] and doc["not_looked_at"] == [] and doc["limits"] == []
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

    print(
        "selfcheck ok: every document field present on pass and on refusal; "
        "a version gap is legal; a declared version that already exists "
        "refuses; the real 2.1.1 refuses under reset-on-bump and names base "
        "2.0.1; a malformed declared version refuses instead of crashing"
    )


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args and args[0] == "--selfcheck":
        selfcheck()
        return 0

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject-dir", type=Path, required=True)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("declared_version")
    parsed = parser.parse_args(args)

    repo = RepoState(subject_dir=parsed.subject_dir, corpus_dir=parsed.corpus_dir)
    doc = run_gate(repo, parsed.declared_version)
    print(json.dumps(doc, indent=2))
    return 0 if doc["outcome"]["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
