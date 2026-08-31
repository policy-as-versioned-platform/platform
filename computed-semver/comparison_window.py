#!/usr/bin/env python3
"""comparison_window.py -- ticket cs-24: the comparison window and the
per-institution matrix.

cs-21's wiring in gate.py compares the new subject against exactly ONE prior
tree (`RepoState.old_subject_dir`, the immediate predecessor). spec.md's
"Where the gate runs" tightens that: multi-version coexistence means several
supported versions run in real clusters at once, so a release must be
measured against EVERY supported version lower than the declared one, not
just the last one -- "comparing only against N-1 hides a break for a cluster
on N-2, and multi-version coexistence guarantees that cluster exists." This
module adds that window on top of `cage_engine.classify_repo` (ticket 21,
reused per line, never re-derived) and the per-institution matrix that
publishes each line's result as the evidence beneath the tagged bump.

Four rules, each literal from the ticket:

  * Compare against every supported version below `declared`, using the
    window as it stood BEFORE this release (`old_window`) -- not after.
    Comparing against the after-window would silently drop exactly the line
    a retirement needs seen: the retired version is, by definition, no
    longer IN the after-window.
  * A version retired between `old_window` and `new_window` (present before,
    absent after, still below declared) forces MAJOR on that line with no
    `cage_engine` run at all. Retiring an array element changes no policy
    body -- a body-diff alone reports "none" and hides exactly the break
    every cluster still pinned to it takes on the next reconcile (the orphan
    guard's allow-list no longer contains it). "No special case" (spec.md)
    means this falls out of the window scan itself -- knowing which window
    entries survive into `new_window` -- not a bespoke corpus signal.
  * A backport narrows the window to its single highest entry below
    `declared` -- the line directly below it -- so a version nobody adopted
    does not decide the number.
  * An empty window (first release, nothing below `declared` at all) has no
    line to compare. It records NO_PREDECESSOR rather than a computed
    "patch" dressed up from nothing, and hands the caller (gate.py) a
    `strictest` of None so `bump.computed` reads NO_PREDECESSOR while every
    OTHER gate rule -- coverage included -- still ran in full before this
    module was ever reached (run_gate's own ordering, unchanged by this
    module).

`subject_tree_for` and the two window lists are explicit inputs, never read
off disk here -- the same convention `RepoState.old_subject_dir` already
set: a real caller (gate.py's CLI, a future release workflow) materializes
real trees (`corpus_generator._materialize_subject`, ticket 19) and reads the
real supported-version array (`render-orphan-guard.py`'s `versions()`,
ticket 12); this module and its tests need only a callable and two lists.
Reading prior versions from their real TAGS rather than a hand-edited HEAD
copy is spec.md's fourth extra gate rule (ticket 26) -- a live-wiring
concern, not a comparison-logic one, and out of this ticket's scope.

Usage:
    comparison_window.py --selfcheck
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import cage_engine
import pairing

NO_PREDECESSOR = "no predecessor"


SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?")


def parse_semver(v: str) -> tuple:
    """The one semver parser gate.py's version-legality rule (cs-18) and this
    module's window both need. Lives here, the leaf module gate.py imports
    (never the reverse), so gate.py delegates to it rather than keeping a
    second copy.

    Ticket 43 / 18 Answer 1: prerelease-aware, because a DEGRADED publish
    carries a prerelease suffix on the declared number
    (`policy/v4.0.1-quarantine.1`) and "the base number stays and sorts
    BELOW the clean number". Semver 2.0.0 rule 11 exactly: a version with a
    prerelease has LOWER precedence than the same base without one, and two
    prereleases compare identifier by identifier, numeric identifiers below
    alphanumeric ones.

    The first three elements stay plain ints, so every caller that indexes
    [0], [1], [2] for major/minor/patch (gate.check_version_legality) is
    unchanged. Element 3 is the release flag -- 0 for a prerelease, 1 for a
    clean release -- which is what makes 4.0.1-quarantine.1 < 4.0.1, and it
    always decides before any mixed-type identifier is reached."""
    m = SEMVER_RE.fullmatch(v.strip())
    if not m:
        raise ValueError(f"not a plain major.minor.patch version: {v!r}")
    base = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    pre = m.group(4)
    if pre is None:
        return base + (1,)
    ids = tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split("."))
    return base + (0,) + ids


def is_prerelease(v: str) -> bool:
    """True for `4.0.1-quarantine.1`, false for `4.0.1`. One reader for the
    one thing a degraded publish is recognised by."""
    return parse_semver(v)[3] == 0


def base_version(v: str) -> str:
    """`4.0.1-quarantine.1` -> `4.0.1`. The declared BASE number, which a
    degraded publish never rewrites (ADR-0011's superseding note)."""
    major, minor, patch = parse_semver(v)[:3]
    return f"{major}.{minor}.{patch}"


def window_below(window: list[str], declared: str, backport: bool = False) -> list[str]:
    """Every version in `window` lower than `declared`, ascending. A gap in
    `window` (a missing intermediate release) is simply absent from the
    list -- nothing here assumes contiguity, so a gap cannot break this.
    `backport` narrows the result to its single highest entry -- the line
    directly below `declared`, and no other."""
    dv = parse_semver(declared)
    below = sorted((v for v in window if parse_semver(v) < dv), key=parse_semver)
    return below[-1:] if backport else below


def _retirement_movement(version: str) -> cage_engine.Movement:
    return cage_engine.Movement(
        policy="<supported-version-array>",
        verdict="major",
        entries=[],
        expressions=[],
        detail=(
            f"version {version} retired from the supported window between the "
            f"before-this-release window and the after -- an array-only change, "
            f"no policy body diff, still breaks every cluster still pinned to it"
        ),
    )


@dataclass
class ComparisonWindow:
    """The seam's window input. Explicit and injected -- mirrors
    `RepoState.old_subject_dir` (cs-21): a real caller supplies real values,
    tests supply fixtures, nothing here reads disk on its own."""
    old_window: list[str]
    new_window: list[str]
    subject_tree_for: Callable[[str], Path]
    backport: bool = False
    institution_pins: dict[str, str] = field(default_factory=dict)
    #: Versions present in `old_window` ONLY as a comparison basis, never
    #: because the array declared them. When the declared array holds one line
    #: there is nothing below the version being cut, so cut-release-gate falls
    #: back to the real tag history for something to diff the body against.
    #: Such a version is not "in the window and now gone", so the retirement
    #: rule must not fire for it: on 2026-08-31 it did, and a release that
    #: moved nothing was classified major, naming the retirement of a version
    #: the array never declared. Dropping it from `old_window` instead lost the
    #: comparison altogether and let a real release through carrying
    #: "no predecessor" -- no body diff at all. It has to be in the window AND
    #: exempt from the retirement rule, which is what this field says.
    basis_only: list[str] = field(default_factory=list)


@dataclass
class LineResult:
    version: str
    retired: bool
    classification: "cage_engine.ClassificationResult"


@dataclass
class WindowEvaluation:
    base: str  # NO_PREDECESSOR, or the comma-joined versions actually compared
    lines: list[LineResult]
    strictest: "cage_engine.ClassificationResult | None"  # None only for NO_PREDECESSOR
    matrix: dict
    pairing_failure: str | None  # set -> caller refuses, naming this reason


def evaluate(window: ComparisonWindow, declared: str, new_subject_dir: Path,
             pods: list[Path]) -> WindowEvaluation:
    """The seam's window computation: pair-check and classify every window
    entry below `declared`, and pick the strictest -- "the strictest result
    wins" (spec.md), never an average, never last-wins."""
    below = window_below(window.old_window, declared, backport=window.backport)
    if not below:
        return WindowEvaluation(NO_PREDECESSOR, [], None, {}, None)

    lines: list[LineResult] = []
    for v in below:
        old_dir = window.subject_tree_for(v)
        check = pairing.check_pairing(old_dir, new_subject_dir)
        if not check.ok:
            return WindowEvaluation(", ".join(below), [], None, {}, f"{v}: {check.reason}")

        # A basis-only version was never declared, so its absence from the new
        # window is not a retirement -- see ComparisonWindow.basis_only.
        retired = v not in window.new_window and v not in window.basis_only
        if retired:
            classification = cage_engine.ClassificationResult(
                computed_bump="major", movement=[_retirement_movement(v)])
        else:
            classification = cage_engine.classify_repo(old_dir, new_subject_dir, pods)
        lines.append(LineResult(v, retired=retired, classification=classification))

    strictest = max(
        (ln.classification for ln in lines),
        key=lambda c: cage_engine.RANK.get(c.computed_bump, 0),
    )

    per_version = {ln.version: ln.classification for ln in lines}
    matrix = {}
    for inst, pin in window.institution_pins.items():
        c = per_version.get(pin)
        matrix[inst] = {
            "pinned_version": pin,
            "computed_bump": c.computed_bump if c else None,
            "movement": [m.as_dict() for m in c.movement] if c else [],
        }

    return WindowEvaluation(", ".join(below), lines, strictest, matrix, None)


# ---------------------------------------------------------------------------
# selfcheck
# ---------------------------------------------------------------------------

def selfcheck() -> None:
    import tempfile

    import rederive_bumps

    # 1. window_below: pure filtering, no kyverno needed. Ascending, and a
    #    gap (2.0.0 simply absent) does not break it.
    assert window_below(["1.0.0", "2.0.1"], "3.0.0") == ["1.0.0", "2.0.1"]
    assert window_below(["2.0.1", "1.0.0"], "3.0.0") == ["1.0.0", "2.0.1"]  # sorted
    assert window_below(["1.0.0", "2.0.0"], "1.5.0") == ["1.0.0"]
    assert window_below([], "1.0.0") == []
    # backport narrows to the single highest entry below declared only.
    assert window_below(["1.0.0", "2.0.1"], "3.0.0", backport=True) == ["2.0.1"]
    assert window_below(["1.0.0"], "3.0.0", backport=True) == ["1.0.0"]
    assert window_below([], "3.0.0", backport=True) == []

    # 1b. Ticket 43 / 18 Answer 1: prerelease ordering. A DEGRADED publish
    #     carries a prerelease suffix on the declared number, and the base
    #     number must sort BELOW the clean number -- if it sorted above, the
    #     degraded release would become the newest supported version and
    #     every window, every `existing_versions` sort and every
    #     `window_below` call would treat the weak release as the strong
    #     one's successor.
    assert parse_semver("4.0.1-quarantine.1") < parse_semver("4.0.1"), "a prerelease must sort BELOW its own release"
    assert parse_semver("4.0.0") < parse_semver("4.0.1-quarantine.1")
    assert parse_semver("4.0.1-quarantine.1") < parse_semver("4.0.1-quarantine.2")
    assert parse_semver("4.0.1-quarantine.2") < parse_semver("4.0.1-quarantine.10"), "numeric identifiers compare numerically"
    assert sorted(["4.0.1", "4.0.1-quarantine.1", "4.0.0"], key=parse_semver) == [
        "4.0.0", "4.0.1-quarantine.1", "4.0.1"], "the sort a release array and a tag history both use"
    assert is_prerelease("4.0.1-quarantine.1") and not is_prerelease("4.0.1")
    assert base_version("4.0.1-quarantine.1") == "4.0.1", "the base number a degraded publish never rewrites"
    #     ...and the window sees a degraded release as a real predecessor
    #     below the clean number, not as something above it.
    assert window_below(["4.0.0", "4.0.1-quarantine.1"], "4.0.1") == ["4.0.0", "4.0.1-quarantine.1"]
    assert window_below(["4.0.0", "4.0.1"], "4.0.1-quarantine.1") == ["4.0.0"]

    # 2. An empty window is NO_PREDECESSOR, not a bare classification --
    #    "a comparison against nothing is not dressed up as a computed patch."
    empty_window = ComparisonWindow(old_window=[], new_window=[], subject_tree_for=lambda v: Path("/nonexistent"))
    ev = evaluate(empty_window, "1.0.0", Path(tempfile.mkdtemp()), [])
    assert ev.base == NO_PREDECESSOR and ev.strictest is None and ev.lines == []
    assert ev.matrix == {}

    fixtures = rederive_bumps.ALL_FIXTURES
    dept_1_0_0 = (rederive_bumps.CORPUS / "department-label-1.0.0.yaml").read_text()
    dept_2_0_0 = (rederive_bumps.CORPUS / "department-label-2.0.0.yaml").read_text()
    known_2_0_1 = (rederive_bumps.CORPUS / "known-department-label-2.0.1.yaml").read_text()

    def tree(**files: str) -> Path:
        d = Path(tempfile.mkdtemp())
        for name, text in files.items():
            (d / f"{name}.yaml").write_text(text)
        return d

    # 3. cs-24 regression guard, built exactly as instructed: a real
    #    before/after case that SHOULD register a change, proven to actually
    #    register it. `old_1_0_0` carries department-label at its ORIGINAL
    #    Audit body; `new` (the release candidate, standing in for what
    #    would be tagged 2.0.1 or later) carries it already promoted to
    #    Deny plus the 2.0.1 addition -- the SAME real major promotion cs-01
    #    live-proved. `old_2_0_1` carries the identical bodies to `new`, so
    #    comparing against the IMMEDIATE predecessor alone reports "none" --
    #    exactly the case spec.md warns about ("comparing only against N-1
    #    hides a break for a cluster on N-2"). The window (both lines, with
    #    2.0.0 itself absent -- a genuine gap) must still surface the major.
    old_1_0_0 = tree(**{"require-department-label": dept_1_0_0})
    old_2_0_1 = tree(**{"require-department-label": dept_2_0_0, "require-known-department-label": known_2_0_1})
    new_dir = tree(**{"require-department-label": dept_2_0_0, "require-known-department-label": known_2_0_1})

    trees = {"1.0.0": old_1_0_0, "2.0.1": old_2_0_1}
    win = ComparisonWindow(old_window=["1.0.0", "2.0.1"], new_window=["1.0.0", "2.0.1"],
                            subject_tree_for=lambda v: trees[v])
    ev = evaluate(win, "3.0.0", new_dir, fixtures)
    assert ev.base == "1.0.0, 2.0.1", ev.base
    per_v = {ln.version: ln.classification.computed_bump for ln in ev.lines}
    # the N-1 line alone would say "none" -- proven directly, not asserted:
    assert cage_engine.classify_repo(old_2_0_1, new_dir, fixtures).computed_bump == "none"
    assert per_v == {"1.0.0": "major", "2.0.1": "none"}, per_v
    # ... and the WINDOW's strictest result is the one that actually wins.
    assert ev.strictest.computed_bump == "major", ev.strictest

    # 4. Backport narrows to 2.0.1 only -- SAME window, same trees, only the
    #    flag differs -- and the outcome genuinely changes (not a no-op
    #    flag): "none" instead of "major", because 1.0.0 is excluded.
    win_backport = ComparisonWindow(old_window=["1.0.0", "2.0.1"], new_window=["1.0.0", "2.0.1"],
                                     subject_tree_for=lambda v: trees[v], backport=True)
    ev_bp = evaluate(win_backport, "3.0.0", new_dir, fixtures)
    assert ev_bp.base == "2.0.1", ev_bp.base
    assert [ln.version for ln in ev_bp.lines] == ["2.0.1"], ev_bp.lines
    assert ev_bp.strictest.computed_bump == "none", ev_bp.strictest

    # 5. Retirement: 1.0.0's line carries the SAME body on both sides (no
    #    policy diff at all -- proven directly against cage_engine first) --
    #    but 1.0.0 is absent from `new_window`, so the line must still force
    #    major, with no cage_engine run needed to explain it.
    same_body_old = tree(**{"require-department-label": dept_1_0_0})
    same_body_new = tree(**{"require-department-label": dept_1_0_0})
    assert cage_engine.classify_repo(same_body_old, same_body_new, fixtures).computed_bump == "none", (
        "fixture setup broken: the bodies must be identical for this to be a genuine array-only case"
    )
    retire_win = ComparisonWindow(old_window=["1.0.0"], new_window=[],  # 1.0.0 retired, nothing replaces it
                                   subject_tree_for=lambda v: same_body_old)
    ev_retire = evaluate(retire_win, "2.0.0", same_body_new, fixtures)
    assert ev_retire.strictest.computed_bump == "major", ev_retire.strictest
    assert ev_retire.lines[0].retired is True
    assert "retired" in ev_retire.lines[0].classification.movement[0].detail

    # 6. The per-institution matrix: three institutions pinned at DIFFERENT
    #    lines of the SAME window from case 3 land at DIFFERENT bands --
    #    driftwood (pinned at 1.0.0) sees the major the N-1-only view would
    #    hide; tuppence and ludlow (pinned at 2.0.1) see none. The tagged
    #    bump is still the strictest across the WHOLE window, evidenced by
    #    the matrix beneath it -- not recomputed per institution.
    win_matrix = ComparisonWindow(
        old_window=["1.0.0", "2.0.1"], new_window=["1.0.0", "2.0.1"],
        subject_tree_for=lambda v: trees[v],
        institution_pins={"driftwood": "1.0.0", "tuppence": "2.0.1", "ludlow": "2.0.1"},
    )
    ev_matrix = evaluate(win_matrix, "3.0.0", new_dir, fixtures)
    assert set(ev_matrix.matrix) == {"driftwood", "tuppence", "ludlow"}, ev_matrix.matrix
    assert ev_matrix.matrix["driftwood"]["computed_bump"] == "major", ev_matrix.matrix["driftwood"]
    assert ev_matrix.matrix["tuppence"]["computed_bump"] == "none", ev_matrix.matrix["tuppence"]
    assert ev_matrix.matrix["ludlow"]["computed_bump"] == "none", ev_matrix.matrix["ludlow"]
    assert ev_matrix.strictest.computed_bump == "major", "the tagged bump is still the worst band in the estate"

    # 7. A pinned version outside the window (never released, or not below
    #    declared) reports as not applicable rather than silently vanishing.
    win_oob = ComparisonWindow(old_window=["2.0.1"], new_window=["2.0.1"],
                                subject_tree_for=lambda v: trees[v],
                                institution_pins={"ico": "9.9.9"})
    ev_oob = evaluate(win_oob, "3.0.0", new_dir, fixtures)
    assert ev_oob.matrix["ico"] == {"pinned_version": "9.9.9", "computed_bump": None, "movement": []}

    # 8. Movement traced to an unversioned member still refuses the WHOLE
    #    window, through pairing.check_pairing, exactly as cs-22 does for
    #    the single-tree case -- naming the offending window line. A labeled
    #    member is present too (identical both sides): the unversioned rule
    #    only engages once the identity scheme is in use somewhere in the
    #    comparison at all (pairing.py's own rule 1 scope), same as cs-22's
    #    own selfcheck sets up.
    old_rogue = tree(**{
        "rogue": pairing._policy_yaml("rogue", None, None, ["y == 1"]),
        "labeled": pairing._policy_yaml("labeled-1-0-0", "posture", "1.0.0", ["x == 1"]),
    })
    new_rogue = tree(**{
        "rogue": pairing._policy_yaml("rogue", None, None, ["y == 2"]),  # real movement, no identity, no version
        "labeled": pairing._policy_yaml("labeled-1-0-0", "posture", "1.0.0", ["x == 1"]),
    })
    win_rogue = ComparisonWindow(old_window=["1.0.0"], new_window=["1.0.0"], subject_tree_for=lambda v: old_rogue)
    ev_rogue = evaluate(win_rogue, "2.0.0", new_rogue, fixtures)
    assert ev_rogue.pairing_failure is not None and "rogue" in ev_rogue.pairing_failure
    assert "1.0.0:" in ev_rogue.pairing_failure, ev_rogue.pairing_failure

    print(
        "selfcheck ok: a prerelease sorts below its own release and above the "
        "version beneath it (ticket 43's degraded publish); window_below filters and sorts ascending, tolerates a gap, "
        "and backport narrows to the single highest entry; an empty window is "
        "NO_PREDECESSOR, not a bare classification; comparing against the whole "
        "window catches a major an N-1-only comparison would hide (proven against "
        "cage_engine.classify_repo directly first); backport genuinely narrows the "
        "outcome, not just the label; a retired version forces major with an "
        "identical body on both sides (proven identical first); the per-institution "
        "matrix lets institutions on different lines land at different bands while "
        "the tagged bump stays the strictest across the window; a pin outside the "
        "window reports not-applicable rather than vanishing; pairing failure on any "
        "window line refuses the whole window and names it"
    )


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        selfcheck()
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
