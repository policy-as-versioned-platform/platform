#!/usr/bin/env python3
"""coverage.py -- ticket cs-23: coverage stated as counts and holes, never a
percentage.

**No coverage percentage anywhere** (spec.md, "Coverage and evidence"). A
percentage invites a threshold; a threshold invites tuning the corpus until
it passes. This module reports two plain counts instead:

  * **cells** -- every predicate expression (`matchConditions` + `validations`
    only, corpus_generator.predicates' own vocabulary -- never `variables`)
    against its three states: satisfied, violated, absent.
  * **pairs** -- the axis combinations ticket 19's generator actually built
    (the union entry count already in the corpus manifest).

**The pairwise gap is one sentence and two counts, never a ratio.** Axes
combine pairwise (expr x pin, expr x tier, pin x tier), never as a full
three-way cross -- the sentence says so; the two counts are cells and pairs
above. It never blocks a release on its own.

**Two binary gates this module owns** (a third, movement on an unversioned
policy, is ticket 22's `pairing.check_pairing`, already wired into gate.py):

  1. **Unreached predicate.** For every predicate this module extracts,
     every one of its three states must be reached by at least one pod in
     the generated union spine -- read back with `witness_set.classify_state`
     (ticket 20's own reader, reused, never a second CEL engine). A cell the
     generator claims to cover but which classifies to zero pods is exactly
     the shape of the cs-20 container-securityContext bug: the generator's
     writer and this module's reader disagreeing about what a probe actually
     produced. The repair is always the generator, per witness_set's own
     convention.
  2. **Missing witness shape.** `witness_set.check_witness_shapes`, called
     directly, never reimplemented.

Both gates only apply to a REAL pairwise-generated spine (its manifest
carries the `axes`/`combination` keys `corpus_generator.build_manifest`
always writes). gate.py's own historical-rederivation selfcheck hand-builds
a manifest for pre-existing fixtures that predate the `.orValue(...)` CEL
idiom entirely (see gate.py's own module docstring) -- corpus_generator
itself could never have produced a probe for those bodies, so this module's
reachability check does not apply to them either; it is guarded off by the
same manifest-shape check, not a special case keyed on ticket number.

**Unreachable expressions get a declared exclusion in two tiers** (spec.md):
a **proved exclusion** is one THIS MODULE can prove nothing reaches --
computed here, from a real, generic, sound rule (`static_proof`): a
top-level `==`/`!=` comparison whose two operands are textually identical is
a tautology/contradiction no pod can ever violate/satisfy. A **declared
hole** is one a human names in `coverage-exclusions.yaml` -- it prints
forever, and the loader has no field a human can set to promote it to
proved (the loader's schema simply has no such field: `identity`, `name`,
`expression`, `reason` are the only keys it ever reads). An unreached cell
that is neither proved nor declared FAILS THE BUILD (gate 1), naming the
expression.

ponytail: the real subject in this repo has zero live tautologies and zero
live unprobeable-but-declared predicates today -- every cell the real
mandatory-member subject builds is genuinely, honestly reached (proven
empirically; see this module's own selfcheck). Both mechanisms are real code
paths, not dead scaffolding: `static_proof` fires the moment anyone writes a
tautological CEL comparison, and the declared-hole path is exercised today
by this module's constructed fixtures, the same way witness_set.py's real-
infra gap is disclosed rather than invented.

**A hole's id is stable across a version bump.** Derived from a hash of the
normalised expression (the version literal stripped), scoped by (identity
family, policy name with its version stripped) -- never by state, so a
predicate with several unreached states still carries one id, matching
spec.md's "an unchanged RULE keeps its id across versions."

**Limits are derived, never written by hand**, each from the check that
would remove it, each with its live count. A limit at zero prints `closed`
with the count that closed it; it never silently vanishes. Two of the three
named limits stay open BY DECISION regardless of their count (spec.md:
"the cage ratchets one way and has no counter-pressure"; "the rule sees only
the workload's side, so removing enforcement scores as a patch") -- both
counted from the current run's Track-2 movement. The third has a real,
already-built check behind it: `witness_set.load_witnesses`' missing
real-infrastructure count, which closes naturally as real captures land.

Usage:
    coverage.py --selfcheck
    coverage.py --update-baseline   # regenerate coverage-baseline.yaml against the live subject
"""
from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

import corpus_generator
import pairing
import witness_set

HERE = Path(__file__).resolve().parent

EXCLUSIONS_PATH = HERE / "coverage-exclusions.yaml"
BASELINE_PATH = HERE / "coverage-baseline.yaml"

STATES = ("satisfied", "violated", "absent")

# ---------------------------------------------------------------------------
# cells / pairs / the pairwise gap sentence -- spec.md: "never a whole-space
# ratio."
# ---------------------------------------------------------------------------


def cells_count(predicate_count: int) -> int:
    return predicate_count * 3


def pairwise_gap_sentence() -> str:
    return (
        "axes were combined pairwise (predicate-expression x version-pin, "
        "predicate-expression x tier-label, version-pin x tier-label), so no "
        "three-way interaction was built"
    )


# ---------------------------------------------------------------------------
# The coverage vocabulary: distinct predicates across the given subject
# trees, each tagged with its (identity family, version-stripped name) --
# reuses pairing.parse_tree rather than re-deriving identity/name parsing.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopedPredicate:
    predicate: corpus_generator.Predicate
    identity: str | None
    base_name: str


def _member_lookup(subject_dir: Path) -> dict[str, pairing.Member]:
    return {m.file.name: m for m in pairing.parse_tree(subject_dir)}


_BARE_VARIABLE_RE = re.compile(r"^variables\.(?P<name>\w+)$")


def is_bare_variable(expr: str) -> str | None:
    """The variable NAME when `expr` (a matchConditions/validations entry,
    stripped) is nothing but a bare `variables.X` reference -- spec.md:
    "several live expressions are variables returning strings or objects,
    and 'satisfied' is meaningless for them." None for every ordinary
    boolean predicate (a comparison, an .exists() call, ...)."""
    m = _BARE_VARIABLE_RE.match(expr.strip())
    return m.group("name") if m else None


def _variable_expr(subject_dirs: list[Path], policy_filename: str, var_name: str) -> str | None:
    """The named CEL variable's own defining expression, read back out of
    whichever subject tree actually carries `policy_filename` -- reused to
    decide whether an existing axis spans a bare variable's value space."""
    for d in subject_dirs:
        for fname, doc in corpus_generator._iter_docs(d):
            if fname != policy_filename:
                continue
            for v in (doc.get("spec") or {}).get("variables") or []:
                if v.get("name") == var_name:
                    return v.get("expression")
    return None


def axis_spans_variable(var_expr: str | None) -> bool:
    """True when an axis the generator already builds enumerates this
    variable's value space (spec.md: "Add no new axis"). Today that is only
    the tier axis (corpus_generator.TIER_LABEL / TIER_VALUES) -- the only
    enumerated label any live variable in this repo reads from."""
    return var_expr is not None and corpus_generator.TIER_LABEL in var_expr


def distinct_predicates(subject_dirs: list[Path]) -> list[ScopedPredicate]:
    """Every distinct (policy, location, name, expression) across the given
    subject trees (new, and old when present -- "a retirement is exactly the
    case a release must see" applies to coverage too), each scoped to its
    identity family and version-stripped name via pairing.parse_tree. Never
    re-derives predicate extraction or identity parsing -- corpus_generator
    and pairing already own those."""
    seen: dict[tuple[str, str, str, str], ScopedPredicate] = {}
    for d in subject_dirs:
        members = _member_lookup(d)
        for pred in corpus_generator.predicates(d):
            key = (pred.policy, pred.location, pred.name, pred.expression)
            if key in seen:
                continue
            member = members.get(pred.policy)
            seen[key] = ScopedPredicate(
                predicate=pred,
                identity=member.identity if member else None,
                base_name=member.base_name if member else pred.policy,
            )
    return list(seen.values())


# ---------------------------------------------------------------------------
# Stable ids -- hash of the normalised expression, scoped by (identity,
# base_name), never by state. Normalising strips a version literal so an
# unchanged rule keeps its id across versions.
# ---------------------------------------------------------------------------

_VERSION_LITERAL_RE = re.compile(r"'\d+\.\d+\.\d+(?:-[\w.]+)?'")


def normalize_expr(expr: str) -> str:
    return _VERSION_LITERAL_RE.sub("'<version>'", expr)


def stable_id(identity: str | None, base_name: str, expr: str) -> str:
    normalized = normalize_expr(expr)
    key = f"{identity or ''}\x1f{base_name}\x1f{normalized}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Proved exclusions -- a real, generic, sound static rule: a top-level
# `==`/`!=` comparison whose two operands are textually identical is a
# tautology/contradiction. Code-only: no human input feeds this.
# ---------------------------------------------------------------------------

_TOP_LEVEL_CMP_RE = re.compile(r"^(?P<left>.*?)\s*(?P<op>==|!=)\s*(?P<right>.*)$")


def static_proof(expr: str) -> tuple[str, str] | None:
    """(unreachable_state, reason) when the expression is a provable
    tautology/contradiction by literal-text comparison of its two operands
    around the ONLY top-level == or != -- e.g. `x == x` can never be
    'violated'. None for every real predicate in this repo today (disclosed
    in the module docstring, not invented); an expression with more than one
    comparison operator is left unproven rather than guessed at."""
    matches = list(re.finditer(r"==|!=", expr))
    if len(matches) != 1:
        return None
    m = _TOP_LEVEL_CMP_RE.match(expr.strip())
    if not m:
        return None
    left, op, right = m.group("left").strip(), m.group("op"), m.group("right").strip()
    if not left or left != right:
        return None
    if op == "==":
        return ("violated", f"{left!r} always equals itself: 'violated' is impossible")
    return ("satisfied", f"{left!r} never differs from itself: 'satisfied' is impossible")


# ---------------------------------------------------------------------------
# Declared holes -- human-editable, additive only. The loader's schema has
# no field a human can use to mark an entry proved; that is the refusal.
# ---------------------------------------------------------------------------


def load_exclusions(path: Path) -> dict[tuple[str | None, str, str], dict]:
    if not path.exists():
        return {}
    doc = yaml.safe_load(path.read_text()) or {}
    out: dict[tuple[str | None, str, str], dict] = {}
    for entry in doc.get("declared_holes") or []:
        identity = entry.get("identity")
        name = entry["name"]
        expr = entry["expression"]
        reason = entry.get("reason", "declared by a human; the gate cannot prove it")
        # Only identity/name/expression/reason are ever read. A human entry
        # carrying "proved: true" or "tier: proved_exclusion" -- an attempted
        # promotion -- is silently ignored: those keys simply do not exist in
        # this loader's vocabulary, so no promotion is possible through it.
        key = (identity, name, normalize_expr(expr))
        out[key] = {"identity": identity, "name": name, "expression": expr, "reason": reason}
    return out


# ---------------------------------------------------------------------------
# Reachability -- gate 1's evidence.
# ---------------------------------------------------------------------------


def _pods_from_manifest(corpus_dir: Path, manifest: dict) -> list[dict]:
    spine = manifest["populations"]["generated-spine"]
    return [yaml.safe_load((corpus_dir / rec["file"]).read_text()) for rec in spine["entries"]]


def is_real_spine(manifest: dict) -> bool:
    """True only for a manifest corpus_generator.build_manifest actually
    wrote (it always sets these two keys). gate.py's own historical-
    rederivation selfcheck hand-writes a manifest without them -- exactly
    the pre-.orValue() fixtures this module's reachability check cannot
    (and must not) run against, since corpus_generator could never have
    probed them either."""
    spine = manifest.get("populations", {}).get("generated-spine", {})
    return "axes" in spine and "combination" in spine


@dataclass
class CoverageResult:
    applicable: bool
    cells: int | None = None
    pairs: int | None = None
    pairwise_gap: str | None = None
    not_looked_at: list[dict] = field(default_factory=list)
    build_failures: list[dict] = field(default_factory=list)  # unreached, undeclared, unproven


def evaluate(
    subject_dir: Path,
    corpus_dir: Path,
    old_subject_dir: Path | None = None,
    exclusions_path: Path = EXCLUSIONS_PATH,
    baseline_path: Path = BASELINE_PATH,
) -> CoverageResult:
    """The coverage measurement + gate 1 (unreached predicate), evaluated
    over the real generated union spine. Not applicable (CoverageResult.
    applicable=False, every other field left at its placeholder) when no
    manifest exists yet or the manifest is not a real pairwise-generated
    spine -- exactly gate.py's own established None-placeholder convention
    for counts/checksum."""
    manifest_file = corpus_dir / "manifest.yaml"
    if not manifest_file.exists():
        return CoverageResult(applicable=False)
    manifest = yaml.safe_load(manifest_file.read_text())
    if not is_real_spine(manifest):
        return CoverageResult(applicable=False)

    dirs = [subject_dir] + ([old_subject_dir] if old_subject_dir is not None else [])
    all_scoped = distinct_predicates(dirs)
    pods = _pods_from_manifest(corpus_dir, manifest)
    exclusions = load_exclusions(exclusions_path)
    baseline = load_baseline(baseline_path)

    # tier -> key -> {"states": set(), "reason": str}
    buckets: dict[str, dict[tuple, dict]] = {"proved_exclusion": {}, "declared_hole": {}}
    undeclared: dict[tuple, dict] = {}  # gate 1 failures

    # A bare `variables.X` predicate is not boolean-tested at all --
    # "satisfied" is meaningless for it (spec.md). It counts as covered,
    # silently, when an existing axis already spans its value space; the
    # rest are NAMED (not_looked_at) but never fail gate 1 on their own --
    # naming them is what spec.md asks for, not a build block. Excluded
    # from `cells` either way: cells are the boolean predicate-expression
    # vocabulary only.
    scoped = []
    for sp in all_scoped:
        var_name = is_bare_variable(sp.predicate.expression)
        if var_name is None:
            scoped.append(sp)
            continue
        var_expr = _variable_expr(dirs, sp.predicate.policy, var_name)
        if axis_spans_variable(var_expr):
            continue  # counts as covered -- nothing to report
        key = (sp.identity, sp.base_name, normalize_expr(sp.predicate.expression))
        bucket = buckets["declared_hole"].setdefault(
            key,
            {
                "states": set(),
                "reason": (
                    f"a bare 'variables.{var_name}' reference returning a non-boolean "
                    "value; no enumerated axis spans its value space"
                ),
                "expression": sp.predicate.expression,
            },
        )
        bucket["states"].add("n/a")

    cells = cells_count(len(scoped))
    pairs = manifest["populations"]["generated-spine"]["counts"]["union"]

    for sp in scoped:
        pred = sp.predicate
        proof = static_proof(pred.expression)
        try:
            seen_states = {witness_set.classify_state(pred, pod) for pod in pods}
        except ValueError:
            # An expression classify_state's own regex families do not
            # recognize (the same "no probe shape recognized" convention
            # corpus_generator.probe_for uses on the write side) means we
            # cannot observe ANY of this predicate's states reached, for
            # ANY pod -- structurally, not just for the ones on hand. Never
            # crashes the whole gate: every one of its states falls through
            # to the same proved/declared/undeclared classification below,
            # same as a genuinely-unreached state.
            seen_states = set()
        key = (sp.identity, sp.base_name, normalize_expr(pred.expression))

        for state in STATES:
            if proof is not None and proof[0] == state:
                bucket = buckets["proved_exclusion"].setdefault(
                    key, {"states": set(), "reason": proof[1], "expression": pred.expression}
                )
                bucket["states"].add(state)
                continue
            if state in seen_states:
                continue
            # unreached: declared, or a build failure
            if key in exclusions:
                bucket = buckets["declared_hole"].setdefault(
                    key,
                    {
                        "states": set(),
                        "reason": exclusions[key]["reason"],
                        "expression": pred.expression,
                    },
                )
                bucket["states"].add(state)
            else:
                entry = undeclared.setdefault(
                    key, {"states": set(), "expression": pred.expression}
                )
                entry["states"].add(state)

    entries: dict[str, dict] = {}
    for tier, keyed in buckets.items():
        for (identity, base_name, _norm), info in keyed.items():
            eid = stable_id(identity, base_name, info["expression"])
            entries[eid] = {
                "id": eid,
                "tier": tier,
                "identity": identity,
                "name": base_name,
                "expression": info["expression"],
                "states": sorted(info["states"]),
                "reason": info["reason"],
            }

    current_ids = set(entries)
    for eid, e in entries.items():
        e["status"] = "carried_over" if eid in baseline else "new"
    for eid, prev in baseline.items():
        if eid not in current_ids:
            closed = dict(prev)
            closed["id"] = eid
            closed["status"] = "closed"
            entries[eid] = closed

    build_failures = [
        {
            "identity": identity,
            "name": base_name,
            "expression": info["expression"],
            "states": sorted(info["states"]),
        }
        for (identity, base_name, _norm), info in undeclared.items()
    ]

    return CoverageResult(
        applicable=True,
        cells=cells,
        pairs=pairs,
        pairwise_gap=pairwise_gap_sentence(),
        not_looked_at=sorted(entries.values(), key=lambda e: e["id"]),
        build_failures=build_failures,
    )


def unreached_reason(build_failures: list[dict]) -> str:
    """One sentence, naming the expression(s) -- the project's own
    "the gate never estimates viability, it prints one sentence instead"
    convention (gate.py, cage_engine.py)."""
    named = "; ".join(
        f"{f['name']}: `{f['expression']}` unreached in {', '.join(f['states'])}"
        for f in build_failures
    )
    return f"unreached predicate(s), never declared as a hole -- {named}"


# ---------------------------------------------------------------------------
# The baseline -- new / carried_over / closed bookkeeping. Read-only inside
# evaluate(); --update-baseline (or update_baseline()) is the only writer,
# out-of-band from the seam, same convention as corpus_generator's own
# generation being a separate step from gate.py's run_gate.
# ---------------------------------------------------------------------------


def load_baseline(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def update_baseline(entries: list[dict], path: Path = BASELINE_PATH) -> None:
    baseline = {
        e["id"]: {k: v for k, v in e.items() if k not in ("status",)}
        for e in entries
        if e["status"] != "closed"
    }
    path.write_text(yaml.safe_dump(baseline, sort_keys=True, width=4096))


# ---------------------------------------------------------------------------
# Limits -- derived, never written by hand. Always present, three named
# entries (spec.md; the ticket's own notes: "the three named-open limits
# must always print").
# ---------------------------------------------------------------------------


def compute_limits(movement: list[dict]) -> list[dict]:
    ratchet_count = sum(1 for m in movement if m.get("verdict") in ("patch", "removed"))
    _, missing_real = witness_set.load_witnesses()
    residual_count = len(missing_real)
    return [
        {
            "name": "cage-ratchet-one-way",
            "description": (
                "the cage only ever tightens or holds under this rule -- nothing widens it "
                "back automatically once a workload's posture recovers, a structural "
                "one-way ratchet (cage_engine.py's RANK table). Kept open by decision, not "
                "by this count reaching zero."
            ),
            "count": ratchet_count,
            "status": "open",
        },
        {
            "name": "cage-removal-scores-patch",
            "description": (
                "the rule reads only the workload's own side of the comparison, so removing "
                "or loosening enforcement classifies no higher than patch even though it "
                "widens what is admitted. Kept open by decision."
            ),
            "count": ratchet_count,
            "status": "open",
        },
        {
            "name": "cage-not-priced-residual",
            "description": (
                "nothing in this corpus maps a pod to a priced residual -- the tier axis is "
                "synthetic (corpus_generator.TIER_VALUES), so the cage half of Track 2 is "
                "proved on synthetic input, never a real infrastructure capture. The check "
                "that would remove it: witness_set's real-infrastructure witnesses."
            ),
            "count": residual_count,
            "status": "closed" if residual_count == 0 else "open",
        },
    ]


# ---------------------------------------------------------------------------
# selfcheck
# ---------------------------------------------------------------------------

_FIXTURE_ONE_PRED = """\
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: fixture-1-0-0
  labels:
    policy-as-versioned.dev/policy: posture
    policy-as-versioned.dev/policy-version: "1.0.0"
spec:
  validationActions: [Audit]
  matchConditions:
    - name: has-team-label
      expression: "object.metadata.?labels['team'].orValue('') != ''"
"""

_FIXTURE_TAUTOLOGY = """\
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: tautology-1-0-0
  labels:
    policy-as-versioned.dev/policy: posture
    policy-as-versioned.dev/policy-version: "1.0.0"
spec:
  validationActions: [Audit]
  matchConditions:
    - name: has-team-label
      expression: "object.metadata.?labels['team'].orValue('') != ''"
  validations:
    - expression: "1 == 1"
      message: "always true -- 'violated' is provably impossible"
"""


def selfcheck() -> None:
    import tempfile

    # 1. cells/pairs are two plain ints, no ratio -- and the pairwise gap is
    #    a sentence carrying "pairwise" and never a percent sign or fraction.
    assert cells_count(12) == 36
    gap = pairwise_gap_sentence()
    assert "pairwise" in gap and "three-way" in gap
    assert "%" not in gap and "/" not in gap

    # 2. the real, live subject: every cell genuinely reached -- an honest
    #    empirical fact about this repo today, not asserted in the abstract.
    # Derived from whatever versions.yaml currently declares (its last/newest
    # element), never a hardcoded literal -- the array changes shape over
    # real releases (cs-15 replaced 1.0.0/2.0.0 with 2.0.0/3.0.0), and this
    # selfcheck must not need editing on every one. Same pattern as this
    # module's own --update-baseline path below, and render-orphan-guard.py's
    # selfcheck.
    live_version = corpus_generator._orphan_guard.versions(corpus_generator.DISTRIBUTION / "versions.yaml")[-1]
    real_subject = corpus_generator._materialize_subject(live_version)
    real_corpus = HERE / "generated-corpus"
    real_result = evaluate(real_subject, real_corpus)
    assert real_result.applicable, "the committed generated-corpus/ manifest must be a real spine"
    assert real_result.cells is not None and real_result.pairs is not None
    assert real_result.pairs == 100, real_result.pairs  # committed manifest's own union count
    assert real_result.build_failures == [], real_result.build_failures
    # not_looked_at may legitimately be non-empty only from the baseline
    # file's own committed content (empty today) -- no live gap exists.
    assert all(e["status"] in ("new", "carried_over", "closed") for e in real_result.not_looked_at)

    # 3. a real, hand-built manifest that is NOT a pairwise-generated spine
    #    (gate.py's own historical-rederivation shape, no axes/combination
    #    keys) is simply not applicable -- never crashes on an unprobeable
    #    pre-.orValue() expression.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        legacy_subject = td / "legacy"
        legacy_subject.mkdir()
        import rederive_bumps
        (legacy_subject / "department.yaml").write_text(
            (rederive_bumps.CORPUS / "department-label-2.0.0.yaml").read_text()
        )
        legacy_corpus = td / "legacy-corpus"
        legacy_corpus.mkdir()
        (legacy_corpus / "manifest.yaml").write_text(yaml.safe_dump({
            "generator_version": "selfcheck",
            "populations": {"generated-spine": {"checksum": "sha256:x", "counts": {"old": 0, "new": 0, "union": 0}, "entries": []}},
        }))
        legacy_result = evaluate(legacy_subject, legacy_corpus)
        assert not legacy_result.applicable, "a hand-built manifest without axes/combination must not be treated as a real spine"

    # 4. static_proof: a real tautology is proved (never observed
    #    empirically -- code alone), a real predicate is not.
    proof = static_proof("1 == 1")
    assert proof == ("violated", "'1' always equals itself: 'violated' is impossible"), proof
    assert static_proof("object.metadata.?labels['team'].orValue('') != ''") is None
    assert static_proof("a == b") is None
    assert static_proof("a == b == c") is None  # more than one operator: unproven, not guessed

    # 5. normalize_expr / stable_id: an unchanged rule keeps its id across a
    #    version bump; a changed rule gets a new one.
    e1 = "object.metadata.?labels['x'].orValue('') == '1.0.0'"
    e2 = "object.metadata.?labels['x'].orValue('') == '2.0.0'"
    assert normalize_expr(e1) == normalize_expr(e2)
    assert stable_id("posture", "p", e1) == stable_id("posture", "p", e2)
    assert stable_id("posture", "p", e1) != stable_id("posture", "p", "object.x == 1")
    assert stable_id("posture", "p", e1) != stable_id("graded-enforcement", "p", e1)

    # 6. exclusions file: a human declares a hole, and it is honoured -- but
    #    an attempted promotion to proved (a "proved: true" key the human
    #    added themselves) is REFUSED: the resulting entry is still
    #    declared_hole, never proved_exclusion. A real, constructed
    #    attempted-promotion case, not just a schema assertion.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        subj = td / "subject"
        subj.mkdir()
        (subj / "unprobeable.yaml").write_text(
            "apiVersion: policies.kyverno.io/v1alpha1\n"
            "kind: ValidatingPolicy\n"
            "metadata:\n"
            "  name: unprobeable-1-0-0\n"
            "  labels: {policy-as-versioned.dev/policy: posture, "
            "policy-as-versioned.dev/policy-version: '1.0.0'}\n"
            "spec:\n"
            "  validationActions: [Audit]\n"
            "  validations:\n"
            "    - expression: \"size(object.spec.containers) > 0 && "
            "object.spec.containers[0].image.startsWith('ghcr.io/')\"\n"
            "      message: m\n"
        )
        expr = (
            "size(object.spec.containers) > 0 && "
            "object.spec.containers[0].image.startsWith('ghcr.io/')"
        )
        corpus_dir = td / "corpus"
        # a real pairwise-generated spine cannot include this predicate at
        # all (corpus_generator.probe_for has no shape for it -- generation
        # would crash), so the spine is built over an EMPTY predicate
        # set... instead, prove the mechanism directly on a manifest that
        # IS shaped like a real spine (axes/combination present) but was
        # hand-populated with a pod that never reaches this predicate's
        # states, which is exactly "unreached, no probe, no evidence."
        corpus_dir.mkdir()
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p", "labels": {}},
               "spec": {"containers": [{"name": "app", "image": "nginx:1.25"}]}}
        spine_dir = corpus_dir / "spine"
        spine_dir.mkdir()
        (spine_dir / "p.yaml").write_text(yaml.safe_dump(pod))
        (corpus_dir / "manifest.yaml").write_text(yaml.safe_dump({
            "generator_version": "selfcheck",
            "populations": {"generated-spine": {
                "checksum": "sha256:x", "counts": {"old": 1, "new": 0, "union": 1},
                "axes": ["predicate-expression", "version-pin", "tier-label"],
                "combination": "pairwise",
                "entries": [{"file": "spine/p.yaml", "source": "old", "pair": "expr-pin"}],
            }},
        }))

        # 6a. undeclared -> a build failure, naming the expression.
        no_excl = td / "no-exclusions.yaml"
        no_excl.write_text(yaml.safe_dump({"declared_holes": []}))
        result = evaluate(subj, corpus_dir, exclusions_path=no_excl, baseline_path=td / "no-baseline.yaml")
        assert result.applicable
        assert len(result.build_failures) == 1, result.build_failures
        assert result.build_failures[0]["expression"] == expr
        reason = unreached_reason(result.build_failures)
        assert "unprobeable" in reason and expr in reason, reason
        assert result.not_looked_at == []  # not declared, not proved -- a plain build failure

        # 6b. declared -> exempted from failing, appears as declared_hole,
        #     status "new" (nothing in the baseline yet).
        excl = td / "exclusions.yaml"
        excl.write_text(yaml.safe_dump({"declared_holes": [
            {"identity": "posture", "name": "unprobeable", "expression": expr,
             "reason": "no probe shape for image-prefix checks yet"},
        ]}))
        result = evaluate(subj, corpus_dir, exclusions_path=excl, baseline_path=td / "no-baseline.yaml")
        assert result.build_failures == [], result.build_failures
        assert len(result.not_looked_at) == 1, result.not_looked_at
        hole = result.not_looked_at[0]
        assert hole["tier"] == "declared_hole", hole
        assert hole["status"] == "new", hole
        expected_id = stable_id("posture", "unprobeable", expr)
        assert hole["id"] == expected_id, hole

        # 6c. attempted promotion: a human adds "proved: true" and "tier:
        #     proved_exclusion" to the SAME entry. The loader never reads
        #     those keys -- the entry is still declared_hole.
        excl.write_text(yaml.safe_dump({"declared_holes": [
            {"identity": "posture", "name": "unprobeable", "expression": expr,
             "reason": "no probe shape for image-prefix checks yet",
             "proved": True, "tier": "proved_exclusion"},
        ]}))
        result = evaluate(subj, corpus_dir, exclusions_path=excl, baseline_path=td / "no-baseline.yaml")
        assert len(result.not_looked_at) == 1
        assert result.not_looked_at[0]["tier"] == "declared_hole", (
            "a human-authored 'proved: true' / 'tier: proved_exclusion' key must be "
            "ignored -- a declared hole can never be promoted to proved through the "
            "exclusion file"
        )

        # 6d. new / carried_over / closed, across two runs. Baseline seeded
        #     with this hole's id -> carried_over. Then the human REMOVES
        #     the declaration (predicate now reachable, say) -> closed.
        baseline_path = td / "baseline.yaml"
        update_baseline(result.not_looked_at, baseline_path)
        result2 = evaluate(subj, corpus_dir, exclusions_path=excl, baseline_path=baseline_path)
        assert result2.not_looked_at[0]["status"] == "carried_over", result2.not_looked_at

        empty_excl = td / "empty-exclusions.yaml"
        empty_excl.write_text(yaml.safe_dump({"declared_holes": []}))
        result3 = evaluate(subj, corpus_dir, exclusions_path=empty_excl, baseline_path=baseline_path)
        # removing the declaration makes it an undeclared build failure again
        # AND the baseline's own hole entry shows up marked closed.
        assert result3.build_failures, result3.build_failures
        closed = [e for e in result3.not_looked_at if e["id"] == expected_id]
        assert closed and closed[0]["status"] == "closed", result3.not_looked_at

        # 6e. an unchanged rule keeps its id across a version bump; a
        #     changed one gets a new id -- proved with a REAL directory pair
        #     at two versions, through evaluate() itself, not just stable_id
        #     in isolation.
        v1 = td / "v1"; v1.mkdir()
        (v1 / "p.yaml").write_text(pairing._policy_yaml("p-1-0-0", "posture", "1.0.0", [expr]))
        v2 = td / "v2"; v2.mkdir()
        (v2 / "p.yaml").write_text(pairing._policy_yaml("p-2-0-0", "posture", "2.0.0", [expr]))
        excl_versioned = td / "exclusions-versioned.yaml"
        excl_versioned.write_text(yaml.safe_dump({"declared_holes": [
            {"identity": "posture", "name": "p", "expression": expr, "reason": "unprobeable"},
        ]}))
        r_v1 = evaluate(v1, corpus_dir, exclusions_path=excl_versioned, baseline_path=td / "nb1.yaml")
        r_v2 = evaluate(v2, corpus_dir, exclusions_path=excl_versioned, baseline_path=td / "nb1.yaml")
        ids_v1 = {e["id"] for e in r_v1.not_looked_at if e["tier"] == "declared_hole"}
        ids_v2 = {e["id"] for e in r_v2.not_looked_at if e["tier"] == "declared_hole"}
        assert ids_v1 and ids_v1 == ids_v2, (ids_v1, ids_v2, "unchanged rule must keep its id across a version bump")

        v3 = td / "v3"; v3.mkdir()
        (v3 / "p.yaml").write_text(pairing._policy_yaml("p-2-0-0", "posture", "2.0.0", [expr + " && true"]))
        excl_v3 = td / "exclusions-v3.yaml"
        excl_v3.write_text(yaml.safe_dump({"declared_holes": [
            {"identity": "posture", "name": "p", "expression": expr + " && true", "reason": "unprobeable"},
        ]}))
        r_v3 = evaluate(v3, corpus_dir, exclusions_path=excl_v3, baseline_path=td / "nb1.yaml")
        ids_v3 = {e["id"] for e in r_v3.not_looked_at if e["tier"] == "declared_hole"}
        assert ids_v3 and ids_v3.isdisjoint(ids_v1), "a changed rule must get a new id"

    # 7. proved exclusion: a real tautology fixture, end to end through
    #    evaluate() -- proved, never a build failure, never dependent on the
    #    exclusion file at all.
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        subj = td / "subj"
        subj.mkdir()
        # corpus_generator.probe_for structurally CANNOT build a probe for
        # `1 == 1` (no field access at all -- no regex family matches), so a
        # subject carrying it can never actually pass through
        # generate_spine -- exactly the same "an unprobeable predicate is a
        # gap in the generator" convention this repo already enforces. The
        # spine below is hand-built (never through generate_spine) so this
        # fixture proves what it claims: `evaluate()` handles a tautology's
        # own text-based proof without ever needing corpus_generator to have
        # generated anything for it.
        (subj / "tautology.yaml").write_text(_FIXTURE_TAUTOLOGY)
        corpus_dir = td / "corpus"
        spine_dir = corpus_dir / "spine"
        spine_dir.mkdir(parents=True)
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p", "labels": {"team": "x"}},
               "spec": {"containers": [{"name": "app", "image": "nginx:1.25"}]}}
        (spine_dir / "p.yaml").write_text(yaml.safe_dump(pod))
        (corpus_dir / "manifest.yaml").write_text(yaml.safe_dump({
            "generator_version": corpus_generator.GENERATOR_VERSION,
            "populations": {"generated-spine": {
                "checksum": "sha256:x", "counts": {"old": 1, "new": 0, "union": 1},
                "axes": ["predicate-expression", "version-pin", "tier-label"], "combination": "pairwise",
                "entries": [{"file": "spine/p.yaml", "source": "old", "pair": "expr-pin"}],
            }},
        }))
        no_excl = td / "no-exclusions.yaml"
        no_excl.write_text(yaml.safe_dump({"declared_holes": []}))
        result = evaluate(subj, corpus_dir, exclusions_path=no_excl, baseline_path=td / "no-baseline.yaml")
        assert result.applicable
        proved = [e for e in result.not_looked_at if e["tier"] == "proved_exclusion"]
        assert len(proved) == 1, result.not_looked_at
        assert proved[0]["states"] == ["violated"], proved[0]
        assert "1" in proved[0]["reason"], proved[0]
        # "violated" is proved, so it never shows up as a plain undeclared
        # build failure for this predicate -- even though classify_state
        # cannot recognize `1 == 1`'s shape at all (no regex family matches
        # a bare literal comparison), so its OTHER two states (satisfied,
        # absent -- neither really meaningful for a fixed literal either)
        # legitimately still surface as undeclared build failures. The
        # PROVED state specifically must never be among them.
        tautology_failures = [f for f in result.build_failures if f["expression"] == "1 == 1"]
        if tautology_failures:
            assert "violated" not in tautology_failures[0]["states"], tautology_failures

    # 8. a bare `variables.X` predicate: "satisfied" is meaningless for it
    #    (spec.md), so it never enters `cells`. Axis-spanned (reads the
    #    tier label the generator's own TIER_VALUES axis enumerates) ->
    #    counts as covered, silently, never in not_looked_at, never a build
    #    failure. NOT axis-spanned -> named in not_looked_at, but this alone
    #    never fails the build (spec.md only says "name the rest").
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        subj = td / "subj"
        subj.mkdir()
        (subj / "bare-var.yaml").write_text(
            "apiVersion: policies.kyverno.io/v1alpha1\n"
            "kind: ValidatingPolicy\n"
            "metadata:\n"
            "  name: bare-var-1-0-0\n"
            "  labels: {policy-as-versioned.dev/policy: posture, "
            "policy-as-versioned.dev/policy-version: '1.0.0'}\n"
            "spec:\n"
            "  validationActions: [Audit]\n"
            "  variables:\n"
            "    - name: spanned\n"
            "      expression: \"object.metadata.?labels['posture.acme.io/tier'].orValue('baseline')\"\n"
            "    - name: unspanned\n"
            "      expression: \"string(object.metadata.namespace)\"\n"
            "  validations:\n"
            "    - expression: \"variables.spanned\"\n"
            "      message: m1\n"
            "    - expression: \"variables.unspanned\"\n"
            "      message: m2\n"
        )
        corpus_dir = td / "corpus"
        spine_dir = corpus_dir / "spine"
        spine_dir.mkdir(parents=True)
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p", "labels": {}},
               "spec": {"containers": [{"name": "app", "image": "nginx:1.25"}]}}
        (spine_dir / "p.yaml").write_text(yaml.safe_dump(pod))
        (corpus_dir / "manifest.yaml").write_text(yaml.safe_dump({
            "generator_version": "selfcheck",
            "populations": {"generated-spine": {
                "checksum": "sha256:x", "counts": {"old": 1, "new": 0, "union": 1},
                "axes": ["predicate-expression", "version-pin", "tier-label"], "combination": "pairwise",
                "entries": [{"file": "spine/p.yaml", "source": "old", "pair": "expr-pin"}],
            }},
        }))
        no_excl = td / "no-exclusions.yaml"
        no_excl.write_text(yaml.safe_dump({"declared_holes": []}))
        result = evaluate(subj, corpus_dir, exclusions_path=no_excl, baseline_path=td / "no-baseline.yaml")
        assert result.applicable
        assert result.cells == 0, result.cells  # both predicates here are bare variables, not booleans
        assert result.build_failures == [], (
            "a bare variable predicate must never fail gate 1 on its own -- "
            "naming it is enough"
        )
        var_holes = {e["expression"]: e for e in result.not_looked_at}
        assert "variables.spanned" not in var_holes, (
            "an axis-spanned variable counts as covered -- it must not appear in not_looked_at at all"
        )
        assert "variables.unspanned" in var_holes, var_holes
        assert var_holes["variables.unspanned"]["tier"] == "declared_hole", var_holes
        assert "axis" in var_holes["variables.unspanned"]["reason"], var_holes

    # 9. compute_limits: always exactly three named entries; the
    #    residual-pricing limit's count comes from witness_set's own
    #    real-infra gap and would print "closed" at zero.
    limits = compute_limits(movement=[])
    names = {l["name"] for l in limits}
    assert names == {"cage-ratchet-one-way", "cage-removal-scores-patch", "cage-not-priced-residual"}, names
    for l in limits:
        assert "%" not in l["description"]
    residual = next(l for l in limits if l["name"] == "cage-not-priced-residual")
    _, missing_real = witness_set.load_witnesses()
    assert residual["count"] == len(missing_real), (residual, missing_real)
    assert residual["status"] == ("closed" if not missing_real else "open")
    if missing_real:
        assert residual["status"] != "closed"
    zeroed = compute_limits(movement=[])
    assert zeroed[2]["status"] in ("open", "closed")  # never silently omitted
    ratcheted = compute_limits(movement=[{"policy": "x", "verdict": "patch"}, {"policy": "y", "verdict": "none"}])
    assert ratcheted[0]["count"] == 1 and ratcheted[1]["count"] == 1, ratcheted
    assert ratcheted[0]["status"] == "open" and ratcheted[1]["status"] == "open", (
        "the two decision-based limits must stay open regardless of their count"
    )

    print(
        "selfcheck ok: cells/pairs are plain counts, no ratio anywhere; the pairwise "
        "gap sentence names pairwise combination with no whole-space ratio; the real "
        "committed generated-corpus/ has zero unreached cells for the live subject; a "
        "hand-built (non-pairwise-shaped) manifest is simply not applicable, never "
        "crashes on a pre-.orValue() legacy predicate; static_proof proves a real "
        "tautology and nothing else; stable ids survive a version bump on an unchanged "
        "rule and change on a changed one; a human can declare a hole but an attempted "
        "'proved: true'/'tier: proved_exclusion' promotion through the exclusion file "
        "is refused (ignored) -- a real constructed attempted-promotion case; new / "
        "carried_over / closed status tracks a persisted baseline correctly; an "
        "undeclared unreached predicate is a build failure naming the expression; a "
        "proved exclusion never appears as a build failure; a bare 'variables.X' "
        "predicate never counts toward cells, an axis-spanned one counts as covered "
        "silently, an unspanned one is named in not_looked_at without failing the "
        "build; compute_limits always names all three limits, the two decision-based "
        "ones stay open regardless of count, the third closes at zero real-infra "
        "witnesses missing"
    )


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args and args[0] == "--selfcheck":
        selfcheck()
        return 0
    if args and args[0] == "--update-baseline":
        version = corpus_generator._orphan_guard.versions(corpus_generator.DISTRIBUTION / "versions.yaml")[-1]
        subject_dir = corpus_generator._materialize_subject(version)
        result = evaluate(subject_dir, HERE / "generated-corpus")
        if not result.applicable:
            print("nothing to write: the committed corpus is not a real pairwise-generated spine")
            return 1
        update_baseline(result.not_looked_at, BASELINE_PATH)
        print(f"wrote {len(result.not_looked_at)} not_looked_at entr(y/ies) into {BASELINE_PATH}")
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
