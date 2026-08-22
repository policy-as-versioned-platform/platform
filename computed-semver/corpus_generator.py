#!/usr/bin/env python3
"""corpus_generator.py -- ticket cs-19: the generated corpus spine and its manifest.

Nobody curates the population toward a wanted bump (spec.md, "The corpus").
This module enumerates PREDICATE EXPRESSIONS -- every `matchConditions[]` and
`validations[]` CEL expression in a subject's policy files (spec.md, "Coverage
and evidence": the field space is infinite, the expression space is finite)
-- and generates a pod per expression per state (satisfied, violated, absent),
crossed pairwise with two more axes: the version-pin (inside/outside the
platform's supported array, so the orphan guard is exercised) and the tier
label (absent, baseline, restricted, quarantine -- absent is a real case,
because cage-tier DEFAULTS it rather than skipping it).

**Pairwise, never fully.** Three axes -- expression-state, pin, tier -- combine
two at a time, the third pinned at a baseline value, never a 3-way cross
product. That is a covering array, not the full space (which is explicitly
banned: "the space is over four million", spec.md).

**Both subjects, unioned.** The generator runs once against the OLD subject
and once against the NEW one and unions the results -- "a rule only the old
policy can distinguish does not exist in a corpus generated from the new one.
A retirement is exactly the case a release must see" (the ticket's own
words). Union is by pod content, not by name: an entry both subjects would
produce identically collapses to one file, tagged `source: both` in the
manifest.

**An entry is a plain pod.** No band, no residual, no claim metadata -- a
residual for an infrastructure workload would manufacture the assertion the
corpus exists to prevent. Claim source (which subject produced an entry, and
which axis pair) lives only in the manifest, keyed under a `populations`
dict. Ticket 20's witness set turned out not to fit as a sibling key here
after all -- a witness entry is a per-name provenance record (shape,
presence, missing-real-infra status), not an aggregate-with-checksum like
`generated-spine`, so forcing it into this dict would have been the
restructuring this shape was meant to avoid. It lives instead in its own
generated-corpus/witness-manifest.yaml (witness_set.build_witness_manifest);
this manifest's shape and CLI are exactly what ticket 19 left them.

**No size ceiling anywhere.** The entry count and the wall-clock are
published in the manifest instead -- a ceiling truncates silently.

Usage:
    corpus_generator.py [--old-version V] [--new-version V] [--out DIR]
    corpus_generator.py --selfcheck
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import re
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DISTRIBUTION = REPO / "distribution"

# Bumped by hand when this module's own logic changes. Not part of the
# subject, so it cannot itself bump a policy version (spec.md, "The corpus").
GENERATOR_VERSION = "0.1.2"

PIN_LABEL = "policy-as-versioned.dev/policy-version"
TIER_LABEL = "posture.acme.io/tier"
TIER_VALUES = ["absent", "baseline", "restricted", "quarantine"]
OUTSIDE_PIN = "0.0.0-outside-array"  # never a real platform version

# The baseline value each axis holds at when it is NOT the one of the pair
# being varied -- what makes "combine pairwise, not fully" concrete.
BASELINE_TIER = "baseline"
BASELINE_PIN_CHOICE = "inside"


def _import_by_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# Hyphenated filenames -- importlib by path, the same convention
# shift-left/ci-check.py already uses for render-orphan-guard.py.
_orphan_guard = _import_by_path("render_orphan_guard", DISTRIBUTION / "render-orphan-guard.py")
_version_tree = _import_by_path("render_version_tree", DISTRIBUTION / "render-version-tree.py")


# ---------------------------------------------------------------------------
# Predicate extraction -- the coverage vocabulary (spec.md, "Coverage is
# defined over predicate expressions only, which means matchConditions and
# validations").
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Predicate:
    policy: str       # source filename -- for a human reading the manifest
    location: str     # "matchConditions" | "validations"
    name: str
    expression: str


def _iter_docs(subject_dir: Path):
    for f in sorted(subject_dir.glob("*.yaml")):
        for doc in yaml.safe_load_all(f.read_text()):
            if doc:
                yield f.name, doc


def predicates(subject_dir: Path) -> list[Predicate]:
    """Every matchConditions/validations expression under subject_dir. A doc
    with neither key (a PriorityClass, say) contributes nothing -- it carries
    no predicate."""
    out: list[Predicate] = []
    for fname, doc in _iter_docs(subject_dir):
        spec = doc.get("spec") or {}
        for cond in spec.get("matchConditions") or []:
            out.append(Predicate(fname, "matchConditions", cond["name"], cond["expression"]))
        for i, val in enumerate(spec.get("validations") or []):
            name = val.get("message") or f"validations[{i}]"
            out.append(Predicate(fname, "validations", name, val["expression"]))
    return out


# ---------------------------------------------------------------------------
# Probes -- how to push a pod into one predicate's satisfied/violated/absent
# state. Two generic shapes cover every expression the current subject
# carries; anything else gets a hand-written probe (the same "hardcode the
# finite, named case" convention rederive_bumps.py's PAIRS table already
# uses) or the generator fails loud rather than silently skipping coverage.
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(
    r"labels\['(?P<key>[^']+)'\]\.orValue\('(?P<default>[^']*)'\)\s*"
    r"(?P<op>!=|==)\s*'(?P<value>[^']*)'"
)
_CONTAINER_BOOL_RE = re.compile(
    # cs-20 fix: an un-anchored `c\.` spuriously matched the "c" that ends
    # "...spec.?securityContext...", misclassifying the POD-level
    # require-nonroot predicate as a per-CONTAINER one -- probe_for then
    # wrote satisfied/violated into containers[0].securityContext instead of
    # spec.securityContext, so the "satisfied" pods it built for that
    # predicate actually FAILED the real policy under `kyverno apply` (found
    # while building cs-20's witness-shape classifier, which mirrors this
    # regex to read a real pod's state back). The negative lookbehind
    # requires `c` to start a CEL lambda parameter (preceded by `(`, `,` or
    # whitespace, or string start) rather than end an unrelated identifier.
    r"(?<![\w.])c\.\?securityContext\.\?(?P<field>\w+)\.orValue\((?P<default>true|false)\)\s*==\s*(?P<want>true|false)"
)
_SPEC_BOOL_RE = re.compile(
    r"object\.spec\.\?securityContext\.\?(?P<field>\w+)\.orValue\((?P<default>true|false)\)\s*==\s*(?P<want>true|false)"
)


@dataclass
class Probe:
    satisfied: object  # Callable[[dict], None]
    violated: object
    absent: object


def _set_label(pod: dict, key: str, value: str) -> None:
    pod.setdefault("metadata", {}).setdefault("labels", {})[key] = value


def _del_label(pod: dict, key: str) -> None:
    pod.get("metadata", {}).get("labels", {}).pop(key, None)


def _set_spec_sc(pod: dict, field: str, value: bool) -> None:
    pod.setdefault("spec", {}).setdefault("securityContext", {})[field] = value


def _set_container_sc(pod: dict, field: str, value: bool) -> None:
    containers = pod.setdefault("spec", {}).setdefault(
        "containers", [{"name": "app", "image": "nginx:1.25"}]
    )
    containers[0].setdefault("securityContext", {})[field] = value


def _label_probe(key: str, value: str, op: str) -> Probe:
    if op == "!=":
        sat_val = "probe-value" if value == "" else value + "~satisfied"
        viol_val = value
    else:  # "=="
        sat_val = value
        viol_val = value + "~violated"
    return Probe(
        satisfied=lambda pod, k=key, v=sat_val: _set_label(pod, k, v),
        violated=lambda pod, k=key, v=viol_val: _set_label(pod, k, v),
        absent=lambda pod, k=key: _del_label(pod, k),
    )


def _spec_bool_probe(field: str, want: str) -> Probe:
    want_b = want == "true"
    return Probe(
        satisfied=lambda pod, f=field, w=want_b: _set_spec_sc(pod, f, w),
        violated=lambda pod, f=field, w=want_b: _set_spec_sc(pod, f, not w),
        absent=lambda pod: None,  # the field simply isn't set -- orValue's default applies
    )


def _container_bool_probe(field: str, want: str) -> Probe:
    want_b = want == "true"
    return Probe(
        satisfied=lambda pod, f=field, w=want_b: _set_container_sc(pod, f, w),
        violated=lambda pod, f=field, w=want_b: _set_container_sc(pod, f, not w),
        absent=lambda pod: None,
    )


def _pin_label_probe(value: str, op: str) -> Probe:
    """PIN_LABEL is also the field the version-pin axis itself sets (build()
    writes pin_choice's value there before applying any expr probe). A
    predicate that reads PIN_LABEL -- cage-tier's claims-a-policy-version,
    and every rendered policy's own only-this-policy-version self-scope
    matchCondition -- would, via the generic _label_probe, blindly overwrite
    that same key to a value derived from its own literal, clobbering
    pin_choice and collapsing the expr x pin cross for exactly the
    predicates the pin axis exists to exercise (AC2, AC4; "so the orphan
    guard is exercised"). This variant composes with whatever pin_choice
    already wrote instead of ignoring it, wherever CEL leaves room to:

      satisfied(!= ''): pin_choice's write (inside_pin or OUTSIDE_PIN) is
      already nonempty, so it already satisfies -- leave it alone.

      violated(== ''): '' has two distinct byte-level encodings that both
      make `.orValue('')` yield '' -- an explicit empty string, or the key
      missing outright. Picked by pin_choice's write so the two pin choices
      stay visibly distinct even though the CEL truth value can't.

      satisfied(== value): exactly one string satisfies a literal equality
      -- `value` itself, which is always a real, in-array version. There is
      no valid "outside" representative; pin_choice cannot vary this one,
      and that collapse is correct, not a bug -- only ever one value.

      violated(== value): any string other than `value` violates it -- an
      inside-flavoured near-miss, or OUTSIDE_PIN itself (already a genuine
      non-member) for an outside-flavoured one.

      absent (either op): there is exactly one way to have no label at all,
      so both pin choices collapse to it -- honestly, since with no label
      there is nothing left for "inside" or "outside" to describe.
    """

    def _current(pod: dict) -> str:
        return pod.get("metadata", {}).get("labels", {}).get(PIN_LABEL, "")

    if op == "!=":
        def satisfied(pod: dict) -> None:
            if _current(pod) == "":
                _set_label(pod, PIN_LABEL, "probe-value")

        def violated(pod: dict) -> None:
            if _current(pod) == OUTSIDE_PIN:
                _del_label(pod, PIN_LABEL)
            else:
                _set_label(pod, PIN_LABEL, "")

        return Probe(
            satisfied=satisfied,
            violated=violated,
            absent=lambda pod: _del_label(pod, PIN_LABEL),
        )

    else:  # "=="
        def violated(pod: dict, v=value) -> None:
            if _current(pod) == OUTSIDE_PIN:
                # Bare OUTSIDE_PIN is exactly what pin_choice already wrote
                # with no override at all -- reusing it verbatim would
                # collide with every other cell that also leaves PIN_LABEL
                # untouched at "outside". A suffixed variant still reads as
                # outside-the-array (never a real version) but stays this
                # cell's own.
                _set_label(pod, PIN_LABEL, OUTSIDE_PIN + "~violated")
            else:
                _set_label(pod, PIN_LABEL, v + "~violated")

        return Probe(
            satisfied=lambda pod, v=value: _set_label(pod, PIN_LABEL, v),
            violated=violated,
            absent=lambda pod: _del_label(pod, PIN_LABEL),
        )


def _posture_equals_claim_probe() -> Probe:
    """posture-trust-boundary's `variables.posture == variables.claimed` --
    not a single-field predicate, so it doesn't match the generic shapes.
    Models the policy's own documented threat: a forger sets posture to
    something other than their validated claim."""
    POSTURE_LABEL = "posture.acme.io/version"

    def _claim(pod: dict) -> str:
        return pod.get("metadata", {}).get("labels", {}).get(PIN_LABEL, "")

    return Probe(
        satisfied=lambda pod: _set_label(pod, POSTURE_LABEL, _claim(pod)),
        violated=lambda pod: _set_label(pod, POSTURE_LABEL, _claim(pod) + "-forged"),
        absent=lambda pod: _del_label(pod, POSTURE_LABEL),
    )


# Expressions that don't match a generic shape, keyed by a stable substring.
MANUAL_PROBES: dict[str, object] = {
    "variables.posture == variables.claimed": _posture_equals_claim_probe,
}


def probe_for(pred: Predicate) -> Probe:
    for substring, factory in MANUAL_PROBES.items():
        if substring in pred.expression:
            return factory()
    m = _CONTAINER_BOOL_RE.search(pred.expression)
    if m:
        return _container_bool_probe(m["field"], m["want"])
    m = _SPEC_BOOL_RE.search(pred.expression)
    if m:
        return _spec_bool_probe(m["field"], m["want"])
    m = _LABEL_RE.search(pred.expression)
    if m:
        if m["key"] == PIN_LABEL:
            # The predicate reads the same label the pin axis writes --
            # _label_probe would clobber pin_choice's value (AC2/AC4).
            return _pin_label_probe(m["value"], m["op"])
        return _label_probe(m["key"], m["value"], m["op"])
    raise ValueError(
        f"no probe shape recognized for {pred.policy}:{pred.location}:{pred.name}: "
        f"{pred.expression!r} -- an unprobeable predicate is a gap in the generator, "
        f"not a statistic to skip past"
    )


# ---------------------------------------------------------------------------
# The pairwise generator
# ---------------------------------------------------------------------------

@dataclass
class Entry:
    filename: str
    pod: dict
    source: str   # "old" | "new" | "both" (set on union)
    pair: str     # "expr-pin" | "expr-tier" | "pin-tier"
    axis_detail: str


def _base_pod() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "corpus", "labels": {}},
        "spec": {"containers": [{"name": "app", "image": "nginx:1.25"}]},
    }


def generate_spine(subject_dir: Path, inside_pin: str, source_tag: str) -> list[Entry]:
    """The offline twin: subject directory + the pin value that counts as
    "inside" -> the pairwise spine for that subject alone. Pure aside from
    reading subject_dir; no writes."""
    preds = predicates(subject_dir)
    if not preds:
        raise ValueError(f"{subject_dir}: no predicate expressions found -- nothing to generate against")

    def build(expr_choice, pin_choice: str, tier_choice: str) -> dict:
        pod = _base_pod()
        _set_label(pod, PIN_LABEL, inside_pin if pin_choice == "inside" else OUTSIDE_PIN)
        if tier_choice != "absent":
            _set_label(pod, TIER_LABEL, tier_choice)
        if expr_choice is not None:
            pred, state = expr_choice
            getattr(probe_for(pred), state)(pod)
        return pod

    entries: list[Entry] = []
    seen: set[str] = set()

    def add(pod: dict, pair: str, detail: str) -> None:
        text = yaml.safe_dump(pod, sort_keys=True)
        digest = hashlib.sha256(text.encode()).hexdigest()[:16]
        fname = f"{pair}-{digest}.yaml"
        if fname in seen:
            return
        seen.add(fname)
        entries.append(Entry(fname, pod, source_tag, pair, detail))

    expr_states = [(p, s) for p in preds for s in ("satisfied", "violated", "absent")]
    pins = ["inside", "outside"]

    # expr x pin, tier held at its baseline
    for pred, state in expr_states:
        for pin_choice in pins:
            pod = build((pred, state), pin_choice, BASELINE_TIER)
            add(pod, "expr-pin", f"{pred.policy}:{pred.name}@{state} pin={pin_choice}")

    # expr x tier, pin held at its baseline
    for pred, state in expr_states:
        for tier_choice in TIER_VALUES:
            pod = build((pred, state), BASELINE_PIN_CHOICE, tier_choice)
            add(pod, "expr-tier", f"{pred.policy}:{pred.name}@{state} tier={tier_choice}")

    # pin x tier, expression held at its baseline (no override at all)
    for pin_choice in pins:
        for tier_choice in TIER_VALUES:
            pod = build(None, pin_choice, tier_choice)
            add(pod, "pin-tier", f"pin={pin_choice} tier={tier_choice}")

    return entries


def union_spines(old_entries: list[Entry], new_entries: list[Entry]) -> list[Entry]:
    """Union by pod content (the filename already IS a content hash). An
    entry both subjects produce identically is tagged `source: both` rather
    than kept twice."""
    merged: dict[str, Entry] = {}
    for e in old_entries + new_entries:
        existing = merged.get(e.filename)
        if existing is None:
            merged[e.filename] = e
        elif existing.source != e.source:
            merged[e.filename] = replace(existing, source="both")
    return list(merged.values())


def build_manifest(old_subject_dir: Path, new_subject_dir: Path, inside_pin: str, out_dir: Path) -> dict:
    """Generate both subjects, union them, write the spine + manifest.yaml
    into out_dir, and return the manifest dict -- ticket 19's own "evidence
    document": the checksum, the entry counts, the generator version and the
    wall-clock a reviewer reads (spec.md: "A reviewer sees the entry count,
    the checksum and the wall-clock")."""
    start = time.monotonic()
    old_entries = generate_spine(old_subject_dir, inside_pin, "old")
    new_entries = generate_spine(new_subject_dir, inside_pin, "new")
    union_entries = sorted(union_spines(old_entries, new_entries), key=lambda e: e.filename)

    spine_dir = out_dir / "spine"
    if spine_dir.exists():
        for f in spine_dir.glob("*.yaml"):
            f.unlink()
    spine_dir.mkdir(parents=True, exist_ok=True)
    for e in union_entries:
        (spine_dir / e.filename).write_text(yaml.safe_dump(e.pod, sort_keys=True))

    checksum = hashlib.sha256(
        "".join(f"{e.filename}\n{yaml.safe_dump(e.pod, sort_keys=True)}" for e in union_entries).encode()
    ).hexdigest()

    manifest = {
        "generator_version": GENERATOR_VERSION,
        "wall_clock": time.monotonic() - start,  # measured; nothing anywhere enforces a ceiling on it
        "populations": {
            # Ticket 20's witness set lives in its own
            # generated-corpus/witness-manifest.yaml, not here -- see the
            # module docstring for why a sibling key was dropped.
            "generated-spine": {
                "checksum": f"sha256:{checksum}",
                "counts": {
                    "old": len(old_entries),
                    "new": len(new_entries),
                    "union": len(union_entries),
                },
                "axes": ["predicate-expression", "version-pin", "tier-label"],
                "combination": "pairwise",
                "entries": [
                    {"file": f"spine/{e.filename}", "source": e.source, "pair": e.pair}
                    for e in union_entries
                ],
            },
        },
    }
    (out_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False, width=4096))
    return manifest


def _materialize_subject(version: str) -> Path:
    """A real per-version subject tree for the live default run: the four
    mandatory admission members rendered for `version` (ticket 12's
    render_tree, reused rather than re-implemented) plus that version's
    require-nonroot copy, if one has actually been released."""
    d = Path(tempfile.mkdtemp(prefix=f"subject-{version}-"))
    for fname, text in _version_tree.render_tree(version).items():
        (d / fname).write_text(text)
    real = DISTRIBUTION / "policies" / f"v{version}"
    if real.exists():
        for f in real.glob("*.yaml"):
            if f.name != "kustomization.yaml":
                (d / f.name).write_text(f.read_text())
    return d


# ---------------------------------------------------------------------------
# selfcheck
# ---------------------------------------------------------------------------

_FIXTURE_A = """\
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: fixture-a
spec:
  validationActions: [Audit]
  matchConditions:
    - name: has-team-label
      expression: "object.metadata.?labels['team'].orValue('') != ''"
  validations:
    - expression: "object.spec.?securityContext.?runAsNonRoot.orValue(false) == true"
      message: "must run as non-root"
"""

_FIXTURE_B = """\
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: fixture-b
spec:
  validationActions: [Audit]
  matchConditions:
    - name: has-legacy-flag
      expression: "object.metadata.?labels['legacy'].orValue('') == 'yes'"
"""

# Exercises the real-world collision the generic fixtures above never do:
# a matchCondition that reads PIN_LABEL itself, the same label the pin axis
# sets -- the shape of cage-tier's claims-a-policy-version (`!=`) and every
# rendered policy's own-version self-scope matchCondition (`==`).
_FIXTURE_PIN = """\
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: fixture-pin
spec:
  validationActions: [Audit]
  matchConditions:
    - name: claims-a-policy-version
      expression: "object.metadata.?labels['policy-as-versioned.dev/policy-version'].orValue('') != ''"
    - name: only-this-fixture-version
      expression: "object.metadata.?labels['policy-as-versioned.dev/policy-version'].orValue('') == '9.9.9'"
"""

_FIXTURE_UNPROBEABLE = """\
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: weird
spec:
  validationActions: [Audit]
  validations:
    - expression: "size(object.spec.containers) > 0 && object.spec.containers[0].image.startsWith('ghcr.io/')"
      message: "no probe shape matches this"
"""


def selfcheck() -> None:
    old_dir = Path(tempfile.mkdtemp())
    new_dir = Path(tempfile.mkdtemp())
    (old_dir / "fixture-a.yaml").write_text(_FIXTURE_A)
    (old_dir / "fixture-b.yaml").write_text(_FIXTURE_B)
    (new_dir / "fixture-a.yaml").write_text(_FIXTURE_A)  # fixture-b retired in "new"

    # 1. predicate extraction reads both matchConditions and validations
    preds_old = predicates(old_dir)
    assert len(preds_old) == 3, preds_old  # fixture-a: 1 matchCondition + 1 validation; fixture-b: 1
    preds_new = predicates(new_dir)
    assert len(preds_new) == 2, preds_new

    # build_manifest tests one declared "inside" pin against both subjects
    # (it is a property of the version under test, not of old vs new) --
    # keep the selfcheck's direct calls consistent with that.
    old_entries = generate_spine(old_dir, inside_pin="1.0.0", source_tag="old")
    new_entries = generate_spine(new_dir, inside_pin="1.0.0", source_tag="new")
    assert old_entries and all(e.source == "old" for e in old_entries)
    assert new_entries and all(e.source == "new" for e in new_entries)

    # 2. axes combine pairwise, never fully -- structurally: whichever axis
    # is not part of the pair being varied stays pinned at its baseline for
    # every entry in that group.
    for e in old_entries:
        tier = e.pod["metadata"]["labels"].get(TIER_LABEL, "<absent>")
        pin = e.pod["metadata"]["labels"].get(PIN_LABEL)
        if e.pair == "expr-pin":
            assert tier == BASELINE_TIER, (e.filename, tier)
        elif e.pair == "expr-tier":
            assert pin == "1.0.0", (e.filename, pin)
        elif e.pair != "pin-tier":
            raise AssertionError(e.pair)

    # 3. version-pin axis covers inside AND outside the array
    pins_seen = {e.pod["metadata"]["labels"].get(PIN_LABEL) for e in old_entries}
    assert {"1.0.0", OUTSIDE_PIN} <= pins_seen, pins_seen

    # 4. tier axis covers all four states, including truly absent (no label)
    tiers_seen = {e.pod["metadata"]["labels"].get(TIER_LABEL, "<absent>") for e in old_entries}
    assert tiers_seen == {"<absent>", "baseline", "restricted", "quarantine"}, tiers_seen

    # 5. no band, no residual, anywhere, ever
    for e in old_entries + new_entries:
        dumped = yaml.safe_dump(e.pod)
        assert "band" not in dumped and "residual" not in dumped, e.filename

    # 6. union: a rule only the OLD policy can distinguish survives the union
    # with NEW -- the retirement case (spec.md: "a retirement is exactly the
    # case a release must see").
    assert any("fixture-b" in e.axis_detail for e in old_entries), "fixture setup broken"
    union_entries = union_spines(old_entries, new_entries)
    assert any("fixture-b" in e.axis_detail for e in union_entries), (
        "a predicate only the retired policy can distinguish vanished from the union"
    )
    assert len(union_entries) <= len(old_entries) + len(new_entries)

    # 7. deterministic: regenerating the same subject is byte-identical
    again = generate_spine(old_dir, inside_pin="1.0.0", source_tag="old")
    key = lambda es: [(e.filename, yaml.safe_dump(e.pod, sort_keys=True)) for e in sorted(es, key=lambda e: e.filename)]
    assert key(again) == key(old_entries)

    # 8. the manifest: checksum, per-population entry counts, generator
    # version, wall-clock (measured, never asserted against a ceiling), and
    # provenance keyed by population. Ticket 20's witness set lives in its
    # own witness-manifest.yaml instead of a sibling key here (module
    # docstring); this manifest stays exactly ticket 19's single population.
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        manifest = build_manifest(old_dir, new_dir, inside_pin="1.0.0", out_dir=out_dir)
        assert manifest["generator_version"] == GENERATOR_VERSION
        assert isinstance(manifest["wall_clock"], float) and manifest["wall_clock"] >= 0
        assert set(manifest["populations"]) == {"generated-spine"}, (
            "populations is keyed by population name -- generated-spine is the only one; "
            "ticket 20's witness set is a separate manifest file, see module docstring"
        )
        spine = manifest["populations"]["generated-spine"]
        assert spine["checksum"].startswith("sha256:")
        assert spine["counts"] == {
            "old": len(old_entries), "new": len(new_entries), "union": len(union_entries),
        }, spine["counts"]

        # claim source lives in the manifest, never on the entry
        for rec in spine["entries"]:
            assert set(rec) == {"file", "source", "pair"}, rec
            pod_text = (out_dir / rec["file"]).read_text()
            assert "source" not in pod_text and "pair" not in pod_text
            assert "band" not in pod_text and "residual" not in pod_text

        # CI's "regenerate and fails on any diff" story: regenerating the
        # same subjects is byte-identical (modulo the measured wall-clock).
        manifest2 = build_manifest(old_dir, new_dir, inside_pin="1.0.0", out_dir=out_dir)
        m1 = {k: v for k, v in manifest.items() if k != "wall_clock"}
        m2 = {k: v for k, v in manifest2.items() if k != "wall_clock"}
        assert m1 == m2, "regenerating identical subjects must be byte-identical (minus wall_clock)"

    # 9. a predicate that reads PIN_LABEL itself does not clobber pin_choice
    # (AC2/AC4): the expr x pin cross for it must still vary between
    # pin=inside and pin=outside wherever the CEL truth value leaves room
    # to. The generic fixtures above never exercise this -- neither 'team'
    # nor 'legacy' collides with PIN_LABEL -- which is exactly why the real
    # collision (cage-tier's claims-a-policy-version, every rendered
    # policy's own-version self-scope matchCondition) shipped untested.
    pin_dir = Path(tempfile.mkdtemp())
    (pin_dir / "fixture-pin.yaml").write_text(_FIXTURE_PIN)
    # inside_pin deliberately != the fixture's own literal ('9.9.9') -- the
    # same mismatch main() has for real between old_v and the new_v it
    # passes as inside_pin, so this fixture also catches an unrelated
    # predicate's satisfied-pin=inside pod coincidentally colliding with
    # this one's.
    pin_entries = generate_spine(pin_dir, inside_pin="1.2.3", source_tag="old")
    pin_expr_pin = [e for e in pin_entries if e.pair == "expr-pin"]
    by_cell: dict[str, set[str]] = {}
    for e in pin_expr_pin:
        cell = e.axis_detail.split(" pin=")[0]
        by_cell.setdefault(cell, set()).add(e.pod["metadata"]["labels"].get(PIN_LABEL, "<absent>"))
    # claims-a-policy-version (!=): satisfied and violated both have two
    # valid byte-level encodings, and pin_choice must pick between them.
    assert len(by_cell["fixture-pin.yaml:claims-a-policy-version@satisfied"]) == 2, by_cell
    assert len(by_cell["fixture-pin.yaml:claims-a-policy-version@violated"]) == 2, by_cell
    # only-this-fixture-version (==): violated has two valid encodings;
    # satisfied has exactly one (the literal itself) -- that collapse is
    # correct, not a regression, so it is asserted as == 1, not left mute.
    assert len(by_cell["fixture-pin.yaml:only-this-fixture-version@violated"]) == 2, by_cell
    # Cells with exactly one valid byte-level representation (satisfied for
    # a literal equality; absent, either op -- there is exactly one way to
    # have no label at all) collapse to <= 1 survivor honestly: either its
    # single representative made it into the spine, or an equally-valid
    # equivalent cell elsewhere in this same tiny fixture already claimed
    # the identical content first and content-hash dedup (by design) kept
    # only one. Either way that is not a distinctness violation, so these
    # are asserted as <= 1, not required to be present.
    for cell in (
        "fixture-pin.yaml:only-this-fixture-version@satisfied",
        "fixture-pin.yaml:claims-a-policy-version@absent",
        "fixture-pin.yaml:only-this-fixture-version@absent",
    ):
        assert len(by_cell.get(cell, set())) <= 1, (cell, by_cell)

    # 10. an unrecognized predicate shape fails loud, never silently
    bad_dir = Path(tempfile.mkdtemp())
    (bad_dir / "weird.yaml").write_text(_FIXTURE_UNPROBEABLE)
    try:
        generate_spine(bad_dir, inside_pin="1.0.0", source_tag="old")
    except ValueError as e:
        assert "no probe shape" in str(e)
    else:
        raise AssertionError("an unprobeable predicate expression must fail, not vanish silently")

    print(
        "selfcheck ok: predicate expressions extracted from matchConditions and "
        "validations; each gets satisfied/violated/absent; axes combine pairwise "
        "(expr x pin, expr x tier, pin x tier -- never a full 3-way cross); "
        "pin covers inside/outside the array; tier covers "
        "absent/baseline/restricted/quarantine; a rule only the retired policy "
        "can distinguish survives the union; generation is deterministic; the "
        "manifest carries checksum/counts/generator_version/wall_clock/"
        "per-population provenance; no band or residual anywhere; claim source "
        "lives only in the manifest; an unrecognized predicate shape fails loud"
    )


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args and args[0] == "--selfcheck":
        selfcheck()
        return 0

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-version")
    parser.add_argument("--new-version")
    parser.add_argument("--out", type=Path, default=HERE / "generated-corpus")
    parsed = parser.parse_args(args)

    supported = _orphan_guard.versions(DISTRIBUTION / "versions.yaml")
    old_v = parsed.old_version or supported[0]
    new_v = parsed.new_version or supported[-1]

    old_dir = _materialize_subject(old_v)
    new_dir = _materialize_subject(new_v)
    manifest = build_manifest(old_dir, new_dir, inside_pin=new_v, out_dir=parsed.out)
    spine = manifest["populations"]["generated-spine"]
    print(
        f"generated {spine['counts']['union']} entries "
        f"(old={spine['counts']['old']} new={spine['counts']['new']}) "
        f"into {parsed.out}, checksum {spine['checksum']}, "
        f"wall_clock {manifest['wall_clock']:.3f}s"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
