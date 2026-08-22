#!/usr/bin/env python3
"""witness_set.py -- ticket cs-20: the witness set and the missing-shape gate.

Two populations exist (spec.md, "The corpus"). The **generated spine**
(corpus_generator.py, ticket 19) decides bumps. The **witness set** proves
the generator did not miss a shape. Witness entries test shape, never
residual: they carry no band, no residual, no claim metadata.

A **shape** is the tuple of outcomes each subject predicate expression gives
on a pod, plus whether its pin is inside the platform's declared version
array (spec.md: "the coverage vocabulary that ticket 23 builds on").
`classify_state` below is the reverse of corpus_generator.probe_for: instead
of pushing a pod INTO a state, it reads which state a REAL pod is already
in, using the exact same regex families probe_for dispatches on -- so a
predicate shape the generator can build is exactly the shape this can read
back, and no separate CEL engine is needed to classify a witness.

**A witness shape missing from the generated spine fails the build. The
repair is always the generator, never the fixture** -- `check_witness_shapes`
below only ever reports; nothing here edits a witness or the spine to make a
failure go away.

The witness set is the five rederive fixtures (cs-01's ALL_FIXTURES -- real
committed files) plus the six real unlabelled infrastructure workloads the
COTS effort named (.scratch/computed-semver/issues/03-what-is-the-corpus.md:
SPIRE, Istio, OpenBao, Pomerium, Dex, git-server). ponytail: none of the six
exist as committed fixtures anywhere in this repo or the hub repo as of this
ticket -- the COTS effort that was meant to produce real captures of those
workloads hasn't landed them. That is a real, named gap, not silently
faked: REAL_INFRA_DIR is where a real Pod manifest for each name would live
(`<name>.yaml`), `load_witnesses` reports any name not found there as
missing rather than inventing a placeholder, and every entry point (the CLI,
the manifest, this docstring) says so out loud. The missing-shape gate itself
works today against whichever witnesses ARE available, and will pick up the
six the moment real captures land -- no code change needed then, only files.

Usage:
    witness_set.py --corpus-dir DIR [--subject-version V] [--out DIR]
    witness_set.py --selfcheck
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

import corpus_generator
import rederive_bumps

HERE = Path(__file__).resolve().parent
REPO = corpus_generator.REPO
REAL_INFRA_DIR = HERE / "corpus" / "witnesses" / "real"

# The six real unlabelled infrastructure workloads the COTS effort named
# (spec.md, "The corpus"; .scratch/computed-semver/issues/03-what-is-the-
# corpus.md). Looked up as REAL_INFRA_DIR/<name>.yaml.
REAL_INFRA_NAMES = ["spire", "istio", "openbao", "pomerium", "dex", "git-server"]


# ---------------------------------------------------------------------------
# The witness set
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Witness:
    name: str
    kind: str  # "rederive-fixture" | "real-infrastructure"
    file: Path


def load_witnesses() -> tuple[list[Witness], list[str]]:
    """(available witnesses, real-infra names not yet committed). The five
    rederive fixtures are always available -- cs-01's ALL_FIXTURES are real
    committed files. Each real-infra name not found under REAL_INFRA_DIR is
    reported as missing, never invented as a placeholder pod."""
    witnesses = [
        Witness(name=f.stem, kind="rederive-fixture", file=f)
        for f in rederive_bumps.ALL_FIXTURES
    ]
    missing: list[str] = []
    for name in REAL_INFRA_NAMES:
        f = REAL_INFRA_DIR / f"{name}.yaml"
        if f.exists():
            witnesses.append(Witness(name=name, kind="real-infrastructure", file=f))
        else:
            missing.append(name)
    return witnesses, missing


# ---------------------------------------------------------------------------
# Shape: the tuple of per-predicate outcomes plus the in-array pin flag.
# classify_state is probe_for's inverse -- read a real pod's state instead of
# writing one -- built from the exact same regex families so the two stay in
# lockstep by construction.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Shape:
    outcomes: tuple[str, ...]
    pin_inside: bool

    def as_dict(self) -> dict:
        return {"outcomes": list(self.outcomes), "pin_inside": self.pin_inside}


def _labels(pod: dict) -> dict:
    return (pod.get("metadata") or {}).get("labels") or {}


def _classify_label(pod: dict, key: str, value: str, op: str) -> str:
    labels = _labels(pod)
    if key not in labels:
        return "absent"
    truth = (labels[key] != value) if op == "!=" else (labels[key] == value)
    return "satisfied" if truth else "violated"


def _classify_spec_bool(pod: dict, field: str, want: str) -> str:
    sc = ((pod.get("spec") or {}).get("securityContext")) or {}
    if field not in sc:
        return "absent"
    return "satisfied" if sc[field] == (want == "true") else "violated"


def _classify_container_bool(pod: dict, field: str, want: str) -> str:
    containers = (pod.get("spec") or {}).get("containers") or []
    if not containers:
        return "absent"
    sc = containers[0].get("securityContext") or {}
    if field not in sc:
        return "absent"
    return "satisfied" if sc[field] == (want == "true") else "violated"


def _classify_posture_equals_claim(pod: dict) -> str:
    """The reverse of corpus_generator._posture_equals_claim_probe."""
    posture_label = "posture.acme.io/version"
    labels = _labels(pod)
    if posture_label not in labels:
        return "absent"
    claim = labels.get(corpus_generator.PIN_LABEL, "")
    return "satisfied" if labels[posture_label] == claim else "violated"


def classify_state(pred: corpus_generator.Predicate, pod: dict) -> str:
    """Which of satisfied/violated/absent a real pod is in for one subject
    predicate. Dispatches on the same regex families corpus_generator's
    probe_for uses, in the same order, so any predicate shape the generator
    can build a probe for, this can classify back -- and an expression
    neither recognizes fails loud (probe_for's own convention: "an
    unprobeable predicate is a gap in the generator, not a statistic to skip
    past")."""
    expr = pred.expression
    for substring in corpus_generator.MANUAL_PROBES:
        if substring in expr:
            if substring == "variables.posture == variables.claimed":
                return _classify_posture_equals_claim(pod)
            raise ValueError(f"no manual classifier wired for {substring!r}")
    m = corpus_generator._CONTAINER_BOOL_RE.search(expr)
    if m:
        return _classify_container_bool(pod, m["field"], m["want"])
    m = corpus_generator._SPEC_BOOL_RE.search(expr)
    if m:
        return _classify_spec_bool(pod, m["field"], m["want"])
    m = corpus_generator._LABEL_RE.search(expr)
    if m:
        return _classify_label(pod, m["key"], m["value"], m["op"])
    raise ValueError(
        f"no probe shape recognized for {pred.policy}:{pred.location}:{pred.name}: "
        f"{expr!r} -- a witness cannot be shaped against an unprobeable predicate"
    )


def shape_of(pod: dict, preds: list[corpus_generator.Predicate], allowed_versions: list[str]) -> Shape:
    outcomes = tuple(classify_state(p, pod) for p in preds)
    pin = _labels(pod).get(corpus_generator.PIN_LABEL)
    return Shape(outcomes=outcomes, pin_inside=pin in allowed_versions)


def spine_shapes(
    corpus_dir: Path, preds: list[corpus_generator.Predicate], allowed_versions: list[str]
) -> set[Shape]:
    """Every distinct shape the already-generated spine (cs-19's
    generated-corpus/, or any dir build_manifest wrote into) actually
    covers, read back off the real pod files -- never off construction-time
    bookkeeping, so this stays honest even if a future generator change
    reorders or renames entries."""
    manifest = yaml.safe_load((corpus_dir / "manifest.yaml").read_text())
    spine = manifest["populations"]["generated-spine"]
    shapes: set[Shape] = set()
    for rec in spine["entries"]:
        pod = yaml.safe_load((corpus_dir / rec["file"]).read_text())
        shapes.add(shape_of(pod, preds, allowed_versions))
    return shapes


# ---------------------------------------------------------------------------
# The missing-shape gate
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MissingShape:
    witness: str
    kind: str
    shape: Shape


def check_witness_shapes(subject_dir: Path, corpus_dir: Path) -> list[MissingShape]:
    """The missing-shape gate (spec.md: "a witness shape missing from the
    generated spine fails the build"). Every AVAILABLE witness (real-infra
    witnesses not yet committed are simply not checked -- load_witnesses
    already names that gap separately, and a witness that does not exist has
    no shape to fail on) must have its shape present in the generated spine.
    Returns the witnesses whose shape is absent; empty means the gate
    passes. The repair for a non-empty return is always the generator
    (regenerate with the missing cell covered), never the witness."""
    preds = corpus_generator.predicates(subject_dir)
    allowed = corpus_generator._orphan_guard.versions(corpus_generator.DISTRIBUTION / "versions.yaml")
    present = spine_shapes(corpus_dir, preds, allowed)
    witnesses, _missing_real = load_witnesses()
    failures = []
    for w in witnesses:
        pod = yaml.safe_load(w.file.read_text())
        shape = shape_of(pod, preds, allowed)
        if shape not in present:
            failures.append(MissingShape(witness=w.name, kind=w.kind, shape=shape))
    return failures


# ---------------------------------------------------------------------------
# The manifest: per-witness provenance (AC: "the manifest records
# per-witness provenance").
# ---------------------------------------------------------------------------

def build_witness_manifest(subject_dir: Path, corpus_dir: Path, out_path: Path) -> dict:
    """Writes out_path with one entry per witness: name, kind, source file,
    its computed shape and whether that shape is present in corpus_dir's
    generated spine -- plus one entry per real-infra name that is not yet
    committed, so the gap is visible in the manifest too, not just in a
    console warning. A separate file from cs-19's own generated-corpus/
    manifest.yaml (that file's shape and CLI stay exactly as ticket 19 left
    them -- this ticket does not touch it)."""
    preds = corpus_generator.predicates(subject_dir)
    allowed = corpus_generator._orphan_guard.versions(corpus_generator.DISTRIBUTION / "versions.yaml")
    present = spine_shapes(corpus_dir, preds, allowed)
    witnesses, missing_real = load_witnesses()

    entries = []
    for w in witnesses:
        pod = yaml.safe_load(w.file.read_text())
        shape = shape_of(pod, preds, allowed)
        entries.append({
            "witness": w.name,
            "kind": w.kind,
            "file": str(w.file.relative_to(REPO)),
            "shape": shape.as_dict(),
            "present_in_spine": shape in present,
        })
    for name in missing_real:
        entries.append({
            "witness": name,
            "kind": "real-infrastructure",
            "file": None,
            "shape": None,
            "present_in_spine": None,
            "status": "not-yet-committed",
        })

    manifest = {
        "counts": {
            "rederive-fixtures": len(rederive_bumps.ALL_FIXTURES),
            "real-infrastructure-committed": len(witnesses) - len(rederive_bumps.ALL_FIXTURES),
            "real-infrastructure-missing": len(missing_real),
        },
        "entries": entries,
    }
    out_path.write_text(yaml.safe_dump(manifest, sort_keys=False, width=4096))
    return manifest


# ---------------------------------------------------------------------------
# selfcheck
# ---------------------------------------------------------------------------

_FIXTURE_SUBJECT = """\
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: fixture
spec:
  validationActions: [Audit]
  matchConditions:
    - name: has-team-label
      expression: "object.metadata.?labels['team'].orValue('') != ''"
    - name: claims-pin
      expression: "object.metadata.?labels['{pin}'].orValue('') != ''"
  validations:
    - expression: "object.spec.?securityContext.?runAsNonRoot.orValue(false) == true"
      message: "must run as non-root"
""".format(pin=corpus_generator.PIN_LABEL)


def selfcheck() -> None:
    import tempfile

    # 1. the witness set holds exactly the five rederive fixtures, plus the
    # six real-infra names -- committed or not.
    witnesses, missing_real = load_witnesses()
    fixture_witnesses = [w for w in witnesses if w.kind == "rederive-fixture"]
    assert len(fixture_witnesses) == 5, fixture_witnesses
    assert {w.name for w in fixture_witnesses} == {
        "fully-compliant", "legal-department", "no-department", "no-owner", "unknown-department",
    }, {w.name for w in fixture_witnesses}
    assert set(REAL_INFRA_NAMES) == {
        "spire", "istio", "openbao", "pomerium", "dex", "git-server",
    }, REAL_INFRA_NAMES
    real_present = {w.name for w in witnesses if w.kind == "real-infrastructure"}
    assert real_present | set(missing_real) == set(REAL_INFRA_NAMES)
    assert real_present.isdisjoint(missing_real)

    # 2. shape = tuple of per-expression outcomes + in-array pin flag,
    # correctly read back for a label predicate, a spec-bool predicate and
    # the pin axis itself.
    subj = Path(tempfile.mkdtemp())
    (subj / "fixture.yaml").write_text(_FIXTURE_SUBJECT)
    preds = corpus_generator.predicates(subj)
    assert len(preds) == 3, preds

    satisfied_pod = {
        "metadata": {"labels": {"team": "platform", corpus_generator.PIN_LABEL: "1.0.0"}},
        "spec": {"securityContext": {"runAsNonRoot": True}},
    }
    shape = shape_of(satisfied_pod, preds, allowed_versions=["1.0.0", "2.0.0"])
    assert shape.outcomes == ("satisfied", "satisfied", "satisfied"), shape.outcomes
    assert shape.pin_inside is True, shape

    violated_pod = {
        "metadata": {"labels": {"team": "platform", corpus_generator.PIN_LABEL: "9.9.9"}},
        "spec": {"securityContext": {"runAsNonRoot": False}},
    }
    shape = shape_of(violated_pod, preds, allowed_versions=["1.0.0", "2.0.0"])
    assert shape.outcomes == ("satisfied", "satisfied", "violated"), shape.outcomes
    assert shape.pin_inside is False, shape  # 9.9.9 not in the allowed array

    absent_pod = {"metadata": {"labels": {}}, "spec": {"containers": [{"name": "app"}]}}
    shape = shape_of(absent_pod, preds, allowed_versions=["1.0.0", "2.0.0"])
    assert shape.outcomes == ("absent", "absent", "absent"), shape.outcomes
    assert shape.pin_inside is False, shape  # no label at all -> None not in the array

    # 3. an unrecognized predicate expression fails loud, not silently, same
    # convention as corpus_generator.probe_for.
    weird = corpus_generator.Predicate("x.yaml", "validations", "weird", "1 == 1")
    try:
        classify_state(weird, satisfied_pod)
    except ValueError as e:
        assert "no probe shape recognized" in str(e)
    else:
        raise AssertionError("an unrecognized predicate expression must fail, not classify silently")

    # 4. no witness entry carries a residual or a band -- the corpus's own
    # honesty rule (spec.md: "witness entries test shape, never residual").
    for w in witnesses:
        dumped = w.file.read_text()
        assert "residual" not in dumped and "band" not in dumped, w.file

    # 5. the missing-shape gate, round-tripped: a witness whose shape the
    # full pairwise spine covers passes; the SAME witness's shape, checked
    # against a spine built with one axis value removed, fails -- this IS
    # "a witness shape missing from the generated spine fails the build,"
    # not just asserted in the abstract. The generator varies at most ONE
    # non-pin predicate per entry (pairwise, never a full cross -- spec.md),
    # so the witness used here must be achievable the same way: its pin
    # value is the only thing that differs from the subject's baseline pod,
    # everything else absent. That makes the version-pin axis (literally
    # part of Shape.pin_inside) the natural one to remove -- unlike
    # TIER_VALUES, which corpus_generator's real subject never reads via a
    # matchCondition/validation at all (spec.md, "Coverage and evidence":
    # a *variable* like the tier dial-map is explicitly excluded from the
    # predicate-expression coverage vocabulary), so shrinking it would not
    # move any Shape this ticket defines.
    def _write_spine(entries: list[corpus_generator.Entry], out_dir: Path) -> None:
        spine_dir = out_dir / "spine"
        spine_dir.mkdir(parents=True, exist_ok=True)
        for e in entries:
            (spine_dir / e.filename).write_text(yaml.safe_dump(e.pod, sort_keys=True))
        manifest = {
            "generator_version": "selfcheck",
            "wall_clock": 0.0,
            "populations": {
                "generated-spine": {
                    "checksum": "sha256:selfcheck",
                    "counts": {"old": len(entries), "new": 0, "union": len(entries)},
                    "axes": ["predicate-expression", "version-pin", "tier-label"],
                    "combination": "pairwise",
                    "entries": [
                        {"file": f"spine/{e.filename}", "source": e.source, "pair": e.pair}
                        for e in entries
                    ],
                },
            },
        }
        (out_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))

    with tempfile.TemporaryDirectory() as td:
        entries = corpus_generator.generate_spine(subj, inside_pin="1.0.0", source_tag="old")
        outside_entries = [e for e in entries if "pin=outside" in e.axis_detail]
        assert outside_entries, "fixture setup broken: no pin=outside entries generated"

        full_dir = Path(td) / "full"
        _write_spine(entries, full_dir)
        shrunk_dir = Path(td) / "shrunk"
        _write_spine([e for e in entries if "pin=outside" not in e.axis_detail], shrunk_dir)

        # A witness pinned OUTSIDE the version array, nothing else set --
        # claims-pin still reads satisfied (OUTSIDE_PIN is a nonempty
        # literal), team-label and runAsNonRoot both absent.
        outside_witness_file = subj / "witness-outside.yaml"
        outside_witness_file.write_text(yaml.safe_dump({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "witness-outside", "labels": {corpus_generator.PIN_LABEL: corpus_generator.OUTSIDE_PIN}},
            "spec": {"containers": [{"name": "app", "image": "nginx:1.25"}]},
        }))

        # load_witnesses() only knows the real five + six named witnesses,
        # so this exercises shape_of/spine_shapes directly for the
        # synthetic one rather than monkeypatching load_witnesses.
        preds = corpus_generator.predicates(subj)
        allowed = corpus_generator._orphan_guard.versions(corpus_generator.DISTRIBUTION / "versions.yaml")
        outside_shape = shape_of(
            yaml.safe_load(outside_witness_file.read_text()), preds, allowed
        )
        assert outside_shape.pin_inside is False, outside_shape

        full_shapes = spine_shapes(full_dir, preds, allowed)
        assert outside_shape in full_shapes, (
            "the full pairwise spine (both pin values present) must cover a "
            "pin-outside witness shape"
        )

        shrunk_shapes = spine_shapes(shrunk_dir, preds, allowed)
        assert outside_shape not in shrunk_shapes, (
            "cs-20's own regression test: removing the 'outside' pin axis "
            "value from the generator must make the pin-outside witness "
            "shape fail -- it did not"
        )

        # Same round trip again, but through check_witness_shapes itself
        # (the actual gate, not just its shape_of/spine_shapes building
        # blocks) -- monkeypatch load_witnesses just for this call so the
        # real gate function is what reports the failure and names it.
        original_load_witnesses = load_witnesses
        module = sys.modules[__name__]
        try:
            module.load_witnesses = lambda: (
                [Witness(name="synthetic-outside", kind="rederive-fixture", file=outside_witness_file)],
                [],
            )
            assert check_witness_shapes(subj, full_dir) == [], (
                "the gate must pass when the full spine covers the witness"
            )
            failures = check_witness_shapes(subj, shrunk_dir)
        finally:
            module.load_witnesses = original_load_witnesses
        assert len(failures) == 1, failures
        assert failures[0].witness == "synthetic-outside", failures[0]
        assert failures[0].shape == outside_shape, failures[0]

    # 6. build_witness_manifest records per-witness provenance, including
    # the six real-infra names that are not yet committed.
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td)
        corpus_generator.build_manifest(subj, subj, inside_pin="1.0.0", out_dir=out_dir)
        manifest_path = out_dir / "witness-manifest.yaml"
        manifest = build_witness_manifest(subj, out_dir, manifest_path)
        assert manifest_path.exists()
        names = {e["witness"] for e in manifest["entries"]}
        assert names == set(REAL_INFRA_NAMES) | {w.name for w in fixture_witnesses}, names
        for e in manifest["entries"]:
            if e["kind"] == "rederive-fixture":
                assert e["shape"] is not None and "outcomes" in e["shape"]
                assert e["file"] is not None
            elif e.get("status") == "not-yet-committed":
                assert e["shape"] is None and e["file"] is None

    print(
        "selfcheck ok: witness set holds the 5 rederive fixtures and names the "
        "6 real-infra witnesses (committed or missing); shape is the tuple of "
        "per-predicate outcomes plus the in-array pin flag, read back correctly "
        "for label/spec-bool predicates and absent fields; an unrecognized "
        "predicate expression fails loud; no witness entry carries a residual "
        "or band; a witness shape absent from the generated spine is reported, "
        "removing an axis value (the version-pin 'outside' choice) from the "
        "generator makes a previously-covered witness shape fail, both directly "
        "and through check_witness_shapes itself; the witness manifest records "
        "per-witness provenance including the not-yet-committed real-infra gap"
    )


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args and args[0] == "--selfcheck":
        selfcheck()
        return 0

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, default=HERE / "generated-corpus")
    parser.add_argument("--subject-version")
    parser.add_argument("--out", type=Path, default=HERE / "generated-corpus")
    parsed = parser.parse_args(args)

    supported = corpus_generator._orphan_guard.versions(corpus_generator.DISTRIBUTION / "versions.yaml")
    version = parsed.subject_version or supported[-1]
    subject_dir = corpus_generator._materialize_subject(version)

    witnesses, missing_real = load_witnesses()
    if missing_real:
        print(
            f"NOTE: {len(missing_real)} real-infrastructure witness(es) not yet committed, "
            f"skipped (not faked): {', '.join(missing_real)}"
        )

    failures = check_witness_shapes(subject_dir, parsed.corpus_dir)
    build_witness_manifest(subject_dir, parsed.corpus_dir, parsed.out / "witness-manifest.yaml")

    for f in failures:
        print(f"MISSING WITNESS SHAPE: witness={f.witness!r} kind={f.kind!r} shape={f.shape.as_dict()}")

    if failures:
        print(
            f"FAIL: {len(failures)} witness shape(s) absent from the generated spine -- "
            f"the repair is the generator, never the witness"
        )
        return 1

    print(
        f"ok: all {len(witnesses)} available witness shape(s) present in the generated spine "
        f"({len(missing_real)} real-infrastructure witness(es) not yet committed, skipped)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
