#!/usr/bin/env python3
"""party_artefact.py -- the party artefact schema and its check (policy-composition ticket 11).

One signed file per party declares that party: its name, its roles, its
parents as party+kind+version, its selected baseline name, and an overlay
with `add` and `restate` lists. The shape is the one
spikes/cs-06b-cross-party-composition/material/parties/*.yaml proposed,
promoted from prototype to format (spec.md, "The party artefact";
ADR-0012, ADR-0013).

This module lives in `platform`, not in an adopter's own repo, because the
adopters call it through their pinned `platform` dependency -- the same
"library, not a service" shape `shift-left/ci-check.py` already uses
(spec.md, "In the adopter's own repo, on the pull request check").

Three things this checks, each named in ticket 11's acceptance criteria:

  1. SCHEMA -- structural shape, against schema.json (the single source of
     truth for the allowed roles and the four parent kinds; this module
     reads its enums from that file rather than re-declaring them, so the
     two can never drift apart).
  2. TAGS -- a declared parent version must equal the tag the adopter's own
     Flux/Renovate files actually pin, for every (party, kind) this estate
     wires through Flux today: `nist`/controls and `platform`/implementations.
     `pricing` (ico) and `threat` (platform's feeds) are real parent kinds
     ADR-0013's own model requires, but neither is pinned by a Flux
     GitRepository anywhere in this estate: ico ships no git tags at all
     (its schema versions are plain `v1`/`v2` directories, signed with a
     detached ed25519 signature, not gitsign), and the threat register is a
     versioned subdirectory read out of the ALREADY-pinned `platform`
     checkout, not a second pin object. There is nothing in `gitops/` to
     compare a declared pricing/threat version against, so this check names
     that plainly (`notes`) rather than silently skipping it or claiming a
     check that was never run (map.md's standing preference: "say which
     findings a plain lint would also have found").
  3. BASELINE MIRROR -- the adopter's `nist` pin ConfigMap carries a
     `baselineName` key (ADR-0013's advisory mirror) that must equal the
     party artefact's own `baseline` field -- the party artefact is the
     signed declaration, the ConfigMap only mirrors it for humans and the
     OSCAL plumbing.

Usage:
    party_artefact.py check <party.yaml> [--adopter-dir DIR] [--nist-configmap PATH]
    party_artefact.py --selfcheck
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "schema.json"

# (party, kind) -> the Flux GitRepository file, relative to the adopter repo
# root, whose spec.ref.tag must equal the declared version. Both real pins
# in this estate write a "v"-prefixed semver tag; the party artefact (per
# spec.md's own example) writes the bare semver, so the comparison adds
# exactly one leading "v" when the declared string doesn't already carry
# one -- never folds case, never strips anything else (ADR-0013's own
# exact-string resolution rule, reapplied to a version instead of a
# control id).
PIN_FILES: dict[tuple[str, str], str] = {
    ("nist", "controls"): "gitops/flux-system/gotk-sync-nist.yaml",
    ("platform", "implementations"): "gitops/platform/platform-pin.yaml",
}

# Real parent kinds with nothing pinned by Flux to check them against in
# this estate today. Named, not silenced -- see the module docstring.
UNPINNED_KINDS = {"pricing", "threat"}

DEFAULT_NIST_CONFIGMAP = "gitops/apps/nist-pin-configmap.yaml"


class Refused(Exception):
    """Any reason a pin file can't even be read. main() turns every
    Refused, and every entry in a result's `errors`, into a non-zero exit
    -- never a silent pass."""


# --------------------------------------------------------------------------
# 1. schema
# --------------------------------------------------------------------------


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def _schema_enums(schema: dict) -> tuple[tuple[str, ...], tuple[str, ...]]:
    roles = tuple(schema["properties"]["roles"]["items"]["enum"])
    kinds = tuple(schema["properties"]["inherits"]["items"]["properties"]["kind"]["enum"])
    return roles, kinds


def validate_schema(doc: object, schema: dict | None = None) -> list[str]:
    """Structural validation against schema.json's shape. Returns every
    error found; an empty list means the document is structurally valid.
    Hand-rolled rather than a `jsonschema` dependency -- the shape is five
    fixed fields, and a real dependency for that is not the estate's own
    "no bespoke tooling" preference (CONTEXT.md), it is the opposite of it."""
    schema = schema or load_schema()
    roles_enum, kinds_enum = _schema_enums(schema)
    errors: list[str] = []

    if not isinstance(doc, dict):
        return ["party artefact must be a mapping at the top level"]

    for field in schema["required"]:
        if field not in doc:
            errors.append(f"missing required field {field!r}")
    allowed_top = set(schema["properties"])
    for field in doc:
        if field not in allowed_top:
            errors.append(f"unknown top-level field {field!r}")
    if errors:
        return errors  # the checks below assume every required field exists

    if not isinstance(doc["party"], str) or not doc["party"]:
        errors.append("'party' must be a non-empty string")

    roles = doc["roles"]
    if not isinstance(roles, list) or not roles:
        errors.append("'roles' must be a non-empty list")
    else:
        for r in roles:
            if r not in roles_enum:
                errors.append(f"role {r!r} is not one of {roles_enum}")

    if not isinstance(doc["baseline"], str) or not doc["baseline"]:
        errors.append("'baseline' must be a non-empty string")

    inherits = doc["inherits"]
    if not isinstance(inherits, list):
        errors.append("'inherits' must be a list")
    else:
        for i, edge in enumerate(inherits):
            if not isinstance(edge, dict):
                errors.append(f"inherits[{i}] must be a mapping")
                continue
            for field in sorted({"party", "kind", "version"} - edge.keys()):
                errors.append(f"inherits[{i}] missing {field!r}")
            for field in sorted(edge.keys() - {"party", "kind", "version"}):
                errors.append(f"inherits[{i}] has unknown field {field!r}")
            if "kind" in edge and edge["kind"] not in kinds_enum:
                errors.append(
                    f"inherits[{i}]: kind {edge['kind']!r} is not one of {kinds_enum} "
                    f"(party {edge.get('party')!r})"
                )
            if "party" in edge and (not isinstance(edge["party"], str) or not edge["party"]):
                errors.append(f"inherits[{i}]: 'party' must be a non-empty string")
            if "version" in edge and (not isinstance(edge["version"], str) or not edge["version"]):
                errors.append(f"inherits[{i}]: 'version' must be a non-empty string")

    overlay = doc["overlay"]
    if not isinstance(overlay, dict):
        errors.append("'overlay' must be a mapping")
    else:
        for field in ("add", "restate"):
            if field not in overlay:
                errors.append(f"overlay missing {field!r}")
            elif not isinstance(overlay[field], list):
                errors.append(f"overlay.{field} must be a list")
        if "controls" in overlay and not isinstance(overlay["controls"], list):
            errors.append("overlay.controls must be a list")
        for field in sorted(overlay.keys() - {"add", "restate", "controls"}):
            errors.append(f"overlay has unknown field {field!r}")

    return errors


# --------------------------------------------------------------------------
# 2. tags
# --------------------------------------------------------------------------


def _read_pinned_tag(pin_path: Path) -> str:
    """The `spec.ref.tag` off the first GitRepository document in a
    (possibly multi-document) Flux pin file -- the same read
    `adopter-gate.py` already does for `platform-pin.yaml`."""
    docs = [d for d in yaml.safe_load_all(pin_path.read_text()) if isinstance(d, dict)]
    matches = [d for d in docs if d.get("kind") == "GitRepository"]
    if not matches:
        raise Refused(f"{pin_path}: no GitRepository document found")
    return matches[0]["spec"]["ref"]["tag"]


def check_tags(doc: dict, adopter_dir: Path) -> tuple[list[str], list[str]]:
    """Returns (errors, notes). An error is a real disagreement between a
    declared version and a pinned tag, or a pin file ticket 11 expects that
    is simply missing. A note names a parent kind this estate has nothing
    pinned to check against -- never silent, never a failure on its own."""
    errors: list[str] = []
    notes: list[str] = []
    for edge in doc.get("inherits", []) or []:
        party, kind, version = edge.get("party"), edge.get("kind"), edge.get("version")
        pin_rel = PIN_FILES.get((party, kind))
        if pin_rel is None:
            if kind in UNPINNED_KINDS:
                notes.append(
                    f"{party}/{kind}@{version}: no Flux/Renovate pin exists for this kind in "
                    f"this estate today -- declared version not checked against anything"
                )
            else:
                notes.append(f"{party}/{kind}@{version}: no known pin file mapping -- not checked")
            continue
        pin_path = adopter_dir / pin_rel
        if not pin_path.exists():
            errors.append(f"{party}/{kind}: expected pin file {pin_rel} does not exist")
            continue
        try:
            pinned_tag = _read_pinned_tag(pin_path)
        except Refused as e:
            errors.append(str(e))
            continue
        declared_tag = version if version.startswith("v") else f"v{version}"
        if pinned_tag != declared_tag:
            errors.append(
                f"{party}/{kind}: party artefact declares {version!r} ({declared_tag}), "
                f"but {pin_rel} pins {pinned_tag!r}"
            )
    return errors, notes


# --------------------------------------------------------------------------
# 3. baseline mirror
# --------------------------------------------------------------------------


def check_baseline_mirror(doc: dict, adopter_dir: Path,
                           configmap_rel: str = DEFAULT_NIST_CONFIGMAP) -> list[str]:
    """The nist pin ConfigMap's `baselineName` key must equal the party
    artefact's own `baseline` field. The party artefact is the risk-bearing
    declaration (ADR-0013); the ConfigMap only mirrors it."""
    cm_path = adopter_dir / configmap_rel
    if not cm_path.exists():
        return [f"{configmap_rel} does not exist -- cannot mirror the baseline name"]
    docs = [d for d in yaml.safe_load_all(cm_path.read_text()) if isinstance(d, dict)]
    matches = [d for d in docs if d.get("kind") == "ConfigMap"]
    if not matches:
        return [f"{configmap_rel}: no ConfigMap document found"]
    data = matches[0].get("data") or {}
    mirrored = data.get("baselineName")
    declared = doc.get("baseline")
    if mirrored is None:
        return [f"{configmap_rel}: data.baselineName is not set (party artefact declares {declared!r})"]
    if mirrored != declared:
        return [
            f"{configmap_rel}: data.baselineName={mirrored!r} disagrees with the party "
            f"artefact's baseline={declared!r}"
        ]
    return []


# --------------------------------------------------------------------------
# the whole check
# --------------------------------------------------------------------------


def check(party_yaml: Path, adopter_dir: Path | None = None,
          configmap_rel: str = DEFAULT_NIST_CONFIGMAP) -> dict:
    """Runs every check in this module against one party artefact. Returns
    {"errors": [...], "notes": [...]} -- empty errors means it passes."""
    adopter_dir = adopter_dir or party_yaml.parent
    doc = yaml.safe_load(party_yaml.read_text())

    schema_errors = validate_schema(doc)
    if schema_errors:
        # A structurally invalid document can't be checked any further --
        # there is nothing safe to read a party/kind/version out of.
        return {"errors": schema_errors, "notes": []}

    tag_errors, notes = check_tags(doc, adopter_dir)
    baseline_errors = check_baseline_mirror(doc, adopter_dir, configmap_rel)
    return {"errors": [*tag_errors, *baseline_errors], "notes": notes}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--selfcheck":
        selfcheck()
        return 0

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("party_yaml", type=Path)
    c.add_argument("--adopter-dir", type=Path, default=None)
    c.add_argument("--nist-configmap", default=DEFAULT_NIST_CONFIGMAP)
    args = p.parse_args(argv[1:])

    if args.cmd == "check":
        adopter_dir = args.adopter_dir or args.party_yaml.parent
        result = check(args.party_yaml, adopter_dir, args.nist_configmap)
        for note in result["notes"]:
            print(f"NOTE: {note}")
        if result["errors"]:
            for e in result["errors"]:
                print(f"REFUSED: {e}", file=sys.stderr)
            return 1
        print(f"OK: {args.party_yaml} is a valid party artefact; pinned tags and the baseline mirror agree")
        return 0
    return 2


# --------------------------------------------------------------------------
# selfcheck -- every acceptance criterion, against real files on disk
# --------------------------------------------------------------------------


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def selfcheck() -> None:
    schema = load_schema()
    roles_enum, kinds_enum = _schema_enums(schema)
    assert kinds_enum == ("controls", "implementations", "pricing", "threat"), kinds_enum
    assert roles_enum == ("publisher", "risk-bearer", "adopter"), roles_enum
    print("OK schema.json: the four parent kinds and three roles are exactly what this module expects")

    valid_doc = {
        "party": "driftwood",
        "roles": ["risk-bearer", "adopter"],
        "baseline": "MODERATE",
        "inherits": [
            {"party": "platform", "kind": "implementations", "version": "0.1.0"},
            {"party": "nist", "kind": "controls", "version": "1.0.0"},
            {"party": "ico", "kind": "pricing", "version": "v1"},
            {"party": "platform", "kind": "threat", "version": "v1"},
        ],
        "overlay": {"add": [], "restate": []},
    }
    assert validate_schema(valid_doc, schema) == []
    print("OK validate_schema: a well-formed party artefact has no errors")

    missing = dict(valid_doc)
    del missing["baseline"]
    errs = validate_schema(missing, schema)
    assert any("baseline" in e for e in errs), errs
    print("OK validate_schema: a missing required field is caught")

    bad_kind = json.loads(json.dumps(valid_doc))
    bad_kind["inherits"][0]["kind"] = "rules"
    errs = validate_schema(bad_kind, schema)
    assert any("rules" in e for e in errs), errs
    print("OK validate_schema: a parent kind outside the four is caught")

    bad_role = json.loads(json.dumps(valid_doc))
    bad_role["roles"] = ["dictator"]
    errs = validate_schema(bad_role, schema)
    assert any("dictator" in e for e in errs), errs
    print("OK validate_schema: a role outside the three is caught")

    extra_field = json.loads(json.dumps(valid_doc))
    extra_field["workloads"] = []
    errs = validate_schema(extra_field, schema)
    assert any("workloads" in e for e in errs), errs
    print("OK validate_schema: an unknown top-level field is caught")

    assert validate_schema(["party: x"])
    print("OK validate_schema: a non-mapping document is refused, not crashed on")

    # ---- check_tags: a REAL agreeing pin, a REAL disagreeing pin, and the
    # two unpinned kinds named rather than silently skipped ----
    tmp = Path(tempfile.mkdtemp(prefix="party-artefact-"))
    _write(tmp / "gitops" / "platform" / "platform-pin.yaml", (
        "apiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\n"
        "metadata: {name: platform, namespace: flux-system}\n"
        "spec:\n  ref:\n    tag: v0.1.0\n    commit: " + "a" * 40 + "\n"
    ))
    _write(tmp / "gitops" / "flux-system" / "gotk-sync-nist.yaml", (
        "apiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\n"
        "metadata: {name: nist, namespace: flux-system}\n"
        "spec:\n  ref:\n    tag: v1.0.0\n    commit: " + "b" * 40 + "\n"
    ))
    tag_errors, notes = check_tags(valid_doc, tmp)
    assert tag_errors == [], tag_errors
    assert any("pricing" in n for n in notes), notes
    assert any("threat" in n for n in notes), notes
    print("OK check_tags: agreeing pins pass; pricing/threat are named as unchecked, not silenced")

    mismatched = json.loads(json.dumps(valid_doc))
    mismatched["inherits"][0]["version"] = "0.2.0"
    tag_errors, _ = check_tags(mismatched, tmp)
    assert any("0.2.0" in e and "v0.1.0" in e for e in tag_errors), tag_errors
    print("OK check_tags: a declared version that disagrees with the pinned tag is refused")

    missing_pin_errors, _ = check_tags(valid_doc, Path(tempfile.mkdtemp(prefix="party-artefact-empty-")))
    assert any("does not exist" in e for e in missing_pin_errors), missing_pin_errors
    print("OK check_tags: a missing pin file that ticket 11 expects is refused, not skipped")

    # ---- check_baseline_mirror: agrees, disagrees, missing key ----
    _write(tmp / "gitops" / "apps" / "nist-pin-configmap.yaml", (
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x-nist-pin, namespace: x}\n"
        "data:\n  baselineName: MODERATE\n  catalogVersion: \"1.0.0\"\n"
    ))
    assert check_baseline_mirror(valid_doc, tmp) == []
    print("OK check_baseline_mirror: an agreeing baselineName passes")

    _write(tmp / "gitops" / "apps" / "nist-pin-configmap.yaml", (
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x-nist-pin, namespace: x}\n"
        "data:\n  baselineName: HIGH\n"
    ))
    errs = check_baseline_mirror(valid_doc, tmp)
    assert any("HIGH" in e and "MODERATE" in e for e in errs), errs
    print("OK check_baseline_mirror: a disagreeing baselineName is refused")

    _write(tmp / "gitops" / "apps" / "nist-pin-configmap.yaml", (
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x-nist-pin, namespace: x}\n"
        "data:\n  catalogVersion: \"1.0.0\"\n"
    ))
    errs = check_baseline_mirror(valid_doc, tmp)
    assert any("baselineName" in e for e in errs), errs
    print("OK check_baseline_mirror: a missing baselineName key is refused")

    # ---- check(): end to end, a real party.yaml on disk ----
    _write(tmp / "gitops" / "apps" / "nist-pin-configmap.yaml", (
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x-nist-pin, namespace: x}\n"
        "data:\n  baselineName: MODERATE\n"
    ))
    party_path = tmp / "party.yaml"
    party_path.write_text(yaml.safe_dump(valid_doc, sort_keys=False))
    result = check(party_path, tmp)
    assert result["errors"] == [], result
    print("OK check(): a real party.yaml with agreeing pins and baseline mirror passes end to end")

    bad_party_path = tmp / "party-bad.yaml"
    bad_party_path.write_text(yaml.safe_dump(bad_kind, sort_keys=False))
    result = check(bad_party_path, tmp)
    assert result["errors"], result
    print("OK check(): a structurally invalid party artefact refuses before touching any pin file")

    print(
        "\nselfcheck ok: schema.json is the single source of truth for the allowed roles and "
        "parent kinds; validate_schema catches every structural defect ticket 11 names (a missing "
        "field, a kind outside the four, an unknown field); check_tags matches a real Flux pin and "
        "refuses a real disagreement, naming pricing/threat as unchecked rather than silencing "
        "them; check_baseline_mirror matches, refuses a disagreement, and refuses a missing key; "
        "check() composes all three end to end against a real party.yaml on disk."
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv))
