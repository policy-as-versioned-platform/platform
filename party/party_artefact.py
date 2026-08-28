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

Four things this checks -- ticket 11's three, plus ticket 21's publish
capability:

  1. SCHEMA -- structural shape, against schema.json (the single source of
     truth for the allowed roles and the three parent kinds; this module
     reads its enums from that file rather than re-declaring them, so the
     two can never drift apart).
  2. TAGS -- a declared parent version must equal the tag the adopter's own
     Flux/Renovate files actually pin, for every (party, kind) this estate
     wires through Flux today: `nist`/controls and `platform`/implementations.
     `feed` -- ADR-0019's third and last parent kind, covering what used to
     be the separate `pricing` and `threat` kinds -- is pinned by a signed
     tag on the publisher repo, not by a Flux GitRepository: a feed carries
     prices, not rules, so nothing in `gitops/` reconciles it and there is
     nothing there to compare a declared feed version against. This check
     names that plainly (`notes`) rather than silently skipping it or
     claiming a check that was never run (map.md's standing preference:
     "say which findings a plain lint would also have found"). The tag
     itself is checked against the real remote by ticket 21's
     `verify-feed-contract.sh`.
  3. BASELINE MIRROR (adopters only) -- the adopter's `nist` pin ConfigMap carries a
     `baselineName` key (ADR-0013's advisory mirror) that must equal the
     party artefact's own `baseline` field -- the party artefact is the
     signed declaration, the ConfigMap only mirrors it for humans and the
     OSCAL plumbing. A party that does not adopt selects no baseline and has
     no ConfigMap to mirror, so this check is named as not run rather than
     passed.
  4. PUBLISH CAPABILITY -- two facts OBSERVED off this party's repo, not
     claims read out of a data file: `verification_key_present` (a consumer
     can verify this party's signature -- its `release.yml` pins the gitsign
     identity it accepts; ADR-0012/0019/0023 make the tag the one and only
     signature, so the pinned identity IS the verification key, replacing the
     retired `feeds/keys` public key) and `can_publish` (the roles include
     `publisher` AND a `cut-release.yml` exists to cut the signed tag). A
     party that lists `publishes[]` it cannot publish is an error: discovery
     is the catalogue (ADR-0019 point 5), so an entry with no release path is
     a promise the estate cannot keep.

Usage:
    party_artefact.py check <party.yaml> [--adopter-dir DIR] [--nist-configmap PATH]
    party_artefact.py --selfcheck
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from datetime import date
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
# `feed` subsumes the old `pricing` and `threat` kinds (ADR-0019).
UNPINNED_KINDS = {"feed"}

DEFAULT_NIST_CONFIGMAP = "gitops/apps/nist-pin-configmap.yaml"

# The two files that make the publish-capability facts observable, relative
# to a party's own repo root. Both are real files in every publisher repo in
# this estate (platform, nist, ico); neither is a claim in a data file.
RELEASE_WORKFLOW = ".github/workflows/release.yml"
CUT_RELEASE_WORKFLOW = ".github/workflows/cut-release.yml"
# What release.yml must carry for a consumer to verify this party's tag
# against a pinned identity rather than merely "a valid signature exists".
IDENTITY_PIN_KEY = "EXPECTED_IDENTITY_REGEXP"


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


def _floor_enum(schema: dict) -> tuple[str, ...]:
    """The cage tiers a party may floor itself at. Read from schema.json for
    the same reason the roles and kinds are: one source of truth."""
    return tuple(schema["properties"]["overlay"]["properties"]["floor"]["enum"])


def _money_errors(where: str, value: object, currencies: bool = True) -> list[str]:
    """A money object is {amount, currency} and nothing else. Every price in
    this estate carries its currency (spec.md, "The £ seam")."""
    if not isinstance(value, dict):
        return [f"{where} must be a mapping of amount+currency"]
    errors = []
    for field in sorted({"amount", "currency"} - value.keys()):
        errors.append(f"{where} missing {field!r}")
    for field in sorted(value.keys() - {"amount", "currency"}):
        errors.append(f"{where} has unknown field {field!r}")
    if "amount" in value and (isinstance(value["amount"], bool)
                              or not isinstance(value["amount"], (int, float))
                              or value["amount"] < 0):
        errors.append(f"{where}.amount must be a number >= 0")
    if currencies and "currency" in value and not _is_currency(value["currency"]):
        errors.append(f"{where}.currency must be a three-letter ISO 4217 code, got {value['currency']!r}")
    return errors


def _is_currency(value: object) -> bool:
    return isinstance(value, str) and len(value) == 3 and value.isalpha() and value.isupper()


def _is_date(value: object) -> bool:
    """YYYY-MM-DD, and a real calendar date -- '2026-02-31' is not one."""
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return len(value) == 10


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

    roles = doc.get("roles")
    required = list(schema["required"])
    # schema.json's if/then: only a party that ADOPTS selects a baseline. A
    # pure publisher (nist, ico, feeds) selects nothing from anyone.
    if isinstance(roles, list) and "adopter" in roles:
        required.append("baseline")
    for field in required:
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

    if not isinstance(roles, list) or not roles:
        errors.append("'roles' must be a non-empty list")
    else:
        for r in roles:
            if r not in roles_enum:
                errors.append(f"role {r!r} is not one of {roles_enum}")

    if "baseline" in doc and (not isinstance(doc["baseline"], str) or not doc["baseline"]):
        errors.append("'baseline' must be a non-empty string")

    errors += _publishes_errors(doc, kinds_enum)
    errors += _size_errors(doc)
    errors += _appetite_errors(doc)
    if "reporting_currency" in doc and not _is_currency(doc["reporting_currency"]):
        errors.append(
            f"'reporting_currency' must be a three-letter ISO 4217 code, "
            f"got {doc['reporting_currency']!r}")

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
            for field in sorted(edge.keys() - {"party", "kind", "version", "name", "since"}):
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
            # ADR-0019: the parent kind is closed, the feed's name is free --
            # so a feed edge without a name pins nothing identifiable.
            if edge.get("kind") == "feed" and not (
                    isinstance(edge.get("name"), str) and edge.get("name")):
                errors.append(
                    f"inherits[{i}]: kind 'feed' requires a non-empty 'name' "
                    f"(party {edge.get('party')!r})")
            if "name" in edge and (not isinstance(edge["name"], str) or not edge["name"]):
                errors.append(f"inherits[{i}]: 'name' must be a non-empty string")
            if "since" in edge and not _is_date(edge["since"]):
                errors.append(
                    f"inherits[{i}]: 'since' must be a YYYY-MM-DD date, got {edge['since']!r}")

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
        floors = _floor_enum(schema)
        if "floor" in overlay and overlay["floor"] not in floors:
            errors.append(
                f"overlay.floor {overlay['floor']!r} is not one of {floors} "
                f"('infra' is deliberately absent: only a platform-role party declares "
                f"infra, and it declares it on a Namespace manifest)")
        for field in sorted(overlay.keys() - {"add", "restate", "controls", "floor"}):
            errors.append(f"overlay has unknown field {field!r}")

    return errors


def _publishes_errors(doc: dict, kinds_enum: tuple[str, ...]) -> list[str]:
    """`publishes[]` is the discovery record (ADR-0019 point 5). There is no
    central catalogue, so a malformed entry is not a cosmetic defect -- it is
    a feed nobody can find."""
    if "publishes" not in doc:
        return []
    entries = doc["publishes"]
    if not isinstance(entries, list):
        return ["'publishes' must be a list"]
    errors: list[str] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"publishes[{i}] must be a mapping")
            continue
        for field in sorted({"kind", "name", "path"} - entry.keys()):
            errors.append(f"publishes[{i}] missing {field!r}")
        for field in sorted(entry.keys() - {"kind", "name", "path", "payload_schema", "revoked"}):
            errors.append(f"publishes[{i}] has unknown field {field!r}")
        if "kind" in entry and entry["kind"] not in kinds_enum:
            errors.append(f"publishes[{i}]: kind {entry['kind']!r} is not one of {kinds_enum}")
        for field in ("name", "path"):
            if field in entry and (not isinstance(entry[field], str) or not entry[field]):
                errors.append(f"publishes[{i}]: {field!r} must be a non-empty string")
        if entry.get("payload_schema") is not None and not isinstance(entry["payload_schema"], str):
            errors.append(f"publishes[{i}]: 'payload_schema' must be a string or null")
        revoked = entry.get("revoked")
        if revoked is not None and (not isinstance(revoked, list)
                                    or not all(isinstance(v, str) and v for v in revoked)):
            errors.append(f"publishes[{i}]: 'revoked' must be a list of version strings")
    return errors


def _size_errors(doc: dict) -> list[str]:
    """The party's own signed size, which the pricing seam scales against
    (ticket 25, ADR-0020). All five fields or none: a half-declared size
    would silently price a party against a default it never signed."""
    if "size" not in doc:
        return []
    size = doc["size"]
    if not isinstance(size, dict):
        return ["'size' must be a mapping"]
    fields = {"turnover", "customers", "data_subjects", "headcount", "as_of"}
    errors = [f"size missing {f!r}" for f in sorted(fields - size.keys())]
    errors += [f"size has unknown field {f!r}" for f in sorted(size.keys() - fields)]
    if "turnover" in size:
        errors += _money_errors("size.turnover", size["turnover"])
    for field in ("customers", "data_subjects", "headcount"):
        if field in size and (isinstance(size[field], bool)
                              or not isinstance(size[field], int)
                              or size[field] < 0):
            errors.append(f"size.{field} must be an integer >= 0")
    if "as_of" in size and not _is_date(size["as_of"]):
        errors.append(f"size.as_of must be a YYYY-MM-DD date, got {size['as_of']!r}")
    return errors


def _appetite_errors(doc: dict) -> list[str]:
    """Appetite as a signed fact on the party's own artefact, replacing the
    platform-held fixture (ticket 25). The tier selection reads this."""
    if "appetite" not in doc:
        return []
    appetite = doc["appetite"]
    if not isinstance(appetite, dict):
        return ["'appetite' must be a mapping"]
    errors = ["appetite missing 'tolerance'"] if "tolerance" not in appetite else \
        _money_errors("appetite.tolerance", appetite["tolerance"])
    errors += [f"appetite has unknown field {f!r}" for f in sorted(appetite.keys() - {"tolerance"})]
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
        label = f"{party}/{kind}"
        if edge.get("name"):
            label += f":{edge['name']}"
        pin_rel = PIN_FILES.get((party, kind))
        if pin_rel is None:
            if kind in UNPINNED_KINDS:
                notes.append(
                    f"{label}@{version}: no Flux/Renovate pin exists for this kind in "
                    f"this estate today -- declared version not checked here; the signed "
                    f"tag it names is checked against the real remote by "
                    f"verify-feed-contract.sh"
                )
            else:
                notes.append(f"{label}@{version}: no known pin file mapping -- not checked")
            continue
        pin_path = adopter_dir / pin_rel
        if not pin_path.exists():
            errors.append(f"{label}: expected pin file {pin_rel} does not exist")
            continue
        try:
            pinned_tag = _read_pinned_tag(pin_path)
        except Refused as e:
            errors.append(str(e))
            continue
        declared_tag = version if version.startswith("v") else f"v{version}"
        if pinned_tag != declared_tag:
            errors.append(
                f"{label}: party artefact declares {version!r} ({declared_tag}), "
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
# 4. publish capability
# --------------------------------------------------------------------------


def publish_capability(doc: dict, party_dir: Path) -> tuple[dict, list[str]]:
    """Two OBSERVED facts about this party's repo, and the one error they can
    produce. Returns ({facts}, [errors]).

    `verification_key_present`: can a consumer verify what this party signs?
    Under ADR-0012/ADR-0019/ADR-0023 the gitsign tag is the only signature, so
    the thing a consumer needs is not a key file but the identity the tag is
    pinned to -- `release.yml`'s EXPECTED_IDENTITY_REGEXP. This replaces the
    old `signing_key_present` flag (honesty/reflexive.py), which reported
    whether a `feeds/keys` public key file existed: a detached-signature
    mechanism D3 retires. A checkout with no release.yml, or a release.yml
    that verifies "a valid signature exists" without pinning an identity,
    reports False -- an unpinned identity is not verification.

    `can_publish`: this party's roles include `publisher` AND a
    `cut-release.yml` exists to cut the signed tag. A role on its own is a
    claim; the workflow is the capability.

    The error: a party that advertises `publishes[]` it cannot publish.
    Discovery is the catalogue (ADR-0019 point 5), so an entry with no
    release path is a promise the estate cannot keep.
    """
    roles = doc.get("roles") or []
    release = party_dir / RELEASE_WORKFLOW
    identity_pinned = release.exists() and IDENTITY_PIN_KEY in release.read_text()
    facts = {
        "verification_key_present": identity_pinned,
        "can_publish": "publisher" in roles and (party_dir / CUT_RELEASE_WORKFLOW).exists(),
    }
    errors: list[str] = []
    published = doc.get("publishes") or []
    if published and not facts["can_publish"]:
        why = ("'publisher' is not in roles" if "publisher" not in roles
               else f"{CUT_RELEASE_WORKFLOW} does not exist in {party_dir}")
        errors.append(
            f"publishes[] declares {len(published)} artefact(s) but this party cannot "
            f"publish: {why}")
    return facts, errors


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
        return {"errors": schema_errors, "notes": [], "facts": {}}

    tag_errors, notes = check_tags(doc, adopter_dir)
    # Only a party that adopts selects a baseline, so only a party that
    # adopts has a pin ConfigMap to mirror it in.
    if "adopter" in (doc.get("roles") or []):
        baseline_errors = check_baseline_mirror(doc, adopter_dir, configmap_rel)
    else:
        baseline_errors = []
        notes.append("baseline mirror not checked: this party does not adopt, so it "
                     "selects no baseline and has no nist pin ConfigMap")
    facts, publish_errors = publish_capability(doc, adopter_dir)
    return {
        "errors": [*tag_errors, *baseline_errors, *publish_errors],
        "notes": notes,
        "facts": facts,
    }


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
        for name, value in sorted(result.get("facts", {}).items()):
            print(f"FACT: {name}={str(value).lower()}")
        if result["errors"]:
            for e in result["errors"]:
                print(f"REFUSED: {e}", file=sys.stderr)
            return 1
        print(f"OK: {args.party_yaml} is a valid party artefact; every check that could run agrees "
              f"(any it could not is a NOTE above)")
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
    assert kinds_enum == ("controls", "implementations", "feed"), kinds_enum
    assert roles_enum == ("publisher", "risk-bearer", "adopter", "platform", "insurer"), roles_enum
    assert _floor_enum(schema) == ("baseline", "restricted", "quarantine", "isolated"), \
        _floor_enum(schema)
    print("OK schema.json: the three parent kinds, five roles and four floor tiers are exactly "
          "what this module expects")

    valid_doc = {
        "party": "driftwood",
        "roles": ["risk-bearer", "adopter"],
        "baseline": "MODERATE",
        "inherits": [
            {"party": "platform", "kind": "implementations", "version": "0.1.0"},
            {"party": "nist", "kind": "controls", "version": "1.0.0"},
            {"party": "ico", "kind": "feed", "name": "penalty-schema", "version": "v1",
             "since": "2026-07-16"},
            {"party": "feeds", "kind": "feed", "name": "threat-register", "version": "v1"},
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
    print("OK validate_schema: a parent kind outside the three is caught")

    bad_role = json.loads(json.dumps(valid_doc))
    bad_role["roles"] = ["dictator"]
    errs = validate_schema(bad_role, schema)
    assert any("dictator" in e for e in errs), errs
    print("OK validate_schema: a role outside the five is caught")

    extra_field = json.loads(json.dumps(valid_doc))
    extra_field["workloads"] = []
    errs = validate_schema(extra_field, schema)
    assert any("workloads" in e for e in errs), errs
    print("OK validate_schema: an unknown top-level field is caught")

    assert validate_schema(["party: x"])
    print("OK validate_schema: a non-mapping document is refused, not crashed on")

    no_name = json.loads(json.dumps(valid_doc))
    del no_name["inherits"][2]["name"]
    errs = validate_schema(no_name, schema)
    assert any("requires a non-empty 'name'" in e for e in errs), errs
    print("OK validate_schema: a feed parent with no name is caught (ADR-0019: kind closed, name free)")

    bad_since = json.loads(json.dumps(valid_doc))
    bad_since["inherits"][2]["since"] = "2026-02-31"
    errs = validate_schema(bad_since, schema)
    assert any("since" in e for e in errs), errs
    print("OK validate_schema: a 'since' that is not a real calendar date is caught")

    # A publisher selects no baseline; an adopter must.
    publisher_doc = {
        "party": "feeds",
        "roles": ["publisher"],
        "inherits": [],
        "publishes": [
            {"kind": "feed", "name": "threat-register", "path": "threat-register",
             "payload_schema": "threat-register/payload.schema.json", "revoked": []},
        ],
        "reporting_currency": "GBP",
        "overlay": {"add": [], "restate": []},
    }
    assert validate_schema(publisher_doc, schema) == [], validate_schema(publisher_doc, schema)
    print("OK validate_schema: a publisher with no baseline is valid; publishes[] validates")

    no_baseline_adopter = json.loads(json.dumps(valid_doc))
    del no_baseline_adopter["baseline"]
    errs = validate_schema(no_baseline_adopter, schema)
    assert any("baseline" in e for e in errs), errs
    print("OK validate_schema: an ADOPTER with no baseline is still refused")

    bad_publish = json.loads(json.dumps(publisher_doc))
    bad_publish["publishes"][0]["kind"] = "prices"
    errs = validate_schema(bad_publish, schema)
    assert any("prices" in e for e in errs), errs
    print("OK validate_schema: a publishes[] kind outside the three is caught")

    sized = json.loads(json.dumps(valid_doc))
    sized["size"] = {"turnover": {"amount": 120000000, "currency": "GBP"}, "customers": 400000,
                     "data_subjects": 400000, "headcount": 900, "as_of": "2026-08-28"}
    sized["appetite"] = {"tolerance": {"amount": 40000, "currency": "GBP"}}
    sized["reporting_currency"] = "GBP"
    sized["overlay"]["floor"] = "restricted"
    assert validate_schema(sized, schema) == [], validate_schema(sized, schema)
    print("OK validate_schema: signed size, appetite, reporting currency and a cage floor validate")

    no_currency = json.loads(json.dumps(sized))
    del no_currency["size"]["turnover"]["currency"]
    errs = validate_schema(no_currency, schema)
    assert any("currency" in e for e in errs), errs
    print("OK validate_schema: a turnover with no currency is refused -- every amount carries one")

    half_size = json.loads(json.dumps(sized))
    del half_size["size"]["data_subjects"]
    errs = validate_schema(half_size, schema)
    assert any("data_subjects" in e for e in errs), errs
    print("OK validate_schema: a half-declared size is refused, not defaulted")

    infra_floor = json.loads(json.dumps(sized))
    infra_floor["overlay"]["floor"] = "infra"
    errs = validate_schema(infra_floor, schema)
    assert any("infra" in e for e in errs), errs
    print("OK validate_schema: an adopter cannot floor itself at 'infra'")

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
    assert any("ico/feed:penalty-schema" in n for n in notes), notes
    assert any("feeds/feed:threat-register" in n for n in notes), notes
    print("OK check_tags: agreeing pins pass; each feed parent is named as unchecked, not silenced")

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

    # ---- publish_capability: two OBSERVED facts, against real files ----
    facts, errs = publish_capability(publisher_doc, tmp)
    assert facts == {"verification_key_present": False, "can_publish": False}, facts
    assert errs and "cannot publish" in errs[0], errs
    print("OK publish_capability: a party advertising publishes[] with no cut-release.yml is refused")

    _write(tmp / CUT_RELEASE_WORKFLOW, "name: cut-release\non: {workflow_dispatch: {}}\n")
    _write(tmp / RELEASE_WORKFLOW, "name: release\non: {push: {tags: ['v*.*.*']}}\n")
    facts, errs = publish_capability(publisher_doc, tmp)
    assert facts["can_publish"] is True, facts
    assert facts["verification_key_present"] is False, facts
    assert errs == [], errs
    print("OK publish_capability: a release.yml that pins NO identity is not verification")

    _write(tmp / RELEASE_WORKFLOW,
           "name: release\nenv:\n  " + IDENTITY_PIN_KEY + ": ^https://github\\.com/x/y$\n")
    facts, errs = publish_capability(publisher_doc, tmp)
    assert facts == {"verification_key_present": True, "can_publish": True}, facts
    print("OK publish_capability: an identity-pinned release.yml + cut-release.yml -> both true")

    no_publisher_role = json.loads(json.dumps(publisher_doc))
    no_publisher_role["roles"] = ["risk-bearer"]
    facts, errs = publish_capability(no_publisher_role, tmp)
    assert facts["can_publish"] is False, facts
    assert errs and "'publisher' is not in roles" in errs[0], errs
    print("OK publish_capability: the workflow alone is not the capability -- the role is read too")

    # ---- check(): end to end, a real party.yaml on disk ----
    _write(tmp / "gitops" / "apps" / "nist-pin-configmap.yaml", (
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x-nist-pin, namespace: x}\n"
        "data:\n  baselineName: MODERATE\n"
    ))
    party_path = tmp / "party.yaml"
    party_path.write_text(yaml.safe_dump(valid_doc, sort_keys=False))
    result = check(party_path, tmp)
    assert result["errors"] == [], result
    assert result["facts"]["verification_key_present"] is True, result
    print("OK check(): a real party.yaml with agreeing pins and baseline mirror passes end to end")

    publisher_path = tmp / "party-publisher.yaml"
    publisher_path.write_text(yaml.safe_dump(publisher_doc, sort_keys=False))
    result = check(publisher_path, tmp)
    assert result["errors"] == [], result
    assert result["facts"] == {"verification_key_present": True, "can_publish": True}, result
    assert any("does not adopt" in n for n in result["notes"]), result
    print("OK check(): a publisher with no baseline passes; the baseline mirror is named, not run")

    bad_party_path = tmp / "party-bad.yaml"
    bad_party_path.write_text(yaml.safe_dump(bad_kind, sort_keys=False))
    result = check(bad_party_path, tmp)
    assert result["errors"], result
    print("OK check(): a structurally invalid party artefact refuses before touching any pin file")

    print(
        "\nselfcheck ok: schema.json is the single source of truth for the allowed roles, parent "
        "kinds and floor tiers; validate_schema catches every structural defect ticket 11 names "
        "and every one ticket 21 adds (a feed parent with no name, a bad 'since', an adopter with "
        "no baseline, a publishes[] kind outside the three, a half-declared size, an amount with "
        "no currency, a floor at 'infra'); check_tags matches a real Flux pin and refuses a real "
        "disagreement, naming each feed parent as unchecked rather than silencing it; "
        "publish_capability reads two facts off real workflow files and refuses a publishes[] "
        "with no release path; check_baseline_mirror matches, refuses a disagreement, and refuses "
        "a missing key; check() composes them end to end against a real party.yaml on disk, for "
        "an adopter and for a publisher."
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv))
