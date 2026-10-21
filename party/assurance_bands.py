"""The declared assurance-band contract, shared by party and offline table readers.

This module uses only the standard library; the legacy offline fixture does
not need the YAML party reader. Field names and scalar rules come from the
party schema. It validates policy inputs and never calculates a cutoff.
"""
from __future__ import annotations

import json
import math
from pathlib import Path


def errors(value: object, rule: dict | None = None, *, legacy: bool = False) -> list[str]:
    if rule is None:
        schema = json.loads(Path(__file__).with_name("schema.json").read_text())
        rule = schema["properties"]["appetite"]["properties"]["assurance_bands"]
    if not isinstance(value, dict):
        return ["assurance bands must be an object"]
    properties = rule["properties"]
    required = set(rule["required"])
    allowed = set(properties)
    if legacy:
        required.remove("currency")  # The existing flat fixture is implicitly GBP.
        allowed.add("note")
    problems = [f"assurance bands missing {key!r}" for key in sorted(required - value.keys())]
    problems += [f"assurance bands has unknown field {key!r}"
                 for key in sorted(value.keys() - allowed, key=str)]
    for key in properties.keys() & value.keys():
        scalar = properties[key]
        item = value[key]
        if scalar["type"] == "number":
            if (type(item) not in (int, float)
                    or (type(item) is float and not math.isfinite(item))
                    or item < scalar["minimum"]):
                problems.append(f"assurance bands {key} must be a finite number >= 0")
        elif type(item) is not str or item != scalar["const"]:
            problems.append(f"assurance bands {key} must equal {scalar['const']!r}")
    if legacy and "note" in value and not isinstance(value["note"], str):
        problems.append("assurance bands note must be a string")
    if not problems and not value["step_up_at"] <= value["attest_at"] <= value["no_cage_at"]:
        problems.append("assurance bands must be ordered step_up_at <= attest_at <= no_cage_at")
    return problems
