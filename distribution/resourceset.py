#!/usr/bin/env python3
"""resourceset.py -- read the LIVE ResourceSet template's own policy documents.

`versions.yaml` is what flux-operator renders onto a cluster. `render-orphan-guard.py` and
`render-governed-namespace-guard.py` are its offline twins: the verify beats, the shift-left
check and composition all run without flux-operator in the loop, so they re-derive the same
documents in python. Two copies of a policy body, with nothing asserting they agree.

They did not agree. Both twins carried `policy-as-versioned.dev/policy: platform-machinery`
(cs-22's identity label, which the pairing rule keys on) and neither copy in the template did;
found while converting both guards for eco-system ticket 89. The same silence is what let the
2026-08-28 `Audit -> Deny` promotion be made in two places by hand.

So each twin's `--selfcheck` now asserts twin == template, and this module is the one place
that reads the template. It parses only the documents that survive without a template engine:
the two guards are static text, while the per-version GitRepository/Kustomization fan-out
carries sprig `<< range >>` markers and is skipped by name (it has no policy body to compare).
The allow-list ranged from the version array is substituted with the twin's own rendered
expression before parsing, in both the forms the template uses it, so the comparison covers
every other line of every document and never pretends to check the range itself.

Usage (library only):
    from resourceset import guard_docs
    guard_docs(Path("versions.yaml"), allowed_expr="['4.0.0', '5.0.0']")["policy-version-orphan-guard"]
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

#: The allow-list, ranged from the version array, in the two forms the template uses it. The
#: whole-value form is the orphan guard's `allowed` variable, quoted because a plain scalar
#: starting with `[` would parse as a flow sequence. The inline form sits inside a longer CEL
#: expression -- the orphan CAGE's and the bottom-rung reach cage's match conditions, which
#: have to test membership of the SAME array and cannot reference a `variables` entry, because
#: Kyverno evaluates match conditions before variables.
_RANGED_WHOLE = re.compile(r'(?m)^(\s*expression: )"\[<<.*?\]"[ \t]*$')
_RANGED_INLINE = re.compile(r'\[<< range \$i.*?<< end >>\]')


def template_text(versions_path: Path) -> str:
    doc = yaml.safe_load(Path(versions_path).read_text())
    return doc["spec"]["resourcesTemplate"]


def guard_docs(versions_path: Path, allowed_expr: str) -> dict[str, dict]:
    """Every policy document the template carries that is not itself template-ranged, by name.

    `allowed_expr` is the twin's rendered allow-list expression; it is substituted for the
    template's `<< range >>` line so the rest of that document can be parsed and compared.
    """
    text = template_text(versions_path)
    text = _RANGED_WHOLE.sub(lambda m: m.group(1) + json.dumps(allowed_expr), text)
    text = _RANGED_INLINE.sub(lambda _: allowed_expr, text)
    out: dict[str, dict] = {}
    for chunk in text.split("\n---\n"):
        if "<<" in chunk:
            continue                      # the version fan-out; no policy body to compare
        doc = yaml.safe_load(chunk)
        if isinstance(doc, dict) and (doc.get("metadata") or {}).get("name"):
            out[doc["metadata"]["name"]] = doc
    return out
