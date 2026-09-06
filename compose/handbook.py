#!/usr/bin/env python3
"""The handbook: a compose-time render of one adopter's composed artefact.

Eco-system ticket 34; ADR-0007's last-mile section, confirmed 2026-09-06 by ticket 80.

WHAT THIS IS. `composition.py` renders an adopter's composed policy set from its signed,
pinned parents. That artefact is machine-readable and no human reads it. This module turns
the artefact -- and nothing else -- into one Markdown page, `composed/HANDBOOK.md`, which
`composition.py` puts in the same `rendered` mapping as `HEADER.yaml` and the policy objects.
So the page lands in the same pull request as the artefact, is compared byte-for-byte by the
same compose-check that grades the artefact, and is carried under the same gitsign tag.

WHAT MAKES IT NOT A LIE. Every sentence here is derived from a field of the artefact. The
module reads no clock, no environment, no network and no file outside the mapping it is
handed. So `render()` is a pure function of the artefact, and that is checkable after the
fact: take the artefact as SERVED at a tag, render it again, and compare bytes with the
`HANDBOOK.md` served at that same tag. `verify-fresh.sh` beside this file is that check.
A handbook that says something the composed artefact does not would have to survive a byte
comparison against a render of that artefact, and it cannot.

WHAT IT REFUSES TO INVENT (ADR-0020). Where a sentence would need an instrument the artefact
does not carry -- no `exposure` block, no `selection-policy`, a price with no `lef_basis` --
the render NAMES the absent field and states no sentence. It never defaults to zero and never
defaults to prose. Every such absence is listed, and counted, in the last section.

WHAT IT IS NOT. It is not a plain-language summary of anybody's reasoning. The `claude -p`
summaries the original handbook generator wove in are not derivable from the artefact, so they
cannot live in this render without breaking the property above. They are a human-run Claude
Code skill whose output lands by its own pull request, outside `composed/`
(hub `.claude/skills/handbook-summaries/`).

    handbook.py render <adopter-dir>              render from the working tree
    handbook.py render <adopter-dir> --ref <ref>  render from the tree at a git ref
    handbook.py --selfcheck                       the seam's own tests
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

import yaml

HEADER_PATH = "composed/HEADER.yaml"
EVIDENCE_PATH = "composed/evidence.json"
HANDBOOK_PATH = "composed/HANDBOOK.md"


class CannotRender(Exception):
    """The artefact does not carry what a handbook is made of. Never a default page."""


# --------------------------------------------------------------------------
# the seam
# --------------------------------------------------------------------------


def _money(amount: Any, currency: str) -> str:
    """One amount, one currency, rounded to the penny. Rounding is a deterministic function of
    the field, so the sentence stays derivable; the section header says the field it came from."""
    if not isinstance(amount, (int, float)):
        raise CannotRender(f"an amount that is not a number: {amount!r}")
    return f"{currency} {amount:,.2f}"


def _absent(absences: list[str], field: str, where: str, consequence: str) -> None:
    absences.append(f"`{field}` (in `{where}`) — {consequence}")


def _policy_objects(files: Mapping[str, str]) -> list[dict]:
    """Every Kubernetes object the artefact carries, in path order. The handbook describes what
    is INSTALLED, so it reads the rendered objects themselves and not a summary of them."""
    objects = []
    for path in sorted(files):
        if not path.startswith("composed/") or not path.endswith(".yaml"):
            continue
        if path == HEADER_PATH:
            continue
        for doc in yaml.safe_load_all(files[path]):
            if isinstance(doc, dict) and doc.get("kind"):
                objects.append({"path": path, "doc": doc})
    return objects


def _verbs(spec: Mapping[str, Any]) -> list[str]:
    """What an object DOES, counted off its own spec. Never a word about intent."""
    out = []
    for field, verb in (("mutations", "mutates"), ("validations", "refuses"),
                        ("generate", "generates"), ("evaluation", "evaluates")):
        got = spec.get(field)
        if isinstance(got, list) and got:
            out.append(f"{verb} ({len(got)})")
        elif got:
            out.append(verb)
    return out


def render(files: Mapping[str, str], evidence: Mapping[str, Any]) -> str:
    """The whole page, from the artefact and nothing else.

    `files` is the composed artefact as a mapping of repository-relative path to content --
    exactly what `composition.py`'s `compose()` returns as `rendered`, and exactly what a
    verifier reads back out of a tag. `evidence` is the composition's own evidence document.
    No clock, no environment, no path outside this mapping is read."""
    if evidence.get("outcome") != "composed":
        raise CannotRender(f"the composition's outcome is {evidence.get('outcome')!r}, "
                           "so there is no artefact to render a handbook from")
    if HEADER_PATH not in files:
        raise CannotRender(f"{HEADER_PATH} is not in the artefact")
    header = yaml.safe_load(files[HEADER_PATH]) or {}

    # The artefact carries its parent list TWICE -- on the rendered HEADER, which Flux applies,
    # and in the evidence document. This page states it once, so it must first observe that the
    # two agree. If they do not, one of the two served files is wrong and there is no honest
    # sentence to write about either.
    if (header.get("parents") or []) != (evidence.get("parents") or []):
        raise CannotRender(
            f"{HEADER_PATH} and {EVIDENCE_PATH} disagree about `parents`; the artefact "
            "contradicts itself, so no sentence about its publishers is derivable from it")

    absences: list[str] = []
    objects = _policy_objects(files)

    # Whose handbook this is. Taken from the objects' own composed-for label -- the field the
    # engine reads -- and cross-checked against the exposure's perspective where there is one.
    parties = sorted({
        o["doc"].get("metadata", {}).get("labels", {}).get("policy-as-versioned.dev/composed-for")
        for o in objects} - {None})
    exposure = header.get("exposure")
    if not parties and isinstance(exposure, dict) and exposure.get("perspective"):
        parties = [exposure["perspective"]]
    if len(parties) != 1:
        raise CannotRender(
            "the artefact's objects carry "
            f"{len(parties)} distinct `policy-as-versioned.dev/composed-for` values ({parties}); "
            "a handbook is one party's or it is nobody's")
    party = parties[0]

    L: list[str] = []
    a = L.append

    a(f"# {party}: what you are running under")
    a("")
    a(f"This page is a **compose-time render**. Every sentence below is derived from a field of "
      f"{party}'s own composed artefact — the files under `composed/` in this repository — and "
      f"from nothing else. It is produced by `platform/compose/handbook.py` during the same "
      f"composition that renders the artefact, lands in the same pull request, and is carried "
      f"under the same signed tag. `platform/compose/verify-fresh.sh` re-renders it from the "
      f"artefact as served at a tag and compares bytes, so this page cannot say something the "
      f"artefact does not.")
    a("")
    a("It is **not** a summary of anybody's reasoning, and nothing here was written by hand.")
    a("")

    # ---------------------------------------------------------------- 1. parents
    a("## 1. Whose rules these are")
    a("")
    a(f"Source: `{HEADER_PATH}` → `parents[]`. Each row is a signed, pinned publisher; the "
      "commit is the tree the composition actually read.")
    a("")
    parents = header.get("parents") or []
    if not parents:
        _absent(absences, "parents", HEADER_PATH,
                "this artefact names no publisher, so this page names none")
    else:
        a("| publisher | kind | feed name | version | commit |")
        a("| --- | --- | --- | --- | --- |")
        for p in parents:
            sha = p.get("sha")
            if not sha:
                _absent(absences, f"parents[{p.get('party')}].sha", HEADER_PATH,
                        "no commit is stated for this publisher")
            a(f"| {p.get('party')} | {p.get('kind')} | {p.get('name') or '—'} | "
              f"{p.get('version')} | `{sha or 'absent'}` |")
    a("")

    # ---------------------------------------------------------------- 2. what runs
    a("## 2. What is actually installed")
    a("")
    a(f"Source: the object files under `composed/`, and `{EVIDENCE_PATH}` → `members[]`. "
      "The verbs are counted off each object's own `spec`.")
    a("")
    a("| object | kind | policy version | does | inherited from | source path |")
    a("| --- | --- | --- | --- | --- | --- |")
    for o in objects:
        doc, meta = o["doc"], o["doc"].get("metadata", {}) or {}
        ann = meta.get("annotations", {}) or {}
        labels = meta.get("labels", {}) or {}
        version = labels.get("policy-as-versioned.dev/policy-version")
        verbs = _verbs(doc.get("spec") or {})
        if not verbs:
            _absent(absences, f"spec of {meta.get('name')}", o["path"],
                    "this object declares no mutation, validation or generation this page can read")
        a(f"| `{meta.get('name')}` | {doc.get('kind')} | {version or '— (not versioned)'} | "
          f"{', '.join(verbs) or 'nothing this page can read'} | "
          f"{ann.get('policy-as-versioned.dev/inherited-from') or '—'} | "
          f"`{ann.get('policy-as-versioned.dev/source-path') or o['path']}` |")
    a("")
    members = evidence.get("members") or []
    a(f"{len(objects)} object(s) in the artefact; `members[]` records {len(members)}: "
      + ", ".join(f"`{m.get('name')}`" for m in members) + ".")
    a("")

    # ---------------------------------------------------------------- 3. the cage
    a("## 3. The cage you land in")
    a("")
    a(f"Source: `{HEADER_PATH}` → `governed-namespaces`, `ungoverned-namespaces`, "
      f"`selection-policy`; `{EVIDENCE_PATH}` → `cages[]` and each `prices[].proposed_tier`.")
    a("")
    governed = header.get("governed-namespaces")
    if governed is None:
        _absent(absences, "governed-namespaces", HEADER_PATH,
                "this page cannot say which namespaces are governed")
    else:
        a(f"- Governed namespaces ({len(governed)}): "
          + (", ".join(f"`{n}`" for n in governed) or "none"))
    ungoverned = header.get("ungoverned-namespaces")
    if ungoverned is None:
        _absent(absences, "ungoverned-namespaces", HEADER_PATH,
                "this page cannot say which namespaces are outside the cage")
    else:
        a(f"- Ungoverned namespaces ({len(ungoverned)}): "
          + (", ".join(f"`{n}`" for n in ungoverned) or "none"))
    sel = header.get("selection-policy")
    if sel is None:
        _absent(absences, "selection-policy", HEADER_PATH,
                "no versioned rule is recorded as having chosen the tier, so this page names none")
    else:
        a(f"- The tier was chosen by selection-policy version **{sel}**.")
    tiers = sorted({p["proposed_tier"] for p in (evidence.get("prices") or [])
                    if p.get("proposed_tier")})
    if tiers:
        a(f"- Tier(s) the pricing proposes ({len(tiers)}): "
          + ", ".join(f"`{t}`" for t in tiers))
    cages = evidence.get("cages") or []
    a(f"- `cages[]` entries: {len(cages)}"
      + ("" if not cages else " — " + ", ".join(str(c.get("name") or c) for c in cages)))
    a("")

    # ---------------------------------------------------------------- 4. money
    a("## 4. What this costs, and to whom")
    a("")
    a(f"Source: `{EVIDENCE_PATH}` → `prices[]`, and `{HEADER_PATH}` → `exposure`. Amounts are "
      "rounded to two decimals from the field named in each row; every one carries the "
      "perspective it is booked under and the currency it is booked in.")
    a("")
    prices = evidence.get("prices") or []
    if not prices:
        _absent(absences, "prices", EVIDENCE_PATH, "nothing was priced, so this page states no cost")
    else:
        a("| priced by | kind | name | perspective | currency | amount | moved | proposed tier |")
        a("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for i, p in enumerate(prices):
            for required in ("perspective", "currency"):
                if not p.get(required):
                    raise CannotRender(
                        f"prices[{i}] ({p.get('source')}/{p.get('name')}) carries no "
                        f"`{required}`; a price without one is not a price this page will state")
            a(f"| {p.get('source')} | {p.get('kind')} | {p.get('name') or '—'} | "
              f"{p['perspective']} | {p['currency']} | {_money(p.get('amount'), p['currency'])} | "
              f"{'yes' if p.get('changed') else 'no'} | {p.get('proposed_tier') or '—'} |")
        a("")
        for i, p in enumerate(prices):
            if not p.get("lef_basis"):
                _absent(absences, f"prices[{i}].lef_basis", EVIDENCE_PATH,
                        f"the loss frequencies behind {p.get('source')}/{p.get('name')}'s amount "
                        "are not sourced in this artefact")
            else:
                a(f"- **{p.get('source')}/{p.get('name')}** — basis: {p['lef_basis']}")
        a("")
        # A hole is a priced absence, never a refusal (ADR-0020, ADR-0026). `holes[]` on a price
        # partitions that price; a singular `hole` is the whole of it. Both are money a reader can
        # act on, so both are named here rather than summed away.
        for p in prices:
            parts = p.get("holes") or []
            if parts:
                a(f"- **{p.get('source')}/{p.get('name')}** carries {len(parts)} priced hole(s) "
                  "inside that amount: "
                  + ", ".join(f"`{h.get('source')}/{h.get('id')}` "
                              f"{_money(h.get('amount'), p['currency'])}" for h in parts))
            whole = p.get("hole")
            if isinstance(whole, dict):
                a(f"- **{p.get('source')}/{p.get('name')}** is itself a priced hole: "
                  f"{whole.get('kind') or 'hole'} `{whole.get('id')}` — {whole.get('detail')}, "
                  f"priced at the whole entry ({_money(p.get('amount'), p['currency'])}).")
        a("")
    if not isinstance(exposure, dict):
        _absent(absences, "exposure", HEADER_PATH,
                "no aggregate exposure is published in this artefact; this page states no total, "
                "and does not state zero")
    else:
        for required in ("perspective", "currency"):
            if not exposure.get(required):
                raise CannotRender(f"`exposure` carries no `{required}`")
        a(f"**Exposure** — booked under perspective `{exposure['perspective']}` in "
          f"`{exposure['currency']}`.")
        a("")
        total = exposure.get("total")
        if total is None:
            _absent(absences, "exposure.total", HEADER_PATH, "no total is stated")
        else:
            a(f"- Total: {_money(total, exposure['currency'])}")
        att = exposure.get("attachment")
        if isinstance(att, dict) and att.get("currency") is not None:
            a(f"- Attachment: {_money(att.get('amount'), att['currency'])}")
        else:
            _absent(absences, "exposure.attachment", HEADER_PATH,
                    "no attachment point is stated")
        regimes = exposure.get("regimes") or []
        a(f"- Regimes ({len(regimes)}):")
        for r in regimes:
            a(f"  - `{r.get('name')}` from {r.get('source')} feed `{r.get('feed')}` "
              f"{r.get('version')}: {_money(r.get('amount'), exposure['currency'])}, "
              f"{len(r.get('controls') or [])} control(s) named")
        a("")

    # ---------------------------------------------------------------- 5. gaps
    a("## 5. What is not covered")
    a("")
    a(f"Source: `{HEADER_PATH}` → `baseline`, `selected-controls`, `holes`; "
      f"`{EVIDENCE_PATH}` → `holes[]`, `ungoverned[]`, `refusals[]`, `restatements[]`, `deltas[]`.")
    a("")
    baseline = header.get("baseline")
    if baseline is None:
        _absent(absences, "baseline", HEADER_PATH, "this page cannot name the control baseline")
    else:
        a(f"- Baseline: **{baseline}**")
    selected = header.get("selected-controls") or []
    holes = evidence.get("holes") or []
    by_status: dict[str, int] = {}
    for h in holes:
        by_status[str(h.get("status"))] = by_status.get(str(h.get("status")), 0) + 1
    a(f"- Controls selected: {len(selected)}")
    a(f"- Controls with no implementation behind them (`holes[]`): {len(holes)}"
      + (" — " + ", ".join(f"{k}: {v}" for k, v in sorted(by_status.items())) if by_status else ""))
    if selected:
        covered = len(selected) - len(holes)
        a(f"- So {covered} of {len(selected)} selected controls have an implementation in this "
          f"artefact. A hole is priced, never refused (ADR-0020).")
    for field in ("refusals", "restatements", "deltas", "ungoverned"):
        a(f"- `{field}[]`: {len(evidence.get(field) or [])}")
    a("")

    # ---------------------------------------------------------------- 6. limits
    a("## 6. What this handbook cannot say")
    a("")
    a(f"Source: `{EVIDENCE_PATH}` → `limits[]`, plus every field this render looked for in the "
      "artefact and did not find. A limit here is a number this page prints, not a sentence "
      "somebody wrote once and stopped checking.")
    a("")
    limits = evidence.get("limits") or []
    a(f"**{len(limits)} recorded limit(s) on the composition itself:**")
    a("")
    if limits:
        a("| limit | status | count | detail |")
        a("| --- | --- | --- | --- |")
        for lim in limits:
            a(f"| `{lim.get('name')}` | {lim.get('status')} | {lim.get('count')} | "
              f"{lim.get('detail')} |")
    else:
        a("(none)")
    a("")
    a(f"**{len(absences)} field(s) this render looked for in the artefact and did not find.** "
      "Where a field is absent this page states nothing in its place — no default prose, no "
      "zero (ADR-0020: a missing instrument refuses; it is never invented).")
    a("")
    if absences:
        for text in absences:
            a(f"- {text}")
    else:
        a("(none — every field this render reads was present)")
    a("")
    a("Two things this page can never tell you, by construction, and neither is a field of the "
      "artefact: whether the rules above are the **right** rules, and whether a human read and "
      "accepted the change that produced them. The first is the editorial review "
      "([ADR-0007](https://github.com/policy-as-versioned-flux/policy-as-versioned-flux/blob/main/docs/adr/0007-agent-assisted-editorial-governance.md)); "
      "the second is the pull request this artefact arrived in.")
    a("")

    # ---------------------------------------------------------------- footer
    a("---")
    a("")
    a(f"Counted from the artefact: {len(parents)} publisher(s), {len(objects)} installed "
      f"object(s), {len(members)} recorded member(s), {len(prices)} price(s), "
      f"{len(selected)} selected control(s), {len(holes)} hole(s), {len(limits)} recorded "
      f"limit(s), {len(absences)} named absence(s).")
    a("")
    return "\n".join(L)


# --------------------------------------------------------------------------
# selfcheck -- the seam's tests, written before the seam
# --------------------------------------------------------------------------


def _fixture() -> tuple[dict[str, str], dict[str, Any]]:
    """A small artefact of the same shape the real ones have."""
    header = {
        "policy-as-versioned.dev/composed": True,
        "parents": [
            {"party": "platform", "kind": "implementations", "version": "2.0.1", "sha": "aaaa111"},
            {"party": "feeds", "kind": "feed", "name": "threat-register", "version": "v2",
             "sha": "bbbb222"},
        ],
        "baseline": "MODERATE",
        "governed-namespaces": ["fixture"],
        "holes": ["ac-1", "ac-2"],
        "selected-controls": ["ac-1", "ac-2", "ac-3"],
        "ungoverned-namespaces": [],
        "selection-policy": "1.1.0",
        "exposure": {
            "perspective": "fixture", "currency": "GBP",
            "attachment": {"amount": 40000.0, "currency": "GBP"},
            "total": 1234.5,
            "regimes": [{"name": "uk-gdpr", "source": "ico", "feed": "penalty-schema",
                         "version": "v3", "amount": 1234.5, "controls": []}],
        },
    }
    policy = {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "MutatingPolicy",
        "metadata": {
            "name": "cage-tier-4-0-0",
            "labels": {"policy-as-versioned.dev/policy": "graded-enforcement",
                       "policy-as-versioned.dev/policy-version": "4.0.0",
                       "policy-as-versioned.dev/composed-for": "fixture"},
            "annotations": {"policy-as-versioned.dev/inherited-from": "platform@2.0.1",
                            "policy-as-versioned.dev/source-path": "distribution/policies/v4.0.0/cage-tier.yaml"},
        },
        "spec": {"mutations": [{"patchType": "ApplyConfiguration"}],
                 "matchConstraints": {"resourceRules": [{"resources": ["pods"],
                                                         "operations": ["CREATE", "UPDATE"]}]}},
    }
    files = {
        HEADER_PATH: yaml.safe_dump(header, sort_keys=False),
        "composed/policies/v4.0.0/cage-tier.yaml": yaml.safe_dump(policy, sort_keys=False),
        "composed/orphan-guard.yaml": yaml.safe_dump(
            {"apiVersion": "policies.kyverno.io/v1alpha1", "kind": "ValidatingPolicy",
             "metadata": {"name": "orphan-guard",
                          "annotations": {"policy-as-versioned.dev/inherited-from": "platform@2.0.1"}},
             "spec": {"validations": [{"message": "no"}]}}, sort_keys=False),
    }
    evidence = {
        "outcome": "composed",
        "party_artefact_errors": [],
        "parents": header["parents"],
        "members": [
            {"family": "graded-enforcement", "name": "cage-tier", "kind": "MutatingPolicy",
             "version": "4.0.0", "source_party": "platform", "source_sha": "aaaa111",
             "action": None},
            {"family": "platform-machinery", "name": "orphan-guard", "kind": "ValidatingPolicy",
             "version": None, "source_party": "platform", "source_sha": "aaaa111", "action": None},
        ],
        "refusals": [], "restatements": [], "cages": [],
        "holes": [{"control_id": "ac-1", "status": "recorded"},
                  {"control_id": "ac-2", "status": "new"}],
        "ungoverned": [],
        "prices": [
            {"source": "ico", "kind": "feed", "perspective": "fixture", "currency": "GBP",
             "amount": 1234.5, "name": "penalty-schema", "old_version": "v3", "new_version": "v3",
             "old_tier": "isolated", "proposed_tier": "isolated", "changed": False,
             "lef": [1, 2, 4], "lef_basis": "fixture basis", "proposed_as": "label",
             "holes": [{"source": "nist", "id": "pl-2", "weight": 0.3, "amount": 370.35}]},
            {"source": "insurer", "kind": "premium", "perspective": "fixture", "currency": "GBP",
             "amount": 500.0, "name": "quote-fixture", "changed": False,
             "hole": {"kind": "untagged-pin", "id": "insurer/quote-fixture@v1",
                      "detail": "no signed tag on the publisher's remote carries this pin"}},
        ],
        "deltas": [],
        "limits": [{"name": "two-publisher-conflict", "detail": "only one publisher is pinned",
                    "count": 1, "status": "open"}],
    }
    return files, evidence


def selfcheck() -> int:
    import copy
    import os
    import time

    files, evidence = _fixture()
    ok = 0

    def check(claim: str, cond: bool) -> None:
        nonlocal ok
        if not cond:
            print(f"FAIL: {claim}")
            raise SystemExit(1)
        ok += 1
        print(f"  ok   {claim}")

    # 1. it renders at all, and it renders text
    page = render(files, evidence)
    check("render() returns a non-empty page from an artefact", bool(page.strip()))

    # 2. PURE: identical inputs, identical bytes -- across cwd, environment and a second later.
    #    This is the property verify-fresh.sh grades at a tag; if it fails here it fails there.
    here = os.getcwd()
    try:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        saved = dict(os.environ)
        os.environ.update({"TZ": "Pacific/Kiritimati", "LANG": "C", "PAV_NOISE": "1"})
        time.sleep(0.01)
        again = render(copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence)))
    finally:
        os.chdir(here)
        os.environ.clear()
        os.environ.update(saved)
    check("render() is a pure function of its inputs (same bytes from another cwd, another "
          "environment, a moment later)", again == page)

    # 3. no clock reaches the page: today's date is not in it unless an input carried it
    today = time.strftime("%Y-%m-%d")
    check(f"the page carries no wall-clock date ({today} does not appear)", today not in page)

    # 4. it BITES: a changed field changes the page. A render nothing moves grades nothing.
    for what, mutate in (
        ("a parent's sha", lambda f, e: (
            e["parents"].__setitem__(0, dict(e["parents"][0], sha="cccc333")),
            f.__setitem__(HEADER_PATH, f[HEADER_PATH].replace("aaaa111", "cccc333", 1)))),
        ("a price amount", lambda f, e: e["prices"][0].__setitem__("amount", 99.0)),
        ("a limit's status", lambda f, e: e["limits"][0].__setitem__("status", "closed")),
        ("a policy object's name", lambda f, e: f.__setitem__(
            "composed/policies/v4.0.0/cage-tier.yaml",
            f["composed/policies/v4.0.0/cage-tier.yaml"].replace("cage-tier-4-0-0", "renamed"))),
        ("the baseline", lambda f, e: f.__setitem__(
            HEADER_PATH, f[HEADER_PATH].replace("MODERATE", "HIGH"))),
    ):
        f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
        mutate(f2, e2)
        check(f"changing {what} changes the render", render(f2, e2) != page)

    # 4b. the artefact states its parents twice; a disagreement between the two is refused,
    #     never quietly resolved in favour of one file
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    e2["parents"][0] = dict(e2["parents"][0], sha="dddd444")
    try:
        render(f2, e2)
        raised = False
    except CannotRender:
        raised = True
    check("HEADER.yaml and evidence.json disagreeing about `parents` is refused", raised)

    # 5. nothing is silently dropped: every parent, member, price and limit is named
    for parent in evidence["parents"]:
        check(f"parent {parent['party']}@{parent['version']} is named on the page",
              parent["party"] in page and str(parent["version"]) in page)
    for member in evidence["members"]:
        check(f"member {member['name']} is named on the page", member["name"] in page)
    for limit in evidence["limits"]:
        check(f"limit {limit['name']} is named on the page", limit["name"] in page)

    # 5b. a priced hole is named as money, both shapes (ADR-0020, ADR-0026)
    check("a hole that partitions a price is named with its control id and amount",
          "nist/pl-2" in page and "370.35" in page)
    check("a hole that IS the whole price entry is named as such",
          "untagged-pin" in page and "insurer/quote-fixture@v1" in page)

    # 6. every price carries a perspective and a currency, on the page and in the rule
    check("the price's perspective and currency are both on the page",
          "fixture" in page and "GBP" in page)
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    del e2["prices"][0]["currency"]
    try:
        render(f2, e2)
        raised = False
    except CannotRender:
        raised = True
    check("a price with no currency is refused, never rendered", raised)
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    del e2["prices"][0]["perspective"]
    try:
        render(f2, e2)
        raised = False
    except CannotRender:
        raised = True
    check("a price with no perspective is refused, never rendered", raised)

    # 7. ADR-0020: an absent field is NAMED, and never defaulted to prose or to zero
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    head = yaml.safe_load(f2[HEADER_PATH])
    del head["exposure"]
    del head["selection-policy"]
    f2[HEADER_PATH] = yaml.safe_dump(head, sort_keys=False)
    thin = render(f2, e2)
    check("an artefact with no exposure names `exposure` as absent",
          "exposure" in thin and "absent" in thin.lower())
    check("...and states no total for it", "0.00" not in thin.split("cannot say")[-1])
    check("an artefact with no selection-policy names `selection-policy` as absent",
          "selection-policy" in thin)
    import re as _re
    declared = _re.search(r"\*\*(\d+) field\(s\) this render looked for", thin)
    listed = [ln for ln in thin.splitlines() if ln.startswith("- `") and "` (in `" in ln]
    check("the absences are counted, and the count is the number listed",
          declared is not None and int(declared.group(1)) == len(listed) == 3)
    check("the footer repeats the same count",
          f"{len(listed)} named absence(s)" in thin)

    # 8. an artefact that is not one is refused, not papered over
    for what, f2, e2 in (
        ("no HEADER.yaml", {k: v for k, v in files.items() if k != HEADER_PATH}, evidence),
        ("a refused composition", files, dict(evidence, outcome="refused")),
    ):
        try:
            render(dict(f2), dict(e2))
            raised = False
        except CannotRender:
            raised = True
        check(f"an artefact with {what} is refused", raised)

    print(f"PASS: handbook render seam: {ok} checks -- pure, clock-free, biting, complete, "
          f"perspective-and-currency bearing, naming its absences, refusing a non-artefact")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def read_artefact(adopter_dir: Path, ref: str | None = None) -> tuple[dict[str, str], dict]:
    """The artefact as SERVED: every file under `composed/` at `ref` (or in the working tree),
    read through git plumbing so a tag's tree is read, never a working copy that happens to sit
    beside it."""
    files: dict[str, str] = {}
    if ref is None:
        root = Path(adopter_dir) / "composed"
        if not root.is_dir():
            raise CannotRender(f"{adopter_dir}/composed/ does not exist")
        paths = sorted(str(p.relative_to(adopter_dir)) for p in root.rglob("*")
                       if p.is_file())
        for rel in paths:
            files[rel] = (Path(adopter_dir) / rel).read_text()
    else:
        done = subprocess.run(["git", "-C", str(adopter_dir), "ls-tree", "-r", "--name-only",
                               ref, "composed/"], capture_output=True, text=True)
        if done.returncode != 0:
            raise CannotRender(f"git ls-tree {ref}:composed/ failed: {done.stderr.strip()}")
        for rel in sorted(p for p in done.stdout.split("\n") if p.strip()):
            got = subprocess.run(["git", "-C", str(adopter_dir), "show", f"{ref}:{rel}"],
                                 capture_output=True, text=True)
            if got.returncode != 0:
                raise CannotRender(f"git show {ref}:{rel} failed")
            files[rel] = got.stdout
    if EVIDENCE_PATH not in files:
        raise CannotRender(f"{EVIDENCE_PATH} is not in the artefact")
    evidence = json.loads(files[EVIDENCE_PATH])
    return files, evidence


def main(argv: list[str]) -> int:
    if "--selfcheck" in argv:
        return selfcheck()
    if len(argv) < 3 or argv[1] != "render":
        print(__doc__)
        return 2
    adopter_dir = Path(argv[2])
    ref = argv[argv.index("--ref") + 1] if "--ref" in argv else None
    try:
        files, evidence = read_artefact(adopter_dir, ref)
        sys.stdout.write(render(files, evidence))
    except CannotRender as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
