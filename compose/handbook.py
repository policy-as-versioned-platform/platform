#!/usr/bin/env python3
"""The handbook: a compose-time render of one adopter's composed artefact.

Eco-system ticket 34; ADR-0007's last-mile section, confirmed 2026-09-06 by ticket 80.

WHAT THIS IS. `composition.py` renders an adopter's composed policy set from its signed,
pinned parents. That artefact is machine-readable and no human reads it. This module turns
the artefact -- and nothing else -- into one Markdown page, `composed/HANDBOOK.md`. From the
platform version that carries this file on, `composition.py`'s `compose()` puts the page in
the same `rendered` mapping as `HEADER.yaml` and the policy objects, so it rides the same
pull request, the same `verify()` byte comparison and the same tag as the artefact.

WHAT THAT DOES NOT SAY. An adopter pinning an EARLIER platform tag runs a `composition.py`
that neither writes nor verifies this page. Its committed page is one a human rendered with
this tool, `composition.py verify` at that pin passes a hand-edited page unchallenged, and
`cut-release.yml` at that pin would sign it. Only the byte comparison below catches that,
and only where it is run: `verify-fresh.sh` beside this file, and the hub's
`verify/handbook/`, which prints how many adopters pin a tag that carries this renderer.
The page therefore says of itself only what a re-render can prove: which tool derives it
and from which files -- never which pull request it landed in or which tag carries it.

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
from typing import Any, Mapping

import yaml

HEADER_PATH = "composed/HEADER.yaml"
EVIDENCE_PATH = "composed/evidence.json"
HANDBOOK_PATH = "composed/HANDBOOK.md"
# Kinds of prices[] entry that propose no tier by construction: a premium is a committed cost
# (ADR-0020's ticket 69 note), a switching entry is a measured counterfactual (ticket 45), and a
# supersede entry is the surcharge on a line that already proposed its tier (ticket 84).
# Only these render `—` in the tier column; any other kind with no proposed_tier is named absent.
NO_TIER_KINDS = ("premium", "switching", "supersede")
# The one recorded limit this page does not state. composition.py writes it on every run:
# `closed` when every priced feed was read from its publisher's own pinned tree, `open` naming
# the publisher when the adopter's vendored copy stood in. That is a fact about which clones the
# RE-DERIVING RUN could read, not about the artefact -- and ticket 45's whole point is that the
# artefact re-renders byte-identically with the publisher absent, which composition.py verify()
# holds the page to. A page that stated this row could never do that. The exclusion is printed
# on the page by name (delegated, ADR-0025, 2026-09-08); the evidence document still records it.
RUN_ENVIRONMENT_LIMITS = ("publisher-clone-absent",)


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


def _listed(absences: list[str], container: Mapping[str, Any], field: str, where: str,
            consequence: str) -> list | None:
    """A list field of the artefact, or None with the absence NAMED. An empty list is a real
    zero and is rendered as one; a missing key is not a zero and is never rendered as one
    (ADR-0020; review F-07 found eight list fields defaulting to 0 through `or []`)."""
    got = container.get(field)
    if got is None:
        _absent(absences, field, where, consequence)
        return None
    if not isinstance(got, list):
        raise CannotRender(f"`{field}` in {where} is not a list: {got!r}")
    return got


def _hole_identity(whole: Mapping[str, Any]) -> str | None:
    """The identity a whole-entry hole carries: composition.py writes `source`, `name` and
    `version`; an older shape carried a single `id`. Neither is invented."""
    if whole.get("source") and whole.get("name"):
        return f"{whole['source']}/{whole['name']}@{whole.get('version')}"
    ident = whole.get("id")
    return str(ident) if ident else None


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
      f"from nothing else. It is rendered by `platform/compose/handbook.py` from those files and "
      f"nothing else. `platform/compose/verify-fresh.sh` and the hub's `verify/handbook/` "
      f"re-render it from the artefact as served at a ref and compare bytes; a page that said "
      f"something the artefact does not would not survive that comparison.")
    a("")
    a("It is **not** a summary of anybody's reasoning, and nothing here was written by hand.")
    a("")

    # ---------------------------------------------------------------- 1. parents
    a("## 1. Whose rules these are")
    a("")
    a(f"Source: `{HEADER_PATH}` → `parents[]`. Each row is a publisher this artefact records as "
      "a parent, at the commit the file records for it. Whether that commit is the tree the "
      "composition actually read is what `composition.py verify` proves (`cut-release.yml` runs "
      "it before a tag is cut; `shift-left.yml` recomposes and diffs); this page only restates "
      "the record.")
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
    members = _listed(absences, evidence, "members", EVIDENCE_PATH,
                      "this artefact records no member list, so this page counts none")
    if members is None:
        a(f"{len(objects)} object(s) in the artefact; `members[]` is absent from the evidence "
          "(named in section 6).")
    else:
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
    cages = _listed(absences, evidence, "cages", EVIDENCE_PATH,
                    "this artefact records no cage list, so this page counts none")
    if cages is not None:
        a(f"- `cages[]` entries: {len(cages)}"
          + ("" if not cages else " — " + ", ".join(str(c.get("name") or c) for c in cages)))
    a("")

    # ---------------------------------------------------------------- 4. money
    a("## 4. What this costs, and to whom")
    a("")
    a(f"Source: `{EVIDENCE_PATH}` → `prices[]`, and `{HEADER_PATH}` → `exposure`. Amounts are "
      "rounded to two decimals from the field named in each row; every one carries the "
      "perspective it is booked under and the currency it is booked in. An entry the composition "
      "could not price carries its reason instead of a number, and is named in section 6. "
      "In the *proposed tier* column, `—` means the entry's kind (`premium`, `switching`, "
      "`supersede`) "
      "proposes no tier by construction; a feed entry with no `proposed_tier` is named absent.")
    a("")
    prices = _listed(absences, evidence, "prices", EVIDENCE_PATH,
                     "nothing was priced, so this page states no cost")
    if prices is None:
        pass
    elif not prices:
        a("`prices[]` is present and empty: nothing was priced.")
        a("")
    else:
        a("| priced by | kind | name | perspective | currency | amount | moved | proposed tier |")
        a("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for i, p in enumerate(prices):
            for required in ("perspective", "currency"):
                if not p.get(required):
                    raise CannotRender(
                        f"prices[{i}] ({p.get('source')}/{p.get('name')}) carries no "
                        f"`{required}`; a price without one is not a price this page will state")
            # A could-not-look is a NAMED absence of a number, never a zero and never a refusal
            # of the whole page (ADR-0020): ticket 45's `switching` entries carry `amount: null`
            # with the publisher's own refusal in `could_not_look`. An entry with no amount and
            # no reason is not a price this page will state.
            if p.get("amount") is None:
                reason = p.get("could_not_look")
                if not reason:
                    raise CannotRender(
                        f"prices[{i}] ({p.get('source')}/{p.get('name')}) carries no `amount` "
                        "and no `could_not_look` reason; a price with neither is not a price")
                _absent(absences, f"prices[{i}].amount", EVIDENCE_PATH,
                        f"{p.get('source')}/{p.get('name')} could not be priced: {reason}")
                amount_cell = "could not look (section 6)"
            else:
                amount_cell = _money(p.get("amount"), p["currency"])
            if p.get("proposed_tier"):
                tier_cell = str(p["proposed_tier"])
            elif p.get("kind") in NO_TIER_KINDS:
                tier_cell = "—"
            else:
                _absent(absences, f"prices[{i}].proposed_tier", EVIDENCE_PATH,
                        f"{p.get('source')}/{p.get('name')} is a `{p.get('kind')}` entry that "
                        "proposes no tier")
                tier_cell = "absent"
            a(f"| {p.get('source')} | {p.get('kind')} | {p.get('name') or '—'} | "
              f"{p['perspective']} | {p['currency']} | {amount_cell} | "
              f"{'yes' if p.get('changed') else 'no'} | {tier_cell} |")
        a("")
        for i, p in enumerate(prices):
            if p.get("publisher_observation_scope"):
                a(f"- **{p.get('source')}/{p.get('name')}** — {p['publisher_observation_scope']}")
            if p.get("kind") == "supersede":
                a(f"- **{p.get('source')}/{p.get('name')} supersede** — "
                  f"clock starts {p.get('since')}; priced as of {p.get('as_of')}. "
                  + " ".join(p.get("limits") or []))
            if p.get("lef_basis"):
                a(f"- **{p.get('source')}/{p.get('name')}** — basis: {p['lef_basis']}")
            elif p.get("basis"):
                # a switching entry (ticket 45) is a measured difference, not an annualised
                # loss, and carries its own basis sentence
                a(f"- **{p.get('source')}/{p.get('name')}** ({p.get('kind')}) — basis: "
                  f"{p['basis']}")
            else:
                _absent(absences, f"prices[{i}].lef_basis", EVIDENCE_PATH,
                        f"the loss frequencies behind {p.get('source')}/{p.get('name')}'s amount "
                        "are not sourced in this artefact")
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
                ident = _hole_identity(whole)
                if ident is None:
                    _absent(absences, f"prices[{prices.index(p)}].hole identity", EVIDENCE_PATH,
                            "the hole names neither `source`/`name` nor `id`, so this page "
                            "cannot say which pin it is")
                a(f"- **{p.get('source')}/{p.get('name')}** is itself a priced hole: "
                  f"{whole.get('kind') or 'hole'} `{ident or 'absent'}` — {whole.get('detail')}, "
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
        # WHAT THE NUMBER IS, beside the number (eco-system ticket 79 item 10;
        # ticket 75 Q4). The composer writes it onto the section; this page
        # RENDERS what the artefact says and never a sentence of its own, so an
        # artefact composed before the statement existed is a named absence here
        # rather than a total this page qualifies on its own authority.
        ordinal = exposure.get("ordinal")
        total = exposure.get("total")
        if total is None:
            _absent(absences, "exposure.total", HEADER_PATH, "no total is stated")
        else:
            a(f"- Total: {_money(total, exposure['currency'])}")
            if ordinal:
                a(f"  - What this number is: {ordinal}.")
            else:
                _absent(absences, "exposure.ordinal", HEADER_PATH,
                        "the artefact states a total and does not say what the number is; "
                        "eco-system ticket 79 item 10 puts that sentence in the composer, so "
                        "an artefact composed before the next signed platform tag carries none")
        if exposure.get("ordinal_basis"):
            a(f"  - {exposure['ordinal_basis']}")
        agg = exposure.get("aggregate")
        if isinstance(agg, dict) and agg.get("selected_tier_residual_total") is not None:
            breach = agg.get("breaches_band")
            cnl = agg.get("could_not_look")
            # Review F3: no verdict where the two amounts are in two currencies
            # and no signed rate could be read. This page renders what the
            # artefact says; where the artefact declines to compare, so does it.
            verdict = ("BREACHES the declared aggregate" if breach
                       else "within the declared aggregate" if breach is False
                       else f"NO VERDICT -- {cnl}" if cnl
                       else "no aggregate tolerance is declared to compare it with")
            converted = agg.get("tolerance_in_reporting_currency")
            shown = _money(agg.get("tolerance"),
                            agg.get("tolerance_currency") or exposure["currency"])
            if converted is not None:
                shown += (f" (= {_money(converted, agg.get('currency', exposure['currency']))} "
                          f"through the signed FX feed)")
            a(f"- Aggregate of the selected-tier residuals: "
              f"{_money(agg['selected_tier_residual_total'], agg.get('currency', exposure['currency']))} "
              f"against a tolerance of {shown} -- {verdict}.")
            for ln in agg.get("lines") or []:
                a(f"  - `{ln.get('name')}` at tier `{ln.get('tier')}`: "
                  f"{_money(ln.get('residual'), agg.get('currency', exposure['currency']))}")
            if agg.get("not_tiered"):
                a(f"  - Not in this total, because they carry no selected tier: "
                  f"{', '.join(agg['not_tiered'])}")
        else:
            _absent(absences, "exposure.aggregate", HEADER_PATH,
                    "the artefact states a per-line total and no aggregate of the residuals the "
                    "selected tiers leave, so a breach of the one annual aggregate the appetite "
                    "declares is not visible (eco-system ticket 79 item 9)")
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

    floor_change = evidence.get("floor_change")
    if floor_change is not None:
        a("### Floor comparison")
        a("")
        a("Source: `composed/floor-change.json`; recorded floor inputs in "
          "`composed/HEADER.yaml` → `floor-comparison`.")
        a("")
        def floor_label(state):
            return ("unknown" if not state["known"] else
                    "absent" if state["value"] is None else str(state["value"]))
        a(f"Floor: **{floor_label(floor_change['before'])} → "
          f"{floor_label(floor_change['after'])}**. {floor_change['basis']}.")
        a("")
        if floor_change.get("could_not_look"):
            a(f"Could not look: {floor_change['could_not_look']}.")
            a("")
        def residual_money(value, currency):
            return "unknown" if value is None else _money(value, currency)
        for line in floor_change["lines"]:
            a(f"- {line['source']}/{line.get('name') or line['kind']}: "
              f"{line['before_tier'] or 'unknown'} → {line['after_tier'] or 'unknown'}; "
              f"retained residual {residual_money(line['before_residual'], line['currency'])} → "
              f"{residual_money(line['after_residual'], line['currency'])}; "
              f"delta {residual_money(line['residual_delta'], line['currency'])}.")
        a("")
        a(f"Instrument: `{floor_change['residual_basis']}`. {floor_change['limit']}.")
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
    selected = _listed(absences, header, "selected-controls", HEADER_PATH,
                       "this artefact records no selected control set, so this page counts none")
    holes = _listed(absences, evidence, "holes", EVIDENCE_PATH,
                    "this artefact records no hole list, so this page counts none")
    if selected is not None:
        a(f"- Controls selected: {len(selected)}")
    if holes is not None:
        by_status: dict[str, int] = {}
        for h in holes:
            by_status[str(h.get("status"))] = by_status.get(str(h.get("status")), 0) + 1
        a(f"- Controls with no implementation behind them (`holes[]`): {len(holes)}"
          + (" — " + ", ".join(f"{k}: {v}" for k, v in sorted(by_status.items()))
             if by_status else ""))
    if selected and holes is not None:
        covered = len(selected) - len(holes)
        a(f"- So {covered} of {len(selected)} selected controls have an implementation in this "
          f"artefact. A hole is priced, never refused (ADR-0020).")
    for field in ("refusals", "restatements", "deltas", "ungoverned"):
        got = _listed(absences, evidence, field, EVIDENCE_PATH,
                      f"this artefact records no `{field}` list, so this page counts none")
        if got is not None:
            a(f"- `{field}[]`: {len(got)}")
    a("")

    # ---------------------------------------------------------------- 6. limits
    a("## 6. What this handbook cannot say")
    a("")
    a(f"Source: `{EVIDENCE_PATH}` → `limits[]`, plus every field this render looked for in the "
      "artefact and did not find. A limit here is a number this page prints, not a sentence "
      "somebody wrote once and stopped checking.")
    a("")
    limits = _listed(absences, evidence, "limits", EVIDENCE_PATH,
                     "this artefact records no limit list, so this page counts none")
    if limits is not None:
        limits = [lim for lim in limits if lim.get("name") not in RUN_ENVIRONMENT_LIMITS]
    if limits is None:
        a("**`limits[]` is absent from the evidence** (named below); this page counts no limits.")
    else:
        a(f"**{len(limits)} recorded limit(s) on the composition itself** (not counting "
          f"{', '.join(f'`{n}`' for n in RUN_ENVIRONMENT_LIMITS)}, see below):")
    a("")
    if limits is None:
        pass
    elif limits:
        a("| limit | status | count | detail |")
        a("| --- | --- | --- | --- |")
        for lim in limits:
            a(f"| `{lim.get('name')}` | {lim.get('status')} | {lim.get('count')} | "
              f"{lim.get('detail')} |")
    else:
        a("(none)")
    a("")
    a(f"One recorded limit is deliberately not stated above: "
      f"{', '.join(f'`{n}`' for n in RUN_ENVIRONMENT_LIMITS)} records which publisher clones "
      "the run that re-derived this artefact could read, which is a fact about that run and not "
      "about the artefact; a page that stated it could not re-render byte-identically with a "
      "publisher absent, and re-rendering with a publisher absent is what `composition.py verify` "
      "holds this page to (ticket 45). `composed/evidence.json` records it in full.")
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
    def _n(got: list | None) -> str:
        return "absent" if got is None else str(len(got))
    a(f"Counted from the artefact: {len(parents)} publisher(s), {len(objects)} installed "
      f"object(s), {_n(members)} recorded member(s), {_n(prices)} price(s), "
      f"{_n(selected)} selected control(s), {_n(holes)} hole(s), {_n(limits)} recorded "
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
             "hole": {"kind": "untagged-pin", "source": "insurer", "name": "quote-fixture",
                      "version": "v1", "status": "new", "amount": 500.0,
                      "perspective": "fixture", "currency": "GBP",
                      "priced_by": "insurer quote-fixture@v1: the premium the pin books",
                      "detail": "no signed tag on the publisher's remote carries this pin"}},
            {"source": "ico", "kind": "switching", "perspective": "fixture", "currency": "GBP",
             "amount": 1234.5, "name": "penalty-schema", "basis": "fixture switching basis",
             "could_not_look": None, "alternates": [], "sized": True},
            {"source": "feeds", "kind": "switching", "perspective": "fixture", "currency": "GBP",
             "amount": None, "name": "threat-register", "basis": "fixture switching basis",
             "could_not_look": "missing instrument: twin/forward-intel/v1/feed.json has no lef",
             "alternates": [], "sized": True},
        ],
        "deltas": [],
        "limits": [{"name": "two-publisher-conflict", "detail": "only one publisher is pinned",
                    "count": 1, "status": "open"},
                   {"name": "publisher-clone-absent", "count": 0, "checked": 2,
                    "status": "closed",
                    "detail": "every priced feed was read from its publisher's own pinned tree"}],
    }
    return files, evidence


def selfcheck() -> int:
    import copy
    import os
    import sys
    import time
    from pathlib import Path

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
    # 2b. ...and from a SEPARATE PROCESS with the environment emptied, a random hash seed and a
    #     fresh cwd: an in-process re-render shares HOME, the hostname, every module-level cache
    #     and the interpreter's own hash seed with the first, so it cannot see a renderer that
    #     reads any of them (review F-06). The subprocess is `handbook.py render <dir>` over the
    #     fixture written to disk, which is also the CLI path verify-fresh.sh runs.
    import random
    import subprocess as _sp
    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        root = Path(td) / "adopter"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text)
        (root / EVIDENCE_PATH).write_text(json.dumps(evidence))
        cwd = Path(td) / "elsewhere"
        cwd.mkdir()
        run = _sp.run([sys.executable, os.path.abspath(__file__), "render", str(root)],
                      env={"PYTHONHASHSEED": str(random.randint(1, 2**31)), "LC_ALL": "C"},
                      cwd=str(cwd), capture_output=True, text=True)
    check("render() gives the same bytes from a separate process under an emptied environment, "
          "a random PYTHONHASHSEED and a fresh cwd",
          run.returncode == 0 and run.stdout == page)

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
    check("a hole that IS the whole price entry is named by its own source/name@version",
          "untagged-pin `insurer/quote-fixture@v1`" in page)
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    for k in ("source", "name", "version"):
        del e2["prices"][1]["hole"][k]
    nameless = render(f2, e2)
    check("a whole-entry hole with neither source/name nor id is named as an absence, never "
          "printed as `None`", "`None`" not in nameless and "hole identity" in nameless
          and "`absent`" in nameless)

    # 5c. a price the composition could not compute is NAMED, never a number and never a
    #     refusal of the page; one with no amount and no reason is refused (ticket 45 shape)
    check("a could-not-look price renders its reason in section 6 and no amount",
          "could not look (section 6)" in page
          and "`prices[3].amount` (in `composed/evidence.json`) — feeds/threat-register could "
              "not be priced: missing instrument" in page)
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    e2["prices"][3]["could_not_look"] = None
    try:
        render(f2, e2)
        raised = False
    except CannotRender:
        raised = True
    check("a price with no amount and no could_not_look reason is refused", raised)
    check("a premium or switching entry renders `—` for the tier it never proposes, and a feed "
          "entry with none is named absent",
          "| insurer | premium | quote-fixture | fixture | GBP | GBP 500.00 | no | — |" in page
          and "prices[1].proposed_tier" not in page)
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    del e2["prices"][0]["proposed_tier"]
    tierless = render(f2, e2)
    check("...a feed entry with no proposed_tier is named absent, not dashed",
          "`prices[0].proposed_tier` (in `composed/evidence.json`)" in tierless
          and "| GBP 1,234.50 | no | absent |" in tierless)

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

    def _absences(text):
        """The field names an absence list actually carries, in the order it carries them."""
        return [ln.split("`")[1] for ln in text.splitlines()
                if ln.startswith("- `") and "` (in `" in ln]

    listed = _absences(thin)
    standing = _absences(page)
    # Deleting `exposure` and `selection-policy` from the header does two things, and the
    # expectation is derived from both rather than from a constant. It NAMES those two. And it
    # withdraws every absence that was a field UNDER exposure -- `exposure.ordinal` and
    # `exposure.aggregate` are not fields this render looked for once their parent is gone, and
    # naming a child of an absent parent would state the artefact is missing something it was
    # never asked for. A hard-coded `standing + 2` said the first half and assumed the second
    # was empty; ticket 79 added two absences under `exposure` and the arithmetic went red for a
    # render that was behaving correctly. Compare the names, not the count.
    expected = sorted(set(n for n in standing if not n.startswith("exposure."))
                      | {"exposure", "selection-policy"})
    check("the absences are counted, and the count is the number listed",
          declared is not None and int(declared.group(1)) == len(listed)
          and sorted(listed) == expected)
    # Both lists above come out of the same render, so a field NAMED WRONG IN BOTH is invisible
    # to that comparison -- measured: renaming `prices[1].lef_basis` to `prices[8].lef_basis`
    # moved both lists together and the check stayed green. The fixture's own absences are
    # therefore stated here by name. Adding one to the render is then a deliberate two-place
    # edit, which is what ticket 79's two new `exposure.*` absences were not.
    check("the fixture page names exactly the absences this file states it names",
          sorted(standing) == sorted([
              "exposure.aggregate",
              "exposure.ordinal",
              "prices[1].lef_basis",
              "prices[3].amount",
          ]))
    check("the footer repeats the same count",
          f"{len(listed)} named absence(s)" in thin)

    # 7a. the one limit the page does not state is a fact about the re-deriving run, so the page
    #     is byte-identical whether that run had the publisher's clone or not (ticket 45)
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    e2["limits"][1] = {"name": "publisher-clone-absent", "count": 1, "checked": 2,
                       "status": "open", "detail": "priced from the adopter's own vendored copy "
                       "because the publisher's clone was not there to read: ico"}
    check("the publisher-clone-absent limit moving from closed to open leaves the page "
          "byte-identical, and the page names the exclusion",
          render(f2, e2) == page and "publisher-clone-absent" in page
          and "| `publisher-clone-absent` |" not in page
          and "**1 recorded limit(s) on the composition itself**" in page)
    check("the limit named `two-publisher-conflict` is still stated",
          "| `two-publisher-conflict` | open | 1 |" in page)

    # 7b. review F-07: an absent LIST field is named, never rendered as 0. An EMPTY list is a
    #     real zero and stays one -- the fixture's own empty `refusals` prints `refusals[]`: 0.
    check("an empty list present in the artefact renders as a real zero",
          "- `refusals[]`: 0" in page and "- `cages[]` entries: 0" in page)
    zero_forms = {
        "members": "records 0", "holes": "(`holes[]`): 0", "limits": "**0 recorded limit(s)",
        "cages": "`cages[]` entries: 0", "refusals": "- `refusals[]`: 0",
        "restatements": "- `restatements[]`: 0", "deltas": "- `deltas[]`: 0",
        "ungoverned": "- `ungoverned[]`: 0",
    }
    for field, zero in zero_forms.items():
        f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
        del e2[field]
        gone = render(f2, e2)
        check(f"evidence with no `{field}` names it absent and prints no `{zero}`",
              f"`{field}` (in `{EVIDENCE_PATH}`)" in gone and zero not in gone)
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    head = yaml.safe_load(f2[HEADER_PATH])
    del head["selected-controls"]
    f2[HEADER_PATH] = yaml.safe_dump(head, sort_keys=False)
    gone = render(f2, e2)
    check("a header with no `selected-controls` names it absent and prints no `Controls "
          "selected: 0`", f"`selected-controls` (in `{HEADER_PATH}`)" in gone
          and "Controls selected: 0" not in gone and "absent selected control(s)" in gone)
    f2, e2 = copy.deepcopy(dict(files)), copy.deepcopy(dict(evidence))
    e2["members"] = "seven"
    try:
        render(f2, e2)
        raised = False
    except CannotRender:
        raised = True
    check("a list field that is not a list is refused, not counted", raised)

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

    print(f"PASS: handbook render seam: {ok} checks -- pure in-process and in a separate "
          f"emptied-environment process, clock-free, biting, complete, perspective-and-currency "
          f"bearing, naming every absent field (lists included) rather than printing a zero, "
          f"refusing a non-artefact")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def read_artefact(adopter_dir: str, ref: str | None = None) -> tuple[dict[str, str], dict]:
    """The artefact as SERVED: every file under `composed/` at `ref` (or in the working tree),
    read through git plumbing so a tag's tree is read, never a working copy that happens to sit
    beside it."""
    import subprocess
    from pathlib import Path
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
    import sys
    if "--selfcheck" in argv:
        return selfcheck()
    if len(argv) < 3 or argv[1] != "render":
        print(__doc__)
        return 2
    adopter_dir = argv[2]
    ref = argv[argv.index("--ref") + 1] if "--ref" in argv else None
    try:
        files, evidence = read_artefact(adopter_dir, ref)
        sys.stdout.write(render(files, evidence))
    except CannotRender as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv))
