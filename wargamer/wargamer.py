#!/usr/bin/env python3
"""wargamer.py — the governance-agent evolved into a war-gaming policy-PR proposer.

The loop-closer (spec stories 28-33). It:

  1. COLLECTS the signed feeds -- the platform reactive feeds (threat register /
     CVE / EOL via ../feeds/to_fair_scenario.py) plus its own war-game scenario
     library (human/device attack paths + the forward ransomware/PQ/Wardley
     class in scenarios/human-device.json). Regulator feeds (nist OSCAL, ico
     penalties) are pinned upstream deps already wired into ../tcor; the
     war-gamer references their pinned versions as evidence, it does not re-price
     them here.

  2. WAR-GAMES current controls against that intelligence:
       * enforcement controls -- the £-implied Audit/Deny (../risk/enforce.py)
         at the CURRENT feed vs the action deployed at the BASELINE feed; a
         changed verdict is proportionality drift.
       * human/device + ransomware/PQ risks -- the cheapest of the four
         risk-financing moves (../tcor/tcor.py crossover) vs the deployed move;
         a changed move is drift (a control gone over-priced, or a stale blunt
         deny a cage/transfer now beats).

  3. On drift, PROPOSES a signed policy PR -- and NEVER DISPOSES. `propose()`
     returns a proposal that is opened, never merged, and carries the version
     cross-check gate (../shift-left/ci-check.py). This module exposes no merge
     capability by construction: a human + the PR gate dispose. Every proposal
     carries the war-gamer's own attestable identity (gitsign keyless -> Rekor,
     stamped at commit time by propose-policy-pr.sh, not here).

Pure/offline. Reuses fair.py, enforce.py, tcor.py, to_fair_scenario.py unchanged.

Usage:
    wargamer.py wargame  [--baseline <feed>] [--current <feed>]   # the drift report
    wargamer.py propose  [--baseline <feed>] [--current <feed>]   # the PR proposals (never merged)
    wargamer.py selfcheck                                         # the feed->PR seam asserts
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PLATFORM = os.path.join(HERE, "..")
for _d in ("fair", "risk", "tcor", "graded"):
    sys.path.insert(0, os.path.join(PLATFORM, _d))
import fair      # noqa: E402  the £ maths
import enforce   # noqa: E402  the appetite band + Audit/Deny verdict
import tcor      # noqa: E402  the four-move crossover


def _load_by_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ../feeds/to_fair_scenario.py: the feed -> scenario converter, reused unmodified.
feeds = _load_by_path("platform_feeds", os.path.join(PLATFORM, "feeds", "to_fair_scenario.py"))

BASELINE_FEED = os.path.join(PLATFORM, "feeds", "threat-register", "v1", "register.json")
# The current feed defaults to the war-gamer's signed drift fixture: a driftwood
# skimmer-campaign LEF uptick that pushes the cart-PII control past driftwood's band.
CURRENT_FEED = os.path.join(HERE, "fixtures", "threat-register", "v3", "register.json")
LIBRARY = os.path.join(HERE, "scenarios", "human-device.json")

# The deployed enforcement control the war-gamer stress-tests the feeds against.
# require-nonroot ships Audit at v2.0.0 (distribution/policies/v2.0.0); its cart-PII
# £ scenario is the threat-register's per-institution lm band (THREAT_LM_GBP), so
# threat_scenario(feed, org) IS the control's war-game scenario -- feed LEF x control LM.
CONTROL = {
    "policy": "require-nonroot",
    "version": "2.0.0",
    "policy_file": "distribution/policies/v2.0.0/require-nonroot.yaml",
}

GATE = "shift-left version cross-check (../shift-left/ci-check.py, target +/-1 window)"


# --- collect ------------------------------------------------------------------
def collect(baseline_feed=BASELINE_FEED, current_feed=CURRENT_FEED, library=LIBRARY):
    """Gather the intelligence the war-gamer reasons over: the baseline + current
    threat feed (per institution) and the war-game scenario library."""
    with open(baseline_feed) as fh:
        base = json.load(fh)
    with open(current_feed) as fh:
        cur = json.load(fh)
    with open(library) as fh:
        lib = json.load(fh)
    return {"baseline": base, "current": cur, "library": lib,
            "baseline_feed": baseline_feed, "current_feed": current_feed}


# --- war-game -----------------------------------------------------------------
def wargame_enforcement(intel):
    """Per institution: the deployed action (verdict at the baseline feed) vs the
    £-implied action at the current feed. A changed verdict is proportionality drift."""
    base, cur = intel["baseline"], intel["current"]
    rows = []
    for org in base["institutions"]:
        deployed = enforce.decide(
            feeds.threat_scenario(base, org), org, enforce.tolerance_for(org))
        implied = enforce.decide(
            feeds.threat_scenario(cur, org), org, enforce.tolerance_for(org))
        drift = deployed["verdict"] != implied["verdict"]
        rows.append({
            "kind": "enforcement",
            "org": org,
            "control": f"{CONTROL['policy']}@{CONTROL['version']}",
            "policy_file": CONTROL["policy_file"],
            "deployed": deployed["verdict"],
            "implied": implied["verdict"],
            "risk_bought_deployed": deployed["risk_bought"],
            "risk_bought_current": implied["risk_bought"],
            "tolerance": deployed["tolerance"],
            "drift": drift,
            "evidence": {
                "baseline_feed": os.path.relpath(intel["baseline_feed"], HERE),
                "current_feed": os.path.relpath(intel["current_feed"], HERE),
                "feed_version": cur.get("feed_version"),
            },
        })
    return rows


def wargame_scenarios(intel):
    """Human/device + ransomware/PQ: the cheapest of the four risk-financing moves
    (tcor crossover) vs the deployed move. A changed move is drift."""
    lib = intel["library"]
    org = lib.get("org", "driftwood")
    tol = enforce.tolerance_for(org)
    rows = []
    for risk in lib["risks"]:
        chosen = tcor.crossover(risk, tol)["chosen"]
        deployed = risk.get("deployed_move", chosen)
        rows.append({
            "kind": "scenario",
            "org": org,
            "control": risk["id"],
            "author": risk.get("author"),
            "deployed": deployed,
            "implied": chosen,
            "drift": deployed != chosen,
            "evidence": {"scenario_library": os.path.relpath(LIBRARY, HERE),
                         "risk": risk["id"], "author": risk.get("author")},
        })
    return rows


def wargame(intel=None):
    intel = intel or collect()
    return wargame_enforcement(intel) + wargame_scenarios(intel)


# --- the party's one tier (ticket 78; ADR-0022) --------------------------------
# Loosest first. `infra` is absent from LADDER because nothing SELECTS it: a
# price never proposes it and a floor never declares it -- the same ladder
# driftwood/selection-policy/selection_policy.py publishes.
LADDER = ("baseline", "restricted", "quarantine", "isolated")
FAIL_CLOSED = LADDER[-1]     # a governed Namespace with no tier renders isolated

# ADR-0022's fifth rung, which a Namespace may nonetheless DECLARE. Only a
# platform-role party may declare it; a declaration from any other party renders
# `isolated`. Both readings answer the two questions this fold asks the same way
# -- `infra` is tighter than every rung on LADDER, and `isolated` is LADDER's own
# tightest rung -- so no proposal can tighten an `infra` declaration and no priced
# line is looser than one, whoever wrote it. That is why this needs no role
# lookup, and why grading `infra` as a missing instrument (which is what happened
# before 2026-09-04) was wrong: it is a legitimate declaration, not an unreadable
# one (ADR-0022, "only a party with the `platform` role may declare a Namespace at
# `infra`").
INFRA = "infra"
DECLARABLE = LADDER + (INFRA,)


def rank(tier):
    """How TIGHT `tier` is, as an index: higher is tighter. Defined over every
    tier a Namespace may declare, which is one rung longer than what a price may
    select. Raises ValueError for anything else -- tighter or looser cannot be
    told, and guessing is a loosening nobody signed (ADR-0020)."""
    if tier not in DECLARABLE:
        raise ValueError(f"tier {tier!r} is not one a Namespace may declare "
                         f"{list(DECLARABLE)} -- tighter or looser cannot be told")
    return DECLARABLE.index(tier)


def _line_key(price, taken):
    """A display name for one priced line that no OTHER priced line can take.

    ADR-0019 made `feed` one kind carrying a `name`, composition's `_parent_key`
    identifies a feed by that name, and party/schema.json constrains nothing about
    `inherits[]` being unique per source -- so `source/kind` alone is not an
    identity. `source/kind/name` is, for everything the estate composes today; the
    `#n` suffix is the belt and braces for a document that repeats even that, so
    that a line can never be silently dropped from the display of what was folded.
    """
    base = f"{price.get('source')}/{price.get('kind')}"
    name = price.get("name")
    if name is not None:
        base = f"{base}/{name}"
    if base not in taken:
        return base
    n = 2
    while f"{base}#{n}" in taken:
        n += 1
    return f"{base}#{n}"


def select_party_tier(prices, current=None, floor=None):
    """One tier for the PARTY from every priced line, and whether writing it
    would tighten the declaration.

    A price line is one regime's view; a Namespace carries one tier for every
    pod in it, so the declaration cannot be looser than its worst-priced
    regime. The rule (the stated interim, pending PE-05 / ticket 75 Q4 on a
    summed residual): the strictest `proposed_tier` across `prices[]`, clamped
    up to the party's declared `overlay.floor`, and never looser than what the
    governed Namespace declares today. driftwood's published selection-policy
    package records the same rule as `select_party()`; the hub's
    verify/tier-binding/ check folds every shape on the ladder through both and
    refuses a disagreement (the two-implementations guard, ADR-0021).

    `held` is True when the fold does not tighten the current declaration --
    the proposer then writes nothing. A missing declaration is `isolated` by
    ADR-0022, and the one write that neither tightens nor loosens it is the
    explicit `isolated` line, which is allowed. A loosening is a different
    question this proposer does not yet ask: it needs the party's aggregate
    residual and a PR body that says so, and neither exists yet.

    A Namespace declared `infra` (ADR-0022's platform-role rung) is tighter than
    every rung a price can select, so the fold is always held against it. A price
    or a floor naming `infra` still raises: nothing SELECTS that rung.

    Raises ValueError for a tier a price may not select or a Namespace may not
    declare (a missing instrument: the proposer cannot tell tighter from looser
    and must not guess).

    The fold runs over the priced tiers THEMSELVES, never over `lines`, which is
    a display of them. Until 2026-09-04 `lines` was keyed `source/kind` and the
    fold read its values, so two priced lines from one publisher of one kind --
    which ADR-0019 admits, `feed` being one kind carrying a `name`, and which
    party/schema.json puts no uniqueness constraint on -- collapsed onto one key
    and the LAST one won instead of the strictest. A stricter line vanished, and
    tier_binding.bind() then computed `required` off the collapsed set and graded
    a looser Namespace `bound`: a false PASS on this ticket's central property."""
    tiers = []
    lines = {}
    for price in prices:
        tier = price.get("proposed_tier")
        if tier is None:
            continue                       # an unpriced line (a premium) selects nothing
        if tier not in LADDER:
            raise ValueError(f"{price.get('source')}/{price.get('kind')} prices tier {tier!r}, "
                             f"which is not on the ladder {list(LADDER)}")
        tiers.append(tier)
        lines[_line_key(price, lines)] = tier
    if floor is not None and floor not in LADDER:
        raise ValueError(f"declared floor {floor!r} is not on the ladder {list(LADDER)}")
    if current is not None and current not in DECLARABLE:
        raise ValueError(f"the Namespace declares tier {current!r}, which is not one a Namespace "
                         f"may declare {list(DECLARABLE)} -- tighter or looser cannot be told")

    strictest = max(tiers, key=LADDER.index) if tiers else None
    tier, clamped = strictest, False
    if floor is not None and (tier is None or LADDER.index(floor) > LADDER.index(tier)):
        tier, clamped = floor, True
    effective = current if current is not None else FAIL_CLOSED
    if tier is None:
        held = True
        basis = "no line prices a tier, so there is nothing to declare"
    else:
        tightens = rank(tier) > rank(effective)
        explicit_default = current is None and tier == FAIL_CLOSED
        held = not (tightens or explicit_default)
        basis = (f"strictest priced line is {strictest!r} across {sorted(lines)}"
                 + (f", clamped up to the declared floor {floor!r}" if clamped else "")
                 + f"; the Namespace declares {current!r}"
                 + (f" (none: {FAIL_CLOSED} by default, ADR-0022)" if current is None else "")
                 + ("; held -- the proposer only tightens" if held else
                    f"; {tier!r} is tighter, so it is proposed"))
    return {"tier": tier, "strictest_line": strictest, "lines": lines, "floor": floor,
            "clamped_to_floor": clamped, "current": current, "effective_current": effective,
            "held": held, "basis": basis}


def wargame_cage_tier(prices, org, selection=None):
    """Ticket 16's `prices[]` -> cage-tier drift rows, in the SAME row shape
    wargame_enforcement() uses (kind/org/control/tolerance/risk_bought_current/
    drift) -- so proposer_bounds.confidence()/bound() gate a tier drift with no
    second formula. `tolerance` is the price before the parent bump,
    `risk_bought_current` is the price after: materiality is how far the
    exposure moved relative to what it was, the same shape a band-crossing is
    for an enforcement flip. Deliberately NOT folded into wargame() -- see
    tier_pr.py's own docstring for why a real adopter run must call this
    explicitly rather than pick up the war-gamer's demo fixture.

    `selection` is select_party_tier()'s answer for this party. A line still
    drifts on its own (that is the question the ledger keys on), but what a
    proposal WRITES is the party's tier, carried on every row (ticket 78)."""
    rows = []
    for price in prices:
        rows.append({
            "kind": "cage-tier",
            "org": org,
            "control": f"{price['source']}-{price['kind']}",
            "tolerance": price.get("old_price"),
            "risk_bought_current": price.get("new_price"),
            "drift": bool(price.get("changed")),
            "price": price,
            "selection": selection,
        })
    return rows


# --- propose (never dispose) --------------------------------------------------
def propose(row):
    """Turn a drift row into a proposal. Opened, never merged; carries the
    version cross-check gate + the war-gamer's gitsign identity.

    There is deliberately NO merge()/dispose() here -- the agent proposes, a human
    + the PR gate dispose. That absence IS the safety property (selfcheck asserts it)."""
    if not row["drift"]:
        return None
    if row["kind"] == "cage-tier":
        return _propose_tier(row)
    slug = f"{row['org']}-{row['control']}".replace("@", "-").replace(".", "-")
    return {
        "branch": f"wargamer/retune-{slug}",
        "title": f"[war-gamer] re-tune {row['control']} ({row['org']}): "
                 f"{row['deployed']} -> {row['implied']}",
        "actor": "wargamer-agent",
        # No `signed` field: a signature is a property of the commit, put there by
        # gitsign in the workflow that lands it and observed by `gitsign verify`
        # against the adopter's own identity regexp -- never a literal a proposal
        # document says about itself (ticket 76 item 6, ticket 78).
        "identity": "gitsign keyless (OIDC -> Fulcio) -> Rekor transparency log, "
                    "stamped by the landing workflow, not claimed here",
        "from_evidence": row["evidence"],
        "change": {
            "target": row.get("policy_file", row["control"]),
            "from": row["deployed"],
            "to": row["implied"],
        },
        "required_gate": GATE,
        "merged": False,              # propose-never-dispose: the agent never merges
        "auto_merge": False,
        "disposition": "OPEN -- awaiting human review + version cross-check gate",
    }


def _propose_tier(row):
    """A priced cage-tier drift (ticket 16's `prices[]`) becomes a proposal
    that tier_pr.py (ticket 17) lands as a real PR against the adopter's
    GOVERNED NAMESPACE declaration -- this only shapes what gets landed.

    Always a pull request. ADR-0022 retired ADR-0015's issue branch: the
    bottom rung is `isolated`, a real running cage, so every tier on the
    ladder travels as a declaration and nothing is ever refused. `deny` is
    not a tier any more, and composition emits `proposed_as: "label"` for
    every entry."""
    price = row["price"]
    slug = f"tier-{row['org']}-{row['kind']}-{price['source']}-{price['kind']}".replace("@", "-").replace(".", "-")
    # What the proposal WRITES is the party's tier, never the line's own
    # (ticket 78): the strictest priced line, clamped to the floor, and only if
    # it tightens what the Namespace declares. The line's own move stays in
    # `price` for the body. Without a selection (a caller that has not read the
    # Namespace) the line's tier is all there is to say.
    selection = row.get("selection")
    if selection:
        change_to = selection["tier"]
        change_from = selection["current"] if selection["current"] is not None \
            else f"none ({FAIL_CLOSED} by default)"
    else:
        change_to, change_from = price.get("proposed_tier"), price.get("old_tier")
    return {
        "branch": f"wargamer/retune-{slug}",
        "title": f"[war-gamer] cage-tier re-tune ({row['org']}, {price['source']}/{price['kind']}): "
                 f"{change_from} -> {change_to}",
        "actor": "wargamer-agent",
        # No `signed` literal (see propose()): propose-tier.yml signs the commit
        # with gitsign and verifies it against the adopter's own regexp.
        "identity": "gitsign keyless (OIDC -> Fulcio) -> Rekor transparency log, "
                    "stamped by the landing workflow, not claimed here",
        "from_evidence": {"source": price["source"], "kind": price["kind"],
                           "old_version": price.get("old_version"), "new_version": price.get("new_version")},
        "change": {
            "label": "posture.acme.io/tier",
            "from": change_from,
            "to": change_to,
            "line_from": price.get("old_tier"),
            "line_to": price.get("proposed_tier"),
        },
        "party_selection": selection,
        # What moved the tier, for the PR body tier_pr.py writes: the price
        # itself, under its own perspective and currency (ADR-0021).
        "price": {
            "source": price["source"], "kind": price["kind"],
            "from": price.get("old_price"), "to": price.get("new_price"),
            "currency": price.get("currency"), "perspective": price.get("perspective"),
            "curve_hash": price.get("curve_hash"),
            "policy_version": price.get("policy_version"),
        },
        "proposal_kind": "pull_request",
        "required_gate": GATE,
        "merged": False,               # propose-never-dispose: the agent never merges
        "auto_merge": False,
        "disposition": "OPEN -- awaiting human review + version cross-check gate",
    }


def proposals(intel=None):
    return [p for p in (propose(r) for r in wargame(intel)) if p]


# --- selfcheck: the feed->PR seam ---------------------------------------------
def selfcheck():
    intel = collect()
    rows = wargame(intel)

    # 1. COLLECT: the signed feed-change fixture is in, and the library loaded.
    assert intel["current"]["feed_version"] == "v3", intel["current"].get("feed_version")
    assert len(intel["library"]["risks"]) >= 5, "war-game scenario library too small"
    authors = {r.get("author") for r in intel["library"]["risks"]}
    assert {"human-seed", "ai-generated"} <= authors, ("scenarios must be both "
                                                       "human-seed and AI-generated", authors)

    # 2. WAR-GAME both classes: enforcement drift AND a human/device path drift.
    enf = [r for r in rows if r["kind"] == "enforcement"]
    scn = [r for r in rows if r["kind"] == "scenario"]
    # driftwood's cart-PII control was proportionately Audit at v1; the v3 skimmer
    # uptick pushes its residual over the £40k band -> the £ now implies Deny.
    dw = next(r for r in enf if r["org"] == "driftwood")
    assert dw["deployed"] == "Audit", dw
    assert dw["implied"] == "Deny", dw
    assert dw["drift"] is True, dw
    assert dw["risk_bought_current"] > dw["tolerance"] >= dw["risk_bought_deployed"], dw
    # a feed bump that does NOT cross a band must NOT drift (ludlow unchanged in v3):
    lud = next(r for r in enf if r["org"] == "ludlow")
    assert lud["drift"] is False, ("unchanged institution must not drift", lud)
    # at least one human/device/ransomware path drifts (a stale move the £ re-prices):
    assert any(r["drift"] for r in scn), ("a war-gamed human/device scenario must "
                                          "surface drift", scn)

    # 2b. hyperscaler-region-concentration: tcor.py's `applicable` field narrows the
    #     move to what an org can actually do to a third party (you cannot fix, cage
    #     or deny a hyperscaler's control plane). Pin down BOTH sides of that: with
    #     `applicable`, transfer wins and matches deployed_move (no drift); strip
    #     `applicable` and the engine defaults costs.fix to 0 and nonsensically
    #     "fixes" the outage for ~£3,726 -- the exact regression research 05 named.
    hyper = next(r for r in scn if r["control"] == "hyperscaler-region-concentration")
    assert hyper["deployed"] == "transfer" and hyper["implied"] == "transfer", hyper
    assert hyper["drift"] is False, ("applicable must keep this risk from drifting", hyper)
    hyper_org = intel["library"].get("org", "driftwood")
    hyper_tol = enforce.tolerance_for(hyper_org)
    hyper_risk = next(r for r in intel["library"]["risks"]
                       if r["id"] == "hyperscaler-region-concentration")
    assert tcor.crossover(hyper_risk, hyper_tol)["chosen"] == "transfer", hyper_risk
    stripped = {k: v for k, v in hyper_risk.items() if k != "applicable"}
    broken = tcor.crossover(stripped, hyper_tol)
    assert broken["chosen"] == "fix", ("without `applicable` the engine must default "
                                       "to the nonsensical free fix", broken)
    assert abs(broken["line"]["tcor"] - 3726) < 1, ("the free-fix number must be the "
                                                    "~£3,726 the ticket names", broken)

    # 3. PROPOSE, NEVER DISPOSE.
    props = proposals(intel)
    assert props, "drift detected but no PR proposed"
    # a PR IS opened for the driftwood flip, and it flips Audit->Deny:
    dw_pr = next(p for p in props if p["change"]["from"] == "Audit"
                 and p["change"]["to"] == "Deny")
    assert dw_pr["change"]["target"].endswith("require-nonroot.yaml"), dw_pr
    for p in props:
        # never auto-merged:
        assert p["merged"] is False and p["auto_merge"] is False, p
        # carries the version cross-check gate:
        assert "cross-check" in p["required_gate"], p
        # names the identity mechanism, and CLAIMS no signature: `signed` is
        # not a field a proposal may carry -- the commit is signed by the
        # landing workflow and verified there (ticket 76 item 6, ticket 78).
        assert "signed" not in p, ("a proposal must not claim to be signed", p)
        assert "Rekor" in p["identity"], p
        # traces to the evidence it was proposed from:
        assert p["from_evidence"], p
    # the SAFETY property, structurally: the agent has no way to merge/dispose.
    assert not hasattr(sys.modules[__name__], "merge"), "war-gamer must expose no merge()"
    assert not hasattr(sys.modules[__name__], "dispose"), "war-gamer must expose no dispose()"

    # 4. THE PROPOSER CAN ONLY TIGHTEN (ticket 78; ADR-0022): the party's one
    #    tier is the strictest priced line, clamped to the floor, and never
    #    looser than the Namespace declares.
    def line(source, tier, changed=False):
        return {"source": source, "kind": "feed", "proposed_tier": tier, "changed": changed}

    driftwood_today = [line("feeds", "restricted", True), line("ico", "isolated"),
                       line("twin", "isolated"), {"source": "insurer", "kind": "premium",
                                                  "proposed_tier": None}]
    sel = select_party_tier(driftwood_today, current="isolated")
    assert sel["tier"] == "isolated" and sel["strictest_line"] == "isolated", sel
    assert sel["held"] is True, ("a per-line crossing on an isolated party writes nothing", sel)
    assert "insurer/premium" not in sel["lines"], ("an unpriced line selects nothing", sel)
    # TWO priced lines from ONE publisher of ONE kind, told apart only by ADR-0019's
    # `name`. Until 2026-09-04 the fold read the values of a dict keyed `source/kind`,
    # so these collapsed onto one key and the LAST one won: the stricter line vanished
    # and tier_binding.bind() graded a looser Namespace `bound` -- a false PASS on this
    # ticket's central property. The fold runs over the priced tiers themselves now.
    two_feeds = [{"source": "ico", "kind": "feed", "name": "penalty-schema",
                  "proposed_tier": "isolated"},
                 {"source": "ico", "kind": "feed", "name": "breach-register",
                  "proposed_tier": "baseline"}]
    sel = select_party_tier(two_feeds, current="baseline")
    assert sel["tier"] == "isolated" and sel["held"] is False, (
        "two named feeds from one publisher must fold to the STRICTEST, not the last", sel)
    assert sorted(sel["lines"]) == ["ico/feed/breach-register", "ico/feed/penalty-schema"], (
        "each priced line must survive into the display of what was folded", sel)
    assert select_party_tier(list(reversed(two_feeds)), current="baseline")["tier"] == "isolated", \
        "the fold cannot depend on the order the lines were composed in"
    # even a document that repeats source/kind/name drops no line from the display
    dupes = [dict(two_feeds[0]), dict(two_feeds[0], proposed_tier="baseline")]
    assert len(select_party_tier(dupes, current="baseline")["lines"]) == 2, "no line is dropped"
    # strictest line wins over the crossing line's own tier
    sel = select_party_tier([line("feeds", "restricted", True), line("ico", "quarantine")],
                            current="baseline")
    assert sel["tier"] == "quarantine" and sel["held"] is False, sel
    # the floor clamps up, never down
    assert select_party_tier([line("feeds", "restricted", True)], current="baseline",
                             floor="quarantine")["tier"] == "quarantine"
    assert select_party_tier([line("feeds", "restricted", True)], current="baseline",
                             floor="quarantine")["clamped_to_floor"] is True
    assert select_party_tier([line("feeds", "isolated", True)], current="baseline",
                             floor="restricted")["tier"] == "isolated"
    # equal is held: a write that does not tighten is not a write
    assert select_party_tier([line("feeds", "restricted", True)], current="restricted")["held"]
    # an undeclared tier is isolated by default; only the explicit isolated line may land
    assert select_party_tier([line("feeds", "restricted", True)], current=None)["held"] is True
    assert select_party_tier([line("feeds", "isolated", True)], current=None)["held"] is False
    # nothing priced: nothing to declare
    assert select_party_tier([{"source": "insurer", "kind": "premium", "proposed_tier": None}],
                             current="baseline")["held"] is True
    # ADR-0022's `infra` rung is a legitimate DECLARATION (only a platform-role party
    # may make it, and from anyone else it renders `isolated`) and it is tighter than
    # anything a price can select, so it is held, never refused as an unreadable tier.
    infra = select_party_tier([line("feeds", "isolated", True)], current="infra")
    assert infra["held"] is True and infra["tier"] == "isolated", infra
    assert rank("infra") > rank("isolated") > rank("baseline")
    # ...but nothing SELECTS infra: a price naming it, or a floor declaring it, is refused
    # off-ladder anything is a missing instrument, never a guess
    for bad in (lambda: select_party_tier([line("feeds", "paranoid", True)], current="baseline"),
                lambda: select_party_tier([line("feeds", "infra", True)], current="baseline"),
                lambda: select_party_tier([line("feeds", "isolated", True)], floor="infra"),
                lambda: select_party_tier([line("feeds", "isolated", True)], current="deny"),
                lambda: select_party_tier([line("feeds", "isolated", True)], floor="deny")):
        try:
            bad()
        except ValueError:
            pass
        else:
            raise AssertionError("an off-ladder tier was not refused")
    # the party tier is what a proposal writes; the line's own move is kept beside it
    tier_rows = wargame_cage_tier([line("feeds", "restricted", True), line("ico", "quarantine")],
                                  "driftwood", selection=sel)
    tier_prop = propose(tier_rows[0])
    assert tier_prop["change"]["to"] == "quarantine" and tier_prop["change"]["from"] == "baseline", tier_prop
    assert tier_prop["change"]["line_to"] == "restricted", tier_prop
    assert "signed" not in tier_prop, tier_prop

    print(
        "ok  collected v1->v3 signed feed + %d-scenario library (human-seed + AI); "
        "war-game: driftwood cart-PII £%.0f>£%.0f band -> Audit->Deny drift, ludlow steady; "
        "%d scenario-path drift(s); proposed %d PR(s) claiming no signature of their own, 0 merged, "
        "all carry the gate; the party tier is the strictest priced line, clamped to the floor, "
        "never looser than the Namespace declares (ticket 78)."
        % (len(intel["library"]["risks"]), dw["risk_bought_current"], dw["tolerance"],
           sum(1 for r in scn if r["drift"]), len(props))
    )


# --- CLI ----------------------------------------------------------------------
def _feed_args(p):
    p.add_argument("--baseline", default=BASELINE_FEED)
    p.add_argument("--current", default=CURRENT_FEED)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    pw = sub.add_parser("wargame", help="the drift report (enforcement + scenarios)")
    _feed_args(pw)

    pp = sub.add_parser("propose", help="the signed policy PR proposals (never merged)")
    _feed_args(pp)

    sub.add_parser("selfcheck", help="the feed->PR seam asserts (propose-never-dispose)")

    args = p.parse_args(argv)

    if args.cmd == "selfcheck":
        selfcheck()
        return
    intel = collect(args.baseline, args.current)
    if args.cmd == "wargame":
        print(json.dumps(wargame(intel), indent=2))
    elif args.cmd == "propose":
        print(json.dumps(proposals(intel), indent=2))


if __name__ == "__main__":
    main()
