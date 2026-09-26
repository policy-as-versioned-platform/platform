#!/usr/bin/env python3
"""cage.py — the graded enforcement envelope: tiers over dials, the £ picks the tier.

Nothing is ever denied. A behind-posture workload does not get a blunt
admit/deny — it keeps running, *caged by degree*, and the bottom rung is
`isolated`: a running cage with no ingress, no egress and first eviction
(ADR-0022). This module is the source of truth for:

  1. NAMED TIERS -> DIAL SETTINGS, deterministically (PSS-style presets over the
     independent dials Kyverno actually injects: cpu/mem limits, drop-ALL-caps,
     read-only-fs, an eviction PriorityClass, reach, a WAF sidecar). One table;
     the `cage-tier` MutatingPolicy mirrors it (verify-graded.sh cross-checks
     drift). The ladder is baseline < restricted < quarantine < isolated, plus
     `infra` — declared by a platform-role party on its own Namespaces, never
     selected by a price.

  2. THE £ SELECTS THE TIER. A cage is a *priced partial-reduce on a retained
     risk*: it collapses part of the behind-posture residual (R' > 0 still) at a
     booked run-cost (C_cage > 0). Given the workload's uncaged residual ALE and
     the org's appetite band, pick the LOOSEST tier whose caged residual still
     fits — else `isolated`, the bottom rung — then clamped UP to the adopter's
     own tighten-only `overlay.floor`. Same behind-posture workload -> baseline
     in loose-appetite driftwood, quarantine in strict-appetite ludlow.

  3. TCoR EMITTED. Total Cost of Risk of the chosen cage = caged residual +
     cost-of-controls (the cage's run-cost). Booked as a risk line, same shape
     the nist OSCAL risk / ico penalty consumers read.

  4. OSCAL RISK EMITTED (ticket 05). A workload that fails a conditional
     policy's condition C used to get a ledger entry and a PolicyException —
     banned outright (CONTEXT.md). It gets a cage instead, and THIS module
     produces the OSCAL `risk` object for it, taking over from the deleted
     render-exemption.py: the cage already knows the tier, the residual and
     the workload, exactly what the risk object needs, so the evidence comes
     from the thing actually constraining the workload, not a document
     asserting an intention. See oscal_risk() below.

Reuses ../fair/fair.py (the £ maths) and ../risk/enforce.py (the appetite band).
No new risk engine, no new appetite store.

Usage:
    cage.py dials <tier>                                   # tier -> dial JSON
    cage.py select <scenario.json> --org driftwood [--floor quarantine]
    cage.py selfcheck
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid

# Reuse the £ engine and the appetite band — single sources of truth, one dir over.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "fair"))
sys.path.insert(0, os.path.join(HERE, "..", "risk"))
import fair  # noqa: E402
import enforce  # noqa: E402

# --- The tier table: PSS-style presets over the dials Kyverno injects ----------
# `reduce`  = fraction of the behind-posture residual this cage collapses (R' shrinks).
# `cost`    = C_cage, the £/yr to OPERATE the cage (WAF sidecar compute + eviction
#             churn). Booked as cost-of-controls in TCoR. Both R' and C_cage stay
#             positive for any real cage — a cage retains-with-mitigation, it does
#             not close the loss path (that is what Deny, the bottom rung, does).
# The rest are the literal dials the `cage-tier` MutatingPolicy stamps onto the pod.
# ponytail: reduce/cost are calibration knobs — tune to real WAF/eviction telemetry;
# the ORDERING (tighter => more reduce AND more cost) is what the selection relies on.
#
# WHOSE NUMBERS THESE ARE. They are the PLATFORM's, self-declared, evidenced by nothing but this
# comment. An adopter that publishes its own graded response curve (driftwood's
# twin/orgs/<org>/responses/*.yaml, each carrying an evidence_grade and a written basis) disagrees
# with them materially -- its own mode reductions are 0.05/0.30/0.65/0.90 against the
# 0.30/0.70/0.92/0.98 here. Composition prices the twin entry off THIS table, so the entry names
# it: `residual_basis: platform-cage-tiers@<TABLE_VERSION>` says which reduction set produced the
# residuals, instead of a free-text sentence a reader would attribute to the adopter's own curve.
# verify/pound-seam/pound_seam.py grades the divergence: it FAILs when this table and a published
# curve stop agreeing about which rung is cheapest.
TABLE_VERSION = "1.0.0"

TIERS = {
    "baseline": {
        "reduce": 0.30, "cost": 500,
        "cpu": "500m", "mem": "256Mi",
        "priorityClass": "cage-baseline", "dropAll": False, "readOnlyRootFs": False,
        "waf": "none", "reach": "cluster", "evictFirst": False,
    },
    "restricted": {
        "reduce": 0.70, "cost": 2000,
        "cpu": "250m", "mem": "128Mi",
        "priorityClass": "cage-restricted", "dropAll": True, "readOnlyRootFs": True,
        "waf": "light", "reach": "namespace+named", "evictFirst": False,
    },
    "quarantine": {
        "reduce": 0.92, "cost": 6000,
        "cpu": "100m", "mem": "64Mi",
        "priorityClass": "cage-quarantine", "dropAll": True, "readOnlyRootFs": True,
        "waf": "heavy", "reach": "namespace", "evictFirst": False,
    },
    # The bottom rung (ADR-0022, eco-system ticket 26): quarantine's dials, plus
    # NO reach at all (no ingress, no egress) and FIRST eviction. It is a
    # RUNNING, unreachable cage -- not a refusal. select_tier() returns it where
    # it used to return "deny": nothing is ever denied, and an unknown or
    # missing tier fails closed to here.
    "isolated": {
        "reduce": 0.98, "cost": 15000,
        "cpu": "100m", "mem": "64Mi",
        "priorityClass": "cage-isolated", "dropAll": True, "readOnlyRootFs": True,
        "waf": "heavy", "reach": "none", "evictFirst": True,
    },
    # The substrate rung. NOT a priced cage and NOT in ORDER: it is declared by
    # role on a Namespace manifest by a platform-role party (kube-system,
    # flux-system, kyverno), never selected by the price. reduce/cost are 0
    # because nothing here is a cage bought against a residual.
    "infra": {
        "reduce": 0.0, "cost": 0,
        "cpu": None, "mem": None,
        "priorityClass": "system-cluster-critical", "dropAll": False,
        "readOnlyRootFs": False,
        "waf": "none", "reach": "cluster", "evictFirst": False,
    },
}
# Loosest -> tightest. The selection walks this order and stops at the first fit;
# falling off the end lands on the bottom rung, `isolated`. `infra` is
# deliberately absent: it is platform-only and out of selection (ADR-0022).
ORDER = ["baseline", "restricted", "quarantine", "isolated"]
# Every value the `cage-tier` label may hold, strictest last but for `infra`,
# which sits outside the ordering because it is a role declaration.
LADDER = ORDER + ["infra"]


# --- The twin agent's dial table (ADR-0031; eco-system tickets 30 and 145) ------
# ONE ladder, a dial table per actor class. The rung names are ORDER's; the dials
# are the twin agent's: what it may write, whether a model step runs and whether
# the owner's local clock runs (ticket 30 decision 11). `infra` is not a twin-agent
# rung: it is a platform-role declaration on a Namespace and nothing here is a
# Namespace. The subject is the adopter's twin acting with nobody at the keyboard,
# on the GitHub sweep and on the local clock (ADR-0031 decision 1).
#
# `cost` is 0 GBP in cash at every rung: Actions minutes are free on a public
# repository and the local clock runs on the owner's own subscription. It enters
# TCoR (twin_agent_tcor) and NEVER the selection, which runs over residuals alone.
#
# `reduce` IS NOT ON THE ROW, on purpose (decision 15: "derived, not typed"). The
# pod table above calls its reductions "evidenced by nothing but this comment". A
# rung's reduction here is derived from the misuse paths the rung closes
# (TWIN_AGENT_PATHS) and from what each path can still land on the adopter's
# own composed prices -- `twin_agent_reduce()` computes it from a `reach` the
# composition derives per adopter, and refuses by name where a path's reach could
# not be derived. Nothing in this table is a number about the world.
TWIN_AGENT_TABLE_VERSION = "1.0.0"
TWIN_AGENT_SUBJECT = "twin-agent"

TWIN_AGENT_TIERS = {
    "baseline": {
        # propose-only, the loosest rung that exists today (ADR-0031 decision 2)
        "writes": ("observation-line", "proposal-branch", "pull-request"),
        "model_step": "local-clock-grade-5",   # no override; GitHub only where a measured permission holds (none today)
        "local_clock": True,
        "cost": 0,
    },
    "restricted": {
        "writes": ("observation-line", "proposal-branch", "pull-request"),
        "model_step": "none",                  # lookup and deterministic render only
        "local_clock": False,
        "cost": 0,
    },
    "quarantine": {
        "writes": ("observation-line",),        # no proposal
        "model_step": "none",
        "local_clock": False,
        "cost": 0,
    },
    "isolated": {
        "writes": (),                           # the twin job runs and writes only to its job log; the writer job does not run
        "model_step": "none",
        "local_clock": False,
        "cost": 0,
    },
}

# The misuse paths that remain once the twin code is pinned by hub commit and the
# sweep is split into a read-only twin job and a writer job (ticket 30 decisions
# 7, 8 and 15). Each is a row of the hub's twin/ecosystem-misuse-catalogue.yaml;
# `closed_at` is the loosest rung that closes it. The writer keeps the same token
# at every rung it runs, so the two token paths close only where the writer job
# does not run at all.
TWIN_AGENT_PATHS = {
    "writer-pushes-a-looser-declaration": {
        "closed_at": "isolated",
        "catalogue_row": "adopter-twin-writer-pushes-a-looser-declaration",
    },
    "writer-merges-or-tags-through-rest": {
        "closed_at": "isolated",
        "catalogue_row": "adopter-twin-writer-merges-or-tags-through-rest",
    },
    "misleading-proposal-merged-by-a-human": {
        "closed_at": "quarantine",
        "catalogue_row": "adopter-merges-a-misleading-twin-proposal",
    },
    "model-step-writes-a-wrong-binding-or-forecast": {
        "closed_at": "restricted",
        "catalogue_row": "adopter-twin-model-step-writes-a-wrong-binding-or-forecast",
    },
}

# The window the scenario's loss magnitude runs over (ticket 30 decision 12): the
# time until the gate detects the act. Since eco-system ticket 142a the hub's
# schedule checker (verify/schedules/lane.py) grades a push to `main` or a merge
# made by a scheduled identity as a FAIL, and verify/tier-binding grades a served
# declaration looser than its priced tier; both run in the hub's truth gate. The
# figure is the gate's cadence, copied from the served workflow it names, not a
# number about the world. A composition prints it beside the price with its basis.
DETECTION_WINDOW = {
    "days": 1.0,
    "source": ("the hub's .github/workflows/truth.yml `schedule: cron: '47 5 * * *'` (once a "
               "day), read 2026-09-26 at policy-as-versioned-flux/policy-as-versioned-flux "
               "origin/main 9c3b1f22"),
    "detects": ("a push to main or a merge made by a scheduled identity "
                "(verify/schedules/lane.py, eco-system ticket 142a) and a served declaration "
                "looser than the strictest priced line (verify/tier-binding)"),
    "assumes": (
        "the truth run fires once a day as scheduled; the delay GitHub adds to a cron run "
        "(measured at up to ~5h on the estate's first firings) is not in the figure",
        "the loss runs until detection, not until repair: a red gate is acted on the day it "
        "is read",
        "one day is the schedule's whole interval, the upper bound on the wait for the next "
        "run; the mean wait is half of it",
    ),
}


def detection_window_years():
    """The window as a fraction of a year, the unit the loss magnitude is annualised in."""
    return float(DETECTION_WINDOW["days"]) / 365.25


def twin_agent_closed(rung):
    """The misuse paths closed at `rung` or at a looser rung (a tighter rung keeps
    every closure of the looser ones). Sorted, so the answer is stable."""
    if rung not in TWIN_AGENT_TIERS:
        sys.exit(f"unknown twin-agent rung '{rung}' (known: {', '.join(TWIN_AGENT_TIERS)})")
    return sorted(p for p, spec in TWIN_AGENT_PATHS.items()
                  if ORDER.index(spec["closed_at"]) <= ORDER.index(rung))


def twin_agent_reduce(rung, reach):
    """The share of the scenario's loss the rung removes, DERIVED from the paths it
    closes and from what each path could still land (decision 15).

    `reach` maps every path in TWIN_AGENT_PATHS to the fraction of the scenario's
    loss that path can land on the served tree (0.0 to 1.0), or None where the
    composition could not derive it. The residual at a rung is what the LOOSEST
    path still open can land: the paths are doors onto one loss (a served cage
    looser than the priced one), so they do not add, and closing a door beside an
    open one that reaches the same loss removes nothing. reduce = 1 - max(reach of
    the open paths); 1.0 when every path is closed. None where an open path's
    reach could not be derived: a rung whose residual cannot be stated is not a
    candidate, by name, never a guess (ADR-0020)."""
    missing = sorted(set(TWIN_AGENT_PATHS) - set(reach))
    if missing:
        raise ValueError(f"reach names no figure for {missing}")
    open_paths = [p for p in TWIN_AGENT_PATHS if p not in twin_agent_closed(rung)]
    if any(reach[p] is None for p in open_paths):
        return None
    for p in open_paths:
        if not 0.0 <= float(reach[p]) <= 1.0:
            raise ValueError(f"reach for {p!r} is {reach[p]!r}, not a fraction of the loss")
    return 1.0 - max((float(reach[p]) for p in open_paths), default=0.0)


def twin_agent_residuals(ale, reach):
    """The residual ALE at every twin-agent rung, `ale * (1 - reduce)`, or None at a
    rung whose reduction could not be derived. The mapping the adopter's own
    selection policy picks from (ADR-0021: the estate prices, the adopter's
    versioned package selects; a None rung is simply not a candidate)."""
    out = {}
    for rung in ORDER:
        reduce = twin_agent_reduce(rung, reach)
        out[rung] = None if reduce is None else float(ale) * (1.0 - reduce)
    return out


def twin_agent_tcor(ale, rung, reach):
    """TCoR of the twin agent's cage at `rung`: residual + the rung's cash cost,
    which is 0 at every rung. Booked, never selected on."""
    residual = twin_agent_residuals(ale, reach)[rung]
    controls = float(TWIN_AGENT_TIERS[rung]["cost"])
    return {"tier": rung, "residual": residual, "cost_of_controls": controls,
            "tcor": None if residual is None else residual + controls}


def dials(tier):
    """The deterministic tier -> dial-settings expansion. Pure lookup, no surprises."""
    if tier not in TIERS:
        sys.exit(f"unknown tier '{tier}' (known: {', '.join(LADDER)})")
    return dict(TIERS[tier])


def clamp_to_floor(tier, floor):
    """A party's own tighten-only floor (party.yaml `overlay.floor`, ADR-0022).
    The selection never returns looser than the floor its adopter declared; it
    may return stricter. Lowering the floor is priced as a delta elsewhere,
    never refused here."""
    if floor is None:
        return tier
    if floor not in ORDER:
        sys.exit(f"unknown cage floor '{floor}' (selectable: {', '.join(ORDER)})")
    return tier if ORDER.index(tier) >= ORDER.index(floor) else floor


def caged_residual(uncaged_ale, tier):
    """Residual ALE that survives this cage. R' = ALE * (1 - reduce), still > 0."""
    return uncaged_ale * (1.0 - TIERS[tier]["reduce"])


def tcor(uncaged_ale, tier):
    """Total Cost of Risk of running this cage = residual + cost-of-controls.

    (Transfer/premium is a separate line the risk officer may add; a bare cage
    books residual + C_cage.)
    """
    residual = caged_residual(uncaged_ale, tier)
    controls = float(TIERS[tier]["cost"])
    return {
        "tier": tier,
        "residual": residual,          # R' — retained, priced, still positive
        "cost_of_controls": controls,  # C_cage — the cage's run-cost
        "tcor": residual + controls,
    }


def select_tier(uncaged_ale, tolerance, floor=None):
    """The £ picks the tier: loosest cage whose residual fits the appetite band,
    then clamped UP to the adopter's own declared floor.

    `isolated` is the bottom rung — reached when even quarantine leaves a
    residual over the band. It is a running, unreachable cage, not a refusal
    (ADR-0022): nothing is ever denied. Deterministic: a pure function of
    (residual, band, floor).
    """
    for tier in ORDER:
        if caged_residual(uncaged_ale, tier) <= tolerance:
            break
    else:
        tier = ORDER[-1]
    return clamp_to_floor(tier, floor)


def select(scenario, org, tolerance, mode="behind", floor=None):
    """Full graded decision for a workload's residual + its TCoR risk line.

    `mode` picks which control-state block of the scenario is the UNCAGED
    residual: "behind" (default) for posture-drift scenarios, "warn" for a
    conditional-policy's root branch (the deviation is in place — same
    convention render-exemption.py used to price a ledger entry's residual).
    `floor` is the adopter's own tighten-only `overlay.floor` (ADR-0022).

    Every outcome is a Cage now: the bottom rung is `isolated`, a running
    cage with no reach, never a Deny (ADR-0022).
    """
    st = fair.state(scenario, mode)
    uncaged = fair.summarize(fair.simulate(st["lef"], st["lm"]))["ale"]
    tier = select_tier(uncaged, tolerance, floor)
    out = {
        "version": scenario.get("version"),
        "name": scenario.get("name"),
        "org": org,
        "uncaged_residual": uncaged,
        "tolerance": tolerance,
        "tier": tier,
        "floor": floor,
    }
    out["action"] = "Cage"
    out["dials"] = dials(tier)
    out["tcor"] = tcor(uncaged, tier)
    out["reason"] = (
        f"uncaged £{uncaged:,.0f}; {tier} cage -> residual "
        f"£{out['tcor']['residual']:,.0f} + controls £{out['tcor']['cost_of_controls']:,.0f} "
        f"= TCoR £{out['tcor']['tcor']:,.0f} (fits band £{tolerance:,.0f})"
    )
    return out


# --- OSCAL risk (ticket 05: the cage is the producer, replacing render-exemption.py) --
# Deterministic UUIDs so re-rendering an unchanged decision is stable (git-diff
# clean). Kept beside oscal_risk() so the risk<->observation join is guaranteed
# by construction: whoever builds an observation for a check result (see
# ../oscal/result2oscal.py) imports observation_uuid() from HERE, the one place
# that also builds the risk pointing back at it.
NS = uuid.UUID("d5f0e0b2-0000-4000-8000-706176662d64")  # constant "pavf" namespace
RISK_SYS = "https://pavf.dev/ns/risk"
GBP_SYS = "https://pavf.dev/ns/risk/gbp"


def observation_uuid(subject, policy):
    """Stable id of the "this check failed for this subject" C2P observation."""
    return str(uuid.uuid5(NS, f"obs:{subject}:{policy}"))


def oscal_risk(result, *, subject, policy, control):
    """A Cage decision -> its OSCAL `risk` object (assessment-results / POA&M shared).

    Only a Cage decision carries a risk: Deny closes the loss path, so there is
    nothing retained to report. `result` is select()'s return value; `subject` is
    "namespace/name" (the PolicyReport scope convention), `policy` the unsuffixed
    check id, `control` the NIST control it evidences.

    Status is "open" (a live OSCAL POA&M status), not "deviation-approved": the
    cage does not except the workload from the policy — the check still fails —
    it wraps the workload with compensating controls and prices what survives.
    No `deadline`: caging is not time-boxed (ADR-0006, no time-conditional
    verdicts); a cage is re-evaluated by a reviewed PR, not a clock.
    """
    if result["action"] != "Cage":
        raise ValueError(f"no risk object for action={result['action']!r} — nothing is retained")
    tcor = result["tcor"]
    org = result["org"]
    owner_uuid = str(uuid.uuid5(NS, f"party:{org}"))
    return {
        "uuid": str(uuid.uuid5(NS, f"risk:cage:{org}:{subject}:{policy}")),
        "title": f"{subject}: {policy} caged at {result['tier']} in {org}",
        "description": result["reason"],
        "statement": f"Conditional control {policy} is not satisfied for {subject}; "
                     f"a {result['tier']} cage implements the control on its behalf "
                     f"and the residual is retained, priced, not carved out.",
        "props": [
            {"name": "policy", "value": policy},
            {"name": "control", "value": control},
            {"name": "cage-tier", "value": result["tier"]},
        ],
        "status": "open",
        "origins": [{"actors": [{"type": "party", "actor-uuid": owner_uuid}]}],
        "characterizations": [{
            "origin": {"actors": [{"type": "party", "actor-uuid": owner_uuid}]},
            "facets": [
                {"name": "likelihood", "system": RISK_SYS, "value": "likely"},
                {"name": "impact", "system": RISK_SYS, "value": "high"},
                {
                    "name": "annualised-loss-expectancy", "system": GBP_SYS,
                    "value": str(round(tcor["residual"])),
                    "props": [
                        {"name": "currency", "value": "GBP"},
                        {"name": "basis", "value": "caged-residual"},
                        {"name": "cost-of-controls", "value": str(round(tcor["cost_of_controls"]))},
                    ],
                },
            ],
        }],
        "remediations": [{
            "uuid": str(uuid.uuid5(NS, f"rem:cage:{org}:{subject}:{policy}")),
            "lifecycle": "implemented",
            "title": f"{result['tier']} cage",
            "description": result["reason"],
            "props": [{"name": "type", "value": "mitigate"}],
        }],
        "related-observations": [{"observation-uuid": observation_uuid(subject, policy)}],
    }


# --- CLI ----------------------------------------------------------------------
def cmd_dials(args):
    print(json.dumps(dials(args.tier), indent=2))


def cmd_select(args):
    sc = fair.load(args.scenario)
    tol = enforce.tolerance_for(args.org, args.party_yaml)
    print(json.dumps(select(sc, args.org, tol, floor=args.floor), indent=2))


def cmd_selfcheck(_args):
    # 1. Tier -> dials is deterministic and total over the WHOLE ladder,
    #    including the two rungs ticket 26 adds: `isolated` (the bottom rung,
    #    a running cage) and `infra` (the platform's own substrate rung).
    assert LADDER == ["baseline", "restricted", "quarantine", "isolated", "infra"], LADDER
    assert "infra" not in ORDER, "infra is declared by role, never selected by a price"
    for t in LADDER:
        assert dials(t) == dials(t) == TIERS[t], t
        assert set(dials(t)) >= {"cpu", "mem", "priorityClass", "dropAll",
                                 "readOnlyRootFs", "waf", "reduce", "cost",
                                 "reach", "evictFirst"}, t
    # `isolated` IS quarantine's dials plus no reach and first eviction.
    _shared = lambda t: {k: v for k, v in TIERS[t].items()
                         if k not in ("reduce", "cost", "priorityClass", "reach", "evictFirst")}
    assert _shared("quarantine") == _shared("isolated"), (_shared("quarantine"), _shared("isolated"))
    assert TIERS["isolated"]["reach"] == "none" and TIERS["isolated"]["evictFirst"], TIERS["isolated"]

    # 2. Tighter tier => more risk collapsed AND more run-cost (the monotonicity the
    #    £-selection relies on). No tier fully closes the loss path (that is Deny).
    reduces = [TIERS[t]["reduce"] for t in ORDER]
    costs = [TIERS[t]["cost"] for t in ORDER]
    assert reduces == sorted(reduces) and costs == sorted(costs), (reduces, costs)
    for t in ORDER:
        assert 0.0 < TIERS[t]["reduce"] < 1.0, t   # R' stays > 0: retained, not closed
        assert TIERS[t]["cost"] > 0, t             # C_cage booked

    # 3. The £ selects the tier: as the band tightens on a FIXED residual, the cage
    #    tightens deterministically, and an impossibly-tight band falls through to Deny.
    r = 30_000.0
    assert select_tier(r, 40_000) == "baseline",   select_tier(r, 40_000)
    assert select_tier(r, 20_000) == "restricted", select_tier(r, 20_000)
    assert select_tier(r, 5_000) == "quarantine",  select_tier(r, 5_000)
    assert select_tier(r, 1_000) == "isolated",    select_tier(r, 1_000)
    assert select_tier(r, 1) == "isolated",        select_tier(r, 1)
    assert "deny" not in TIERS and "deny" not in LADDER, "the deny rung is retired (ADR-0022)"

    # 3b. The adopter's own floor clamps the selection UP and never down: a
    #     price that would pick baseline is held at the declared floor, and a
    #     price stricter than the floor is left alone. Tighten-only.
    assert select_tier(r, 40_000, floor="quarantine") == "quarantine", "floor must clamp up"
    assert select_tier(r, 1_000, floor="baseline") == "isolated", "floor must never loosen"
    assert select_tier(r, 40_000, floor=None) == "baseline"
    assert clamp_to_floor("restricted", "isolated") == "isolated"

    # 4. TCoR is booked as residual + cost-of-controls, both positive (priced
    #    partial-reduce on a RETAINED risk), and tightening trades residual for cost.
    t_loose = tcor(r, "baseline")
    t_tight = tcor(r, "quarantine")
    assert t_loose["residual"] > t_tight["residual"] > 0, (t_loose, t_tight)
    assert t_tight["cost_of_controls"] > t_loose["cost_of_controls"] > 0, (t_loose, t_tight)
    assert t_loose["tcor"] == t_loose["residual"] + t_loose["cost_of_controls"]

    # 5. Same behind-posture workload, real scenario: loose driftwood cages light,
    #    strict ludlow cages hard — proportionality, tier edition (reuses appetite.json).
    sc = fair.load(os.path.join(HERE, "scenarios", "driftwood-behind-posture.json"))
    dw = select(sc, "driftwood", enforce.tolerance_for("driftwood"))
    lud = select(sc, "ludlow", enforce.tolerance_for("ludlow"))
    assert dw["action"] == "Cage" and lud["action"] == "Cage", (dw, lud)
    assert ORDER.index(dw["tier"]) < ORDER.index(lud["tier"]), (dw["tier"], lud["tier"])

    # 6. OSCAL risk (ticket 05): a workload that fails a conditional policy's
    #    condition C is caged (mode="warn" = the deviation in place, same
    #    convention render-exemption.py used), and the cage's own decision
    #    produces a valid, joinable OSCAL risk — no ledger involved.
    root_sc = fair.load(os.path.join(HERE, "..", "policy", "scenarios", "driftwood-root-residual.json"))
    till = select(root_sc, "driftwood", enforce.tolerance_for("driftwood"), mode="warn")
    assert till["action"] == "Cage", till  # this scenario+org fits under a cage, not Deny
    risk = oscal_risk(till, subject="shop/legacy-till-0", policy="may-run-root-if-attested",
                       control="nist-800-53:AC-6")
    assert risk["status"] == "open", risk["status"]
    assert "deadline" not in risk, "a cage is not time-boxed (ADR-0006)"
    assert risk["remediations"][0]["props"][0] == {"name": "type", "value": "mitigate"}
    ale_facets = [f for f in risk["characterizations"][0]["facets"]
                  if f["name"] == "annualised-loss-expectancy"]
    assert len(ale_facets) == 1 and int(ale_facets[0]["value"]) == round(till["tcor"]["residual"])
    assert risk["related-observations"][0]["observation-uuid"] == \
        observation_uuid("shop/legacy-till-0", "may-run-root-if-attested")
    assert oscal_risk(till, subject="shop/legacy-till-0", policy="may-run-root-if-attested",
                       control="nist-800-53:AC-6") == risk, "not deterministic"
    try:
        oscal_risk(dict(till, action="Deny"), subject="x", policy="y", control="z")
        raise AssertionError("oscal_risk must refuse a Deny decision — nothing is retained")
    except ValueError:
        pass

    # 7. The twin agent's dial table (ADR-0031; eco-system ticket 145). One ladder:
    #    the same four rung names, `infra` absent (a Namespace role, not an actor's
    #    rung), every row carrying the twin agent's own dials and a cash cost of 0.
    assert list(TWIN_AGENT_TIERS) == ORDER, list(TWIN_AGENT_TIERS)
    assert "infra" not in TWIN_AGENT_TIERS, "infra is not a twin-agent rung (ADR-0031)"
    for rung, row in TWIN_AGENT_TIERS.items():
        assert set(row) == {"writes", "model_step", "local_clock", "cost"}, (rung, row)
        assert row["cost"] == 0, ("every rung runs for 0 GBP in cash (decision 15)", rung, row)
        assert "reduce" not in row, ("reduce is derived, never typed (decision 15)", rung)
    # The dials tighten one step at a time: first the model step and the local
    # clock, then the proposal, then every write (decision 11).
    writes = [set(TWIN_AGENT_TIERS[r]["writes"]) for r in ORDER]
    assert all(later <= earlier for earlier, later in zip(writes, writes[1:])), writes
    assert TWIN_AGENT_TIERS["baseline"]["model_step"] != "none" and TWIN_AGENT_TIERS["baseline"]["local_clock"]
    assert all(TWIN_AGENT_TIERS[r]["model_step"] == "none" and not TWIN_AGENT_TIERS[r]["local_clock"]
               for r in ORDER[1:]), TWIN_AGENT_TIERS
    assert "pull-request" in TWIN_AGENT_TIERS["restricted"]["writes"], "restricted still proposes"
    assert TWIN_AGENT_TIERS["quarantine"]["writes"] == ("observation-line",), "quarantine observes only"
    assert TWIN_AGENT_TIERS["isolated"]["writes"] == (), "isolated writes nothing"
    # Every path closes at a rung on the ladder, and a tighter rung keeps every
    # closure of the looser ones.
    for p, spec in TWIN_AGENT_PATHS.items():
        assert spec["closed_at"] in ORDER, (p, spec)
    closed = [set(twin_agent_closed(r)) for r in ORDER]
    assert all(earlier <= later for earlier, later in zip(closed, closed[1:])), closed
    assert closed[-1] == set(TWIN_AGENT_PATHS), "isolated closes every path"
    assert closed[0] == set(), "baseline closes none"
    # The reduction is DERIVED from what the open paths can still land. The two
    # token paths reach the whole declaration gap and stay open until isolated,
    # the proposal path reaches none of it past the served PR gate, and the
    # model step reaches no priced figure (grade 5 never prices): so restricted
    # AND quarantine carry the same residual as baseline, and only isolated
    # collapses it. That is the consequence ADR-0031 records for restricted,
    # measured here rather than asserted.
    reach = {"writer-pushes-a-looser-declaration": 1.0, "writer-merges-or-tags-through-rest": 1.0,
             "misleading-proposal-merged-by-a-human": 0.0,
             "model-step-writes-a-wrong-binding-or-forecast": 0.0}
    assert [twin_agent_reduce(r, reach) for r in ORDER] == [0.0, 0.0, 0.0, 1.0]
    res = twin_agent_residuals(1_000.0, reach)
    assert res["restricted"] == res["baseline"] == res["quarantine"] == 1_000.0, res
    assert res["isolated"] == 0.0, res
    # A path with a partial reach: closing it beside a fully-reaching open path
    # removes nothing (doors onto one loss do not add); closing the last open
    # path removes everything above what remains.
    partial = dict(reach, **{"writer-pushes-a-looser-declaration": 0.4,
                             "writer-merges-or-tags-through-rest": 0.4,
                             "misleading-proposal-merged-by-a-human": 1.0})
    assert [twin_agent_reduce(r, partial) for r in ORDER] == [0.0, 0.0, 0.6, 1.0]
    # A reach that could not be derived makes every rung it is still open at a
    # named non-candidate (None), never a guessed number; the rungs that close it
    # still price.
    unknown = dict(reach, **{"misleading-proposal-merged-by-a-human": None})
    assert [twin_agent_reduce(r, unknown) for r in ORDER] == [None, None, 0.0, 1.0]
    assert twin_agent_residuals(1_000.0, unknown)["baseline"] is None
    for bad in (dict(reach, **{"writer-pushes-a-looser-declaration": 1.5}),
                {k: v for k, v in reach.items() if k != "writer-merges-or-tags-through-rest"}):
        try:
            twin_agent_reduce("baseline", bad)
            raise AssertionError("a reach off [0, 1] or missing a path must refuse")
        except ValueError:
            pass
    # Cost enters TCoR and never the selection: the residual alone is what a
    # selection policy reads, and the booked cost is 0 at every rung.
    for r in ORDER:
        t = twin_agent_tcor(1_000.0, r, reach)
        assert t["cost_of_controls"] == 0.0 and t["tcor"] == t["residual"], t
    assert 0 < detection_window_years() < 1 and DETECTION_WINDOW["days"] == 1.0, DETECTION_WINDOW
    assert DETECTION_WINDOW["source"] and DETECTION_WINDOW["assumes"], "the window names its source"

    print(
        "ok  twin-agent table v%s: rungs %s, cost 0 at every rung, reduce derived from the "
        "paths each rung closes (%d paths); restricted and quarantine carry baseline's residual, "
        "isolated collapses it; an underived reach is a named non-candidate"
        % (TWIN_AGENT_TABLE_VERSION, ORDER, len(TWIN_AGENT_PATHS))
    )
    print(
        "ok  tiers %s | £ picks: band40k->%s band20k->%s band5k->%s band1k->isolated | "
        "scenario £%.0f: driftwood->%s (TCoR £%.0f), ludlow->%s (TCoR £%.0f) | "
        "legacy-till (warn) -> %s cage, OSCAL risk open £%s -> observation resolves"
        % (ORDER, "baseline", "restricted", "quarantine",
           dw["uncaged_residual"], dw["tier"], dw["tcor"]["tcor"],
           lud["tier"], lud["tcor"]["tcor"], till["tier"], ale_facets[0]["value"])
    )


def main(argv=None):
    p = argparse.ArgumentParser(description="Graded enforcement: tiers over dials, the £ picks the tier.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pd = sub.add_parser("dials", help="deterministic tier -> dial-settings expansion")
    pd.add_argument("tier")
    pd.set_defaults(func=cmd_dials)

    psel = sub.add_parser("select", help="the £ picks the tier + emits the TCoR ledger line")
    psel.add_argument("scenario")
    psel.add_argument("--org", required=True)
    psel.add_argument("--party-yaml", default=enforce.DEFAULT_APPETITE,
                      help="read the band from THIS party.yaml instead of the party's own")
    psel.add_argument("--floor", default=None, choices=ORDER,
                      help="the adopter's own tighten-only cage floor (ADR-0022)")
    psel.set_defaults(func=cmd_select)

    pk = sub.add_parser("selfcheck", help="run the graded-envelope assertions")
    pk.set_defaults(func=cmd_selfcheck)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
