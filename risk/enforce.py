#!/usr/bin/env python3
"""enforce.py — the £ picks Audit or Deny (pure stdlib, offline, no date logic).

The proportionality decision, made a number instead of a vibe. Reads a versioned
FAIR scenario (warn/deny triples) and an org's risk-appetite tolerance band, then:

    risk_bought = ALE_warn - ALE_deny        # what escalating to Deny buys
    verdict     = Deny  if risk_bought > tolerance  else  Audit

That verdict IS the Kyverno `validationActions` value. So tightening a versioned
triple raises ALE_warn, pushes risk_bought over the band, and flips Audit->Deny —
in a reviewable PR whose justification is the £, never a timer (ADR-0006).

Reuses the load-bearing maths in ../fair/fair.py (control_value); adds only the
appetite comparison. No new risk engine.

Appetite is a SIGNED FACT on each party's own party.yaml (`appetite.tolerance`,
ADR-0021 / eco-system ticket 25). The platform-held fixture `appetite.json` is
retired: a party's band is now declared by the party that carries it, next to
its size, and nobody else. `tolerance_for()` below is the ONE helper that reads
it — composition, the cage, the war-gamer and the reflexive self-check all come
through here. A party with no declared appetite is a MISSING INSTRUMENT: it
refuses (ADR-0020), it never defaults to a number nobody signed.

Usage:
    enforce.py decide <scenario.json> --org driftwood [--party-yaml path]
    enforce.py action <scenario.json> --org driftwood     # bare 'Audit'|'Deny'
    enforce.py selfcheck
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import yaml

# Reuse the FAIR engine one dir over — it is the single source of the £ maths.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fair"))
import fair  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
# .estate-clone/ — every party is a sibling directory of `platform`, each with
# its own signed party.yaml. Same layout clone-estate.sh assembles.
ESTATE_DIR = os.path.dirname(os.path.dirname(HERE))
# Kept as the argparse default other modules already import (tcor, cage). None
# means "resolve the party's own artefact"; an explicit path is a party.yaml.
DEFAULT_APPETITE = None


class MissingInstrument(Exception):
    """ADR-0020: the £ cannot be read, so no number may be emitted. Names what
    is missing. Distinct from a priced hole, which is a missing BEHAVIOUR."""


def party_yaml_path(org):
    """The party's own signed artefact. `platform` signs the one next to this
    module's own repo root; every other party is a sibling checkout."""
    if org == "platform":
        return os.path.join(os.path.dirname(HERE), "party.yaml")
    return os.path.join(ESTATE_DIR, org, "party.yaml")


def appetite_money(org, party_path=DEFAULT_APPETITE):
    """`appetite.tolerance` = {amount, currency} off the party's OWN party.yaml.

    Raises MissingInstrument naming the party and the file when the artefact is
    absent or declares no appetite — never a default, never a fixture.
    """
    path = party_path or party_yaml_path(org)
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh) or {}
    except OSError:
        raise MissingInstrument(
            f"no risk appetite for '{org}': no party artefact at {path}") from None
    tolerance = (doc.get("appetite") or {}).get("tolerance")
    if not isinstance(tolerance, dict) or "amount" not in tolerance:
        raise MissingInstrument(
            f"no risk appetite for '{org}': {path} declares no appetite.tolerance")
    return {"amount": float(tolerance["amount"]), "currency": tolerance.get("currency")}


def tolerance_for(org, party_path=DEFAULT_APPETITE):
    """The band as a bare number, in the party's own appetite currency. Public
    name and shape unchanged for every existing caller (cage, tcor, wargamer,
    wardley, verify/proportionality); only the STORE moved."""
    return appetite_money(org, party_path)["amount"]


def decide(scenario, org, tolerance):
    """Return the enforcement decision + the number that justifies it.

    verdict = Deny iff the risk a Deny buys (ALE_warn - ALE_deny) exceeds the
    org's tolerance band. No dates, no timers — a pure function of the £.
    """
    cv = fair.control_value(fair.state(scenario, "warn"), fair.state(scenario, "deny"))
    risk_bought = cv["risk_bought"]  # ALE_warn - ALE_deny
    verdict = "Deny" if risk_bought > tolerance else "Audit"
    headroom = tolerance - risk_bought
    return {
        "version": scenario.get("version"),
        "name": scenario.get("name"),
        "org": org,
        "verdict": verdict,
        "validationActions": [verdict],
        "residual_warn": cv["residual_warn"],   # ALE_warn (Audit still ships)
        "residual_deny": cv["residual_deny"],   # ALE_deny (path closed)
        "risk_bought": risk_bought,             # ALE_warn - ALE_deny
        "tolerance": tolerance,
        "headroom": headroom,                   # <0 means over-band -> Deny
        "reason": (
            f"risk_bought £{risk_bought:,.0f} "
            f"{'>' if verdict == 'Deny' else '<='} tolerance £{tolerance:,.0f} "
            f"-> {verdict} (justified by the £, not a timer)"
        ),
    }


# --- CLI ----------------------------------------------------------------------
def cmd_decide(args):
    sc = fair.load(args.scenario)
    print(json.dumps(decide(sc, args.org, tolerance_for(args.org, args.appetite)), indent=2))


def cmd_action(args):
    sc = fair.load(args.scenario)
    print(decide(sc, args.org, tolerance_for(args.org, args.appetite))["verdict"])


def cmd_selfcheck(_args):
    loose = fair.load(os.path.join(HERE, "..", "fair", "scenarios", "driftwood-cart-pii.json"))
    tight = fair.load(os.path.join(HERE, "scenarios", "driftwood-cart-pii-tightened.json"))

    dw = tolerance_for("driftwood")
    lud = tolerance_for("ludlow")

    d_loose = decide(loose, "driftwood", dw)
    d_tight = decide(tight, "driftwood", dw)

    # 1. Below the band -> Audit; above it -> Deny.
    assert d_loose["verdict"] == "Audit", d_loose
    assert d_tight["verdict"] == "Deny", d_tight

    # 2. Tightening the triple RAISES the £ (that is what drives the flip).
    assert d_tight["risk_bought"] > d_loose["risk_bought"], (d_loose, d_tight)
    assert d_loose["risk_bought"] <= dw < d_tight["risk_bought"], (d_loose, d_tight)

    # 3. Same control, different band -> different verdict (proportionality money-shot):
    #    the loose cart-PII that Audits in driftwood Denies under ludlow's strict band.
    assert decide(loose, "ludlow", lud)["verdict"] == "Deny", (loose, lud)

    # 4. The escalation is justified by a number, not a timer: this module imports
    #    no clock. Scan real import statements only (not these string literals).
    with open(os.path.abspath(__file__)) as fh:
        for line in fh:
            s = line.strip()
            if s.startswith(("import ", "from ")):
                assert "datetime" not in s and "time" not in s, \
                    f"date/timer logic leaked into enforcement: {s}"

    # 5. The band is the PARTY's own signed fact, and a party that declares
    #    none is a missing instrument that refuses (ADR-0020) -- never a
    #    default and never a fixture.
    import tempfile
    assert dw == float(yaml.safe_load(open(party_yaml_path("driftwood")))
                       ["appetite"]["tolerance"]["amount"]), dw
    assert appetite_money("driftwood")["currency"] == "GBP", appetite_money("driftwood")
    assert not os.path.exists(os.path.join(HERE, "appetite.json")), \
        "risk/appetite.json is retired -- appetite is a signed fact on party.yaml"
    with tempfile.TemporaryDirectory() as td:
        bare = os.path.join(td, "party.yaml")
        with open(bare, "w") as fh:
            fh.write("party: nobody\nroles: [adopter]\n")
        for missing in (bare, os.path.join(td, "nothing.yaml")):
            try:
                tolerance_for("nobody", missing)
                raise AssertionError(f"a party with no appetite must refuse: {missing}")
            except MissingInstrument as e:
                assert "nobody" in str(e), e

    print(
        "ok  driftwood(£%.0f tol, from its OWN party.yaml): loose buys £%.0f -> Audit | "
        "tightened buys £%.0f -> Deny | same loose under ludlow(£%.0f tol) -> Deny | "
        "a party with no declared appetite refuses as a missing instrument"
        % (dw, d_loose["risk_bought"], d_tight["risk_bought"], lud)
    )


def main(argv=None):
    p = argparse.ArgumentParser(description="Risk-tuned enforcement: the £ picks Audit or Deny.")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, fn, helptext in (
        ("decide", cmd_decide, "full decision + the £ that justifies it (JSON)"),
        ("action", cmd_action, "bare validationActions value: Audit|Deny"),
    ):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("scenario")
        sp.add_argument("--org", required=True)
        sp.add_argument("--party-yaml", dest="appetite", default=DEFAULT_APPETITE,
                        help="read the band from THIS party.yaml instead of the party's own")
        sp.set_defaults(func=fn)

    pk = sub.add_parser("selfcheck", help="run the enforcement assertions")
    pk.set_defaults(func=cmd_selfcheck)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
