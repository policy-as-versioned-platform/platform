#!/usr/bin/env python3
"""to_fair_scenario.py — turn a signed platform feed entry into a fair.py scenario.

Same shape as estate/ico/schema/to_fair_scenario.py: reads a versioned feed and
emits scenario JSON in the (min,mode,max) shape `platform/fair/fair.py` already
consumes -- bumping a feed version is the whole diff needed to move the £; no
change to fair.py itself.

Three feeds:
  threat  institution threat register -> lef AND lm straight from the publisher's
          own payload from major 3 (eco-system ticket 79 item 4). Before major 3
          the magnitude comes from FROZEN_LM_GBP here and every scenario says so
          by name. The publisher now ships its own copy of this subcommand at
          `threat-register/to_fair_scenario.py` in the feeds repository, which is
          what composition uses; this one is the fallback for a feeds checkout
          from before the move, and the selfcheck asserts the two agree.
  cve     trivy/GHSA-style feed -> lm from severity_lm_gbp, lef from epss
          (exploit-probability proxy) scaled onto an editorial annual event count.
  eol     endoflife.date-style feed -> lm/lef straight from the component's base
          bands, with lef RAMPED by how far --as-of sits past eol_date: this is
          the time-varying thread (past-EOL -> unpatched CVEs accumulate -> £
          ramps), not a one-off sunset event.

Deny state (all three): loss path closed, lef ~ (0,0,1), same convention as
every other scenario in this estate.

Headline entry (eco-system ticket 84). `cve` and `eol` price ONE entry each, and
composition prices a whole feed for an adopter: it has no cve id or component
of its own to name. With the entry omitted the converter prices the feed's
HEADLINE -- the entry with the largest mode-product, mode(lef) x mode(lm), an
ordinal proxy that can diverge from fair.py's PERT expectation (review F5),
for `eol` as ramped at `--as-of` -- and the scenario's `note` names
which entry that is, how many the feed carries and which ones this line does
not price. One entry, not a sum: fair.py's own selfcheck refuses summing
independent risks' ALEs after the fact, and PERT triples do not add. The
headline is the ordinal reading of the feed (ticket 75 Q4), said on the line.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys

DENY_LEF = (0, 0, 1)

# THE MAGNITUDES MOVED (eco-system ticket 79 item 4, ticket 24).
#
# This table was an ADOPTER-KEYED map of impact per loss event, held HERE, in the
# subscriber's own repository. So the platform carried a signed-looking number
# about each institution that no publisher had published, that no subscriber
# could re-derive from anything signed, and that a fourth adopter could not have
# obtained at all. From `threat-register` payload major 3 the number is in the
# PUBLISHER's payload (`institutions.<name>.lm_gbp`, with `lm_basis`) and the
# converter that reads it is in the publisher's repository, at
# `threat-register/to_fair_scenario.py` in the feeds repo -- which is the FIRST
# place composition's `_converter()` looks, so a composition against any feeds
# checkout that carries it uses the publisher's copy and not this one.
#
# This copy stays for one reason: a composition against a feeds checkout pinned
# to a commit from BEFORE the move finds no converter in the publisher's tree and
# falls back here. It must then price exactly what the publisher's copy prices,
# and the selfcheck below asserts that against the real feeds checkout when there
# is one. The table is FROZEN -- it gains no entry ever, because an entry added
# here would be a number about an institution invented in the subscriber's code,
# which is the whole defect.
FROZEN_LM_GBP = {
    "driftwood": (1_000, 4_000, 9_000),
    "tuppence": (5_000, 25_000, 90_000),
    "ludlow": (20_000, 100_000, 400_000),
}
THREAT_LM_GBP = FROZEN_LM_GBP      # the name the estate's older callers know it by
FROZEN_NOTE = (
    "MAGNITUDE UNSOURCED: the impact per event {lm} {currency} is not in payload version "
    "{version}, which predates the publisher's `lm_gbp` field; it is this converter's frozen "
    "copy of the adopter-keyed table that used to live in the SUBSCRIBER's own code "
    "(platform/feeds/to_fair_scenario.py THREAT_LM_GBP). From major 3 the number and its basis "
    "are in the payload. A named could-not-look (eco-system ticket 79 item 4), never a bare "
    "number.")


def _triple(value, what: str, where: str) -> tuple:
    if not (isinstance(value, (list, tuple)) and len(value) == 3):
        sys.exit(f"{where}: {what} is {value!r}, not a (min, mode, max) triple")
    lo, mode, hi = (float(x) for x in value)
    if not lo <= mode <= hi:
        sys.exit(f"{where}: {what} is {value!r}, which is not lo<=mode<=hi")
    return (lo, mode, hi)


def _basis_note(basis, what: str, where: str) -> str:
    """A published number must say what it rests on. One the publisher signs and
    cannot say the source of is a missing instrument (ADR-0020), never a cheaper
    one -- so this refuses rather than annotating it away."""
    if not isinstance(basis, dict) or not basis.get("statement") or not basis.get("as_of"):
        sys.exit(f"{where}: publishes {what} with no basis carrying a `statement` and an "
                 f"`as_of` date. Its basis belongs beside it in the payload "
                 f"(eco-system ticket 79 item 4)")
    note = (f"{what} basis ({basis.get('kind', 'unlabelled')}, read {basis['as_of']}): "
            f"{basis['statement']}")
    if basis.get("could_not_look"):
        note += f" COULD NOT LOOK: {basis['could_not_look']}"
    return note


# --- threat register -----------------------------------------------------------
def threat_scenario(feed: dict, institution: str) -> dict:
    """Byte-for-byte the publisher's own `threat-register/to_fair_scenario.py`.
    The selfcheck asserts the two agree on every published payload version, so
    the fallback path cannot drift away from what the publisher ships."""
    version = feed.get("feed_version", "unversioned")
    currency = feed.get("currency") or "GBP"
    institutions = feed.get("institutions") or {}
    if institution not in institutions:
        sys.exit(f"threat-register {version}: no institution {institution!r} in this payload "
                 f"(it carries {sorted(institutions)})")
    entry = institutions[institution]
    where = f"threat-register {version}: institutions.{institution}"

    lef = _triple(entry["lef"], "lef", where)
    notes = [f"{entry['threat']} ({entry['flavour']})."]
    if "lef_basis" in entry:
        notes.append(_basis_note(entry["lef_basis"], "Frequency", where))
    else:
        notes.append(f"lef sourced from {entry['source']}.")

    if "lm_gbp" in entry:
        lm = _triple(entry["lm_gbp"], "lm_gbp", where)
        notes.append(_basis_note(entry.get("lm_basis"), "Magnitude", where))
    else:
        if institution not in FROZEN_LM_GBP:
            sys.exit(f"{where}: payload version {version} publishes no `lm_gbp`, and this "
                     f"converter holds no frozen magnitude for {institution!r}. The magnitude "
                     f"belongs in the publisher's payload from major 3 (eco-system ticket 79 "
                     f"item 4); there is nothing here to price from (ADR-0020)")
        lm = tuple(float(x) for x in FROZEN_LM_GBP[institution])
        notes.append(FROZEN_NOTE.format(lm=lm, currency=currency, version=version))

    return {
        "version": version,
        "name": f"threat-register:{version} {institution}",
        "note": " ".join(notes),
        "warn": {"lef": list(lef), "lm": list(lm)},
        "deny": {"lef": list(DENY_LEF), "lm": list(lm)},
    }


# --- CVE feed --------------------------------------------------------------------
def _expected(lef: tuple, lm: tuple) -> float:
    """mode(lef) x mode(lm): the ordinal the headline is picked on."""
    return float(lef[1]) * float(lm[1])


def _headline(candidates: dict[str, tuple[tuple, tuple]]) -> tuple[str, str]:
    """(entry id, note fragment) for the entry with the largest expected
    annual loss; ties break on the id so the pick is deterministic."""
    if not candidates:
        raise SystemExit("FAIL: the feed carries no entry to price")
    ranked = sorted(candidates, key=lambda k: (-_expected(*candidates[k]), k))
    others = ", ".join(ranked[1:]) or "none"
    return ranked[0], (f"headline entry {ranked[0]} of {len(ranked)} (largest mode-product "
                       f"entry, mode lef x mode lm -- an ordinal proxy, not fair.py's PERT "
                       f"expectation; ticket 75 Q4); not priced by this line: {others}.")


def cve_scenario(feed: dict, cve_id: str | None = None,
                 annual_events_if_exploited=(1, 2, 6)) -> dict:
    headline = ""
    if cve_id is None:
        lo, mode, hi = annual_events_if_exploited
        cve_id, headline = _headline({
            k: ((lo * c["epss"], mode * c["epss"], hi * c["epss"]),
                tuple(feed["severity_lm_gbp"][c["severity"]]))
            for k, c in feed["cves"].items()})
        headline = " " + headline
    cve = feed["cves"][cve_id]
    lm = tuple(feed["severity_lm_gbp"][cve["severity"]])
    # lef: epss (0..1 exploit-probability proxy) scales an editorial "if this CVE
    # is actively exploited against us, how many loss events/yr" band.
    epss = cve["epss"]
    lo, mode, hi = annual_events_if_exploited
    lef = (lo * epss, mode * epss, hi * epss)
    return {
        "version": feed["feed_version"],
        "name": f"cve:{feed['feed_version']} {cve_id}",
        "note": f"{cve['component']} CVSS {cve['cvss']} ({cve['severity']}), epss={epss}. Source: {cve['source']}.{headline}",
        "warn": {"lef": list(lef), "lm": list(lm)},
        "deny": {"lef": list(DENY_LEF), "lm": list(lm)},
    }


# --- EOL feed (time-varying) ------------------------------------------------------
def eol_ramp(eol_date: str, as_of: str) -> float:
    """Loss-event-frequency multiplier for how far as_of sits past eol_date.

    <= eol_date: 1.0 (still in support, base rate applies).
    past eol: unpatched CVEs accumulate -- ramps linearly, +1x per year past EOL,
    capped at 4x (ponytail: linear ramp capped at 4yrs-worth; a real curve would
    taper as attackers move to newer targets, but monotonic-and-bounded is the
    only property fair.py's caller needs).
    """
    eol = datetime.date.fromisoformat(eol_date)
    asof = datetime.date.fromisoformat(as_of)
    days_past = (asof - eol).days
    if days_past <= 0:
        return 1.0
    years_past = days_past / 365.0
    return 1.0 + min(years_past, 4.0)


def eol_scenario(feed: dict, component: str | None, as_of: str) -> dict:
    headline = ""
    if component is None:
        def _ramped(c: dict) -> tuple:
            r = eol_ramp(c["eol_date"], as_of)
            return tuple(x * r for x in c["base_lef"])
        component, headline = _headline({
            k: (_ramped(c), tuple(c["base_lm_gbp"])) for k, c in feed["components"].items()})
        headline = " " + headline
    c = feed["components"][component]
    ramp = eol_ramp(c["eol_date"], as_of)
    lo, mode, hi = c["base_lef"]
    lef = (lo * ramp, mode * ramp, hi * ramp)
    lm = tuple(c["base_lm_gbp"])
    return {
        "version": feed["feed_version"],
        "name": f"eol:{feed['feed_version']} {component}@{as_of}",
        "note": f"eol_date={c['eol_date']}, as_of={as_of}, ramp={ramp:.2f}x. Source: {c['source']}.{headline}",
        "warn": {"lef": list(lef), "lm": list(lm)},
        "deny": {"lef": list(DENY_LEF), "lm": list(lm)},
    }


# --- selfcheck -------------------------------------------------------------------
def selfcheck():
    import glob
    import os

    root = os.path.dirname(__file__)

    checked = 0
    for path in sorted(glob.glob(os.path.join(root, "threat-register/v*/register.json"))):
        with open(path) as fh:
            feed = json.load(fh)
        for inst in feed["institutions"]:
            sc = threat_scenario(feed, inst)
            lo, mode, hi = sc["warn"]["lef"]
            assert lo <= mode <= hi, (path, inst, sc)
            checked += 1

    for path in sorted(glob.glob(os.path.join(root, "cve/v*/cve-feed.json"))):
        with open(path) as fh:
            feed = json.load(fh)
        for cve_id in feed["cves"]:
            sc = cve_scenario(feed, cve_id)
            lo, mode, hi = sc["warn"]["lef"]
            assert lo <= mode <= hi, (path, cve_id, sc)
            checked += 1

    for path in sorted(glob.glob(os.path.join(root, "eol/v*/eol-feed.json"))):
        with open(path) as fh:
            feed = json.load(fh)
        for comp in feed["components"]:
            sc = eol_scenario(feed, comp, "2026-07-31")
            lo, mode, hi = sc["warn"]["lef"]
            assert lo <= mode <= hi, (path, comp, sc)
            checked += 1

    # EOL ramp: the time-varying property the ticket cares about.
    r_before = eol_ramp("2025-10-31", "2025-01-01")
    r_at = eol_ramp("2025-10-31", "2025-10-31")
    r_1yr = eol_ramp("2025-10-31", "2026-10-31")
    r_2yr = eol_ramp("2025-10-31", "2027-10-31")
    r_10yr = eol_ramp("2025-10-31", "2035-10-31")
    assert r_before == 1.0, r_before
    assert r_at == 1.0, r_at
    assert 1.0 < r_1yr < r_2yr < r_10yr, (r_1yr, r_2yr, r_10yr)
    assert r_10yr == 5.0, r_10yr  # capped at +4x

    # Ticket 84: the headline pick is deterministic, names what it did not price,
    # and for eol moves with --as-of (a component past EOL longer ramps higher).
    cve_feed = {"feed_version": "vX", "severity_lm_gbp": {"critical": (50_000, 150_000, 400_000),
                                                           "high": (10_000, 40_000, 120_000)},
                "cves": {"A-low-epss": {"component": "a", "cvss": 9.0, "severity": "critical",
                                        "epss": 0.10, "source": "s"},
                         "B-high-epss": {"component": "b", "cvss": 7.5, "severity": "high",
                                         "epss": 0.90, "source": "s"}}}
    head = cve_scenario(cve_feed)
    # A: 2*0.10*150000 = 30000; B: 2*0.90*40000 = 72000 -> B is the headline
    assert "B-high-epss" in head["name"] and "headline entry B-high-epss of 2" in head["note"], head
    assert "not priced by this line: A-low-epss" in head["note"], head
    assert cve_scenario(cve_feed, "A-low-epss")["note"].endswith("Source: s."), "a named entry carries no headline note"
    eol_feed = {"feed_version": "vX", "components": {
        "old": {"eol_date": "2020-01-01", "source": "s", "base_lef": (1, 1, 2), "base_lm_gbp": (1_000, 1_000, 2_000)},
        "big": {"eol_date": "2030-01-01", "source": "s", "base_lef": (1, 2, 4), "base_lm_gbp": (1_000, 1_000, 2_000)}}}
    # on old's EOL day nothing has ramped: old 1*1000=1000 < big 2*1000=2000 -> big
    assert "big@" in eol_scenario(eol_feed, None, "2020-01-01")["name"]
    # four years on, old ramps 5.0 (capped): 5000 > big's 2000 -> the headline moved with --as-of
    assert "old@" in eol_scenario(eol_feed, None, "2024-01-01")["name"]
    checked += 4

    # Eco-system ticket 79 item 4: this copy is the FALLBACK for a feeds checkout
    # from before the move. It must price exactly what the publisher's own copy
    # prices, so where a feeds checkout is present the two are run over the same
    # payloads and compared. A checkout that is not there is a named absence.
    feeds_converter = os.path.join(root, "..", "..", "feeds",
                                    "threat-register", "to_fair_scenario.py")
    if os.path.isfile(feeds_converter):
        import importlib.util
        spec = importlib.util.spec_from_file_location("feeds_threat_converter", feeds_converter)
        pub = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pub)
        agreed = 0
        for path in sorted(glob.glob(os.path.join(
                os.path.dirname(feeds_converter), "v*/feed.json"))):
            payload = json.load(open(path))["payload"]
            for inst in payload["institutions"]:
                mine = threat_scenario(payload, inst)
                theirs = pub.threat_scenario(payload, inst)
                if mine != theirs:
                    # Review F7: a named refusal, not a tuple dump. A reader has
                    # to be able to see WHICH field drifted without re-running it.
                    fields = sorted(k for k in set(mine) | set(theirs)
                                    if mine.get(k) != theirs.get(k))
                    detail = "; ".join(
                        f"{k}: this copy says {mine.get(k)!r}, the publisher's says "
                        f"{theirs.get(k)!r}" for k in fields)
                    raise AssertionError(
                        f"{os.path.relpath(path, root)} institutions.{inst}: this FALLBACK copy "
                        f"and the publisher's own threat-register converter no longer agree, so "
                        f"a composition against a pre-move feeds checkout would price something "
                        f"the publisher does not publish. Fields that differ -- {detail}")
                agreed += 1
        assert agreed >= 9, f"only compared {agreed} scenarios against the publisher's converter"
        print(f"ok  this fallback copy and the publisher's own threat-register converter agree "
              f"byte-for-byte on all {agreed} published (version, institution) scenarios. WHAT "
              f"THIS RESTS ON (review F7, corrected by review N5): the runner is the FEEDS "
              f"repository's own `verify-feeds.sh`, which invokes this selfcheck; the hub's gate "
              f"manifest carries `.estate-clone/platform/feeds/verify-feeds.sh`, and "
              f".estate-clone always holds a feeds tree beside platform, so the agreement IS "
              f"asserted on every full-estate gate run. What still does not assert it is "
              f"PLATFORM's own CI: no workflow in this repository runs this selfcheck and none "
              f"clones feeds beside it")
    else:
        print(f"ok  no feeds checkout at {os.path.relpath(feeds_converter, root)}, so the "
              f"fallback copy could NOT be compared with the publisher's own converter. A named "
              f"absence and not a pass about it: on this run nothing checked that the two agree "
              f"(review F7)")

    assert checked >= 9, f"expected to check every feed-version x entry, only checked {checked}"
    print(f"ok  {checked} feed entries valid (lo<=mode<=hi); headline pick deterministic and "
          f"named; EOL ramp monotonic & capped "
          f"(1yr={r_1yr:.2f}x 2yr={r_2yr:.2f}x 10yr={r_10yr:.2f}x)")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    pt = sub.add_parser("threat", help="threat-register feed -> scenario")
    pt.add_argument("feed")
    pt.add_argument("institution")
    pt.add_argument("-o", "--out")

    pc = sub.add_parser("cve", help="cve feed -> scenario (omit cve_id: the feed's headline entry)")
    pc.add_argument("feed")
    pc.add_argument("cve_id", nargs="?", default=None)
    pc.add_argument("-o", "--out")

    pe = sub.add_parser("eol", help="eol feed -> scenario (time-varying; omit component: the headline as of --as-of)")
    pe.add_argument("feed")
    pe.add_argument("component", nargs="?", default=None)
    pe.add_argument("--as-of", default=datetime.date.today().isoformat())
    pe.add_argument("-o", "--out")

    sub.add_parser("selfcheck", help="assert every feed entry yields a valid triple + EOL ramp behaves")

    args = p.parse_args(argv)

    if args.cmd == "selfcheck":
        selfcheck()
        return

    with open(args.feed) as fh:
        feed = json.load(fh)

    if args.cmd == "threat":
        scenario = threat_scenario(feed, args.institution)
    elif args.cmd == "cve":
        scenario = cve_scenario(feed, args.cve_id)
    elif args.cmd == "eol":
        scenario = eol_scenario(feed, args.component, args.as_of)
    else:
        sys.exit(f"unknown cmd {args.cmd}")

    out = json.dumps(scenario, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(out + "\n")
    else:
        print(out)


if __name__ == "__main__":
    main()
