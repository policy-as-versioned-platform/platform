#!/usr/bin/env python3
"""tier_binding.py -- the enacted tier is bound to the priced tier (ticket 78; ADR-0022).

One check, run by each adopter's shift-left.yml on every pull request through the pinned
platform dependency (the same "library, not a service" shape ci-check.py rides) and by the
hub's gate over the real adopters:

    read `proposed_tier` off every prices[] line in the adopter's composed/evidence.json;
    read `posture.acme.io/tier` off the adopter's GOVERNED Namespace manifest, found by its
    `policy-as-versioned.dev/governed: "true"` label and never by a path;
    REFUSE a declaration looser than the strictest priced line, clamped to the party's own
    `overlay.floor`.

Why a second check when the proposer already only tightens: the proposer writes proposals,
and a human edits the Namespace by hand too. This is the pull-request gate that catches the
hand edit -- or a merge that raced a re-price -- before Flux renders a looser cage than the
party's worst-priced regime. A missing declaration is `isolated` by ADR-0022 and binds; an
off-ladder tier cannot be compared and is refused as a missing instrument.

Reads the COMMITTED evidence document: on a pull request the compose-check job regenerates
it and fails on any drift, so the committed copy is the recomposed one by the time this runs.

Exit 0 bound; 1 REFUSED (last line `FAIL: <reason>`); 3 could not look (last line
`SKIP: <reason>`: no evidence document, no governed Namespace, or two of them).

Usage:
    tier_binding.py check --evidence <composed/evidence.json> --adopter-dir <dir>
    tier_binding.py selfcheck
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "wargamer"))
import tier_pr   # noqa: E402  the governed-Namespace reader and the floor reader
import wargamer  # noqa: E402  the ladder and the party fold

LADDER = wargamer.LADDER
FAIL_CLOSED = wargamer.FAIL_CLOSED


def bind(prices: list[dict], declared: str | None, floor: str | None) -> dict:
    """The verdict, as data. `bound` is True when the declaration is at least as
    tight as the strictest priced line clamped to the floor."""
    sel = wargamer.select_party_tier(prices, current=declared, floor=floor)
    required = sel["tier"]
    effective = declared if declared is not None else FAIL_CLOSED
    bound = required is None or LADDER.index(effective) >= LADDER.index(required)
    return {"bound": bound, "declared": declared, "effective": effective, "required": required,
            "strictest_line": sel["strictest_line"], "lines": sel["lines"], "floor": floor,
            "clamped_to_floor": sel["clamped_to_floor"]}


def check(evidence_path: Path, adopter_dir: Path) -> tuple[int, str, dict | None]:
    """(exit code, last line, verdict). Never raises for a shape it can name."""
    if not evidence_path.exists():
        return 3, f"SKIP: {evidence_path} does not exist -- nothing composed to bind against", None
    try:
        prices = json.loads(evidence_path.read_text()).get("prices", [])
    except ValueError as e:
        return 1, f"FAIL: {evidence_path} does not parse: {e}", None
    hits = tier_pr.find_governed_namespaces(adopter_dir)
    if not hits:
        return 3, (f"SKIP: no manifest under {adopter_dir} declares a Namespace carrying "
                   f'{tier_pr.GOVERNED_LABEL}: "true" -- there is no declaration to bind'), None
    if len(hits) > 1:
        rel = ", ".join(str(h.relative_to(adopter_dir)) for h in hits)
        return 3, f"SKIP: {len(hits)} governed Namespace manifests under {adopter_dir} ({rel})", None
    declared = tier_pr.declared_tier(hits[0].read_text())
    floor = tier_pr.read_overlay_floor(adopter_dir / "party.yaml")
    try:
        verdict = bind(prices, declared, floor)
    except ValueError as e:
        return 1, f"FAIL: missing instrument -- {e}", None
    verdict["manifest"] = str(hits[0].relative_to(adopter_dir))
    lines = ", ".join(f"{k}={v}" for k, v in sorted(verdict["lines"].items())) or "none priced"
    where = (f"{verdict['manifest']} declares {declared!r}"
             + (f" (none: {FAIL_CLOSED} by default, ADR-0022)" if declared is None else ""))
    what = (f"strictest priced line {verdict['strictest_line']!r} [{lines}]"
            + (f", clamped to the declared floor {floor!r}" if verdict["clamped_to_floor"] else
               (f", floor {floor!r} does not clamp" if floor else "")))
    if verdict["required"] is None:
        return 0, f"OK: {where}; no line prices a tier, so nothing binds it (unpriced is not loose)", verdict
    if verdict["bound"]:
        return 0, f"OK: {where}; {what}; the declaration is at least as tight -- bound", verdict
    return 1, (f"FAIL: {where}, LOOSER than {what} -- a Namespace cannot carry a tier looser "
               f"than its worst-priced regime (ADR-0022, ticket 78); declare "
               f"{verdict['required']!r} or tighter"), verdict


# --------------------------------------------------------------------------
# selfcheck -- planted declarations, each of which must grade as it must
# --------------------------------------------------------------------------
def selfcheck() -> None:
    import tempfile

    def line(source, tier, kind="feed"):
        return {"source": source, "kind": kind, "proposed_tier": tier, "changed": False}

    def plant(tmp: Path, declared: str | None, prices: list[dict], floor: str | None = None,
              namespace: bool = True) -> tuple[int, str, dict | None]:
        adopter = tmp / "adopter"
        if adopter.exists():
            import shutil
            shutil.rmtree(adopter)
        (adopter / "gitops" / "apps").mkdir(parents=True)
        if namespace:
            (adopter / "gitops" / "apps" / "namespace.yaml").write_text(
                'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n  labels:\n'
                '    policy-as-versioned.dev/governed: "true"\n'
                + (f'    posture.acme.io/tier: "{declared}"\n' if declared else ''))
        if floor:
            (adopter / "party.yaml").write_text(
                f"party: x\nroles: [adopter]\noverlay:\n  add: []\n  floor: {floor}\n")
        ev = tmp / "evidence.json"
        ev.write_text(json.dumps({"prices": prices}))
        return check(ev, adopter)

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        driftwood_today = [line("ico", "isolated"), line("feeds", "baseline"),
                           {"source": "insurer", "kind": "premium", "proposed_tier": None},
                           line("twin", "isolated", kind="twin")]
        # 1. driftwood as committed today: isolated declared over {isolated, baseline, isolated}
        rc, last, v = plant(tmp, "isolated", driftwood_today)
        assert rc == 0 and last.startswith("OK:") and v["bound"], (rc, last)
        assert v["strictest_line"] == "isolated" and "insurer/premium" not in v["lines"], v
        # 2. the hand edit: restricted declared over a party whose worst line is isolated
        rc, last, v = plant(tmp, "restricted", driftwood_today)
        assert rc == 1 and last.startswith("FAIL:") and "LOOSER" in last, (rc, last)
        assert v["required"] == "isolated" and v["bound"] is False, v
        # 3. tighter than priced is fine: quarantine declared over {restricted, baseline}
        rc, last, _ = plant(tmp, "quarantine", [line("ico", "restricted"), line("feeds", "baseline")])
        assert rc == 0, (rc, last)
        # 4. equal is bound: restricted over {restricted, baseline}
        rc, last, _ = plant(tmp, "restricted", [line("ico", "restricted"), line("feeds", "baseline")])
        assert rc == 0, (rc, last)
        # 5. one rung looser than the strictest line refuses
        rc, last, _ = plant(tmp, "baseline", [line("ico", "restricted"), line("feeds", "baseline")])
        assert rc == 1 and "declare 'restricted' or tighter" in last, (rc, last)
        # 6. no declaration is isolated by default (ADR-0022): binds against anything
        rc, last, v = plant(tmp, None, driftwood_today)
        assert rc == 0 and v["effective"] == "isolated", (rc, last, v)
        # 7. the floor binds too: restricted declared, lines say baseline, floor says quarantine
        rc, last, v = plant(tmp, "restricted", [line("ico", "baseline")], floor="quarantine")
        assert rc == 1 and v["clamped_to_floor"] and v["required"] == "quarantine", (rc, last, v)
        rc, last, _ = plant(tmp, "quarantine", [line("ico", "baseline")], floor="quarantine")
        assert rc == 0, (rc, last)
        # 8. an off-ladder declaration is a missing instrument, refused, never guessed
        rc, last, _ = plant(tmp, "paranoid", driftwood_today)
        assert rc == 1 and "missing instrument" in last, (rc, last)
        # 9. nothing priced (a premium-only document) binds nothing and says so
        rc, last, v = plant(tmp, "baseline", [{"source": "insurer", "kind": "premium",
                                                "proposed_tier": None}])
        assert rc == 0 and "nothing binds" in last, (rc, last)
        # 10. could not look: no governed Namespace, no evidence document
        rc, last, _ = plant(tmp, "baseline", driftwood_today, namespace=False)
        assert rc == 3 and last.startswith("SKIP:"), (rc, last)
        rc, last, _ = check(tmp / "absent.json", tmp / "adopter")
        assert rc == 3 and last.startswith("SKIP:"), (rc, last)

    print("ok  tier binding: driftwood's committed shape (isolated over {isolated, baseline, "
          "isolated}) is bound; restricted or baseline over a stricter line is REFUSED and told "
          "what to declare; tighter or equal is bound; no declaration is isolated by default; "
          "the declared floor binds; an off-ladder tier is a missing instrument; a premium-only "
          "document binds nothing and says so; no Namespace or no evidence is could-not-look")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--evidence", type=Path, required=True)
    c.add_argument("--adopter-dir", type=Path, required=True)
    sub.add_parser("selfcheck")
    args = p.parse_args(argv[1:])
    if args.cmd == "selfcheck":
        selfcheck()
        return 0
    rc, last, _ = check(args.evidence, args.adopter_dir)
    print(last)
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
