#!/usr/bin/env python3
"""The loop: price the rows, add the rung's cost, compare with the tolerance, decide one notch.

Standard library only. It runs no cluster command. Its only subprocesses are
"git ls-remote" and "git diff".
"""
import argparse
import json
import re
import statistics
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

RUNG_LINE = re.compile(r'^    posture\.acme\.io/tier: "(baseline|quarantine|isolated)"$')
PIN_LINE = re.compile(r'^    "(platform|ico|feeds)": \{"repo": "(policy-as-versioned-[a-z]+/[a-z]+)", '
                      r'"ref": "([A-Za-z0-9._/-]+)", "commit": "([0-9a-f]{40})"\},?$')
SEPARATOR = re.compile(r"^---(\s.*)?$")
KIND_NAMESPACE = re.compile(r"""^kind:\s*["']?Namespace["']?\s*$""")
GOVERNED = re.compile(r"""^\s+policy-as-versioned\.dev/governed:\s*["']?true["']?\s*(#.*)?$""")
TAG = re.compile(r"^(.*)v([0-9]+)\.([0-9]+)\.([0-9]+)$")
TS = "%Y-%m-%dT%H:%M:%SZ"
PARTY_KEYS = ("note", "party", "currency", "turnover", "turnover_as_of", "tolerance", "margin",
              "dwell_days", "mode", "pins")
PRICING_STATUS = ("final", "imposed-appeal-unchecked")
ROW_BASIS_KINDS = ("editorial", "published", "counted")
BASIS_KINDS = ("not-counted", "unsourced", "editorial", "published", "counted")  # weakest first
EXIT = {"within": 0, "within-partial": 0, "tighten": 0, "release": 0,
        "saturated": 2, "cage-ineffective": 2, "could-not-look": 3}


class Refused(ValueError):
    """An input is refused. The command exits 1 and writes no line."""


class CouldNotLook(Exception):
    """The loop could not measure. No judgement, no move."""


class CageIneffective(Exception):
    """A capability the current rung declares closed is measured open."""


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and abs(value) < float("inf")


def pounds(amounts):
    """Add amounts that are already whole pence. The rounding only removes binary drift."""
    return round(sum(amounts), 2)


def mean(lo, mode, hi):
    return (lo + 4 * mode + hi) / 6


def _no_duplicates(pairs):
    keys = [key for key, _ in pairs]
    for key in keys:
        if keys.count(key) > 1:
            raise Refused(f"duplicate key {key}")
    return dict(pairs)


def _load(text):
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as error:
        raise Refused(f"not JSON: {error}") from None


def _keys(value, keys, what):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Refused(f"{what}: the keys must be exactly {', '.join(keys)}")


def read_party(text):
    """The party file of 3.1. Nothing has a default."""
    party = _load(text)
    _keys(party, PARTY_KEYS, "party")
    tol = party["tolerance"]
    forms = [key for key in ("amount", "share_of_turnover") if isinstance(tol, dict) and key in tol]
    if len(forms) != 1:
        raise Refused("tolerance: exactly one of amount or share_of_turnover")
    _keys(tol, (forms[0], "basis"), "tolerance")
    strings = [party[key] for key in ("note", "party", "currency", "turnover_as_of")] + [tol["basis"]]
    numbers = [party["turnover"], party["margin"], party["dwell_days"], tol[forms[0]]]
    if not all(isinstance(value, str) for value in strings) or not all(map(is_number, numbers)):
        raise Refused("party: a string or a number is of the wrong type")
    if party["turnover"] <= 0 or not 0 <= party["margin"] < 1 or party["dwell_days"] < 0:
        raise Refused("turnover, margin or dwell_days is out of range")
    if forms[0] == "share_of_turnover" and not 0 < tol[forms[0]] < 1:
        raise Refused("tolerance is out of range")
    if party["mode"] not in ("measure", "act"):
        raise Refused("mode is not measure or act")
    lines = [pin.groups() for pin in map(PIN_LINE.match, text.split("\n")) if pin]
    pins = {name: {"repo": repo, "ref": ref, "commit": commit} for name, repo, ref, commit in lines}
    if party["pins"] != pins or set(pins) != {"platform", "ico", "feeds"}:
        raise Refused("pins: platform, ico and feeds must each be one line in the pin form")
    return party


def read_rungs(text):
    """The ladder of 3.4, loosest first."""
    document = _load(text)
    _keys(document, ("ladder",), "rungs")
    ladder = document["ladder"]
    for rung in ladder:
        _keys(rung, ("rung", "closes", "cost", "cost_basis"), "rung")
        if not is_number(rung["cost"]) or rung["cost"] < 0 or not isinstance(rung["closes"], list) \
                or not isinstance(rung["cost_basis"], str) or not rung["cost_basis"]:
            raise Refused(f"rung {rung['rung']}: it needs a list of closes, a cost and a cost_basis")
    return ladder


def tolerance(party):
    """The loss a year the party will bear, in pounds."""
    tol = party["tolerance"]
    if "amount" in tol:
        return tol["amount"]
    return tol["share_of_turnover"] * party["turnover"]


def mean_penalty(tier, turnover):
    """The mean penalty of one tier at a turnover (3.3). None when no fine prices."""
    pricing = [fine for fine in tier["fines"] if fine.get("status") in PRICING_STATUS]
    if any(not fine.get("source") for fine in pricing):
        raise Refused("a pricing fine has no source")
    if not pricing:
        return None
    amounts = [fine["amount"] for fine in pricing]
    rate, cap = tier["rate"], tier["cap"]
    if not all(map(is_number, [rate, cap, *amounts])):
        raise Refused("a tier's rate, cap or pricing fine amount is not a number")
    median = statistics.median(amounts)
    scale = rate * turnover / cap
    lo, mode, hi = min(amounts) * scale, median * scale, max(cap, 1.2 * max(amounts)) * scale
    hi = min(hi, max(cap, rate * turnover))
    mode = min(mode, hi)
    lo = min(lo, mode)
    return mean(lo, mode, hi)


def _basis_kind(row, key):
    basis = row.get(key)
    if not isinstance(basis, dict) or not all(basis.get(part) for part in ("kind", "as_of", "text")) \
            or basis["kind"] not in ROW_BASIS_KINDS:
        raise Refused(f"row {row.get('id')}: {key} needs a kind, an as_of and a text")
    return basis["kind"]


def price(rows, penalties, party):
    """Price the party's rows (section 1, step 2). An amount of None is an unpriced row."""
    for name, regime in penalties["regimes"].items():
        if regime["currency"] != party["currency"]:
            raise Refused(f"regime {name} is in {regime['currency']}, not {party['currency']}")
    priced = []
    for row in rows:
        if row["party"] != party["party"]:
            continue
        sourced = "editorial" not in (_basis_kind(row, "events_basis"), _basis_kind(row, "loss_basis"))
        bound, penalty = "estimate", 0
        if row["penalty"] is not None:
            regime = penalties["regimes"].get(row["penalty"]["regime"])
            if regime is None:
                raise Refused(f"row {row['id']}: no regime {row['penalty']['regime']}")
            rate, tier = regime["penalty_rate"], row["penalty"]["tier"]
            if rate is not None and not (is_number(rate) and 0 < rate <= 1):
                raise Refused(f"regime {row['penalty']['regime']}: the penalty rate is out of range")
            if tier is not None and tier not in regime["tiers"]:
                raise Refused(f"row {row['id']}: no tier {tier}")
            tiers = regime["tiers"].values() if tier is None else [regime["tiers"][tier]]
            means = [mean_penalty(one, party["turnover"]) for one in tiers]
            # A missing rate is 1. An uncited tier is the tier with the larger mean penalty.
            penalty = None if None in means else (1 if rate is None else rate) * max(means)
            if rate is None or tier is None:
                bound = "upper"
            sourced = sourced and tier is not None and regime["penalty_rate_basis"]["kind"] == "counted"
        amount = None
        if row["events_a_year"] is not None and row["loss_an_event"] is not None and penalty is not None:
            amount = round(mean(*row["events_a_year"]) * (mean(*row["loss_an_event"]) + penalty), 2)
            if not 0 <= amount < float("inf"):
                raise Refused(f"row {row['id']}: {amount} is not a sum of money")
        needs = [need["capability"] for need in row["needs"] if need.get("source")]
        priced.append({"id": row["id"], "amount": amount, "bound": bound, "needs": needs,
                       "sourced": sourced and amount is not None})
    return priced


def _index(rungs, rung):
    names = [one["rung"] for one in rungs]
    if rung not in names:
        raise Refused(f"{rung} is not a rung of the ladder")
    return names.index(rung)


def _declared(rungs, k):
    """The capabilities declared closed at rung k: a rung keeps what the rungs before it close."""
    return {capability for one in rungs[:k + 1] for capability in one["closes"]}


def closed_capabilities(probe, rungs, rung):
    """The capabilities measured closed and declared closed, in the order of section 1, step 6."""
    if probe is None:
        raise CouldNotLook("no probe result")
    if probe.get("looked") is not True:
        raise CouldNotLook(probe.get("why") or "the probe did not look")
    if probe.get("rung") != rung:
        raise CouldNotLook(f"the cluster is at {probe.get('rung')} and git is at {rung}")
    declared = _declared(rungs, _index(rungs, rung))
    measured = probe["capabilities"]
    for capability in sorted(declared):
        if measured.get(capability) == "open":
            raise CageIneffective(f"{rung} declares {capability} closed and it is measured open")
    closed = {capability for capability, state in measured.items() if state == "closed"}
    if declared - closed:
        raise CouldNotLook(f"{', '.join(sorted(declared - closed))} was not measured")
    if closed - declared:
        raise CouldNotLook(f"{', '.join(sorted(closed - declared))} is measured closed and {rung} "
                           "does not declare it closed, so something other than the cage closed it")
    return closed


def exposure(priced, closed):
    """The sum of the amounts of the open rows. Closing any one need closes a row."""
    return pounds(row["amount"] for row in priced
                  if row["amount"] is not None and not closed & set(row["needs"]))


def predicted(priced, rungs, k):
    """The figure rung k would give if exactly what it declares closed were closed."""
    return pounds([exposure(priced, _declared(rungs, k)), rungs[k]["cost"]])


def goal(priced, rungs, limit):
    """The loosest rung predicted at or below the limit, else the rung with the lowest prediction."""
    figures = [predicted(priced, rungs, k) for k in range(len(rungs))]
    for k, figure in enumerate(figures):
        if figure <= limit:
            return k
    return figures.index(min(figures))


def dwell_met(lines, now, dwell_days):
    """Has the ledger been release-ready, without a break, for dwell_days?"""
    if dwell_days <= 0:
        return True
    oldest = None
    for line in reversed(lines):
        if line.get("verdict") in (None, "could-not-look"):
            continue
        if not line.get("release_ready"):
            break
        oldest = datetime.strptime(line["ts"], TS).replace(tzinfo=timezone.utc)
    return oldest is not None and now - oldest >= timedelta(days=dwell_days)


def decide(priced, rungs, rung, closed, tol, margin, dwell_ok):
    """Section 1, steps 3 to 6, after a real look. The first match wins."""
    k = _index(rungs, rung)
    figure = pounds([exposure(priced, closed), rungs[k]["cost"]])
    lowest = min(predicted(priced, rungs, i) for i in range(len(rungs)))
    target = goal(priced, rungs, tol)
    release_ready = goal(priced, rungs, (1 - margin) * tol) < k
    all_priced = all(row["amount"] is not None for row in priced)
    verdict, rung_to = "saturated", None
    if target > k:
        verdict, rung_to = "tighten", rungs[k + 1]["rung"]
    elif all_priced and release_ready and dwell_ok:
        verdict, rung_to = "release", rungs[k - 1]["rung"]
    elif figure <= tol:
        verdict = "within" if all_priced else "within-partial"
    return {"verdict": verdict, "rung_to": rung_to, "goal": rungs[target]["rung"], "figure": figure,
            "unreachable": max(0, pounds([lowest, -tol])), "release_ready": release_ready}


def weakest_basis(rows, penalties, rung):
    """The weakest basis that enters the figure: the open rows, their regimes, the rung's cost."""
    candidates, regimes = [], []
    for row in rows:
        candidates.append((row["events_basis"]["kind"], f"{row['id']} events"))
        candidates.append((row["loss_basis"]["kind"], f"{row['id']} loss"))
        if row["penalty"] is not None and row["penalty"]["regime"] not in regimes:
            regimes.append(row["penalty"]["regime"])
    for regime in regimes:
        kind = penalties["regimes"][regime]["penalty_rate_basis"]["kind"]
        candidates.append((kind, f"{regime} penalty_rate"))
    cost_kind = "unsourced" if rung["cost_basis"].startswith("unsourced:") else "counted"
    candidates.append((cost_kind, f"cost of {rung['rung']}"))
    kind, of = min(candidates, key=lambda candidate: BASIS_KINDS.index(candidate[0]))
    return {"kind": kind, "of": of}


def _rung_line(text):
    """The lines of the file and the index of its one rung line, in its one governed Namespace."""
    lines = text.split("\n")
    documents, start = [], 0
    for i, line in enumerate(lines + ["---"]):
        if SEPARATOR.match(line):
            documents.append(range(start, i))
            start = i + 1
    governed = [document for document in documents
                if any(KIND_NAMESPACE.match(lines[i]) for i in document)
                and any(GOVERNED.match(lines[i]) for i in document)]
    if len(governed) != 1:
        raise Refused(f"{len(governed)} governed Namespaces, not one")
    found = [i for i, line in enumerate(lines) if RUNG_LINE.match(line)]
    if len(found) != 1 or found[0] not in governed[0]:
        raise Refused("the file must hold exactly one rung line, in the governed Namespace")
    return lines, found[0]


def read_rung(text):
    lines, i = _rung_line(text)
    return RUNG_LINE.match(lines[i]).group(1)


def set_rung(text, rung):
    """Change the one rung line. Every other byte stays."""
    lines, i = _rung_line(text)
    lines[i] = f'    posture.acme.io/tier: "{rung}"'
    if not RUNG_LINE.match(lines[i]):
        raise Refused(f"{rung} is not a rung")
    return "\n".join(lines)


def check_diff(diff, kind, frm=None, to=None, ladder=None):
    """Is this "git diff --unified=0" one notch of the rung line, or pin lines only?"""
    path = {"rung": "gitops/apps/namespace.yaml", "pins": "party.json"}[kind]
    lines = diff.split("\n")
    head = [f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}"]
    if lines.pop() or len(lines) < 5 or [lines[0], lines[2], lines[3]] != head:
        return False, f"the diff is not a change to the content of {path} alone"
    if not all(line.startswith(("@@ ", "-", "+")) for line in lines[4:]):
        return False, "the diff holds more than changed lines"
    removed = [line[1:] for line in lines[4:] if line.startswith("-")]
    added = [line[1:] for line in lines[4:] if line.startswith("+")]
    if kind == "rung":
        names = [rung["rung"] for rung in ladder or []]
        if len(lines) != 7 or len(removed) != 1 or len(added) != 1:
            return False, "the diff is not one line removed and one added"
        old, new = RUNG_LINE.match(removed[0]), RUNG_LINE.match(added[0])
        if not old or not new:
            return False, "a changed line is not the rung line"
        if (old.group(1), new.group(1)) != (frm, to):
            return False, f"the diff moves {old.group(1)} to {new.group(1)}, not {frm} to {to}"
        if frm not in names or to not in names or abs(names.index(frm) - names.index(to)) != 1:
            return False, f"{frm} to {to} is not one notch"
        return True, f"one notch, {frm} to {to}"
    old = {pin.group(1): pin.group(2) for pin in map(PIN_LINE.match, removed) if pin}
    new = {pin.group(1): pin.group(2) for pin in map(PIN_LINE.match, added) if pin}
    if len(old) != len(removed) or len(new) != len(added):
        return False, "a changed line is not a pin line"
    if not old or old != new:
        return False, "the pin lines do not pair by name with the repo unchanged"
    return True, f"pin lines only: {', '.join(sorted(old))}"


def next_pin(ref, commit, ls_remote):
    """Where a pin moves to, read from the text "git ls-remote" printed."""
    refs = dict(reversed(line.split("\t")) for line in ls_remote.splitlines() if "\t" in line)
    family = TAG.match(ref)
    if not family:
        return ref, refs.get(f"refs/heads/{ref}", commit)
    best = None
    for name in refs:
        tag = TAG.match(name[len("refs/tags/"):]) if name.startswith("refs/tags/") else None
        if tag and tag.group(1) == family.group(1):
            version = tuple(int(part) for part in tag.groups()[1:])
            if best is None or version > best[0]:
                best = (version, tag.group(0))
    if best is None:
        return ref, commit
    peeled = refs.get(f"refs/tags/{best[1]}^{{}}", refs[f"refs/tags/{best[1]}"])
    return best[1], peeled


def cycle(party, rung, penalties, threats, rungs, probe, ledger, now,
          cause, cluster, run, commit, rung_set_by):
    """Build the ledger line of 3.5 from parsed inputs. Every field, every time."""
    if threats["currency"] != party["currency"]:
        raise Refused(f"the threat feed is in {threats['currency']}, not {party['currency']}")
    here = rungs[_index(rungs, rung)]
    priced = price(threats["rows"], penalties, party)
    if not priced:
        raise Refused(f"the threat feed has no row for {party['party']}")
    looked, why, verdict = True, "", None
    try:
        closed = closed_capabilities(probe, rungs, rung)
    except CageIneffective as error:
        closed, why, verdict = set(), str(error), "cage-ineffective"
    except CouldNotLook as error:
        closed, why, verdict, looked = set(), str(error), "could-not-look", False
    tol = tolerance(party)
    decision = decide(priced, rungs, rung, closed, tol, party["margin"],
                      dwell_met(ledger, now, party["dwell_days"]))
    if verdict:
        decision.update(verdict=verdict, rung_to=None)
    rows = [{"id": row["id"], "amount": row["amount"], "open": not closed & set(row["needs"]),
             "bound": row["bound"], "needs": row["needs"]} for row in priced]
    open_ids = {row["id"] for row in rows if row["open"] and row["amount"] is not None}
    sourced = [row["amount"] for row in priced if row["id"] in open_ids and row["sourced"]]
    open_rows = [row for row in threats["rows"] if row["party"] == party["party"] and row["id"] in open_ids]
    if not here["cost_basis"].startswith("unsourced:"):
        sourced.append(here["cost"])
    figure = decision["figure"]
    return {
        "ts": now.strftime(TS), "party": party["party"], "run": run, "commit": commit,
        "cause": cause, "cluster": cluster, "mode": party["mode"],
        "pins": {name: pin["commit"] for name, pin in party["pins"].items()},
        "rung": rung, "rung_set_by": rung_set_by, "looked": looked, "why": why,
        "pods": probe.get("pods", []) if probe else [],
        "capabilities": probe["capabilities"] if looked else None,
        "reference": probe.get("reference") if probe else None,
        "serving": probe["serving"] if looked else None,
        "rows": rows, "unpriced": [row["id"] for row in priced if row["amount"] is None],
        "exposure": exposure(priced, closed), "cost": here["cost"], "cost_basis": here["cost_basis"],
        "figure": figure, "tolerance": tol, "tolerance_basis": party["tolerance"]["basis"],
        "margin": party["margin"], "dwell_days": party["dwell_days"],
        "goal": decision["goal"], "unreachable": decision["unreachable"],
        "release_ready": decision["release_ready"],
        "sourced_share": pounds(sourced) / figure if figure else 0.0,
        "weakest_basis": weakest_basis(open_rows, penalties, here),
        "verdict": decision["verdict"], "rung_to": decision["rung_to"]}


def _read(path):
    return Path(path).read_bytes().decode("utf-8")


def _git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout.decode("utf-8")


def _cycle(args):
    party = read_party(_read(args.party))
    namespace = _read(args.namespace_file)
    probe = _load(_read(args.probe)) if args.probe else None
    ledger = []
    if args.ledger:
        ledger = [_load(line) for line in _read(args.ledger).splitlines() if line.strip()]
    line = cycle(party, read_rung(namespace), _load(_read(args.penalties)), _load(_read(args.threats)),
                 read_rungs(_read(args.rungs)), probe, ledger, datetime.now(timezone.utc),
                 args.cause, args.cluster, args.run, args.commit, args.rung_set_by)
    moved = args.write and party["mode"] == "act" and line["rung_to"] and set_rung(namespace, line["rung_to"])
    text = json.dumps(line)
    Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    if moved:
        Path(args.namespace_file).write_text(moved, encoding="utf-8")
    return EXIT[line["verdict"]]


def _check_diff(args):
    diff = _git("diff", "--unified=0", "--merge-base", args.base, args.head)
    ladder = read_rungs(_read(args.rungs)) if args.rungs else None
    allowed, reason = check_diff(diff, args.kind, args.frm, args.to, ladder)
    print(reason)
    return 0 if allowed else 1


def _bump_pins(args):
    text = _read(args.party)
    read_party(text)
    lines = text.split("\n")
    for i, line in enumerate(lines):
        pin = PIN_LINE.match(line)
        if pin:
            name, repo, ref, commit = pin.groups()
            new_ref, new_commit = next_pin(ref, commit, _git("ls-remote", f"https://github.com/{repo}"))
            lines[i] = line.replace(f'"ref": "{ref}", "commit": "{commit}"',
                                    f'"ref": "{new_ref}", "commit": "{new_commit}"')
            print(f"{name}: {ref} {commit} to {new_ref} {new_commit}")
    if args.write:
        Path(args.party).write_text("\n".join(lines), encoding="utf-8")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(prog="loop.py", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    one = commands.add_parser("cycle")
    for flag in ("party", "namespace-file", "penalties", "threats", "rungs",
                 "cause", "cluster", "run", "commit", "rung-set-by", "out"):
        one.add_argument(f"--{flag}", required=True)
    one.add_argument("--probe")
    one.add_argument("--ledger")
    one.add_argument("--write", action="store_true")
    one.set_defaults(act=_cycle)
    one = commands.add_parser("check-diff")
    one.add_argument("--kind", required=True, choices=("rung", "pins"))
    one.add_argument("--base", required=True)
    one.add_argument("--head", required=True)
    one.add_argument("--from", dest="frm")
    one.add_argument("--to")
    one.add_argument("--rungs")
    one.set_defaults(act=_check_diff)
    one = commands.add_parser("bump-pins")
    one.add_argument("--party", required=True)
    one.add_argument("--write", action="store_true")
    one.set_defaults(act=_bump_pins)
    try:
        args = parser.parse_args(argv)
    except SystemExit as stop:  # argparse exits 2 on a bad argument, and 2 here means a red verdict
        return 1 if stop.code else 0
    try:
        return args.act(args)
    except (Refused, OSError, subprocess.CalledProcessError) as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
