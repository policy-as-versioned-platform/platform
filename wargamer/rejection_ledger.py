#!/usr/bin/env python3
"""rejection_ledger.py -- the rejection ledger, DERIVED from closed pull requests.

Ticket 28 answer item 5; ADR-0024 (which supersedes ADR-0015's per-adopter
`rejections.json`). The old ledger was a committed fixture in `platform/honesty/`
that counted rejections; every adopter read platform's copy as its own, so a real
tuppence run would have suppressed a proposal from a file tuppence never wrote.
That file is deleted. The ledger is now computed, every run, from the only record
that cannot drift from what a human actually did: the proposal PRs on the
proposer's own dedupe branch that a human closed WITHOUT merging.

    suppress while  sum(0.5 ** (age_days / h)) >= reject_suppress

`h` and `reject_suppress` are versioned in `rejection-decay.yaml` beside this
file -- a calibration knob, not a literal (the estate's other decay knob is
`twin/decay.yaml`'s 180 days). The key is `<org>/<kind>/<slug>`, so a cage-tier
proposal and a retirement proposal about the same slug are different questions.

A rejected PR whose recorded **curve hash** or **selection-policy version**
differs from today's does not count. A new GBP is a new question: a rejection of
GBP2,000 must not silence a proposal of GBP20,000 (ticket 10, Q5).

**Offline the ledger is EMPTY and the caller is told so.** `derive()` returns
`(ledger, note)`, and the note names the reason the PR list could not be read.
A clock that cannot see the rejections must not silently suppress (it would drop
a real proposal) and must not silently propose (it would re-ask a closed
question) -- it proposes and SAYS the ledger was unavailable. See tier_pr.py,
which prints the note on every run.

Usage:
    rejection_ledger.py derive --repo owner/name [--curve-hash H] [--policy-version V]
    rejection_ledger.py selfcheck
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CALIBRATION = HERE / "rejection-decay.yaml"
BRANCH_PREFIX = "wargamer/"
PR_LIMIT = 100

# The proposer stamps this into every PR body it opens, so a closed PR carries
# the question it was asking. One HTML comment, the same span-marker pattern
# tier_pr.py already uses for issue dedupe and adopter-gate.py for PR bodies.
MARKER = ('<!-- wargamer:ledger key="{key}" curve="{curve_hash}" '
          'policy="{policy_version}" -->')
_MARKER_RE = re.compile(
    r'<!--\s*wargamer:ledger\s+key="([^"]*)"\s+curve="([^"]*)"\s+policy="([^"]*)"\s*-->')


# --- the versioned knob -------------------------------------------------------
def load_calibration(path: Path = CALIBRATION) -> dict:
    """Flat `key: value`, standard library only -- same shape (and the same
    reason) as the feeds repo's per-feed `rule.yaml`: a GitHub runner is not
    promised pyyaml."""
    out: dict = {}
    for line in path.read_text().splitlines():
        if line.lstrip().startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        try:
            value = float(value) if "." in value and value.count(".") == 1 else int(value)
        except ValueError:
            pass
        out[key.strip()] = value
    for required in ("version", "half_life_days", "reject_suppress"):
        if required not in out:
            raise SystemExit(f"FAIL: {path} declares no {required}")
    return out


# --- the key and the marker ---------------------------------------------------
def key(org: str, kind: str, slug: str) -> str:
    """`<org>/<kind>/<slug>` (ADR-0024, D5). `kind` separates a cage-tier
    proposal from a retirement proposal about the same subject."""
    return f"{org}/{kind}/{slug}"


def marker(ledger_key: str, curve_hash: str, policy_version: str) -> str:
    return MARKER.format(key=ledger_key, curve_hash=curve_hash or "",
                         policy_version=policy_version or "")


def parse_marker(body: str) -> tuple[str, str, str] | None:
    found = _MARKER_RE.search(body or "")
    return (found.group(1), found.group(2), found.group(3)) if found else None


def fingerprint(prices: list[dict]) -> dict:
    """Today's proposal shape: the curve the twin published and the version of
    the adopter's own selection-policy package that read it (ADR-0021). Both
    ride on the single `source: twin` price entry composition emits. An adopter
    with no twin overlay yet has an empty fingerprint, which compares equal to
    another empty one -- absence is not a mismatch, it is the same absence."""
    twin = next((p for p in prices if p.get("source") == "twin"), {})
    return {"curve_hash": twin.get("curve_hash") or "",
            "policy_version": twin.get("policy_version") or ""}


# --- deriving -----------------------------------------------------------------
def _age_days(closed_at: str, now: dt.datetime) -> float:
    closed = dt.datetime.fromisoformat(closed_at.replace("Z", "+00:00"))
    return max(0.0, (now - closed).total_seconds() / 86400.0)


def closed_unmerged(repo: str | None) -> list[dict]:
    """Every closed-unmerged PR on a proposer dedupe branch. Raises
    `subprocess.SubprocessError`/`OSError`/`ValueError` when GitHub cannot be
    reached or answers with something that is not the JSON asked for -- derive()
    turns any of those into an empty ledger plus a note, never a silence."""
    cmd = ["gh", "pr", "list", "--state", "closed", "--limit", str(PR_LIMIT),
           "--json", "number,headRefName,closedAt,mergedAt,body"]
    if repo:
        cmd += ["--repo", repo]
    done = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return [pr for pr in json.loads(done.stdout or "[]")
            if not pr.get("mergedAt") and str(pr.get("headRefName", "")).startswith(BRANCH_PREFIX)]


def weigh(prs: list[dict], today: dict, now: dt.datetime, half_life: float) -> dict:
    """Sum the decayed weight of every counting rejection, per key."""
    ledger: dict = {}
    for pr in prs:
        parsed = parse_marker(pr.get("body") or "")
        if not parsed:
            continue                      # a PR that carries no question cannot answer one
        ledger_key, curve_hash, policy_version = parsed
        want = today.get(ledger_key)
        if want is None:
            continue                      # not a question being asked today
        if (curve_hash, policy_version) != (want["curve_hash"], want["policy_version"]):
            continue                      # a new GBP is a new question (ticket 10 Q5)
        weight = 0.5 ** (_age_days(pr["closedAt"], now) / half_life)
        entry = ledger.setdefault(ledger_key, {"count": 0.0, "reasons": []})
        entry["count"] += weight
        entry["reasons"].append(
            f"#{pr['number']} closed unmerged {pr['closedAt'][:10]}, weight {weight:.3f}")
    for entry in ledger.values():
        entry["count"] = round(entry["count"], 4)
    return ledger


def derive(repo: str | None, today: dict, now: dt.datetime | None = None,
           calibration: dict | None = None) -> tuple[dict, str]:
    """(ledger, note). The ledger is in the shape `proposer_bounds.bound()`
    already consumes, so the summed weight lands straight on its `>=
    reject_suppress` test with no second formula anywhere."""
    cal = calibration or load_calibration()
    empty = {"reject_suppress": cal["reject_suppress"], "rejections": {}}
    try:
        prs = closed_unmerged(repo)
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        return empty, (f"ledger UNAVAILABLE: could not read closed pull requests for "
                       f"{repo or 'this repo'} ({str(detail).strip().splitlines()[-1] if str(detail).strip() else e}). "
                       f"Proposing with an EMPTY ledger -- nothing was suppressed, and that is "
                       f"a stated fact, not a silence.")
    now = now or dt.datetime.now(dt.timezone.utc)
    rejections = weigh(prs, today, now, float(cal["half_life_days"]))
    return ({"reject_suppress": cal["reject_suppress"], "rejections": rejections},
            f"ledger derived from {len(prs)} closed-unmerged proposal PR(s) on "
            f"{repo or 'this repo'}; {len(rejections)} key(s) carry weight; "
            f"half-life {cal['half_life_days']}d, suppress at {cal['reject_suppress']} "
            f"(rejection-decay.yaml {cal['version']}).")


# --- selfcheck ----------------------------------------------------------------
def selfcheck() -> None:
    cal = load_calibration()
    h = float(cal["half_life_days"])
    now = dt.datetime(2026, 8, 28, tzinfo=dt.timezone.utc)
    k = key("driftwood", "cage-tier", "ico-pricing")
    today = {k: {"curve_hash": "sha256:aa", "policy_version": "1.0.0"}}

    def pr(number, days_ago, ledger_key=k, curve="sha256:aa", policy="1.0.0", merged=None):
        return {"number": number, "headRefName": f"{BRANCH_PREFIX}retune-x",
                "mergedAt": merged,
                "closedAt": (now - dt.timedelta(days=days_ago)).isoformat().replace("+00:00", "Z"),
                "body": "text\n" + marker(ledger_key, curve, policy)}

    # 1. the curve is the forgetting curve, not a counter.
    one = weigh([pr(1, 0)], today, now, h)
    assert 0.99 < one[k]["count"] <= 1.0, one
    assert weigh([pr(1, h)], today, now, h)[k]["count"] == 0.5, "one half-life halves it"

    # 2. one rejection suppresses for just UNDER a half-life and then re-raises;
    #    a second rejection holds it quiet for longer. Never a counter.
    suppress_at = float(cal["reject_suppress"])
    assert one[k]["count"] >= suppress_at, ("a fresh rejection suppresses", one)
    lapsed = weigh([pr(1, h + 1)], today, now, h)
    assert lapsed[k]["count"] < suppress_at, ("one rejection re-raises after h days", lapsed)
    pair = weigh([pr(1, h + 1), pr(2, h + 8)], today, now, h)
    assert pair[k]["count"] >= suppress_at, ("repeated rejections suppress longer", pair)
    stale = weigh([pr(1, 4 * h), pr(2, 4 * h)], today, now, h)
    assert stale[k]["count"] < suppress_at, ("a stale pair must re-raise", stale)

    # 3. a different GBP is a different question: neither a moved curve nor a
    #    bumped selection policy counts against today's proposal.
    assert weigh([pr(1, 0, curve="sha256:bb")], today, now, h) == {}, "moved curve must not count"
    assert weigh([pr(1, 0, policy="2.0.0")], today, now, h) == {}, "bumped policy must not count"
    assert weigh([pr(1, 0, ledger_key="tuppence/cage-tier/ico-pricing")], today, now, h) == {}, \
        "another org's rejection is not this org's ledger"

    # 4. a MERGED proposal is not a rejection, and a PR off the dedupe branch is
    #    not a proposal at all.
    merged = dict(pr(9, 0)); merged["mergedAt"] = "2026-08-27T00:00:00Z"
    other = dict(pr(10, 0)); other["headRefName"] = "renovate/some-pin"
    assert [p["number"] for p in _filter(merged, other, pr(11, 0))] == [11], "merged/off-branch drop out"

    # 5. offline: an empty ledger AND a note that says so. Never a silence.
    #    Forced here rather than waited for: `gh` is usually installed, and the
    #    branch that must never regress is the one nobody can arrange on demand.
    me = sys.modules[__name__]
    real, me.closed_unmerged = me.closed_unmerged, _raises
    try:
        ledger, note = derive("owner/name", today, now=now, calibration=cal)
    finally:
        me.closed_unmerged = real
    assert ledger["rejections"] == {}, ledger
    assert "UNAVAILABLE" in note and "EMPTY ledger" in note, note
    # ...and the reachable path says how many PRs it read, so a run is never mute.
    me.closed_unmerged = lambda repo: [pr(1, 0)]
    try:
        ledger, note = derive("owner/name", today, now=now, calibration=cal)
    finally:
        me.closed_unmerged = real
    assert "derived from 1 closed-unmerged" in note, note

    # 6. the fingerprint rides the twin entry, and absence equals absence.
    assert fingerprint([{"source": "twin", "curve_hash": "sha256:aa",
                         "policy_version": "1.0.0"}]) == today[k]
    assert fingerprint([{"source": "ico"}]) == {"curve_hash": "", "policy_version": ""}

    print("ok  the ledger is a decay curve derived from closed-unmerged PRs, keyed "
          "<org>/<kind>/<slug>: one rejection suppresses for just under a half-life then "
          "re-raises, a second holds it longer, a pair four half-lives old re-raises, a "
          "moved curve hash or bumped selection-policy "
          "version does not count, a merged or off-branch PR is not a rejection, and an "
          "unreachable GitHub gives an EMPTY ledger with the reason attached "
          "(h=%s, suppress_at=%s, rejection-decay.yaml %s)"
          % (cal["half_life_days"], cal["reject_suppress"], cal["version"]))


def _filter(*prs):
    """The same filter closed_unmerged() applies to `gh pr list` output."""
    return [p for p in prs
            if not p.get("mergedAt") and str(p.get("headRefName", "")).startswith(BRANCH_PREFIX)]


def _raises(repo):
    """Stands in for an unreachable GitHub inside the selfcheck."""
    raise subprocess.CalledProcessError(1, "gh", stderr="could not resolve host: github.com")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("derive")
    d.add_argument("--repo", default=None)
    d.add_argument("--key", action="append", default=[],
                   help="a <org>/<kind>/<slug> being proposed today (repeatable)")
    d.add_argument("--curve-hash", default="")
    d.add_argument("--policy-version", default="")
    sub.add_parser("selfcheck")
    args = parser.parse_args(argv[1:])
    if args.cmd == "selfcheck":
        selfcheck()
        return 0
    today = {k: {"curve_hash": args.curve_hash, "policy_version": args.policy_version}
             for k in args.key}
    ledger, note = derive(args.repo, today)
    # The note goes to stderr so stdout is the ledger and nothing else -- a
    # caller redirects the JSON and still SEES why it is empty (ADR-0024).
    print(note, file=sys.stderr)
    print(json.dumps(ledger, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
