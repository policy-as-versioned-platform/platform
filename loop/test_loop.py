"""The unit tests of the contract's 6.1. No network, cluster, git remote or installed package."""
import contextlib
import copy
import io
import json
import math
import pathlib
import random
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import loop
import probe

RUNGS_TEXT = (ROOT / "cage" / "rungs.json").read_text()
PENALTIES_TEXT = (ROOT / "harness" / "fixture" / "penalties.json").read_text()
RUNGS = loop.read_rungs(RUNGS_TEXT)
PENALTIES = json.loads(PENALTIES_TEXT)
NOW = datetime(2026, 11, 15, 6, 52, 10, tzinfo=timezone.utc)
ZEROS = "0" * 40


def pin(name, repo=None, ref="main", commit=ZEROS, comma=","):
    repo = repo or f"policy-as-versioned-{name}/{name}"
    return f'    "{name}": {{"repo": "{repo}", "ref": "{ref}", "commit": "{commit}"}}{comma}'


TOLERANCE_LINE = '  "tolerance": {"amount": 40000, "basis": "fixture 2026-07-31, not owner-declared"},'
PARTY_TEXT = "\n".join([
    "{", '  "note": "A demonstration party.",', '  "party": "driftwood",', '  "currency": "GBP",',
    '  "turnover": 86000000,', '  "turnover_as_of": "2026-06-30",', TOLERANCE_LINE, '  "margin": 0.2,',
    '  "dwell_days": 7,', '  "mode": "measure",', '  "pins": {',
    pin("platform"), pin("ico"), pin("feeds", comma=""), "  }", "}", ""])
PARTY = loop.read_party(PARTY_TEXT)
NAMESPACE = "\n".join([
    "# the governed Namespace", "apiVersion: v1", "kind: Namespace", "metadata:", "  name: shop",
    "  labels:", '    policy-as-versioned.dev/governed: "true"  # the cage reads this',
    '    posture.acme.io/tier: "baseline"', "--- # not governed", "apiVersion: v1", "kind: Namespace",
    "metadata:", "  name: other", ""])


def row(name, events, needs=(), party="driftwood", kind="editorial", loss=(1000, 4000, 9000), penalty=True):
    basis = {"kind": "editorial", "as_of": "2026-11-14", "text": "the publisher's band"}
    return {"id": name, "party": party, "events_a_year": events, "events_basis": dict(basis, kind=kind),
            "loss_an_event": list(loss), "loss_basis": basis,
            "penalty": {"regime": "uk-gdpr", "tier": None} if penalty else None,
            "needs": [{"capability": need, "source": "MITRE ATT&CK"} for need in needs]}


R1 = row("checkout-pii-exfiltration", [2, 4, 9], ["inbound"])
R2 = row("scheduled-agent-misuses-write-credential", [8.4186e-05, 8.4186e-05, 0.00029465], kind="published")
R3 = row("insider-or-lost-device-disclosure", [0.2, 0.4, 0.9])
ROWS = [R1, R2, R3]
FIELDS = ("ts party run commit cause cluster mode pins rung rung_set_by looked why pods capabilities "
          "reference serving rows unpriced exposure cost cost_basis figure tolerance tolerance_basis "
          "margin dwell_days goal unreachable release_ready sourced_share weakest_basis verdict rung_to")


def look(rung, egress="open", inbound="open", ok=3):
    return {"looked": True, "why": "", "rung": rung, "pods": [{"name": "api", "ready": True, "rung": rung}],
            "capabilities": {"egress": egress, "inbound": inbound},
            "reference": {"before": True, "after": True}, "serving": {"ok": ok, "total": 3}}


def cycle(rung, result, rows=ROWS, party=PARTY, penalties=PENALTIES, ledger=()):
    return loop.cycle(party, rung, penalties, {"currency": "GBP", "rows": rows}, RUNGS, result,
                      list(ledger), NOW, "schedule", "throwaway", "1234567890", "c0ffee", "github-actions[bot]")


def counted(rate):
    penalties = copy.deepcopy(PENALTIES)
    penalties["regimes"]["uk-gdpr"].update(penalty_rate=rate, penalty_rate_basis={
        "kind": "counted", "as_of": "2026-11-14", "text": "counted for a test"})
    return penalties


def with_tolerance(amount, dwell_days=7):
    return dict(PARTY, tolerance={"amount": amount, "basis": "test"}, dwell_days=dwell_days)


def ready_since(days):
    stamp = (NOW - timedelta(days=days)).strftime(loop.TS)
    return {"ts": stamp, "verdict": "within", "release_ready": True, "rung": "isolated"}


def command_line(rung, result=None):
    """Run `loop.py cycle` on files. Returns the exit code and the line it wrote."""
    with tempfile.TemporaryDirectory() as tmp:
        files = {"party": PARTY_TEXT, "namespace-file": NAMESPACE.replace("baseline", rung),
                 "penalties": PENALTIES_TEXT, "threats": json.dumps({"currency": "GBP", "rows": ROWS}),
                 "rungs": RUNGS_TEXT}
        if result is not None:
            files["probe"] = json.dumps(result)
        argv = ["cycle", "--cause", "schedule", "--cluster", "throwaway", "--run", "1", "--commit", "c",
                "--rung-set-by", "a person", "--out", f"{tmp}/line.json"]
        for flag, text in files.items():
            pathlib.Path(tmp, flag).write_text(text)
            argv += [f"--{flag}", f"{tmp}/{flag}"]
        with contextlib.redirect_stdout(io.StringIO()):
            code = loop.main(argv)
        return code, json.loads(pathlib.Path(tmp, "line.json").read_text())


def diff(path, removed, added):
    head = [f"diff --git a/{path} b/{path}", "index 1111111..2222222 100644", f"--- a/{path}", f"+++ b/{path}",
            "@@ -8 +8 @@"]
    return "\n".join(head + ["-" + line for line in removed] + ["+" + line for line in added]) + "\n"


def rung_line(rung):
    return f'    posture.acme.io/tier: "{rung}"'


class LoopTest(unittest.TestCase):
    def test_mean(self):
        self.assertEqual(loop.mean(2, 4, 9), 4.5)
        self.assertEqual(round(loop.mean(1000, 4000, 9000), 2), 4333.33)

    def test_mean_penalty(self):
        tiers = PENALTIES["regimes"]["uk-gdpr"]["tiers"]
        self.assertEqual(round(loop.mean_penalty(tiers["higher"], 86000000), 2), 3613638.10)
        self.assertEqual(round(loop.mean_penalty(tiers["lower"], 86000000), 2), 301823.75)
        self.assertEqual(round(loop.mean_penalty(tiers["higher"], 861741000), 2), 32893885.03)

    def test_amounts(self):
        other = row("another-party", [2, 4, 9], party="tuppence")
        priced = loop.price(ROWS + [other], PENALTIES, PARTY)
        self.assertEqual([one["amount"] for one in priced], [16280871.43, 431.49, 1628087.14])
        self.assertEqual([one["bound"] for one in priced], ["upper", "upper", "upper"])
        self.assertRaises(loop.Refused, cycle, "baseline", look("baseline"), rows=[other])
        cited = loop.price([dict(R1, penalty={"regime": "uk-gdpr", "tier": "lower"})], PENALTIES, PARTY)
        self.assertEqual(cited[0]["amount"], 1377706.90)

    def test_figure_at_baseline(self):
        line = cycle("baseline", look("baseline"))
        self.assertEqual(tuple(line), tuple(FIELDS.split()))
        self.assertEqual((line["exposure"], line["cost"], line["figure"]), (17909390.06, 500, 17909890.06))
        self.assertEqual(json.dumps(line["rows"][0]), '{"id": "checkout-pii-exfiltration", '
                         '"amount": 16280871.43, "open": true, "bound": "upper", "needs": ["inbound"]}')
        self.assertEqual((line["goal"], line["unreachable"], line["sourced_share"]), ("isolated", 1603518.63, 0.0))
        self.assertEqual((line["tolerance"], line["ts"]), (40000, "2026-11-15T06:52:10Z"))
        self.assertEqual(line["pins"], {"platform": ZEROS, "ico": ZEROS, "feeds": ZEROS})

    def test_predicted_and_goal(self):
        priced = loop.price(ROWS, PENALTIES, PARTY)
        self.assertEqual(loop.predicted(priced, RUNGS, 1), 17915390.06)
        self.assertEqual(loop.predicted(priced, RUNGS, 2), 1643518.63)
        self.assertEqual(loop.goal(priced, RUNGS, 40000), 2)
        self.assertEqual(loop.predicted(loop.price([R1, R2], PENALTIES, PARTY), RUNGS, 2), 15431.49)

    def test_walk_on_todays_inputs(self):
        line = cycle("baseline", look("baseline"))
        self.assertEqual((line["verdict"], line["rung_to"]), ("tighten", "quarantine"))
        self.assertEqual(command_line("baseline", look("baseline"))[0], 0)
        line = cycle("quarantine", look("quarantine", egress="closed"))
        self.assertEqual((line["figure"], line["verdict"], line["rung_to"]), (17915390.06, "tighten", "isolated"))
        code, line = command_line("isolated", look("isolated", "closed", "closed", ok=0))
        self.assertEqual((line["figure"], line["verdict"], line["rung_to"]), (1643518.63, "saturated", None))
        self.assertEqual((code, line["unreachable"], line["release_ready"]), (2, 1603518.63, False))
        self.assertEqual(line["serving"], {"ok": 0, "total": 3})
        line = cycle("isolated", look("isolated", "closed", "closed", ok=0), ledger=[ready_since(7)])
        self.assertEqual((line["verdict"], line["rung_to"]), ("saturated", None))

    def test_within(self):
        line = cycle("isolated", look("isolated", "closed", "closed"), rows=[R1, R2])
        self.assertEqual((line["figure"], line["verdict"], line["unreachable"]), (15431.49, "within", 0))

    def test_release_after_dwell(self):
        penalties, both = counted(0.0005), look("isolated", "closed", "closed")
        self.assertEqual(loop.predicted(loop.price(ROWS, penalties, PARTY), RUNGS, 0), 30894.49)
        line = cycle("isolated", both, penalties=penalties, ledger=[ready_since(7)])
        self.assertEqual((line["figure"], line["verdict"], line["rung_to"]), (17763.80, "release", "quarantine"))
        waiting = cycle("isolated", both, penalties=penalties, ledger=[ready_since(6)])
        self.assertEqual((waiting["verdict"], waiting["release_ready"]), ("within", True))
        held = cycle("isolated", both, penalties=penalties, party=with_tolerance(35000), ledger=[ready_since(7)])
        self.assertEqual((held["verdict"], held["release_ready"]), ("within", False))
        line = cycle("quarantine", look("quarantine", egress="closed"), penalties=penalties,
                     ledger=[ready_since(7), line])
        self.assertEqual((line["verdict"], line["rung_to"]), ("release", "baseline"))

    def test_unreachable_counts_cost(self):
        line = cycle("isolated", look("isolated", "closed", "closed"), rows=[R1, R2], party=with_tolerance(10000))
        self.assertEqual((line["verdict"], line["unreachable"]), ("saturated", 5431.49))

    def test_cost_stops_a_notch(self):
        rows = [row("one", [1, 1, 1], ["egress"], loss=(3000, 3000, 3000), penalty=False)]
        line = cycle("baseline", look("baseline"), rows=rows, party=with_tolerance(1000))
        self.assertEqual(loop.predicted(loop.price(rows, PENALTIES, PARTY), RUNGS, 1), 6000)
        self.assertEqual((line["figure"], line["verdict"], line["rung_to"]), (3500, "saturated", None))
        self.assertEqual(line["unreachable"], 2500)

    def test_cost_gives_a_notch_back(self):
        met = loop.decide([], RUNGS, "quarantine", {"egress"}, 1000, 0.2, True)
        self.assertEqual((met["figure"], met["verdict"], met["rung_to"]), (6000, "release", "baseline"))
        unmet = loop.decide([], RUNGS, "quarantine", {"egress"}, 1000, 0.2, False)
        self.assertEqual((unmet["verdict"], unmet["rung_to"]), ("saturated", None))

    def test_exactly_at_tolerance_is_within(self):
        self.assertEqual(loop.decide([], RUNGS, "baseline", set(), 500, 0.2, True)["verdict"], "within")

    def test_cage_ineffective(self):
        code, line = command_line("quarantine", look("quarantine"))
        self.assertEqual((code, line["verdict"], line["rung_to"], line["looked"]), (2, "cage-ineffective", None, True))
        self.assertEqual(([one["open"] for one in line["rows"]], line["exposure"]), ([True] * 3, 17909390.06))
        self.assertEqual(line["capabilities"], {"egress": "open", "inbound": "open"})
        line = cycle("quarantine", look("quarantine", inbound="closed"))
        self.assertEqual((line["verdict"], line["exposure"]), ("cage-ineffective", 17909390.06))
        line = cycle("isolated", look("isolated", inbound="closed"))
        self.assertEqual((line["verdict"], line["exposure"]), ("cage-ineffective", 17909390.06))

    def test_closed_but_undeclared_is_could_not_look(self):
        line = cycle("baseline", look("baseline", inbound="closed"))
        self.assertEqual((line["verdict"], line["rung_to"], line["looked"]), ("could-not-look", None, False))
        self.assertEqual((line["rows"][0]["open"], line["exposure"]), (True, 17909390.06))

    def test_could_not_look(self):
        failed = dict(look("baseline"), looked=False, why="the reference could not connect")
        for result in (None, failed, look("quarantine")):
            code, line = command_line("baseline", result)
            self.assertEqual((code, line["verdict"], line["rung_to"], line["looked"]), (3, "could-not-look", None, False))
            self.assertEqual((line["figure"], line["capabilities"], line["serving"]), (17909890.06, None, None))
            self.assertEqual(tuple(line), tuple(FIELDS.split()))
            self.assertTrue(line["why"])
        code, line = command_line("baseline")
        self.assertEqual((line["pods"], line["reference"]), ([], None))
        line = cycle("isolated", dict(look("isolated", "closed", "closed"), looked=False, why="x"))
        self.assertEqual((line["verdict"], line["figure"]), ("could-not-look", 17924390.06))

    def test_within_partial_never_releases(self):
        unknown = row("unknown", None)
        party, closed = with_tolerance(40000, dwell_days=0), look("quarantine", egress="closed")
        line = cycle("quarantine", closed, rows=[unknown], party=party)
        self.assertEqual((line["unpriced"], line["rows"][0]["amount"]), (["unknown"], None))
        self.assertEqual((line["verdict"], line["release_ready"], line["rung_to"]), ("within-partial", True, None))
        line = cycle("baseline", look("baseline"), rows=[unknown, R1], party=party)
        self.assertEqual((line["verdict"], line["rung_to"]), ("tighten", "quarantine"))

    def test_need_without_source_is_ignored(self):
        unsourced = dict(R1, needs=[{"capability": "inbound", "source": ""}, {"capability": "egress"}])
        line = cycle("isolated", look("isolated", "closed", "closed"), rows=[unsourced])
        self.assertEqual((line["rows"][0]["needs"], line["rows"][0]["open"]), ([], True))

    def test_weakest_basis(self):
        line = cycle("baseline", look("baseline"))
        self.assertEqual(line["weakest_basis"], {"kind": "not-counted", "of": "uk-gdpr penalty_rate"})
        line = cycle("baseline", look("baseline"), penalties=counted(0.0005))
        self.assertEqual(line["weakest_basis"], {"kind": "unsourced", "of": "cost of baseline"})

    def test_tolerance(self):
        share = '  "tolerance": {"share_of_turnover": 0.005, "basis": "audit materiality, low end"},'
        self.assertEqual(loop.tolerance(loop.read_party(PARTY_TEXT.replace(TOLERANCE_LINE, share))), 430000)
        both = TOLERANCE_LINE.replace('"amount"', '"share_of_turnover": 0.005, "amount"')
        for line in ("", '  "tolerance": {"basis": "none"},', both):
            with self.assertRaises(loop.Refused):
                loop.read_party(PARTY_TEXT.replace(TOLERANCE_LINE, line))

    def test_party_is_read_strictly(self):
        split = pin("ico").replace('", "commit"', '",\n      "commit"')
        for old, new in (('  "margin": 0.2,', '  "margin": 0.2,\n  "margin": 0.2,'),
                         ('  "margin": 0.2,', '  "margin": 0.2,\n  "floor": "isolated",'),
                         ("86000000", "true"), ('"measure"', '"watch"'), (pin("ico"), split)):
            self.assertIn(old, PARTY_TEXT)
            with self.assertRaises(loop.Refused):
                loop.read_party(PARTY_TEXT.replace(old, new))

    def test_currency_is_never_mixed(self):
        dollars = copy.deepcopy(PENALTIES)
        dollars["regimes"]["uk-gdpr"]["currency"] = "USD"
        with self.assertRaises(loop.Refused):
            loop.price(ROWS, dollars, PARTY)

    def test_fine_rules(self):
        lower = copy.deepcopy(PENALTIES["regimes"]["uk-gdpr"]["tiers"]["lower"])
        self.assertEqual(lower["fines"][0]["status"], "not-collected")
        only_final = dict(lower, fines=lower["fines"][1:])
        self.assertEqual(loop.mean_penalty(lower, 86000000), loop.mean_penalty(only_final, 86000000))
        self.assertIsNone(loop.mean_penalty(dict(lower, fines=lower["fines"][:1]), 86000000))
        del lower["fines"][1]["source"]
        with self.assertRaises(loop.Refused):
            loop.mean_penalty(lower, 86000000)
        undated = dict(R1, events_basis={"kind": "editorial", "text": "no date"})
        with self.assertRaises(loop.Refused):
            loop.price([undated], PENALTIES, PARTY)

    def test_set_rung_changes_one_line(self):
        after = loop.set_rung(NAMESPACE, "quarantine")
        changed = [new for old, new in zip(NAMESPACE.split("\n"), after.split("\n")) if old != new]
        self.assertEqual((changed, loop.read_rung(after)), ([rung_line("quarantine")], "quarantine"))
        self.assertEqual(len(after.split("\n")), len(NAMESPACE.split("\n")))
        self.assertIn("# the governed Namespace", after)
        self.assertIn("# the cage reads this", after)
        governed, other = NAMESPACE.split("--- # not governed\n")
        # Were "--- # comment" no separator, this would read as one governed Namespace.
        split = other + "--- # comment\n" + governed.replace("kind: Namespace", "kind: ConfigMap")
        for text in (NAMESPACE + "---\n" + governed.replace(rung_line("baseline") + "\n", ""),
                     NAMESPACE.replace("baseline", "restricted"), other, split):
            with self.assertRaises(loop.Refused):
                loop.read_rung(text)
        self.assertEqual(loop.read_rung(split.replace("--- # comment\n", "")), "baseline")
        with self.assertRaises(loop.Refused):
            loop.set_rung(NAMESPACE, "restricted")

    def test_check_diff_rung(self):
        path = "gitops/apps/namespace.yaml"
        tighter = diff(path, [rung_line("baseline")], [rung_line("quarantine")])
        looser = diff(path, [rung_line("isolated")], [rung_line("quarantine")])
        self.assertTrue(loop.check_diff(tighter, "rung", "baseline", "quarantine", RUNGS)[0])
        self.assertTrue(loop.check_diff(looser, "rung", "isolated", "quarantine", RUNGS)[0])
        two_lines = diff(path, [rung_line("baseline"), "  name: shop"], [rung_line("quarantine"), "  name: x"])
        two_notches = diff(path, [rung_line("baseline")], [rung_line("isolated")])
        other_file = diff("gitops/apps/pod.yaml", [rung_line("baseline")], [rung_line("quarantine")])
        second_file = tighter + diff("party.json", ['  "mode": "measure",'], ['  "mode": "act",'])
        for text, frm, to in ((two_lines, "baseline", "quarantine"), (two_notches, "baseline", "isolated"),
                              (tighter, "quarantine", "baseline"), (other_file, "baseline", "quarantine"),
                              (second_file, "baseline", "quarantine"), ("", "baseline", "quarantine")):
            self.assertFalse(loop.check_diff(text, "rung", frm, to, RUNGS)[0])

    def test_check_diff_pins(self):
        commit = diff("party.json", [pin("ico")], [pin("ico", commit="a" * 40)])
        ref = diff("party.json", [pin("feeds", comma="")], [pin("feeds", ref="threat-register/v5.0.0", comma="")])
        self.assertTrue(loop.check_diff(commit, "pins")[0])
        self.assertTrue(loop.check_diff(ref, "pins")[0])
        tolerance = diff("party.json", [TOLERANCE_LINE], [TOLERANCE_LINE.replace("40000", "90000000")])
        mode = diff("party.json", [pin("ico"), '  "mode": "measure",'], [pin("ico", commit="a" * 40), '  "mode": "act",'])
        repo = diff("party.json", [pin("ico")], [pin("ico", repo="policy-as-versioned-evil/ico")])
        for text in (tolerance, mode, repo):
            self.assertFalse(loop.check_diff(text, "pins")[0])

    def test_next_pin(self):
        listing = "\n".join(f"{sha * 40}\t{ref}" for sha, ref in (
            ("1", "HEAD"), ("1", "refs/heads/main"), ("2", "refs/heads/observations"),
            ("3", "refs/tags/v6.3.0"), ("4", "refs/tags/cloud/v11.0.1"), ("5", "refs/tags/policy/v7.0.0"),
            ("6", "refs/tags/policy/v8.0.0"), ("7", "refs/tags/policy/v8.0.0^{}"),
            ("8", "refs/tags/policy/v10.1.0"), ("9", "refs/tags/policy/v10.1.0^{}")))
        self.assertEqual(loop.next_pin("main", ZEROS, listing), ("main", "1" * 40))
        self.assertEqual(loop.next_pin("policy/v7.0.0", ZEROS, listing), ("policy/v10.1.0", "9" * 40))

    def test_dwell(self):
        broken = dict(ready_since(3), release_ready=False)
        unseen = dict(ready_since(1), verdict="could-not-look", release_ready=False)
        moved = dict(ready_since(2), rung="quarantine", verdict="release")
        self.assertTrue(loop.dwell_met([ready_since(7), ready_since(6)], NOW, 7))
        self.assertFalse(loop.dwell_met([ready_since(7), broken, ready_since(2)], NOW, 7))
        self.assertTrue(loop.dwell_met([ready_since(7), moved], NOW, 7))
        self.assertTrue(loop.dwell_met([ready_since(7), {"cause": "reset"}, ready_since(6), unseen], NOW, 7))
        self.assertFalse(loop.dwell_met([], NOW, 7))
        self.assertTrue(loop.dwell_met([], NOW, 0))

    def test_monte_carlo_agrees(self):
        rng = random.Random(20261114)
        penalty = loop.mean_penalty(PENALTIES["regimes"]["uk-gdpr"]["tiers"]["higher"], 86000000)

        def pert(lo, mode, hi):
            return lo + rng.betavariate(1 + 4 * (mode - lo) / (hi - lo), 1 + 4 * (hi - mode) / (hi - lo)) * (hi - lo)

        def poisson(rate):
            count, product, limit = 0, rng.random(), math.exp(-rate)
            while product > limit:
                count, product = count + 1, product * rng.random()
            return count

        years = [sum(pert(1000, 4000, 9000) + penalty for _ in range(poisson(pert(2, 4, 9)))) for _ in range(20000)]
        self.assertLess(abs(sum(years) / len(years) / loop.price([R1], PENALTIES, PARTY)[0]["amount"] - 1), 0.02)

    def test_no_deny_and_no_reduction(self):
        for path in (ROOT / "cage").iterdir():
            text = path.read_text()
            self.assertNotIn("Deny", text, path.name)
            self.assertNotIn("validationActions", text, path.name)
        self.assertNotIn("reduce", RUNGS_TEXT)

    def test_loop_runs_no_forge_command(self):
        for path in (HERE / "loop.py", HERE / "probe.py"):
            text = path.read_text()
            self.assertIsNone(re.search(r"(?<![A-Za-z])gh(?![A-Za-z])", text), path.name)
            self.assertNotIn("api.github.com", text, path.name)
            self.assertNotIn("approve", text, path.name)


SINK = "10.96.0.7"


def kube_pod(name, rung=None, is_ready=True, labels=()):
    stamp = {probe.CAGED: "true", probe.TIER: rung} if rung else {}
    return {"metadata": {"name": name, "labels": dict(stamp, **dict(labels))},
            "spec": {"containers": [{"ports": [{"containerPort": 80}]}]},
            "status": {"podIP": "10.244.0.5", "conditions": [{"type": "Ready", "status": str(is_ready)}]}}


class Cluster:
    """A fake kubectl. It answers each call from a table. Connect codes are used up in order."""

    def __init__(self, **changes):
        self.pods = [kube_pod("shop", "quarantine", labels={probe.PROBE: "true"})]
        self.reference = [kube_pod("sink"), kube_pod("client")]
        self.policy_ready, self.netpols, self.slept = True, {"fixture": [], "loop-reference": []}, 0
        self.codes = {"reference": ["0"], "egress": ["0"], "inbound": ["0"]}
        self.codes.update(changes)

    def run(self, args):
        if args[0] == "exec":
            reading = "inbound" if args[8] != SINK else "egress" if args[3] == "shop" else "reference"
            codes = self.codes[reading]
            code = codes.pop(0) if len(codes) > 1 else codes[0]
            return 1, "" if code is None else f"loop-probe-rc={code}\n"
        namespace = args[args.index("-n") + 1] if "-n" in args else None
        governed = {"metadata": {"name": "fixture", "labels": {probe.TIER: "quarantine"}}}
        policy = {"metadata": {"name": "cage-tier-8-0-0"}, "status": {"conditionStatus": {"ready": self.policy_ready}}}
        answer = {"namespaces": {"items": [governed]}, "mutatingpolicies.policies.kyverno.io": {"items": [policy]},
                  "pods": {"items": self.pods if namespace == "fixture" else self.reference},
                  "networkpolicies": {"items": self.netpols.get(namespace, [])},
                  "service": {"spec": {"clusterIP": SINK}}}[args[1]]
        return 0, json.dumps(answer)

    def sleep(self, seconds):
        self.slept += seconds

    def measure(self, settle_seconds=10):
        return probe.measure(self.run, self.sleep, settle_seconds)


class ProbeTest(unittest.TestCase):
    def test_probe_reads_the_marker(self):
        result = Cluster().measure()  # every exec exits 1, and the marker says 0
        self.assertEqual((result["looked"], result["rung"]), (True, "quarantine"))
        self.assertEqual(result["capabilities"], {"egress": "open", "inbound": "open"})
        self.assertEqual((result["serving"], result["reference"]), ({"ok": 1, "total": 1}, {"before": True, "after": True}))
        self.assertEqual(result["pods"], [{"name": "shop", "ready": True, "rung": "quarantine"}])
        for code in (None, "127"):
            result = Cluster(egress=[code]).measure()
            self.assertEqual((result["looked"], result["capabilities"], bool(result["why"])), (False, None, True))

    def test_probe_closed_must_hold(self):
        self.assertEqual(Cluster(egress=["1", "0"]).measure()["capabilities"]["egress"], "open")
        cluster = Cluster(egress=["1"])
        self.assertEqual(cluster.measure()["capabilities"], {"egress": "closed", "inbound": "open"})
        self.assertEqual(cluster.slept, 9)
        cluster = Cluster(egress=["0", "1"], inbound=["0", "0", "1"])
        cluster.netpols["fixture"] = [{"metadata": {"name": "cage-reach-quarantine"}}]
        result = cluster.measure()
        self.assertEqual(result["capabilities"], {"egress": "closed", "inbound": "closed"})
        self.assertEqual((result["serving"], result["looked"]), ({"ok": 0, "total": 1}, True))

    def test_probe_reference_brackets(self):
        for codes, before in ((["1"], False), (["0", "1"], True)):
            cluster = Cluster(reference=codes)
            result = cluster.measure()
            self.assertEqual((result["looked"], result["capabilities"], cluster.slept), (False, None, 27))
            self.assertEqual(result["reference"], {"before": before, "after": False if before else None})

    def test_probe_settle(self):
        unstamped, elsewhere = kube_pod("api"), kube_pod("api", "baseline")
        starting = kube_pod("api", "quarantine", is_ready=False)
        for extra, slept in ((unstamped, 0), (elsewhere, 0), (starting, 10)):
            cluster = Cluster()
            cluster.pods.append(extra)
            self.assertEqual((cluster.measure()["looked"], cluster.slept), (False, slept))
        cluster.pods = []
        self.assertFalse(cluster.measure()["looked"])

    def test_probe_policy_not_ready(self):
        cluster = Cluster()
        cluster.policy_ready = False
        self.assertFalse(cluster.measure()["looked"])

    def test_probe_reference_must_be_uncaged(self):
        cluster = Cluster()
        cluster.reference[1] = kube_pod("client", "quarantine")
        self.assertFalse(cluster.measure()["looked"])
        cluster = Cluster()
        cluster.netpols["loop-reference"] = [{"metadata": {"name": "deny"}}]
        self.assertFalse(cluster.measure()["looked"])


if __name__ == "__main__":
    unittest.main()
