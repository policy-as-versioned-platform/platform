"""Eco-system ticket 148 (hub ADR-0033 points 2 and 3): composition prices an unsupported pairing.

An adopter declares its engine in `gitops/engine/kyverno.yaml`. Each composed line supports the
engines in its own `tested_engines` element of the parent's `distribution/versions.yaml`, and the
machinery supports the engines in `distribution/machinery.yaml`. On an engine a line or the
machinery does not support, its claims do not count, so each control it claims is a hole, priced
as ADR-0026 prices one, and an `unsupported-engine` delta names the pairing. No declaration gives
the same price under `undeclared-engine`. A declaration that is present and does not read is a
missing instrument, and it refuses by name. These tests hold that at `compose()`:

  * a supported pairing prints no engine delta, and the header records the declared engine;
  * an undeclared engine gives one `undeclared-engine` delta per line and one for the machinery;
  * an engine only the machinery lists gives one `unsupported-engine` delta, for the line;
  * a retired scope, an absent `tested_engines` and an absent machinery declaration each
    support no engine, and the reason is kept;
  * a control a second, supported line also claims is still a hole (the conservative reading);
  * a claim that stops counting reopens its control as a new hole whose delta says why;
  * every malformed declaration refuses as a missing instrument naming the file;
  * the delta's amount is the sum of the hole prices of the controls it names, or null;
  * the rule that reads `tested_engines` is the grader's own;
  * a composition with an unsupported pairing re-renders byte for byte under `verify()`.

No git, no network. Run: python3 -m unittest discover -s compose -p 'test_engine_pairing.py'
"""
import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

import composition as ct

REAL = ct.PLATFORM_DIR
LINE = "fixture-platform policy 1.0.0"
MACHINERY = "fixture-platform machinery"


def _engine_deltas(doc):
    return [d for d in doc["deltas"] if d["kind"] in ("unsupported-engine", "undeclared-engine")]


class EnginePairing(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.platform = root / "platform"
        self.adopter = root / "adopter"
        self.trees = {"fixture-platform": self.platform, "fixture-nist": root / "nist"}
        ct._write_fixture_catalog(self.trees["fixture-nist"])
        # SMALL selects aa-1, aa-1.1 and aa-2. The line's member-a claims aa-2; the machinery's
        # governed-namespace-requires-claim claims aa-1; aa-1.1 is a hole nobody claims.
        ct._write_fixture_platform(self.platform, REAL, [
            ("aa-2", "member-a"), ("aa-1", "governed-namespace-requires-claim")])
        ct._write_fixture_adopter(self.adopter, "SMALL")

    # ------------------------------------------------------------------ helpers
    def compose(self, outcome="composed"):
        doc, rendered = ct.compose(self.adopter, self.trees)
        self.assertEqual(doc["outcome"], outcome, doc["refusals"])
        return doc, rendered

    def declare(self, version):
        ct._write_engine_declaration(self.adopter, version)

    def machinery_lists(self, *versions):
        path = self.platform.joinpath(*ct.MACHINERY_DECLARATION)
        path.write_text(yaml.safe_dump({"tested_engines": {
            "scope": "every-served-body-v1", "kyverno": list(versions)}}))

    def write_outputs(self, doc, rendered):
        for rel, content in rendered.items():
            path = self.adopter / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (self.adopter / "composed" / "evidence.json").write_text(json.dumps(doc, indent=2))

    def holes(self, doc):
        return {h["control_id"]: h for h in doc["holes"]}

    # ------------------------------------------------------------------ the pairings
    def test_a_supported_pairing_prints_no_engine_delta_and_the_header_records_the_engine(self):
        doc, rendered = self.compose()
        self.assertEqual(_engine_deltas(doc), [])
        self.assertEqual(set(self.holes(doc)), {"aa-1.1"})
        header = yaml.safe_load(rendered["composed/HEADER.yaml"])
        self.assertEqual(header["declared-engine"], {
            "engine": "kyverno", "version": ct.FIXTURE_ENGINE, "file": "gitops/engine/kyverno.yaml"})
        self.assertEqual({p["subject"]: p["status"] for p in doc["engine"]["pairings"]},
                         {LINE: "supported", MACHINERY: "supported"})
        self.assertEqual({p["subject"]: p["controls"] for p in doc["engine"]["pairings"]},
                         {LINE: ["aa-2"], MACHINERY: ["aa-1"]})

    def test_no_declaration_is_priced_under_undeclared_engine(self):
        self.adopter.joinpath(*ct.ENGINE_DECLARATION).unlink()
        doc, rendered = self.compose()
        deltas = {d["subject"]: d for d in _engine_deltas(doc)}
        self.assertEqual(set(deltas), {LINE, MACHINERY})
        for d in deltas.values():
            self.assertEqual(d["kind"], "undeclared-engine")
            self.assertIsNone(d["engine"])
            self.assertEqual((d["perspective"], d["currency"]), ("fixture-adopter14", "GBP"))
        self.assertEqual([c["control_id"] for c in deltas[LINE]["controls"]], ["aa-2"])
        self.assertEqual([c["control_id"] for c in deltas[MACHINERY]["controls"]], ["aa-1"])
        self.assertEqual(set(self.holes(doc)), {"aa-1", "aa-1.1", "aa-2"})
        self.assertEqual(self.holes(doc)["aa-2"]["uncounted_claims"], [LINE])
        self.assertIsNone(yaml.safe_load(rendered["composed/HEADER.yaml"])["declared-engine"])
        self.assertEqual({p["status"] for p in doc["engine"]["pairings"]}, {"undeclared"})

    def test_an_engine_only_the_machinery_lists_prices_the_line_alone(self):
        self.machinery_lists("1.18.2", "1.19.1")
        self.declare("1.19.1")
        doc, _ = self.compose()
        deltas = _engine_deltas(doc)
        self.assertEqual([(d["kind"], d["subject"], d["line"]) for d in deltas],
                         [("unsupported-engine", LINE, "1.0.0")])
        self.assertEqual(deltas[0]["engine"], {"engine": "kyverno", "version": "1.19.1"})
        self.assertEqual(deltas[0]["tested_engines"], [ct.FIXTURE_ENGINE])
        self.assertIn("1.19.1", deltas[0]["detail"])
        self.assertEqual(set(self.holes(doc)), {"aa-1.1", "aa-2"})

    def test_an_engine_nothing_lists_prices_the_line_and_the_machinery(self):
        self.declare("1.19.1")
        doc, _ = self.compose()
        self.assertEqual(sorted((d["kind"], d["subject"]) for d in _engine_deltas(doc)),
                         [("unsupported-engine", MACHINERY), ("unsupported-engine", LINE)])
        self.assertEqual(set(self.holes(doc)), {"aa-1", "aa-1.1", "aa-2"})

    def test_a_retired_scope_supports_no_engine(self):
        ct._write_versions_yaml(self.platform, [{
            "version": "1.0.0", "tag": "policy/v1.0.0", "commit": "e" * 40,
            "tested_engines": {"scope": "published-cage-fixtures-v1", "kyverno": [ct.FIXTURE_ENGINE]}}])
        doc, _ = self.compose()
        (line,) = [p for p in doc["engine"]["pairings"] if p["subject"] == LINE]
        self.assertEqual((line["status"], line["tested_engines"]), ("unsupported", None))
        self.assertIn("published-cage-fixtures-v1", line["reason"])
        self.assertEqual([d["subject"] for d in _engine_deltas(doc)], [LINE])

    def test_a_line_with_no_tested_engines_supports_no_engine(self):
        ct._write_versions_yaml(self.platform, [
            {"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "e" * 40}], supported=None)
        doc, _ = self.compose()
        (line,) = [p for p in doc["engine"]["pairings"] if p["subject"] == LINE]
        self.assertEqual(line["status"], "unsupported")
        self.assertIn("declares no tested_engines", line["reason"])

    def test_a_platform_with_no_machinery_declaration_supports_no_engine_for_the_machinery(self):
        self.platform.joinpath(*ct.MACHINERY_DECLARATION).unlink()
        doc, _ = self.compose()
        deltas = _engine_deltas(doc)
        self.assertEqual([d["subject"] for d in deltas], [MACHINERY])
        self.assertIn("distribution/machinery.yaml is absent", deltas[0]["detail"])
        self.assertIn("aa-1", self.holes(doc))

    def test_a_control_a_supported_line_also_claims_is_still_a_hole(self):
        # Two lines both carry member-a, so the one claim on aa-2 belongs to both. Only 2.0.0
        # supports 1.19.1. A workload claiming 1.0.0 is governed by a body priced as not loading,
        # so aa-2 is not implemented for it: the conservative reading (ticket 148, delegated).
        ct._write_versions_yaml(self.platform, [
            {"version": "1.0.0", "tag": "policy/v1.0.0", "commit": "e" * 40},
            {"version": "2.0.0", "tag": "policy/v2.0.0", "commit": "d" * 40,
             "tested_engines": {"scope": "every-served-body-v1", "kyverno": ["1.18.2", "1.19.1"]}}])
        ct._write_admission_doc(self.platform / "distribution" / "policies" / "v2.0.0" / "member-a.yaml",
                                "ValidatingPolicy", "member-a-2-0-0", "fam-a", "2.0.0",
                                validation_actions=["Audit"])
        self.machinery_lists("1.18.2", "1.19.1")
        self.declare("1.19.1")
        doc, _ = self.compose()
        self.assertEqual([d["subject"] for d in _engine_deltas(doc)], [LINE])
        self.assertEqual(self.holes(doc)["aa-2"]["uncounted_claims"], [LINE])

    def test_a_claim_that_stops_counting_opens_a_new_hole_that_says_why(self):
        doc, rendered = self.compose()
        self.write_outputs(doc, rendered)
        self.declare("1.19.1")
        self.machinery_lists("1.18.2", "1.19.1")
        doc, _ = self.compose()
        hole = self.holes(doc)["aa-2"]
        self.assertEqual(hole["status"], "new")
        (delta,) = [d for d in doc["deltas"] if d["kind"] == "new-hole" and d["control_id"] == "aa-2"]
        self.assertIn(f"carried by {LINE}, which do not support the declared engine", delta["detail"])
        self.assertEqual(self.holes(doc)["aa-1.1"]["status"], "recorded")
        # Back on a supported engine the claim counts again, and the hole closes.
        self.write_outputs(doc, _)
        self.declare(ct.FIXTURE_ENGINE)
        doc, _ = self.compose()
        self.assertEqual(self.holes(doc)["aa-2"]["status"], "closed")
        self.assertEqual(_engine_deltas(doc), [])

    def test_an_unsupported_pairing_verifies_byte_for_byte(self):
        self.declare("1.19.1")
        doc, rendered = self.compose()
        self.write_outputs(doc, rendered)
        self.assertEqual(ct.verify(self.adopter, self.trees), (True, []))

    # ------------------------------------------------------------------ the declaration
    def test_every_malformed_declaration_refuses_as_a_missing_instrument(self):
        good = yaml.safe_load(self.adopter.joinpath(*ct.ENGINE_DECLARATION).read_text())
        releases = ct.KYVERNO_RELEASES
        plants = {
            "a range, not a version": lambda d: d.__setitem__("version", ">=1.18"),
            "a version YAML reads as a number": lambda d: d.__setitem__("version", 1.18),
            "a boolean schema": lambda d: d.__setitem__("schema", True),
            "another engine": lambda d: d.__setitem__("engine", "gatekeeper"),
            "a key no reader reads": lambda d: d.__setitem__("chart", "3.8.2"),
            "a missing key": lambda d: d.pop("cli"),
            "an install.yaml of another release": lambda d: d["install"].__setitem__(
                "url", f"{releases}/v9.9.9/install.yaml"),
            "a short install checksum": lambda d: d["install"].__setitem__("sha256", "3dcd43ea"),
            "a CLI archive of another release": lambda d: d["cli"]["linux_x86_64"].__setitem__(
                "file", "kyverno-cli_v9.9.9_linux_x86_64.tar.gz"),
            "no CLI checksum": lambda d: d["cli"]["linux_x86_64"].pop("sha256"),
        }
        path = self.adopter.joinpath(*ct.ENGINE_DECLARATION)
        for name, plant in plants.items():
            with self.subTest(name):
                doc = copy.deepcopy(good)
                plant(doc)
                path.write_text(yaml.safe_dump(doc))
                self.assert_refused_by_name()
        with self.subTest("not YAML"):
            path.write_text("schema: [1\n")
            self.assert_refused_by_name()
        with self.subTest("an empty file"):
            path.write_text("")
            self.assert_refused_by_name()

    def assert_refused_by_name(self):
        doc, _ = self.compose(outcome="refused")
        named = [r for r in doc["refusals"] if r["kind"] == "missing-instrument"
                 and r["subject"] == "gitops/engine/kyverno.yaml"]
        self.assertEqual(len(named), 1, doc["refusals"])
        self.assertIn("missing instrument: gitops/engine/kyverno.yaml", named[0]["detail"])

    # ------------------------------------------------------------------ the arithmetic and the rule
    def test_the_delta_amount_is_the_sum_of_the_hole_prices_of_the_controls_it_names(self):
        subjects = [{"subject": LINE, "party": "p", "line": "1.0.0", "tree": "p@1", "read_from": "x",
                     "tested_engines": ["1.18.2"], "reason": None, "status": "unsupported",
                     "controls": [("n", "a-1"), ("n", "a-2"), ("n", "a-3"), ("n", "z-9")]}]
        holes = [{"source": "n", "control_id": "a-1", "status": "new", "amount": 100.0, "priced_by": "w1"},
                 {"source": "n", "control_id": "a-2", "status": "recorded", "amount": 25.5, "priced_by": "w2"},
                 {"source": "n", "control_id": "a-3", "status": "new", "amount": None, "priced_by": None}]
        selected = {("n", "a-1"), ("n", "a-2"), ("n", "a-3")}
        engine = {"engine": "kyverno", "version": "1.19.1", "file": "gitops/engine/kyverno.yaml"}
        (delta,) = ct.engine_deltas(subjects, engine, holes, selected, "adopter", "GBP")
        self.assertEqual((delta["amount"], delta["priced"]), (125.5, 2))
        z9 = [c for c in delta["controls"] if c["control_id"] == "z-9"][0]
        self.assertEqual((z9["selected"], z9["amount"]), (False, None))
        # No control priced is a named absence, never a zero.
        for h in holes:
            h["amount"], h["priced_by"] = None, None
        (delta,) = ct.engine_deltas(subjects, engine, holes, selected, "adopter", "GBP")
        self.assertEqual((delta["amount"], delta["priced"]), (None, 0))
        self.assertIn("named absence", delta["detail"])

    def test_the_rule_that_reads_tested_engines_is_the_graders(self):
        spec = importlib.util.spec_from_file_location("grader_under_test", ct.ENGINE_GRADER)
        grader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(grader)
        rule = ct._supported_engines_rule()
        for value in (None, [], {"scope": "every-served-body-v1", "kyverno": ["1.18.2"]},
                      {"scope": "every-served-body-v1", "kyverno": ["1.18.2", "1.19.1"]},
                      {"scope": "published-cage-fixtures-v1", "kyverno": ["1.18.2"]},
                      {"scope": "somebody-elses-v1", "kyverno": ["1.18.2"]},
                      {"scope": "every-served-body-v1", "kyverno": [">=1.18"]},
                      {"scope": "every-served-body-v1", "kyverno": []},
                      {"scope": "every-served-body-v1", "kyverno": ["1.18.2", "1.18.2"]}):
            with self.subTest(value=value):
                self.assertEqual(rule(copy.deepcopy(value)), grader.declared_engines(copy.deepcopy(value)))
        self.assertEqual(rule({"scope": "every-served-body-v1", "kyverno": ["1.18.2"]}), (["1.18.2"], None))


if __name__ == "__main__":
    unittest.main()
