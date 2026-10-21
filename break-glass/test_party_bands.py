"""Synthetic party policies exercised only through the public offline CLI."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = Path(__file__).resolve().parent


class PartyBandsCLI(unittest.TestCase):
    def declaration(self):
        return {"party": "fixture", "roles": ["risk-bearer"], "inherits": [],
                "overlay": {"add": [], "restate": []},
                "appetite": {"tolerance": {"amount": 1000, "currency": "GBP"},
                             "assurance_bands": {"currency": "GBP", "step_up_at": 1000,
                                                 "attest_at": 2000, "no_cage_at": 3000}}}

    def run_policy(self, declaration=None, *, raw=None, scenario=None, scenario_raw=None,
                   policy_arguments=None, factors=("--oidc",), interpreter_options=()):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            declaration = self.declaration() if declaration is None else declaration
            raw = (json.dumps(declaration, indent=2) + "\n").encode() if raw is None else raw
            (root / "party.yaml").write_bytes(raw)
            scenario = ({"name": "synthetic fixed operation", "org": "fixture",
                         "lef": [1, 1, 1], "lm": [100, 100, 100]}
                        if scenario is None else scenario)
            (root / "scenario.json").write_text(json.dumps(scenario) if scenario_raw is None else scenario_raw)
            arguments = (["--party-yaml", str(root / "party.yaml")]
                         if policy_arguments is None else policy_arguments)
            result = subprocess.run(
                [sys.executable, *interpreter_options, str(HERE / "break-glass.py"), "decide",
                 str(root / "scenario.json"), *factors, *arguments],
                capture_output=True, text=True, timeout=30)
            return result, raw

    def assert_refused(self, result, reason):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("FAIL: invalid assurance bands:", result.stderr)
        self.assertIn(reason, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_declared_party_bands_control_the_public_decision(self):
        for party, thresholds, expected in (
            ("fixture-loose", [1000, 2000, 3000], (0, 1, "ALLOW")),
            ("fixture-strict", [0, 1, 2], (1, 3, "DENY")),
        ):
            with self.subTest(party=party), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                bands = dict(zip(("step_up_at", "attest_at", "no_cage_at"), thresholds))
                declaration = {
                    "party": party, "roles": ["risk-bearer"], "inherits": [],
                    "overlay": {"add": [], "restate": []},
                    "appetite": {"tolerance": {"amount": 1000, "currency": "GBP"},
                                 "assurance_bands": {"currency": "GBP", **bands}},
                }
                raw = (json.dumps(declaration, indent=2) + "\n").encode()
                (root / "party.yaml").write_bytes(raw)
                scenario = {"name": "synthetic fixed operation", "org": party,
                            "lef": [1, 1, 1], "lm": [100, 100, 100]}
                (root / "scenario.json").write_text(json.dumps(scenario))
                result = subprocess.run(
                    [sys.executable, str(HERE / "break-glass.py"), "decide",
                     str(root / "scenario.json"), "--oidc", "--party-yaml",
                     str(root / "party.yaml")], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, expected[0], result.stdout + result.stderr)
                value = json.loads(result.stdout)
                self.assertEqual((value["tier"], value["decision"]), expected[1:])
                self.assertEqual(value["assurance_policy"], {
                    "party": party, "source_sha256": hashlib.sha256(raw).hexdigest(),
                    "currency": "GBP", **bands,
                })

    def test_explicit_empty_policy_paths_do_not_fall_back_to_the_global_fixture(self):
        for flag in ("--party-yaml", "--bands"):
            with self.subTest(flag=flag):
                result, _ = self.run_policy(policy_arguments=[flag, ""])
                self.assert_refused(result, "assurance bands")

    def test_ambiguous_scenario_party_refuses_instead_of_using_the_last_key(self):
        result, _ = self.run_policy(scenario_raw='{"name":"synthetic", "org":"other", '
                                   '"org":"fixture", "lef":[1,1,1], "lm":[100,100,100]}')
        self.assert_refused(result, "duplicate JSON key")

    def test_legacy_fixture_stays_stdlib_only_and_party_mode_names_its_missing_reader(self):
        normal, _ = self.run_policy(policy_arguments=[])
        stdlib, _ = self.run_policy(policy_arguments=[], interpreter_options=["-S"])
        self.assertEqual((stdlib.returncode, stdlib.stdout, stdlib.stderr),
                         (normal.returncode, normal.stdout, normal.stderr))
        missing, _ = self.run_policy(interpreter_options=["-S"])
        self.assert_refused(missing, "missing instrument: PyYAML")

    def test_missing_explicit_policy_is_not_inferred_from_tolerance(self):
        for missing in ("assurance_bands", "appetite"):
            with self.subTest(missing=missing):
                document = self.declaration()
                if missing == "appetite":
                    del document[missing]
                else:
                    del document["appetite"][missing]
                result, _ = self.run_policy(document)
                self.assert_refused(result, "missing instrument")

    def test_declared_party_and_scenario_org_must_match_exactly(self):
        for org in (None, "other", "FIXTURE", " fixture", 42):
            with self.subTest(org=org):
                scenario = {"name": "synthetic", "lef": [1, 1, 1], "lm": [100, 100, 100]}
                if org is not None:
                    scenario["org"] = org
                result, _ = self.run_policy(scenario=scenario)
                self.assert_refused(result, "scenario.org")

    def test_closed_declaration_and_numeric_policy_refuse_before_pricing(self):
        cases = [("currency", "USD"), ("currency", None), ("unknown", 1)]
        for field in ("step_up_at", "attest_at", "no_cage_at"):
            cases += [(field, value) for value in (True, None, "100", -1, [], {})]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                document = self.declaration()
                document["appetite"]["assurance_bands"][field] = value
                result, _ = self.run_policy(document)
                self.assert_refused(result, "assurance bands")
        for missing in ("currency", "step_up_at", "attest_at", "no_cage_at"):
            with self.subTest(missing=missing):
                document = self.declaration()
                del document["appetite"]["assurance_bands"][missing]
                result, _ = self.run_policy(document)
                self.assert_refused(result, "missing")
        for scalar in (".nan", ".inf", "-.inf", "1e999"):
            with self.subTest(scalar=scalar):
                raw = json.dumps(self.declaration()).replace('"step_up_at": 1000',
                                                            '"step_up_at": ' + scalar).encode()
                result, _ = self.run_policy(raw=raw)
                self.assert_refused(result, "finite")

    def test_same_party_tolerance_is_an_explicit_gbp_instrument(self):
        for value in ({"amount": 1000, "currency": "USD"},
                      {"amount": None, "currency": "GBP"},
                      {"amount": True, "currency": "GBP"}):
            with self.subTest(tolerance=value):
                document = self.declaration()
                document["appetite"]["tolerance"] = value
                result, _ = self.run_policy(document)
                self.assert_refused(result, "tolerance")
        raw = json.dumps(self.declaration()).replace('"amount": 1000', '"amount": .nan').encode()
        result, _ = self.run_policy(raw=raw)
        self.assert_refused(result, "finite")

    def test_strict_schema_and_duplicate_party_keys_refuse(self):
        document = self.declaration()
        document["undeclared"] = "not a party field"
        result, _ = self.run_policy(document)
        self.assert_refused(result, "unknown top-level")
        raw = json.dumps(self.declaration())[:-1] + ', "party": "fixture"}'
        result, _ = self.run_policy(raw=raw.encode())
        self.assert_refused(result, "duplicate party YAML key")

    def test_flags_are_mutually_exclusive_before_files_are_read(self):
        result, _ = self.run_policy(policy_arguments=["--party-yaml", "absent",
                                                      "--bands", "also-absent"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("not allowed with argument", result.stderr)

    def test_equal_and_strict_threshold_boundaries_keep_the_existing_decisions(self):
        # This operation loses exactly100/year, with no unexpected loss/risk load.
        for thresholds, device, expected in (
            ([100, 200, 300], "none", (0, 1, "ALLOW")),
            ([99, 100, 300], "none", (2, 2, "STEP_UP")),
            ([0, 99, 100], "stale", (3, 3, "CAGE")),
            ([0, 99, 99], "stale", (1, 3, "DENY")),
            ([100, 100, 100], "none", (0, 1, "ALLOW")),
        ):
            with self.subTest(thresholds=thresholds, device=device):
                document = self.declaration()
                document["appetite"]["assurance_bands"].update(
                    zip(("step_up_at", "attest_at", "no_cage_at"), thresholds))
                result, _ = self.run_policy(document, factors=["--oidc", "--device", device])
                value = json.loads(result.stdout)
                self.assertEqual((result.returncode, value["tier"], value["decision"]), expected)
                self.assertEqual(value["carried_gbp"], 100)

    def test_hash_covers_captured_raw_metadata_without_changing_the_decision(self):
        raw = json.dumps(self.declaration()).encode()
        first, first_raw = self.run_policy(raw=raw + b"\n# synthetic sourceA\n")
        second, second_raw = self.run_policy(raw=raw + b"\n# synthetic sourceB\n")
        a, b = json.loads(first.stdout), json.loads(second.stdout)
        policy_a, policy_b = a.pop("assurance_policy"), b.pop("assurance_policy")
        self.assertEqual(a, b)
        self.assertEqual(policy_a.pop("source_sha256"), hashlib.sha256(first_raw).hexdigest())
        self.assertEqual(policy_b.pop("source_sha256"), hashlib.sha256(second_raw).hexdigest())
        self.assertEqual(policy_a, policy_b)

    def test_one_source_read_binds_interpretation_and_hash(self):
        # A one-shot FIFO is a real file interface: a second source read blocks
        # rather than quietly hashing bytes different from the declared policy.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "party.yaml"
            os.mkfifo(path)
            raw = json.dumps(self.declaration()).encode()
            scenario = root / "scenario.json"
            scenario.write_text('{"name":"synthetic", "org":"fixture", '
                                '"lef":[1,1,1], "lm":[100,100,100]}')
            def publish_once():
                with path.open("wb") as destination:
                    destination.write(raw)
            writer = threading.Thread(target=publish_once, daemon=True)
            writer.start()
            result = subprocess.run(
                [sys.executable, str(HERE / "break-glass.py"), "decide", str(scenario),
                 "--oidc", "--party-yaml", str(path)],
                capture_output=True, text=True, timeout=5)
            writer.join(timeout=1)
            self.assertFalse(writer.is_alive())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual(value["assurance_policy"]["source_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual((value["tier"], value["decision"]), (1, "ALLOW"))

    def test_the_public_party_validator_uses_the_same_optional_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "party.yaml"
            command = [sys.executable, str(HERE.parent / "party/party_artefact.py"),
                       "check", str(path), "--adopter-dir", str(Path(temp))]
            document = self.declaration()
            path.write_text(json.dumps(document))
            valid = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
            document["appetite"]["assurance_bands"]["attest_at"] = -1
            path.write_text(json.dumps(document))
            invalid = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(invalid.returncode, 1)
            self.assertIn("assurance bands", invalid.stdout + invalid.stderr)
            document = self.declaration()
            document["appetite"]["tolerance"]["currency"] = "USD"
            path.write_text(json.dumps(document))
            currency = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(currency.returncode, 1, currency.stdout + currency.stderr)
            self.assertIn("GBP", currency.stdout + currency.stderr)


class FlatBandsCLI(unittest.TestCase):
    def test_unordered_flat_bands_refuse_before_pricing(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bands.json"
            path.write_text(json.dumps({"step_up_at": 1000000, "attest_at": 100000,
                                        "no_cage_at": 10000}))
            result = subprocess.run(
                [sys.executable, str(HERE / "break-glass.py"), "decide",
                 str(HERE / "scenarios/ludlow-patient-data.json"), "--oidc", "--webauthn",
                 "--device", "fresh", "--bands", str(path)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("ordered", result.stderr)

    def test_flat_duplicate_unknown_negative_and_wrong_currency_tables_refuse(self):
        raw_tables = [
            '{"step_up_at":1,"step_up_at":2,"attest_at":3,"no_cage_at":4}',
            '{"step_up_at":-1,"attest_at":3,"no_cage_at":4}',
            '{"step_up_at":1,"attest_at":3,"no_cage_at":4,"extra":1}',
            '{"step_up_at":1,"attest_at":3,"no_cage_at":4,"currency":"USD"}',
        ]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bands.json"
            for raw in raw_tables:
                with self.subTest(raw=raw):
                    path.write_text(raw)
                    result = subprocess.run(
                        [sys.executable, str(HERE / "break-glass.py"), "decide",
                         str(HERE / "scenarios/ludlow-patient-data.json"), "--oidc",
                         "--webauthn", "--device", "fresh", "--bands", str(path)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("FAIL: invalid assurance bands:", result.stderr)


if __name__ == "__main__":
    unittest.main()
