"""Alternate assurance bands must be readable before the CLI selects access."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class AlternateBandsCLI(unittest.TestCase):
    def run_cli(self, raw: str | None = None) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, str(HERE / "break-glass.py"), "decide",
                   str(HERE / "scenarios/ludlow-patient-data.json"),
                   "--oidc", "--webauthn", "--device", "none"]
        with tempfile.TemporaryDirectory(prefix="assurance-bands-") as directory:
            if raw is not None:
                path = Path(directory) / "bands.json"
                path.write_text(raw)
                command += ["--bands", str(path)]
            return subprocess.run(command, text=True, capture_output=True, timeout=30)

    def assert_invalid(self, raw: str) -> None:
        result = self.run_cli(raw)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn('"decision"', result.stdout)
        self.assertIn("FAIL: invalid assurance bands:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_nonfinite_attestation_band_refuses_before_a_decision(self) -> None:
        bands = json.loads((HERE / "assurance-bands.json").read_text())
        bands["attest_at"] = float("nan")
        self.assert_invalid(json.dumps(bands))

    def test_each_existing_band_requires_a_finite_number(self) -> None:
        original = json.loads((HERE / "assurance-bands.json").read_text())
        for key in ("step_up_at", "attest_at", "no_cage_at"):
            for invalid in (float("inf"), float("-inf"), True, "100000", None):
                with self.subTest(key=key, invalid=invalid):
                    self.assert_invalid(json.dumps({**original, key: invalid}))
            with self.subTest(key=key, missing=True):
                self.assert_invalid(json.dumps({k: v for k, v in original.items() if k != key}))

    def test_json_number_overflow_refuses_before_a_decision(self) -> None:
        original = json.loads((HERE / "assurance-bands.json").read_text())
        raw = json.dumps({**original, "attest_at": "overflow"}).replace('"overflow"', "1e999")
        self.assert_invalid(raw)

    def test_nonobject_and_malformed_documents_refuse(self) -> None:
        for raw in ("null", "[]", "true", "{"):
            with self.subTest(raw=raw):
                self.assert_invalid(raw)

    def test_finite_alternate_bands_keep_the_default_decision(self) -> None:
        original = json.loads((HERE / "assurance-bands.json").read_text())
        default = self.run_cli()
        for bands in (original, {**original, **{key: float(original[key]) for key in
                      ("step_up_at", "attest_at", "no_cage_at")}}):
            with self.subTest(bands=bands):
                result = self.run_cli(json.dumps(bands))
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (default.returncode, default.stdout, default.stderr))
        value = json.loads(default.stdout)
        self.assertEqual((default.returncode, value["tier"], value["decision"]), (1, 3, "DENY"))


if __name__ == "__main__":
    unittest.main()
