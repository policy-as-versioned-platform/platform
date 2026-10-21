"""The included break-glass verifier does not need the legacy operation selector."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHILD_PROBE = "_PAVC_BREAK_GLASS_FACTORS_WRAPPER_CHILD"


class IndependentFactors(unittest.TestCase):
    @unittest.skipIf(os.environ.get(CHILD_PROBE) == "1", "nested independence fixture deletes the retired entrypoint")
    def test_legacy_read_cannot_grant_access(self) -> None:
        result = subprocess.run([sys.executable, "-B", str(ROOT / "access/access.py"),
                                 "decide", "read", "--oidc"],
                                cwd=ROOT, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("retired", result.stderr)
        self.assertIn("break-glass", result.stderr)

    @unittest.skipIf(os.environ.get(CHILD_PROBE) == "1", "nested independence fixture deletes the retired entrypoint")
    def test_other_legacy_invocations_report_retirement(self) -> None:
        for arguments in ([], ["--help"], ["selfcheck"],
                          ["decide", "write", "--oidc", "--device"],
                          ["decide", "break-glass", "--oidc", "--webauthn", "--device"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, "-B", str(ROOT / "access/access.py"), *arguments],
                                        cwd=ROOT, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("retired", result.stderr)
                self.assertIn("remains shelved", result.stderr)

    @unittest.skipIf(os.environ.get(CHILD_PROBE) == "1", "only the nested wrapper probe avoids recursion")
    def test_verifier_runs_without_the_legacy_operation_selector(self) -> None:
        with tempfile.TemporaryDirectory(prefix="break-glass-factors-") as directory:
            copied = Path(directory)
            for name in ("access", "break-glass", "fair"):
                shutil.copytree(ROOT / name, copied / name,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            (copied / "access/access.py").unlink()
            environment = os.environ.copy()
            environment[CHILD_PROBE] = "1"
            environment.pop("PYTHONPATH", None)
            environment.pop("PYTHONHOME", None)
            result = subprocess.run(["bash", str(copied / "break-glass/verify-break-glass.sh")],
                                    cwd=copied, env=environment, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("break-glass selfcheck: all asserts passed", result.stdout)
            self.assertIn("-- all offline invariants hold --", result.stdout)


if __name__ == "__main__":
    unittest.main()
