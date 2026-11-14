"""Actual generated-document seam: removing either gate must change the grade."""
from pathlib import Path
import importlib.util
import os
import shutil
import tempfile
import unittest
import yaml

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cells", HERE / "engine_compatibility.py")
cells = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cells)

class GeneratedDocuments(unittest.TestCase):
    def test_each_generation_gate_is_observed_on_each_available_engine(self):
        folder = HERE.parent / "graded/tests/cage-netpol"
        engine_dir = os.environ.get("KYVERNO_ENGINE_DIR")
        binaries = sorted(Path(engine_dir).glob("*/kyverno")) if engine_dir else []
        if not binaries and shutil.which("kyverno"):
            binaries = [Path(shutil.which("kyverno"))]
        if not binaries:
            self.skipTest("no Kyverno binary available for generated-document proof")
        for binary in binaries:
            for gate in [None, "tier-restricts-reach", "is-caged"]:
                with self.subTest(engine=binary.parent.name, gate=gate), tempfile.TemporaryDirectory() as temp:
                    work = Path(temp)
                    fixture = work / "fixture"
                    shutil.copytree(folder, fixture)
                    policy = yaml.safe_load((HERE.parent / "graded/policies/cage-netpol.yaml").read_text())
                    policy["metadata"]["name"] += "-9-9-9"
                    policy["spec"].setdefault("matchConditions", []).append({"name":"only-this-policy-version", "expression":"object.metadata.?labels['policy-as-versioned.dev/policy-version'].orValue('') == '9.9.9'"})
                    if gate:
                        policy["spec"]["matchConditions"] = [c for c in policy["spec"]["matchConditions"] if c["name"] != gate]
                    path=work / "policy.yaml"
                    path.write_text(yaml.safe_dump(policy, sort_keys=False))
                    body={"family":"cage-netpol", "names":[policy["metadata"]["name"]], "path":path}
                    report=cells.run_legacy_fixture(fixture, body, "9.9.9", str(binary))
                    self.assertEqual(report["outcome"], "failed" if gate else "passed", report)

if __name__ == "__main__":
    unittest.main()
