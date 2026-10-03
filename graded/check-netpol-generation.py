#!/usr/bin/env python3
"""Grade generated reach documents, including the empty set on an unmatched trigger."""
from pathlib import Path
import importlib.util
import json
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("engine_cells", HERE.parent / "computed-semver/engine_compatibility.py")
cells = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cells)

def main() -> int:
    binary = shutil.which("kyverno")
    if not binary:
        print("SKIP: kyverno CLI unavailable for generated-document comparison")
        return 3
    policy = HERE / "policies/cage-netpol.yaml"
    with tempfile.TemporaryDirectory() as temp:
        fixture = Path(temp) / "fixture"
        shutil.copytree(HERE / "tests/cage-netpol", fixture)
        report = cells.run_generation(fixture, {"family":"cage-netpol", "path":policy}, binary)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["outcome"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())
