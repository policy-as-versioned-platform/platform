"""Disposable fixtures retain committed scenario inputs without copying dirt."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import composition
from fixture_inventory import commit_fixture_state


class AdopterFixtureInputs(unittest.TestCase):
    def test_scenarios_come_from_the_committed_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "estate" / "driftwood"
            source.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            (source / "party.yaml").write_text("name: synthetic-fixture\n")
            scenarios = source / "scenarios"
            scenarios.mkdir()
            committed = b'{"id":"synthetic-committed-recovery"}\n'
            (scenarios / "recovery.json").write_bytes(committed)
            commit_fixture_state(source, "Synthetic committed scenario fixture")
            (scenarios / "recovery.json").write_text("dirty working bytes\n")
            (scenarios / "untracked.json").write_text("untracked fixture\n")
            with patch.object(composition, "DEFAULT_ESTATE_CLONE", source.parent):
                copied = composition._adopter_copy("driftwood", root / "copies")
            self.assertTrue((copied / "scenarios/recovery.json").is_file())
            self.assertEqual((copied / "scenarios/recovery.json").read_bytes(), committed)
            self.assertFalse((copied / "scenarios/untracked.json").exists())
            self.assertEqual((scenarios / "recovery.json").read_text(), "dirty working bytes\n")


if __name__ == "__main__":
    unittest.main()
