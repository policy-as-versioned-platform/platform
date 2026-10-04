"""Real-adopter fixture copies retain immutable apps objects and a fresh comparison."""
import importlib.util
from pathlib import Path
import subprocess
from unittest.mock import patch
import unittest

import comparison_history
import composition as ct
from fixture_inventory import commit_fixture_state
from test_portable_observations import PublisherFixture


class RealAdopterFixture(unittest.TestCase):
    def test_committed_apps_objects_travel_without_dirty_bytes_or_prior_comparison(self):
        fixture=PublisherFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        adopter=fixture.adopter
        for name in ('twin','selection-policy','composed'):
            (adopter/name).mkdir()
            (adopter/name/'fixture.txt').write_text('committed, deliberately excluded\n')
        commit_fixture_state(adopter,'Record the complete synthetic source declaration')
        before=subprocess.check_output(['git','-C',str(adopter),'rev-parse','HEAD'])
        (adopter/'gitops/apps/inventory-fixture.yaml').write_text('kind: Pod\nspec: {containers: [{image: nginx}]}\n')
        with patch.object(ct,'DEFAULT_ESTATE_CLONE',fixture.root):
            copied=ct._adopter_copy('adopter',fixture.root/'copies')
        spec=importlib.util.spec_from_file_location('fixture_inventory_reader',ct.PLATFORM_DIR/'wargamer/inventory.py')
        reader=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        self.assertEqual(reader.served_images(copied),['example.invalid/declared-fixture@sha256:'+'a'*64])
        self.assertEqual(comparison_history.read_committed(copied),(None,[],[]))
        for name in ('twin','selection-policy','composed'):
            self.assertFalse((copied/name).exists(),name)
        self.assertEqual(subprocess.check_output(['git','-C',str(adopter),'rev-parse','HEAD']),before)
        self.assertIn('nginx',(adopter/'gitops/apps/inventory-fixture.yaml').read_text())


if __name__=='__main__':
    unittest.main()
