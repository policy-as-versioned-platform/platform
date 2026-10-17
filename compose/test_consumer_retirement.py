"""An explicit retirement is verified at the real composition seam, never silently ignored."""
from pathlib import Path
import unittest

from test_engine_pairing import EnginePairing


class RetirementComposition(unittest.TestCase):
    def test_an_invalid_explicit_record_cannot_render_the_whole_parent_as_if_it_were_honored(self):
        fixture = EnginePairing()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        records = fixture.adopter / 'implementation-retirements'
        records.mkdir()
        (records / 'fixture-platform.yaml').write_text('schema: 1\nkind: consumer-retirement\n')
        document, rendered = fixture.compose()
        self.assertEqual(document['outcome'], 'refused',
                         'an explicit retirement record was silently ignored')
        self.assertEqual(rendered, {})


if __name__ == '__main__':
    unittest.main()
