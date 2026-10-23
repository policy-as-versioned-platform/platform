"""Pure shadow routing regressions, no source authentication or financial engine."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import composition as subject
import publisher_reliability as quality

SHADOW = {'party': 'feeds', 'kind': 'feed', 'name': 'recovery-expense', 'version': 'v1', 'since': '2099-01-01'}


class ShadowRecovery(unittest.TestCase):
    def test_exact_family_only_is_intrinsically_diagnostic_without_policy(self):
        self.assertTrue(subject._diagnostic(SHADOW, {}))
        for change in [{'party': 'another-publisher'}, {'name': 'threat-register'}, {'kind': 'controls'}]:
            self.assertFalse(subject._diagnostic({**SHADOW, **change}, {}))

    def test_shadow_cannot_age_existing_financial_inputs(self):
        old = {'party': 'ico', 'kind': 'feed', 'name': 'penalty-schema', 'version': 'v3', 'since': '2026-10-03'}
        self.assertEqual(subject._composition_as_of_source([old, SHADOW], {}),
                         subject._composition_as_of_source([old], {}))

    def test_public_price_seam_never_calls_price_engine_for_shadow(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(subject, 'price_parent', side_effect=AssertionError('shadow entered engine')), \
                 patch.object(subject, 'price_twin', return_value=None), \
                 patch.object(subject, 'price_twin_agent', return_value={'kind': 'TEST_ONLY_existing_twin'}):
                result = subject.compute_prices([SHADOW], 'driftwood', 15, {}, None,
                    adopter_dir=Path(temporary), perspective_doc={'reporting_currency': 'GBP'}, include_switching=False)
                baseline = subject.compute_prices([], 'driftwood', 15, {}, None,
                    adopter_dir=Path(temporary), perspective_doc={'reporting_currency': 'GBP'}, include_switching=False)
                self.assertEqual(result, baseline)

    def test_direct_ordinary_price_and_headline_paths_refuse(self):
        with self.assertRaisesRegex(subject.Refused, 'shadow-only'):
            subject.price_parent(SHADOW, 'driftwood', 15, None, None, perspective_doc={},
                                 reporting_currency='GBP', band_currency=None, floor=None)
        with self.assertRaisesRegex(subject.Refused, 'separate forecast SDK'):
            subject._feed_scenario('recovery-expense', 'v1', 'driftwood', Path('.'), None)

    def test_exact_recovery_converter_binding_rejects_other_source_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); feed = root / 'feed.json'; converter = root / 'converter.py'
            feed.write_bytes(b'TEST_ONLY feed'); converter.write_bytes(b'TEST_ONLY converter')
            admission = object.__new__(quality._Admission)
            target = {'party': 'feeds', 'path': 'recovery-expense/v1/feed.json'}
            admission.records = {('feeds', 'recovery-expense', 'v1'): {'target': target}}
            admission._same_tree = lambda enclosing, path: {**enclosing, 'path': path}
            admission._read = lambda ref, parse: (b'TEST_ONLY feed' if ref['path'].endswith('feed.json')
                else b'TEST_ONLY converter' if ref['path'] == 'recovery-expense/to_fair_scenario.py' else b'WRONG')
            admission.bind_live(SHADOW, feed, converter)
            converter.write_bytes(b'WRONG')
            with self.assertRaisesRegex(quality.Refused, 'converter differs'):
                admission.bind_live(SHADOW, feed, converter)


if __name__ == '__main__':
    unittest.main()
