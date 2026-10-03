"""CVE version comparisons preserve named absences on either side of the move."""
import json
from pathlib import Path
import tempfile
import unittest

import composition


class FeedPriceTransitions(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tree = Path(temporary.name)
        self.cve = 'CVE-2021-44228'
        self.inventory = {
            'schema_version': '1.0.0',
            'images': [{'image': 'example@sha256:' + 'a' * 64,
                        'digest': 'sha256:' + 'a' * 64,
                        'scanner_version': '0.69.3',
                        'database_date': '2026-10-03T00:00:00Z',
                        'vulnerabilities': [{'id': self.cve, 'package': 'log4j',
                                             'installed_version': '2.14.1',
                                             'fixed_version': '2.17.1',
                                             'severity': 'critical'}]}],
        }
        for version, entries in [('v1', {}), ('v2', {self.cve: {
            'component': 'Apache Log4j', 'cvss': 10, 'severity': 'critical',
            'epss': 0.9, 'source': 'declared regression fixture',
        }})]:
            directory = self.tree / 'cve' / version
            directory.mkdir(parents=True)
            (directory / 'feed.json').write_text(json.dumps({
                'feed_version': version, 'severity_lm_gbp': {'critical': [100, 200, 300]},
                'cves': entries,
            }))

    def price(self, previous, current, *, inventory=True, currency='GBP'):
        return composition.price_parent(
            {'party': 'fixture-feeds', 'kind': 'feed', 'name': 'cve', 'version': current},
            'tuppence', 10000, self.tree, previous,
            perspective_doc={'size': {'customers': 10}}, reporting_currency=currency,
            band_currency=currency, floor=None, inventory=self.inventory if inventory else None,
        )

    def test_previously_absent_intersection_can_be_priced_without_a_fabricated_old_price(self):
        row = self.price('v1', 'v2')
        self.assertGreater(row['amount'], 0)
        self.assertEqual(row['new_price'], row['amount'])
        self.assertEqual(row['priced_cve'], self.cve)
        self.assertIsNone(row['old_price'])
        self.assertIsNone(row['old_tier'])
        self.assertIn(row['proposed_tier'], composition._cage_engine().ORDER)
        self.assertFalse(row['changed'], 'an absent old tier provides no measured tier comparison')
        self.assertTrue(row['old_absence_only'])
        self.assertIn('No scanned CVE', row['old_could_not_look'])

    def test_newly_absent_intersection_retains_the_known_old_price_and_no_new_zero(self):
        row = self.price('v2', 'v1')
        previous = self.price('v2', 'v2')
        self.assertEqual(row['old_price'], previous['new_price'])
        self.assertEqual(row['old_tier'], previous['proposed_tier'])
        self.assertIsNone(row['new_price'])
        self.assertIsNone(row['amount'])
        self.assertIsNone(row['proposed_tier'])
        self.assertIsNone(row['per_customer'])
        self.assertTrue(row['absence_only'])
        self.assertFalse(row['changed'])
        self.assertEqual(row['absences'], [
            {'id': self.cve, 'amount': None, 'reason': 'outside pinned KEV feed'}])

    def test_both_absent_intersections_remain_unpriced(self):
        row = self.price('v1', 'v1')
        for field in ('amount', 'old_price', 'new_price', 'old_tier', 'proposed_tier'):
            self.assertIsNone(row[field], field)
        self.assertTrue(row['absence_only'])
        self.assertFalse(row['changed'])

    def test_two_priced_intersections_retain_their_measured_comparison(self):
        row = self.price('v2', 'v2')
        self.assertGreater(row['amount'], 0)
        self.assertEqual(row['old_price'], row['new_price'])
        self.assertEqual(row['old_tier'], row['proposed_tier'])
        self.assertFalse(row['changed'])
        self.assertNotIn('old_absence_only', row)

    def test_a_known_old_price_still_requires_an_actual_currency_conversion(self):
        with self.assertRaises(composition.Refused):
            self.price('v2', 'v1', currency='USD')

    def test_missing_inventory_remains_a_refused_instrument(self):
        with self.assertRaisesRegex(composition.Refused, 'missing instrument.*inventory'):
            self.price('v1', 'v2', inventory=False)

    def test_a_malformed_scenario_still_refuses_in_the_price_engine(self):
        with self.assertRaisesRegex(SystemExit, 'no.*warn.*block'):
            composition._cage_engine().select({'name': 'malformed'}, 'tuppence', 10000, mode='warn')


if __name__ == '__main__':
    unittest.main()
