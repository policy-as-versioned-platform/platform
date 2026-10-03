"""Switching-cost instrument absences are portable across filesystem aliases."""
import json
from pathlib import Path
import tempfile
import unittest

import yaml

import composition


class PortableSwitchingReason(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.adopter = self.root / 'adopter'
        self.edge = {'party': 'fixture-feeds', 'kind': 'feed', 'name': 'eol',
                     'version': 'v1', 'since': '2026-09-01'}
        composition._write_fixture_adopter(self.adopter, 'SMALL', extra_inherits=[self.edge])
        self.party = yaml.safe_load((self.adopter / 'party.yaml').read_text())
        self.alias = self.root / 'adopter-alias'
        self.alias.symlink_to(self.adopter, target_is_directory=True)
        self.publisher = self.root / 'publisher'
        feed = self.publisher / 'eol/v1/feed.json'
        feed.parent.mkdir(parents=True)
        (self.publisher / 'party.yaml').write_text(yaml.safe_dump({
            'party': 'fixture-feeds', 'roles': ['publisher'],
            'publishes': [{'kind': 'feed', 'name': 'eol', 'path': 'eol'}],
        }))
        feed.write_text(json.dumps({
            'feed_version': 'v1', 'currency': 'GBP',
            'components': {'fixture': {'eol_date': '2027-01-01',
                                      'base_lef': [1, 2, 3], 'base_lm_gbp': [100, 200, 300],
                                      'source': 'declared regression fixture'}},
        }))
        twin = self.adopter / 'twin/forward-intel/v1/feed.json'
        twin.parent.mkdir(parents=True)
        twin.write_text(json.dumps({
            'kind': 'feed', 'name': 'forward-intel', 'version': '1.0.0',
            'published_by': self.party['party'], 'published_at': '2026-10-03T00:00:00Z',
            'payload_schema': 'twin/forward-intel/payload.schema.json',
            'payload': {'perspective': self.party['party'], 'currency': 'GBP', 'lef': None,
                        'lm': [10, 20, 30], 'derived_from': [self.edge]},
        }))
        self.trees = {'fixture-feeds': self.publisher}
        self.price = composition.price_parent(
            self.edge, self.party['party'], 40000, self.publisher, None,
            perspective_doc=self.party, reporting_currency='GBP', band_currency='GBP',
            floor=None, composition_as_of='2026-10-03',
        )

    def switching(self, adopter):
        return composition.compute_switching(
            [self.edge], self.party['party'], 40000, self.trees, None,
            adopter_dir=adopter, perspective_doc=self.party, band_currency='GBP',
            floor=None, prev_prices=[], full_prices=[self.price], as_of='2026-10-03',
        )

    def test_real_missing_frequency_refusal_is_identical_through_a_symlink_alias(self):
        actual = self.switching(self.adopter)
        aliased = self.switching(self.alias)
        self.assertEqual(aliased, actual)
        row, = aliased
        self.assertIsNone(row['amount'])
        self.assertIsNone(row['over_pin_life'])
        self.assertTrue(row['could_not_look'].startswith(
            'missing instrument: twin/forward-intel/v1/feed.json supplies no lef'))
        self.assertNotIn(str(self.root), json.dumps(row))
        self.assertEqual(row['unpriceable'][0]['amount'], self.price['amount'])

    def test_declared_parent_paths_normalize_both_lexical_and_resolved_names(self):
        alias = self.root / 'publisher-alias'
        alias.symlink_to(self.publisher, target_is_directory=True)
        text = f'{alias}/eol/v1/feed.json; {alias.resolve()}/eol/v1/feed.json'
        portable = composition._portable_reason(text, self.adopter, {'fixture-feeds': alias})
        self.assertEqual(portable, '<fixture-feeds>/eol/v1/feed.json; <fixture-feeds>/eol/v1/feed.json')

    def test_feed_specific_paths_keep_the_most_specific_declared_source_label(self):
        class Trees(dict):
            pass

        nested = self.adopter / 'vendored/eol'
        nested.mkdir(parents=True)
        alias = self.alias / 'vendored/eol'
        trees = Trees({'fixture-platform': self.alias / 'vendored'})
        trees.feeds = {('fixture-feeds', 'eol', 'v1'): alias}
        text = f'{alias}/feed.json; {alias.resolve()}/feed.json'
        self.assertEqual(composition._portable_reason(text, self.alias, trees),
                         '<fixture-feeds>/feed.json; <fixture-feeds>/feed.json')


if __name__ == '__main__':
    unittest.main()
