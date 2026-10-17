"""Quote validity through public pricing, composition, replay and handbook seams.

The unchanged quote fixture is insurer/quote/driftwood/v1/feed.json from public
ff40f72d6cf2169926bdbd0ec9f84ea796745b11 (tree5683eb5c5abe7411c954dc79c41a387babdf3352).
Boundary dates and mutated instruments are offline test cases, never observations.
No mock of price_quote, no wall clock and no signature claim is involved.
"""
import json
from pathlib import Path
import tempfile
import unittest

import yaml

import composition as ct
import handbook
import test_portable_observations as fixtures


QUOTE = Path(__file__).parent / 'fixtures/quote-validity/driftwood-v1.json'


class QuoteValidity(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.publisher = self.root / 'publisher'
        self.feed = self.publisher / 'quote/driftwood/v1/feed.json'
        self.feed.parent.mkdir(parents=True)
        self.feed.write_bytes(QUOTE.read_bytes())
        (self.publisher / 'party.yaml').write_text(yaml.safe_dump({
            'party': 'insurer', 'roles': ['publisher', 'insurer'],
            'publishes': [{'kind': 'feed', 'name': 'quote-driftwood',
                           'path': 'quote/driftwood',
                           'payload_schema': 'quote/payload.schema.json'}]}))
        self.edge = {'party': 'insurer', 'kind': 'feed', 'name': 'quote-driftwood',
                     'version': 'v1', 'since': '2026-08-28'}
        self.party = {'party': 'driftwood', 'reporting_currency': 'GBP',
                      'size': {'customers': 240000}}

    def prices(self, as_of):
        return ct.compute_prices([self.edge], 'driftwood', 40000,
                                 {'insurer': self.publisher}, None,
                                 adopter_dir=self.root, perspective_doc=self.party,
                                 include_switching=False, as_of=as_of)

    def premium(self, as_of):
        return next(p for p in self.prices(as_of) if p['kind'] == 'premium')

    def test_lapsed_quote_reaches_actual_call_site_without_repricing_premium(self):
        entry = self.premium('2027-08-29')
        self.assertEqual(entry['quote_validity']['state'], 'lapsed')
        self.assertEqual(entry['quote_validity']['retention'], 'fully-retained')
        self.assertEqual(entry['amount'], 113403.3)
        self.assertEqual(entry['per_customer'], {'amount': 0.47251375, 'currency': 'GBP'})

    def test_inclusive_boundaries_and_all_existing_entry_values_are_conserved(self):
        baseline = self.premium('2026-08-28')
        original = {k: v for k, v in baseline.items() if k != 'quote_validity'}
        for day, state, retention in (
                ('2026-08-27', 'not-yet-valid', 'fully-retained'),
                ('2026-08-28', 'within-window', 'not-assessed'),
                ('2027-08-28', 'within-window', 'not-assessed'),
                ('2027-08-29', 'lapsed', 'fully-retained')):
            with self.subTest(as_of=day):
                entry = self.premium(day)
                validity = entry.pop('quote_validity')
                self.assertEqual(entry, original)
                self.assertEqual((validity['schema'], validity['as_of'], validity['state'],
                                  validity['retention']), (1, day, state, retention))
                self.assertIn('no transfer credit or retained-loss amount', validity['basis'])
                self.assertIn('Conditions, priced_against matching and claim payability are not '
                              'assessed', validity['basis'])

    def test_newest_input_date_is_used_without_an_override(self):
        self.edge['since'] = '2027-08-29'
        self.assertEqual(self.premium(None)['quote_validity']['state'], 'lapsed')
        self.assertEqual(self.premium(None)['quote_validity']['as_of'], '2027-08-29')

    def test_unknown_time_is_named_without_falling_back_to_today(self):
        # A pre-envelope test instrument has no published_at and the edge has no since.
        self.feed.write_text(json.dumps(json.loads(QUOTE.read_text())['payload']))
        del self.edge['since']
        validity = self.premium(None)['quote_validity']
        self.assertEqual((validity['as_of'], validity['state'], validity['retention']),
                         (None, 'unobserved', 'not-assessed'))
        self.assertEqual(self.premium('invalid')['quote_validity']['state'], 'unobserved')

    def test_missing_malformed_or_backwards_contract_dates_refuse_by_name(self):
        for field, value in (('valid_from', None), ('valid_until', '2027-02-29'),
                             ('valid_from', '2026-13-01'), ('valid_until', '2026-08-27')):
            with self.subTest(field=field, value=value):
                doc = json.loads(QUOTE.read_text())
                doc['payload'][field] = value
                self.feed.write_text(json.dumps(doc))
                with self.assertRaisesRegex(ct.Refused, f'missing instrument: quote-driftwood@v1.*{field}'):
                    self.premium('2026-10-17')

    def test_handbook_shows_evidence_and_names_historical_absence(self):
        files, evidence = handbook._fixture()
        header = yaml.safe_load(files[handbook.HEADER_PATH])
        header['quote-validity-schema'] = 1
        files[handbook.HEADER_PATH] = yaml.safe_dump(header)
        entry = self.premium('2027-08-29')
        evidence['prices'] = [entry]
        page = handbook.render(files, evidence)
        self.assertIn('validity schema1', page)
        self.assertIn('as of 2027-08-29', page)
        self.assertIn('lapsed', page)
        self.assertIn('fully-retained', page)
        self.assertIn(entry['quote_validity']['basis'], page)
        del entry['quote_validity']
        historical = handbook.render(files, evidence)
        self.assertIn('prices[0].quote_validity', historical)
        self.assertIn('this historical premium carries no dated validity assessment', historical)


class QuoteReplay(unittest.TestCase):
    def setUp(self):
        self.inputs = QuoteValidity()
        self.inputs.setUp()
        self.addCleanup(self.inputs.doCleanups)
        self.fixture = fixtures.PublisherFixture()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.trees['insurer'] = self.inputs.publisher
        path = self.fixture.adopter / 'party.yaml'
        party = yaml.safe_load(path.read_text())
        party['party'] = 'driftwood'
        party['inherits'].append(self.inputs.edge)
        path.write_text(yaml.safe_dump(party))

    def save(self, doc, rendered):
        self.fixture.save(rendered)
        (self.fixture.adopter / 'composed/evidence.json').write_text(json.dumps(doc))

    def test_saved_composition_replays_exact_state_and_detects_changed_handbook(self):
        doc, rendered = self.fixture.composed(as_of='2027-08-29')
        self.assertEqual(yaml.safe_load(rendered['composed/HEADER.yaml'])['quote-validity-schema'], 1)
        self.save(doc, rendered)
        replay, rerendered = ct.compose(self.fixture.adopter, self.fixture.trees,
                                       as_of='2027-08-29', replay_observations=True)
        self.assertEqual(replay['prices'], doc['prices'])
        self.assertEqual(rerendered, rendered)
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))
        page = self.fixture.adopter / handbook.HANDBOOK_PATH
        page.write_text(page.read_text().replace('fully-retained', 'transferred'))
        ok, differences = ct.verify(self.fixture.adopter, self.fixture.trees)
        self.assertFalse(ok)
        self.assertTrue(any('HANDBOOK.md' in line for line in differences))

    def test_legacy_contract_replays_absence_and_rejects_present_unknown_versions(self):
        doc, rendered = self.fixture.composed(as_of='2027-08-29')
        header = yaml.safe_load(rendered['composed/HEADER.yaml'])
        del header['quote-validity-schema']
        rendered['composed/HEADER.yaml'] = ct.HEADER_COMMENT + yaml.safe_dump(header, **ct.YAML_KWARGS)
        next(p for p in doc['prices'] if p['kind'] == 'premium').pop('quote_validity')
        # Explicit unsigned fixture of the pre-schema contract, not a historical signature.
        rendered[handbook.HANDBOOK_PATH] = handbook.render(rendered, doc)
        self.save(doc, rendered)
        replay, rerendered = ct.compose(self.fixture.adopter, self.fixture.trees,
                                       as_of='2027-08-29', replay_observations=True)
        self.assertNotIn('quote_validity', next(p for p in replay['prices'] if p['kind'] == 'premium'))
        self.assertEqual(rerendered, rendered)
        self.assertEqual(ct.verify(self.fixture.adopter, self.fixture.trees), (True, []))
        for version in (None, 0, 2, True):
            with self.subTest(version=version):
                header['quote-validity-schema'] = version
                (self.fixture.adopter / 'composed/HEADER.yaml').write_text(yaml.safe_dump(header))
                ok, differences = ct.verify(self.fixture.adopter, self.fixture.trees)
                self.assertFalse(ok)
                self.assertIn('unsupported quote-validity-schema', str(differences))


if __name__ == '__main__':
    unittest.main()
