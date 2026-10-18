"""Quote condition claims through actual public pricing and replay interfaces.

The existing real insurer quote is unchanged. Counted implementation claims are
composition evidence, never proof of fulfilled insurance conditions or payability.
"""
import json
import unittest

import yaml

import composition as ct
import handbook
import test_quote_validity as fixtures


class QuoteConditionClaims(unittest.TestCase):
    def setUp(self):
        self.inputs = fixtures.QuoteValidity()
        self.inputs.setUp()
        self.addCleanup(self.inputs.doCleanups)

    def premium(self, implemented):
        prices = ct.compute_prices(
            [self.inputs.edge], 'driftwood', 40000,
            {'insurer': self.inputs.publisher}, None,
            adopter_dir=self.inputs.root, perspective_doc=self.inputs.party,
            include_switching=False, as_of='2026-10-17', implemented=implemented)
        return next(p for p in prices if p['kind'] == 'premium')

    def test_actual_quote_prices_report_the_counted_condition_claims(self):
        entry = self.premium({('nist', 'ac-6')})
        claims = entry['quote_condition_evidence']
        self.assertEqual(claims['schema'], 1)
        self.assertEqual(
            [(r['source'], r['id'], r['consequence'], r['state']) for r in claims['conditions']],
            [('nist', 'ac-6', 'void', 'counted-implementation-claim'),
             ('nist', 'cm-6', 'uplift', 'no-counted-implementation-claim')])
        self.assertEqual(entry['amount'], 113403.3)
        self.assertEqual(entry['quote_validity']['retention'], 'not-assessed')

    def test_none_empty_and_foreign_publisher_claims_are_distinct(self):
        for implemented, expected in (
                (None, ['unobserved', 'unobserved']),
                (set(), ['no-counted-implementation-claim'] * 2),
                ({('another-publisher', 'ac-6')}, ['no-counted-implementation-claim'] * 2),
                ({('nist', 'ac-6'), ('nist', 'cm-6')}, ['counted-implementation-claim'] * 2)):
            with self.subTest(implemented=implemented):
                entry = self.premium(implemented)
                self.assertEqual([r['state'] for r in entry['quote_condition_evidence']['conditions']], expected)
                self.assertEqual(entry['conditions'][1]['uplift'], {'amount': 25000, 'currency': 'GBP'})
                self.assertEqual(entry['amount'], 113403.3)

    def test_existing_malformed_quote_instruments_still_refuse(self):
        for field, value in (('adopter', 'another-party'), ('valid_until', 'not-a-date')):
            with self.subTest(field=field):
                quote = json.loads(fixtures.QUOTE.read_text())
                quote['payload'][field] = value
                self.inputs.feed.write_text(json.dumps(quote))
                with self.assertRaisesRegex(ct.Refused, 'missing instrument'):
                    self.premium({('nist', 'ac-6')})

    def test_all_other_premium_values_are_exact_across_claim_contexts(self):
        original = self.premium(None)
        original.pop('quote_condition_evidence')
        for claims in (set(), {('nist', 'ac-6'), ('nist', 'cm-6')}):
            with self.subTest(claims=claims):
                entry = self.premium(claims)
                entry.pop('quote_condition_evidence')
                self.assertEqual(entry, original)

    def test_handbook_names_claim_evidence_limits_and_historical_absence(self):
        files, evidence = handbook._fixture()
        header = yaml.safe_load(files[handbook.HEADER_PATH])
        header['quote-condition-schema'] = 1
        files[handbook.HEADER_PATH] = yaml.safe_dump(header)
        entry = self.premium({('nist', 'ac-6')})
        evidence['prices'] = [entry]
        page = handbook.render(files, evidence)
        self.assertIn('condition evidence schema1', page)
        self.assertIn('nist/ac-6: counted-implementation-claim', page)
        self.assertIn('nist/cm-6: no-counted-implementation-claim', page)
        self.assertIn(entry['quote_condition_evidence']['basis'], page)
        del entry['quote_condition_evidence']
        historical = handbook.render(files, evidence)
        self.assertIn('prices[0].quote_condition_evidence', historical)
        self.assertIn('this historical premium carries no counted-condition claim evidence', historical)
    def test_unknown_or_unreadable_conditions_never_become_claims(self):
        for conditions in ([{'source': 'nist', 'id': 'ac-6', 'consequence': 'unrecognised'}],
                           [{'source': 'nist', 'consequence': 'void'}],
                           [{'source': 'nist', 'id': 'ac-6', 'consequence': 'uplift',
                             'uplift': {'amount': -1, 'currency': 'GBP'}}],
                           ['not-a-condition'], {'source': 'nist', 'id': 'ac-6'}):
            with self.subTest(conditions=conditions):
                quote = json.loads(fixtures.QUOTE.read_text())
                quote['payload']['conditions'] = conditions
                self.inputs.feed.write_text(json.dumps(quote))
                entry = self.premium({('nist', 'ac-6')})
                claims = entry['quote_condition_evidence']
                self.assertEqual(entry['conditions'], conditions)
                self.assertTrue(claims.get('unreadable') or all(
                    r['state'] == 'unobserved' and r.get('basis') for r in claims['conditions']))
                self.assertEqual(entry['amount'], 113403.3)

    def test_no_quote_edge_invents_no_premium_or_condition_evidence(self):
        prices = ct.compute_prices([], 'driftwood', 40000, {}, None,
                                   adopter_dir=self.inputs.root, perspective_doc=self.inputs.party,
                                   include_switching=False, implemented={('nist', 'ac-6')})
        self.assertTrue(all(p['kind'] != 'premium' and 'quote_condition_evidence' not in p for p in prices))

    def test_missing_required_conditions_is_not_an_explicit_empty_set(self):
        quote = json.loads(fixtures.QUOTE.read_text())
        quote['payload']['conditions'] = []
        self.inputs.feed.write_text(json.dumps(quote))
        explicit_empty = self.premium({('nist', 'ac-6')})
        self.assertEqual(explicit_empty['quote_condition_evidence']['conditions'], [])
        self.assertNotIn('unreadable', explicit_empty['quote_condition_evidence'])
        del quote['payload']['conditions']
        self.inputs.feed.write_text(json.dumps(quote))
        missing = self.premium({('nist', 'ac-6')})
        self.assertIn('unreadable', missing['quote_condition_evidence'])
        self.assertEqual(missing['quote_condition_evidence']['conditions'], [])
        # Legacy quote acceptance and every monetary/contract field stay exact.
        missing.pop('quote_condition_evidence')
        explicit_empty.pop('quote_condition_evidence')
        self.assertEqual(missing, explicit_empty)

    def test_schema_invalid_condition_fields_are_unobserved_at_actual_quote_call(self):
        cases = (
            ('source-empty', 0, {'source': ''}),
            ('id-not-string', 0, {'id': 7}),
            ('unknown-consequence', 0, {'consequence': 'unknown'}),
            ('unknown-field', 0, {'future-term': True}),
            ('why-empty', 0, {'why': ''}),
            ('void-with-malformed-money', 0, {'uplift': {'amount': 25000, 'currency': 'gbp'}}),
            ('malformed-currency', 1, {'uplift': {'amount': 25000, 'currency': 'not-a-currency'}}),
            ('currency-not-string', 1, {'uplift': {'amount': 25000, 'currency': 123}}),
            ('currency-trailing-newline', 1, {'uplift': {'amount': 25000, 'currency': 'GBP\n'}}),
            ('negative-amount', 1, {'uplift': {'amount': -1, 'currency': 'GBP'}}),
            ('boolean-amount', 1, {'uplift': {'amount': True, 'currency': 'GBP'}}),
            ('nonfinite-amount', 1, {'uplift': {'amount': float('inf'), 'currency': 'GBP'}}),
            ('missing-amount', 1, {'uplift': {'currency': 'GBP'}}),
            ('unknown-money-field', 1, {'uplift': {'amount': 25000, 'currency': 'GBP', 'future': 1}}),
            ('missing-money', 1, {'uplift': None}),
        )
        for name, index, changes in cases:
            with self.subTest(case=name):
                quote = json.loads(fixtures.QUOTE.read_text())
                quote['payload']['conditions'][index].update(changes)
                self.inputs.feed.write_text(json.dumps(quote))
                entry = self.premium({('nist', 'ac-6'), ('nist', 'cm-6')})
                condition = entry['quote_condition_evidence']['conditions'][index]
                self.assertEqual(condition['state'], 'unobserved')
                self.assertIn('Unreadable', condition['basis'])
                self.assertEqual(entry['conditions'], quote['payload']['conditions'])
                self.assertEqual(entry['amount'], 113403.3)


class QuoteConditionReplay(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.QuoteReplay()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_new_condition_evidence_is_saved_and_replayed_without_money_changes(self):
        doc, rendered = self.fixture.fixture.composed(as_of='2026-10-17')
        header = yaml.safe_load(rendered['composed/HEADER.yaml'])
        self.assertEqual(header['quote-condition-schema'], 1)
        premium = next(p for p in doc['prices'] if p['kind'] == 'premium')
        self.assertEqual(premium['amount'], 113403.3)
        self.assertEqual(premium['quote_condition_evidence']['schema'], 1)
        self.fixture.save(doc, rendered)
        replay, rerendered = ct.compose(self.fixture.fixture.adopter, self.fixture.fixture.trees,
                                       as_of='2026-10-17', replay_observations=True)
        self.assertEqual(replay['prices'], doc['prices'])
        self.assertEqual(rerendered, rendered)
        self.assertEqual(ct.verify(self.fixture.fixture.adopter, self.fixture.fixture.trees), (True, []))

    def test_historical_absence_replays_and_present_unknown_schemas_refuse(self):
        doc, rendered = self.fixture.fixture.composed(as_of='2026-10-17')
        header = yaml.safe_load(rendered['composed/HEADER.yaml'])
        header.pop('quote-condition-schema', None)
        rendered['composed/HEADER.yaml'] = ct.HEADER_COMMENT + yaml.safe_dump(header, **ct.YAML_KWARGS)
        for entry in doc['prices']:
            entry.pop('quote_condition_evidence', None)
        rendered[handbook.HANDBOOK_PATH] = handbook.render(rendered, doc)
        self.fixture.save(doc, rendered)
        replay, rerendered = ct.compose(self.fixture.fixture.adopter, self.fixture.fixture.trees,
                                       as_of='2026-10-17', replay_observations=True)
        self.assertTrue(all('quote_condition_evidence' not in p for p in replay['prices']))
        self.assertEqual(rerendered, rendered)
        self.assertEqual(ct.verify(self.fixture.fixture.adopter, self.fixture.fixture.trees), (True, []))
        for version in (None, 0, 2, True):
            with self.subTest(version=version):
                header['quote-condition-schema'] = version
                (self.fixture.fixture.adopter / 'composed/HEADER.yaml').write_text(yaml.safe_dump(header))
                ok, differences = ct.verify(self.fixture.fixture.adopter, self.fixture.fixture.trees)
                self.assertFalse(ok)
                self.assertIn('unsupported quote-condition-schema', str(differences))

if __name__ == '__main__':
    unittest.main()
