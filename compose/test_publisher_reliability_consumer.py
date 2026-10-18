"""Publisher quality through the public monetary consumer and composition seams.

These source fixtures are synthetic and confer no real score or money credit.
"""
import importlib
from pathlib import Path
import tempfile
import unittest

import yaml
import handbook
import test_portable_observations as fixtures


class PublisherReliabilityConsumer(unittest.TestCase):
    def test_rendered_sheet_keeps_quality_effect_and_its_two_clocks_explicit(self):
        fixture = fixtures.PublisherFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        document, rendered = fixture.composed()
        price = next(p for p in document['prices'] if p['kind'] == 'feed')
        price['publisher_reliability_effect'] = {
            'schema': 'publisher-reliability/effect-v1', 'state': 'widened',
            'criterion': 'money-empirical-crps/v1', 'eligible_cases': 2, 'minimum_cases': 2,
            'score': {'numerator': '-20', 'denominator': '1'}, 'bar': '-10',
            'causes': ['score-below-bar'], 'financial_as_of': '2026-09-01',
            'reliability_evidence_as_of': '2026-10-18T12:00:00Z',
            'base': {'uncaged_price': '10', 'tier': 'baseline'},
            'effective': {'uncaged_price': '40', 'tier': 'restricted'}, 'reason': 'synthetic example'}
        page = handbook.render(rendered, document)
        self.assertIn('Publisher monetary quality', page)
        self.assertIn('financial as of 2026-09-01', page)
        self.assertIn('evidence cutoff 2026-10-18T12:00:00Z', page)
        self.assertIn('current-context base GBP 10', page)
        self.assertIn('effective GBP 40', page)
        self.assertIn('score-below-bar', page)

    def test_a_declared_report_cannot_be_replaced_by_an_unsigned_dictionary(self):
        with tempfile.TemporaryDirectory() as temporary:
            adopter = Path(temporary)
            reference = {'party': 'nist', 'tag': 'publisher-reliability/v2.0.0',
                         'commit': '1' * 40, 'path': 'publisher-reliability/v2/feed.json',
                         'git_blob': '2' * 40}
            profile = {**reference, 'party': 'ico', 'tag': 'synthetic-profile/v1.0.0',
                       'path': 'price-accuracy/profile.json'}
            widening = {**profile, 'tag': 'synthetic-widening/v1.0.0',
                        'path': 'price-accuracy/widening.json'}
            (adopter / 'party.yaml').write_text(yaml.safe_dump({
                'party': 'synthetic-adopter', 'roles': ['adopter'], 'baseline': 'MODERATE',
                'overlay': {'add': [], 'restate': []}, 'inherits': [
                    {'party': 'ico', 'kind': 'feed', 'name': 'penalty-schema', 'version': 'v9'},
                    {'party': 'nist', 'kind': 'feed', 'name': 'publisher-reliability', 'version': 'v2'}],
                'appetite': {'tolerance': {'amount': 15, 'currency': 'GBP'},
                    'pricing_threshold': 3, 'publisher_reliability': [{
                        'schema': 'publisher-reliability/adopter-policy-v1',
                        'target_edge': {'party': 'ico', 'name': 'penalty-schema', 'version': 'v9'},
                        'report': reference, 'profile': profile, 'widening': widening,
                        'criterion': 'money-empirical-crps/v1',
                        'unit': {'currency': 'GBP', 'basis': 'synthetic nominal GBP'},
                        'minimum_cases': 2, 'aggregation': 'equal-case-mean',
                        'bar': '-10', 'on_below': 'publisher-widen-to/v1'}]}}))
            consumer = importlib.import_module('publisher_reliability')
            with self.assertRaisesRegex(consumer.Refused, 'canonical source checkout for nist is absent'):
                consumer.assess_and_adjust(
                    adopter_dir=adopter, source_roots={}, edge={}, base_scenario={},
                    pricing_context={'financial_as_of': '2026-10-18',
                                     'report': {'status': 'measured', 'score': 0}})

    def test_absent_policy_preserves_the_entire_scenario_without_an_effect_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            adopter = Path(temporary)
            (adopter / 'party.yaml').write_text(yaml.safe_dump({'party': 'synthetic-adopter'}))
            scenario = {'version': 'synthetic1', 'name': 'synthetic',
                        'warn': {'lef': [1, 1, 1], 'lm': [10, 10, 10]},
                        'deny': {'lef': [0, 0, 0], 'lm': [10, 10, 10]}}
            consumer = importlib.import_module('publisher_reliability')
            result = consumer.assess_and_adjust(
                adopter_dir=adopter, source_roots={},
                edge={'party': 'ico', 'kind': 'feed', 'name': 'penalty-schema', 'version': 'v9'},
                base_scenario=scenario, pricing_context={'financial_as_of': '2026-10-18'})
            self.assertEqual(result.scenario, scenario)
            self.assertIsNone(result.effect)


if __name__ == '__main__':
    unittest.main()
