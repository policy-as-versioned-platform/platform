"""Synthetic party declarations at the public structural-validation seam.

These examples supply no genuine signature, forecast, outcome or price credit.
The complete producer-to-compose regression is a separate required seam.
"""
from __future__ import annotations

import unittest
import copy
from pathlib import Path
import tempfile

import yaml

import party_artefact as party


def declaration() -> dict:
    def reference(publisher: str, digit: str, path: str) -> dict:
        return {
            'party': publisher, 'tag': 'synthetic/v1.0.0',
            'commit': digit * 40, 'path': path, 'git_blob': digit * 40,
        }

    return {
        'party': 'synthetic-adopter', 'roles': ['adopter'],
        'baseline': 'MODERATE',
        'inherits': [
            {'party': 'ico', 'kind': 'feed', 'name': 'penalty-schema', 'version': 'v9'},
            {'party': 'nist', 'kind': 'feed', 'name': 'publisher-reliability', 'version': 'v2'},
        ],
        'overlay': {'add': [], 'restate': []},
        'appetite': {
            'tolerance': {'amount': 15, 'currency': 'GBP'},
            'pricing_threshold': 3,
            'publisher_reliability': [{
                'schema': 'publisher-reliability/adopter-policy-v1',
                'target_edge': {'party': 'ico', 'name': 'penalty-schema', 'version': 'v9'},
                'report': reference('nist', '8', 'publisher-reliability/v2/feed.json'),
                'profile': reference('ico', '2', 'price-accuracy/profile.json'),
                'criterion': 'money-empirical-crps/v1',
                'unit': {'currency': 'GBP', 'basis': 'synthetic nominal GBP'},
                'minimum_cases': 2, 'aggregation': 'equal-case-mean',
                'bar': '-10', 'on_below': 'publisher-widen-to/v1',
                'widening': reference('ico', '1', 'price-accuracy/widening.json'),
            }],
        },
    }


class PublisherReliabilityDeclaration(unittest.TestCase):
    def test_quality_bar_is_a_separate_optional_per_target_policy(self):
        self.assertEqual(party.validate_schema(declaration()), [])

    def test_policy_cannot_name_a_target_version_the_party_does_not_inherit(self):
        document = declaration()
        document['appetite']['publisher_reliability'][0]['target_edge']['version'] = 'v99'
        errors = party.validate_schema(document)
        self.assertTrue(any('target_edge must name one declared feed edge' in e for e in errors), errors)

    def test_quality_bar_requires_canonical_bounded_nonpositive_decimal(self):
        for bar in ('1', '-0', '-1.0', '-' + '1' * 129):
            with self.subTest(bar=bar):
                document = declaration()
                document['appetite']['publisher_reliability'][0]['bar'] = bar
                errors = party.validate_schema(document)
                self.assertTrue(any('.bar ' in e for e in errors), errors)

    def test_each_target_has_one_policy(self):
        document = declaration()
        policies = document['appetite']['publisher_reliability']
        policies.append(copy.deepcopy(policies[0]))
        errors = party.validate_schema(document)
        self.assertTrue(any('duplicate target_edge' in e for e in errors), errors)

    def test_the_target_publisher_owns_profile_and_widening_but_not_report(self):
        for field, publisher in (('profile', 'other'), ('widening', 'other'), ('report', 'ico')):
            with self.subTest(field=field):
                document = declaration()
                document['appetite']['publisher_reliability'][0][field]['party'] = publisher
                errors = party.validate_schema(document)
                self.assertTrue(any('publisher ownership' in e for e in errors), errors)

    def test_the_report_has_one_declared_publisher_reliability_subscription(self):
        document = declaration()
        document['inherits'].pop()
        errors = party.validate_schema(document)
        self.assertTrue(any('report must name one declared publisher-reliability feed' in e
                            for e in errors), errors)

    def test_signed_party_yaml_cannot_silently_select_one_of_two_quality_bars(self):
        raw = yaml.safe_dump(declaration(), sort_keys=False)
        line = next(line for line in raw.splitlines() if line.lstrip().startswith('bar:'))
        indent = line[:len(line) - len(line.lstrip())]
        raw = raw.replace(line, indent + "bar: '-20'\n" + line)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'party.yaml'
            source.write_text(raw)
            errors = party.check(source, Path(directory))['errors']
        self.assertTrue(any('duplicate party YAML key' in e for e in errors), errors)


if __name__ == '__main__':
    unittest.main()
