"""Pure shadow routing regressions, no source authentication or financial engine."""
import ast
from contextlib import redirect_stdout
import inspect
import io
import json
from pathlib import Path
from types import SimpleNamespace
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


class FeedPriceAssertionsReached(Exception):
    """Stop the real selfcheck after its feed-key and multiplicity assertions."""


class FeedPriceBoundary(dict):
    def __getitem__(self, key):
        if key == "old_version":
            raise FeedPriceAssertionsReached
        return super().__getitem__(key)


class SelfcheckFeedPrices(unittest.TestCase):
    @staticmethod
    def selfcheck_ast():
        source, first_line = inspect.getsourcelines(subject.selfcheck)
        caller = ast.parse(''.join(source)).body[0]
        ast.increment_lineno(caller, first_line - 1)
        return caller

    def check_vendored_replay(self, record):
        # Execute the entire actual F1 caller, including ordinary converter
        # replay, on explicit TEST_ONLY bytes. No financial engine is imported.
        caller = self.selfcheck_ast()
        loop = next(node for node in caller.body if isinstance(node, ast.For)
                    and ast.unparse(node.iter) == "doc45['vendored']")
        base = subject.vendored_rel(record['party'], record['name'], record['version'])
        converter = ("import json,sys\n"
                     "assert sys.argv[1] == 'TEST_ONLY'\n"
                     "with open(sys.argv[2]) as stream: payload=json.load(stream)\n"
                     "assert payload['feed_version'] == 'v1'\n"
                     "print(json.dumps({'TEST_ONLY': True}, sort_keys=True))\n")
        namespace = {**vars(subject), 'doc45': {'vendored': [record]},
            'parent_trees': {}, 'rendered45': {
                f"{base}/{record['converter']}": converter,
                f"{base}/{record['feed_path']}": json.dumps({'payload': {}})}}
        exec(compile(ast.Module(body=[loop], type_ignores=[]),
                     subject.__file__, 'exec'), namespace)

    def replay_record(self, name='recovery-expense'):
        return {'party': 'feeds', 'kind': 'feed', 'name': name, 'version': 'v1',
                'converter': 'TEST_ONLY_converter.py', 'feed_path': 'TEST_ONLY_feed.json',
                'payload_version_key': 'feed_version', 'invocation': None,
                'scenario_sha256': None}

    def test_shadow_vendored_converter_has_no_financial_replay(self):
        record = self.replay_record()
        with patch.object(subject.subprocess, 'run',
                          side_effect=AssertionError('shadow converter was invoked')):
            self.check_vendored_replay(record)
        self.assertEqual(record['converter'], 'TEST_ONLY_converter.py')

    def test_shadow_financial_invocation_or_digest_is_a_contradiction(self):
        for change in ({'invocation': ['TEST_ONLY']}, {'scenario_sha256': 'a' * 64}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                self.check_vendored_replay({**self.replay_record(), **change})

    def test_shadow_replay_still_requires_the_vendored_admission_converter(self):
        for converter in (None, ''):
            with self.subTest(converter=converter), self.assertRaises(AssertionError):
                self.check_vendored_replay({**self.replay_record(), 'converter': converter})

    def test_converterless_quote_remains_uninvoked_and_requires_null_replay(self):
        record = {**self.replay_record('quote-driftwood'), 'party': 'insurer', 'converter': None}
        with patch.object(subject.subprocess, 'run',
                          side_effect=AssertionError('converterless quote was invoked')):
            self.check_vendored_replay(record)
        with self.assertRaises(AssertionError):
            self.check_vendored_replay({**record, 'scenario_sha256': 'a' * 64})

    def test_ordinary_replay_still_requires_invocation_and_exact_scenario_digest(self):
        record = self.replay_record('threat-register')
        with self.assertRaises(AssertionError):
            self.check_vendored_replay(record)
        record['invocation'] = ['TEST_ONLY']
        with self.assertRaises(AssertionError):
            self.check_vendored_replay(record)
        record['scenario_sha256'] = subject._digest(json.dumps({'TEST_ONLY': True}, sort_keys=True))
        self.check_vendored_replay(record)
        record['scenario_sha256'] = '0' * 64
        with self.assertRaises(AssertionError):
            self.check_vendored_replay(record)

    def test_claimed_shadow_flags_cannot_skip_another_family_replay(self):
        for change in ({'party': 'other-feeds'}, {'name': 'other-recovery'}, {'kind': 'controls'}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                self.check_vendored_replay({**self.replay_record(), **change,
                                           'shadow': True, 'diagnostic': True})

    def check_feed_assertions(self, edges, prices, trees=None):
        # Only compose's result is synthetic: execute the real selfcheck caller's
        # key and count assertions, then stop before its unrelated pricing cases.
        with tempfile.TemporaryDirectory() as temporary:
            estate = Path(temporary)
            (estate / 'driftwood').mkdir()
            (estate / 'driftwood' / 'party.yaml').write_text(
                subject.yaml.safe_dump({'inherits': edges}))
            document = {key: [] for key in ('parents', 'members', 'refusals',
                'restatements', 'cages', 'holes', 'ungoverned', 'deltas', 'limits')}
            document.update(outcome='composed', party_artefact_errors=[], prices=prices)
            with patch.object(subject, 'DEFAULT_ESTATE_CLONE', estate), \
                 patch.object(subject, '_real_parent_trees', return_value=trees if trees is not None else {}), \
                 patch.object(subject, '_version_array', return_value=[{'version': '1.0.0'}]), \
                 patch.object(subject, 'compose', return_value=(document, {})), \
                 redirect_stdout(io.StringIO()):
                subject.selfcheck()

    def check_switching_assertions(self, edges, prices):
        # Isolate the real second selfcheck caller after its native fixture work.
        # Execute its actual assignments and both assertions, not a copied filter.
        caller = self.selfcheck_ast()
        start = next(i for i, node in enumerate(caller.body)
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'drift_doc'
                for target in node.targets))
        end = next(i for i in range(start, len(caller.body))
            if isinstance(caller.body[i], ast.For)
            and isinstance(caller.body[i].iter, ast.Name)
            and caller.body[i].iter.id == 'switching')
        block = caller.body[start:end]
        self.assertEqual([type(node).__name__ for node in block][-3:],
                         ['Assert', 'Assign', 'Assert'])
        with tempfile.TemporaryDirectory() as temporary:
            adopter = Path(temporary)
            (adopter / 'party.yaml').write_text(subject.yaml.safe_dump({'inherits': edges}))
            namespace = {**vars(subject), 'driftwood': adopter, 'doc45': {'prices': prices},
                         'parent_trees': {}}
            exec(compile(ast.Module(body=block, type_ignores=[]),
                         subject.__file__, 'exec'), namespace)
            return namespace

    def test_switching_selfcheck_excludes_intrinsic_shadow(self):
        ordinary = {'party': 'ico', 'kind': 'pricing', 'version': 'v1'}
        checked = self.check_switching_assertions([ordinary, SHADOW],
                    [{'kind': 'switching', 'name': 'penalty-schema'}])
        # The later vendoring checks must still cover the complete signed feed
        # tree, including shadow inputs that deliberately have no financial cost.
        self.assertEqual(checked['feed_edges'], [ordinary, SHADOW])

    def test_switching_selfcheck_retains_cardinality_and_identity_guards(self):
        ordinary = {'party': 'ico', 'kind': 'pricing', 'version': 'v1'}
        expected = {'kind': 'switching', 'name': 'penalty-schema'}
        extra = {'kind': 'switching', 'name': 'cve'}
        for prices in ([], [expected, extra], [expected, expected], [extra]):
            with self.subTest(prices=prices), self.assertRaises(AssertionError):
                self.check_switching_assertions([ordinary], prices)

    def test_intrinsic_shadow_does_not_become_an_expected_financial_price(self):
        ordinary = {'party': 'ico', 'kind': 'pricing', 'version': 'v1'}
        price = FeedPriceBoundary(kind='feed', source='ico', name='penalty-schema')
        with self.assertRaises(FeedPriceAssertionsReached):
            self.check_feed_assertions([ordinary, SHADOW], [price])

    def test_report_diagnostic_does_not_become_an_expected_financial_price(self):
        ordinary = {'party': 'ico', 'kind': 'pricing', 'version': 'v1'}
        diagnostic = {'party': 'feeds', 'kind': 'feed', 'name': 'threat-register', 'version': 'v1'}
        trees = subject.ParentTrees()
        trees.publisher_quality = SimpleNamespace(diagnostic={('feeds', 'threat-register', 'v1')})
        price = FeedPriceBoundary(kind='feed', source='ico', name='penalty-schema')
        with self.assertRaises(FeedPriceAssertionsReached):
            self.check_feed_assertions([ordinary, diagnostic], [price], trees)

    def test_ordinary_missing_extra_and_duplicate_prices_still_fail(self):
        ordinary = {'party': 'ico', 'kind': 'pricing', 'version': 'v1'}
        price = FeedPriceBoundary(kind='feed', source='ico', name='penalty-schema')
        extra = FeedPriceBoundary(kind='feed', source='feeds', name='cve')
        for prices in ([], [price, extra], [price, price]):
            with self.subTest(prices=prices), self.assertRaises(AssertionError):
                self.check_feed_assertions([ordinary], prices)


if __name__ == '__main__':
    unittest.main()
