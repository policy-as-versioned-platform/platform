"""Modeled quote consequences through real compose and rendered sheet.

All external evidence fixtures in this file are explicitly synthetic. They do
not execute real signatures, networks, actors or clusters, or prove fulfillment.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import yaml

import composition as ct
import consumer_retirement as clock
import handbook
import quote_assessment

import test_quote_validity as fixtures


class QuoteAssessment(unittest.TestCase):
    def setUp(self):
        self.inputs = fixtures.QuoteReplay()
        self.inputs.setUp()
        self.addCleanup(self.inputs.doCleanups)

    def test_missing_observation_is_unknown_in_the_actual_conditional_cost_view(self):
        doc, rendered = self.inputs.fixture.composed(as_of='2026-10-18')
        premium = next(p for p in doc['prices'] if p['kind'] == 'premium')
        self.assertEqual(premium['amount'], 113403.3)
        view = premium['conditional_cost_view']
        self.assertEqual(view['state'], 'unobserved')
        self.assertIsNone(view['effective_premium'])
        self.assertEqual(view['contract_premium'], {'amount': 113403.3, 'currency': 'GBP'})
        self.assertIn('observation selector', view['basis'])
        self.assertIn('Modeled conditional cost', rendered['composed/HANDBOOK.md'])
        self.assertIn('unobserved', rendered['composed/HANDBOOK.md'])


class ScheduledQuoteAssessment(unittest.TestCase):
    """Real isolated Git objects, explicit synthetic official/signature boundaries."""

    def setUp(self):
        self.inputs = fixtures.QuoteReplay()
        self.inputs.setUp()
        self.addCleanup(self.inputs.doCleanups)
        self.f = self.inputs.fixture
        self.adopter = self.f.adopter
        self.platform = self.f.trees['fixture-platform']
        ct._write_component_definition(self.platform / 'oscal/component-definition.json', [
            ('aa-1', 'member-a'), ('aa-2', 'member-b')])
        policy = self.platform / 'distribution/policies/v1.0.0/member-a.yaml'
        doc = yaml.safe_load(policy.read_text())
        doc['metadata']['name'] = 'member-b-1-0-0'
        (policy.parent / 'member-b.yaml').write_text(yaml.safe_dump(doc))
        quote = json.loads(self.inputs.inputs.feed.read_bytes())
        quote['payload']['conditions'] = [
            {'source': 'fixture-nist', 'id': 'aa-1', 'consequence': 'void'},
            {'source': 'fixture-nist', 'id': 'aa-2', 'consequence': 'uplift',
             'uplift': {'amount': 25000, 'currency': 'GBP'}}]
        self.quote_file = self.inputs.inputs.feed
        quote['payload']['conditions'] = self.condition_fixture(quote['payload']['conditions'])
        self.quote_file.write_text(json.dumps(quote))
        for name, tree in self.f.trees.items():
            if not (tree / '.git').exists():
                self.git(tree, 'init', '-q')
                self.commit(tree)
            if not self.git(tree, 'remote').strip():
                self.git(tree, 'remote', 'add', 'origin', 'https://github.com/fixture/' + name)
        self.git(self.adopter, 'init', '-q')
        self.git(self.adopter, 'remote', 'add', 'origin', 'https://github.com/fixture/driftwood')
        apps = self.adopter / 'gitops/apps'
        apps.mkdir(parents=True, exist_ok=True)
        ct._write_namespace(self.adopter, 'x', governed=True)
        (apps / 'kustomization.yaml').write_text('kind: Kustomization\nresources: [synthetic.yaml, namespace-x.yaml]\n')
        (apps / 'synthetic.yaml').write_text(yaml.safe_dump({'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'namespace': 'x', 'name': 'synthetic', 'labels': {
                'policy-as-versioned.dev/policy-version': '1.0.0'}},
            'spec': {'containers': [{'name': 'fixture', 'image':
                'example.invalid/declared-fixture@sha256:' + 'a' * 64}]}}))
        self.apps_fixture(apps)
        initial, files = self.f.composed(as_of='2026-10-18')
        self.f.save(files)
        self.apps_commit = self.commit(self.adopter)
        self.git(self.adopter, 'tag', 'apps/v1.0.0')
        exposure = yaml.safe_load(files['composed/HEADER.yaml'])['exposure']
        quote['payload']['priced_against'] = [
            {k: p[k] for k in ('party', 'kind', 'version')} for p in initial['parents']
            if p['kind'] == 'implementations'] + [
                {'party': 'driftwood', 'kind': 'feed', 'name': 'exposure', 'version': 'apps/v1.0.0',
                 'exposure_sha256': 'sha256:' + hashlib.sha256(json.dumps(
                     exposure, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}]
        self.quote_context_fixture(quote)
        self.quote_file.write_text(json.dumps(quote))
        self.publisher_fixture()
        self.commit(self.inputs.inputs.publisher)
        for party in ('fixture-platform', 'fixture-nist', 'insurer'):
            self.git(self.f.trees[party], 'tag', 'condition-fixture/v1.0.0')
        self.write('gitops/flux-system/condition-fixture-pins.yaml', yaml.safe_dump_all([
            {'kind': 'GitRepository', 'spec': {'url': 'https://github.com/fixture/' + party,
                'ref': {'tag': 'condition-fixture/v1.0.0', 'commit': self.git(tree, 'rev-parse', 'HEAD')}}}
            for party, tree in self.f.trees.items() if party in ('fixture-platform', 'fixture-nist', 'insurer')]))
        current, files = self.f.composed(as_of='2026-10-18')
        self.f.save(files)
        self.composed_commit = self.commit(self.adopter)
        self.git(self.adopter, 'tag', 'composed/v1.0.0')
        self.write('gitops/flux-system/gotk-sync.yaml', yaml.safe_dump_all([
            {'kind': 'GitRepository', 'metadata': {'name': 'fixture-apps'},
             'spec': {'ref': {'tag': 'apps/v1.0.0', 'commit': self.apps_commit}}},
            {'kind': 'Kustomization', 'spec': {'path': './gitops/apps',
                'sourceRef': {'kind': 'GitRepository', 'name': 'fixture-apps'}}}]))
        self.write('gitops/composed/composed-set.yaml', yaml.safe_dump({
            'kind': 'GitRepository', 'spec': {'ref': {'tag': 'composed/v1.0.0', 'commit': self.composed_commit}}}))
        self.source = self.commit(self.adopter)
        self.parent = next(p for p in current['parents'] if p.get('party') == 'insurer')
        self.rows = {}
        for path, (kind, count) in clock.LANE.items():
            rows = []
            for index in range(count):
                row = {'kind': kind, 'run': '123', 'event': 'schedule',
                       'ts': '2026-10-18T09:10:00Z', 'synthetic_fixture_row': index}
                if 'workload' in path:
                    row.update(apps_ref='apps/v1.0.0', observed=True, workloads=[{
                        'name': 'synthetic', 'manifest': 'gitops/apps/synthetic.yaml', 'observed': True,
                        'image': ['example.invalid/declared-fixture@sha256:' + 'a' * 64],
                        'caged': {'labels': {'policy-as-versioned.dev/policy-version': '1.0.0'}}}])
                if 'oscal' in path:
                    row.update(status='observed', report_count=1, report_read_errors=[],
                        assessment_results={'assessment-results': {'results': [{
                            'observations': [self.observation('member-a', 'pass'),
                                             self.observation('member-b', 'fail')],
                            'findings': [self.finding('aa-1', 'member-a'), self.finding('aa-2', 'member-b')]}]}})
                rows.append(row)
            self.rows[path] = rows
        self.original = self.append_original()
        self.descriptor = {'schema': 1, 'profile': 'served-policy-conditions/v1',
            'party': 'driftwood', 'repository': 'fixture/driftwood', 'examined_at': '2026-10-18T10:00:00Z',
            'quote': {'source': 'insurer', 'name': 'quote-driftwood', 'version': 'v1',
                      'parent_sha': self.parent['sha'],
                      'payload_sha256': 'sha256:' + hashlib.sha256(self.quote_file.read_bytes()).hexdigest()},
            'baseline': {'original_commit': self.original, 'source_commit': self.source,
                         'run_id': 123, 'attempt': 1, 'appends': self.appends}}
        self.write_selector()
        self.calls = []
        self.official_data = {'id': 123, 'run_attempt': 1, 'event': 'schedule', 'head_branch': 'main',
            'head_sha': self.source, 'status': 'completed', 'path': '.github/workflows/drift-sample.yml',
            'repository': {'full_name': 'fixture/driftwood'}, 'created_at': '2026-10-18T09:00:00Z',
            'run_started_at': '2026-10-18T09:05:00Z',
            'updated_at': '2026-10-18T09:30:00Z'}
        for name, implementation in [('_official', self.official), ('_signature', self.signature),
                                     ('_tag_signature', self.tag_signature)]:
            guard = patch.object(clock, name, side_effect=implementation)
            guard.start()
            self.addCleanup(guard.stop)

    @staticmethod
    def condition_fixture(conditions):
        return conditions

    @staticmethod
    def apps_fixture(apps):
        pass

    @staticmethod
    def quote_context_fixture(quote):
        pass

    def publisher_fixture(self):
        pass

    def variant(self, *, conditions=None, apps=None, context=None, publisher=None):
        fixture = ScheduledQuoteAssessment('test_authenticated_breach_prices_the_signed_increment_in_the_consumed_modeled_view')
        if conditions is not None:
            fixture.condition_fixture = lambda _: conditions
        if apps is not None:
            fixture.apps_fixture = apps
        if context is not None:
            fixture.quote_context_fixture = context
        if publisher is not None:
            fixture.publisher_fixture = lambda: publisher(fixture)
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        return fixture

    @staticmethod
    def git(root, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME='explicit synthetic fixture',
                   GIT_AUTHOR_EMAIL='fixture@example.invalid', GIT_COMMITTER_NAME='explicit synthetic fixture',
                   GIT_COMMITTER_EMAIL='fixture@example.invalid', GIT_AUTHOR_DATE='2026-10-18T09:00:00Z',
                   GIT_COMMITTER_DATE='2026-10-18T09:00:00Z')
        return subprocess.check_output(['git', '-C', str(root), '-c', 'core.hooksPath=/dev/null',
            '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', *args], env=env,
            stderr=subprocess.DEVNULL, timeout=15).decode().strip()

    def commit(self, root):
        self.git(root, 'add', '.')
        self.git(root, 'commit', '--allow-empty', '-qm', 'explicit synthetic quote-condition fixture')
        return self.git(root, 'rev-parse', 'HEAD')

    def write(self, path, content):
        target = self.adopter / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    @staticmethod
    def observation(policy, result):
        return {'uuid': ScheduledQuoteAssessment.observation_id(policy),
            'props': [{'name': 'policy', 'value': policy + '-1-0-0'},
                      {'name': 'policy-version', 'value': '1-0-0'}, {'name': 'result', 'value': result}],
            'subjects': [{'title': 'Pod x/synthetic', 'subject-uuid': '22222222-2222-4222-8222-222222222222'}]}

    @staticmethod
    def observation_id(policy):
        return ('11111111' if policy == 'member-a' else '33333333') + '-1111-4111-8111-111111111111'

    @staticmethod
    def finding(control, policy):
        return {'target': {'target-id': control, 'status': {'state': 'satisfied'}},
                'related-observations': [{'observation-uuid': ScheduledQuoteAssessment.observation_id(policy)}]}

    def append_original(self):
        self.appends = {}
        for path, rows in self.rows.items():
            data = ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows)
            self.write(path, data)
            self.appends[path] = hashlib.sha256(data.encode()).hexdigest()
        return self.commit(self.adopter)

    def reobserve(self):
        """New unsigned synthetic original, with the same measured source parent."""
        for path, rows in self.rows.items():
            data = ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows)
            self.write(path, data)
            self.appends[path] = hashlib.sha256(data.encode()).hexdigest()
        self.git(self.adopter, 'add', *clock.LANE)
        tree = self.git(self.adopter, 'write-tree')
        self.original = self.git(self.adopter, 'commit-tree', tree, '-p', self.source,
                                 '-m', 'explicit alternate synthetic observation; not real evidence')
        self.git(self.adopter, 'checkout', '--detach', '-q', self.original)
        self.descriptor['baseline']['original_commit'] = self.original
        self.descriptor['baseline']['appends'] = self.appends.copy()
        self.write_selector()

    def result(self):
        return self.rows['drift/oscal-samples.jsonl'][0]['assessment_results']['assessment-results']['results'][0]

    def view(self):
        doc, rendered = self.compose()
        self.assertEqual(doc['outcome'], 'composed', doc.get('refusals') or doc.get('party_artefact_errors'))
        return next(p['conditional_cost_view'] for p in doc['prices'] if p['kind'] == 'premium'), rendered

    def assert_refused(self, contains):
        doc, _ = self.compose()
        self.assertEqual(doc['outcome'], 'refused')
        self.assertIn(contains, str(doc.get('refusals') or doc.get('party_artefact_errors')))

    def write_selector(self):
        self.write('insurance/condition-observation.yaml', yaml.safe_dump(self.descriptor))

    def official(self, path):
        self.calls.append(('official', path))
        if path == 'repos/fixture/driftwood':
            return {'full_name': 'fixture/driftwood', 'default_branch': 'main'}
        if path == 'repos/fixture/driftwood/actions/runs/123/attempts/1':
            return self.official_data
        if path == 'repos/fixture/driftwood/compare/' + self.original + '...main':
            return {'status': 'ahead', 'merge_base_commit': {'sha': self.original}}
        raise AssertionError('unexpected external request: ' + path)

    def signature(self, root, original, repository, source, branch):
        self.assertEqual((root, original, repository, source, branch),
                         (self.adopter, self.original, 'fixture/driftwood', self.source, 'main'))
        self.calls.append(('synthetic-certificate-boundary', original))

    def tag_signature(self, root, tag, repository):
        if root == self.adopter:
            self.assertEqual(repository, 'fixture/driftwood')
            self.assertIn(tag, ['apps/v1.0.0', 'composed/v1.0.0'])
        else:
            party = next(p for p, tree in self.f.trees.items() if tree == root)
            expected = 'fx/v1.0.0' if party == 'fixture-publisher' else 'condition-fixture/v1.0.0'
            self.assertEqual((repository, tag), ('fixture/' + party, expected))
        self.calls.append(('synthetic-tag-boundary', tag))

    def compose(self):
        return ct.compose(self.adopter, self.f.trees, as_of='2026-10-18')

    def test_authenticated_breach_prices_the_signed_increment_in_the_consumed_modeled_view(self):
        doc, rendered = self.compose()
        self.assertEqual(doc['outcome'], 'composed', doc)
        premium = next(p for p in doc['prices'] if p['kind'] == 'premium')
        view = premium['conditional_cost_view']
        self.assertEqual(view['quote_basis']['state'], 'matched', view)
        self.assertEqual(view['state'], 'breached', view)
        self.assertEqual(view['effective_premium'], {'amount': 138403.3, 'currency': 'GBP'})
        self.assertEqual(premium['amount'], 113403.3, 'booked contract is unchanged until re-quote')
        self.assertIn('138,403.30', rendered['composed/HANDBOOK.md'])
        self.assertIn(view['as_of'], rendered['composed/HANDBOOK.md'])
        self.assertIn('re-quote and adoption', rendered['composed/HANDBOOK.md'])
        self.assertIn(('synthetic-certificate-boundary', self.original), self.calls)

    def test_complete_pass_and_void_breach_are_distinct_from_implementation_claims(self):
        self.result()['observations'] = [self.observation('member-a', 'pass'), self.observation('member-b', 'pass')]
        self.reobserve()
        view, _ = self.view()
        self.assertEqual((view['state'], view['retention'], view['effective_premium']['amount']),
                         ('met', 'not-assessed', 113403.3))
        self.result()['observations'][0] = self.observation('member-a', 'fail')
        self.reobserve()
        view, _ = self.view()
        self.assertEqual((view['state'], view['retention'], view['effective_premium']['amount']),
                         ('breached', 'fully-retained', 113403.3))

    def test_missing_skip_warn_cells_and_unlinked_findings_do_not_grant_a_known_cost(self):
        original = copy.deepcopy(self.result())
        mutations = {
            'missing check': lambda r: r['observations'].pop(),
            'skip even if finding says satisfied': lambda r: r['observations'][1]['props'][2].update(value='skip'),
            'warn': lambda r: r['observations'][1]['props'][2].update(value='warn'),
            'missing finding linkage': lambda r: r['findings'].pop(),
            'foreign finding control': lambda r: r['findings'][1]['target'].update({'target-id': 'aa-1'}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.result().clear();self.result().update(copy.deepcopy(original));mutate(self.result())
                self.reobserve()
                view, _ = self.view()
                self.assertEqual(view['state'], 'unobserved');self.assertIsNone(view['effective_premium'])

    def test_old_policy_pass_repeated_uuid_cannot_hide_the_current_fail(self):
        old = self.observation('member-b', 'pass')
        old['props'][0]['value'] = 'member-b-0-9-0';old['props'][1]['value'] = '0-9-0'
        self.result()['observations'].insert(0, old)
        self.reobserve()
        view, _ = self.view()
        self.assertEqual(view['state'], 'breached')
        self.assertEqual(view['effective_premium']['amount'], 138403.3)

    def test_exact_subject_version_apps_and_source_mapping_are_required(self):
        original = copy.deepcopy(self.rows)
        mutations = {
            'wrong apps tag': lambda: self.rows['drift/workload-samples.jsonl'][0].update(apps_ref='another/v1'),
            'missing workload': lambda: self.rows['drift/workload-samples.jsonl'][0].update(workloads=[]),
            'sample not observed': lambda: self.rows['drift/workload-samples.jsonl'][0].update(observed=False),
            'workload not observed': lambda: self.rows['drift/workload-samples.jsonl'][0]['workloads'][0].update(observed=False),
            'wrong manifest': lambda: self.rows['drift/workload-samples.jsonl'][0]['workloads'][0].update(manifest='gitops/apps/other.yaml'),
            'wrong image': lambda: self.rows['drift/workload-samples.jsonl'][0]['workloads'][0].update(image=['other:latest']),
            'old caged version': lambda: self.rows['drift/workload-samples.jsonl'][0]['workloads'][0]['caged']['labels'].update(
                {'policy-as-versioned.dev/policy-version': '0.9.0'}),
            'wrong subject': lambda: self.result()['observations'][0]['subjects'][0].update(title='Pod x/another'),
            'subject UID collision': lambda: self.result()['observations'][0]['subjects'][0].update(
                {'subject-uuid': '44444444-4444-4444-8444-444444444444'}),
            'wrong policy version': lambda: self.result()['observations'][0]['props'][1].update(value='9-0-0'),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.rows = copy.deepcopy(original);mutate();self.reobserve()
                view, _ = self.view();self.assertEqual(view['state'], 'unobserved')
        self.rows = original;self.reobserve()
        mapping = self.platform / 'oscal/component-definition.json'
        raw = mapping.read_bytes()
        mapping.write_bytes(raw.replace(b'aa-2', b'aa-3'))
        view, _ = self.view();self.assertEqual(view['state'], 'unobserved')

    def test_freshness_uses_explicit_instant_and_official_attempt_without_guessing_today(self):
        for instant in ('2026-10-18T09:09:59Z', '2026-10-20T09:10:01Z', '2027-08-29T10:00:00Z'):
            with self.subTest(instant=instant):
                self.descriptor['examined_at'] = instant;self.write_selector()
                view, rendered = self.view();self.assertEqual(view['state'], 'unobserved')
                self.assertIn(instant, rendered[handbook.HANDBOOK_PATH])
        self.descriptor['examined_at'] = '2026-10-20T09:10:00Z';self.write_selector()
        view, _ = self.view();self.assertEqual(view['state'], 'breached', '48h is inclusive')
        self.official_data['updated_at'] = '2026-10-18T09:09:59Z'
        view, _ = self.view();self.assertEqual(view['state'], 'unobserved')

    def test_attempt_started_at_and_each_observation_quote_date_are_required(self):
        self.official_data['run_started_at'] = '2026-10-18T09:10:01Z'
        view, _ = self.view();self.assertEqual(view['state'], 'unobserved')
        del self.official_data['run_started_at']
        self.assert_refused('UTC seconds')
        self.official_data.update(created_at='2026-08-27T09:00:00Z',
            run_started_at='2026-08-27T09:05:00Z', updated_at='2026-08-27T09:30:00Z')
        self.descriptor['examined_at'] = '2026-08-28T10:00:00Z'
        for rows in self.rows.values():
            for row in rows:
                row['ts'] = '2026-08-27T09:10:00Z'
        self.reobserve()
        view, _ = self.view();self.assertEqual(view['state'], 'unobserved')
        self.assertIn('outside the signed quote window', view['basis'])

    def test_present_malformed_selector_and_wrong_quote_never_supply_admission(self):
        original = copy.deepcopy(self.descriptor)
        mutations = [lambda d: d.update(admitted=True), lambda d: d.update(schema=True),
            lambda d: d.update(profile='unknown/v1'), lambda d: d.update(party='another'),
            lambda d: d.update(examined_at='2026-10-18'),
            lambda d: d['quote'].update(payload_sha256='sha256:' + '0' * 64),
            lambda d: d['baseline'].update(attempt=True)]
        for mutate in mutations:
            self.descriptor = copy.deepcopy(original);mutate(self.descriptor);self.write_selector()
            self.assert_refused('quote-driftwood')

    def test_authentication_and_committed_original_bytes_are_load_bearing(self):
        for key, value in [('event', 'workflow_dispatch'), ('head_sha', '0' * 40),
                           ('run_attempt', 2), ('head_branch', 'other')]:
            with self.subTest(key=key):
                old = self.official_data[key];self.official_data[key] = value
                self.assert_refused('exact scheduled');self.official_data[key] = old
        with patch.object(clock, '_signature', side_effect=clock.InvalidRetirement('synthetic wrong certificate')):
            self.assert_refused('synthetic wrong certificate')
        lane = self.adopter / 'drift/oscal-samples.jsonl'
        raw = lane.read_bytes();lane.write_bytes(raw + raw)
        self.assert_refused('changed, removed or duplicated');lane.write_bytes(raw)
        self.descriptor['baseline']['appends']['drift/oscal-samples.jsonl'] = '0' * 64;self.write_selector()
        self.assert_refused('exact digest')

    def test_source_declaration_edits_and_unsigned_carrier_refuse_or_remain_unknown(self):
        self.write('gitops/apps/extra.yaml', 'kind: Pod\nmetadata: {name: unexpected}\n')
        view, _ = self.view();self.assertEqual(view['state'], 'unobserved')
        (self.adopter / 'gitops/apps/extra.yaml').unlink()
        with patch.object(clock, '_tag_signature', side_effect=clock.InvalidRetirement('synthetic unsigned carrier')):
            self.assert_refused('synthetic unsigned carrier')

    def test_replay_reauthenticates_the_immutable_origin_and_never_accepts_cached_success(self):
        doc, files = self.compose();self.f.save(files)
        replay, rendered = ct.compose(self.adopter, self.f.trees, as_of='2026-10-18', replay_observations=True)
        self.assertEqual(replay['outcome'], 'composed', replay.get('refusals'))
        self.assertEqual(replay['prices'], doc['prices']);self.assertEqual(rendered, files)
        with patch.object(clock, '_signature', side_effect=clock.InvalidRetirement('synthetic unavailable authority')):
            replay, _ = ct.compose(self.adopter, self.f.trees, as_of='2026-10-18', replay_observations=True)
            self.assertEqual(replay['outcome'], 'refused')

    def test_condition_identity_duplicate_uplift_and_money_do_not_borrow_a_result(self):
        fixture = self.variant(conditions=[{'source': 'another-catalogue', 'id': 'aa-2',
            'consequence': 'uplift', 'uplift': {'amount': 25000, 'currency': 'GBP'}}])
        view, _ = fixture.view();self.assertEqual(view['state'], 'unobserved')
        fixture.doCleanups()
        for amount, currency in [(10 ** 500, 'GBP'), (True, 'GBP'), (-1, 'GBP'), (float('inf'), 'GBP'),
                                 (float('nan'), 'GBP'), (1, 'gbp'), (1, 'USD')]:
            with self.subTest(amount=amount, currency=currency):
                fixture = self.variant(conditions=[{'source': 'fixture-nist', 'id': 'aa-2',
                    'consequence': 'uplift', 'uplift': {'amount': amount, 'currency': currency}}])
                fixture.assert_refused('uplift');fixture.doCleanups()
        duplicate = [{'source': 'fixture-nist', 'id': 'aa-2', 'consequence': 'uplift',
                      'uplift': {'amount': 25000, 'currency': 'GBP'}}] * 2
        fixture = self.variant(conditions=duplicate)
        fixture.assert_refused('duplicated')

    def test_every_listed_manifest_must_be_accounted_not_just_one_valid_pod(self):
        for label, content in [('empty', ''), ('scalar', 'not-a-resource\n'), ('unsupported', 'kind: Deployment\n')]:
            with self.subTest(label=label):
                def extra(apps):
                    (apps / 'extra.yaml').write_text(content)
                    (apps / 'kustomization.yaml').write_text('kind: Kustomization\nresources: [synthetic.yaml, namespace-x.yaml, extra.yaml]\n')
                fixture = self.variant(apps=extra)
                view, _ = fixture.view();self.assertEqual(view['state'], 'unobserved')

    def test_quoted_exposure_and_parent_versions_must_match_before_using_new_observations(self):
        for label, mutate in [
                ('exposure', lambda q: q['payload']['priced_against'][-1].update(exposure_sha256='sha256:' + '0' * 64)),
                ('parent', lambda q: q['payload']['priced_against'][0].update(version='0.9.0'))]:
            with self.subTest(label=label):
                fixture = self.variant(context=mutate)
                view, _ = fixture.view();self.assertEqual(view['state'], 'unobserved')
                self.assertIsNone(view['effective_premium'])

    def test_selector_symlink_is_not_admission_and_handbook_rejects_unknown_cost_promotion(self):
        path = self.adopter / quote_assessment.SELECTOR
        target = path.with_suffix('.actual.yaml');path.rename(target);path.symlink_to(target.name)
        self.assert_refused('symlink')
        path.unlink();target.rename(path)
        doc, files = self.compose()
        premium = next(p for p in doc['prices'] if p['kind'] == 'premium')
        premium['conditional_cost_view'].update(state='unobserved')
        with self.assertRaisesRegex(handbook.CannotRender, 'unknown cost'):
            handbook.render(files, doc)

    def test_foreign_uplift_uses_the_existing_converter_only_with_exact_signed_dated_fx_inputs(self):
        def publisher(fixture):
            tree = fixture.f.trees['fixture-publisher']
            (tree / 'converters').mkdir()
            (tree / 'fx/v1').mkdir(parents=True)
            (tree / 'fx/v1/feed.json').write_text(json.dumps({
                'version': '1.0.0', 'fixture_date': '2026-08-28', 'synthetic_usd_to_gbp': 0.5}))
            (tree / 'converters/fx.py').write_text('''"""Labelled synthetic dated FX reader, not financial evidence."""
import json
from pathlib import Path
class MissingInstrument(ValueError): pass
def convert(amount, frm, to, as_of, root):
    row = json.loads((Path(root) / 'fx/v1/feed.json').read_text())
    if (frm, to, as_of) != ('USD', 'GBP', row['fixture_date']):
        raise MissingInstrument('synthetic fixture has no rate for this pair/date')
    return amount * row['synthetic_usd_to_gbp']
''')
            commit = fixture.commit(tree);fixture.git(tree, 'tag', 'fx/v1.0.0')
            fixture.write('gitops/flux-system/fixture-fx.yaml', yaml.safe_dump({
                'kind': 'GitRepository', 'metadata': {'name': 'fx'}, 'spec': {
                    'url': 'https://github.com/fixture/fixture-publisher',
                    'ref': {'tag': 'fx/v1.0.0', 'commit': commit}}}))
        fixture = self.variant(conditions=[{'source': 'fixture-nist', 'id': 'aa-2', 'consequence': 'uplift',
            'uplift': {'amount': 25000, 'currency': 'USD'}}], publisher=publisher)
        view, rendered = fixture.view()
        self.assertEqual(view['effective_premium'], {'amount': 125903.3, 'currency': 'GBP'})
        self.assertEqual(len(view['input']['fx']), 2)
        self.assertIn('125,903.30', rendered[handbook.HANDBOOK_PATH])
        publisher_tree = fixture.f.trees['fixture-publisher']
        fixture.git(publisher_tree, 'remote', 'set-url', 'origin', 'git@github.com:fixture/fixture-publisher.git')
        ssh_view, _ = fixture.view()
        self.assertEqual(ssh_view, view, 'canonical SSH and HTTPS transport select the same signed FX source')
        fixture.git(publisher_tree, 'remote', 'set-url', 'origin', 'https://github.com/fixture/fixture-publisher')
        raw = fixture.f.trees['fixture-publisher'] / 'fx/v1/feed.json'
        raw.write_text(raw.read_text().replace('0.5', '0.25'))
        view, _ = fixture.view();self.assertEqual(view['state'], 'unobserved')

    def test_official_default_ancestry_cannot_be_replaced_by_a_local_original(self):
        official = self.official
        def not_public(path):
            if '/compare/' in path:
                return {'status': 'behind', 'merge_base_commit': {'sha': self.source}}
            return official(path)
        with patch.object(clock, '_official', side_effect=not_public):
            self.assert_refused('not on the actual public default')

    def test_probe_and_infrastructure_copies_cannot_substitute_for_governed_subject_cells(self):
        self.result()['observations'][1] = self.observation('member-b', 'pass')
        outside = self.observation('member-b', 'fail')
        outside['subjects'][0]['title'] = 'Pod cage-probe-reference/synthetic'
        self.result()['observations'].append(outside)
        self.reobserve()
        view, _ = self.view();self.assertEqual(view['state'], 'met')
        self.result()['observations'].pop(1)
        self.reobserve()
        view, _ = self.view();self.assertEqual(view['state'], 'unobserved')

    def test_supported_git_transports_preserve_adopter_and_condition_publisher_identity(self):
        expected, _ = self.view()
        for repository, tree in [('driftwood', self.adopter), ('fixture-platform', self.platform),
                                 ('fixture-nist', self.f.trees['fixture-nist']), ('insurer', self.f.trees['insurer'])]:
            self.git(tree, 'remote', 'set-url', 'origin', 'ssh://git@github.com/fixture/' + repository + '.git')
        actual, _ = self.view();self.assertEqual(actual, expected)
        self.git(self.adopter, 'remote', 'set-url', 'origin', 'https://example.invalid/fixture/driftwood')
        self.assert_refused('adopter origin')

    def test_history_absence_empty_conditions_and_unsupported_replay_marker(self):
        fixture = self.variant(conditions=[])
        doc, files = fixture.compose()
        premium = next(p for p in doc['prices'] if p['kind'] == 'premium')
        self.assertNotIn('conditional_cost_view', premium)
        self.assertNotIn('quote-assessment-schema', yaml.safe_load(files['composed/HEADER.yaml']))
        fixture.doCleanups()
        doc, files = self.compose()
        premium = next(p for p in doc['prices'] if p['kind'] == 'premium')
        premium.pop('conditional_cost_view')
        header = yaml.safe_load(files['composed/HEADER.yaml']);header.pop('quote-assessment-schema')
        files['composed/HEADER.yaml'] = ct.HEADER_COMMENT + yaml.safe_dump(header, **ct.YAML_KWARGS)
        files[handbook.HANDBOOK_PATH] = handbook.render(files, doc);self.f.save(files)
        replay, rerendered = ct.compose(self.adopter, self.f.trees, as_of='2026-10-18', replay_observations=True)
        self.assertEqual(replay['prices'], doc['prices']);self.assertEqual(rerendered, files)
        for marker in (True, None, 0, 2):
            header['quote-assessment-schema'] = marker
            self.write('composed/HEADER.yaml', yaml.safe_dump(header))
            replay, _ = ct.compose(self.adopter, self.f.trees, as_of='2026-10-18', replay_observations=True)
            self.assertEqual(replay['outcome'], 'refused');self.assertIn('unsupported quote-assessment-schema', str(replay))


if __name__ == '__main__':
    unittest.main()
