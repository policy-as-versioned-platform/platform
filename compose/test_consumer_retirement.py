"""An explicit retirement is verified at the real composition seam, never silently ignored."""
import copy
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

import composition as ct
import consumer_retirement as retirement

import test_engine_pairing


class RetirementComposition(unittest.TestCase):
    def test_an_invalid_explicit_record_cannot_render_the_whole_parent_as_if_it_were_honored(self):
        fixture = test_engine_pairing.EnginePairing()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        records = fixture.adopter / 'implementation-retirements'
        records.mkdir()
        (records / 'fixture-platform.yaml').write_text('schema: 1\nkind: consumer-retirement\n')
        document, rendered = test_engine_pairing.ct.compose(fixture.adopter, fixture.trees)
        self.assertEqual(document['outcome'], 'refused',
                         'an explicit retirement record was silently ignored')
        self.assertEqual(rendered, {})

    def test_default_composition_does_not_ask_github_or_change_the_output_shape(self):
        fixture = test_engine_pairing.EnginePairing()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with patch.object(retirement, '_official', side_effect=AssertionError('no record has no new external reads')):
            document, rendered = ct.compose(fixture.adopter, fixture.trees)
        self.assertEqual(document['outcome'], 'composed')
        self.assertNotIn('consumer_retirements', document)
        self.assertNotIn('consumer-retirements', yaml.safe_load(rendered['composed/HEADER.yaml']))

    def test_selected_machinery_treats_a_retired_claim_as_an_orphan_in_every_ranged_member(self):
        whole = ct.machinery_members(ct.PLATFORM_DIR)
        selected = ct._load_guards(ct.PLATFORM_DIR, ['7.0.0'])
        self.assertEqual(len(selected), len(whole))
        ranged = {'policy-version-orphan-guard', 'policy-version-orphan-cage',
                  'policy-version-orphan-cage-holds', 'cage-netpol-bottom-rung'}
        for member in selected:
            body = json.dumps(member['doc'])
            if member['doc']['metadata']['name'] in ranged:
                self.assertIn('7.0.0', body)
                self.assertNotIn('5.0.0', body)
                self.assertNotIn('6.0.0', body)
        self.assertIn('5.0.0', json.dumps(whole))


class RetirementAuthority(unittest.TestCase):
    """Real Git graphs/bytes with explicit synthetic external-authority adapters."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.adopter, self.parent = self.root / 'adopter', self.root / 'platform'
        for repository in (self.adopter, self.parent):
            repository.mkdir()
            self.git(repository, 'init', '-q')
            self.git(repository, 'config', 'user.name', 'synthetic test fixture')
            self.git(repository, 'config', 'user.email', 'synthetic@example.invalid')
            self.git(repository, 'remote', 'add', 'origin',
                     'https://github.com/fixture/' + ('adopter' if repository == self.adopter else 'platform'))
        scope = 'every-served-body-v1'
        self.versions = ['5.0.0', '6.0.0', '7.0.0']
        self.write(self.parent, 'distribution/versions.yaml', yaml.safe_dump({'spec': {'inputs': [{'versions': [
            {'version': version, 'tested_engines': {'scope': scope, 'kyverno': ['1.18.2'] +
             (['1.19.1'] if version == '7.0.0' else [])}} for version in self.versions]}]}}))
        self.write(self.parent, 'distribution/machinery.yaml', yaml.safe_dump(
            {'tested_engines': {'scope': scope, 'kyverno': ['1.18.2', '1.19.1']}}))
        self.parent_sha = self.commit(self.parent)
        self.git(self.parent, 'tag', 'v5.0.0')
        self.write(self.adopter, retirement.ENGINE_FILE, 'version: "1.18.2"\n')
        self.write(self.adopter, 'gitops/platform/pin.yaml', yaml.safe_dump({
            'kind': 'GitRepository', 'spec': {'url': 'https://github.com/fixture/platform',
                                           'ref': {'tag': 'v5.0.0', 'commit': self.parent_sha}}}))
        self.write(self.adopter, 'party.yaml', yaml.safe_dump({'party': 'fixture-adopter', 'inherits': [
            {'party': 'fixture-platform', 'kind': 'implementations', 'version': '5.0.0'}]}))
        self.write(self.adopter, 'composed/evidence.json', json.dumps({
            'members': [{'version': version} for version in self.versions],
            'parents': [{'party': 'fixture-platform', 'kind': 'implementations',
                         'version': '5.0.0', 'sha': self.parent_sha}]}))
        self.write(self.adopter, 'gitops/apps/kustomization.yaml', 'kind: Kustomization\nresources: [pod.yaml]\n')
        self.write(self.adopter, 'gitops/apps/pod.yaml', yaml.safe_dump({'kind': 'Pod', 'metadata': {
            'name': 'synthetic', 'labels': {'policy-as-versioned.dev/policy-version': '7.0.0'}}}))
        apps = self.commit(self.adopter)
        self.git(self.adopter, 'tag', 'v4.0.0')
        self.write(self.adopter, 'gitops/flux-system/gotk-sync.yaml', yaml.safe_dump_all([
            {'kind': 'GitRepository', 'metadata': {'name': 'fixture-adopter'},
             'spec': {'ref': {'tag': 'v4.0.0', 'commit': apps}}},
            {'kind': 'Kustomization', 'spec': {'path': './gitops/apps',
                'sourceRef': {'kind': 'GitRepository', 'name': 'fixture-adopter'}}}]))
        self.source = self.commit(self.adopter)
        appends = {}
        for path, (kind, count) in retirement.LANE.items():
            rows = []
            for index in range(count):
                row = {'kind': kind, 'run': '123', 'event': 'schedule', 'fixture_row': index}
                if 'oscal' in path:
                    row.update(status='observed', report_count=1, report_read_errors=[],
                               assessment_results={'fixture': 'synthetic, never production evidence'})
                rows.append(json.dumps(row) + '\n')
            data = ''.join(rows)
            self.write(self.adopter, path, data)
            appends[path] = hashlib.sha256(data.encode()).hexdigest()
        self.original = self.commit(self.adopter)
        self.record = {'schema': 1, 'kind': 'consumer-retirement', 'party': 'fixture-adopter',
                       'repository': 'fixture/adopter', 'publisher': 'fixture-platform',
                       'parent': {'version': '5.0.0', 'tag': 'v5.0.0', 'commit': self.parent_sha,
                                  'window': self.versions},
                       'retired': ['5.0.0', '6.0.0'], 'retained': ['7.0.0'],
                       'engine': {'from': '1.18.2', 'to': '1.19.1'},
                       'baseline': {'original_commit': self.original, 'source_commit': self.source,
                                    'run_id': 123, 'attempt': 1, 'appends': appends},
                       'authorization': {'decided_by': 'synthetic fixture decision',
                                         'decided_on': '2026-10-17', 'basis': 'synthetic test only'}}
        self.run = {'id': 123, 'run_attempt': 1, 'event': 'schedule', 'head_branch': 'main',
                    'head_sha': self.source, 'status': 'completed',
                    'path': '.github/workflows/drift-sample.yml',
                    'repository': {'full_name': 'fixture/adopter'}}
        self.public = {'status': 'ahead', 'merge_base_commit': {'sha': self.original}}
        self.official = Mock(side_effect=lambda path: self.run if '/actions/runs/' in path else self.public)
        self.signature = Mock()
        self.tag_signature = Mock()

    @staticmethod
    def write(repository, path, value):
        target = repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)

    @staticmethod
    def git(repository, *args):
        return subprocess.check_output(['git', '-c', 'tag.gpgsign=false', '-C', str(repository), *args],
                                       stderr=subprocess.DEVNULL, timeout=10).decode().strip()

    def commit(self, repository):
        self.git(repository, 'add', '.')
        self.git(repository, '-c', 'commit.gpgsign=false', 'commit', '-qm', 'explicit synthetic fixture')
        return self.git(repository, 'rev-parse', 'HEAD')

    def select(self):
        return retirement.select(self.adopter, self.record, 'fixture-adopter', 'fixture-platform',
                                 '5.0.0', self.parent_sha, self.parent, self.versions,
                                 official=self.official, verify_signature=self.signature,
                                 verify_tag=self.tag_signature)

    def test_exact_record_reads_official_attempt_and_public_ancestry_then_verifies_original_claims(self):
        self.assertEqual(self.select(), self.record)
        self.assertEqual(self.official.call_args_list[0].args,
                         ('repos/fixture/adopter/actions/runs/123/attempts/1',))
        self.assertEqual(self.official.call_args_list[1].args,
                         (f'repos/fixture/adopter/compare/{self.original}...main',))
        self.signature.assert_called_once_with(self.adopter, self.original, 'fixture/adopter', self.source)

    def test_dispatched_wrong_source_wrong_attempt_or_unlanded_original_cannot_supply_baseline(self):
        for field, value in [('event', 'workflow_dispatch'), ('head_sha', 'a' * 40),
                             ('run_attempt', 2), ('head_branch', 'feature'), ('status', 'in_progress')]:
            with self.subTest(field=field):
                previous = copy.deepcopy(self.run)
                self.run[field] = value
                with self.assertRaises(retirement.InvalidRetirement):
                    self.select()
                self.run = previous
        self.public['status'] = 'behind'
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'actual public main'):
            self.select()

    def test_an_official_read_failure_or_invalid_gitsign_is_not_an_asserted_success_receipt(self):
        self.official.side_effect = retirement.InvalidRetirement('official unavailable')
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'official unavailable'):
            self.select()
        self.official.side_effect = lambda path: self.run if '/actions/runs/' in path else self.public
        self.signature.side_effect = retirement.InvalidRetirement('signature did not verify')
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'signature'):
            self.select()

    def test_mutated_missing_duplicated_or_wrong_digest_rows_refuse(self):
        path = self.adopter / 'drift/oscal-samples.jsonl'
        original = path.read_bytes()
        for data in (b'', original + original, original.replace(b'"observed"', b'"could-not-look"')):
            with self.subTest(data=data[:20]):
                path.write_bytes(data)
                with self.assertRaises(retirement.InvalidRetirement):
                    self.select()
        path.write_bytes(original)
        self.record['baseline']['appends']['drift/oscal-samples.jsonl'] = 'a' * 64
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'digest'):
            self.select()

    def test_exact_parent_window_party_engine_and_support_are_bound(self):
        mutations = [lambda r: r.update(party='another-party'),
                     lambda r: r['parent'].update(commit='a' * 40),
                     lambda r: r['parent'].update(tag='policy/v7.0.0'),
                     lambda r: r['parent'].update(window=['5.0.0', '7.0.0']),
                     lambda r: r.update(retained=['6.0.0', '7.0.0']),
                     lambda r: r['engine'].update(to='1.20.0'),
                     lambda r: r.update(retained=['5.0.0'], retired=['6.0.0', '7.0.0']),
                     lambda r: r.update(unknown='must not silently ignore'),
                     lambda r: r['authorization'].update(decided_on='yesterday')]
        original = copy.deepcopy(self.record)
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.record = copy.deepcopy(original)
                mutate(self.record)
                with self.assertRaises(retirement.InvalidRetirement):
                    self.select()

    def test_original_is_required_in_current_history_even_if_official_api_says_landed(self):
        self.git(self.adopter, 'checkout', '-q', self.source)
        for path in retirement.LANE:
            self.write(self.adopter, path, 'copied text is not original history\n')
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'tree under composition'):
            self.select()

    def test_served_claims_include_nested_pod_templates_and_reject_a_retired_claim(self):
        retirement.require_claims(self.record, [{'metadata': {'labels': {
            'policy-as-versioned.dev/policy-version': '7.0.0'}}}])
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'served workload'):
            retirement.require_claims(self.record, [{'spec': {'template': {'metadata': {'labels': {
                'policy-as-versioned.dev/policy-version': '5.0.0'}}}}}])

    def test_engine_move_cannot_introduce_its_own_retirement_authorization(self):
        self.write(self.adopter, retirement.ENGINE_FILE, 'version: "1.19.1"\n')
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'already on public main'):
            retirement.require_delivered(self.adopter, self.record, official=lambda path: {})

    def test_dirty_parent_cannot_borrow_the_signed_tag_support_declaration(self):
        (self.parent / 'distribution/machinery.yaml').write_text('edited support is not signed\n')
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'unchanged pinned implementation tree'):
            self.select()

    def test_deleted_then_readded_rows_do_not_borrow_the_original_clock_attribution(self):
        path = self.adopter / 'drift/oscal-samples.jsonl'
        data = path.read_bytes()
        path.write_bytes(b'')
        self.commit(self.adopter)
        path.write_bytes(data)
        self.commit(self.adopter)
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'attributed'):
            self.select()

    def test_first_engine_flip_requires_signed_retirement_delivery_on_the_old_engine(self):
        composed = {'kind': 'GitRepository', 'spec': {'ref': {'tag': 'v9.0.0', 'commit': ''}}}
        evidence = {'members': [{'version': '7.0.0'}], 'consumer_retirements': [self.record],
                    'engine': {'declared': {'version': '1.19.1'}}}
        self.write(self.adopter, retirement.ENGINE_FILE, 'version: "1.19.1"\n')
        self.write(self.adopter, 'composed/evidence.json', json.dumps(evidence))
        delivery = self.commit(self.adopter)
        self.git(self.adopter, 'tag', 'v9.0.0')
        composed['spec']['ref']['commit'] = delivery
        source_bytes = yaml.safe_dump(composed).encode()
        self.write(self.adopter, 'gitops/composed/composed-set.yaml', source_bytes.decode())
        def encoded(data):
            return {'content': base64.b64encode(data).decode()}
        def official(path):
            if '/implementation-retirements/' in path:
                return encoded(yaml.safe_dump(self.record).encode())
            if '/gitops/engine/' in path:
                return encoded(b'version: "1.18.2"\n')
            return encoded(source_bytes)
        with patch.object(retirement, '_tag_signature'):
            with self.assertRaisesRegex(retirement.InvalidRetirement, 'baseline engine'):
                retirement.require_delivered(self.adopter, self.record, official=official)
            # Once the public engine has actually moved, new-engine compositions
            # remain possible: the first-transition guard is not a permanent freeze.
            def after_move(path):
                if '/gitops/engine/' in path:
                    return encoded(b'version: "1.19.1"\n')
                return official(path)
            retirement.require_delivered(self.adopter, self.record, official=after_move)

    def test_duplicate_record_keys_cannot_silently_replace_authorization(self):
        directory = self.adopter / retirement.DIRECTORY
        directory.mkdir()
        (directory / 'fixture-platform.yaml').write_text('schema: 1\nschema: 2\n')
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'unique'):
            retirement.read_records(self.adopter, {'fixture-platform'})

    def test_the_shared_admission_reads_real_before_after_graph_and_keeps_major(self):
        self.write(self.adopter, retirement.DIRECTORY + '/fixture-platform.yaml', yaml.safe_dump(self.record))
        before = json.loads((self.adopter / 'composed/evidence.json').read_text())
        after = dict(before, members=[{'version': '7.0.0'}], consumer_retirements=[self.record])
        self.write(self.adopter, 'composed/evidence.json', json.dumps(after))
        proposal = self.commit(self.adopter)
        def admit():
            return retirement.admit(self.adopter, self.parent, self.source, proposal,
                                    official=self.official, verify_signature=self.signature,
                                    verify_tag=self.tag_signature)
        self.assertEqual(admit(), {'admitted': True, 'bump': 'major', 'retired': ['5.0.0', '6.0.0'],
                                  'retained': ['7.0.0'], 'publisher': 'fixture-platform'})
        # The authority for removing5/6 cannot admit an extra removed7 or a
        # head that merely claims it used this reader without matching the record.
        after['consumer_retirements'] = []
        self.write(self.adopter, 'composed/evidence.json', json.dumps(after))
        proposal = self.commit(self.adopter)
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'omits or changes'):
            admit()


if __name__ == '__main__':
    unittest.main()
