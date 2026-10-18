"""An explicit retirement is verified at the real composition seam, never silently ignored."""
import copy
import base64
from email.message import Message
import hashlib
from http.client import IncompleteRead
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request
import urllib.response

import yaml

import composition as ct
import consumer_retirement as retirement

import test_engine_pairing


class RetirementOfficialReads(unittest.TestCase):
    """Actual gh authentication refusal; HTTPS responses are explicit data fixtures."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='retirement-official-fixture-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        allowed = ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'SSL_CERT_FILE', 'SSL_CERT_DIR')
        environment = {key: os.environ[key] for key in allowed if key in os.environ}
        environment.update(GH_CONFIG_DIR=str(self.root), GH_PROMPT_DISABLED='1')
        isolated = patch.dict(os.environ, environment, clear=True)
        isolated.start()
        self.addCleanup(isolated.stop)
        self.requests = []
        self.http_status = 200
        self.http_body = b'{"full_name":"fixture/adopter","default_branch":"main"}'
        self.expected_url = 'https://api.github.com/repos/fixture/adopter'

    def fixture_gh(self, exit_code, body=b'', error=b'explicit synthetic gh fixture'):
        tools = self.root / 'bin'
        tools.mkdir(exist_ok=True)
        command = tools / 'gh'
        command.write_text('#!' + sys.executable + '\nimport sys\n'
                           'sys.stdout.buffer.write(' + repr(body) + ')\n'
                           'sys.stderr.buffer.write(' + repr(error) + ')\n'
                           'sys.exit(' + str(exit_code) + ')\n')
        command.chmod(0o755)
        os.environ['PATH'] = str(tools) + os.pathsep + os.environ.get('PATH', '')

    def fixture_https(self, opener, request, *args, **kwargs):
        """External HTTP data adapter, never a real GitHub response or authority claim."""
        self.assertEqual(request.full_url, self.expected_url)
        self.assertEqual(request.get_method(), 'GET')
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertNotIn('authorization', headers)
        self.assertNotIn('proxy-authorization', headers)
        self.assertEqual(headers['accept'], 'application/vnd.github+json')
        self.assertEqual(headers['x-github-api-version'], '2022-11-28')
        self.assertTrue(headers['user-agent'])
        self.assertEqual(kwargs.get('timeout'), 60)
        self.requests.append(request)
        response = Mock()
        response.status = self.http_status
        response.read.return_value = self.http_body
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        return response

    def test_authentication_required_gh_can_read_a_public_object_without_gate_credentials(self):
        if shutil.which('gh') is None:
            self.skipTest('the actual gh authentication-preflight regression needs gh installed')
        with patch.object(urllib.request.OpenerDirector, 'open', autospec=True,
                          side_effect=self.fixture_https):
            value = retirement._official('repos/fixture/adopter')
        self.assertEqual(value, {'full_name': 'fixture/adopter', 'default_branch': 'main'})
        self.assertEqual(len(self.requests), 1)

    def test_configured_gh_success_never_uses_public_fallback(self):
        self.fixture_gh(0, b'{"full_name":"fixture/adopter","default_branch":"main"}')
        with patch.object(urllib.request.OpenerDirector, 'open',
                          side_effect=AssertionError('successful gh must keep its existing transport')):
            value = retirement._official('repos/fixture/adopter')
        self.assertEqual(value, {'full_name': 'fixture/adopter', 'default_branch': 'main'})

    def test_other_gh_failures_never_use_public_fallback(self):
        for exit_code in (1, 2, 3):
            with self.subTest(exit_code=exit_code):
                self.fixture_gh(exit_code, error=b'explicit fixture API denial or transport error')
                with patch.object(urllib.request.OpenerDirector, 'open',
                                  side_effect=AssertionError('only auth-required exit 4 can fall back')):
                    with self.assertRaises(retirement.InvalidRetirement):
                        retirement._official('repos/fixture/adopter')

    def test_invalid_gh_json_or_nonobject_never_uses_public_fallback(self):
        for body in (b'not JSON', b'[]', b'null'):
            with self.subTest(body=body):
                self.fixture_gh(0, body)
                with patch.object(urllib.request.OpenerDirector, 'open',
                                  side_effect=AssertionError('bad gh data is not an auth refusal')):
                    with self.assertRaises(retirement.InvalidRetirement):
                        retirement._official('repos/fixture/adopter')

    def test_missing_gh_remains_an_unavailable_instrument_without_fallback(self):
        os.environ['PATH'] = str(self.root)
        with patch.object(urllib.request.OpenerDirector, 'open',
                          side_effect=AssertionError('missing gh is outside the exit-4 repair')):
            with self.assertRaises(retirement.InvalidRetirement):
                retirement._official('repos/fixture/adopter')

    def test_native_public_get_never_sends_synthetic_environment_tokens(self):
        self.fixture_gh(4)
        os.environ.update(GH_TOKEN='synthetic-fixture-token-never-send',
                          GITHUB_TOKEN='synthetic-other-fixture-token-never-send')
        self.expected_url += '/contents/a.yaml?ref=release%2Fcurrent'
        with patch.object(urllib.request.OpenerDirector, 'open', autospec=True,
                          side_effect=self.fixture_https):
            value = retirement._official('repos/fixture/adopter/contents/a.yaml?ref=release%2Fcurrent')
        self.assertEqual(value['full_name'], 'fixture/adopter')
        self.assertEqual(len(self.requests), 1)
        self.assertNotIn('synthetic-', str(self.requests[0].header_items()))
        self.assertNotIn('synthetic-', self.requests[0].full_url)

    def test_invalid_native_json_and_nonobjects_are_refused(self):
        self.fixture_gh(4)
        for body in (b'not JSON', b'[]', b'null', b'false', b'1', b'"text"'):
            with self.subTest(body=body):
                self.http_body = body
                with patch.object(urllib.request.OpenerDirector, 'open', autospec=True,
                                  side_effect=self.fixture_https):
                    with self.assertRaises(retirement.InvalidRetirement):
                        retirement._official('repos/fixture/adopter')

    def test_native_bad_http_and_redirect_responses_are_refused(self):
        self.fixture_gh(4)
        for status in (301, 302, 403, 404, 429, 500):
            with self.subTest(status=status):
                self.http_status = status
                with patch.object(urllib.request.OpenerDirector, 'open', autospec=True,
                                  side_effect=self.fixture_https):
                    with self.assertRaises(retirement.InvalidRetirement):
                        retirement._official('repos/fixture/adopter')

    def test_native_http_exception_and_timeout_are_named_unavailable(self):
        self.fixture_gh(4)
        errors = (TimeoutError('explicit fixture timeout'),
                  IncompleteRead(b'explicit partial fixture body'),
                  urllib.error.URLError('explicit fixture transport error'),
                  urllib.error.HTTPError(self.expected_url, 403, 'explicit fixture denial', {}, None))
        for error in errors:
            if isinstance(error, urllib.error.HTTPError):
                self.addCleanup(error.close)
            with self.subTest(error=type(error).__name__):
                with patch.object(urllib.request.OpenerDirector, 'open', side_effect=error) as http:
                    with self.assertRaisesRegex(retirement.InvalidRetirement,
                                                'official GitHub GET unavailable for repos/fixture/adopter'):
                        retirement._official('repos/fixture/adopter')
                self.assertEqual(http.call_count, 1)

    def test_native_redirect_never_requests_a_second_or_different_origin(self):
        self.fixture_gh(4)
        requests = []
        def fixture_transport(handler, request):
            requests.append(request)
            self.assertEqual(request.full_url, self.expected_url)
            headers = Message()
            headers['Location'] = 'https://example.invalid/never-request-this-fixture'
            response = urllib.response.addinfourl(BytesIO(b''), headers, request.full_url, 302)
            response.msg = 'explicit fixture redirect'
            self.addCleanup(response.close)
            return response
        with patch.object(urllib.request.HTTPSHandler, 'https_open', autospec=True,
                          side_effect=fixture_transport):
            with self.assertRaises(retirement.InvalidRetirement) as unavailable:
                retirement._official('repos/fixture/adopter')
        self.assertEqual(len(requests), 1)
        self.assertTrue(unavailable.exception.__cause__.closed)

    def test_native_https_handler_excludes_environment_proxy_authentication(self):
        self.fixture_gh(4)
        requests = []
        def fixture_transport(handler, request):
            headers = {key.lower(): value for key, value in request.header_items()}
            self.assertNotIn('authorization', headers)
            self.assertNotIn('proxy-authorization', headers)
            self.assertEqual(request.full_url, self.expected_url)
            self.assertEqual(request.host, 'api.github.com')
            self.assertEqual(request.get_method(), 'GET')
            requests.append(request)
            response = urllib.response.addinfourl(BytesIO(self.http_body), Message(), request.full_url, 200)
            response.msg = 'explicit synthetic HTTPS fixture'
            self.addCleanup(response.close)
            return response
        for proxy_name in ('HTTPS_PROXY', 'https_proxy'):
            with self.subTest(proxy_name=proxy_name):
                environment = {proxy_name: 'http://synthetic-user:synthetic-proxy-secret@proxy.fixture.invalid:8443'}
                with patch.dict(os.environ, environment), \
                        patch.object(urllib.request.HTTPSHandler, 'https_open', autospec=True,
                                     side_effect=fixture_transport):
                    value = retirement._official('repos/fixture/adopter')
                self.assertEqual(value, {'full_name': 'fixture/adopter', 'default_branch': 'main'})
        self.assertEqual(len(requests), 2)

    def test_native_object_still_requires_the_exact_repository_and_default_branch(self):
        self.fixture_gh(4)
        for body in (b'{}', b'{"full_name":"fixture/other","default_branch":"main"}',
                     b'{"full_name":"fixture/adopter","default_branch":null}'):
            with self.subTest(body=body):
                self.http_body = body
                with patch.object(urllib.request.OpenerDirector, 'open', autospec=True,
                                  side_effect=self.fixture_https):
                    with self.assertRaises(retirement.InvalidRetirement):
                        retirement._default_branch(self.root, 'fixture/adopter', retirement._official)


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
        self.metadata = {'full_name': 'fixture/adopter', 'default_branch': 'main'}
        self.official = Mock(side_effect=self.official_read)
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

    def official_read(self, path):
        if path == 'repos/fixture/adopter':
            return self.metadata
        return self.run if '/actions/runs/' in path else self.public

    def select(self):
        return retirement.select(self.adopter, self.record, 'fixture-adopter', 'fixture-platform',
                                 '5.0.0', self.parent_sha, self.parent, self.versions,
                                 official=self.official, verify_signature=self.signature,
                                 verify_tag=self.tag_signature)

    def test_exact_record_reads_official_attempt_and_public_ancestry_then_verifies_original_claims(self):
        self.assertEqual(self.select(), self.record)
        self.assertEqual(self.official.call_args_list[0].args, ('repos/fixture/adopter',))
        self.assertEqual(self.official.call_args_list[1].args,
                         ('repos/fixture/adopter/actions/runs/123/attempts/1',))
        self.assertEqual(self.official.call_args_list[2].args,
                         (f'repos/fixture/adopter/compare/{self.original}...main',))
        self.signature.assert_called_once_with(self.adopter, self.original, 'fixture/adopter', self.source, 'main')

    def test_a_non_main_default_binds_the_run_comparison_and_certificate_ref(self):
        self.metadata['default_branch'] = 'release/current'
        self.run['head_branch'] = 'release/current'
        self.git(self.adopter, 'branch', 'release/current', self.original)
        self.assertEqual(self.select(), self.record)
        self.signature.assert_called_once_with(
            self.adopter, self.original, 'fixture/adopter', self.source, 'release/current')
        self.assertIn(f'repos/fixture/adopter/compare/{self.original}...release%2Fcurrent',
                      [call.args[0] for call in self.official.call_args_list])
        with patch.object(retirement, '_command') as command:
            retirement._signature(self.adopter, self.original, 'fixture/adopter', self.source, 'release/current')
        self.assertIn('--certificate-github-workflow-ref=refs/heads/release/current', command.call_args.args[0])
        self.assertIn('--certificate-identity=https://github.com/fixture/adopter/.github/workflows/'
                      'drift-sample.yml@refs/heads/release/current', command.call_args.args[0])

    def test_actual_default_metadata_is_exact_and_ref_well_formed(self):
        for metadata in ({'full_name': 'other/repo', 'default_branch': 'main'},
                         {'full_name': 'fixture/adopter', 'default_branch': 'bad branch'},
                         {'full_name': 'fixture/adopter'}):
            with self.subTest(metadata=metadata):
                self.metadata = metadata
                with self.assertRaises(retirement.InvalidRetirement):
                    self.select()

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
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'actual public default'):
            self.select()

    def test_an_official_read_failure_or_invalid_gitsign_is_not_an_asserted_success_receipt(self):
        self.official.side_effect = retirement.InvalidRetirement('official unavailable')
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'official unavailable'):
            self.select()
        self.official.side_effect = self.official_read
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
        with self.assertRaisesRegex(retirement.InvalidRetirement, 'actual|public|repository'):
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
            if path == 'repos/fixture/adopter':
                return self.metadata
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

    def test_first_engine_transition_reads_every_authority_file_from_actual_default(self):
        self.metadata['default_branch'] = 'release/current'
        self.write(self.adopter, 'composed/evidence.json', json.dumps({
            'members': [{'version': '7.0.0'}], 'consumer_retirements': [self.record],
            'engine': {'declared': {'version': '1.18.2'}}}))
        delivery = self.commit(self.adopter)
        self.git(self.adopter, 'tag', 'v9.0.0')
        source = yaml.safe_dump({'kind': 'GitRepository', 'spec': {'ref': {
            'tag': 'v9.0.0', 'commit': delivery}}}).encode()
        self.write(self.adopter, 'gitops/composed/composed-set.yaml', source.decode())
        self.write(self.adopter, retirement.ENGINE_FILE, 'version: "1.19.1"\n')
        calls = []
        def official(path):
            calls.append(path)
            if path == 'repos/fixture/adopter':
                return self.metadata
            if not path.endswith('?ref=release%2Fcurrent'):
                raise AssertionError('reader used stale main instead of the actual default')
            if '/implementation-retirements/' in path:
                data = yaml.safe_dump(self.record).encode()
            elif '/gitops/engine/' in path:
                data = b'version: "1.18.2"\n'
            else:
                data = source
            return {'content': base64.b64encode(data).decode()}
        with patch.object(retirement, '_tag_signature'):
            retirement.require_delivered(self.adopter, self.record, official=official)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(path.endswith('?ref=release%2Fcurrent') for path in calls[1:]))

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
