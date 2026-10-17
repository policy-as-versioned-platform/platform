#!/usr/bin/env python3
"""Native inventory CLI/Git/gh-call regression; no scanner or live credentials.

Composition and GitHub are explicit synthetic stand-ins. Disposable fixture
commits are unsigned: this does not claim genuine scan/signature issuance,
remote publication, permission validation or a GitHub title length limit.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import contextlib
import io

SPEC = importlib.util.spec_from_file_location('inventory', Path(__file__).with_name('inventory.py'))
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), '-c', 'commit.gpgsign=false',
                           '-c', 'tag.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                           *args], check=True, capture_output=True, text=True).stdout.strip()


class Publication(unittest.TestCase):
    def setUp(self):
        temporary = self.enterContext(tempfile.TemporaryDirectory(prefix='inventory-publication-'))
        self.root = Path(temporary).resolve()
        self.work, self.remote = self.root/'ludlow', self.root/'remote.git'
        self.work.mkdir()
        image = 'ghcr.io/example-institution/reports@sha256:' + 'a'*64
        self.old = {'schema_version': '1.0.0', 'images': [{'image': image,
            'digest': image.split('@')[1], 'scanner_version': '0.69.3',
            'database_date': '2026-10-17T00:00:00Z', 'vulnerabilities': [
                {'id': f'CVE-2026-{10000+i}', 'package': f'package-{i}',
                 'installed_version': '1.0', 'fixed_version': '1.1', 'severity': 'HIGH'}
                for i in range(300)]}]}
        self.new = json.loads(json.dumps(self.old))
        self.new['images'][0]['vulnerabilities'] = self.old['images'][0]['vulnerabilities'][1:] + [
            {'id': 'CVE-2026-99999', 'package': 'new-package', 'installed_version': '2.0',
             'fixed_version': '', 'severity': 'CRITICAL'}]
        (self.work/'inventory').mkdir(); (self.work/'composed').mkdir()
        (self.work/'inventory/images.json').write_text(json.dumps(self.old))
        (self.work/'composed/HEADER.yaml').write_text('synthetic: source\n')
        (self.work/'composed/evidence.json').write_text('{"coverage": "stale source"}\n')
        (self.work/'party.yaml').write_text('party: ludlow\n')
        git(self.work, 'init', '-q', '-b', 'main')
        for key, value in [('commit.gpgsign', 'false'), ('core.hooksPath', '/dev/null'),
                           ('user.name', 'Unsigned inventory fixture'), ('user.email', 'fixture@example.invalid')]:
            git(self.work, 'config', key, value)
        git(self.work, 'add', '.'); git(self.work, 'commit', '-qm', 'Synthetic inventory source')
        git(self.work, 'init', '-q', '--bare', str(self.remote))
        git(self.work, 'remote', 'add', 'origin', str(self.remote))
        git(self.work, 'push', '-qu', 'origin', 'main')
        self.source = git(self.work, 'rev-parse', 'HEAD')
        candidate, prior = self.root/'candidate.json', self.root/'prior.json'
        self.output, self.call = self.root/'proposals.json', self.root/'publication.json'
        candidate.write_text(json.dumps(self.new)); prior.write_text('[]')
        # The actual Ludlow workflow invokes inventory.py directly with these flags.
        self.enterContext(patch.object(sys, 'argv', [str(Path(inventory.__file__)), 'propose',
            '--adopter-dir', str(self.work), '--org', 'ludlow', '--candidate', str(candidate),
            '--prior-proposals', str(prior), '--out', str(self.output)]))
        self.document = {'outcome': 'composed', 'coverage': {'count': 388, 'note': 'café'}}
        self.generated = {'composed/HEADER.yaml': 'synthetic: proposal\n',
                          'composed/generated/policy.yaml': 'synthetic: generated policy\n'}
        composition = SimpleNamespace(_default_parent_trees=lambda *args: {},
            compose=lambda *args: (self.document, self.generated))
        self.enterContext(patch.dict(sys.modules, {'composition': composition}))
        tools = self.root/'bin'; tools.mkdir()
        (tools/'gh').write_text(f'#!{sys.executable}\n' +
            'import json, os, pathlib, sys\n'
            'args=sys.argv[1:]\n'
            "if args[:2]==['pr','list']:\n"
            " if 'closed' not in args and os.environ.get('FIXTURE_LIST_FAILURE'):\n"
            "  print('HTTP 403: cannot list open PRs token='+os.environ['GH_TOKEN'],file=sys.stderr); raise SystemExit(1)\n"
            " print('[]' if 'closed' in args else os.environ.get('FIXTURE_OPEN_PR','')); raise SystemExit\n"
            "assert args[:2] in (['pr','create'],['pr','edit']),args\n"
            "body=pathlib.Path(args[args.index('--body-file')+1]).read_text()\n" +
            f"pathlib.Path({str(self.call)!r}).write_text(json.dumps({{'argv':args,'body':body}}))\n" +
            "failure=os.environ.get('FIXTURE_PR_FAILURE','')\n"
            "if failure=='silent': raise SystemExit(1)\n"
            "if failure:\n"
            " print(failure+' token='+os.environ['GH_TOKEN'],file=sys.stderr); raise SystemExit(1)\n"
            "print('https://example.invalid/fixture/pull/7')\n")
        (tools/'gh').chmod(0o755)
        self.enterContext(patch.dict(os.environ, {'PATH': str(tools)+os.pathsep+os.environ['PATH'],
            'GITHUB_REPOSITORY': 'fixture/fixture', 'GH_TOKEN': 'synthetic-sensitive-token',
            'FIXTURE_OPEN_PR': '', 'FIXTURE_PR_FAILURE': '', 'FIXTURE_LIST_FAILURE': ''}))
        self.stderr = self.enterContext(contextlib.redirect_stderr(io.StringIO()))

    def assert_main_preserved(self):
        self.assertEqual(git(self.remote, 'rev-parse', 'main'), self.source)
        self.assertEqual(git(self.work, 'branch', '--show-current'), 'main')
        self.assertEqual(git(self.work, 'status', '--porcelain'), '')

    def assert_publication(self, existing):
        os.environ['FIXTURE_OPEN_PR'] = '7' if existing else ''
        self.assertEqual(inventory.main(), 0)
        request = json.loads(self.call.read_text())
        self.assertEqual(request['argv'][:2], ['pr', 'edit' if existing else 'create'])
        title = request['argv'][request['argv'].index('--title')+1]
        self.assertEqual(title, '[war-gamer] update served image inventory (ludlow)')
        # Semantic title, complete typed facts: no truncation or numeric API-limit claim.
        change = {'target': inventory.INVENTORY_PATH,
                  'from': inventory.id_sets(self.old), 'to': inventory.id_sets(self.new)}
        body_change = json.loads(request['body'].split('```json\n', 1)[1].split('\n```', 1)[0])
        self.assertEqual(body_change, change)
        proposed = json.loads(self.output.read_text())[0]
        self.assertEqual(proposed['change'], change)
        self.assertIn(proposed['ledger_marker'], request['body'])
        self.assertIs(proposed['merged'], False)
        self.assertIs(proposed['auto_merge'], False)
        self.assertEqual(proposed['landed']['action'], 'updated' if existing else 'created')
        branch = proposed['branch']
        self.assertEqual(git(self.work, 'show', branch+':inventory/images.json'),
                         json.dumps(self.new, indent=2, sort_keys=True))
        # The real compose CLI writes this separately returned document after
        # generated files. Exercise the actual proposal commit, not a helper.
        expected_evidence = (b'{\n  "outcome": "composed",\n  "coverage": {\n'
                             b'    "count": 388,\n    "note": "caf\\u00e9"\n  }\n}')
        self.assertEqual(subprocess.check_output(['git', '-C', str(self.work), 'show',
                                                 branch+':composed/evidence.json']), expected_evidence)
        for relative, body in self.generated.items():
            self.assertEqual(subprocess.check_output(['git', '-C', str(self.work), 'show',
                                                     branch+':'+relative]), body.encode())
        self.assertEqual(git(self.work, 'diff', '--name-only', self.source, branch).splitlines(),
                         ['composed/HEADER.yaml', 'composed/evidence.json',
                          'composed/generated/policy.yaml', 'inventory/images.json'])
        self.assert_main_preserved()

    def test_create_preserves_full_change(self):
        self.assert_publication(False)

    def test_update_preserves_full_change(self):
        self.assert_publication(True)

    def assert_canonical_composition(self, relative):
        # Use the genuine composer with its smallest existing fixture parents.
        # A twin borrowing its feed's frequency makes the switching-cost absence
        # path-sensitive when that feed is dropped, just like real Driftwood.
        platform = Path(inventory.__file__).resolve().parents[1]
        self.enterContext(patch.object(sys, 'path', [str(platform/'compose'), *sys.path]))
        spec = importlib.util.spec_from_file_location('composition', platform/'compose/composition.py')
        real = importlib.util.module_from_spec(spec)
        self.enterContext(patch.dict(sys.modules, {'composition': real}))
        spec.loader.exec_module(real)
        # Machinery renderers import this shared module by name.
        self.enterContext(patch.object(sys, 'path', [str(platform/'distribution'), *sys.path]))
        import cage_body
        self.enterContext(patch.dict(sys.modules, {'cage_body': cage_body}))
        real._write_fixture_catalog(self.root/'fixture-nist')
        real._write_fixture_platform(self.root/'fixture-platform', platform, [])
        edge = {'party': 'fixture-publisher', 'kind': 'feed', 'name': 'threat-register',
                'version': 'v1', 'since': '2026-09-01'}
        real._write_fixture_adopter(self.work, 'SMALL', extra_inherits=[edge])
        from fixture_inventory import write_inventory_fixture
        write_inventory_fixture(self.work, ['fixture'])
        feed = self.root/'fixture-publisher/threat-register/v1/feed.json'
        feed.parent.mkdir(parents=True)
        feed.write_text(json.dumps({'kind': 'feed', 'name': 'threat-register', 'version': '1.0.0',
            'published_by': 'fixture-publisher', 'published_at': '2026-10-03T00:00:00Z',
            'payload_schema': 'threat-register/payload.schema.json', 'payload': {
                'currency': 'GBP', 'institutions': {'fixture-adopter14': {
                    'lef': [1, 2, 3], 'threat': 'declared fixture', 'flavour': 'regression',
                    'source': 'synthetic frequency', 'lm_gbp': [1000, 2000, 3000],
                    'lm_basis': {'statement': 'declared synthetic magnitude', 'as_of': '2026-10-03'}}}}}))
        twin = self.work/'twin/forward-intel/v1/feed.json'
        twin.parent.mkdir(parents=True)
        twin.write_text(json.dumps({'kind': 'feed', 'name': 'forward-intel', 'version': '1.0.0',
            'published_by': 'fixture-adopter14', 'published_at': '2026-10-03T00:00:00Z',
            'payload_schema': 'twin/forward-intel/payload.schema.json', 'payload': {
                'perspective': 'fixture-adopter14', 'currency': 'GBP', 'lef': None,
                'lm': [10, 20, 30], 'derived_from': [edge]}}))
        policy = self.work/'selection-policy/selection_policy.py'
        policy.parent.mkdir()
        policy.write_text("VERSION = 'declared-fixture'\n"
                          "def select(residuals, tolerance, floor):\n"
                          "    return {'tier': 'isolated', 'policy_version': VERSION,\n"
                          "            'basis': 'synthetic fixture always selects the bottom rung'}\n")
        # This is an unsigned disposable source, never an observed real feed.
        git(self.work, 'add', '.'); git(self.work, 'commit', '-qm', 'Canonical composer fixture')
        git(self.work, 'push', '-q', 'origin', 'main')
        self.source = git(self.work, 'rev-parse', 'HEAD')
        candidate = json.loads((self.work/'inventory/images.json').read_text())
        extra = dict(candidate['images'][0]['vulnerabilities'][0], id='new-fixture')
        candidate['images'][0]['vulnerabilities'].append(extra)
        (self.root/'candidate.json').write_text(json.dumps(candidate))
        adopter_arg = self.work.name if relative else str(self.work)
        sys.argv[sys.argv.index('--adopter-dir')+1] = adopter_arg
        caller = Path.cwd()
        with contextlib.chdir(self.root):
            self.assertEqual(inventory.main(), 0, self.stderr.getvalue())
            self.assertEqual(Path.cwd(), self.root)
        self.assertEqual(Path.cwd(), caller)
        branch = json.loads(self.output.read_text())[0]['branch']
        git(self.work, 'checkout', '-q', branch)
        try:
            # The published adopter wrapper forwards `.` and cwd=adopter,
            # with estate/output paths resolved before entering that cwd.
            output = self.root/'canonical-output'
            with contextlib.chdir(self.work), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(real.cmd_compose(Path('.'), self.root, output), 0)
            generated = {str(p.relative_to(output)): p.read_bytes()
                         for p in output.rglob('*') if p.is_file()}
            self.assertIn('composed/HANDBOOK.md', generated)
            document = json.loads(generated['composed/evidence.json'])
            switching = next(p for p in document['prices'] if p['kind'] == 'switching')
            self.assertTrue(switching['could_not_look'].startswith('missing instrument: twin/'))
            for path, expected in generated.items():
                with self.subTest(path=path, relative=relative):
                    self.assertEqual((self.work/path).read_bytes(), expected)
        finally:
            git(self.work, 'checkout', '-q', 'main')
        self.assert_main_preserved()

    def test_real_composer_matches_canonical_wrapper_from_relative_adopter(self):
        self.assert_canonical_composition(True)

    def test_real_composer_matches_canonical_wrapper_from_absolute_adopter(self):
        self.assert_canonical_composition(False)

    def test_composition_refusal_restores_caller_cwd(self):
        import composition
        with patch.object(composition, 'compose', return_value=(
                {'outcome': 'refused', 'refusals': ['declared fixture refusal']}, {})):
            caller = Path.cwd()
            self.assertEqual(inventory.main(), 2)
            self.assertEqual(Path.cwd(), caller)
        self.assertIn('declared fixture refusal', self.stderr.getvalue())
        # A refusal leaves the candidate inventory unstaged on main, as before.
        self.assertEqual(git(self.work, 'branch', '--show-current'), 'main')
        self.assertEqual(git(self.remote, 'rev-parse', 'main'), self.source)
        self.assertFalse(self.output.exists())

    def test_composition_exception_restores_caller_cwd(self):
        import composition
        with patch.object(composition, 'compose', side_effect=RuntimeError('fixture failure')):
            caller = Path.cwd()
            with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
                inventory.main()
            self.assertEqual(Path.cwd(), caller)
        self.assertEqual(git(self.work, 'branch', '--show-current'), 'main')
        self.assertEqual(git(self.remote, 'rev-parse', 'main'), self.source)
        self.assertFalse(self.output.exists())

    def assert_failure(self, message):
        os.environ['FIXTURE_PR_FAILURE'] = message
        self.assertEqual(inventory.main(), 2)
        error = self.stderr.getvalue()
        self.assertIn(message, error)
        self.assertNotIn('synthetic-sensitive-token', error)
        self.assertIn('<REDACTED>', error)
        self.assert_main_preserved()
        self.assertTrue(git(self.remote, 'rev-parse', 'wargamer/retune-ludlow-served-images'))
        self.assertFalse(self.output.exists())

    def test_permission_error_remains_actionable(self):
        self.assert_failure('HTTP 403: pull request creation is disabled')

    def test_validation_error_remains_actionable(self):
        os.environ['FIXTURE_OPEN_PR'] = '7'
        self.assert_failure('HTTP 422: title validation failed')

    def test_open_pr_query_error_remains_actionable(self):
        os.environ['FIXTURE_LIST_FAILURE'] = '1'
        self.assertEqual(inventory.main(), 2)
        self.assertIn('gh pr list failed (exit 1): HTTP 403: cannot list open PRs', self.stderr.getvalue())
        self.assertIn('<REDACTED>', self.stderr.getvalue())
        self.assertNotIn('synthetic-sensitive-token', self.stderr.getvalue())
        self.assert_main_preserved()

    def test_empty_stderr_still_fails_without_inventing_a_cause(self):
        os.environ['FIXTURE_PR_FAILURE'] = 'silent'
        self.assertEqual(inventory.main(), 2)
        self.assertIn('gh pr create failed (exit 1): no diagnostic on stderr', self.stderr.getvalue())
        self.assert_main_preserved()


if __name__ == '__main__':
    unittest.main()
