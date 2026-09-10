"""Public compatibility seam: real Git histories, external CLI fixtures."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


class EngineCompatibility(unittest.TestCase):
    def test_missing_binary_is_not_compatibility(self):
        spec = importlib.util.spec_from_file_location('engine_compatibility', HERE / 'engine_compatibility.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.check(HERE.parent, '/nonexistent/kyverno')
        self.assertEqual(result['outcome'], 'could-not-look')
        self.assertIn('binary', result['reason'])


class PublishedMatrix(unittest.TestCase):
    def setUp(self):
        import tempfile, subprocess, yaml, sys
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.subprocess = subprocess
        self.yaml = yaml
        spec = importlib.util.spec_from_file_location('engine_compatibility', HERE / 'engine_compatibility.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@invalid')
        for family in ('cage-tier', 'cage-netpol'):
            policy = self.repo / f'distribution/policies/v1.0.0/{family}.yaml'
            policy.parent.mkdir(parents=True, exist_ok=True)
            policy.write_text(yaml.safe_dump({'apiVersion': 'policies.kyverno.io/v1alpha1',
                'kind': 'MutatingPolicy' if family == 'cage-tier' else 'GeneratingPolicy',
                'metadata': {'name': family+'-1-0-0'}, 'spec': {'marker': 'published'}}))
            fixture = self.repo / 'graded/tests' / family
            fixture.mkdir(parents=True)
            (fixture / 'kyverno-test.yaml').write_text(yaml.safe_dump({'policies': ['unused'],
                'results': [{'policy': family, 'rule': family, 'resources': ['fixture'], 'result': 'pass'}]}))
            (fixture / 'resources.yaml').write_text('kind: Pod\nmetadata:\n  name: fixture\n  labels: {}\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'published fixture')
        self.commit = self.git('rev-parse', 'HEAD')
        self.git('tag', '-a', 'policy/v1.0.0', '-m', 'unsigned fixture, never production evidence')
        self.entry = {'version': '1.0.0', 'tag': 'policy/v1.0.0', 'commit': self.commit,
            'tested_engines': {'scope': self.module.SCOPE, 'kyverno': ['1.18.2']}}
        self.declare()
        self.binary = self.root / 'kyverno-fixture'
        self.binary.write_text(f'''#!{sys.executable}
import sys, pathlib, yaml
if sys.argv[1]=='version':
 print('Version: '+pathlib.Path(__file__).with_suffix('.version').read_text().strip())
else:
 doc=yaml.safe_load((pathlib.Path(sys.argv[2])/'kyverno-test.yaml').read_text())
 policy=yaml.safe_load(pathlib.Path(doc['policies'][0]).read_text())
 assert policy['spec']['marker']=='published', 'not the published tree'
 mode=pathlib.Path(__file__).with_suffix('.mode').read_text().strip()
 if mode=='fail':
  print('Test Summary: 0 tests passed and 1 tests failed');sys.exit(1)
 elif mode=='zero': print('Test Summary: 0 tests passed and 0 tests failed')
 else: print('Test Summary: 1 tests passed and 0 tests failed')
''')
        self.binary.chmod(0o755)
        self.binary.with_suffix('.version').write_text('1.18.2')
        self.binary.with_suffix('.mode').write_text('pass')

    def git(self, *args):
        return self.subprocess.check_output(['git', '-C', str(self.repo), '-c', 'core.hooksPath=/dev/null',
            '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', *args], text=True).strip()

    def declare(self):
        (self.repo / 'distribution/versions.yaml').write_text(self.yaml.safe_dump(
            {'spec': {'inputs': [{'versions': [self.entry]}]}}))

    def check(self):
        return self.module.check(self.repo, str(self.binary))

    def test_published_tree_and_binary_identity_are_reported_not_working_policies(self):
        import hashlib
        (self.repo/'distribution/policies/v1.0.0/cage-tier.yaml').write_text('spec: {marker: changed}\n')
        result = self.check()
        self.assertEqual(result['outcome'], 'passed', result)
        row = result['rows'][0]
        self.assertEqual(row['tag_commit'], self.commit)
        self.assertEqual(len(row['matrices']), 2)
        self.assertEqual(row['prerelease_api_versions'], ['policies.kyverno.io/v1alpha1'])
        self.assertEqual(result['engine']['sha256'], hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def test_undeclared_engine_and_missing_declaration_are_unknown(self):
        self.binary.with_suffix('.version').write_text('1.19.0')
        self.assertEqual(self.check()['outcome'], 'could-not-look')
        self.binary.with_suffix('.version').write_text('1.18.2')
        self.entry.pop('tested_engines');self.declare()
        self.assertEqual(self.check()['outcome'], 'could-not-look')

    def test_failed_or_zero_assertions_never_report_compatibility(self):
        for mode in ('fail', 'zero'):
            with self.subTest(mode=mode):
                self.binary.with_suffix('.mode').write_text(mode)
                self.assertEqual(self.check()['outcome'], 'failed')

    def test_pin_and_tag_tree_mismatch_refuses(self):
        (self.repo/'distribution/policies/v1.0.0/cage-tier.yaml').write_text('spec: {marker: changed}\n')
        self.git('add', '.');self.git('commit', '-qm', 'different tree')
        self.entry['commit'] = self.git('rev-parse', 'HEAD');self.declare()
        result = self.check()
        self.assertEqual(result['outcome'], 'failed')
        self.assertIn('differs', result['rows'][0]['reason'])

    def test_uncut_policy_is_not_reported_as_tested(self):
        self.entry.pop('commit');self.declare()
        self.assertEqual(self.check()['outcome'], 'could-not-look')

    def test_unavailable_historical_inputs_are_not_incompatibility(self):
        self.git('tag', '-d', 'policy/v1.0.0')
        result = self.check()
        self.assertEqual(result['outcome'], 'could-not-look', result)
        self.assertIn('unavailable', result['rows'][0]['reason'])
        self.git('tag', '-a', 'policy/v1.0.0', '-m', 'restored synthetic tag')
        self.entry['commit'] = 'f' * 40
        self.declare()
        self.assertEqual(self.check()['outcome'], 'could-not-look')

    def test_observed_nonannotated_tag_still_fails(self):
        self.git('tag', '-d', 'policy/v1.0.0')
        self.git('tag', 'policy/v1.0.0')
        result = self.check()
        self.assertEqual(result['outcome'], 'failed', result)
        self.assertIn('not annotated', result['rows'][0]['reason'])

    def test_unmeasured_extra_declared_engine_prevents_a_complete_matrix(self):
        self.entry['tested_engines']['kyverno'].append('1.19.0');self.declare()
        self.assertEqual(self.check()['outcome'], 'could-not-look')
