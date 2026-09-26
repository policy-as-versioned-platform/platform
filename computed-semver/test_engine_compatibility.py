"""Public compatibility seam: real Git histories, an explicitly synthetic CLI.

The synthetic `kyverno` below is never evidence about Kyverno. It reports the version it is told,
passes or fails a `test` run as its mode file says, fails any policy whose `spec.fails_on` names
its own version, and on `apply -o` writes the documents a policy's `spec.generate` names for a
trigger. Under `test -o json` it prints one row per asserted resource, as Kyverno does, and reads
a resource a policy's `spec.excludes` names as Pass / Excluded whatever the row asserts, as
Kyverno does for a Pod in a Namespace it does not know. It refuses to grade a policy whose
`spec.marker` is not the tree the test expects, which is how these tests know which tree the
grader read. The real matrix run supplies the evidence.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

HERE = Path(__file__).resolve().parent

FAKE = r'''#!{python}
import json, pathlib, sys, yaml
me = pathlib.Path(__file__)
version = me.with_suffix('.version').read_text().strip()
if sys.argv[1] == 'version':
    print('Version: ' + version); sys.exit(0)
want = me.with_suffix('.marker').read_text().strip()
def policy_at(path):
    doc = yaml.safe_load(pathlib.Path(path).read_text())
    assert doc['spec']['marker'] == want, 'graded ' + doc['spec']['marker'] + ', expected ' + want
    return doc
if sys.argv[1] == 'test':
    t = yaml.safe_load((pathlib.Path(sys.argv[2]) / 'kyverno-test.yaml').read_text())
    doc = policy_at(t['policies'][0])
    mode = me.with_suffix('.mode').read_text().strip()
    excludes = doc['spec'].get('excludes', [])
    rows = [{'ID': 0, 'POLICY': r['policy'], 'RULE': '', 'RESOURCE': 'v1/Pod/default/' + n, 'RESULT': 'Pass',
             'REASON': 'Excluded' if n in excludes else 'Ok'} for r in t['results'] for n in r['resources']]
    as_json = sys.argv[3:5] == ['-o', 'json'] and mode != 'norows'
    if mode == 'fail' or version in doc['spec'].get('fails_on', []):
        rows[0].update(RESULT='Fail', REASON='Want pass, got fail')
        if as_json: print(json.dumps(rows, indent=2))
        print('Test Summary: %d tests passed and 1 tests failed' % (len(rows) - 1)); sys.exit(1)
    if mode == 'zero':
        if as_json: print('[]')
        print('Test Summary: 0 tests passed and 0 tests failed'); sys.exit(0)
    if as_json: print(json.dumps(rows, indent=2))
    print('Test Summary: %d tests passed and 0 tests failed' % len(rows)); sys.exit(0)
if sys.argv[1] == 'apply':
    doc = policy_at(sys.argv[2])
    trigger = yaml.safe_load(pathlib.Path(sys.argv[sys.argv.index('--resource') + 1]).read_text())
    out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1]); out.mkdir(parents=True, exist_ok=True)
    made = (doc['spec'].get('generate') or {}).get(trigger['metadata']['name'], [])
    if made:
        (out / (doc['metadata']['name'] + '-generated.yaml')).write_text(yaml.safe_dump_all(made))
    print('pass: %d, fail: 0, warn: 0, error: 0, skip: 0' % bool(made)); sys.exit(0)
sys.exit('unexpected call: ' + ' '.join(sys.argv))
'''

COMPOSER = '''
def machinery_members(root):
    import yaml
    doc = yaml.safe_load((root / "distribution" / "guard-body.yaml").read_text())
    return [{"member_name": doc["metadata"]["name"], "doc": doc, "out_path": "composed/guard.yaml"},
            {"member_name": "cage-isolated", "out_path": "composed/pc.yaml",
             "doc": {"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass",
                     "metadata": {"name": "cage-isolated"}, "value": -10000}}]
'''


def _module():
    spec = importlib.util.spec_from_file_location('engine_compatibility', HERE / 'engine_compatibility.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EngineCompatibility(unittest.TestCase):
    def test_missing_binary_is_not_compatibility(self):
        result = _module().check(HERE.parent, '/nonexistent/kyverno')
        self.assertEqual(result['outcome'], 'could-not-look')
        self.assertIn('binary', result['reason'])


class Matrix(unittest.TestCase):
    """One synthetic platform: a cut line 1.0.0 with three bodies and a non-policy file, and the
    machinery. Each test changes one thing and reads the outcome."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.module = _module()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@invalid')
        self.write_line('1.0.0', 'published')
        self.write('graded/tests/cage-tier/kyverno-test.yaml', {'policies': ['unused'], 'results': [
            {'policy': 'cage-tier', 'rule': 'cage-tier', 'resources': ['p'], 'result': 'pass'}]})
        self.write('graded/tests/cage-tier/resources.yaml', {'kind': 'Pod', 'metadata': {'name': 'p', 'labels': {}}})
        self.write('graded/tests/cage-netpol/kyverno-test.yaml', {'policies': ['unused'], 'results': [
            {'policy': 'cage-netpol', 'rule': 'cage-netpol', 'resources': ['p'], 'result': 'pass'}]})
        self.write('graded/tests/cage-netpol/resources.yaml', {'kind': 'Pod', 'metadata': {'name': 'p'}})
        self.write_line_fixture('1.0.0')
        self.write('distribution/guard-body.yaml', self.policy('guard', 'ValidatingPolicy', 'published'))
        (self.repo / 'compose').mkdir()
        (self.repo / 'compose/composition.py').write_text(COMPOSER)
        self.write('computed-semver/engine-fixtures/machinery/guard/kyverno-test.yaml', {
            'policies': ['rendered'], 'results': [{'policy': 'guard', 'resources': ['p'], 'result': 'pass'}]})
        self.write('distribution/machinery.yaml', {'tested_engines': {'scope': self.module.SCOPE, 'kyverno': ['1.18.2']}})
        self.git('add', '.')
        self.git('commit', '-qm', 'published line')
        self.commit = self.git('rev-parse', 'HEAD')
        self.git('tag', '-a', 'policy/v1.0.0', '-m', 'unsigned fixture, never production evidence')
        self.entries = [{'version': '1.0.0', 'tag': 'policy/v1.0.0', 'commit': self.commit,
                         'tested_engines': {'scope': self.module.SCOPE, 'kyverno': ['1.18.2']}}]
        self.declare()
        self.binary = self.fake('kyverno-fixture', '1.18.2')

    # -- building the synthetic estate ------------------------------------------------------
    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), '-c', 'core.hooksPath=/dev/null',
            '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', *args], text=True).strip()

    def write(self, rel, doc):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(doc))

    @staticmethod
    def policy(name, kind, marker, **spec):
        return {'apiVersion': 'policies.kyverno.io/v1alpha1', 'kind': kind,
                'metadata': {'name': name}, 'spec': {'marker': marker, **spec}}

    def write_line(self, version, marker, **extra):
        suffix = version.replace('.', '-')
        base = f'distribution/policies/v{version}'
        self.write(f'{base}/cage-tier.yaml', self.policy(f'cage-tier-{suffix}', 'MutatingPolicy', marker, **extra))
        self.write(f'{base}/cage-netpol.yaml', self.policy(f'cage-netpol-{suffix}', 'GeneratingPolicy', marker, **extra))
        self.write(f'{base}/require-nonroot.yaml', self.policy(f'require-nonroot-{suffix}', 'ValidatingPolicy', marker, **extra))
        self.write(f'{base}/priorityclasses.yaml', {'apiVersion': 'scheduling.k8s.io/v1', 'kind': 'PriorityClass',
                                                    'metadata': {'name': f'cage-isolated-{suffix}'}, 'value': -10000})

    def write_line_fixture(self, version):
        suffix = version.replace('.', '-')
        self.write(f'computed-semver/engine-fixtures/v{version}/require-nonroot/kyverno-test.yaml', {
            'policies': ['rewritten'], 'results': [
                {'policy': f'require-nonroot-{suffix}', 'resources': ['p'], 'result': 'pass'}]})

    def declare(self, commit=True):
        self.write('distribution/versions.yaml', {'spec': {'inputs': [{'versions': self.entries}]}})
        if commit:
            self.git('add', '.')
            self.git('commit', '-qm', 'declare')

    def fake(self, name, version, mode='pass', marker='published'):
        path = self.root / name
        path.write_text(FAKE.replace('{python}', sys.executable))
        path.chmod(0o755)
        path.with_suffix('.version').write_text(version)
        path.with_suffix('.mode').write_text(mode)
        path.with_suffix('.marker').write_text(marker)
        return path

    def check(self, *binaries):
        return self.module.check(self.repo, [str(b) for b in (binaries or (self.binary,))])

    @staticmethod
    def cells(result, subject):
        return {c['engine']: c for r in result['rows'] if r['subject'] == subject for c in r.get('cells', [])}

    # -- the published line -----------------------------------------------------------------
    def test_every_body_of_the_published_tree_is_graded_and_the_machinery_too(self):
        import hashlib
        # the working tree and HEAD both change the policy bytes; the tag does not
        (self.repo / 'distribution/policies/v1.0.0/cage-tier.yaml').write_text('spec: {marker: changed}\n')
        result = self.check()
        self.assertEqual(result['outcome'], 'passed', json.dumps(result, indent=1))
        line = result['rows'][0]
        self.assertEqual(line['state'], 'published')
        self.assertEqual(line['tag_commit'], self.commit)
        self.assertEqual(line['bodies'], ['cage-netpol', 'cage-tier', 'require-nonroot'])
        self.assertEqual(line['not_bodies'], ['priorityclasses.yaml'])
        graded = {b['family']: b['fixture'] for b in line['cells'][0]['bodies']}
        self.assertEqual(graded, {'cage-netpol': 'graded/tests (adapted)', 'cage-tier': 'graded/tests (adapted)',
                                  'require-nonroot': 'engine-fixtures'})
        self.assertEqual(line['prerelease_api_versions'], ['policies.kyverno.io/v1alpha1'])
        self.assertEqual(result['matrix'], {'policy 1.0.0': {'1.18.2': 'passed'}, 'machinery': {'1.18.2': 'passed'}})
        machinery = result['rows'][1]
        self.assertEqual(machinery['bodies'], ['guard'])
        self.assertEqual(machinery['not_bodies'], ['cage-isolated.yaml'])
        self.assertEqual(result['engines'][0]['sha256'], hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def test_a_body_with_no_fixture_fails_its_cell(self):
        self.git('rm', '-q', '-r', 'computed-semver/engine-fixtures/v1.0.0')
        self.git('commit', '-qm', 'drop the fixture')
        result = self.check()
        self.assertEqual(result['outcome'], 'failed')
        body = {b['family']: b for b in self.cells(result, 'policy 1.0.0')['1.18.2']['bodies']}
        self.assertIn('has no fixture', body['require-nonroot']['reason'])

    def test_a_fixture_that_names_another_policy_fails(self):
        self.write('computed-semver/engine-fixtures/v1.0.0/require-nonroot/kyverno-test.yaml', {
            'policies': ['x'], 'results': [{'policy': 'something-else', 'resources': ['p'], 'result': 'pass'}]})
        self.git('commit', '-qam', 'a fixture for another policy')
        result = self.check()
        self.assertEqual(result['outcome'], 'failed')
        body = {b['family']: b for b in self.cells(result, 'policy 1.0.0')['1.18.2']['bodies']}
        self.assertIn('not a policy in the served file', body['require-nonroot']['reason'])

    def test_undeclared_retired_scope_and_missing_declaration_are_unknown(self):
        self.entries[0]['tested_engines']['scope'] = 'published-cage-fixtures-v1'
        self.declare()
        result = self.check()
        self.assertEqual(result['outcome'], 'could-not-look')
        self.assertIn('narrower meaning', result['rows'][0]['reason'])
        self.entries[0].pop('tested_engines')
        self.declare()
        result = self.check()
        self.assertEqual(result['outcome'], 'could-not-look')
        self.assertIn('supports no engine', result['rows'][0]['reason'])

    def test_failed_zero_or_unread_assertions_never_report_compatibility(self):
        # 'norows': the summary says passed, but no row says why, so an excluded row is unreadable
        for mode in ('fail', 'zero', 'norows'):
            with self.subTest(mode=mode):
                self.binary.with_suffix('.mode').write_text(mode)
                self.assertEqual(self.check()['outcome'], 'failed')

    def test_pin_and_tag_tree_mismatch_refuses(self):
        (self.repo / 'distribution/policies/v1.0.0/cage-tier.yaml').write_text('spec: {marker: changed}\n')
        self.git('commit', '-qam', 'different tree')
        self.entries[0]['commit'] = self.git('rev-parse', 'HEAD')
        self.declare()
        result = self.check()
        self.assertEqual(result['outcome'], 'failed')
        self.assertIn('differs', result['rows'][0]['reason'])

    def test_unavailable_historical_inputs_are_not_incompatibility(self):
        self.git('tag', '-d', 'policy/v1.0.0')
        result = self.check()
        self.assertEqual(result['outcome'], 'could-not-look', result)
        self.assertIn('unavailable', result['rows'][0]['reason'])
        self.git('tag', '-a', 'policy/v1.0.0', '-m', 'restored synthetic tag', self.commit)
        self.entries[0]['commit'] = 'f' * 40
        self.declare()
        self.assertEqual(self.check()['outcome'], 'could-not-look')

    def test_observed_nonannotated_tag_still_fails(self):
        self.git('tag', '-d', 'policy/v1.0.0')
        self.git('tag', 'policy/v1.0.0', self.commit)
        result = self.check()
        self.assertEqual(result['outcome'], 'failed', result)
        self.assertIn('not annotated', result['rows'][0]['reason'])

    def test_the_verdict_line_names_the_graded_commit_and_each_cut_line_s_tag(self):
        out = subprocess.run([sys.executable, str(HERE / 'engine_compatibility.py'), '--repo', str(self.repo),
                              '--engine', str(self.binary)], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout[-600:])
        last = out.stdout.splitlines()[-1]
        head = self.git('rev-parse', 'HEAD')
        self.assertTrue(last.startswith('PASS: engine cells -- passed; 2 cell(s): 2 passed'), last)
        self.assertIn(f'graded platform commit {head}', last)
        self.assertIn(f'policy 1.0.0 from refs/tags/policy/v1.0.0 at {self.commit}', last)
        self.assertIn('machinery rendered by compose/composition.py at the graded commit', last)

    # -- a row the engine did not apply the policy to ---------------------------------------
    def test_a_pass_or_fail_row_the_engine_excluded_fails_its_cell(self):
        # Kyverno counts a resource it did not apply the policy to as a pass, whatever the row says
        self.write('distribution/guard-body.yaml',
                   self.policy('guard', 'ValidatingPolicy', 'published', excludes=['p']))
        self.git('commit', '-qam', 'the guard never applies to p')
        result = self.check()
        self.assertEqual(result['outcome'], 'failed')
        body = self.cells(result, 'machinery')['1.18.2']['bodies'][0]
        part = body['parts'][0]
        self.assertEqual((part['passed_assertions'], part['failed_assertions']), (1, 0))
        self.assertEqual(part['row_reasons'], {'Excluded': 1})
        self.assertIn('reads Excluded where the fixture asserts pass', part['refusals'][0])

    def test_a_skip_row_may_read_excluded_beside_a_row_that_measures(self):
        self.write('distribution/guard-body.yaml',
                   self.policy('guard', 'ValidatingPolicy', 'published', excludes=['outside']))
        self.write('computed-semver/engine-fixtures/machinery/guard/kyverno-test.yaml', {
            'policies': ['rendered'], 'results': [
                {'policy': 'guard', 'resources': ['p'], 'result': 'pass'},
                {'policy': 'guard', 'resources': ['outside'], 'result': 'skip'}]})
        self.git('commit', '-qam', 'a scope row')
        result = self.check()
        self.assertEqual(result['outcome'], 'passed', json.dumps(result, indent=1))
        part = self.cells(result, 'machinery')['1.18.2']['bodies'][0]['parts'][0]
        self.assertEqual(part['row_reasons'], {'Ok': 1, 'Excluded': 1})

    # -- the tag-bound cage grade -------------------------------------------------------------
    def test_a_later_fixture_never_replaces_the_tag_bound_cage_grade(self):
        # the tag's own cage-tier fixture is weakened to skip rows only, which grades nothing
        self.write('graded/tests/cage-tier/kyverno-test.yaml', {'policies': ['unused'], 'results': [
            {'policy': 'cage-tier', 'rule': 'cage-tier', 'resources': ['p'], 'result': 'skip'}]})
        # and a fixture that passes is committed for the same body beside the line's other fixtures
        self.write('computed-semver/engine-fixtures/v1.0.0/cage-tier/kyverno-test.yaml', {
            'policies': ['rewritten'], 'results': [{'policy': 'cage-tier-1-0-0', 'resources': ['p'], 'result': 'pass'}]})
        self.git('add', '.')
        self.git('commit', '-qm', 'a weak tag fixture and a passing later one')
        self.git('tag', '-f', '-a', 'policy/v1.0.0', '-m', 'unsigned fixture, never production evidence')
        self.entries[0]['commit'] = self.git('rev-parse', 'HEAD')
        self.declare()
        result = self.check()
        self.assertEqual(result['outcome'], 'failed', json.dumps(result, indent=1))
        body = {b['family']: b for b in self.cells(result, 'policy 1.0.0')['1.18.2']['bodies']}
        self.assertIn('no positive assertions', body['cage-tier']['reason'])
        # with the tag's fixture whole again, both run and both must pass
        self.write('graded/tests/cage-tier/kyverno-test.yaml', {'policies': ['unused'], 'results': [
            {'policy': 'cage-tier', 'rule': 'cage-tier', 'resources': ['p'], 'result': 'pass'}]})
        self.git('commit', '-qam', 'the tag fixture restored')
        self.git('tag', '-f', '-a', 'policy/v1.0.0', '-m', 'unsigned fixture, never production evidence')
        self.entries[0]['commit'] = self.git('rev-parse', 'HEAD')
        self.declare()
        result = self.check()
        self.assertEqual(result['outcome'], 'passed', json.dumps(result, indent=1))
        body = {b['family']: b for b in self.cells(result, 'policy 1.0.0')['1.18.2']['bodies']}
        self.assertEqual([p['fixture'] for p in body['cage-tier']['parts']],
                         ['graded/tests (adapted)', 'engine-fixtures'])

    # -- many engines ------------------------------------------------------------------------
    def test_a_second_listed_engine_with_no_binary_reads_could_not_look(self):
        self.entries[0]['tested_engines']['kyverno'].append('1.19.1')
        self.declare()
        result = self.check()
        self.assertEqual(result['outcome'], 'could-not-look')
        cells = self.cells(result, 'policy 1.0.0')
        self.assertEqual(cells['1.18.2']['outcome'], 'passed')
        self.assertEqual(cells['1.19.1']['outcome'], 'could-not-look')
        self.assertIn('no binary for kyverno 1.19.1', cells['1.19.1']['reason'])
        self.assertEqual(result['matrix']['policy 1.0.0'], {'1.18.2': 'passed', '1.19.1': 'could-not-look'})
        # the verdict line alone names the cell that could not look, and why
        out = subprocess.run([sys.executable, str(HERE / 'engine_compatibility.py'), '--repo', str(self.repo),
                              '--engine', str(self.binary)], capture_output=True, text=True)
        self.assertEqual(out.returncode, 3, out.stdout[-400:])
        self.assertIn('not passed: policy 1.0.0 on 1.19.1 could-not-look (no binary for kyverno 1.19.1 '
                      'was handed to this run)', out.stdout.splitlines()[-1])

    def test_one_run_grades_every_cell_with_one_binary_per_engine(self):
        self.entries[0]['tested_engines']['kyverno'].append('1.19.1')
        self.declare()
        second = self.fake('kyverno-second', '1.19.1')
        result = self.check(self.binary, second)
        self.assertEqual(result['outcome'], 'passed', json.dumps(result, indent=1))
        self.assertEqual(result['matrix']['policy 1.0.0'], {'1.18.2': 'passed', '1.19.1': 'passed'})
        self.assertEqual(result['matrix']['machinery'], {'1.18.2': 'passed'})
        self.assertEqual(result['extra_engines'], [])

    def test_an_extra_binary_is_reported_and_never_read_as_support(self):
        extra = self.fake('kyverno-extra', '1.20.0')
        result = self.check(self.binary, extra)
        self.assertEqual(result['outcome'], 'passed')
        self.assertEqual([e['version'] for e in result['extra_engines']], ['1.20.0'])
        self.assertNotIn('1.20.0', {e for m in result['matrix'].values() for e in m})
        self.assertIn('1.20.0', self.module.matrix_table(result).splitlines()[0])

    def test_two_binaries_for_one_version_with_different_digests_cannot_be_read(self):
        twin = self.fake('kyverno-twin', '1.18.2')
        twin.write_text(twin.read_text() + '\n# a different build\n')
        result = self.check(self.binary, twin)
        self.assertEqual(result['outcome'], 'could-not-look')
        self.assertIn('different digests', self.cells(result, 'policy 1.0.0')['1.18.2']['reason'])

    # -- a candidate, before its cut ---------------------------------------------------------
    def declare_candidate(self, **extra):
        self.write_line('2.0.0', 'published', **extra)
        self.write_line_fixture('2.0.0')
        self.entries.append({'version': '2.0.0', 'tag': 'policy/v2.0.0', 'bump': 'major',
                             'tested_engines': {'scope': self.module.SCOPE, 'kyverno': ['1.18.2', '1.19.1']}})
        self.declare()
        return self.git('rev-parse', 'HEAD')

    def test_an_uncut_candidate_is_graded_on_the_commit_that_declares_it(self):
        head = self.declare_candidate()
        # an uncommitted edit is not the declaring commit's tree, and is not what is graded
        (self.repo / 'distribution/policies/v2.0.0/cage-tier.yaml').write_text('spec: {marker: uncommitted}\n')
        result = self.check(self.binary, self.fake('kyverno-second', '1.19.1'))
        self.assertEqual(result['outcome'], 'passed', json.dumps(result, indent=1))
        candidate = result['rows'][1]
        self.assertEqual((candidate['state'], candidate['candidate_commit']), ('candidate', head))
        self.assertEqual(result['matrix']['policy 2.0.0'], {'1.18.2': 'passed', '1.19.1': 'passed'})

    def test_a_candidate_that_fails_a_cell_reads_fail(self):
        self.declare_candidate(fails_on=['1.19.1'])
        result = self.check(self.binary, self.fake('kyverno-second', '1.19.1'))
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(result['matrix']['policy 2.0.0'], {'1.18.2': 'passed', '1.19.1': 'failed'})
        self.assertEqual(result['matrix']['policy 1.0.0'], {'1.18.2': 'passed'})
        out = subprocess.run([sys.executable, str(HERE / 'engine_compatibility.py'), '--repo', str(self.repo),
                              '--engine', str(self.binary), '--engine', str(self.root / 'kyverno-second')],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 1)
        self.assertTrue(out.stdout.splitlines()[-1].startswith('FAIL: engine cells -- failed'), out.stdout[-400:])
        self.assertIn('not passed: policy 2.0.0 on 1.19.1 failed (cage-netpol, cage-tier, require-nonroot)',
                      out.stdout.splitlines()[-1])

    def test_an_engine_directory_with_no_binary_is_not_the_cli_on_path(self):
        empty = self.root / 'no-engines'
        empty.mkdir()
        out = subprocess.run([sys.executable, str(HERE / 'engine_compatibility.py'), '--repo', str(self.repo),
                              '--engine-dir', str(empty)], capture_output=True, text=True)
        self.assertEqual(out.returncode, 3, out.stdout[-400:])
        self.assertIn('no engine was handed in', out.stdout.splitlines()[-1])

    # -- the machinery -----------------------------------------------------------------------
    def test_the_machinery_without_a_declaration_supports_nothing_and_reads_could_not_look(self):
        self.git('rm', '-q', 'distribution/machinery.yaml')
        self.git('commit', '-qm', 'no machinery declaration')
        result = self.check()
        self.assertEqual(result['outcome'], 'could-not-look')
        self.assertIn('declares no tested_engines', result['rows'][-1]['reason'])

    def test_a_machinery_member_with_no_fixture_fails(self):
        self.git('rm', '-q', '-r', 'computed-semver/engine-fixtures/machinery')
        self.git('commit', '-qm', 'no machinery fixture')
        result = self.check()
        self.assertEqual(result['outcome'], 'failed')
        self.assertIn('has no fixture', self.cells(result, 'machinery')['1.18.2']['bodies'][0]['reason'])

    # -- a generator graded on what it generates ---------------------------------------------
    def test_a_generator_is_graded_on_the_documents_it_generates(self):
        netpol = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                  'metadata': {'name': 'deny', 'namespace': 'a'}, 'spec': {'podSelector': {}}}
        body = self.policy('guard', 'GeneratingPolicy', 'published', generate={'caged': [netpol]})
        self.write('distribution/guard-body.yaml', body)
        folder = 'computed-semver/engine-fixtures/machinery/guard'
        self.git('rm', '-q', f'{folder}/kyverno-test.yaml')
        (self.repo / folder).mkdir(parents=True, exist_ok=True)
        (self.repo / folder / 'resources.yaml').write_text(yaml.safe_dump_all([
            {'kind': 'Pod', 'metadata': {'name': 'caged'}}, {'kind': 'Pod', 'metadata': {'name': 'free'}}]))
        self.write(f'{folder}/expected.yaml', netpol)
        self.write(f'{folder}/generates.yaml', {'triggers': [
            {'resource': 'caged', 'generates': 'expected.yaml'}, {'resource': 'free', 'generates': []}]})
        self.git('add', '.')
        self.git('commit', '-qm', 'a generator')
        self.assertEqual(self.check()['outcome'], 'passed')
        # the body now generates for a trigger the fixture says must generate nothing
        body['spec']['generate']['free'] = [netpol]
        self.write('distribution/guard-body.yaml', body)
        self.git('commit', '-qam', 'generates too much')
        result = self.check()
        self.assertEqual(result['outcome'], 'failed')
        part = self.cells(result, 'machinery')['1.18.2']['bodies'][0]['parts'][0]
        self.assertEqual((part['trigger'], part['expected'], len(part['generated'])), ('free', [], 1))


if __name__ == '__main__':
    unittest.main()
