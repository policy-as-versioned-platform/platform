#!/usr/bin/env python3
"""The public proposer explains a counterfactual move; fixtures have no auth credit."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROPOSER = Path(__file__).with_name('tier_pr.py')


class NamespaceMove(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-tier-move-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.adopter = self.root / 'adopter'
        self.adopter.mkdir()
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'synthetic proposer fixture')
        self.git('config', 'user.email', 'synthetic@example.invalid')
        self.git('config', 'commit.gpgsign', 'false')
        self.manifest = self.adopter / 'workloads.yaml'
        self.original = '''apiVersion: v1
kind: Namespace
metadata:
  name: synthetic-party
  labels:
    policy-as-versioned.dev/governed: "true"
    posture.acme.io/tier: "baseline"
---
apiVersion: v1
kind: Pod
metadata:
  name: synthetic-workload
  namespace: synthetic-party
  labels:
    policy-as-versioned.dev/policy-version: "7.0.0"
'''
        self.manifest.write_text(self.original)
        (self.adopter / 'party.yaml').write_text('party: synthetic-party\noverlay:\n  floor: baseline\n')
        self.evidence = self.adopter / 'composed/evidence.json'
        self.evidence.parent.mkdir()
        self.price = {
            'source': 'synthetic-feed', 'kind': 'feed', 'name': 'synthetic-risk',
            'perspective': 'synthetic-party', 'currency': 'GBP', 'amount': 90000,
            'old_price': 1000, 'new_price': 90000,
            'old_tier': 'isolated', 'proposed_tier': 'quarantine', 'changed': True,
            'proposed_as': 'label', 'lef_basis': 'synthetic annual comparison fixture',
            'rests_on_grade': None,
        }
        self.evidence.write_text(json.dumps({'prices': [self.price], 'parents': [], 'vendored': []}))
        self.git('add', 'workloads.yaml', 'party.yaml', 'composed/evidence.json')
        self.git('commit', '-qm', 'synthetic declaration and prices; not a measurement')
        self.commit = self.git('rev-parse', 'HEAD')
        self.ledger = self.root / 'rejections.json'
        self.ledger.write_text('{}')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('gh', 'gitsign', 'curl', 'docker', 'kubectl', 'kyverno'):
            path = self.bin / name
            path.write_text('#!/bin/sh\necho "unexpected fixture external command" >&2\nexit 97\n')
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        PYTHONDONTWRITEBYTECODE='1', GIT_TERMINAL_PROMPT='0')
        for name in ('GH_TOKEN', 'GITHUB_TOKEN', 'GIT_ASKPASS', 'SSH_ASKPASS'):
            self.env.pop(name, None)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.adopter), *args], text=True).strip()

    def propose(self, dry_run=True):
        command = [sys.executable, '-B', str(PROPOSER), 'run', '--adopter-dir', str(self.adopter),
                   '--evidence', str(self.evidence), '--org', 'synthetic-party',
                   '--rejections', str(self.ledger), '--repo', 'synthetic/never-publish',
                   '--as-of', '2026-10-19']
        if dry_run:
            command.append('--dry-run')
        result = subprocess.run(command, env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_dry_run_prices_the_declared_move_at_one_current_snapshot(self):
        plan, = self.propose()
        move = plan['namespace_tier_move']
        self.assertEqual(move['before']['declared'], 'baseline')
        self.assertEqual(move['after'], 'quarantine')
        self.assertEqual(move['declaration']['commit'], self.commit)
        self.assertEqual(move['snapshot']['sha256'], hashlib.sha256(self.evidence.read_bytes()).hexdigest())
        self.assertEqual(move['snapshot']['adopter_commit_at_load'], self.commit)
        line, = move['lines']
        self.assertAlmostEqual(line['before_residual'], 63000)
        self.assertAlmostEqual(line['after_residual'], 7200)
        self.assertAlmostEqual(line['residual_delta'], -55800)
        self.assertEqual(line['rests_on_grade'], None)
        self.assertIn('counterfactual', plan['body'].lower())
        self.assertIn('63,000.00 GBP', plan['body'])
        self.assertIn('7,200.00 GBP', plan['body'])
        self.assertEqual(plan['diff'], self.original.replace('tier: "baseline"', 'tier: "quarantine"'))
        self.assertEqual(self.manifest.read_text(), self.original)
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.commit)

    def test_real_run_rebinds_the_body_to_fetched_base_without_repricing(self):
        original_evidence = self.evidence.read_bytes()
        origin = self.root / 'origin.git'
        subprocess.run(['git', 'init', '--bare', '-q', str(origin)], check=True)
        self.git('remote', 'add', 'origin', str(origin))
        self.git('push', '-q', 'origin', 'main')
        writer = self.root / 'writer'
        subprocess.run(['git', 'clone', '-q', '--no-local', '--branch', 'main', str(origin), str(writer)],
                       check=True)
        def write_git(*args):
            return subprocess.check_output(['git', '-C', str(writer), *args], text=True).strip()
        write_git('config', 'user.name', 'synthetic concurrent writer')
        write_git('config', 'user.email', 'synthetic@example.invalid')
        write_git('config', 'commit.gpgsign', 'false')
        (writer / 'workloads.yaml').write_text(self.original.replace('tier: "baseline"', 'tier: "restricted"'))
        (writer / 'composed/evidence.json').write_text(json.dumps({
            'prices': [dict(self.price, amount=1, lef_basis='different B fixture basis')],
            'parents': [{'party': 'synthetic-B-only'}], 'vendored': []}))
        write_git('commit', '-qam', 'synthetic newer declaration, not a measurement')
        base = write_git('rev-parse', 'HEAD')
        write_git('push', '-q', 'origin', 'main')
        transport_log = self.root / 'synthetic-gh.json'
        gh = self.bin / 'gh'
        gh.write_text(f'''#!{sys.executable}
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
if args[:2] == ['pr', 'list']:
    print('')
elif args[:2] == ['pr', 'create']:
    Path(os.environ['SYNTHETIC_GH_LOG']).write_text(json.dumps(args))
    print('https://synthetic.invalid/pull/1')
else:
    sys.exit('unexpected synthetic transport call')
''')
        self.env['SYNTHETIC_GH_LOG'] = str(transport_log)
        plan, = self.propose(dry_run=False)
        move = plan['namespace_tier_move']
        self.assertEqual(move['before']['declared'], 'restricted')
        self.assertEqual(move['declaration']['commit'], base)
        self.assertEqual(move['snapshot']['adopter_commit_at_load'], self.commit)
        self.assertEqual(move['snapshot']['sha256'], hashlib.sha256(original_evidence).hexdigest())
        self.assertEqual(move['snapshot']['parents'], [])
        self.assertEqual(move['lines'][0]['provenance']['lef_basis'], 'synthetic annual comparison fixture')
        line, = move['lines']
        self.assertAlmostEqual(line['before_residual'], 27000)
        self.assertAlmostEqual(line['after_residual'], 7200)
        self.assertAlmostEqual(line['residual_delta'], -19800)
        sent = json.loads(transport_log.read_text())
        body = sent[sent.index('--body') + 1]
        self.assertEqual(body, plan['body'])
        self.assertIn('27,000.00 GBP', body)
        self.assertIn('The Namespace declared `restricted`', body)
        branch = plan['branch']
        proposed = self.git('rev-parse', f'origin/{branch}')
        self.assertEqual(self.git('rev-parse', f'{proposed}^'), base)
        self.assertEqual(self.git('show', f'{proposed}:workloads.yaml'),
                         self.original.replace('tier: "baseline"', 'tier: "quarantine"').strip())
        self.assertEqual(self.git('diff', '--name-only', base, proposed), 'workloads.yaml')

    def test_pricing_dates_and_grade_are_readable_without_relabeling_caller_date(self):
        self.price.update(as_of='2026-10-18', fx_as_of='2026-10-17', rests_on_grade=3)
        self.evidence.write_text(json.dumps({'prices': [self.price]}))
        plan, = self.propose()
        self.assertIn('input as-of `2026-10-18`', plan['body'])
        self.assertIn('FX as-of `2026-10-17`', plan['body'])
        self.assertIn('caller as-of `2026-10-19`', plan['body'])
        self.assertIn('evidence grade 3', plan['body'])

    def test_unreadable_currency_does_not_become_a_numeric_residual(self):
        self.price['currency'] = 'not-a-currency'
        self.evidence.write_text(json.dumps({'prices': [self.price]}))
        plan, = self.propose()
        line, = plan['namespace_tier_move']['lines']
        self.assertIsNone(line['before_residual'])
        self.assertIsNone(line['after_residual'])
        self.assertIsNone(line['residual_delta'])
        self.assertIn('currency', line['could_not_look'])

    def test_absent_money_and_boolean_grade_are_not_zero_or_evidence(self):
        self.price.update(amount=None, rests_on_grade=True)
        self.evidence.write_text(json.dumps({'prices': [self.price]}))
        plan, = self.propose()
        line, = plan['namespace_tier_move']['lines']
        self.assertIsNone(line['before_residual'])
        self.assertIsNone(line['after_residual'])
        self.assertIsNone(line['residual_delta'])
        self.assertIsNone(line['rests_on_grade'])
        self.assertTrue(line['provenance']['rests_on_grade'])
        self.assertIn('amount', line['could_not_look'])
        self.assertIn('evidence grade unobserved', plan['body'])

    def test_nonfinite_boolean_or_unrepresentable_amounts_are_unknown_but_explicit_zero_is_zero(self):
        for amount in (True, float('nan'), float('inf'), -1, 10 ** 400, 0):
            with self.subTest(amount=repr(amount)):
                self.price['amount'] = amount
                self.evidence.write_text(json.dumps({'prices': [self.price]}))
                plan, = self.propose()
                line, = plan['namespace_tier_move']['lines']
                if type(amount) is int and amount == 0:
                    self.assertEqual(line['before_residual'], 0)
                    self.assertEqual(line['after_residual'], 0)
                    self.assertIsNone(line['could_not_look'])
                else:
                    self.assertIsNone(line['before_residual'])
                    self.assertIsNone(line['after_residual'])
                    self.assertIsNone(line['residual_delta'])
                    self.assertIn('amount', line['could_not_look'])

    def test_duplicate_lines_keep_their_units_and_subjects_without_totals_or_repeated_costs(self):
        prices = [self.price,
                  dict(self.price, amount=100, currency='USD', perspective='another-perspective',
                       proposed_tier='restricted', changed=False),
                  dict(self.price, kind='agent-cage', subject='twin-agent', changed=False),
                  dict(self.price, kind='premium', proposed_tier=None, changed=False),
                  dict(self.price, kind='supersede', proposed_tier=None, changed=False)]
        self.evidence.write_text(json.dumps({'prices': prices}))
        plan, = self.propose()
        move = plan['namespace_tier_move']
        first, second = move['lines']
        self.assertEqual([first['index'], second['index']], [0, 1])
        self.assertEqual(second['currency'], 'USD')
        self.assertEqual(second['perspective'], 'another-perspective')
        self.assertAlmostEqual(second['before_residual'], 70)
        self.assertAlmostEqual(second['after_residual'], 8)
        self.assertEqual([row['kind'] for row in move['excluded']], ['agent-cage', 'premium', 'supersede'])
        self.assertNotIn('total', move)
        self.assertNotIn('cost_of_controls', first)
        self.assertNotIn('cost_of_controls', second)

    def test_existing_held_tighten_only_path_has_no_move_or_transport(self):
        self.manifest.write_text(self.original.replace('tier: "baseline"', 'tier: "isolated"'))
        self.git('commit', '-qam', 'synthetic isolated declaration')
        plan, = self.propose()
        self.assertEqual(plan['held'], 'tighten-only')
        self.assertNotIn('namespace_tier_move', plan)

    def test_unknown_line_makes_report_completeness_explicit(self):
        self.price['amount'] = None
        self.evidence.write_text(json.dumps({'prices': [self.price]}))
        plan, = self.propose()
        move = plan['namespace_tier_move']
        self.assertEqual(move['state'], 'unavailable')
        self.assertIn('amount', move['could_not_look'])

    def test_namespace_identity_comes_from_the_governed_declaration_not_the_price_party(self):
        self.manifest.write_text(self.original.replace('name: synthetic-party', 'name: actual-declared-name', 1))
        self.git('commit', '-qam', 'synthetic Namespace name distinct from pricing perspective')
        plan, = self.propose()
        move = plan['namespace_tier_move']
        self.assertEqual(move['declaration']['namespace'], 'actual-declared-name')
        self.assertEqual(move['lines'][0]['perspective'], 'synthetic-party')

    def test_ordered_prices_identity_is_independent_of_json_layout_but_not_row_order(self):
        prices = [self.price, dict(self.price, amount=100, changed=False, currency='USD')]
        self.evidence.write_text(json.dumps({'prices': prices}))
        first, = self.propose()
        self.evidence.write_text(json.dumps({'prices': prices}, indent=4))
        formatted, = self.propose()
        self.evidence.write_text(json.dumps({'prices': list(reversed(prices))}))
        reversed_plan, = self.propose()
        initial = first['namespace_tier_move']['snapshot']
        changed_layout = formatted['namespace_tier_move']['snapshot']
        changed_order = reversed_plan['namespace_tier_move']['snapshot']
        self.assertEqual(initial['prices_sha256'], changed_layout['prices_sha256'])
        self.assertNotEqual(initial['sha256'], changed_layout['sha256'])
        self.assertNotEqual(initial['prices_sha256'], changed_order['prices_sha256'])


if __name__ == '__main__':
    unittest.main()
