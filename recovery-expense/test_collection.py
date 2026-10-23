"""Synthetic public CLI/collection regressions; no actual expenses or completed cases."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('recovery_collection_test_subject', HERE / 'collection.py')
collect = importlib.util.module_from_spec(spec); spec.loader.exec_module(collect)


class CollectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.policy = {'schema': 'recovery-expense/accounting-policy-v1', 'unit': dict(collect.UNIT),
            'cost_centres': {p: [p + '-TEST-ONLY'] for p in collect.PARTIES},
            'labour_rates_gbp_per_hour': {p: '10' for p in collect.PARTIES},
            'operator_control_disclosure': 'SYNTHETIC TEST ONLY shared operator; no institutional independence proof'}
        self.profile = {'schema': 'publisher-reliability/price-profile-v1', 'id': 'direct-security-recovery-2027',
            'unit': dict(collect.UNIT), 'target_feed': {'publisher': 'feeds', 'name': 'recovery-expense'},
            'criterion': 'money-empirical-crps/v1',
            'horizon_rule': {'duration': 'P1Y', 'boundary': '[start,end)', 'calendar': 'UTC-Gregorian'},
            'resolver_rule': {'party': 'platform', 'source_schema': 'recovery-expense/resolution-source-v1',
                'amount_pointer': '/amount', 'finality_pointer': '/final', 'completeness_pointer': '/complete'},
            'definition': {'loss_categories': collect.ACCOUNTING['included'],
                'accounting_rule': collect.ACCOUNTING['allocation'] + ' Recognition: ' + collect.ACCOUNTING['recognition'] + ' Excluded: ' + '; '.join(collect.ACCOUNTING['excluded']) + ' Collection-policy-sha256=' + collect.digest(collect.canonical(self.policy)),
                'completeness_rule': collect.ACCOUNTING['completeness'], 'finality_rule': collect.ACCOUNTING['finality']}}
        self.worklog = self.reference('worklog', 'SYNTHETIC TEST ONLY two hours, no observed work')
        self.reconciliation = self.reference('annual-reconciliation', 'SYNTHETIC TEST ONLY independent closure stand-in')

    def tearDown(self):
        self.tmp.cleanup()

    def reference(self, kind, content):
        p = self.root / (kind + '.txt'); p.write_text(content)
        return {'path': p.name, 'sha256': collect.digest(p.read_bytes()), 'uri': 'https://test-only.invalid/' + p.name,
                'custodian': 'TEST-ONLY-independent-auditor', 'kind': kind}

    def row(self, **changes):
        r = {'schema': 'recovery-expense/entry-v1', 'sequence': 1, 'previous_sha256': None,
             'entry_id': 'TEST-ONLY-1', 'incident_id': 'TEST-ONLY-incident', 'incurred_at': '2027-06-01T00:00:00Z',
             'recorded_at': '2027-06-02T00:00:00Z', 'subject': 'driftwood', 'cost_centre': 'driftwood-TEST-ONLY',
             'category': 'incremental-response-labour', 'source_id': 'TEST-ONLY-worklog', 'source_amount': '20',
             'allocation_amount': '20', 'hours': '2', 'rate': '10', 'evidence': self.worklog, 'duplicate_of': None}
        r.update(changes); return r

    def raw(self, *rows):
        raw = b''; previous = None
        for i, original in enumerate(rows):
            r = copy.deepcopy(original); r['sequence'] = i + 1; r['previous_sha256'] = previous
            line = collect.canonical(r); raw += line + b'\n'; previous = collect.digest(line)
        return raw

    def closure(self, raw, **changes):
        c = {'schema': 'recovery-expense/closure-v1', 'case_id': 'driftwood/2027', 'subject': 'driftwood', 'perspective': 'driftwood',
             'horizon': {'starts_at': '2027-01-01T00:00:00Z', 'ends_at': '2028-01-01T00:00:00Z', 'boundary': '[start,end)'},
             'unit': dict(collect.UNIT), 'cost_centres': self.policy['cost_centres']['driftwood'],
             'resolved_at': '2028-01-02T00:00:00Z', 'published_at': '2028-01-03T00:00:00Z',
             'ledger_sha256': collect.digest(raw), 'final': True, 'complete': True, 'unresolved': [], 'disputed': [],
             'incident_ids': ['TEST-ONLY-incident'], 'source_ids': ['TEST-ONLY-worklog'], 'reconciliation': self.reconciliation, 'no_events': None, 'no_expense': None}
        c.update(changes); return c

    def resolve(self, raw, closure=None):
        return collect.resolution_source(raw, self.policy, self.root, closure or self.closure(raw), self.profile)

    def test_public_append_and_annual_source_cli(self):
        ledger = self.root / 'ledger.jsonl'; ledger.write_bytes(b'')
        files = {}
        for name, value in [('policy', self.policy), ('row', self.row()), ('profile', self.profile)]:
            p = self.root / (name + '.json'); p.write_text(json.dumps(value)); files[name] = p
        args = [sys.executable, '-B', str(HERE / 'collection.py'), 'append', '--ledger', str(ledger), '--policy', str(files['policy']),
                '--record', str(files['row']), '--evidence-root', str(self.root)]
        call = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(call.returncode, 0, call.stderr); self.assertIsNone(json.loads(call.stdout)['annual_outcome'])
        raw = ledger.read_bytes(); closure = self.root / 'closure.json'; closure.write_text(json.dumps(self.closure(raw)))
        call = subprocess.run([sys.executable, '-B', str(HERE / 'collection.py'), 'resolve-source', '--ledger', str(ledger),
            '--policy', str(files['policy']), '--record', str(closure), '--profile', str(files['profile']), '--evidence-root', str(self.root)], capture_output=True, text=True)
        self.assertEqual(call.returncode, 0, call.stderr)
        result = json.loads(call.stdout); self.assertEqual(result['amount'], '20'); self.assertTrue(result['final']); self.assertTrue(result['complete'])
        self.assertEqual(ledger.read_bytes(), raw)

    def test_append_only_hash_chain_and_duplicate_cost_linkage(self):
        a = self.row(); b = self.row(entry_id='TEST-ONLY-duplicate', duplicate_of=a['entry_id'])
        raw = self.raw(a, b)
        self.assertEqual(self.resolve(raw)['amount'], '20')
        tampered = raw.replace(b'"source_amount":"20"', b'"source_amount":"21"', 1)
        with self.assertRaises(collect.Refused): self.resolve(tampered)

    def test_double_counted_source_alias_and_shared_allocations_refuse(self):
        a = self.row(); b = self.row(entry_id='TEST-ONLY-other', source_id='different-alias')
        with self.assertRaisesRegex(collect.Refused, 'aliased'): self.resolve(self.raw(a, b))
        b = self.row(entry_id='TEST-ONLY-other', subject='tuppence', cost_centre='tuppence-TEST-ONLY')
        with self.assertRaisesRegex(collect.Refused, 'more than once'): self.resolve(self.raw(a, b))

    def test_shared_source_allocated_once_across_cases(self):
        a = self.row(allocation_amount='12'); b = self.row(entry_id='TEST-ONLY-other', subject='tuppence', cost_centre='tuppence-TEST-ONLY', allocation_amount='8')
        self.assertEqual(self.resolve(self.raw(a, b))['amount'], '12')
        with self.assertRaisesRegex(collect.Refused, 'fully reconciled'): self.resolve(self.raw(a))

    def test_policy_boundary_evidence_and_independence_tampering_refuse(self):
        raw = self.raw(self.row()); bad = copy.deepcopy(self.profile); bad['definition']['accounting_rule'] = 'different accounting'
        with self.assertRaisesRegex(collect.Refused, 'profile policy'):
            collect.resolution_source(raw, self.policy, self.root, self.closure(raw), bad)
        (self.root / self.worklog['path']).write_text('changed')
        with self.assertRaisesRegex(collect.Refused, 'content hash'): self.resolve(raw)

    def test_policy_digest_alone_cannot_relabel_the_outcome_or_target(self):
        raw = self.raw(self.row())
        for field, value in [('target_feed', {'publisher': 'feeds', 'name': 'threat-register'}),
                             ('definition', {**self.profile['definition'], 'loss_categories': ['missed sales']})]:
            profile = {**self.profile, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(collect.Refused, 'outcome accounting boundaries'):
                collect.resolution_source(raw, self.policy, self.root, self.closure(raw), profile)

    def test_empty_ledger_is_not_zero_without_independent_non_event_close(self):
        closure = self.closure(b'', incident_ids=[], source_ids=[])
        with self.assertRaisesRegex(collect.Refused, 'empty records'): self.resolve(b'', closure)
        closure['no_events'] = self.reference('independent-no-events-attestation', 'SYNTHETIC TEST ONLY explicitly complete no-events attestation')
        self.assertEqual(self.resolve(b'', closure)['amount'], '0')
        closure['no_events']['custodian'] = 'feeds'
        with self.assertRaisesRegex(collect.Refused, 'forecaster/scorer'): self.resolve(b'', closure)

    def test_incomplete_disputed_or_early_annual_closure_refuses(self):
        raw = self.raw(self.row())
        for changes in [{'final': False}, {'complete': False}, {'disputed': ['TEST-ONLY-dispute']}, {'resolved_at': '2027-12-31T23:59:59Z'}]:
            with self.subTest(changes=changes), self.assertRaises(collect.Refused): self.resolve(raw, self.closure(raw, **changes))

    def test_actual_incident_without_cost_is_not_relabelled_a_non_event(self):
        incident = self.row(category='incident-register', source_id=None, source_amount=None,
            allocation_amount=None, hours=None, rate=None,
            evidence=self.reference('incident-register', 'SYNTHETIC TEST ONLY actual incident, no incremental expense recorded'))
        raw = self.raw(incident)
        closure = self.closure(raw, source_ids=[])
        with self.assertRaisesRegex(collect.Refused, 'not non-events'): self.resolve(raw, closure)
        closure['no_expense'] = self.reference('independent-no-additional-expense-attestation', 'SYNTHETIC TEST ONLY independently reconciled no incremental expense')
        result = self.resolve(raw, closure)
        self.assertEqual(result['amount'], '0'); self.assertIsNone(result['independent_no_events_attestation'])
        self.assertIsNotNone(result['independent_no_additional_expense_attestation'])

    def test_expense_incurred_boundary_excludes_carry_out_even_for_same_incident(self):
        a = self.row()
        invoice = self.reference('invoice', 'SYNTHETIC TEST ONLY carry-out expense')
        b = self.row(entry_id='TEST-ONLY-next-year', source_id='TEST-ONLY-next-invoice',
            incurred_at='2028-01-01T00:00:00Z', recorded_at='2028-01-01T12:00:00Z',
            category='incremental-restoration-invoice', source_amount='50', allocation_amount='50',
            hours=None, rate=None, evidence=invoice)
        raw = self.raw(a, b)
        self.assertEqual(self.resolve(raw)['amount'], '20')
        with self.assertRaisesRegex(collect.Refused, 'exact incident/source inventory'):
            self.resolve(raw, self.closure(raw, source_ids=['TEST-ONLY-worklog', 'TEST-ONLY-next-invoice']))

    def test_thirty_day_process_is_never_an_annual_outcome(self):
        assessment = {'schema': 'recovery-expense/process-assessment-v1', 'starts_at': '2026-10-24T00:00:00Z',
            'ends_at': '2026-11-23T00:00:00Z', 'assessed_at': '2026-11-23T00:00:00Z', 'ledger_sha256': collect.digest(b''),
            'evidence': self.reference('process-reconciliation', 'SYNTHETIC TEST ONLY process coverage'), 'complete': True}
        result = collect.process_assessment(b'', self.policy, self.root, assessment)
        self.assertFalse(result['annual_case_eligible']); self.assertIsNone(result['observed_annual_amount']); self.assertIsNone(result['score'])
        assessment['ends_at'] = '2026-11-22T00:00:00Z'
        with self.assertRaisesRegex(collect.Refused, '30-day'): collect.process_assessment(b'', self.policy, self.root, assessment)


if __name__ == '__main__':
    unittest.main()
