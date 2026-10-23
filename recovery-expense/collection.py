"""Append-only direct-recovery collection; independent closure feeds the existing NIST SDK."""
from __future__ import annotations

import argparse
from collections import defaultdict
from decimal import Decimal, localcontext
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

PARTIES = ('driftwood', 'tuppence', 'ludlow')
BASIS = 'nominal direct security-incident recovery expense per registered subject-year'
UNIT = {'currency': 'GBP', 'basis': BASIS}
ACCOUNTING = {
    'unit_basis': 'nominal direct security-incident recovery expense per registered subject-year',
    'included': ['Incremental incident-response and restoration labour at an agreed charge-out rule, supported by worklogs',
                 'Actual incremental restoration/vendor invoices allocated once to a registered cost centre'],
    'excluded': ['Routine controls and already-budgeted operating cost',
                 'Missed sales, fines, premiums, customer/patient losses',
                 'Double-counted shared incident costs, forecast-generated outcomes and synthetic tests'],
    'allocation': 'Allocate each independently evidenced source cost once across registered cost centres; disclose shared incidents and dependence.',
    'recognition': 'Recognize eligible expense by incurred UTC date in the registered subject-year, not incident onset, payment or recording date. Annual frequency counts incidents with eligible recovery activity in that year, including carry-in; severity is only their eligible within-year incremental direct expense, excluding carry-out.',
    'completeness': 'Complete cost-centre incident ledger plus attributable invoices/worklogs and an independent final completeness attestation; an empty log is not zero.',
    'finality': 'Year-end independent reconciliation and signed final/complete record; unresolved or disputed amounts are ineligible. Closing within 31 days is a process target.'}


class Refused(ValueError):
    pass


def closed(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise Refused(label + ': missing or unknown fields')
    return value


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise Refused(label + ': nonempty text required')
    return value


def stamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value):
        raise Refused('exact UTC timestamp required')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise Refused('invalid UTC timestamp') from error


def money(value, *, positive=False):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]{0,15})(\.[0-9]{1,8})?', value):
        raise Refused('bounded nonnegative exact decimal string required')
    result = Decimal(value)
    if positive and result <= 0:
        raise Refused('positive expense/hours/rate required; zero is not a non-event record')
    return result


def wire(value):
    result = format(value, 'f')
    return result.rstrip('0').rstrip('.') if '.' in result else result


def parse(raw):
    if len(raw) > 33554432:
        raise Refused('collection input exceeds 32 MiB')
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise Refused('duplicate JSON key')
            value[key] = item
        return value
    def constant(_):
        raise Refused('nonfinite JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def read(path):
    return parse(Path(path).read_bytes())


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def accounting_policy(policy):
    closed(policy, ('schema', 'unit', 'cost_centres', 'labour_rates_gbp_per_hour', 'operator_control_disclosure'), 'accounting policy')
    if policy['schema'] != 'recovery-expense/accounting-policy-v1' or policy['unit'] != UNIT:
        raise Refused('explicit direct-expense accounting policy/unit required')
    closed(policy['cost_centres'], PARTIES, 'cost centre population')
    closed(policy['labour_rates_gbp_per_hour'], PARTIES, 'labour rates')
    for party in PARTIES:
        centres = policy['cost_centres'][party]
        if not isinstance(centres, list) or not centres or any(not isinstance(x, str) or not x.strip() for x in centres) or len(centres) != len(set(centres)):
            raise Refused('explicit unique registered cost centres required')
        money(policy['labour_rates_gbp_per_hour'][party], positive=True)
    text(policy['operator_control_disclosure'], 'shared operator/control disclosure')
    return policy


def evidence(reference, root, kind):
    closed(reference, ('path', 'sha256', 'uri', 'custodian', 'kind'), 'independent evidence')
    relative = reference['path']
    if not isinstance(relative, str) or not relative or any(x in ('', '.', '..', '.git') for x in relative.split('/')) or '\\' in relative or relative.startswith('/'):
        raise Refused('strict relative evidence path required')
    base = Path(root).resolve(); path = base / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(base):
        raise Refused('evidence must be an actual regular file inside the evidence root')
    with path.open('rb') as stream:
        actual_hash = digest(stream.read(33554433))
    if not isinstance(reference['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', reference['sha256']) or actual_hash != reference['sha256']:
        raise Refused('independent evidence content hash differs')
    if path.stat().st_size > 33554432:
        raise Refused('individual evidence exceeds 32 MiB')
    if not isinstance(reference['uri'], str) or not reference['uri'].startswith('https://'):
        raise Refused('independent evidence requires its actual HTTPS authority URI')
    custodian = text(reference['custodian'], 'evidence custodian')
    if custodian.lower() in ('feeds', 'nist') or reference['kind'] != kind:
        raise Refused('forecaster/scorer cannot supply recovery outcomes or substituted evidence kinds')
    return reference


def ledger(raw, policy, evidence_root):
    """Validate every row and the complete cross-institution allocation before selection."""
    accounting_policy(policy)
    if len(raw) > 33554432 or (raw and not raw.endswith(b'\n')):
        raise Refused('ledger must be bounded complete newline-terminated JSONL')
    rows = []; previous = None; ids = {}; sources = {}; allocated = defaultdict(Decimal); seen_allocations = set(); evidence_sources = {}; seen_incidents = set()
    lines = raw.splitlines()
    if len(lines) > 100000:
        raise Refused('ledger row budget exceeded')
    for index, line in enumerate(lines):
        row = parse(line)
        closed(row, ('schema', 'sequence', 'previous_sha256', 'entry_id', 'incident_id', 'incurred_at', 'recorded_at',
                     'subject', 'cost_centre', 'category', 'source_id', 'source_amount', 'allocation_amount',
                     'hours', 'rate', 'evidence', 'duplicate_of'), 'ledger row')
        if row['schema'] != 'recovery-expense/entry-v1' or type(row['sequence']) is not int or row['sequence'] != index + 1 or row['previous_sha256'] != previous:
            raise Refused('append-only sequence/raw-line hash chain differs')
        previous = digest(line)
        for name in ('entry_id', 'incident_id'):
            text(row[name], name)
        if row['entry_id'] in ids:
            raise Refused('duplicate ledger entry identity')
        ids[row['entry_id']] = row
        subject = row['subject']
        if subject not in PARTIES or row['cost_centre'] not in policy['cost_centres'][subject]:
            raise Refused('expense is outside the explicitly registered institutional cost centres')
        if stamp(row['recorded_at']) < stamp(row['incurred_at']):
            raise Refused('expense recording precedes its incurred timestamp')
        if row['category'] == 'incident-register':
            if any(row[k] is not None for k in ('source_id', 'source_amount', 'allocation_amount', 'hours', 'rate', 'duplicate_of')):
                raise Refused('incident registration cannot invent a zero or monetary expense')
            evidence(row['evidence'], evidence_root, 'incident-register')
            incident_key = (row['incident_id'], subject, row['cost_centre'])
            if incident_key in seen_incidents:
                raise Refused('duplicate incident registration identity')
            seen_incidents.add(incident_key)
            rows.append(row)
            continue
        text(row['source_id'], 'source_id')
        if row['category'] not in ('incremental-response-labour', 'incremental-restoration-invoice'):
            raise Refused('routine costs, fines, missed sales, synthetic tests and other categories are excluded')
        kind = 'worklog' if row['category'] == 'incremental-response-labour' else 'invoice'
        evidence(row['evidence'], evidence_root, kind)
        amount = money(row['source_amount'], positive=True)
        allocation = money(row['allocation_amount'], positive=True)
        if allocation > amount:
            raise Refused('allocation exceeds its evidenced source cost')
        if kind == 'worklog':
            hours = money(row['hours'], positive=True); rate = money(row['rate'], positive=True)
            if rate != money(policy['labour_rates_gbp_per_hour'][subject], positive=True):
                raise Refused('worklog rate differs from the explicit pre-agreed charge-out rule')
            with localcontext() as context:
                context.prec = 80
                if hours * rate != amount:
                    raise Refused('worklog hours/rate do not reproduce the exact source expense')
        elif row['hours'] is not None or row['rate'] is not None:
            raise Refused('invoice cannot invent labour hours/rate')
        source = (row['incident_id'], row['incurred_at'], row['source_amount'], row['category'], row['evidence'], row['hours'], row['rate'])
        if row['source_id'] in sources and sources[row['source_id']] != source:
            raise Refused('a shared source substitutes incident, evidence, amount or accounting identity')
        evidence_key = (kind, row['evidence']['sha256'])
        if evidence_key in evidence_sources and evidence_sources[evidence_key] != row['source_id']:
            raise Refused('one evidence document cannot be aliased as multiple source expenses')
        evidence_sources[evidence_key] = row['source_id']
        sources[row['source_id']] = source
        duplicate = row['duplicate_of']
        if duplicate is not None:
            if duplicate == row['entry_id'] or duplicate not in ids:
                raise Refused('duplicate linkage must name an earlier ledger entry')
            original = ids[duplicate]
            if original['duplicate_of'] is not None or any(original[k] != row[k] for k in ('incident_id', 'source_id', 'subject', 'cost_centre', 'allocation_amount', 'evidence')):
                raise Refused('duplicate linkage does not bind the exact original cost allocation')
        else:
            key = (row['source_id'], subject, row['cost_centre'])
            if key in seen_allocations:
                raise Refused('repeated source/cost-centre allocation requires explicit duplicate linkage')
            seen_allocations.add(key)
            with localcontext() as context:
                context.prec = 80
                allocated[row['source_id']] += allocation
            if allocated[row['source_id']] > amount:
                raise Refused('shared source expense is allocated more than once across the population')
        rows.append(row)
    return {'rows': rows, 'ledger_sha256': digest(raw), 'last_raw_line_sha256': previous,
            'source_allocations': {k: wire(v) for k, v in allocated.items()},
            'unallocated_source_ids': [k for k, value in sources.items() if allocated[k] != money(value[2])],
            'operator_control_disclosure': policy['operator_control_disclosure']}


def append_entry(path, entry, policy, evidence_root):
    """Append exactly one checked raw row under a local exclusive file lock; never rewrite."""
    descriptor = os.open(path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'r+b') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Refused('ledger is not a regular file')
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        raw = stream.read(33554433)
        candidate = raw + canonical(entry) + b'\n'
        result = ledger(candidate, policy, evidence_root)
        stream.write(canonical(entry) + b'\n'); stream.flush(); os.fsync(stream.fileno())
        return {'state': 'collection-only', 'entries': len(result['rows']), 'ledger_sha256': result['ledger_sha256'], 'annual_outcome': None}


def process_assessment(raw, policy, evidence_root, assessment):
    """Thirty-day process evidence cannot become an annual scored resolution."""
    result = ledger(raw, policy, evidence_root)
    closed(assessment, ('schema', 'starts_at', 'ends_at', 'assessed_at', 'ledger_sha256', 'evidence', 'complete'), 'process assessment')
    if assessment['schema'] != 'recovery-expense/process-assessment-v1' or stamp(assessment['ends_at']) - stamp(assessment['starts_at']) != timedelta(days=30) or stamp(assessment['assessed_at']) < stamp(assessment['ends_at']):
        raise Refused('process assessment requires an actual completed 30-day collection window')
    if assessment['ledger_sha256'] != result['ledger_sha256'] or type(assessment['complete']) is not bool:
        raise Refused('process completeness must bind the actual complete ledger bytes')
    if any(stamp(r['recorded_at']) > stamp(assessment['assessed_at']) for r in result['rows']):
        raise Refused('process assessment cannot use expense records from its future')
    evidence(assessment['evidence'], evidence_root, 'process-reconciliation')
    return {'schema': 'recovery-expense/process-result-v1', 'state': 'collection-process-only',
            'starts_at': assessment['starts_at'], 'ends_at': assessment['ends_at'],
            'complete_attested': assessment['complete'], 'ledger_entries': len(result['rows']),
            'annual_case_eligible': False, 'observed_annual_amount': None, 'score': None,
            'limitation': 'Collection-process attestation is not annual completeness, a non-event, a financial observation or calibration.'}


def resolution_source(raw, policy, evidence_root, closure, profile):
    result = ledger(raw, policy, evidence_root)
    closed(closure, ('schema', 'case_id', 'subject', 'perspective', 'horizon', 'unit', 'cost_centres',
                     'resolved_at', 'published_at', 'ledger_sha256', 'final', 'complete', 'unresolved', 'disputed',
                     'incident_ids', 'source_ids', 'reconciliation', 'no_events', 'no_expense'), 'independent annual closure')
    policy_hash = digest(canonical(policy))
    if (not isinstance(profile, dict) or profile.get('schema') != 'publisher-reliability/price-profile-v1'
            or profile.get('id') != 'direct-security-recovery-2027'
            or profile.get('unit') != UNIT
            or re.findall(r'Collection-policy-sha256=([0-9a-f]{64})', profile.get('definition', {}).get('accounting_rule', '')) != [policy_hash]):
        raise Refused('annual resolver accounting differs from the exact publisher profile policy')
    expected_definition = {'loss_categories': ACCOUNTING['included'],
        'accounting_rule': ACCOUNTING['allocation'] + ' Recognition: ' + ACCOUNTING['recognition'] + ' Excluded: ' + '; '.join(ACCOUNTING['excluded']) + ' Collection-policy-sha256=' + policy_hash,
        'completeness_rule': ACCOUNTING['completeness'], 'finality_rule': ACCOUNTING['finality']}
    if (profile.get('target_feed') != {'publisher': 'feeds', 'name': 'recovery-expense'}
            or profile.get('definition') != expected_definition
            or profile.get('criterion') != 'money-empirical-crps/v1'
            or profile.get('horizon_rule') != {'duration': 'P1Y', 'boundary': '[start,end)', 'calendar': 'UTC-Gregorian'}
            or profile.get('resolver_rule', {}).get('party') != 'platform'
            or profile.get('resolver_rule', {}).get('source_schema') != 'recovery-expense/resolution-source-v1'
            or any(profile.get('resolver_rule', {}).get(k) != v for k, v in {
                'amount_pointer': '/amount', 'finality_pointer': '/final', 'completeness_pointer': '/complete'}.items())):
        raise Refused('annual resolver and publisher profile outcome accounting boundaries differ')
    subject = closure['subject']
    if (closure['schema'] != 'recovery-expense/closure-v1' or subject not in PARTIES
            or closure['case_id'] != subject + '/2027' or closure['perspective'] != subject or closure['unit'] != UNIT
            or closure['horizon'] != {'starts_at': '2027-01-01T00:00:00Z', 'ends_at': '2028-01-01T00:00:00Z', 'boundary': '[start,end)'}
            or closure['cost_centres'] != policy['cost_centres'][subject]):
        raise Refused('annual closure must bind the exact registered 2027 case/accounting boundary')
    if closure['final'] is not True or closure['complete'] is not True or closure['unresolved'] != [] or closure['disputed'] != []:
        raise Refused('unresolved, disputed or nonfinal/incomplete annual amounts are ineligible')
    if stamp(closure['resolved_at']) < stamp(closure['horizon']['ends_at']) or stamp(closure['published_at']) < stamp(closure['resolved_at']):
        raise Refused('independent annual reconciliation must follow the horizon and publication must follow reconciliation')
    if closure['ledger_sha256'] != result['ledger_sha256']:
        raise Refused('closure does not bind the actual append-only ledger')
    if any(stamp(r['recorded_at']) > stamp(closure['published_at']) for r in result['rows']):
        raise Refused('annual closure cannot bind ledger records unavailable at its publication')
    evidence(closure['reconciliation'], evidence_root, 'annual-reconciliation')
    start, end = stamp(closure['horizon']['starts_at']), stamp(closure['horizon']['ends_at'])
    case_records = [r for r in result['rows'] if r['subject'] == subject and start <= stamp(r['incurred_at']) < end]
    eligible = [r for r in case_records if r['category'] != 'incident-register' and r['duplicate_of'] is None]
    if sorted(closure['incident_ids']) != sorted({r['incident_id'] for r in case_records}) or sorted(closure['source_ids']) != sorted({r['source_id'] for r in eligible}):
        raise Refused('closure does not reconcile the exact incident/source inventory')
    if any(r['source_id'] in result['unallocated_source_ids'] for r in eligible):
        raise Refused('shared source allocation is not fully reconciled across registered cost centres')
    if eligible:
        if closure['no_events'] is not None or closure['no_expense'] is not None:
            raise Refused('a case with actual cost records cannot claim no events or no expense')
    elif case_records:
        if closure['no_events'] is not None or closure['no_expense'] is None:
            raise Refused('recorded incidents are not non-events; independent no-additional-expense reconciliation required')
        evidence(closure['no_expense'], evidence_root, 'independent-no-additional-expense-attestation')
    else:
        if closure['no_events'] is None or closure['no_expense'] is not None:
            raise Refused('empty records do not establish zero; independent explicit non-event closure required')
        evidence(closure['no_events'], evidence_root, 'independent-no-events-attestation')
    with localcontext() as context:
        context.prec = 80
        amount = sum((money(r['allocation_amount']) for r in eligible), Decimal())
    return {'schema': 'recovery-expense/resolution-source-v1',
            **{k: closure[k] for k in ('case_id', 'subject', 'perspective', 'horizon', 'unit', 'resolved_at', 'published_at')},
            'amount': wire(amount), 'final': True, 'complete': True,
            'ledger_sha256': result['ledger_sha256'], 'accounting_policy_sha256': policy_hash,
            'incident_ids': closure['incident_ids'], 'source_ids': closure['source_ids'],
            'incident_entry_ids': [r['entry_id'] for r in case_records if r['category'] == 'incident-register'],
            'source_entry_ids': [r['entry_id'] for r in eligible],
            'reconciliation': closure['reconciliation'], 'independent_no_events_attestation': closure['no_events'],
            'independent_no_additional_expense_attestation': closure['no_expense'],
            'operator_control_disclosure': policy['operator_control_disclosure'],
            'limitation': 'Source construction validates accounting and supplied evidence bytes, not authenticity, independence or world completeness. Signed source/history admission remains with the existing NIST SDK.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('check', 'append', 'process', 'resolve-source'):
        p = sub.add_parser(name)
        p.add_argument('--ledger', required=True); p.add_argument('--policy', required=True); p.add_argument('--evidence-root', required=True)
        if name != 'check': p.add_argument('--record', required=True)
        if name == 'resolve-source': p.add_argument('--profile', required=True)
    args = parser.parse_args(argv)
    try:
        policy = read(args.policy)
        if args.command == 'append':
            result = append_entry(args.ledger, read(args.record), policy, args.evidence_root)
        else:
            raw = Path(args.ledger).read_bytes()
            if args.command == 'check':
                checked = ledger(raw, policy, args.evidence_root)
                result = {'state': 'collection-only-unmeasured', 'entries': len(checked['rows']), 'ledger_sha256': checked['ledger_sha256'],
                          'annual_outcome': None, 'score': None, 'unallocated_source_ids': checked['unallocated_source_ids']}
            elif args.command == 'process': result = process_assessment(raw, policy, args.evidence_root, read(args.record))
            else: result = resolution_source(raw, policy, args.evidence_root, read(args.record), read(args.profile))
        print(json.dumps(result, indent=2, allow_nan=False))
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
