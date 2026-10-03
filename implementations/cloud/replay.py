#!/usr/bin/env python3
"""Exercise the real Kyverno CLI on cloud mutations and Audit outcomes.

No Kubernetes client, provider installation, network or AWS API is used.
This proves CEL and the declared fields, not CRD schema validity, webhook
registration, cloud networking or provider reconciliation. oldObject/status
exclusion compiles but is a live admission question: CLI supplies no oldObject.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import yaml

from render import HERE, LABEL, render, write_tree


def resource(case: dict) -> dict:
    kind = case['kind']
    group = 'rds' if kind == 'Instance' else 's3'
    md = {'name': case['name'], 'namespace': 'cloud-proof', 'labels': {'app.kubernetes.io/name': 'ledger'}}
    if case.get('claim', '5.0.0') is not None:
        md['labels'][LABEL] = case.get('claim', '5.0.0')
    if 'workload_tier' in case:
        md['labels']['posture.acme.io/tier'] = case['workload_tier']
    provider = {'region': 'eu-west-1'}
    if kind == 'Instance':
        provider.update({'engine': 'postgres', 'instanceClass': 'db.t3.micro',
                         'allocatedStorage': 20, 'username': 'ledger',
                         'publiclyAccessible': True, 'storageEncrypted': False, 'multiAz': False})
    else:
        provider['bucketRef'] = {'name': 'ledger-data'}
    provider.update(copy.deepcopy(case.get('provider', {})))
    return {'apiVersion': f'{group}.aws.m.upbound.io/v1beta1', 'kind': kind,
            'metadata': md, 'spec': {'forProvider': provider}}


def namespace(case: dict) -> dict:
    labels = {}
    if case.get('governed', True):
        labels['policy-as-versioned.dev/governed'] = 'true'
    if case.get('tier') is not None:
        labels['posture.acme.io/tier'] = case['tier']
    return {'apiVersion': 'v1', 'kind': 'Namespace',
            'metadata': {'name': 'cloud-proof', 'labels': labels}}


def run(binary: str, *args: str) -> subprocess.CompletedProcess:
    result = subprocess.run([binary, *args], capture_output=True, text=True, timeout=30)
    text = result.stdout + result.stderr
    # The CLI has printed compile errors while returning zero. Inspect them.
    if re.search(r'Error:|failed to compile|error: [1-9]', text):
        raise AssertionError(text)
    return result


def check_fields(before: dict, after: dict, case: dict) -> None:
    expected = case['expected']
    labels = after['metadata']['labels']
    assert labels['posture.acme.io/tier'] == expected['tier'], case['name']
    assert labels['posture.acme.io/caged'] == 'true', case['name']
    assert labels['app.kubernetes.io/name'] == 'ledger'
    fp = after['spec']['forProvider']
    assert fp['region'] == before['spec']['forProvider']['region']
    if case['kind'] == 'Instance':
        assert fp['publiclyAccessible'] is False and fp['storageEncrypted'] is True
        for key in ('multiAz', 'backupRetentionPeriod'):
            assert fp[key] == expected[key], (case['name'], key, fp[key])
        for key in ('engine', 'instanceClass', 'allocatedStorage', 'username'):
            assert fp[key] == before['spec']['forProvider'][key]
    else:
        assert fp['bucketRef'] == before['spec']['forProvider']['bucketRef']
        for rule in fp['rule']:
            assert rule['applyServerSideEncryptionByDefault']['sseAlgorithm'] == expected['sseAlgorithm']
            if 'kmsMasterKeyId' in expected:
                assert rule['applyServerSideEncryptionByDefault']['kmsMasterKeyId'] == expected['kmsMasterKeyId']
            if 'bucketKeyEnabled' in expected:
                assert rule['bucketKeyEnabled'] == expected['bucketKeyEnabled']


def replay(binary: str, package: Path = HERE) -> dict:
    version_output = run(binary, 'version').stdout
    version = re.search(r'Version:\s*(\d+\.\d+\.\d+)', version_output).group(1)
    descriptor = yaml.safe_load((package / 'package.yaml').read_text())
    assert version in descriptor['tested_engines'], f'engine {version} is not declared by this package'
    crd_flag = '--crd-paths' if '--crd-paths' in run(binary, 'apply', '--help').stdout else '--crd-path'
    docs = render(package, '5.0.0', 'tuppence', '0' * 40)
    assert all(d['spec'].get('validationActions', ['Audit']) == ['Audit'] for d in docs)
    cases = yaml.safe_load((package / 'tests/cases.yaml').read_text())['cases']
    with tempfile.TemporaryDirectory(prefix='cloud-replay-') as tmp:
        work = Path(tmp)
        write_tree(work / 'policies', docs)
        for case in cases:
            before = resource(case)
            (work / 'input.yaml').write_text(yaml.safe_dump(before))
            (work / 'values.yaml').write_text(yaml.safe_dump({
                'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Values',
                'namespaces': [namespace(case)],
                'globalValues': {'request.operation': 'CREATE'},
            }))
            service = 'rds' if case['kind'] == 'Instance' else 's3'
            mutate = work / 'policies' / f'cloud-cage-{service}-5-0-0.yaml'
            audit = work / 'policies' / (('require-rds-multi-az' if service == 'rds' else 'require-s3-bucket-encryption') + '-5-0-0.yaml')
            args = ['--values-file', str(work / 'values.yaml'), crd_flag,
                    str(package / 'tests/resource-mapping-crds.yaml')]
            result = run(binary, 'apply', str(mutate), '--resource', str(work / 'input.yaml'), *args,
                         '--output', str(work / 'mutated.yaml'))
            assert result.returncode == 0, result.stdout + result.stderr
            after = next(d for d in yaml.safe_load_all((work / 'mutated.yaml').read_text()) if d)
            check_fields(before, after, case)
            # Idempotency is verified by evaluating the shipped CEL again.
            run(binary, 'apply', str(mutate), '--resource', str(work / 'mutated.yaml'), *args,
                '--output', str(work / 'twice.yaml'))
            twice = next(d for d in yaml.safe_load_all((work / 'twice.yaml').read_text()) if d)
            assert after == twice, f'{case["name"]}: mutation changed an already caged object'
            result = run(binary, 'apply', str(audit), '--resource', str(work / 'input.yaml'), *args, '--audit-warn')
            stats = re.search(r'pass: (\d+), fail: (\d+), warn: (\d+), error: (\d+), skip: (\d+)', result.stdout)
            assert stats, result.stdout + result.stderr
            passed, failed, warned, errors, skipped = map(int, stats.groups())
            assert errors == 0, result.stdout
            if case['audit'] == 'skip':
                assert skipped > 0 and passed == warned == failed == 0, case['name']
            elif case['audit']:
                assert passed == 1 and warned == failed == 0, case['name']
            else:
                # CEL Audit failures may still appear in the CLI's `fail`
                # column. That is an observation, never an admission Deny.
                assert warned + failed == 1 and passed == 0, (case['name'], result.stdout)
    return {'engine': version, 'cases': len(cases), 'mutation': 'fields-and-idempotency-pass',
            'audit': 'original-input-outcomes-pass', 'scope': descriptor['engine_scope'],
            'limits': ['offline-not-admission', 'provider-schema-unmeasured', 'status-update-unmeasured', 'no-AWS-reconciliation']}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--kyverno', default=shutil.which('kyverno'))
    args = ap.parse_args()
    assert args.kyverno, 'kyverno CLI is required; no green without the instrument'
    result = replay(args.kyverno)
    print(json.dumps(result, sort_keys=True))
    print(f'PASS: offline cloud replay on Kyverno {result["engine"]}; {result["cases"]} cases; no admission or AWS observation claimed')


if __name__ == '__main__':
    main()
