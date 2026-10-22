"""Opt-in real webhook regression; requires an explicitly prepared test cluster.

Install the pinned vendor CRDs and this source's rendered cloud policies first.
No cluster is started, provider installed, or cloud account contacted here.
"""
import json
import os
import subprocess
import uuid

import pytest

from replay import check_fields, resource


@pytest.fixture(scope='module')
def admission():
    config = os.environ.get('CLOUD_ADMISSION_KUBECONFIG')
    context = os.environ.get('CLOUD_ADMISSION_CONTEXT')
    if not config or not context:
        pytest.skip('explicit CLOUD_ADMISSION_KUBECONFIG and CLOUD_ADMISSION_CONTEXT required')

    def call(*args, obj=None):
        result = subprocess.run(
            ['kubectl', '--kubeconfig', config, '--context', context, *args],
            input=json.dumps(obj) if obj is not None else None,
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout) if args[0] != 'delete' else None

    names = {}
    try:
        for governed in (True, False):
            name = 'cloud-regression-' + uuid.uuid4().hex[:12]
            labels = {'posture.acme.io/tier': 'restricted'}
            if governed:
                labels['policy-as-versioned.dev/governed'] = 'true'
            call('create', '-f', '-', '-o', 'json', obj={
                'apiVersion': 'v1', 'kind': 'Namespace',
                'metadata': {'name': name, 'labels': labels},
            })
            names[governed] = name
        yield call, names
    finally:
        for name in names.values():
            call('delete', 'namespace', name, '--wait=false')


@pytest.mark.parametrize('kind', ['Instance', 'BucketServerSideEncryptionConfiguration'])
@pytest.mark.parametrize('claim', ['5.0.0', None, '99.0.0'])
def test_governed_create_is_caged_by_namespace(admission, kind, claim):
    call, namespaces = admission
    tier = 'restricted' if claim == '5.0.0' else 'isolated'
    case = {'kind': kind, 'claim': claim, 'name': 'cloud-admission-regression',
            'expected': {'tier': tier, 'multiAz': True,
                         'backupRetentionPeriod': 7 if tier == 'restricted' else 35,
                         'sseAlgorithm': 'AES256'}}
    before = resource(case)
    before['metadata']['namespace'] = namespaces[True]
    after = call('create', '--dry-run=server', '-f', '-', '-o', 'json', obj=before)
    check_fields(before, after, case)


@pytest.mark.parametrize('kind', ['Instance', 'BucketServerSideEncryptionConfiguration'])
def test_unclaimed_ungoverned_create_stays_outside_population(admission, kind):
    call, namespaces = admission
    case = {'kind': kind, 'claim': None, 'name': 'cloud-outside-population'}
    # S3's real vendor schema requires a rule even when no policy targets it.
    if kind != 'Instance':
        case['provider'] = {'rule': [{'applyServerSideEncryptionByDefault': {'sseAlgorithm': 'AES256'}}]}
    before = resource(case)
    before['metadata']['namespace'] = namespaces[False]
    after = call('create', '--dry-run=server', '-f', '-', '-o', 'json', obj=before)
    assert after['metadata']['labels'] == before['metadata']['labels']
    for key, value in before['spec']['forProvider'].items():
        assert after['spec']['forProvider'][key] == value
