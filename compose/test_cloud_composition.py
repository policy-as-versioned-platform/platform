"""The ordinary composition seam must reproduce optional signed cloud paths."""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import shutil
import subprocess
from unittest.mock import patch

import pytest
import yaml

import composition as ct


@pytest.fixture
def estate(tmp_path: Path):
    adopter = tmp_path / 'adopter'
    platform = tmp_path / 'fixture-platform'
    trees = {'fixture-platform': platform, 'fixture-nist': tmp_path / 'nist'}
    ct._write_fixture_catalog(trees['fixture-nist'])
    ct._write_fixture_platform(platform, ct.PLATFORM_DIR, [])
    ct._write_fixture_adopter(adopter, 'SMALL')
    cloud = tmp_path / 'platform'
    cloud.mkdir()
    shutil.copytree(ct.PLATFORM_DIR / 'implementations/cloud', cloud / 'implementations/cloud')
    (cloud / 'party.yaml').write_text('party: platform\npublishes:\n  - {kind: implementations, name: cloud, path: implementations/cloud}\n')
    for args in [('init', '-q'), ('add', '.'), ('-c', 'commit.gpgsign=false', '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'cloud fixture')]:
        subprocess.run(['git', '-C', str(cloud), *args], check=True)
    sha = subprocess.check_output(['git', '-C', str(cloud), 'rev-parse', 'HEAD'], text=True).strip()
    subprocess.run(['git', '-C', str(cloud), '-c', 'tag.gpgsign=false', 'tag', 'cloud/v1.0.0'], check=True)
    trees['platform'] = cloud
    source = adopter / 'gitops/cloud'
    source.mkdir(parents=True)
    (source / 'claims.yaml').write_text(yaml.safe_dump({
        'apiVersion': 'rds.aws.m.upbound.io/v1beta1', 'kind': 'Instance',
        'metadata': {'name': 'existing-datastore', 'namespace': 'fixture-adopter14',
                     'labels': {'policy-as-versioned.dev/policy-version': '1.0.0'}},
        'spec': {'forProvider': {'engine': 'postgres', 'region': 'eu-west-1'}},
    }))
    original = {'apiVersion': 'rds.aws.m.upbound.io/v1beta1', 'kind': 'Instance',
                'metadata': {'name': 'existing-datastore', 'namespace': 'default',
                             'labels': {'mycompany.com/policy-version': '2.2.0'}},
                'spec': {'forProvider': {'engine': 'postgres', 'region': 'eu-west-1'}}}
    raw = yaml.safe_dump(original).encode()
    (source / 'original.yaml').write_bytes(raw)
    (source / 'INCUMBENT.json').write_text(json.dumps({
        'repository': 'https://example.invalid/fixture', 'commit': '1' * 40,
        'path': 'claims.yaml', 'source_snapshot': 'original.yaml',
        'sha256': hashlib.sha256(raw).hexdigest(),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
        'lift_changes': {'namespace': {'from': 'default', 'to': 'fixture-adopter14'},
                         'claim_label': {'from': 'mycompany.com/policy-version', 'to': 'policy-as-versioned.dev/policy-version'},
                         'claim_version': {'from': '2.2.0', 'to': '1.0.0'}}}))
    (adopter / 'gitops/composed').mkdir()
    (adopter / 'gitops/composed/composed-set.yaml').write_text('kind: ResourceSet\nspec:\n  inputs:\n    - versions: [{version: 1.0.0}]\n')
    pin = {'apiVersion': 'source.toolkit.fluxcd.io/v1', 'kind': 'GitRepository',
           'metadata': {'name': 'platform-cloud'}, 'spec': {
               'url': 'https://github.com/policy-as-versioned-platform/platform',
               'ref': {'tag': 'cloud/v1.0.0', 'commit': sha}}}
    return adopter, trees, pin


def test_cloud_pin_is_not_silently_omitted_from_ordinary_composition(estate):
    adopter, trees, pin = estate
    (adopter / 'gitops/cloud/platform-cloud-pin.yaml').write_text(yaml.safe_dump(pin))
    real_run = subprocess.run
    calls = []
    def commands(command, **kwargs):
        if command[0] == 'gitsign':
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, '', '')
        return real_run(command, **kwargs)
    with patch('subprocess.run', commands):
        document, rendered = ct.compose(adopter, trees)
    assert document['outcome'] == 'composed', document
    assert 'composed/cloud/v1.0.0/kustomization.yaml' in rendered
    assert 'composed/cloud-crds/instances.rds.aws.m.upbound.io.yaml' in rendered
    assert yaml.safe_load(rendered['composed/cloud-workload/claims.yaml'])['metadata']['name'] == 'existing-datastore'
    assert document['cloud']['sha'] == pin['spec']['ref']['commit']
    assert calls and calls[0][1:3] == ['verify-tag', 'cloud/v1.0.0']
    for path, text in rendered.items():
        output = adopter / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
    with patch('subprocess.run', commands):
        verified, mismatches = ct.verify(adopter, trees)
    assert verified, mismatches


def test_no_cloud_pin_preserves_the_existing_composition(estate):
    adopter, trees, _ = estate
    document, rendered = ct.compose(adopter, trees)
    assert document['outcome'] == 'composed', document
    assert 'cloud' not in document
    assert not any(path.startswith('composed/cloud') for path in rendered)


@pytest.mark.parametrize('fault', ['wrong-sha', 'wrong-url', 'failed-signature'])
def test_an_invalid_cloud_pin_refuses_before_publishing_an_artefact(estate, fault):
    adopter, trees, pin = estate
    if fault == 'wrong-sha':
        pin['spec']['ref']['commit'] = '0' * 40
    elif fault == 'wrong-url':
        pin['spec']['url'] = 'https://github.com/elsewhere/platform'
    (adopter / 'gitops/cloud/platform-cloud-pin.yaml').write_text(yaml.safe_dump(pin))
    real_run = subprocess.run
    def commands(command, **kwargs):
        if command[0] == 'gitsign':
            return subprocess.CompletedProcess(command, 1, '', 'wrong certificate identity')
        return real_run(command, **kwargs)
    with patch('subprocess.run', commands):
        document, rendered = ct.compose(adopter, trees)
    assert document['outcome'] == 'refused'
    assert not rendered
