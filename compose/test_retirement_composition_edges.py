"""Real composition regressions with explicit synthetic external-authority adapters."""
from pathlib import Path
import json
import os
import subprocess
import sys
from unittest.mock import Mock, patch

import pytest
import yaml

import composition as ct
import consumer_retirement as retirement
import test_consumer_retirement as retirement_fixtures
import test_cloud_composition as cloud_fixtures


def test_baseline_must_be_on_the_actual_public_default():
    fixture = retirement_fixtures.RetirementAuthority()
    fixture.setUp()
    try:
        # The old main contains the genuine-shape original, while the newly selected
        # default is still at its source. Official metadata must not be ignored.
        fixture.git(fixture.adopter, 'branch', 'release/current', fixture.source)
        absent = subprocess.run(['git', '-C', str(fixture.adopter), 'merge-base',
            '--is-ancestor', fixture.original, 'release/current'], capture_output=True)
        assert absent.returncode == 1

        def official(path):
            if path == 'repos/fixture/adopter':
                return {'full_name': 'fixture/adopter', 'default_branch': 'release/current'}
            if '/actions/runs/' in path:
                return fixture.run
            if path.endswith('...main'):
                return fixture.public
            if '/compare/' in path:
                return {'status': 'behind', 'merge_base_commit': {'sha': fixture.source}}
            raise retirement.InvalidRetirement('actual default reader lacks this synthetic endpoint')

        fixture.official = Mock(side_effect=official)
        with pytest.raises(retirement.InvalidRetirement, match='default|public'):
            fixture.select()
    finally:
        fixture.doCleanups()


@pytest.mark.parametrize('claim,expected', [('1.0.0', 'refused'), ('2.0.0', 'composed')])
def test_cloud_claim_and_replay_follow_the_effective_window(tmp_path, claim, expected):
    adopter, trees, pin = cloud_fixtures.estate.__wrapped__(tmp_path)
    parent = trees['fixture-platform']
    ct._write_versions_yaml(parent, [
        {'version': '1.0.0', 'tag': 'policy/v1.0.0', 'commit': 'e' * 40},
        {'version': '2.0.0', 'tag': 'policy/v2.0.0', 'commit': 'f' * 40},
    ])
    ct._write_admission_doc(parent / 'distribution/policies/v2.0.0/member-a.yaml',
        'ValidatingPolicy', 'member-a-2-0-0', 'fam-a', '2.0.0', validation_actions=['Audit'])
    (adopter / 'gitops/cloud/platform-cloud-pin.yaml').write_text(yaml.safe_dump(pin))
    claims_path = adopter / 'gitops/cloud/claims.yaml'
    cloud_claim = yaml.safe_load(claims_path.read_text())
    cloud_claim['metadata']['labels']['policy-as-versioned.dev/policy-version'] = claim
    claims_path.write_text(yaml.safe_dump(cloud_claim))
    incumbent_path = adopter / 'gitops/cloud/INCUMBENT.json'
    incumbent = json.loads(incumbent_path.read_text())
    incumbent['lift_changes']['claim_version']['to'] = claim
    incumbent_path.write_text(json.dumps(incumbent))
    # Cloud fixture claims 1.0.0 and its caller's ResourceSet still lists 1.0.0.
    # The actual immutable apps source claims retained 2.0.0, so that independent
    # reader must pass; it does not exercise or replace the separate cloud reader.
    apps = adopter / 'gitops/apps'
    apps.mkdir(parents=True, exist_ok=True)
    (apps / 'kustomization.yaml').write_text('kind: Kustomization\nresources: [pod.yaml]\n')
    (apps / 'pod.yaml').write_text(yaml.safe_dump({'kind': 'Pod', 'metadata': {
        'name': 'retained', 'namespace': 'fixture-adopter14',
        'labels': {'policy-as-versioned.dev/policy-version': '2.0.0'}}}))

    def git(*args):
        return subprocess.check_output(['git', '-C', str(adopter), *args],
            stderr=subprocess.DEVNULL).decode().strip()

    git('init', '-q')
    git('add', '.')
    git('-c', 'commit.gpgsign=false', '-c', 'user.name=synthetic reviewer',
        '-c', 'user.email=review@example.invalid', 'commit', '-qm', 'synthetic retained apps')
    sha = git('rev-parse', 'HEAD')
    git('-c', 'tag.gpgsign=false', 'tag', 'apps/v1.0.0')
    sync = adopter / 'gitops/flux-system/gotk-sync.yaml'
    sync.parent.mkdir(parents=True, exist_ok=True)
    sync.write_text(yaml.safe_dump_all([
        {'kind': 'GitRepository', 'metadata': {'name': 'apps'},
         'spec': {'ref': {'tag': 'apps/v1.0.0', 'commit': sha}}},
        {'kind': 'Kustomization', 'spec': {'path': './gitops/apps',
         'sourceRef': {'kind': 'GitRepository', 'name': 'apps'}}},
    ]))
    # This test starts at the validated-selection seam. It explicitly stubs that
    # authority and delivery check, plus cloud signing. It does not assert any
    # genuine baseline, signature, server admission or production measurement.
    selected = {'retired': ['1.0.0'], 'retained': ['2.0.0']}
    real_run = subprocess.run

    def commands(args, **kwargs):
        if args[0] == 'gitsign':
            return subprocess.CompletedProcess(args, 0, '', '')
        return real_run(args, **kwargs)

    with patch.object(retirement, 'read_records', return_value={'fixture-platform': selected}), \
         patch.object(retirement, 'select', return_value=selected), \
         patch.object(retirement, 'require_delivered'), patch('subprocess.run', commands):
        document, rendered = ct.compose(adopter, trees)
        assert document['outcome'] == expected, document.get('refusals')
        if expected == 'refused':
            assert not rendered
        else:
            assert sorted({member['version'] for member in document['members']
                           if member.get('version')}) == ['2.0.0']
            assert yaml.safe_load(rendered['composed/cloud-workload/claims.yaml'])[
                'metadata']['labels']['policy-as-versioned.dev/policy-version'] == '2.0.0'
            for path, text in rendered.items():
                target = adopter / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
            verified, mismatches = ct.verify(adopter, trees)
            assert verified, mismatches
