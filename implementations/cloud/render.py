#!/usr/bin/env python3
"""Render the cloud package for a workload claim; no network or release act.

This is deliberately separate from distribution/versions.yaml and the Pod
computed-semver subject. Published Pod lines are never edited by adding a
cloud member. The platform owns the source policies and OSCAL claims;
tuppence owns the derived signed composed artefact.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import re

import yaml

HERE = Path(__file__).resolve().parent
LABEL = 'policy-as-versioned.dev/policy-version'


def render(package: Path, claim: str, party: str, source_commit: str,
           served_claims: list[str] | None = None) -> list[dict]:
    if not re.fullmatch(r'\d+\.\d+\.\d+', claim):
        raise ValueError('workload claim must be an exact semver')
    if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('source commit must be a full immutable SHA, never a placeholder')
    served_claims = served_claims or [claim]
    if claim not in served_claims or any(not re.fullmatch(r'\d+\.\d+\.\d+', value) for value in served_claims):
        raise ValueError('served claims must include this copy and contain only exact semvers')
    descriptor = yaml.safe_load((package / 'package.yaml').read_text())
    version = (package / 'VERSION').read_text().strip()
    if descriptor['version'] != version or descriptor['tag'] != f'cloud/v{version}':
        raise ValueError('package descriptor, VERSION and tag disagree')
    dials = yaml.safe_load((package / 'crossplane-dials.yaml').read_text())['tiers']
    if list(dials) != ['baseline', 'restricted', 'quarantine', 'isolated']:
        raise ValueError('cloud dials must carry exactly the cage ladder, with no infra exemption')
    # CEL maps are homogeneous; encode the mixed dial values as strings and
    # convert them only at the field assignment, as the Pod cage does.
    cel_dials = {tier: {key: str(value).lower() if isinstance(value, bool) else str(value)
                        for key, value in row.items()} for tier, row in dials.items()}
    dial_cel = json.dumps(cel_dials, separators=(',', ':')) + '[variables.tier]'
    out = []
    for member in descriptor['members']:
        doc = yaml.safe_load((package / member).read_text())
        for condition in doc['spec'].get('matchConditions', []):
            condition['expression'] = condition['expression'].replace('__POLICY_VERSION__', claim).replace('__SERVED_CLAIMS__', json.dumps(served_claims))
        for variable in doc['spec'].get('variables', []):
            variable['expression'] = variable['expression'].replace('__POLICY_VERSION__', claim).replace('__DIAL_TABLE__', dial_cel)
        md = doc['metadata']
        # Keep result2oscal's existing one-suffix identity normalization exact.
        md['name'] += '-' + claim.replace('.', '-')
        md.setdefault('labels', {}).update({
            LABEL: claim, 'policy-as-versioned.dev/composed-for': party,
            'policy-as-versioned.dev/cloud-package-version': version,
        })
        md.setdefault('annotations', {}).update({
            'policy-as-versioned.dev/inherited-from': f'platform@{source_commit}',
            'policy-as-versioned.dev/source-path': f'implementations/cloud/{member}',
        })
        out.append(copy.deepcopy(doc))
    return out


def write_tree(destination: Path, docs: list[dict]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    members = []
    for doc in docs:
        name = doc['metadata']['name'] + '.yaml'
        (destination / name).write_text(yaml.safe_dump(doc, sort_keys=False))
        members.append(name)
    (destination / 'kustomization.yaml').write_text(yaml.safe_dump({
        'apiVersion': 'kustomize.config.k8s.io/v1beta1', 'kind': 'Kustomization',
        'resources': members,
    }, sort_keys=False))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--claim', required=True)
    ap.add_argument('--party', default='tuppence')
    ap.add_argument('--source-commit', required=True)
    ap.add_argument('--served-claims', nargs='+')
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    docs = render(HERE, args.claim, args.party, args.source_commit, args.served_claims)
    if args.output:
        write_tree(args.output, docs)
    else:
        print(yaml.safe_dump_all(docs, sort_keys=False), end='')


if __name__ == '__main__':
    main()
