#!/usr/bin/env python3
"""Read the exact public vendor schemas this cloud package was tested against.

Fetching these two CRD documents installs no provider, controller or credentials.
The release source pins both the upstream commit and the original file bytes.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import urllib.request

import yaml

HERE = Path(__file__).resolve().parent
NAMES = {'instances.rds.aws.m.upbound.io',
         'bucketserversideencryptionconfigurations.s3.aws.m.upbound.io'}


def manifest(package: Path = HERE) -> dict:
    result = yaml.safe_load((package / 'provider-crds.yaml').read_text())
    descriptor = yaml.safe_load((package / 'package.yaml').read_text())
    if result['schema'] != 1 or result['version'] != descriptor['provider_crds']['package_version']:
        raise ValueError('provider schema version disagrees with the cloud package')
    commit = result['commit']
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('vendor schema requires an immutable upstream commit')
    if len(result['resources']) != 2 or {r['name'] for r in result['resources']} != NAMES:
        raise ValueError('vendor schema manifest must name exactly the RDS and S3 CRDs')
    for row in result['resources']:
        if Path(row['path']).name != row['path'] or not row['path'].endswith('.yaml'):
            raise ValueError('vendor schema filename is not a plain YAML filename')
        expected = f'https://raw.githubusercontent.com/crossplane-contrib/provider-upjet-aws/{commit}/package/crds/{row["path"]}'
        if row['url'] != expected or not re.fullmatch(r'[0-9a-f]{64}', row['sha256']):
            raise ValueError('vendor schema URL or SHA256 is not pinned to its source')
    return result


def validate(directory: Path, package: Path = HERE) -> list[tuple[dict, dict]]:
    """Return parsed CRDs with exact source receipts, or fail before any render."""
    pinned = manifest(package)
    if {p.name for p in directory.glob('*.yaml')} != {r['path'] for r in pinned['resources']}:
        raise ValueError('supply exactly the two pinned vendor schema files')
    result = []
    for row in pinned['resources']:
        raw = (directory / row['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('vendor schema SHA256 differs: ' + row['name'])
        docs = [doc for doc in yaml.safe_load_all(raw) if doc]
        if len(docs) != 1:
            raise ValueError('vendor schema file must contain one CRD')
        doc = docs[0]
        if doc.get('kind') != 'CustomResourceDefinition' or doc['metadata']['name'] != row['name'] or doc['spec']['scope'] != 'Namespaced':
            raise ValueError('vendor schema is not the declared namespaced CRD')
        versions = [v for v in doc['spec']['versions'] if v['name'] == 'v1beta1' and v['served']]
        if len(versions) != 1:
            raise ValueError('vendor schema does not serve the package API version')
        provider = versions[0]['schema']['openAPIV3Schema']['properties']['spec']['properties']['forProvider']
        if provider.get('x-kubernetes-preserve-unknown-fields') or not provider.get('properties'):
            raise ValueError('offline resource mapping is not a vendor field schema')
        fields = provider['properties']
        if row['name'].startswith('instances.'):
            expected = {'multiAz': 'boolean', 'publiclyAccessible': 'boolean',
                        'storageEncrypted': 'boolean', 'backupRetentionPeriod': 'number'}
            if any(fields.get(name, {}).get('type') != kind for name, kind in expected.items()):
                raise ValueError('vendor RDS dial types differ from the cloud package')
        else:
            defaults = fields['rule']['items']['properties']['applyServerSideEncryptionByDefault']
            if defaults.get('type') != 'object' or defaults['properties']['sseAlgorithm']['type'] != 'string':
                raise ValueError('vendor encryption shape differs from the cloud package')
        receipt = dict(row, version=pinned['version'], commit=pinned['commit'])
        result.append((doc, receipt))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['fetch', 'verify'])
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'fetch':
        args.directory.mkdir(parents=True, exist_ok=True)
        for row in manifest()['resources']:
            with urllib.request.urlopen(row['url'], timeout=30) as response:
                raw = response.read()
            if hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('downloaded vendor schema SHA256 differs: ' + row['name'])
            (args.directory / row['path']).write_bytes(raw)
    result = validate(args.directory)
    print(f'PASS: {len(result)} exact vendor CRD schemas; no provider controller or AWS observation')


if __name__ == '__main__':
    main()
