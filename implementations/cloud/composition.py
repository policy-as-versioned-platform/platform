"""Reproduce the complete cloud artefact from this package and workload data."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

import yaml


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def build(package: Path, workload: Path, party: str, source_commit: str,
          served_claims: list[str]) -> tuple[dict, dict[str, str]]:
    """Return source receipts and relative cloud paths, without writing the adopter."""
    source = json.loads((workload / 'INCUMBENT.json').read_text())
    snapshot = workload / source['source_snapshot']
    if not snapshot.resolve().is_relative_to(workload.resolve()):
        raise ValueError('incumbent snapshot escapes the cloud workload directory')
    raw = snapshot.read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if hashlib.sha256(raw).hexdigest() != source['sha256'] or blob != source['git_blob']:
        raise ValueError('incumbent resource snapshot differs from its source receipt')
    expected = [doc for doc in yaml.safe_load_all(raw) if doc]
    changes = source['lift_changes']
    for doc in expected:
        metadata = doc['metadata']
        labels = metadata['labels']
        if metadata['namespace'] != changes['namespace']['from'] or labels.get(changes['claim_label']['from']) != changes['claim_version']['from']:
            raise ValueError('incumbent resource does not have its recorded original binding')
        metadata['namespace'] = changes['namespace']['to']
        del labels[changes['claim_label']['from']]
        labels[changes['claim_label']['to']] = changes['claim_version']['to']
    actual = [doc for doc in yaml.safe_load_all((workload / 'claims.yaml').read_text()) if doc]
    if not actual or actual != expected:
        raise ValueError('cloud lift changed incumbent resource names, specs or non-claim labels')
    label = 'policy-as-versioned.dev/policy-version'
    claims = {doc['metadata']['labels'].get(label) for doc in actual}
    if len(claims) != 1 or not claims <= set(served_claims):
        raise ValueError('cloud workload must select one currently composed policy claim')
    for doc in actual:
        if doc['metadata']['namespace'] != party or doc['kind'] not in ('Instance', 'BucketServerSideEncryptionConfiguration') or 'providerConfigRef' in doc['spec']:
            raise ValueError('cloud workload must remain namespaced and admission-only')
    renderer = _module('cloud_package_render', package / 'render.py')
    schemas = _module('cloud_package_schemas', package / 'provider_schema.py')
    verified = schemas.validate(package / 'vendor-crds', package)
    version = (package / 'VERSION').read_text().strip()
    docs = renderer.render(package, claims.pop(), party, source_commit, served_claims)
    files = {}
    crd_names = []
    receipts = []
    for doc, receipt in verified:
        name = doc['metadata']['name'] + '.yaml'
        data = yaml.safe_dump(doc, sort_keys=False)
        files['cloud-crds/' + name] = data
        crd_names.append(name)
        receipts.append(dict(receipt, rendered_sha256=hashlib.sha256(data.encode()).hexdigest()))
    files['cloud-crds/cloud-rbac.yaml'] = (package / 'cloud-rbac.yaml').read_text()
    crd_names.append('cloud-rbac.yaml')
    files['cloud-crds/kustomization.yaml'] = yaml.safe_dump({
        'apiVersion': 'kustomize.config.k8s.io/v1beta1', 'kind': 'Kustomization',
        'resources': crd_names}, sort_keys=False)
    with tempfile.TemporaryDirectory(prefix='cloud-composed-') as tmp:
        rendered = Path(tmp)
        renderer.write_tree(rendered, docs)
        files.update({'cloud/v' + version + '/' + path.name: path.read_text() for path in sorted(rendered.iterdir())})
    files['cloud/v' + version + '/component-definition.json'] = (package / 'component-definition.json').read_text()
    files['cloud-workload/claims.yaml'] = (workload / 'claims.yaml').read_text()
    files['cloud-workload/kustomization.yaml'] = 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [claims.yaml]\n'
    parent = {'party': 'platform', 'kind': 'implementations', 'name': 'cloud',
              'version': version, 'tag': 'cloud/v' + version, 'sha': source_commit,
              'path': 'implementations/cloud', 'provider_crds': receipts,
              'incumbent': {key: source[key] for key in ('repository', 'commit', 'path', 'git_blob', 'sha256')},
              'proof_boundary': 'admission-only'}
    files['CLOUD-PARENT.json'] = json.dumps(parent, indent=2) + '\n'
    return parent, files
