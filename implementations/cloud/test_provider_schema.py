"""Exercise the package's real pinned upstream schemas and false substitutes."""
from pathlib import Path
import shutil

import pytest

from provider_schema import HERE, manifest, validate


def test_exact_upstream_schemas_expose_the_dials():
    result = validate(HERE / 'vendor-crds')
    assert len(result) == 2
    assert {doc['metadata']['name'] for doc, _ in result} == {
        'instances.rds.aws.m.upbound.io',
        'bucketserversideencryptionconfigurations.s3.aws.m.upbound.io',
    }
    assert {receipt['commit'] for _, receipt in result} == {'857b535dd0eb9b8242ad9d7c4e54aaa3e4616d60'}


@pytest.mark.parametrize('substitution', ['extra-byte', 'fixture-mapping', 'missing', 'extra'])
def test_schema_substitutes_are_rejected(tmp_path: Path, substitution: str):
    source = tmp_path / 'crds'
    shutil.copytree(HERE / 'vendor-crds', source)
    filename = manifest()['resources'][0]['path']
    if substitution == 'extra-byte':
        with (source / filename).open('ab') as output:
            output.write(b'\n')
    elif substitution == 'fixture-mapping':
        shutil.copyfile(HERE / 'tests/resource-mapping-crds.yaml', source / filename)
    elif substitution == 'missing':
        (source / filename).unlink()
    else:
        (source / 'extra.yaml').write_text('kind: ProviderConfig\n')
    with pytest.raises(ValueError, match='SHA256 differs|exactly the two'):
        validate(source)
