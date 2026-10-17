"""Optional cloud-package pin adapter for the ordinary compose/verify seam.

The cloud parent and compiler are independent of the frozen Pod policy parent.
Only identity-verified code from the exact cloud tag may render cloud paths.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

import yaml

PIN = 'gitops/cloud/platform-cloud-pin.yaml'
IDENTITY = r'^https://github\.com/policy-as-versioned-platform/platform/\.github/workflows/cloud-release\.yml@refs/heads/(main|release/[0-9]+\.[0-9]+\.x)$'


def render(adopter: Path, platform: Path | None, party: str,
           served_claims: list[str]) -> tuple[dict | None, dict[str, str]]:
    pin = adopter / PIN
    if not pin.exists():
        return None, {}
    document = yaml.safe_load(pin.read_text())
    if not isinstance(document, dict) or not isinstance(document.get('spec'), dict):
        raise ValueError('cloud package pin must be a GitRepository mapping')
    spec = document.get('spec', {})
    ref = spec.get('ref', {})
    if not isinstance(ref, dict):
        raise ValueError('cloud package pin must carry a tag and commit mapping')
    tag, commit = ref.get('tag'), ref.get('commit')
    if (document.get('kind') != 'GitRepository' or
            spec.get('url', '').removesuffix('.git').rstrip('/') != 'https://github.com/policy-as-versioned-platform/platform' or
            not isinstance(tag, str) or not re.fullmatch(r'cloud/v\d+\.\d+\.\d+', tag) or
            not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit) or
            set(ref) != {'tag', 'commit'}):
        raise ValueError('cloud package pin needs its canonical publisher, cloud tag and full commit')
    if platform is None:
        raise ValueError('cloud package has no platform repository to verify')
    def git(*args: str) -> str:
        return subprocess.check_output(['git', '-C', str(platform), *args], text=True).strip()
    if git('rev-parse', tag + '^{commit}') != commit:
        raise ValueError('cloud package tag and commit disagree')
    verified = subprocess.run(['gitsign', 'verify-tag', tag,
                               '--certificate-identity-regexp=' + IDENTITY,
                               '--certificate-oidc-issuer=https://token.actions.githubusercontent.com'],
                              cwd=platform, env=dict(os.environ, GITSIGN_REKOR_MODE='offline'),
                              capture_output=True, text=True, timeout=30)
    if verified.returncode:
        raise ValueError('cloud package tag failed identity-pinned signature verification')
    publisher = yaml.safe_load(git('show', commit + ':party.yaml'))
    if not any(row.get('kind') == 'implementations' and row.get('name') == 'cloud' and row.get('path') == 'implementations/cloud' for row in publisher.get('publishes', [])):
        raise ValueError('cloud package is absent from its publisher discovery record')
    with tempfile.TemporaryDirectory(prefix='signed-cloud-package-') as tmp:
        snapshot = Path(tmp)
        archive = subprocess.check_output(['git', '-C', str(platform), 'archive', commit, 'implementations/cloud'])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
            tree.extractall(snapshot, filter='data')
        package = snapshot / 'implementations/cloud'
        if (package / 'VERSION').read_text().strip() != tag.removeprefix('cloud/v'):
            raise ValueError('cloud tag and package version disagree')
        loader = importlib.util.spec_from_file_location('signed_cloud_composition', package / 'composition.py')
        assert loader is not None and loader.loader is not None
        builder = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(builder)
        parent, files = builder.build(package, adopter / 'gitops/cloud', party, commit, served_claims)
        parent['signature_identity'] = IDENTITY
        # The parent receipt is itself reproduced, including the verifier identity.
        files['CLOUD-PARENT.json'] = json.dumps(parent, indent=2) + '\n'
        return parent, {'composed/' + path: text for path, text in files.items()}
