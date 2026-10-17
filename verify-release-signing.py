#!/usr/bin/env python3
"""Probe the actual release signing calls without issuing a signature or tag.

A deliberate failing gitsign stand-in records Git's effective configuration at
its signing boundary. This proves mode selection and abort behavior only; genuine
certificate issuance and transparency-log verification remain live release checks.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parent


class ReleaseSigning(unittest.TestCase):
    def probe(self, caller: str) -> None:
        with tempfile.TemporaryDirectory(prefix='release-signing-mode-') as temporary:
            root = Path(temporary)
            tools = root / 'bin'
            tools.mkdir()
            record = root / 'signing-mode'
            signer = tools / 'gitsign'
            signer.write_text(
                '#!/bin/sh\n'
                'mode="$(git config --get gitsign.rekorMode || true)"\n'
                'printf "%s\\n" "${mode:-<unset>}" >> "$SIGNING_MODE_PROBE"\n'
                '# Deliberately refuse issuance: the caller must abort here.\n'
                'exit 97\n')
            signer.chmod(0o755)
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1',
                       GIT_CONFIG_COUNT='2', GIT_CONFIG_KEY_0='commit.gpgsign',
                       GIT_CONFIG_VALUE_0='false', GIT_CONFIG_KEY_1='tag.gpgsign',
                       GIT_CONFIG_VALUE_1='false', SIGNING_MODE_PROBE=str(record),
                       GITHUB_REPOSITORY_OWNER='synthetic-fixture', VERSION='1.0.0',
                       RELEASE_MESSAGE='synthetic signer-mode probe',
                       PATH=str(tools) + os.pathsep + os.environ['PATH'])
            env.pop('CUT_RELEASE_TEST_MODE', None)
            env.pop('GITSIGN_REKOR_MODE', None)
            for name in tuple(env):
                if name.endswith('_TOKEN') or name == 'PAVC_OTHER_HAND_PRIVATE_KEY':
                    env.pop(name)

            def git(*args: str) -> str:
                return subprocess.check_output(['git', *args], cwd=root, env=env,
                                               text=True, stderr=subprocess.DEVNULL).strip()

            git('init', '-q', '-b', 'main')
            git('config', 'core.hooksPath', os.devnull)
            git('config', 'user.name', 'synthetic fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (root / 'fixture').write_text('No release identity, key or remote.\n')
            git('add', 'fixture')
            git('commit', '-qm', 'synthetic unsigned fixture')
            before = git('rev-parse', 'HEAD')
            if caller == 'cut-release':
                tags = root / 'tags.json'
                tags.write_text(json.dumps([{'tag': 'v1.0.0', 'message': 'synthetic mode probe'}]))
                command = ['bash', str(ROOT / '.github/scripts/cut-release-create-tags.sh'), str(tags)]
            else:
                document = yaml.load((ROOT / '.github/workflows/cloud-release.yml').read_text(),
                                     Loader=yaml.BaseLoader)
                step = next(step for step in document['jobs']['release']['steps']
                            if step.get('name') == 'Sign and verify the one immutable cloud tag')
                command = ['bash', '-e', '-c', step['run']]
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, 'the deliberately refusing signer must stop the caller')
            self.assertTrue(record.is_file(), 'the actual Git signing call must reach the signer probe')
            self.assertEqual(git('tag', '--list'), '', 'the probe must issue no tag')
            self.assertEqual(git('rev-parse', 'HEAD'), before)
            self.assertEqual(git('remote'), '', 'the probe must have no publication destination')
            self.assertEqual(record.read_text(), 'offline\n',
                             'the exact signing call must embed its Rekor proof, once')

    def test_actual_cut_release_signing_call_embeds_rekor_proof(self) -> None:
        self.probe('cut-release')

    def test_actual_cloud_release_signing_call_embeds_rekor_proof(self) -> None:
        self.probe('cloud-release')


if __name__ == '__main__':
    unittest.main()
