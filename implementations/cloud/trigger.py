#!/usr/bin/env python3
"""Grade an immutable step-4 artifact handed in by the clocks job, offline.

Input: run_metadata.json from the forge, truth.txt (that run's full truth
output), and captures/ containing that run's uncut check output. The collector
must download that numeric run, never copy the moving current captures tree.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import os
import subprocess

CHECK = 'verify/e2e/verify-e2e-step4-flux-reconciles-cage.sh'
CAPTURE = 'verify_e2e_verify-e2e-step4-flux-reconciles-cage.out'
IDENTITY = r'^https://github\.com/policy-as-versioned-flux/policy-as-versioned-flux/\.github/workflows/truth\.yml@refs/heads/main$'


def find(repository: Path, exact_record: str | None = None) -> dict | None:
    """Read immutable clock captures, not a builder's current capture files.

The dated trigger amendment is 2026-09-25. An older step-4 grade cannot
discharge its re-registered question. A candidate must be a signed record on
origin/main and contain that run's TRUTH line; signature verification uses
gitsign's offline Rekor mode. Missing evidence returns no trigger.
"""
    def git(*args: str) -> str:
        return subprocess.check_output(['git', '-C', str(repository), *args], text=True, stderr=subprocess.DEVNULL).strip()
    path = 'talk/captures/' + CAPTURE
    refs = [exact_record] if exact_record else git('log', '--since=2026-09-25', '--format=%H', 'origin/main', '--', path).splitlines()
    for record in refs:
        if not re.fullmatch(r'[0-9a-f]{40}', record):
            raise ValueError('trigger record must be a full immutable commit')
        try:
            capture = git('show', f'{record}:{path}')
            final = next((line for line in reversed(capture.splitlines()) if line.strip()), '')
            if not final.startswith('PASS:') or 'fixture' in final.lower():
                continue
            subject = git('show', '-s', '--format=%s', record)
            match = re.fullmatch(r'truth: record run (\d+).*', subject)
            if not match or git('show', '-s', '--format=%ae', record) != 'truth@users.noreply.github.com':
                continue
            run = match.group(1)
            log = git('show', f'{record}:talk/truth.log')
            rows = [line for line in log.splitlines() if line.startswith('TRUTH ') and f' run={run} ' in line]
            if len(rows) != 1 or rows[0].split()[1][:10] < '2026-09-25' or 'fixture=1' in rows[0]:
                continue
            if rows[0] not in git('show', 'origin/main:talk/truth.log').splitlines():
                continue
            subprocess.run(['git', '-C', str(repository), 'merge-base', '--is-ancestor', record, 'origin/main'], check=True, capture_output=True)
            env = dict(os.environ, GITSIGN_REKOR_MODE='offline')
            verified = subprocess.run(['gitsign', 'verify-commit', record,
                                       '--certificate-identity-regexp=' + IDENTITY,
                                       '--certificate-oidc-issuer=https://token.actions.githubusercontent.com'],
                                      cwd=repository, env=env, capture_output=True, text=True, timeout=30)
            if verified.returncode:
                raise ValueError('citable step-4 record failed offline identity-pinned signature verification')
            return {'run': int(run), 'record_commit': record, 'truth': rows[0], 'check': CHECK}
        except subprocess.CalledProcessError:
            continue
    return None


def check(directory: Path, recorded_truth: Path | None = None) -> dict:
    metadata = json.loads((directory / 'run_metadata.json').read_text())
    if metadata.get('path') != '.github/workflows/truth.yml' or metadata.get('status') != 'completed':
        raise ValueError('trigger is not a completed truth workflow run')
    run, sha = str(metadata['id']), metadata['head_sha']
    if not run.isdigit() or not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('trigger needs a numeric forge run and full head SHA')
    output = (directory / 'truth.txt').read_text()
    rows = [line for line in output.splitlines() if line.startswith('TRUTH ') and f' run={run} ' in line]
    if len(rows) != 1:
        raise ValueError('no unique TRUTH line for the trigger run')
    truth = rows[0]
    if 'fixture=1' in truth or 'units=[fixture]' in truth:
        raise ValueError('a fixture TRUTH line is never a citable trigger')
    hub = re.search(r'\bhub=([0-9a-f]+)\b', truth)
    if not hub or not sha.startswith(hub.group(1)):
        raise ValueError('TRUTH hub disagrees with the Actions head SHA')
    if recorded_truth is not None and truth not in recorded_truth.read_text().splitlines():
        raise ValueError('trigger is absent from recorded talk/truth.log')
    if not re.search(r'^\s*' + re.escape(CHECK) + r'\s+PASS\s*$', output, re.M):
        raise ValueError('e2e step 4 did not grade PASS on this run')
    capture = (directory / 'captures' / CAPTURE).read_text()
    final = next((line for line in reversed(capture.splitlines()) if line.strip()), '')
    if not final.startswith('PASS:') or 'fixture' in final.lower():
        raise ValueError('uncut step-4 capture does not end in an observed PASS')
    return {'run': int(run), 'hub': sha, 'truth': truth, 'check': CHECK}
