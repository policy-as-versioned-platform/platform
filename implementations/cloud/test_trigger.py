"""A recorded trigger must reach the commit verifier's real CLI contract."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess

import pytest


SOURCE = Path(__file__).with_name('trigger.py')
SPEC = importlib.util.spec_from_file_location('cloud_trigger', SOURCE)
assert SPEC is not None and SPEC.loader is not None
trigger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trigger)


@pytest.fixture
def recorded(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / 'hub'
    repository.mkdir()
    def git(*args: str) -> str:
        return subprocess.check_output(['git', '-C', str(repository), *args], text=True).strip()
    git('init', '-q')
    git('config', 'user.name', 'truth')
    git('config', 'user.email', 'truth@users.noreply.github.com')
    capture = repository / 'talk/captures' / trigger.CAPTURE
    capture.parent.mkdir(parents=True)
    capture.write_text('PASS: observed signed-source reconciliation\n')
    (repository / 'talk/truth.log').write_text('TRUTH 2026-10-03T12:00Z run=388 hub=aaaaaaa units=[p=1] pass=1 fail=0 skip=0 excluded=0 total=1 ceiling=1\n')
    git('add', 'talk')
    git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'truth: record run 388')
    record = git('rev-parse', 'HEAD')
    git('update-ref', 'refs/remotes/origin/main', record)
    return repository, record


def test_recorded_trigger_uses_gitsign_commit_verification(recorded, monkeypatch):
    repository, record = recorded
    real_run = subprocess.run
    verified = []
    def cli(command, **kwargs):
        if command[0] != 'gitsign':
            return real_run(command, **kwargs)
        # gitsign 0.17.1 exposes `verify`, whereas verify-commit is a Git command.
        if command[1] != 'verify':
            return subprocess.CompletedProcess(command, 1, '', 'unknown command')
        assert command[2] == record
        assert '--certificate-identity-regexp=' + trigger.IDENTITY in command
        assert '--certificate-oidc-issuer=https://token.actions.githubusercontent.com' in command
        assert kwargs['env']['GITSIGN_REKOR_MODE'] == 'offline'
        verified.append(record)
        return subprocess.CompletedProcess(command, 0, 'Validated Certificate claims: true', '')
    monkeypatch.setattr(trigger.subprocess, 'run', cli)
    result = trigger.find(repository, record)
    assert result['record_commit'] == record
    assert result['run'] == 388
    assert verified == [record]


def test_signature_failure_never_becomes_a_trigger(recorded, monkeypatch):
    repository, record = recorded
    real_run = subprocess.run
    def cli(command, **kwargs):
        if command[0] == 'gitsign':
            return subprocess.CompletedProcess(command, 1, '', 'wrong certificate identity')
        return real_run(command, **kwargs)
    monkeypatch.setattr(trigger.subprocess, 'run', cli)
    with pytest.raises(ValueError, match='identity-pinned signature'):
        trigger.find(repository, record)


def test_normal_recovery_merge_does_not_hide_an_earlier_qualifying_clock(tmp_path, monkeypatch):
    repository = tmp_path / 'recovered-hub'
    repository.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repository), *args], text=True).strip()
    git('init', '-q', '-b', 'main')
    git('config', 'user.name', 'truth')
    git('config', 'user.email', 'truth@users.noreply.github.com')
    capture = repository / 'talk/captures' / trigger.CAPTURE
    capture.parent.mkdir(parents=True)
    capture.write_text('SKIP: no cluster\n')
    log = repository / 'talk/truth.log'
    log.write_text('')
    git('add', 'talk')
    git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'original source')
    git('checkout', '-qb', 'original-clock')
    capture.write_text('PASS: observed signed-source reconciliation\n')
    log.write_text('TRUTH 2026-10-03T12:00Z run=388 hub=aaaaaaa units=[p=1] pass=1 fail=0 skip=0 excluded=0 total=1 ceiling=1\n')
    git('add', 'talk')
    git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'truth: record run 388')
    original = git('rev-parse', 'HEAD')
    git('checkout', '-q', 'main')
    (repository / 'source.txt').write_text('new source\n')
    git('add', '.')
    git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'new source')
    git('-c', 'commit.gpgsign=false', 'merge', '--no-ff', '--no-commit', 'original-clock')
    # Recovery preserves the original row and object, while its final captures
    # may come from a later SKIP measurement. Default path history hides 388.
    capture.write_text('SKIP: no cluster\n')
    git('add', 'talk')
    git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'Merge original clock; retain the latest capture tree')
    git('update-ref', 'refs/remotes/origin/main', 'HEAD')
    real_run = subprocess.run
    def cli(command, **kwargs):
        if command[0] == 'gitsign':
            assert command[1:3] == ['verify', original]
            return subprocess.CompletedProcess(command, 0, '', '')
        return real_run(command, **kwargs)
    monkeypatch.setattr(trigger.subprocess, 'run', cli)
    result = trigger.find(repository)
    assert result is not None, 'a normal merge hid the genuine qualifying clock'
    assert result['record_commit'] == original


@pytest.mark.parametrize('capture', ['SKIP: no cluster\n', 'PASS: fixture replay\n'])
def test_non_observations_do_not_reach_verifier(recorded, monkeypatch, capture):
    repository, record = recorded
    real_run = subprocess.run
    def cli(command, **kwargs):
        assert command[0] != 'gitsign'
        return real_run(command, **kwargs)
    monkeypatch.setattr(trigger.subprocess, 'run', cli)
    path = repository / 'talk/captures' / trigger.CAPTURE
    path.write_text(capture)
    subprocess.run(['git', '-C', str(repository), 'add', 'talk'], check=True)
    subprocess.run(['git', '-C', str(repository), '-c', 'commit.gpgsign=false', 'commit', '-qm', 'truth: record run 389'], check=True)
    record = subprocess.check_output(['git', '-C', str(repository), 'rev-parse', 'HEAD'], text=True).strip()
    subprocess.run(['git', '-C', str(repository), 'update-ref', 'refs/remotes/origin/main', record], check=True)
    assert trigger.find(repository, record) is None
