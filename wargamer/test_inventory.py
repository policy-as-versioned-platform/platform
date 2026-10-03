"""Public scan/proposal seams refuse unknown images and ignore metadata-only moves."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import pytest
import yaml
SPEC = importlib.util.spec_from_file_location('inventory', Path(__file__).with_name('inventory.py'))
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)

def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false',
                           '-c', 'core.hooksPath=/dev/null',
                           '-c', 'user.name=Inventory fixture', '-c', 'user.email=inventory@example.invalid',
                           *args], check=True, capture_output=True, text=True).stdout.strip()

def pin(repo, tag, commit, path='gitops/apps'):
    source = repo/'gitops/flux-system/gotk-sync.yaml'
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(yaml.safe_dump_all([
        {'kind': 'GitRepository', 'metadata': {'name': 'fixture'},
         'spec': {'ref': {'tag': tag, 'commit': commit}}},
        {'kind': 'Kustomization', 'spec': {'sourceRef': {'kind': 'GitRepository', 'name': 'fixture'},
                                        'path': './'+path}}]))

def adopter(tmp_path, image, path='gitops/apps'):
    path=tmp_path/path;path.mkdir(parents=True)
    (path/'kustomization.yaml').write_text('kind: Kustomization\nresources: [pods.yaml]\n')
    (path/'pods.yaml').write_text('kind: Pod\nspec:\n  initContainers:\n    - name: init\n      image: '+image+'\n  containers:\n    - name: app\n      image: '+image+'\n')
    git(tmp_path, 'init', '-q')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-qm', 'Declared apps source fixture')
    commit=git(tmp_path, 'rev-parse', 'HEAD')
    git(tmp_path, 'tag', 'v1.0.0')
    pin(tmp_path, 'v1.0.0', commit, str(path.relative_to(tmp_path)))
    return tmp_path

def test_every_container_is_scanned_without_a_policy_label(tmp_path):
    image='example@sha256:'+'a'*64
    assert m.served_images(adopter(tmp_path,image)) == [image]

def test_the_served_tag_rejects_an_unpinned_image(tmp_path):
    adopter(tmp_path, 'nginx')
    with pytest.raises(m.InstrumentFault,match='digest'):
        m.served_images(tmp_path)

def test_head_cannot_replace_the_digest_at_the_apps_pin(tmp_path):
    served='example@sha256:'+'a'*64
    repo=adopter(tmp_path, served)
    (repo/'gitops/apps/pods.yaml').write_text('kind: Pod\nspec:\n  containers:\n    - name: future\n      image: example@sha256:'+'b'*64+'\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'Candidate images are not served')
    assert m.served_images(repo) == [served]

def test_the_apps_kustomization_declares_the_served_path(tmp_path):
    image='example@sha256:'+'a'*64
    repo=adopter(tmp_path, image, path='deployments/actual-apps')
    shadow=repo/'gitops/apps';shadow.mkdir()
    (shadow/'kustomization.yaml').write_text('kind: Kustomization\nresources: [unserved.yaml]\n')
    (shadow/'unserved.yaml').write_text('kind: Pod\nspec:\n  containers: [{name: ignored, image: nginx}]\n')
    assert m.served_images(repo) == [image]

@pytest.mark.parametrize('fault', ['missing-tag', 'mismatched-commit', 'missing-commit', 'unsafe-path'])
def test_unreadable_or_inconsistent_apps_pins_refuse(tmp_path, fault):
    repo=adopter(tmp_path, 'example@sha256:'+'a'*64)
    commit=git(repo, 'rev-parse', 'HEAD')
    if fault=='missing-tag':
        git(repo, 'tag', '-d', 'v1.0.0')
    elif fault=='mismatched-commit':
        pin(repo, 'v1.0.0', 'b'*40)
    elif fault=='missing-commit':
        pin(repo, 'v1.0.0', '')
    else:
        pin(repo, 'v1.0.0', commit, '../outside')
    with pytest.raises(m.InstrumentFault, match='apps'):
        m.served_images(repo)

def test_checker_snapshot_needs_explicit_pinned_repository_objects(tmp_path):
    image='example@sha256:'+'a'*64
    repo=adopter(tmp_path/'repo', image)
    snapshot=tmp_path/'snapshot'
    shutil.copytree(repo, snapshot, ignore=shutil.ignore_patterns('.git'))
    assert m.served_images(snapshot, repository=repo) == [image]
    with pytest.raises(m.InstrumentFault, match='apps'):
        m.served_images(snapshot)

def test_trim_records_database_and_sorted_findings_and_refuses_wrong_scanner():
    image='example@sha256:'+'a'*64
    report={'Metadata':{'RepoDigests':[image]},'Results':[{'Vulnerabilities':[{'VulnerabilityID':'CVE-B','PkgName':'b','InstalledVersion':'1','Severity':'HIGH'}, {'VulnerabilityID':'CVE-A','PkgName':'a','InstalledVersion':'1','FixedVersion':'2','Severity':'LOW'}]}]}
    version={'Version':'0.69.3','VulnerabilityDB':{'UpdatedAt':'2026-10-03T00:00:00Z'}}
    got=m.trim(image,report,version)
    assert [v['id'] for v in got['vulnerabilities']] == ['CVE-A','CVE-B']
    assert got['digest']==image.split('@')[1] and got['database_date']==version['VulnerabilityDB']['UpdatedAt']
    with pytest.raises(m.InstrumentFault,match='version'):
        m.trim(image,report,{**version,'Version':'latest'})
    with pytest.raises(m.InstrumentFault,match='digest'):
        m.trim(image,{**report,'Metadata':{'RepoDigests':['example@sha256:'+'b'*64]}},version)

def test_metadata_only_scan_opens_no_proposal(tmp_path):
    old={'schema_version':'1.0.0','images':[{'image':'example@sha256:'+'a'*64,'database_date':'yesterday','vulnerabilities':[{'id':'CVE-A'}]}]}
    path=tmp_path/'inventory';path.mkdir();(path/'images.json').write_text(json.dumps(old))
    newer={**old,'images':[{**old['images'][0],'database_date':'today','scanner_version':'updated'}]}
    assert m.propose(tmp_path,newer,'fixture',dry_run=True)==[]

def test_inventory_uses_proposer_key_and_rejection_bounds(tmp_path, monkeypatch):
    sys.path.insert(0,str(Path(__file__).parents[1]/'honesty'));sys.path.insert(0,str(Path(__file__).parent))
    import rejection_ledger
    candidate={'images':[{'image':'example@sha256:'+'a'*64,'vulnerabilities':[{'id':'CVE-A'}]}]}
    monkeypatch.setattr(rejection_ledger,'derive',lambda repo,today: ({'reject_suppress':1,'rejections':{'fixture/inventory/served-images':{'count':1}}},'derived fixture'))
    got=m.propose(tmp_path,candidate,'fixture',dry_run=True)
    assert got[0]['disposition']=='suppress-learned-rejection'
    monkeypatch.setattr(rejection_ledger,'derive',lambda repo,today: ({'rejections':{}},'derived fixture'))
    got=m.propose(tmp_path,candidate,'fixture',dry_run=True)
    assert got[0]['branch']=='wargamer/retune-fixture-served-images' and got[0]['merged'] is False
    assert 'key="fixture/inventory/served-images"' in got[0]['ledger_marker']
