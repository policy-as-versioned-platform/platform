"""Explicit synthetic apps/inventory closure for composition tests, never scan evidence."""
import json
from pathlib import Path
import subprocess

import yaml


def commit_fixture_state(adopter: Path, message: str) -> None:
    """Record a disposable test fixture, without creating signed evidence."""
    command=['git','-C',str(adopter),'-c','core.hooksPath=/dev/null',
             '-c','commit.gpgsign=false','-c','user.name=Declared inventory fixture',
             '-c','user.email=fixture@example.invalid']
    subprocess.run([*command,'add','.'],check=True,capture_output=True)
    if subprocess.run([*command,'diff','--cached','--quiet']).returncode:
        subprocess.run([*command,'commit','-qm',message],check=True,capture_output=True)


def write_inventory_fixture(adopter: Path, identifiers: list[str]) -> None:
    """Pin one fixture image through an actual temporary Git apps graph."""
    image = 'example.invalid/declared-fixture@sha256:' + 'a' * 64
    apps = adopter / 'gitops/apps'
    apps.mkdir(parents=True, exist_ok=True)
    (apps/'inventory-fixture.yaml').write_text(yaml.safe_dump({
        'apiVersion':'v1','kind':'Pod','metadata':{'name':'inventory-fixture'},
        'spec':{'containers':[{'name':'fixture','image':image}]},
    }))
    (apps/'kustomization.yaml').write_text('kind: Kustomization\nresources: [inventory-fixture.yaml]\n')
    def git(*args):
        return subprocess.check_output(['git','-C',str(adopter),
            '-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false','-c','tag.gpgsign=false',
            '-c','user.name=Declared inventory fixture','-c','user.email=fixture@example.invalid',*args],
            stderr=subprocess.PIPE,text=True).strip()
    git('init','-q')
    git('add','.')
    git('commit','-qm','Declared synthetic inventory fixture; no real scan or signature')
    commit=git('rev-parse','HEAD')
    git('tag','fixture-apps-v1')
    source=adopter/'gitops/flux-system/gotk-sync.yaml'
    source.parent.mkdir(parents=True,exist_ok=True)
    source.write_text(yaml.safe_dump_all([
        {'kind':'GitRepository','metadata':{'name':'fixture-apps'},
         'spec':{'ref':{'tag':'fixture-apps-v1','commit':commit}}},
        {'kind':'Kustomization','spec':{'sourceRef':{'kind':'GitRepository','name':'fixture-apps'},'path':'./gitops/apps'}},
    ]))
    inventory=adopter/'inventory/images.json'
    inventory.parent.mkdir(parents=True,exist_ok=True)
    inventory.write_text(json.dumps({'schema_version':'1.0.0','images':[{
        'image':image,'digest':'sha256:'+'a'*64,'scanner_version':'declared synthetic fixture, not Trivy observation',
        'database_date':'2026-01-01T00:00:00Z','vulnerabilities':[
            {'id':identifier,'package':'fixture','installed_version':'fixture','fixed_version':'',
             'severity':'HIGH'} for identifier in identifiers],
    }]},indent=2)+'\n')
