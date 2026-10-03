#!/usr/bin/env python3
"""Native digest-pinned image inventory and bounded PR proposer (ADR-0035).

scan is read-only and writes its requested output. propose writes a single
signed dedupe branch and opens/updates its PR; it never merges. All dependencies
run through the independently authenticated platform tools checkout.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
import yaml

HERE = Path(__file__).resolve().parent
PINNED_VERSION = '0.69.3'
INVENTORY_PATH = 'inventory/images.json'
DIGEST = re.compile(r'^.+@sha256:[0-9a-f]{64}$')

class InstrumentFault(ValueError):
    pass

def served_images(adopter: Path, *, repository: Path | None = None) -> list[str]:
    """Read the apps source's exact tag+commit and Kustomization path, never HEAD.

    A checker may archive the declaration tree and explicitly supply its original
    repository for immutable tag objects. A snapshot without that context refuses.
    """
    repository = (repository or adopter).resolve()
    def git(*args: str) -> str:
        try:
            return subprocess.run(['git', '-C', str(repository), *args], check=True,
                                  capture_output=True, text=True, timeout=30).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise InstrumentFault('apps source or pinned tree is unreadable: ' + str(exc)) from exc
    if git('rev-parse', '--show-toplevel') != str(repository):
        raise InstrumentFault('apps source needs its own repository, not an ancestor checkout')
    try:
        declarations = list(yaml.safe_load_all((adopter/'gitops/flux-system/gotk-sync.yaml').read_text()))
        sources = [d for d in declarations if isinstance(d, dict) and d.get('kind') == 'GitRepository']
        if len(sources) != 1:
            raise InstrumentFault('apps source must declare exactly one GitRepository')
        source = sources[0]
        pin = source['spec']['ref']
        tag, commit = pin['tag'], pin['commit']
        if not isinstance(tag, str) or not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise InstrumentFault('apps source must pin a tag and full commit')
        git('check-ref-format', 'refs/tags/'+tag)
        if git('rev-parse', '--verify', 'refs/tags/'+tag+'^{commit}') != commit:
            raise InstrumentFault('apps source tag and commit disagree')
        syncs = [d for d in declarations if isinstance(d, dict) and d.get('kind') == 'Kustomization'
                 and d.get('spec', {}).get('sourceRef', {}).get('name') == source['metadata']['name']
                 and d.get('spec', {}).get('sourceRef', {}).get('kind', 'GitRepository') == 'GitRepository']
        if len(syncs) != 1:
            raise InstrumentFault('apps source must have exactly one matching Kustomization')
        root = syncs[0]['spec']['path']
        if not isinstance(root, str) or root.startswith('/') or '..' in root.split('/'):
            raise InstrumentFault('apps source Kustomization path leaves its pinned tree')
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise InstrumentFault('apps source pin or Kustomization is unreadable: ' + str(exc)) from exc
    images: set[str] = set()
    seen: set[str] = set()
    def containers(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ('containers', 'initContainers', 'ephemeralContainers'):
                    if not isinstance(value, list):
                        raise InstrumentFault('served container list is malformed')
                    for container in value:
                        image = container.get('image') if isinstance(container, dict) else None
                        if not isinstance(image, str) or not DIGEST.fullmatch(image):
                            raise InstrumentFault('every served image must be pinned by sha256 digest: ' + str(image))
                        images.add(image)
                else:
                    containers(value)
        elif isinstance(node, list):
            for item in node:
                containers(item)
    def visit(target: str) -> None:
        target = posixpath.normpath(target)
        if target.startswith('/') or target == '..' or target.startswith('../'):
            raise InstrumentFault('apps resource leaves its pinned tree')
        if target in seen:
            return
        seen.add(target)
        if git('cat-file', '-t', commit+':'+target) == 'tree':
            target = posixpath.join(target, 'kustomization.yaml')
        entry = git('ls-tree', commit, '--', target)
        if not entry.startswith(('100644 blob ', '100755 blob ')):
            raise InstrumentFault('apps resource is not a pinned manifest file: ' + target)
        for doc in yaml.safe_load_all(git('show', commit+':'+target)):
            if not isinstance(doc, dict):
                continue
            if doc.get('kind') == 'Kustomization' and 'resources' in doc:
                if any(key in doc for key in ('images', 'patches', 'patchesStrategicMerge', 'replacements')):
                    raise InstrumentFault('served image transforms require rendered inventory input; refusing an unrendered guess')
                for entry in doc['resources']:
                    if not isinstance(entry, str):
                        raise InstrumentFault('apps resource path is malformed')
                    visit(posixpath.join(posixpath.dirname(target), entry))
            else:
                containers(doc)
    visit(root)
    if not images:
        raise InstrumentFault('served manifests name no image to scan')
    return sorted(images)

def trim(image: str, report: dict, version: dict) -> dict:
    if str(version.get('Version')) != PINNED_VERSION:
        raise InstrumentFault('scanner version differs from pinned Trivy ' + PINNED_VERSION)
    database = (version.get('VulnerabilityDB') or {}).get('UpdatedAt')
    if not database:
        raise InstrumentFault('Trivy reports no vulnerability database date')
    observed = (report.get('Metadata') or {}).get('RepoDigests') or []
    expected = image.split('@')[-1]
    if observed and not any(str(item).endswith('@' + expected) for item in observed):
        raise InstrumentFault('Trivy scanned a digest different from the requested image')
    rows: dict[tuple[str, ...], dict] = {}
    for result in report.get('Results') or []:
        for vulnerability in result.get('Vulnerabilities') or []:
            row = {'id': vulnerability['VulnerabilityID'], 'package': vulnerability['PkgName'],
                   'installed_version': vulnerability['InstalledVersion'],
                   'fixed_version': vulnerability.get('FixedVersion') or '',
                   'severity': vulnerability['Severity']}
            rows[tuple(str(row[key]) for key in row)] = row
    return {'image': image, 'digest': expected, 'scanner_version': PINNED_VERSION,
            'database_date': database, 'vulnerabilities': [rows[key] for key in sorted(rows)]}

def scan(adopter: Path, scanner: str = 'trivy') -> dict:
    rows = []
    for image in served_images(adopter):
        report = subprocess.run([scanner, 'image', '--timeout', '10m', '--scanners', 'vuln',
                                 '--format', 'json', '--quiet', image], capture_output=True, text=True, check=True)
        version = subprocess.run([scanner, 'version', '--format', 'json'], capture_output=True, text=True, check=True)
        rows.append(trim(image, json.loads(report.stdout), json.loads(version.stdout)))
    return {'schema_version': '1.0.0', 'images': rows}

def id_sets(inventory: dict) -> dict[str, list[str]]:
    return {row['image']: sorted({v['id'] for v in row['vulnerabilities']}) for row in inventory.get('images', [])}

def validate(adopter: Path, inventory: dict, *, repository: Path | None = None) -> None:
    sys.path.insert(0, str(HERE.parent / 'feeds'))
    from to_fair_scenario import inventory_ids
    inventory_ids(inventory)
    if sorted(row['image'] for row in inventory['images']) != served_images(adopter, repository=repository):
        raise InstrumentFault('committed inventory does not match every served image digest')

def propose(adopter: Path, candidate: dict, org: str, *, base: str = 'main', repo: str | None = None,
            dry_run: bool = False, prior_proposals: list[dict] | None = None) -> list[dict]:
    sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / 'honesty'))
    import proposer_bounds, rejection_ledger
    committed = adopter / INVENTORY_PATH
    old = json.loads(committed.read_text()) if committed.is_file() else {'images': []}
    if id_sets(old) == id_sets(candidate):
        return []
    shape = {'curve_hash': 'sha256:' + hashlib.sha256(json.dumps(id_sets(candidate), sort_keys=True).encode()).hexdigest(),
             'policy_version': 'inventory-1.0.0'}
    row = {'org': org, 'kind': 'inventory', 'control': 'served-images', 'drift': True,
           'deployed': id_sets(old), 'implied': id_sets(candidate),
           'policy_file': INVENTORY_PATH, 'evidence': 'digest-pinned Trivy ' + PINNED_VERSION + ' scan'}
    key = rejection_ledger.key(org, 'inventory', 'served-images')
    ledger, note = rejection_ledger.derive(repo, {key: shape})
    print(note, file=sys.stderr)
    # This clock shares the existing per-run allowance with tier proposals.
    already = sum(isinstance(p.get('landed'), dict) and p['landed'].get('action') in ('created', 'updated') for p in (prior_proposals or []))
    if already >= proposer_bounds.RATE_LIMIT:
        return [{'proposal_kind': 'inventory', 'held': 'defer-rate-limit', 'key': key}]
    disposition = proposer_bounds.bound([row], ledger)[0]
    p = disposition['proposal']
    if not p:
        return [{'proposal_kind': 'inventory', **disposition}]
    p['proposal_kind'] = 'inventory'
    p['ledger_marker'] = rejection_ledger.marker(key, shape['curve_hash'], shape['policy_version'])
    if dry_run:
        return [{**p, 'landed': 'dry-run'}]
    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(['git', '-C', str(adopter), *args], text=True, capture_output=True, check=True)
    git('checkout', '-B', p['branch'], 'origin/' + base)
    try:
        path = adopter / INVENTORY_PATH; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(candidate, indent=2, sort_keys=True) + '\n')
        # Native composer invocation carries provenance for portable offline replay.
        sys.path.insert(0, str(HERE.parent / 'compose'))
        import composition
        party = yaml.safe_load((adopter / 'party.yaml').read_text())
        document, files = composition.compose(adopter, composition._default_parent_trees(party, adopter.parent))
        if document['outcome'] != 'composed':
            raise InstrumentFault('inventory proposal composition refused: ' + json.dumps(document.get('refusals')))
        for rel, body in files.items():
            out = adopter / rel; out.parent.mkdir(parents=True, exist_ok=True); out.write_text(body)
        git('add', '--', INVENTORY_PATH, 'composed')
        git('commit', '-m', p['title'])
        git('push', '--force-with-lease', 'origin', p['branch'])
        gh = ['gh', 'pr']; repo_args = ['--repo', repo] if repo else []
        listed = subprocess.run(gh + ['list', '--head', p['branch'], '--state', 'open', '--json', 'number', '-q', '.[0].number'] + repo_args, text=True, capture_output=True, check=True)
        number = listed.stdout.strip()
        body = 'Updates only the digest-pinned served image inventory when an image CVE id set changes. Scanner/database metadata changes alone open no PR. Carries the composed re-render through the independently pinned, verified platform tools tag. Human review and the ordinary compose gate remain required.\n\n' + p['ledger_marker']
        with tempfile.NamedTemporaryFile('w', suffix='.md') as fh:
            fh.write(body); fh.flush()
            args = ['edit', number] if number else ['create', '--head', p['branch'], '--base', base]
            result = subprocess.run(gh + args + ['--title', p['title'], '--body-file', fh.name] + repo_args, text=True, capture_output=True, check=True)
        return [{**p, 'landed': {'action': 'updated' if number else 'created', 'number': number, 'url': result.stdout.strip()}}]
    finally:
        git('checkout', base)

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command', choices=('scan', 'propose', 'check'))
    ap.add_argument('--adopter-dir', type=Path, required=True)
    ap.add_argument('--scanner', default='trivy'); ap.add_argument('--out', type=Path)
    ap.add_argument('--candidate', type=Path); ap.add_argument('--prior-proposals', type=Path)
    ap.add_argument('--org'); ap.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY'))
    ap.add_argument('--base', default='main'); ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()
    try:
        if args.command == 'check':
            validate(args.adopter_dir, json.loads((args.adopter_dir / INVENTORY_PATH).read_text())); print('PASS: inventory matches all served image digests'); return 0
        if args.command == 'scan':
            output = scan(args.adopter_dir, args.scanner)
        else:
            if not args.candidate or not args.org:
                ap.error('propose requires --candidate and --org')
            output = propose(args.adopter_dir, json.loads(args.candidate.read_text()), args.org,
                             base=args.base, repo=args.repo, dry_run=args.dry_run,
                             prior_proposals=json.loads(args.prior_proposals.read_text()) if args.prior_proposals else [])
        text = json.dumps(output, indent=2, sort_keys=True) + '\n'
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True); args.out.write_text(text)
        else:
            print(text, end='')
        return 0
    except (InstrumentFault, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('missing instrument: inventory: ' + str(exc), file=sys.stderr); return 2

if __name__ == '__main__':
    raise SystemExit(main())
