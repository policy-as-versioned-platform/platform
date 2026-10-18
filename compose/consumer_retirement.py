"""Explicit consumer retirement: one strict reader for composition and reviewed admission.

No record means the complete publisher window. An explicit record must prove a real,
landed scheduled baseline before it can remove any body. External readers are private
seams; production uses real Git, gitsign and read-only official GitHub endpoints.
"""
from __future__ import annotations

import argparse
import base64
from collections.abc import Callable, Mapping
from datetime import date
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any
from urllib.parse import quote
import urllib.error
import urllib.request

import yaml

DIRECTORY = 'implementation-retirements'
SHA = re.compile(r'[0-9a-f]{40}')
DIGEST = re.compile(r'[0-9a-f]{64}')
VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+')
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
LANE = {'drift/samples.jsonl': ('flux.five-facts/v1', 3),
        'drift/workload-samples.jsonl': ('flux.served-workloads/v1', 1),
        'drift/oscal-samples.jsonl': ('flux.oscal-lane/v1', 1)}
ENGINE_FILE = 'gitops/engine/kyverno.yaml'
ISSUER = 'https://token.actions.githubusercontent.com'


class InvalidRetirement(ValueError):
    """An explicit record could not establish its exact authority or measured inputs."""


class _UniqueLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader: _UniqueLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise InvalidRetirement('retirement mapping keys must be unique strings')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _command(args: list[str], root: Path | None = None, **kwargs: Any) -> bytes:
    try:
        result = subprocess.run(args, cwd=root, capture_output=True, check=True,
                                timeout=60, **kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        # Tool stderr can contain credentials or arbitrary remote text. Name the
        # missing instrument without copying it into a signed artefact or CI log.
        raise InvalidRetirement(f'{args[0]} could not verify the consumer-retirement input') from exc
    return result.stdout


def _git(root: Path, *args: str) -> bytes:
    return _command(['git', '-C', str(root), *args])


def _show(root: Path, ref: str, path: str, *, absent: bool = False) -> bytes:
    try:
        return _git(root, 'show', f'{ref}:{path}')
    except InvalidRetirement:
        if absent and not _git(root, 'ls-tree', ref, '--', path).strip():
            return b''
        raise


class _NoOfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: urllib.request.Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


def _official(path: str) -> dict:
    try:
        try:
            data = _command(['gh', 'api', '--method', 'GET', path])
        except InvalidRetirement as exc:
            cause = exc.__cause__
            if not isinstance(cause, subprocess.CalledProcessError) or cause.returncode != 4:
                raise
            # gh requires authentication even for public reads. The gate holds no
            # credential; only this named auth refusal uses the public API directly.
            request = urllib.request.Request('https://api.github.com/' + path, method='GET', headers={
                'Accept': 'application/vnd.github+json',
                'User-Agent': 'policy-as-versioned-platform',
                'X-GitHub-Api-Version': '2022-11-28',
            })
            with urllib.request.build_opener(_NoOfficialRedirect()).open(request, timeout=60) as response:
                if response.status != 200:
                    raise ValueError('official public GET did not return HTTP 200')
                data = response.read()
        value = json.loads(data)
    except (OSError, HTTPException, ValueError, InvalidRetirement) as exc:
        if isinstance(exc, urllib.error.HTTPError):
            exc.close()
        raise InvalidRetirement(f'official GitHub GET unavailable for {path}') from exc
    if not isinstance(value, dict):
        raise InvalidRetirement(f'official GitHub GET returned no object for {path}')
    return value


def _signature(root: Path, commit: str, repository: str, source: str, branch: str) -> None:
    identity = f'https://github.com/{repository}/.github/workflows/drift-sample.yml@refs/heads/{branch}'
    _command(['gitsign', 'verify', commit,
              '--certificate-identity=' + identity,
              '--certificate-oidc-issuer=' + ISSUER,
              '--certificate-github-workflow-sha=' + source,
              '--certificate-github-workflow-repository=' + repository,
              '--certificate-github-workflow-ref=refs/heads/' + branch,
              '--certificate-github-workflow-trigger=schedule'], root,
             env=dict(os.environ, GITSIGN_REKOR_MODE='offline'))


def _tag_signature(root: Path, tag: str, repository: str) -> None:
    certificate = (f'^https://github\\.com/{re.escape(repository)}/\\.github/workflows/'
                   'cut-release\\.yml@refs/heads/(main|release/[0-9]+\\.[0-9]+\\.x)$')
    _command(['gitsign', 'verify-tag', tag, '--certificate-identity-regexp=' + certificate,
              '--certificate-oidc-issuer=' + ISSUER], root,
             env=dict(os.environ, GITSIGN_REKOR_MODE='offline'))


def _object(value: Any, keys: set[str], where: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise InvalidRetirement(f'{where} requires exactly {sorted(keys)}')
    return value


def _text(value: Any, where: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value.strip() or (pattern and not pattern.fullmatch(value)):
        raise InvalidRetirement(f'{where} is missing or malformed')
    return value


def _versions(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not value or any(
            not isinstance(v, str) or not VERSION.fullmatch(v) for v in value):
        raise InvalidRetirement(f'{where} must name exact nonempty policy versions')
    if len(set(value)) != len(value) or sorted(value) != value:
        raise InvalidRetirement(f'{where} must be sorted and unique')
    return value


def read_records(adopter: Path, publishers: set[str]) -> dict[str, dict]:
    """Read the closed record set. Nothing explicit may be silently ignored."""
    directory = adopter / DIRECTORY
    if not directory.exists():
        return {}
    if directory.is_symlink() or not directory.is_dir():
        raise InvalidRetirement(f'{DIRECTORY} must be a regular directory')
    result = {}
    for path in sorted(directory.iterdir()):
        if path.name == 'README.md' and path.is_file() and not path.is_symlink():
            continue
        if path.suffix != '.yaml' or path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise InvalidRetirement(f'{DIRECTORY} contains an unexpected or nonregular record')
        try:
            record = yaml.load(path.read_text(), Loader=_UniqueLoader)
        except InvalidRetirement:
            raise
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise InvalidRetirement(f'{path.name} is not a readable retirement record') from exc
        record = _object(record, {'schema', 'kind', 'party', 'repository', 'publisher', 'parent',
                                   'retired', 'retained', 'engine', 'baseline', 'authorization'}, path.name)
        publisher = _text(record['publisher'], 'publisher')
        if publisher not in publishers or path.name != publisher + '.yaml' or publisher in result:
            raise InvalidRetirement('retirement record does not name one inherited implementation publisher')
        result[publisher] = record
    return result


def _ancestor(root: Path, older: str, newer: str, where: str) -> None:
    try:
        _git(root, 'merge-base', '--is-ancestor', older, newer)
    except InvalidRetirement as exc:
        raise InvalidRetirement(f'{where}: original scheduled baseline is not an ancestor') from exc


def _engine(data: bytes) -> str:
    try:
        declaration = yaml.safe_load(data)
        return _text(declaration['version'], 'declared engine', VERSION)
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise InvalidRetirement('baseline engine declaration is unavailable') from exc


def _default_branch(adopter: Path, repository: str, official: Callable[[str], dict]) -> str:
    metadata = official(f'repos/{repository}')
    if metadata.get('full_name') != repository:
        raise InvalidRetirement('official metadata does not name the exact adopter repository')
    branch = _text(metadata.get('default_branch'), 'actual public default branch')
    try:
        _git(adopter, 'check-ref-format', 'refs/heads/' + branch)
    except InvalidRetirement as error:
        raise InvalidRetirement('actual public default branch is malformed') from error
    return branch


def _baseline(adopter: Path, record: dict, official: Callable[[str], dict],
              verify_signature: Callable[[Path, str, str, str, str], None]) -> dict:
    baseline = _object(record['baseline'], {'original_commit', 'source_commit', 'run_id',
                                           'attempt', 'appends'}, 'baseline')
    original = _text(baseline['original_commit'], 'baseline original commit', SHA)
    source = _text(baseline['source_commit'], 'baseline source commit', SHA)
    run_id, attempt = baseline['run_id'], baseline['attempt']
    if type(run_id) is not int or type(attempt) is not int or run_id < 1 or attempt < 1:
        raise InvalidRetirement('baseline requires positive integer run_id and attempt')
    repository = record['repository']
    branch = _default_branch(adopter, repository, official)
    run = official(f'repos/{repository}/actions/runs/{run_id}/attempts/{attempt}')
    if (run.get('id') != run_id or run.get('run_attempt') != attempt or
            run.get('event') != 'schedule' or run.get('head_branch') != branch or
            run.get('head_sha') != source or run.get('status') != 'completed' or
            run.get('path') != '.github/workflows/drift-sample.yml' or
            (run.get('repository') or {}).get('full_name') != repository):
        raise InvalidRetirement('official attempt is not the exact scheduled default-branch baseline')
    public = official(f'repos/{repository}/compare/{original}...{quote(branch, safe="")}')
    if (public.get('status') not in {'ahead', 'identical'} or
            (public.get('merge_base_commit') or {}).get('sha') != original):
        raise InvalidRetirement('original scheduled baseline is not on the actual public default')
    parent_line = _git(adopter, 'rev-list', '--parents', '-n', '1', original).decode().split()
    if parent_line != [original, source]:
        raise InvalidRetirement('baseline original must retain its one measured-source parent')
    _ancestor(adopter, original, 'HEAD', 'tree under composition')
    if _engine(_show(adopter, source, ENGINE_FILE)) != record['engine']['from']:
        raise InvalidRetirement('baseline source engine does not match the declared transition')
    verify_signature(adopter, original, repository, source, branch)
    appends = _object(baseline['appends'], set(LANE), 'baseline appends')
    paths = _git(adopter, 'diff-tree', '--no-commit-id', '--name-only', '-r', original).decode().splitlines()
    if set(paths) != set(LANE):
        raise InvalidRetirement('baseline original changed paths outside its exact observation lane')
    for path, (kind, count) in LANE.items():
        digest = _text(appends[path], 'baseline append digest', DIGEST)
        mode = _git(adopter, 'ls-tree', original, '--', path).decode().split()[0]
        if mode != '100644':
            raise InvalidRetirement('baseline lane contains a nonregular file')
        before = _show(adopter, source, path, absent=True)
        after = _show(adopter, original, path)
        if not after.startswith(before) or (before and not before.endswith(b'\n')):
            raise InvalidRetirement('baseline original rewrote its observation prefix')
        delta = after[len(before):]
        if not delta.endswith(b'\n') or hashlib.sha256(delta).hexdigest() != digest:
            raise InvalidRetirement('baseline append bytes differ from the recorded exact digest')
        lines = delta.splitlines(keepends=True)
        if len(lines) != count:
            raise InvalidRetirement('baseline append has the wrong number of observations')
        current_path = adopter / path
        if current_path.is_symlink() or not current_path.is_file():
            raise InvalidRetirement('baseline lane is missing or nonregular in the current tree')
        current = current_path.read_bytes()
        current_lines = current.splitlines(keepends=True)
        if not current.startswith(before) or current.count(delta) != 1 or any(current_lines.count(line) != 1 for line in lines):
            raise InvalidRetirement('baseline observation bytes were changed, removed or duplicated')
        committed = _show(adopter, 'HEAD', path)
        if committed != current:
            raise InvalidRetirement('baseline lane bytes differ from committed history')
        for line in lines:
            number = current_lines.index(line) + 1
            attribution = _git(adopter, 'blame', '--line-porcelain', '-L', f'{number},{number}',
                               'HEAD', '--', path).decode().splitlines()[0].split()[0]
            if attribution.lstrip('^') != original:
                raise InvalidRetirement('baseline row is not attributed to its original signed clock commit')
        for line in lines:
            try:
                row = json.loads(line)
            except (ValueError, TypeError) as exc:
                raise InvalidRetirement('baseline append is not JSONL') from exc
            if not isinstance(row, dict) or (row.get('kind'), row.get('event'), str(row.get('run'))) != (
                    kind, 'schedule', str(run_id)):
                raise InvalidRetirement('baseline observation does not belong to the scheduled attempt')
            if path == 'drift/oscal-samples.jsonl' and (
                    row.get('status') != 'observed' or type(row.get('report_count')) is not int or
                    row['report_count'] < 1 or row.get('report_read_errors') != [] or
                    not isinstance(row.get('assessment_results'), dict) or not row['assessment_results']):
                raise InvalidRetirement('scheduled baseline did not capture usable PolicyReports')
    return dict(baseline)


def _support(declaration: Any, engines: set[str], where: str) -> None:
    if not isinstance(declaration, dict) or declaration.get('scope') != 'every-served-body-v1' or not engines.issubset(
            set(declaration.get('kyverno') or [])):
        raise InvalidRetirement(f'{where} does not declare measured support for both transition engines')


def select(adopter: Path, record: dict, party: str, publisher: str, parent_version: str,
           parent_sha: str, parent_root: Path, versions: list[str], *,
           official: Callable[[str], dict] = _official,
           verify_signature: Callable[[Path, str, str, str, str], None] = _signature,
           verify_tag: Callable[[Path, str, str], None] = _tag_signature) -> dict:
    """Validate one explicit selection and return its immutable evidence, or refuse.

    This same function is used by composition and adopter admission. The engine move
    itself is checked separately by require_delivered() after the retirement is enacted.
    """
    _object(record, {'schema', 'kind', 'party', 'repository', 'publisher', 'parent', 'retired',
                     'retained', 'engine', 'baseline', 'authorization'}, 'consumer retirement')
    if type(record.get('schema')) is not int or record['schema'] != 1 or record.get('kind') != 'consumer-retirement':
        raise InvalidRetirement('unknown consumer-retirement schema or kind')
    if record['party'] != party or record['publisher'] != publisher:
        raise InvalidRetirement('consumer retirement names another party or publisher')
    repository = _text(record['repository'], 'retirement repository', REPOSITORY)
    remote = _git(adopter, 'remote', 'get-url', 'origin').decode().strip()
    normalized = remote.removesuffix('.git').replace('git@github.com:', 'https://github.com/')
    if normalized != 'https://github.com/' + repository:
        raise InvalidRetirement('retirement repository differs from the adopter Git remote')
    parent = _object(record['parent'], {'version', 'tag', 'commit', 'window'}, 'retirement parent')
    _text(parent['commit'], 'implementation parent commit', SHA)
    if parent['version'] != str(parent_version) or parent['commit'] != parent_sha:
        raise InvalidRetirement('retirement is bound to another implementation parent')
    _text(parent['tag'], 'implementation parent tag')
    publisher_remote = _git(parent_root, 'remote', 'get-url', 'origin').decode().strip().removesuffix('.git')
    if not publisher_remote.startswith('https://github.com/'):
        raise InvalidRetirement('implementation parent requires its canonical public GitHub remote')
    pins = []
    for pin_path in sorted((adopter / 'gitops').rglob('*.yaml')):
        for document in yaml.safe_load_all(pin_path.read_text()):
            if (isinstance(document, dict) and document.get('kind') == 'GitRepository' and
                    document.get('spec', {}).get('url', '').removesuffix('.git') == publisher_remote):
                pins.append(document['spec'].get('ref'))
    if pins != [{'tag': parent['tag'], 'commit': parent_sha}]:
        raise InvalidRetirement('retirement differs from the exact implementation GitRepository pin')
    if _git(parent_root, 'rev-parse', '--verify', 'refs/tags/' + parent['tag'] + '^{commit}').decode().strip() != parent_sha:
        raise InvalidRetirement('retirement parent tag differs from the exact parent SHA')
    if (_git(parent_root, 'rev-parse', 'HEAD').decode().strip() != parent_sha or
            _git(parent_root, 'status', '--porcelain', '--untracked-files=all').strip()):
        raise InvalidRetirement('consumer retirement requires the unchanged pinned implementation tree')
    verify_tag(parent_root, parent['tag'], publisher_remote.removeprefix('https://github.com/'))
    before = _versions(parent['window'], 'parent window')
    retired = _versions(record['retired'], 'retired window')
    retained = _versions(record['retained'], 'retained window')
    if before != sorted(versions) or set(retired) & set(retained) or sorted(retired + retained) != before:
        raise InvalidRetirement('retirement must partition the exact complete implementation window')
    transition = _object(record['engine'], {'from', 'to'}, 'engine transition')
    old_engine = _text(transition['from'], 'baseline engine', VERSION)
    new_engine = _text(transition['to'], 'planned engine', VERSION)
    if old_engine == new_engine:
        raise InvalidRetirement('retirement requires a distinct measured engine transition')
    current_engine = _engine((adopter / ENGINE_FILE).read_bytes())
    if current_engine not in {old_engine, new_engine}:
        raise InvalidRetirement('current engine differs from the explicit transition')
    array = yaml.safe_load((parent_root / 'distribution/versions.yaml').read_text())['spec']['inputs'][0]['versions']
    by_version = {str(row['version']): row for row in array}
    for version in retained:
        _support(by_version[version].get('tested_engines'), {old_engine, new_engine}, 'retained policy ' + version)
    machinery = yaml.safe_load((parent_root / 'distribution/machinery.yaml').read_text())
    _support(machinery.get('tested_engines'), {old_engine, new_engine}, 'retained machinery')
    authorization = _object(record['authorization'], {'decided_by', 'decided_on', 'basis'}, 'retirement authorization')
    _text(authorization['decided_by'], 'retirement decision author')
    _text(authorization['basis'], 'retirement decision basis')
    try:
        date.fromisoformat(_text(authorization['decided_on'], 'retirement decision date'))
    except ValueError as exc:
        raise InvalidRetirement('retirement decision date is not an ISO date') from exc
    baseline = _baseline(adopter, record, official, verify_signature)
    return dict(record, baseline=baseline)


def require_claims(retirement: dict, documents: list[dict]) -> None:
    """Versioned workload declarations cannot keep a claim that the decision removes."""
    retained = set(retirement['retained'])
    def walk(value: Any) -> None:
        if isinstance(value, dict):
            labels = (value.get('metadata') or {}).get('labels') or {}
            claim = labels.get('policy-as-versioned.dev/policy-version')
            if claim is not None and str(claim) not in retained:
                raise InvalidRetirement('a served workload still claims a version outside the retained window')
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    for document in documents:
        walk(document)


def require_delivered(adopter: Path, retirement: dict, *, official: Callable[[str], dict] = _official) -> None:
    """Moving the engine requires this exact decision already landed and signed delivery selected."""
    if _engine((adopter / ENGINE_FILE).read_bytes()) != retirement['engine']['to']:
        return
    repository = retirement['repository']
    branch = _default_branch(adopter, repository, official)
    query = '?ref=' + quote(branch, safe='')
    response = official(f'repos/{repository}/contents/{DIRECTORY}/{retirement["publisher"]}.yaml{query}')
    try:
        public_record = yaml.safe_load(base64.b64decode(response['content']))
    except (KeyError, ValueError, yaml.YAMLError) as exc:
        raise InvalidRetirement('engine move requires the exact retirement decision already on public default') from exc
    if public_record != retirement:
        raise InvalidRetirement('engine move cannot introduce or change the retirement decision')
    public_engine_response = official(f'repos/{repository}/contents/{ENGINE_FILE}{query}')
    try:
        public_engine = _engine(base64.b64decode(public_engine_response['content']))
    except (KeyError, ValueError) as exc:
        raise InvalidRetirement('engine transition requires the actual public default declaration') from exc
    if public_engine not in set(retirement['engine'].values()):
        raise InvalidRetirement('public default engine differs from the authorized transition')
    source_docs = list(yaml.safe_load_all((adopter / 'gitops/composed/composed-set.yaml').read_text()))
    source = next((doc for doc in source_docs if isinstance(doc, dict) and doc.get('kind') == 'GitRepository'), {})
    ref = source.get('spec', {}).get('ref', {})
    tag, commit = ref.get('tag'), ref.get('commit')
    _text(commit, 'delivered composition commit', SHA)
    _text(tag, 'delivered composition tag')
    public_source = official(f'repos/{repository}/contents/gitops/composed/composed-set.yaml{query}')
    try:
        public_documents = list(yaml.safe_load_all(base64.b64decode(public_source['content'])))
        public_pin = next(doc['spec']['ref'] for doc in public_documents
                          if isinstance(doc, dict) and doc.get('kind') == 'GitRepository')
    except (KeyError, ValueError, StopIteration, yaml.YAMLError) as exc:
        raise InvalidRetirement('engine move requires the signed composition pointer already on public default') from exc
    if public_engine == retirement['engine']['from'] and public_pin != ref:
        raise InvalidRetirement('engine move cannot introduce the retirement delivery pointer')
    if _git(adopter, 'rev-parse', '--verify', f'refs/tags/{tag}^{{commit}}').decode().strip() != commit:
        raise InvalidRetirement('engine move requires the exact published composition tag and SHA')
    _tag_signature(adopter, tag, repository)
    try:
        evidence = json.loads(_show(adopter, commit, 'composed/evidence.json'))
        window = sorted({str(member['version']) for member in evidence['members'] if member.get('version')})
    except (ValueError, KeyError, TypeError) as exc:
        raise InvalidRetirement('delivered composition does not carry a readable retained window') from exc
    if window != retirement['retained'] or evidence.get('consumer_retirements') != [retirement]:
        raise InvalidRetirement('engine move requires the signed composition of this exact retirement')
    if public_engine == retirement['engine']['from'] and (
            _engine(_show(adopter, commit, ENGINE_FILE)) != retirement['engine']['from'] or
            (evidence.get('engine', {}).get('declared') or {}).get('version') != retirement['engine']['from']):
        raise InvalidRetirement('first engine move requires retirement delivered on the baseline engine')


def admit(adopter: Path, parent_root: Path, base_ref: str, head_ref: str, *,
          official: Callable[[str], dict] = _official,
          verify_signature: Callable[[Path, str, str, str, str], None] = _signature,
          verify_tag: Callable[[Path, str, str], None] = _tag_signature) -> dict:
    """Exact retirement admission beside the adopter's unchanged computed major."""
    if _git(adopter, 'rev-parse', head_ref + '^{commit}') != _git(adopter, 'rev-parse', 'HEAD'):
        raise InvalidRetirement('retirement admission requires the exact reviewed head checkout')
    if _git(adopter, 'status', '--porcelain', '--untracked-files=all').strip():
        raise InvalidRetirement('retirement admission requires the unchanged reviewed source tree')
    party = yaml.safe_load((adopter / 'party.yaml').read_text())
    edges = [edge for edge in party.get('inherits', []) if edge.get('kind') == 'implementations']
    records = read_records(adopter, {edge['party'] for edge in edges})
    if len(records) != 1:
        raise InvalidRetirement('one reviewed consumer retirement must name exactly one publisher')
    publisher, record = next(iter(records.items()))
    edge = next(edge for edge in edges if edge['party'] == publisher)
    parent_sha = record['parent']['commit']
    array = yaml.safe_load((parent_root / 'distribution/versions.yaml').read_text())['spec']['inputs'][0]['versions']
    validated = select(adopter, record, party['party'], publisher, str(edge['version']),
                       parent_sha, parent_root, sorted(str(row['version']) for row in array),
                       official=official, verify_signature=verify_signature, verify_tag=verify_tag)
    before = json.loads(_show(adopter, base_ref, 'composed/evidence.json'))
    after = json.loads(_show(adopter, head_ref, 'composed/evidence.json'))
    def window(evidence: dict) -> list[str]:
        return sorted({str(member['version']) for member in evidence['members'] if member.get('version')})
    if window(before) != validated['parent']['window'] or window(after) != validated['retained']:
        raise InvalidRetirement('admission does not match the exact before/after composed windows')
    if after.get('consumer_retirements') != [validated]:
        raise InvalidRetirement('composition evidence omits or changes the validated retirement decision')
    if _engine(_show(adopter, base_ref, ENGINE_FILE)) != validated['engine']['from'] or (
            _engine(_show(adopter, head_ref, ENGINE_FILE)) != validated['engine']['from']):
        raise InvalidRetirement('retirement must land while still declaring the baseline engine')
    before_parent = next(parent for parent in before['parents']
                         if parent.get('party') == publisher and parent.get('kind') == 'implementations')
    if before_parent.get('sha') != parent_sha or before_parent.get('version') != validated['parent']['version']:
        raise InvalidRetirement('a retirement decision cannot silently move its implementation parent')
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location('_retirement_admission_apps', Path(__file__).resolve().parents[1] / 'wargamer/inventory.py')
    if spec is None or spec.loader is None:
        raise InvalidRetirement('immutable apps reader is unavailable')
    reader = module_from_spec(spec)
    spec.loader.exec_module(reader)
    require_claims(validated, reader.served_documents(adopter, strict_claims=True))
    return {'admitted': True, 'bump': 'major', 'retired': validated['retired'],
            'retained': validated['retained'], 'publisher': publisher}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['admit'])
    parser.add_argument('--adopter-dir', required=True, type=Path)
    parser.add_argument('--parent-dir', required=True, type=Path)
    parser.add_argument('--base-ref', required=True)
    parser.add_argument('--head-ref', required=True)
    args = parser.parse_args()
    try:
        result = admit(args.adopter_dir, args.parent_dir, args.base_ref, args.head_ref)
    except (OSError, ValueError, KeyError, TypeError, StopIteration, yaml.YAMLError) as error:
        print(json.dumps({'admitted': False, 'reason': str(error)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
