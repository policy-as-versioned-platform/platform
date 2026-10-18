"""Source-bound technical condition assessment; never billing or claim payability."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Callable
from uuid import UUID

import yaml

import consumer_retirement as clock


SELECTOR = 'insurance/condition-observation.yaml'
PROFILE = 'served-policy-conditions/v1'
_SUFFIX = re.compile(r'-\d+-\d+-\d+$')


class InvalidAssessment(ValueError):
    """A present assessment instrument cannot be read or authenticated."""


class _Unobserved(ValueError):
    """Authentic evidence is insufficient for this technical assessment."""


@dataclass(frozen=True)
class _ServedContext:
    policies: dict[str, dict]
    subjects: dict[str, dict]
    apps_tag: str
    pins: list[dict]
    governed: set[str]


def _digest(value: object) -> str:
    return 'sha256:' + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _instant(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise InvalidAssessment('examined and observed instants require exact UTC seconds')
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


def _yaml(data: bytes) -> object:
    return yaml.load(data, Loader=clock._UniqueLoader)


def _github_repository(value: object) -> str | None:
    """One exact GitHub identity, independent of its supported Git transport."""
    if not isinstance(value, str):
        return None
    for prefix in ('https://github.com/', 'git@github.com:', 'ssh://git@github.com/'):
        if value.startswith(prefix):
            repository = value[len(prefix):].removesuffix('.git')
            return repository if clock.REPOSITORY.fullmatch(repository) else None
    return None


def _file(root: Path, relative: str) -> bytes:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in ('.', '..') for p in parts):
        raise InvalidAssessment('assessment input path must stay within its declared tree')
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise InvalidAssessment('assessment input must be a regular file without symlink parents')
    if not path.is_file():
        raise _Unobserved('an exact declared context file is unavailable')
    return path.read_bytes()


def _unknown(entry: dict, basis: str, *, quote_basis: dict | None = None, as_of: str | None = None) -> dict:
    return {
        'schema': 1, 'profile': PROFILE, 'as_of': as_of, 'state': 'unobserved', 'retention': 'not-assessed',
        'contract_premium': {'amount': entry['amount'], 'currency': entry['currency']},
        'effective_premium': None,
        'conditions': [{'source': c.get('source'), 'id': c.get('id'), 'state': 'unobserved',
                        'required_cells': None, 'observed_cells': None}
                       for c in entry.get('conditions', []) if isinstance(c, dict)],
        'quote_basis': quote_basis,
        'basis': basis + ' The booked contract premium is unchanged; this modeled view '
                 'is not billing, legal payability or transfer.',
    }


def _basis(entry: dict, exposure: dict | None, parents: list[dict], adopter: Path,
           repository: str, verify_tag: Callable[[Path, str, str], None]) -> dict:
    rows = entry.get('priced_against')
    if not isinstance(rows, list) or not rows or not isinstance(exposure, dict):
        raise _Unobserved('quoted basis or the current premium-free exposure is unavailable')
    checks: list[dict] = []
    identities = set()
    for row in rows:
        if not isinstance(row, dict):
            raise _Unobserved('a quoted basis row is unreadable')
        identity = tuple(row.get(k) for k in ('party', 'kind', 'name'))
        if identity in identities:
            raise _Unobserved('quoted basis identities are duplicated')
        identities.add(identity)
        if row.get('name') == 'exposure':
            expected = row.get('exposure_sha256')
            if (row.get('party') != exposure.get('perspective') or not isinstance(expected, str)
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', expected)):
                raise _Unobserved('quoted exposure identity or digest is unavailable')
            actual = _digest(exposure)
            state = 'matched' if expected == actual else 'mismatched'
            checks.append({'field': 'exposure_sha256', 'quoted': expected, 'current': actual, 'state': state})
            # A current self tag is never guessed from HEAD. The quoted real tag
            # must carry the same exposure and verify at the existing source boundary.
            tag = row.get('version')
            if not isinstance(tag, str) or not tag or tag.startswith('-'):
                raise _Unobserved('quoted exposure has no exact tag')
            target = clock._git(adopter, 'rev-parse', '--verify', 'refs/tags/' + tag + '^{commit}').decode().strip()
            header = _yaml(clock._show(adopter, target, 'composed/HEADER.yaml'))
            if not isinstance(header, dict) or _digest(header.get('exposure')) != expected:
                raise _Unobserved('quoted tag does not carry the quoted exposure digest')
            verify_tag(adopter, tag, repository)
            checks.append({'field': 'exposure_tag', 'tag': tag, 'commit': target, 'state': 'matched'})
        else:
            key = tuple(row.get(k) for k in ('party', 'kind', 'name'))
            current = [p for p in parents if tuple(p.get(k) for k in ('party', 'kind', 'name')) == key]
            if len(current) != 1 or not isinstance(row.get('version'), str):
                raise _Unobserved('a quoted parent has no exact comparable current identity')
            state = 'matched' if row['version'] == current[0]['version'] else 'mismatched'
            checks.append({'field': 'parent', 'party': row.get('party'), 'kind': row.get('kind'),
                           'name': row.get('name'), 'quoted': row['version'],
                           'current': current[0]['version'], 'state': state})
    if sum(r.get('name') == 'exposure' for r in rows) != 1:
        raise _Unobserved('quoted basis requires one exact insured exposure')
    return {'state': 'mismatched' if any(c['state'] == 'mismatched' for c in checks) else 'matched',
            'checks': checks}


def _policies(documents: list[dict]) -> dict[str, dict]:
    result = {}
    for doc in documents:
        if not isinstance(doc, dict) or not str(doc.get('kind', '')).endswith('Policy'):
            continue
        name = (doc.get('metadata') or {}).get('name')
        if not isinstance(name, str) or not name or name in result:
            raise _Unobserved('served policy names are missing or ambiguous')
        result[name] = doc
    return result


def _git_file(tree: Path, ref: str, path: str) -> bytes:
    mode = clock._git(tree, 'ls-tree', ref, '--', path).decode().split()
    if not mode or mode[0] != '100644':
        raise _Unobserved('a measured manifest/input is missing or not a regular Git file')
    return clock._show(tree, ref, path)


def _documents(adopter: Path, ref: str, prefix: str) -> list[dict]:
    docs: list[dict] = []
    for path in clock._git(adopter, 'ls-tree', '-r', '--name-only', ref, '--', prefix).decode().splitlines():
        if path.endswith(('.yaml', '.yml')) and path != 'composed/HEADER.yaml':
            docs.extend(d for d in yaml.load_all(_git_file(adopter, ref, path), Loader=clock._UniqueLoader)
                        if isinstance(d, dict))
    return docs


def _pin(documents: list[dict], path: str) -> dict:
    pins = [d.get('spec', {}).get('ref') for d in documents if d.get('kind') == 'GitRepository']
    if len(pins) != 1 or not isinstance(pins[0], dict) or set(pins[0]) != {'tag', 'commit'}:
        raise _Unobserved(path + ' has no exact single tag/commit source')
    return pins[0]


def _source_context(adopter: Path, source: str, parents: list[dict], exposure: dict,
                    rendered: dict[str, str], repository: str,
                    verify_tag: Callable[[Path, str, str], None]) -> _ServedContext:
    header = _yaml(clock._show(adopter, source, 'composed/HEADER.yaml'))
    if not isinstance(header, dict) or header.get('parents') != parents or header.get('exposure') != exposure:
        raise _Unobserved('scheduled source differs from the current parent/exposure context')
    # All authored subject, selection and pin declarations must be unchanged.
    names = clock._git(adopter, 'ls-tree', '-r', '--name-only', source).decode().splitlines()
    def authored(path: str) -> bool:
        return path == 'party.yaml' or path.startswith(('gitops/', 'deploy/', 'overlay/', 'inventory/'))
    current_names = {'party.yaml'}
    for directory in ('gitops', 'deploy', 'overlay', 'inventory'):
        root = adopter / directory
        if root.is_symlink():
            raise InvalidAssessment('authored context directories cannot be symlinks')
        if root.is_dir():
            current_names.update(str(p.relative_to(adopter)) for p in root.rglob('*') if p.is_file() or p.is_symlink())
    if current_names != {p for p in names if authored(p)}:
        raise _Unobserved('the authored context file set differs from the scheduled source')
    for path in names:
        if authored(path):
            if _file(adopter, path) != clock._show(adopter, source, path):
                raise _Unobserved('current declarations differ from the scheduled source context')
    apps = _pin(list(yaml.load_all(clock._show(adopter, source, 'gitops/flux-system/gotk-sync.yaml'),
                                  Loader=clock._UniqueLoader)), 'apps pin')
    composed = _pin(list(yaml.load_all(clock._show(adopter, source, 'gitops/composed/composed-set.yaml'),
                                      Loader=clock._UniqueLoader)), 'composed pin')
    for pin in (apps, composed):
        if (not isinstance(pin['tag'], str) or pin['tag'].startswith('-')
                or not isinstance(pin['commit'], str) or not clock.SHA.fullmatch(pin['commit'])):
            raise _Unobserved('served source pin is malformed')
        target = clock._git(adopter, 'rev-parse', '--verify', 'refs/tags/' + pin['tag'] + '^{commit}').decode().strip()
        if target != pin['commit']:
            raise _Unobserved('served source tag and commit disagree')
        verify_tag(adopter, pin['tag'], repository)
    served = _policies(_documents(adopter, composed['commit'], 'composed'))
    current = _policies([d for path, text in rendered.items() if path.endswith(('.yaml', '.yml'))
                         for d in yaml.load_all(text, Loader=clock._UniqueLoader) if isinstance(d, dict)])
    if not served or served != current:
        raise _Unobserved('current composed policy bodies differ from the measured served set')
    manifest = _yaml(_git_file(adopter, apps['commit'], 'gitops/apps/kustomization.yaml'))
    if (not isinstance(manifest, dict) or manifest.get('kind') != 'Kustomization'
            or not isinstance(manifest.get('resources'), list) or not manifest['resources']
            or len(set(manifest['resources'])) != len(manifest['resources'])):
        raise _Unobserved('served apps have no complete manifest enumeration')
    subjects = {}
    governed = header.get('governed-namespaces')
    if not isinstance(governed, list) or not governed or any(not isinstance(n, str) for n in governed):
        raise _Unobserved('the measured governed namespace set is unavailable')
    for resource in manifest['resources']:
        if not isinstance(resource, str) or '/' in resource or '..' in resource:
            raise _Unobserved('served apps include an unsupported manifest reference')
        documents = [d for d in yaml.load_all(_git_file(adopter, apps['commit'], 'gitops/apps/' + resource),
                                             Loader=clock._UniqueLoader) if d is not None]
        if not documents or any(not isinstance(d, dict) for d in documents):
            raise _Unobserved('a listed served manifest is empty or not an object')
        for doc in documents:
            if doc.get('kind') in ('Namespace', 'ConfigMap'):
                continue
            if doc.get('kind') != 'Pod':
                raise _Unobserved('the technical profile cannot account for this served workload kind')
            meta = doc.get('metadata') or {};ns, name = meta.get('namespace'), meta.get('name')
            version = (meta.get('labels') or {}).get('policy-as-versioned.dev/policy-version')
            if not (isinstance(ns, str) and ns and isinstance(name, str) and name
                    and isinstance(version, str) and version):
                raise _Unobserved('a served Pod has no exact namespace/name/policy claim')
            if ns not in governed or not clock.VERSION.fullmatch(version):
                raise _Unobserved('a served Pod is outside the governed/versioned technical profile')
            subject = 'Pod ' + ns + '/' + name
            if subject in subjects:
                raise _Unobserved('served subjects are duplicated')
            images = [c.get('image') for k in ('containers', 'initContainers')
                      for c in doc.get('spec', {}).get(k, [])]
            if not images or any(not isinstance(image, str) or not image for image in images):
                raise _Unobserved('a served Pod has no exact declared images')
            subjects[subject] = {'version': version, 'manifest': 'gitops/apps/' + resource, 'images': images}
    if not subjects:
        raise _Unobserved('an empty served set cannot fulfill a condition')
    pins = [d for d in _documents(adopter, source, 'gitops') if d.get('kind') == 'GitRepository']
    return _ServedContext(served, subjects, apps['tag'], pins, set(governed))


def _bound_blob(parent: dict, tree: Path, relative: str, pins: list[dict]) -> bytes:
    """A measured source pin, its signed carrier and the consumed blob must agree."""
    if not isinstance(parent.get('sha'), str) or not clock.SHA.fullmatch(parent['sha']):
        raise _Unobserved('the exact condition publisher parent commit is unavailable')
    repository = _github_repository(clock._git(tree, 'remote', 'get-url', 'origin').decode().strip())
    if repository is None:
        raise _Unobserved('a condition publisher has no canonical GitHub origin')
    candidates = [p for p in pins if _github_repository(p.get('spec', {}).get('url')) == repository]
    if len(candidates) != 1:
        raise _Unobserved('the measured source has no unambiguous condition publisher pin')
    pin = candidates[0].get('spec', {}).get('ref')
    if (not isinstance(pin, dict) or set(pin) != {'tag', 'commit'} or
            not isinstance(pin['tag'], str) or not pin['tag'] or pin['tag'].startswith('-') or
            not isinstance(pin['commit'], str) or not clock.SHA.fullmatch(pin['commit'])):
        raise _Unobserved('the condition publisher pin is not an exact tag and commit')
    target = clock._git(tree, 'rev-parse', '--verify', 'refs/tags/' + pin['tag'] + '^{commit}').decode().strip()
    if target != pin['commit']:
        raise _Unobserved('the condition publisher carrier tag differs from its pinned commit')
    clock._ancestor(tree, parent['sha'], target, 'condition publisher carrier')
    raw = _file(tree, relative)
    if raw != _git_file(tree, parent['sha'], relative) or raw != _git_file(tree, target, relative):
        raise _Unobserved('consumed condition input differs from the exact measured publisher objects')
    clock._tag_signature(tree, pin['tag'], repository)
    return raw


def _mapping(parents: list[dict], trees: dict[str, Path], pins: list[dict]) -> dict[tuple[str, str], set[str]]:
    controls = {p['party']: p for p in parents if p.get('kind') == 'controls'}
    mapping: dict[tuple[str, str], set[str]] = defaultdict(set)
    seen = {}
    for parent in parents:
        if parent.get('kind') != 'implementations' or parent['party'] not in trees:
            continue
        tree = trees[parent['party']]
        raw = _bound_blob(parent, tree, 'oscal/component-definition.json', pins)
        for component in json.loads(raw).get('component-definition', {}).get('components', []):
            for implementation in component.get('control-implementations', []):
                source = implementation.get('source')
                match = re.fullmatch(r'\.\./([A-Za-z0-9_.-]+)/catalog/[^/]+\.json', source or '')
                if not match or match[1] not in controls:
                    raise _Unobserved('publisher mapping has no exact inherited catalogue source')
                control_parent = controls[match[1]]
                if match[1] not in trees:
                    raise _Unobserved('the exact mapped control publisher is unavailable')
                catalog = json.loads(_bound_blob(control_parent, trees[match[1]], 'catalog/' + source.rsplit('/', 1)[1], pins))
                def ids(value: object) -> set[str]:
                    if isinstance(value, list):
                        return set().union(*(ids(v) for v in value))
                    if isinstance(value, dict):
                        own = {c['id'] for c in value.get('controls', [])
                               if isinstance(c, dict) and isinstance(c.get('id'), str)}
                        return own | set().union(*(ids(v) for v in value.values()))
                    return set()
                catalogue_ids = ids(catalog)
                for requirement in implementation.get('implemented-requirements', []):
                    control = requirement.get('control-id')
                    if not isinstance(control, str) or not control or control not in catalogue_ids:
                        raise _Unobserved('publisher mapping has an unreadable control id')
                    for prop in requirement.get('props', []):
                        if prop.get('name') != 'Check_Id':
                            continue
                        policy = prop.get('value')
                        if not isinstance(policy, str) or not policy or policy in seen:
                            raise _Unobserved('publisher check mapping is ambiguous')
                        seen[policy] = (match[1], control)
                        mapping[(match[1], control)].add(policy)
    return dict(mapping)


def _fx_inputs(parents: list[dict], trees: dict[str, Path], pins: list[dict]) -> list[dict]:
    """Bind the existing dated FX reader's inputs before it computes an increment."""
    bound = []
    for party, tree in sorted(trees.items()):
        if not (tree / 'converters/fx.py').exists():
            continue
        if not any(p['party'] == party for p in parents):
            raise InvalidAssessment('the FX converter is outside the current parent set')
        fx_pins = [p for p in pins if isinstance(p.get('spec', {}).get('ref', {}).get('tag'), str)
                   and p['spec']['ref']['tag'].startswith('fx/')]
        versions = sorted(tree.glob('fx/v*/feed.json'))
        if not versions:
            raise InvalidAssessment('the pinned FX publisher has no dated feed')
        files = ['converters/fx.py', *(str(path.relative_to(tree)) for path in versions)]
        repository = _github_repository(clock._git(tree, 'remote', 'get-url', 'origin').decode().strip())
        if repository is None:
            raise InvalidAssessment('the FX publisher has no canonical GitHub origin')
        matching = [p for p in fx_pins if _github_repository(p.get('spec', {}).get('url')) == repository]
        if len(matching) != 1:
            raise InvalidAssessment('the scheduled source has no exact signed FX pin')
        carrier = matching[0]['spec']['ref']['commit']
        for path in files:
            raw = _bound_blob({'sha': carrier}, tree, path, fx_pins)
            bound.append({'party': party, 'carrier': carrier, 'path': path,
                          'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest()})
    if not bound:
        raise InvalidAssessment('no signed dated FX instrument supplies the quoted uplift currency')
    return bound


def _matrix(conditions: list[dict], assessment: dict, served: dict[str, dict],
            subjects: dict[str, dict], mapping: dict[tuple[str, str], set[str]], governed: set[str]) -> list[dict]:
    cells: dict[tuple[str, str], list[str]] = defaultdict(list)
    identities: dict[str, str] = {}
    policy_control = {policy: key for key, policies in mapping.items() for policy in policies}
    for result in assessment.get('assessment-results', {}).get('results', []):
        links: dict[str, set[str]] = defaultdict(set)
        for finding in result.get('findings', []):
            control = finding.get('target', {}).get('target-id')
            for reference in finding.get('related-observations', []):
                links[reference.get('observation-uuid')].add(control)
        for observation in result.get('observations', []):
            props = observation.get('props')
            if (not isinstance(props, list) or any(not isinstance(p, dict) or not isinstance(p.get('name'), str) for p in props)
                    or len({p.get('name') for p in props}) != len(props)):
                raise _Unobserved('an observation has ambiguous properties')
            props = {p['name']: p.get('value') for p in props}
            policy = props.get('policy')
            for subject in observation.get('subjects', []):
                title = subject.get('title')
                if not isinstance(title, str):
                    raise _Unobserved('an observed subject has no exact title')
                scoped = re.fullmatch(r'(Pod|Deployment|ReplicaSet|StatefulSet|DaemonSet|Job|CronJob) ([^/]+)/[^/]+', title)
                if scoped and scoped[2] in governed and title not in subjects:
                    raise _Unobserved('the measured Pod set differs from the declared served subjects')
                if title not in subjects or policy not in served:
                    continue
                UUID(observation['uuid']);UUID(subject['subject-uuid'])
                if title in identities and identities[title] != subject['subject-uuid']:
                    raise _Unobserved('an observed subject title names multiple resource identities')
                identities[title] = subject['subject-uuid']
                expected_version = policy[len(_SUFFIX.sub('', policy)) + 1:] or 'unversioned'
                if props.get('policy-version') != expected_version:
                    raise _Unobserved('an observed policy name and version disagree')
                key = policy_control.get(_SUFFIX.sub('', policy))
                if key is None:
                    continue
                if links.get(observation['uuid']) != {key[1]}:
                    raise _Unobserved('observation linkage does not identify its mapped control')
                cells[(title, policy)].append(props.get('result'))
    out = []
    for condition in conditions:
        bases = mapping.get((condition['source'], condition['id']), set())
        expected = [(subject, policy) for subject, context in subjects.items() for policy in served
                    if _SUFFIX.sub('', policy) in bases and
                    (not _SUFFIX.search(policy) or policy.endswith('-' + context['version'].replace('.', '-')))]
        observed = [value for cell in expected for value in cells.get(cell, [])]
        complete = bool(expected) and bool(bases) and all(cells.get(c) for c in expected)
        # Every mapped check must be represented in the actual served window.
        complete = complete and bases.issubset({_SUFFIX.sub('', p) for _, p in expected})
        state = ('breached' if 'fail' in observed else
                 'met' if complete and all(v == 'pass' for v in observed) else 'unobserved')
        out.append({'source': condition['source'], 'id': condition['id'], 'state': state,
                    'required_cells': len(expected), 'observed_cells': sum(bool(cells.get(c)) for c in expected)})
    return out


def assess(entry: dict, adopter: Path, *, exposure: dict | None, parents: list[dict],
           parent_trees: dict[str, Path], rendered: dict[str, str],
           quote_path: Path, convert: Callable[[float, str], float]) -> dict:
    """Authenticate inputs and consume consequences; no caller supplies an admitted result.

    Replay repeats authentication of the selected immutable original. There is
    no serialized success/cache override; unavailable authority is a refusal.
    """
    path = adopter / SELECTOR
    if not path.exists() and not path.is_symlink():
        return _unknown(entry, 'No authenticated observation selector was supplied; '
                        'technical conditions and the effective conditional cost are unobserved.')
    basis = None
    examined_at = None
    try:
        descriptor = clock._object(_yaml(_file(adopter, SELECTOR)), {
            'schema', 'profile', 'party', 'repository', 'examined_at', 'quote', 'baseline'}, 'condition observation selector')
        if type(descriptor['schema']) is not int or descriptor['schema'] != 1 or descriptor['profile'] != PROFILE:
            raise InvalidAssessment('unsupported technical assessment schema/profile')
        if not isinstance(exposure, dict) or descriptor['party'] != exposure.get('perspective'):
            raise InvalidAssessment('observation selector names another insured party')
        repository = clock._text(descriptor['repository'], 'assessment repository', clock.REPOSITORY)
        remote = _github_repository(clock._git(adopter, 'remote', 'get-url', 'origin').decode().strip())
        if remote != repository:
            raise InvalidAssessment('assessment repository differs from the adopter origin')
        selected = clock._object(descriptor['quote'], {'source', 'name', 'version', 'parent_sha', 'payload_sha256'}, 'quote binding')
        parent = next((p for p in parents if p.get('party') == entry['source'] and p.get('name') == entry['name']), None)
        actual = {'source': entry['source'], 'name': entry['name'], 'version': entry['new_version'],
                  'parent_sha': (parent or {}).get('sha'),
                  'payload_sha256': 'sha256:' + hashlib.sha256(quote_path.read_bytes()).hexdigest()}
        if selected != actual:
            raise InvalidAssessment('observation selector is bound to another exact quote')
        examined = _instant(descriptor['examined_at'])
        examined_at = descriptor['examined_at']
        receipt = clock.read_scheduled_original(adopter, descriptor['baseline'], repository,
                                                clock._official, clock._signature)
        run = receipt['run']
        created, started, finished = (_instant(run.get(key)) for key in
                                     ('created_at', 'run_started_at', 'updated_at'))
        if not created <= started <= finished:
            raise InvalidAssessment('official attempt has no coherent attempt-specific time interval')
        for rows in receipt['rows'].values():
            for row in rows:
                stamp = _instant(row.get('ts'))
                if not started <= stamp <= finished or not timedelta(0) <= examined - stamp <= timedelta(hours=48):
                    raise _Unobserved('scheduled observation is future, stale or outside its official attempt')
                if not entry['valid_from'] <= row['ts'][:10] <= entry['valid_until']:
                    raise _Unobserved('scheduled observation is outside the signed quote window')
        if not entry['valid_from'] <= descriptor['examined_at'][:10] <= entry['valid_until']:
            raise _Unobserved('examined technical instant is outside the signed quote window')
        basis = _basis(entry, exposure, parents, adopter, repository, clock._tag_signature)
        if basis['state'] != 'matched':
            raise _Unobserved('quoted basis differs from the current premium-free exposure or parents')
        assert isinstance(exposure, dict)
        served_context = _source_context(adopter, descriptor['baseline']['source_commit'], parents,
                                         exposure, rendered, repository, clock._tag_signature)
        subjects, pins = served_context.subjects, served_context.pins
        quote_parent = next(p for p in parents if p.get('party') == entry['source'] and p.get('name') == entry['name'])
        quote_tree = parent_trees.get(entry['source'])
        if quote_tree is None:
            raise _Unobserved('the exact quote publisher is unavailable for context authentication')
        _bound_blob(quote_parent, quote_tree, str(quote_path.relative_to(quote_tree)), pins)
        work = receipt['rows']['drift/workload-samples.jsonl'][0]
        workloads = work.get('workloads')
        if (not isinstance(workloads, list) or len(workloads) != len(subjects) or
                set(w.get('name') for w in workloads) != {s.rsplit('/', 1)[1] for s in subjects} or
                work.get('apps_ref') != served_context.apps_tag or work.get('observed') is not True):
            raise _Unobserved('the scheduled workload sample does not enumerate every required served subject')
        if len({s.rsplit('/', 1)[1] for s in subjects}) != len(subjects):
            raise _Unobserved('workload names do not identify unique namespace subjects')
        for workload in workloads:
            context = next(value for title, value in subjects.items() if title.rsplit('/', 1)[1] == workload['name'])
            labels = workload.get('caged', {}).get('labels', {})
            if (workload.get('manifest') != context['manifest'] or workload.get('observed') is not True or
                    workload.get('image') != context['images'] or
                    labels.get('policy-as-versioned.dev/policy-version') != context['version']):
                raise _Unobserved('observed workload manifest, identity, images or policy claim differs from the served subject')
        conditions = entry['conditions']
        if not isinstance(conditions, list) or not conditions:
            raise InvalidAssessment('assessment requires an explicit nonempty quoted condition list')
        seen = set()
        for c in conditions:
            if (not isinstance(c, dict) or c.keys() - {'source', 'id', 'consequence', 'uplift', 'why'}
                    or not all(isinstance(c.get(k), str) and c[k] for k in ('source', 'id'))
                    or c.get('consequence') not in ('void', 'uplift') or (c['source'], c['id']) in seen
                    or ('why' in c and (not isinstance(c['why'], str) or not c['why']))):
                raise InvalidAssessment('quoted conditions are malformed, unsupported or duplicated')
            seen.add((c['source'], c['id']))
            if c['consequence'] == 'uplift':
                money = clock._object(c.get('uplift'), {'amount', 'currency'}, 'quoted uplift')
                if (type(money['amount']) not in (int, float) or not math.isfinite(money['amount'])
                        or money['amount'] < 0 or not isinstance(money['currency'], str)
                        or not re.fullmatch('[A-Z]{3}', money['currency'])):
                    raise InvalidAssessment('quoted uplift is not finite nonnegative money')
            elif 'uplift' in c:
                raise InvalidAssessment('a void condition cannot also carry an uplift')
        oscal = receipt['rows']['drift/oscal-samples.jsonl'][0]
        states = _matrix(conditions, oscal['assessment_results'], served_context.policies, subjects,
                         _mapping(parents, parent_trees, pins), served_context.governed)
        unknown = any(c['state'] == 'unobserved' for c in states)
        void = any(state['state'] == 'breached' and c['consequence'] == 'void' for c, state in zip(conditions, states))
        fx = (_fx_inputs(parents, parent_trees, pins) if any(
            c['consequence'] == 'uplift' and state['state'] == 'breached' and
            c['uplift']['currency'] != entry['currency'] for c, state in zip(conditions, states)) else [])
        increments = [convert(c['uplift']['amount'], c['uplift']['currency']) for c, state in zip(conditions, states)
                      if c['consequence'] == 'uplift' and state['state'] == 'breached']
        if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in increments):
            raise InvalidAssessment('the declared uplift has no finite nonnegative converted cost')
        effective = None if unknown else {'amount': entry['amount'] + sum(increments), 'currency': entry['currency']}
        if effective is not None and not math.isfinite(effective['amount']):
            raise InvalidAssessment('the modeled conditional cost is not finite')
        return {'schema': 1, 'profile': PROFILE, 'as_of': descriptor['examined_at'],
                'state': 'unobserved' if unknown else ('breached' if any(c['state'] == 'breached' for c in states) else 'met'),
                'retention': 'fully-retained' if void else 'not-assessed',
                'contract_premium': {'amount': entry['amount'], 'currency': entry['currency']},
                'effective_premium': effective, 'conditions': states, 'quote_basis': basis,
                'input': {'original': descriptor['baseline']['original_commit'], 'source': descriptor['baseline']['source_commit'],
                          'run': descriptor['baseline']['run_id'], 'attempt': descriptor['baseline']['attempt'], 'quote': actual, 'fx': fx},
                'basis': 'Authenticated scheduled technical observations of the declared served subject/check matrix. '
                         'Modeled conditional/TCoR premium component only; actual billing changes only through signed '
                         're-quote and adoption. No legal payability or transfer credit; the booked premium is unchanged.'}
    except _Unobserved as exc:
        return _unknown(entry, str(exc), quote_basis=basis, as_of=examined_at)
    except (clock.InvalidRetirement, OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, yaml.YAMLError) as exc:
        if isinstance(exc, InvalidAssessment):
            raise
        raise InvalidAssessment('condition evidence instrument could not be authenticated or read: ' + str(exc)) from exc
