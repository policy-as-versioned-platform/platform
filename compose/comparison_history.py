"""Signed comparison inputs, independent of freshly rendered transition outputs.

The caller supplies current source identity and the existing recorded state. A
same-input repeat retains the before-state; a source change starts a comparison
from the existing after-state. These are historical inputs, never trusted deltas.

A fresh composition reads the recorded state as last committed (ticket 133), and
the identity leaves out the files a clock's declared lane appends (ticket 134).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path, PurePosixPath
from typing import Callable

import yaml


class InvalidHistory(ValueError):
    pass


HEADER_FIELDS = ('parents', 'baseline', 'holes', 'selected-controls', 'ungoverned-namespaces')
# A header field carried only where the recorded header carries it (eco-system
# tickets 123 and 126). Absent means the header predates it, which is not the
# same fact as an empty list or false, so the projection never defaults it.
# `overlay-controls` is a list of ids; `withdrawn-selectable` is a boolean.
OPTIONAL_HEADER_FIELDS = ('overlay-controls', 'withdrawn-selectable')
OPTIONAL_BOOLEAN_FIELDS = ('withdrawn-selectable',)
PRICE_FIELDS = ('kind', 'source', 'name', 'proposed_tier', 'hole')
CAGE_FIELDS = ('party', 'rule', 'tier')


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


# Eco-system ticket 134. A clock appends observations to the paths its workflow
# declares as OBSERVATION_LANE, and never declarations (ADR-0023). The hub's
# verify/schedules/lane.py grades every clock commit against that declaration,
# and verify/map-surface grades that a unit owns every path it declares. So the
# declaration is the one statement of what a clock may write, and those files
# are observations, not source. Hashing them made every daily lane commit
# start a new comparison and turned compose-check and the pre-tag verify red.
#
# This reader reads exactly what the hub grades, and no more: the env of a
# workflow that has a `schedule:` trigger, at top level and job level, merged
# as the job sees it (verify/schedules/schedules.py `scheduled_jobs` and
# `_env`). A dispatched or pushed job, or a step's own env, is not a clock's
# lane, so it takes nothing out of the identity.
LANE_KEY = 'OBSERVATION_LANE'
WORKFLOWS = ('.github', 'workflows')
# ADR-0024 point 3 (D1): the complete list of paths a scheduled run may ever
# commit. A copy of the hub's verify/schedules/schedules.py ALLOW_LIST, carried
# here because the composer runs in the adopter's CI with no hub checkout. The
# hub's verify/schedules/lane.py compares the two on platform main on every run
# and fails when they differ, so neither copy can drift alone.
OBSERVATION_PATHS = ('talk/truth.log', 'drift/samples.jsonl', 'talk/captures', 'observations')
# The composer walks every `*.yaml` file in the adopter's tree for Namespaces
# and workloads (composition._namespace_facts, which globs `*.yaml` only). A
# YAML file inside a lane is read as a declaration, so it stays in the identity
# whatever the lane says. `.yml` is kept too: the composer does not read it,
# but nothing a clock appends is YAML, so keeping it costs nothing and a
# future reader of `.yml` cannot turn a lane file into unhashed source.
COMPOSER_READS = ('.yaml', '.yml')


def _scheduled(doc: dict) -> bool:
    # YAML 1.1 reads a bare `on` key as the boolean True, so both keys.
    on = doc.get('on', doc.get(True))
    schedule = on.get('schedule') if isinstance(on, dict) else None
    return isinstance(schedule, list) and any(
        isinstance(entry, dict) and 'cron' in entry for entry in schedule)


def _lane_envs(doc: object) -> list[dict]:
    """The env each scheduled job runs with: top level, then job level over it.
    Nothing for a workflow with no `schedule:` trigger, and never a step env."""
    if not isinstance(doc, dict) or not _scheduled(doc):
        return []
    top = doc.get('env') if isinstance(doc.get('env'), dict) else {}
    jobs = doc.get('jobs')
    envs = []
    for job in (jobs.values() if isinstance(jobs, dict) else []):
        job_env = job.get('env') if isinstance(job, dict) else None
        envs.append({**top, **(job_env if isinstance(job_env, dict) else {})})
    return envs


def _observation_path(lane: str) -> str | None:
    """The lane path, normalised, when it sits inside ADR-0024's list; else None."""
    lane = lane.strip('"\'').rstrip('/')
    pure = PurePosixPath(lane)
    parts = pure.parts
    if not parts or pure.is_absolute() or '..' in parts or '.' in lane.split('/'):
        return None
    normal = '/'.join(parts)
    if not any(normal == allowed or normal.startswith(allowed + '/')
               for allowed in OBSERVATION_PATHS):
        return None
    return normal


def observation_lanes(adopter: Path) -> list[str]:
    """The lane paths the adopter's own scheduled jobs declare, read from the
    tree under composition. Quoted and unquoted values both count, and a value
    may name several space-separated paths, as the workflows' shell loops read
    it. A declaration that cannot be read, or that names a path outside
    ADR-0024's observation list, refuses by name rather than guessing."""
    lanes: set[str] = set()
    workflows = adopter.joinpath(*WORKFLOWS)
    if not workflows.is_dir():
        return []
    for path in sorted(workflows.iterdir()):
        if path.suffix not in ('.yml', '.yaml') or not path.is_file():
            continue
        where = '/'.join((*WORKFLOWS, path.name))
        try:
            doc = yaml.safe_load(path.read_text())
        except (OSError, ValueError, yaml.YAMLError) as error:
            raise InvalidHistory(f'invalid comparison history: cannot read the {LANE_KEY} '
                                 f'declarations in {where} ({error})') from None
        for env in _lane_envs(doc):
            if LANE_KEY not in env:
                continue
            value = env[LANE_KEY]
            if not isinstance(value, str):
                raise InvalidHistory(f'invalid comparison history: {LANE_KEY} in {where} '
                                     'is not a string of paths')
            for lane in value.split():
                normal = _observation_path(lane)
                if normal is None:
                    raise InvalidHistory(
                        f'invalid comparison history: {LANE_KEY} in {where} names {lane!r}, '
                        f'which is not inside the ADR-0024 observation list '
                        f'({", ".join(OBSERVATION_PATHS)})')
                lanes.add(normal)
    return sorted(lanes)


def _in_lane(relative: Path, lanes: list[str]) -> bool:
    parts = relative.parts
    return any(parts[:len(lane)] == lane for lane in (PurePosixPath(x).parts for x in lanes))


def identity(adopter: Path, parents: list[dict], observations: list[dict], as_of: str | None, namespace_facts: object) -> str:
    # Source bytes, not checkout paths, Git HEAD, generated artefacts or Python
    # caches. Include every non-hidden source file: a source edit deliberately
    # starts a new comparison, even if it does not change the selected tier.
    # A clock's observation is not a source edit (ticket 134): files under a
    # lane a scheduled job declares, inside ADR-0024's list, are left out,
    # except the YAML the composer reads. The lane list itself is hashed, so a
    # changed declaration starts a new comparison.
    lanes = observation_lanes(adopter)
    sources = {}
    for path in sorted(adopter.rglob('*')):
        relative = path.relative_to(adopter)
        if any(part.startswith('.') or part == '__pycache__' for part in relative.parts):
            continue
        if relative.parts[0] == 'composed' or not path.is_file():
            continue
        if _in_lane(relative, lanes) and path.suffix not in COMPOSER_READS:
            continue
        sources[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return _digest({'sources': sources, 'parents': parents, 'observations': observations,
                    'as_of': as_of, 'namespace_facts': namespace_facts,
                    'observation-lanes': lanes})


def v330_identity(adopter: Path, parents: list[dict], observations: list[dict], as_of: str | None, namespace_facts: object) -> str:
    """The identity tools v3.3.0 recorded, which hashed the lane files too.

    Kept for one migration only (ticket 134): an artefact recorded under the
    old formula is still the same comparison, so moving the tools pin does not
    by itself start a new one and drop the open deltas. Each non-YAML lane file
    is read as it stood in the commit that last wrote composed/HEADER.yaml,
    which is the lane state the old identity was computed over. Later lane
    commits therefore do not defeat the match, and any other source edit still
    does. Outside a git work tree the lane files are read from the working
    tree. A depth-1 checkout whose one commit already carries a later lane
    commit cannot show the old lane bytes: the match fails there and a new
    comparison starts, exactly as under v3.3.0, so the migrating recompose is
    made from a full clone."""
    lanes = observation_lanes(adopter)
    at = None
    if lanes and (adopter / '.git').exists():
        log = _git(adopter, 'log', '-1', '--format=%H', '--', RECORDED[0])
        at = log.stdout.strip() if log.returncode == 0 and log.stdout.strip() else None
    sources = {}
    for path in sorted(adopter.rglob('*')):
        relative = path.relative_to(adopter)
        if any(part.startswith('.') or part == '__pycache__' for part in relative.parts):
            continue
        if relative.parts[0] == 'composed' or not path.is_file():
            continue
        if at and _in_lane(relative, lanes) and path.suffix not in COMPOSER_READS:
            continue
        sources[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    if at:
        listed = _git(adopter, 'ls-tree', '-r', '-z', '--name-only', at, '--', *lanes)
        if listed.returncode != 0:
            raise InvalidHistory(f'invalid comparison history: cannot list the lane at {at} '
                                 f'({listed.stderr.strip()})')
        for name in filter(None, listed.stdout.split('\0')):
            listed_path = PurePosixPath(name)
            if (any(part.startswith('.') or part == '__pycache__' for part in listed_path.parts)
                    or listed_path.parts[0] == 'composed' or listed_path.suffix in COMPOSER_READS):
                continue
            blob = _git_bytes(adopter, 'cat-file', 'blob', f'{at}:{name}')
            sources[name] = hashlib.sha256(blob).hexdigest()
    return _digest({'sources': dict(sorted(sources.items())), 'parents': parents,
                    'observations': observations, 'as_of': as_of, 'namespace_facts': namespace_facts})


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(x, str) for x in value)


def _validate(before: object) -> None:
    if not isinstance(before, dict) or set(before) != {'header', 'prices', 'cages'}:
        raise InvalidHistory('invalid comparison history: incomplete before-state')
    header = before['header']
    if header is not None:
        if (not isinstance(header, dict) or not set(HEADER_FIELDS) <= set(header)
                or not set(header) <= set(HEADER_FIELDS) | set(OPTIONAL_HEADER_FIELDS)):
            raise InvalidHistory('invalid comparison history: header fields')
        if header['baseline'] is not None and not isinstance(header['baseline'], str):
            raise InvalidHistory('invalid comparison history: baseline')
        if not all(_strings(header[k]) for k in HEADER_FIELDS[2:]
                   + tuple(k for k in OPTIONAL_HEADER_FIELDS
                           if k in header and k not in OPTIONAL_BOOLEAN_FIELDS)):
            raise InvalidHistory('invalid comparison history: control/namespace lists')
        if not all(isinstance(header[k], bool) for k in OPTIONAL_BOOLEAN_FIELDS if k in header):
            raise InvalidHistory('invalid comparison history: boolean header fields')
        if not isinstance(header['parents'], list) or not all(
                isinstance(p, dict) and all(isinstance(p.get(k), str) for k in ('party', 'kind', 'version', 'sha'))
                for p in header['parents']):
            raise InvalidHistory('invalid comparison history: parents')
    for key, fields in (('prices', PRICE_FIELDS), ('cages', CAGE_FIELDS)):
        rows = before[key]
        if not isinstance(rows, list) or not all(isinstance(row, dict) and set(row) == set(fields) for row in rows):
            raise InvalidHistory(f'invalid comparison history: {key}')
        for row in rows:
            if not all(row[k] is None or isinstance(row[k], str) for k in fields if k != 'hole'):
                raise InvalidHistory(f'invalid comparison history: {key} values')
            if key == 'prices' and row['hole'] is not None:
                if (not isinstance(row['hole'], dict) or set(row['hole']) != {'status'}
                        or row['hole']['status'] not in ('new', 'recorded', 'closed')):
                    raise InvalidHistory('invalid comparison history: pin hole')


def project(header: dict | None, prices: list[dict], cages: list[dict]) -> dict:
    prior_header = None if header is None else {
        key: header.get(key, [] if key != 'baseline' else None) for key in HEADER_FIELDS}
    if prior_header is not None:
        prior_header.update({key: header[key] for key in OPTIONAL_HEADER_FIELDS if key in header})
    prior_prices = [{key: row.get(key) for key in PRICE_FIELDS} for row in prices]
    for row in prior_prices:
        if isinstance(row['hole'], dict):
            row['hole'] = {'status': row['hole'].get('status')}
    before = {'header': prior_header, 'prices': prior_prices,
              'cages': [{key: row.get(key) for key in CAGE_FIELDS} for row in cages]}
    _validate(before)
    return before


def resolve(current: str, header: dict | None, prices: list[dict], cages: list[dict], *, replay: bool,
            legacy: Callable[[], str] | None = None) -> dict:
    if header is None or 'comparison-inputs' not in header:
        return {'schema': 1, 'after': current, 'before': project(header, prices, cages)}
    record = header['comparison-inputs']
    if (not isinstance(record, dict) or set(record) != {'schema', 'after', 'before'}
            or type(record['schema']) is not int or record['schema'] != 1
            or not isinstance(record['after'], str) or len(record['after']) != 64
            or any(c not in '0123456789abcdef' for c in record['after'])):
        raise InvalidHistory('invalid comparison history: schema or current input identity')
    _validate(record['before'])
    if record['after'] == current:
        return record
    if legacy is not None and record['after'] == legacy():
        # Recorded by tools v3.3.0 over the same sources (ticket 134).
        # Verification replays it byte for byte; a fresh composition keeps
        # its comparison and stamps it with this formula's identity.
        return record if replay else {**record, 'after': current}
    if replay:
        raise InvalidHistory('comparison history does not match current source inputs')
    return {'schema': 1, 'after': current, 'before': project(header, prices, cages)}


def _parse_recorded(header_text: str | None, evidence_text: str | None) -> tuple[dict | None, list[dict], list[dict]]:
    header = yaml.safe_load(header_text) if header_text is not None else None
    evidence = json.loads(evidence_text) if evidence_text is not None else {}
    if header_text is not None and not isinstance(header, dict):
        raise InvalidHistory('invalid comparison history: recorded header is not a mapping')
    if not isinstance(evidence, dict):
        raise InvalidHistory('invalid comparison history: recorded evidence is not a mapping')
    prices, cages = evidence.get('prices', []), evidence.get('cages', [])
    if not isinstance(prices, list) or not isinstance(cages, list) or not all(
            isinstance(row, dict) for row in prices + cages):
        raise InvalidHistory('invalid comparison history: recorded price/cage rows')
    return header, prices, cages


RECORDED = ('composed/HEADER.yaml', 'composed/evidence.json')


def read_recorded(adopter: Path) -> tuple[dict | None, list[dict], list[dict]]:
    """Absent legacy evidence is empty; corrupt present evidence is not absence."""
    header_path, evidence_path = (adopter / rel for rel in RECORDED)
    try:
        return _parse_recorded(header_path.read_text() if header_path.exists() else None,
                               evidence_path.read_text() if evidence_path.exists() else None)
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise InvalidHistory(f'invalid comparison history: cannot read recorded inputs ({error})') from None


def _git(adopter: Path, *args: str) -> subprocess.CompletedProcess[str]:
    # The adopter's own repository, whatever GIT_DIR a caller's environment carries.
    env = {k: v for k, v in os.environ.items()
           if k not in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR')}
    return subprocess.run(['git', '-C', str(adopter), *args], capture_output=True, text=True, env=env)


def _git_bytes(adopter: Path, *args: str) -> bytes:
    env = {k: v for k, v in os.environ.items()
           if k not in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR')}
    done = subprocess.run(['git', '-C', str(adopter), *args], capture_output=True, env=env)
    if done.returncode != 0:
        raise InvalidHistory(f'invalid comparison history: git {" ".join(args)} failed '
                             f'({done.stderr.decode(errors="replace").strip()})')
    return done.stdout


def read_committed(adopter: Path) -> tuple[dict | None, list[dict], list[dict]] | None:
    """Eco-system ticket 133. The recorded inputs as the adopter last COMMITTED
    them: `composed/` at HEAD, never the working tree. A fresh composition
    compares against this, so a previous pass that left its own output in the
    working tree cannot become the next pass's "before" and hide its delta.

    None when the adopter directory is not the top of a git work tree (a
    fixture or scratch directory): its files are the only artefact it has.
    A work tree with no commit has committed nothing, which is absence.
    A work tree whose HEAD git cannot read refuses by name."""
    if not (adopter / '.git').exists():
        return None
    if _git(adopter, 'rev-parse', '--verify', '--quiet', 'HEAD^{commit}').returncode != 0:
        if _git(adopter, 'rev-parse', '--git-dir').returncode != 0:
            raise InvalidHistory('invalid comparison history: the adopter is a git work tree '
                                 'but git cannot read it, so its committed artefact is unknown')
        return None, [], []
    texts: list[str | None] = []
    for rel in RECORDED:
        if _git(adopter, 'cat-file', '-e', f'HEAD:{rel}').returncode != 0:
            texts.append(None)
            continue
        shown = _git(adopter, 'cat-file', 'blob', f'HEAD:{rel}')
        if shown.returncode != 0:
            raise InvalidHistory(f'invalid comparison history: cannot read {rel} at HEAD '
                                 f'({shown.stderr.strip()})')
        texts.append(shown.stdout)
    try:
        return _parse_recorded(*texts)
    except (ValueError, yaml.YAMLError) as error:
        raise InvalidHistory(f'invalid comparison history: cannot read recorded inputs at HEAD ({error})') from None
