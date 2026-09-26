#!/usr/bin/env python3
"""Every cell a declaration names: one policy line, or the machinery, on one exact engine.

Hub ADR-0033 and eco-system ticket 146. A policy line supports exactly the engines in its
`tested_engines`, and on each of them every body the line serves compiles and its fixtures pass.
The machinery the composer renders declares its own `tested_engines`, in
`distribution/machinery.yaml`, and is graded the same way. A CELL is one subject (a line, or the
machinery) on one engine. One run grades every cell:

  * the caller hands in one binary per engine (`--engine`, `--engine-dir`), and each binary is
    identified by running it, never by its path;
  * a cell a subject lists with no binary for its engine reads could-not-look;
  * a binary for an engine no subject lists is reported as EXTRA and is never read as support;
  * the report carries the whole matrix.

WHAT IS GRADED, AND FROM WHICH TREE. Everything is read from one commit, `--ref` (HEAD by
default): the array, the machinery declaration, the machinery itself and the line fixtures.
  * A CUT line (its array element carries `commit`) is graded on its annotated
    `policy/vX.Y.Z` tag, whose policy tree must equal the array commit's.
  * An UNCUT line that carries `tested_engines` is a CANDIDATE. It is graded on the tree of the
    commit being graded, which is the commit that declares it. So a declaration is graded before
    its cut, and cut-release.yml runs this before it signs a tag.
  * A BODY is every Kyverno policy document in the line's `distribution/policies/v<version>/`
    tree. Each file is graded against its own fixture: `computed-semver/engine-fixtures/
    v<version>/<file>/` at the graded commit, with its `policies:` pointed at the served bytes
    and nothing else changed. For cage-tier and cage-netpol the line tree's own
    `graded/tests/<family>` (at the tag, once cut), adapted as below, always runs when the tree
    carries it, and an engine-fixtures folder for the same body runs beside it, never instead of
    it. A body with neither FAILS: support means its fixtures pass, and it has none.
  * Every `kyverno test` run is read row by row (`-o json`). A pass or fail row that reads
    `Excluded` fails the body: Kyverno counts a resource it did not apply the policy to as a pass
    whatever the row asserts (see `_excluded`).
  * The MACHINERY is what `compose/composition.py`'s `machinery_members()` renders from the
    graded commit, the same call composition makes. Each policy member is graded against
    `computed-semver/engine-fixtures/machinery/<member>/`.

Signatures, Kubernetes admission, live reach and controller behaviour are outside this
instrument. The binaries' authenticity rests on the caller's checksum (engine/kyverno/
engine-table.yaml and engine/install-kyverno-engines.sh); this records each binary's own digest.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Iterable

import yaml

SCOPE = 'every-served-body-v1'
# A scope this grader will not accept. A declaration written under a narrower meaning has not
# been graded under the wider one, so it cannot pass under it (ticket 146 item 3).
RETIRED_SCOPES = {
    'published-cage-fixtures-v1': 'graded the cage-tier and cage-netpol fixtures only '
                                  '(ticket 71, platform PR 26), not every body the line serves',
}
LEGACY_FAMILIES = ('cage-tier', 'cage-netpol')
FIXTURES = 'computed-semver/engine-fixtures'
MACHINERY = 'distribution/machinery.yaml'
POLICY_GROUPS = ('policies.kyverno.io/', 'kyverno.io/')
_VERSION = re.compile(r'\d+\.\d+\.\d+')
LIMITS = [
    'Offline Kyverno CLI only: no Kubernetes admission, no background controller, no live reach.',
    'Exact CLI versions only; no patch range, Kubernetes version or adopter runtime is inferred.',
    'A cell grades the bodies the subject serves against their fixtures; a fixture proves what its '
    'rows assert and nothing else. The CLI evaluates every resource as a CREATE and cannot '
    'populate oldObject, so an UPDATE-only body is graded on compiling only.',
    'Line fixtures under computed-semver/engine-fixtures/ are read from the graded commit, not '
    'from the tag, because a fixture can be written after its line was cut; the row records both. '
    'For cage-tier and cage-netpol the tag\'s own graded/tests fixture always runs as well.',
    'A pass or fail row that kyverno test reads as Excluded (the policy was not applied to the '
    'resource) fails its body; a skip row may read Excluded.',
    'Tag signature verification remains the provenance gate; this check binds tag and array policy trees.',
    'Executable SHA256 identifies each binary; its authenticity rests on the caller checksum.',
    'This evidence changes no policy body, policy bump, money, or release authorization.',
]


class SourceUnavailable(Exception):
    """The local checkout cannot supply a historical input for measurement."""


def _run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=300, **kwargs)


def _git(repo: Path, *args: str) -> str:
    result = _run(['git', '-C', str(repo), *args])
    if result.returncode:
        raise ValueError(result.stderr.strip() or 'Git source unavailable')
    return result.stdout.strip()


def _has(repo: Path, ref: str, path: str) -> bool:
    return _run(['git', '-C', str(repo), 'cat-file', '-e', f'{ref}:{path}']).returncode == 0


def _extract(repo: Path, ref: str, paths: Iterable[str] | None, dest: Path) -> None:
    """`git archive` of `paths` at `ref` (the whole tree when `paths` is None), never the
    working tree. A path the commit does not carry is left out, not guessed at."""
    present = [] if paths is None else [p for p in paths if _has(repo, ref, p)]
    if paths is not None and not present:
        return
    data = subprocess.check_output(['git', '-C', str(repo), 'archive', ref, *present])
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(dest, filter='data')


def _tree_digest(root: Path) -> str:
    files = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(root.rglob('*')) if p.is_file()}
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


# ------------------------------------------------------------------------------- the engines

def identify(binaries: Iterable[str]) -> dict:
    """Each binary, by what it reports and what it hashes to. Never by its path."""
    engines: dict[str, dict] = {}
    unusable: list[dict] = []
    ambiguous: dict[str, list[dict]] = {}
    for given in binaries:
        resolved = shutil.which(given)
        if resolved is None:
            unusable.append({'binary': given, 'reason': 'Kyverno binary is unavailable'})
            continue
        try:
            identity = _run([resolved, 'version'])
        except (OSError, subprocess.SubprocessError) as exc:
            unusable.append({'binary': given, 'reason': f'Kyverno binary could not run: {exc}'})
            continue
        match = re.search(r'^Version:\s*v?(\d+\.\d+\.\d+)\s*$', identity.stdout, re.MULTILINE)
        if identity.returncode or not match:
            unusable.append({'binary': given, 'reason': 'Kyverno binary version could not be identified'})
            continue
        found = {'name': 'kyverno', 'version': match.group(1), 'binary': resolved,
                 'sha256': hashlib.sha256(Path(resolved).read_bytes()).hexdigest()}
        known = engines.get(found['version'])
        if known and known['sha256'] != found['sha256']:
            ambiguous.setdefault(found['version'], [known]).append(found)
        elif not known:
            engines[found['version']] = found
    for version in ambiguous:
        engines.pop(version, None)
    return {'engines': engines, 'unusable': unusable, 'ambiguous': ambiguous}


def declared_engines(value: Any) -> tuple[list[str] | None, str | None]:
    """A subject's `tested_engines`, or the reason there is no cell to grade."""
    if value is None:
        return None, ('declares no tested_engines, so it supports no engine (ADR-0033 point 3) '
                      'and there is no cell to grade')
    if not isinstance(value, dict):
        return None, 'tested_engines is not a mapping'
    scope = value.get('scope')
    if scope in RETIRED_SCOPES:
        return None, (f'tested_engines is scoped {scope}, which {RETIRED_SCOPES[scope]}; a declaration '
                      f'under the narrower meaning cannot pass under {SCOPE}')
    if scope != SCOPE:
        return None, f'tested_engines scope {scope!r} is not {SCOPE}'
    listed = value.get('kyverno')
    if (not isinstance(listed, list) or not listed or len(set(map(str, listed))) != len(listed)
            or not all(isinstance(v, str) and _VERSION.fullmatch(v) for v in listed)):
        return None, 'tested_engines.kyverno must be a non-empty list of distinct exact X.Y.Z strings'
    return list(listed), None


# ------------------------------------------------------------------------------- the bodies

def _is_policy(doc: Any) -> bool:
    return isinstance(doc, dict) and str(doc.get('apiVersion', '')).startswith(POLICY_GROUPS)


def _reaches_create(doc: dict) -> bool:
    """Whether the offline CLI can evaluate this body at all. The CLI evaluates every resource as
    a CREATE, so a body whose rules name no CREATE is graded on compiling and its gates only."""
    rules = ((doc.get('spec') or {}).get('matchConstraints') or {}).get('resourceRules')
    if not rules:
        return True
    return any('CREATE' in (r.get('operations') or []) or '*' in (r.get('operations') or [])
               for r in rules)


def bodies_in(tree: Path) -> tuple[list[dict], list[str]]:
    """Every file of a served tree that carries a Kyverno policy, and the files that carry none."""
    found, other = [], []
    for path in sorted(tree.glob('*.yaml')):
        docs = [d for d in yaml.safe_load_all(path.read_text()) if d is not None]
        policies = [d for d in docs if _is_policy(d)]
        if policies:
            found.append({'family': path.stem, 'path': path,
                          'names': [d['metadata']['name'] for d in policies],
                          'kinds': sorted({d['kind'] for d in policies}),
                          'reaches_create': any(_reaches_create(d) for d in policies),
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        else:
            other.append(path.name)
    return found, other


_ROW_START = re.compile(r'^\[', re.MULTILINE)


def _test_rows(output: str) -> list[dict] | None:
    """The rows `kyverno test -o json` prints, one JSON array per test manifest, or None when the
    output carries none. Each row names its POLICY, RESOURCE, RESULT (whether the row's assertion
    held) and REASON (why)."""
    decoder, rows, seen, pos = json.JSONDecoder(), [], False, 0
    while (start := _ROW_START.search(output, pos)) is not None:
        try:
            value, pos = decoder.raw_decode(output, start.start())
        except json.JSONDecodeError:
            pos = start.end()
            continue
        if isinstance(value, list) and all(isinstance(r, dict) and {'RESULT', 'REASON'} <= r.keys()
                                           for r in value):
            rows.extend(value)
            seen = True
    return rows if seen else None


def _asserted(results: list[dict]) -> dict[tuple[str, str], set[str]]:
    """(policy, resource name) -> every result the fixture's rows assert for that pair."""
    out: dict[tuple[str, str], set[str]] = {}
    for r in results:
        for resource in r.get('resources') or []:
            key = (str(r.get('policy')), str(resource).rsplit('/', 1)[-1])
            out.setdefault(key, set()).add(str(r.get('result') or r.get('status')))
    return out


def _excluded(rows: list[dict], results: list[dict]) -> list[str]:
    """Every row the engine did not apply the policy to, where the fixture asserts pass or fail.

    Kyverno counts a resource the policy is not applied to (REASON `Excluded`: no engine response
    at all, as for a Pod in a Namespace the CLI does not know, against a `namespaceSelector`) as a
    PASS whatever the row asserts. Such a pass or fail row measures nothing the body does, so it
    is refused here. A skip row may read Excluded: it asserts the body does not act, and it fails
    with "Want skip" if the body does act. Measured on 1.18.2, 2026-09-26 (ticket 146 fixer)."""
    asserted = _asserted(results)
    vacuous = []
    for row in rows:
        if row.get('REASON') != 'Excluded':
            continue
        key = (str(row.get('POLICY')), str(row.get('RESOURCE', '')).rsplit('/', 1)[-1])
        wants = asserted.get(key)
        if not wants or wants - {'skip'}:
            vacuous.append(f'{row.get("POLICY")} on {row.get("RESOURCE")} reads Excluded where the '
                           f'fixture asserts {"/".join(sorted(wants or {"no row"}))}')
    return vacuous


def _summary(run: subprocess.CompletedProcess[str], results: list[dict]) -> tuple[bool, dict]:
    """One `kyverno test -o json` run, read row by row. It passes only when the engine exits 0,
    prints one summary with at least one passed and no failed assertion, prints one row per
    counted assertion, and no pass or fail row reads Excluded (see `_excluded`)."""
    output = run.stdout + run.stderr
    summaries = re.findall(r'Test Summary:\s*(\d+) tests passed and (\d+) tests failed', output)
    passed, failed = (map(int, summaries[0]) if len(summaries) == 1 else (0, 0))
    rows = _test_rows(output)
    reasons: dict[str, int] = {}
    for row in rows or []:
        reasons[str(row.get('REASON'))] = reasons.get(str(row.get('REASON')), 0) + 1
    refusals = []
    if rows is None:
        refusals.append('the engine printed no per-row results, so a row it did not apply the '
                        'policy to cannot be told from one that passed')
    elif len(rows) != passed + failed:
        refusals.append(f'the engine printed {len(rows)} rows for {passed + failed} counted assertions')
    else:
        refusals += _excluded(rows, results)
    ok = (run.returncode == 0 and passed > 0 and failed == 0 and len(summaries) == 1
          and not refusals)
    return ok, {'passed_assertions': passed, 'failed_assertions': failed,
                'row_reasons': reasons, 'refusals': refusals,
                'exit_code': run.returncode,
                'output_sha256': hashlib.sha256(output.encode()).hexdigest(),
                'diagnostic': None if ok else output[-6000:]}


def run_fixture(folder: Path, body: dict, binary: str) -> dict:
    """One served body against its own fixture. Only `policies:` is rewritten, to the served bytes.

    The fixture must name the body: every row names one of the file's policies, and every policy
    in the file is named by a row, so a fixture cannot pass by testing something else. A body the
    CLI can evaluate needs at least one row that asserts pass or fail."""
    manifest = folder / 'kyverno-test.yaml'
    test = yaml.safe_load(manifest.read_text())
    results = test.get('results') or []
    if not results:
        raise ValueError(f'{body["family"]}: the fixture has no results')
    named = {r.get('policy') for r in results}
    stray = sorted(str(n) for n in named - set(body['names']))
    if stray:
        raise ValueError(f'{body["family"]}: fixture rows name {stray}, which is not a policy in the served file')
    missing = sorted(set(body['names']) - named)
    if missing:
        raise ValueError(f'{body["family"]}: no fixture row names {missing}')
    if body['reaches_create'] and not any(r.get('result') in ('pass', 'fail') for r in results):
        raise ValueError(f'{body["family"]}: the fixture asserts only skip rows for a body the CLI can '
                         'evaluate, so it grades nothing the body does')
    test['policies'] = [str(body['path'])]
    manifest.write_text(yaml.safe_dump(test, sort_keys=False))
    ok, facts = _summary(_run([binary, 'test', str(folder), '-o', 'json']), results)
    return {'family': body['family'], 'policies': body['names'], 'fixture': 'engine-fixtures',
            'outcome': 'passed' if ok else 'failed', **facts}


def _doc_key(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True)


def run_generation(folder: Path, body: dict, binary: str) -> dict:
    """A generator graded on what it GENERATES, trigger by trigger (hub ADR-0033 point 6).

    `generates.yaml` names each trigger in the folder's resources and the documents the body must
    generate for it; an empty list is a "generates nothing" check. For each trigger the grader runs
    `kyverno apply <body> --resource <that trigger> -o <dir>` and compares the generated documents
    with the expected ones as parsed YAML. It never reads how the engine REPORTS a trigger it does
    not match: Kyverno 1.18.2's `kyverno test` reads such a trigger as Pass / Excluded even on a row
    that expects a generated resource, and 1.19 returns no result at all (upstream PR #16505)."""
    spec = yaml.safe_load((folder / 'generates.yaml').read_text()) or {}
    triggers = spec.get('triggers') or []
    if not triggers:
        raise ValueError(f'{body["family"]}: generates.yaml names no trigger')
    if not any(t.get('generates') for t in triggers):
        raise ValueError(f'{body["family"]}: generates.yaml expects nothing from every trigger, so it '
                         'grades nothing the body generates')
    pool = [d for d in yaml.safe_load_all((folder / spec.get('resources', 'resources.yaml')).read_text())
            if isinstance(d, dict)]
    values = folder / spec['values'] if spec.get('values') else None
    checked = []
    for t in triggers:
        name = t.get('resource')
        match = [d for d in pool if (d.get('metadata') or {}).get('name') == name]
        if len(match) != 1:
            raise ValueError(f'{body["family"]}: trigger {name!r} is not exactly one resource in the fixture')
        want_file = t.get('generates')
        want = ([d for d in yaml.safe_load_all((folder / want_file).read_text()) if isinstance(d, dict)]
                if want_file else [])
        work = folder / f'.trigger-{name}'
        work.mkdir()
        (work / 'trigger.yaml').write_text(yaml.safe_dump(match[0], sort_keys=False))
        args = [binary, 'apply', str(body['path']), '--resource', str(work / 'trigger.yaml'),
                '-o', str(work / 'out')]
        if values is not None:
            args += ['-f', str(values)]
        run = _run(args)
        output = run.stdout + run.stderr
        errors = re.findall(r'error: (\d+)', output)
        if run.returncode or not errors or any(e != '0' for e in errors) or re.search(r'^Error:', output, re.M):
            return {'family': body['family'], 'fixture': 'generates.yaml', 'outcome': 'failed',
                    'trigger': name, 'exit_code': run.returncode, 'diagnostic': output[-6000:]}
        out = work / 'out'
        files = sorted(out.glob('*-generated.yaml')) if out.is_dir() else []
        got = [d for f in files for d in yaml.safe_load_all(f.read_text()) if isinstance(d, dict)]
        if sorted(map(_doc_key, got)) != sorted(map(_doc_key, want)):
            return {'family': body['family'], 'fixture': 'generates.yaml', 'outcome': 'failed',
                    'trigger': name, 'expected': want, 'generated': got}
        checked.append({'trigger': name, 'documents': len(got)})
    return {'family': body['family'], 'fixture': 'generates.yaml', 'outcome': 'passed', 'triggers': checked}


def _adapt(value: Any, version: str) -> None:
    """Change version-scoping identifiers only, never expected dial/reach values."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'policy-as-versioned.dev/policy-version':
                value[key] = version
            elif key == 'priorityClassName' and isinstance(item, str) and item in (
                    'cage-baseline', 'cage-restricted', 'cage-quarantine', 'cage-isolated'):
                value[key] = item + '-' + version.replace('.', '-')
            else:
                _adapt(item, version)
    elif isinstance(value, list):
        for item in value:
            _adapt(item, version)


def run_legacy_fixture(folder: Path, body: dict, version: str, binary: str) -> dict:
    """cage-tier and cage-netpol, graded from the line's own authoring fixture (the format the
    tagged 5.0.0 tree carries). Only policy/rule identifiers, claim version labels and PriorityClass
    suffixes are adapted, so the unversioned fixture exercises the released version-scoped body."""
    family = body['family']
    manifest = folder / 'kyverno-test.yaml'
    test = yaml.safe_load(manifest.read_text())
    results = test.get('results', [])
    if not results or not any(r.get('result') == 'pass' for r in results):
        raise ValueError(f'{family}: no positive assertions in published fixture')
    for path in folder.glob('*.yaml'):
        if path == manifest:
            continue
        docs = list(yaml.safe_load_all(path.read_text()))
        for doc in docs:
            _adapt(doc, version)
            # Authoring generator fixtures are unversioned. Select the released
            # policy without changing their caged/tier labels or reach assertions.
            if family == 'cage-netpol' and path.name == 'resources.yaml' and isinstance(doc, dict):
                doc['metadata'].setdefault('labels', {})['policy-as-versioned.dev/policy-version'] = version
        path.write_text(yaml.safe_dump_all(docs, sort_keys=False))
    test['policies'] = [str(body['path'])]
    for result in results:
        result['policy'] = family + '-' + version.replace('.', '-')
        result['rule'] = result['policy']
    manifest.write_text(yaml.safe_dump(test, sort_keys=False))
    ok, facts = _summary(_run([binary, 'test', str(folder), '-o', 'json']), results)
    return {'family': family, 'policies': body['names'], 'fixture': 'graded/tests (adapted)',
            'outcome': 'passed' if ok else 'failed', **facts}


def _grade_body(body: dict, fixture: Path | None, legacy: Path | None, version: str | None,
                binary: str, work: Path) -> dict:
    """One body against every fixture it has. For cage-tier and cage-netpol the line tree's own
    `graded/tests/<family>` (read from the tag once cut) is ALWAYS run when the tree carries it;
    an `engine-fixtures` folder at the graded commit, if there is one, runs as well and never
    replaces it. So nothing committed after a cut can swap a weaker fixture in for the tag-bound
    grade. Every part must pass."""
    base = {'family': body['family'], 'policies': body['names'], 'body_sha256': body['sha256']}
    try:
        parts = []
        if legacy is not None and version is not None and (legacy / 'kyverno-test.yaml').is_file():
            folder = work / ('legacy-' + body['family'])
            shutil.copytree(legacy, folder)
            parts.append(run_legacy_fixture(folder, body, version, binary))
        if fixture is not None and fixture.is_dir():
            folder = work / ('fixture-' + body['family'])
            shutil.copytree(fixture, folder)
            found = []
            if (folder / 'kyverno-test.yaml').is_file():
                found.append(run_fixture(folder, body, binary))
            if (folder / 'generates.yaml').is_file():
                found.append(run_generation(folder, body, binary))
            if not found:
                raise ValueError(f'{body["family"]}: its fixture folder carries neither kyverno-test.yaml '
                                 'nor generates.yaml')
            parts += found
        if not parts:
            return {**base, 'outcome': 'failed',
                    'reason': (f'{body["family"]} has no fixture, so it is not graded; a supported engine '
                               'means every body the subject serves passes its fixtures')}
        return {**base, 'fixture': ' + '.join(dict.fromkeys(p['fixture'] for p in parts)),
                'outcome': 'passed' if all(p['outcome'] == 'passed' for p in parts) else 'failed',
                'parts': parts}
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        return {**base, 'outcome': 'failed', 'reason': str(exc)}


def _cell(engine: str, found: dict, bodies: list[dict], fixture_for, legacy_for,
          version: str | None) -> dict:
    if engine in found['ambiguous']:
        return {'engine': engine, 'outcome': 'could-not-look',
                'reason': f'two binaries report kyverno {engine} with different digests'}
    binary = found['engines'].get(engine)
    if binary is None:
        return {'engine': engine, 'outcome': 'could-not-look',
                'reason': f'no binary for kyverno {engine} was handed to this run'}
    with tempfile.TemporaryDirectory() as temp:
        results = [_grade_body(b, fixture_for(b), legacy_for(b), version, binary['binary'], Path(temp))
                   for b in bodies]
    outcome = 'passed' if bodies and all(r['outcome'] == 'passed' for r in results) else 'failed'
    return {'engine': engine, 'binary_sha256': binary['sha256'], 'outcome': outcome, 'bodies': results}


def _roll(outcomes: list[str]) -> str:
    return ('failed' if 'failed' in outcomes else
            'could-not-look' if 'could-not-look' in outcomes or not outcomes else 'passed')


# ------------------------------------------------------------------------------- the subjects

def _line_source(repo: Path, entry: dict, head: str) -> dict:
    """Where a line's bytes come from: its tag once cut, the declaring commit before."""
    version = entry.get('version')
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ValueError(f'{version!r} is not an exact X.Y.Z policy version')
    if not entry.get('commit'):
        return {'state': 'candidate', 'ref': head, 'candidate_commit': head}
    tag, commit = entry.get('tag'), entry['commit']
    if tag != 'policy/v' + version:
        raise ValueError('published policy requires its exact policy/vX.Y.Z tag')
    if not re.fullmatch(r'[a-f0-9]{40}', str(commit)):
        raise ValueError('published array commit must be a full SHA')
    ref = 'refs/tags/' + tag
    for source in (ref, commit):
        if _run(['git', '-C', str(repo), 'cat-file', '-e', source]).returncode:
            raise SourceUnavailable(f'historical Git input unavailable: {source}')
    if _git(repo, 'cat-file', '-t', ref) != 'tag':
        raise ValueError('published policy tag is not annotated')
    path = 'distribution/policies/v' + version
    tree = _git(repo, 'rev-parse', ref + ':' + path)
    if tree != _git(repo, 'rev-parse', commit + ':' + path):
        raise ValueError('tag policy tree differs from the array-pinned policy tree')
    return {'state': 'published', 'ref': ref, 'tag': tag, 'array_commit': commit,
            'tag_commit': _git(repo, 'rev-parse', ref + '^{commit}')}


def _line_row(repo: Path, head: str, entry: dict, found: dict) -> dict:
    version = entry.get('version')
    row: dict[str, Any] = {'subject': f'policy {version}', 'kind': 'line', 'policy_version': version}
    listed, why = declared_engines(entry.get('tested_engines'))
    if listed is None:
        return {**row, 'outcome': 'could-not-look', 'reason': why}
    row['declared'] = listed
    try:
        source = _line_source(repo, entry, head)
    except SourceUnavailable as exc:
        return {**row, 'outcome': 'could-not-look', 'reason': str(exc)}
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as exc:
        return {**row, 'outcome': 'failed', 'reason': str(exc)}
    row.update(source)
    path = 'distribution/policies/v' + version
    fixtures = f'{FIXTURES}/v{version}'
    with tempfile.TemporaryDirectory() as temp:
        tree, fx = Path(temp) / 'line', Path(temp) / 'fixtures'
        try:
            _extract(repo, source['ref'], [path, 'graded/tests'], tree)
            _extract(repo, head, [fixtures], fx)
            policy_dir = tree / path
            if not policy_dir.is_dir():
                raise ValueError(f'{source["ref"]} carries no {path}')
            row['policy_tree'] = _git(repo, 'rev-parse', f'{source["ref"]}:{path}')
            row['policy_sha256'] = _tree_digest(policy_dir)
            row['fixtures_commit'] = head
            row['fixtures_sha256'] = _tree_digest(fx / fixtures) if (fx / fixtures).is_dir() else None
            apis = sorted({doc['apiVersion'] for p in policy_dir.glob('*.yaml')
                           for doc in yaml.safe_load_all(p.read_text())
                           if isinstance(doc, dict) and 'apiVersion' in doc})
            row['api_versions'] = apis
            row['prerelease_api_versions'] = [a for a in apis if re.search(r'/v\d+(alpha|beta)', a)]
            bodies, other = bodies_in(policy_dir)
            row['bodies'] = [b['family'] for b in bodies]
            row['not_bodies'] = other
            if not bodies:
                raise ValueError(f'{path} carries no Kyverno policy')
        except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError, yaml.YAMLError) as exc:
            return {**row, 'outcome': 'failed', 'reason': str(exc)}

        def fixture_for(b: dict) -> Path:
            return fx / fixtures / b['family']

        def legacy_for(b: dict) -> Path | None:
            return tree / 'graded/tests' / b['family'] if b['family'] in LEGACY_FAMILIES else None

        row['cells'] = [_cell(e, found, bodies, fixture_for, legacy_for, version) for e in listed]
    row['outcome'] = _roll([c['outcome'] for c in row['cells']])
    return row


_RENDER = r'''
import importlib.util, json, sys, yaml
from pathlib import Path
root, out = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("composition_under_grade", root / "compose" / "composition.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
index = []
for m in mod.machinery_members(root):
    name = m["member_name"]
    (out / (name + ".yaml")).write_text(yaml.safe_dump(m["doc"], sort_keys=False))
    index.append({"member": name, "kind": m["doc"].get("kind"), "out_path": m.get("out_path")})
print(json.dumps(index))
'''


def _machinery_row(repo: Path, head: str, found: dict) -> dict:
    row: dict[str, Any] = {'subject': 'machinery', 'kind': 'machinery', 'declaration': MACHINERY}
    if not _has(repo, head, MACHINERY):
        return {**row, 'outcome': 'could-not-look',
                'reason': f'{MACHINERY} is absent at {head[:12]}: the machinery declares no tested_engines'}
    try:
        declaration = yaml.safe_load(_git(repo, 'show', f'{head}:{MACHINERY}')) or {}
    except (ValueError, yaml.YAMLError) as exc:
        return {**row, 'outcome': 'failed', 'reason': f'{MACHINERY} unreadable: {exc}'}
    listed, why = declared_engines(declaration.get('tested_engines') if isinstance(declaration, dict) else None)
    if listed is None:
        return {**row, 'outcome': 'could-not-look', 'reason': why}
    row.update({'declared': listed, 'state': 'graded commit', 'ref': head})
    with tempfile.TemporaryDirectory() as temp:
        tree, rendered = Path(temp) / 'tree', Path(temp) / 'rendered'
        rendered.mkdir()
        try:
            _extract(repo, head, None, tree)
            render = _run([sys.executable, '-c', _RENDER, str(tree), str(rendered)])
            if render.returncode:
                raise ValueError('the composer could not render the machinery: '
                                 + (render.stderr.strip().splitlines() or ['no output'])[-1])
            row['members'] = json.loads(render.stdout)
            bodies, other = bodies_in(rendered)
            row['bodies'] = [b['family'] for b in bodies]
            row['not_bodies'] = other
            row['fixtures_sha256'] = (_tree_digest(tree / FIXTURES / 'machinery')
                                      if (tree / FIXTURES / 'machinery').is_dir() else None)
            if not bodies:
                raise ValueError('the composer rendered no machinery policy')
        except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError,
                yaml.YAMLError, json.JSONDecodeError) as exc:
            return {**row, 'outcome': 'failed', 'reason': str(exc)}
        row['cells'] = [_cell(e, found, bodies, lambda b: tree / FIXTURES / 'machinery' / b['family'],
                              lambda b: None, None) for e in listed]
    row['outcome'] = _roll([c['outcome'] for c in row['cells']])
    return row


# ------------------------------------------------------------------------------- the seam

def check(repo: Path, engines: Iterable[str] | str = ('kyverno',), ref: str = 'HEAD') -> dict:
    """Public seam. A missing or undeclared instrument never reports compatibility."""
    if isinstance(engines, str):
        engines = [engines]
    report: dict[str, Any] = {'schema': 2, 'scope': SCOPE, 'outcome': 'could-not-look',
                              'graded_commit': None, 'engines': [], 'extra_engines': [],
                              'unusable_engines': [], 'rows': [], 'limits': LIMITS}
    found = identify(engines)
    report['engines'] = list(found['engines'].values())
    report['unusable_engines'] = found['unusable']
    report['ambiguous_engines'] = {v: [e['sha256'] for e in es] for v, es in found['ambiguous'].items()}
    if not found['engines'] and not found['ambiguous']:
        reasons = sorted({u['reason'] for u in found['unusable']}) or ['no engine was handed in']
        return {**report, 'reason': '; '.join(reasons)}
    try:
        head = _git(repo, 'rev-parse', ref + '^{commit}')
        report['graded_commit'] = head
        doc = yaml.safe_load(_git(repo, 'show', f'{head}:distribution/versions.yaml'))
        entries = doc['spec']['inputs'][0]['versions']
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            raise ValueError('declared policy lines must be a list of array elements')
        if not entries:
            return {**report, 'reason': 'no declared policy lines'}
        rows = [_line_row(repo, head, entry, found) for entry in entries]
        rows.append(_machinery_row(repo, head, found))
        report['rows'] = rows
        listed = {v for r in rows for v in r.get('declared', [])}
        report['extra_engines'] = [
            {'version': v, 'sha256': e['sha256'],
             'note': 'no line and no machinery lists this engine; it is reported, never read as support'}
            for v, e in sorted(found['engines'].items()) if v not in listed]
        report['matrix'] = {r['subject']: {c['engine']: c['outcome'] for c in r.get('cells', [])}
                            for r in rows}
        report['outcome'] = _roll([r['outcome'] for r in rows])
        return report
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        return {**report, 'outcome': 'failed', 'reason': str(exc)}


def matrix_table(report: dict) -> str:
    """The whole matrix, one line per subject, one column per engine a subject lists or a binary
    brought. `-` is a cell nobody lists; an extra engine's column is all `-` by construction."""
    rows = report.get('rows') or []
    columns = sorted({c['engine'] for r in rows for c in r.get('cells', [])}
                     | {e['version'] for e in report.get('extra_engines', [])},
                     key=lambda v: tuple(int(x) for x in v.split('.')))
    width = max([len(r['subject']) for r in rows] + [7])
    lines = ['subject'.ljust(width) + '  ' + '  '.join(c.ljust(14) for c in columns) + '  row']
    for r in rows:
        cells = {c['engine']: c['outcome'] for c in r.get('cells', [])}
        lines.append(r['subject'].ljust(width) + '  ' +
                     '  '.join(cells.get(c, '-').ljust(14) for c in columns) + '  ' + r['outcome'] +
                     (f' ({r["reason"]})' if r.get('reason') else ''))
    return '\n'.join(lines)


def _count(report: dict) -> str:
    cells = [c['outcome'] for r in report.get('rows', []) for c in r.get('cells', [])]
    parts = [f'{cells.count(o)} {o}' for o in ('passed', 'failed', 'could-not-look') if cells.count(o)]
    extra = ', '.join(e['version'] for e in report.get('extra_engines', []))
    return (f'{len(cells)} cell(s): ' + (', '.join(parts) or 'none') +
            (f'; extra engine(s) reported, not support: {extra}' if extra else ''))


def not_passed(report: dict) -> str:
    """Every subject or cell that did not pass, by name, so the verdict line alone says which
    engine is missing or failing and why."""
    named = []
    for r in report.get('rows') or []:
        if not r.get('cells') and r.get('outcome') != 'passed':
            named.append(f'{r["subject"]} {r.get("outcome")} ({r.get("reason")})')
        for c in r.get('cells', []):
            if c['outcome'] == 'could-not-look':
                named.append(f'{r["subject"]} on {c["engine"]} could-not-look ({c.get("reason")})')
            elif c['outcome'] == 'failed':
                bodies = [b['family'] for b in c.get('bodies', []) if b['outcome'] != 'passed']
                named.append(f'{r["subject"]} on {c["engine"]} failed ({", ".join(bodies)})')
    return '; not passed: ' + '; '.join(named) if named else ''


def served(report: dict) -> str:
    """What the verdict line was measured against: the platform commit graded, and for each
    subject the ref its bodies were read from by `git archive` before `kyverno test` and
    `kyverno apply` ran them. A cut line names its tag and the commit the tag points at."""
    if not report.get('graded_commit'):
        return ''
    where = []
    for r in report.get('rows') or []:
        if r.get('state') == 'published':
            where.append(f'{r["subject"]} from {r["ref"]} at {r["tag_commit"]}')
        elif r.get('state') == 'candidate':
            where.append(f'{r["subject"]} (uncut candidate) from the graded commit')
        elif r.get('state') == 'graded commit':
            where.append(f'{r["subject"]} rendered by compose/composition.py at the graded commit')
    return (f'; graded platform commit {report["graded_commit"]}' +
            (': ' + ', '.join(where) if where else '') +
            '; each body read by git archive at that ref and run by the kyverno binaries above')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--ref', default='HEAD', help='the commit to grade (default HEAD)')
    parser.add_argument('--engine', action='append', default=[],
                        help='a Kyverno binary; repeat for each engine')
    parser.add_argument('--engine-dir', action='append', default=[], type=Path,
                        help='a directory holding <version>/kyverno, as install-kyverno-engines.sh writes it')
    args = parser.parse_args(argv)
    binaries = list(args.engine)
    for d in args.engine_dir:
        binaries += [str(p) for p in sorted(d.glob('*/kyverno'))]
    # The CLI on PATH only when the caller named no engine at all. A named directory that holds
    # no binary is an instrument that did not arrive, not a reason to grade a different one.
    if not args.engine and not args.engine_dir:
        binaries = ['kyverno']
    result = check(args.repo, binaries, args.ref)
    print(json.dumps(result, indent=2))
    print(matrix_table(result))
    code = {'passed': 0, 'failed': 1, 'could-not-look': 3}[result['outcome']]
    reason = f' -- {result["reason"]}' if result.get('reason') else ''
    print(('PASS' if code == 0 else 'FAIL' if code == 1 else 'SKIP') +
          f': engine cells -- {result["outcome"]}; {_count(result)}{reason}{not_passed(result)}'
          f'{served(result)}')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
