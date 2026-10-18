"""Authenticated monetary quality, consumed before ordinary FAIR pricing.

Only original Git objects are portable authority: a saved composition rechecks
its captured certificates, exact source identities and report reconstruction.
A diagnostic report never becomes a separate exposure or insurance credit.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import date

PORTABLE = 'composed/publisher-reliability/sources.json'
_LIMIT = 268435456
_REF_KEYS = {'party', 'tag', 'commit', 'path', 'git_blob'}
_PARTY = re.compile(r'[a-z0-9][a-z0-9-]*')
_SHA = re.compile(r'[0-9a-f]{40}')
_TAG = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]*')
_RANK = {'none': 0, 'patch': 1, 'minor': 2, 'major': 3}


class Refused(ValueError):
    """A declared monetary instrument cannot safely affect this composition."""


@dataclass
class AdjustedScenario:
    scenario: dict
    effect: dict | None


def _party(adopter, captured: bytes | None = None):
    schema_path = Path(__file__).resolve().parent.parent / 'party/party_artefact.py'
    spec = importlib.util.spec_from_file_location('_publisher_quality_party', schema_path)
    if spec is None or spec.loader is None:
        raise Refused('publisher-reliability: party declaration validator unavailable')
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    path = Path(adopter) / 'party.yaml'
    try:
        before = path.read_bytes() if captured is None else captured
        document = validator.parse_document(before)
        after = path.read_bytes()
    except (validator.Refused, OSError) as error:
        raise Refused('publisher-reliability: ' + str(error)) from error
    if after != before or not isinstance(document, dict):
        raise Refused('publisher-reliability: adopter declaration changed or is not an object')
    return validator, document, before


def _json(raw: bytes | str, *, limit=33554432):
    if len(raw) > limit:
        raise Refused('publisher-reliability resource-limit: record exceeds its byte bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Refused('publisher-reliability: duplicate JSON key ' + key)
            result[key] = value
        return result
    def nonfinite(value):
        raise Refused('publisher-reliability: nonfinite JSON number ' + value)
    def numeric(token):
        mantissa, _, exponent = token.lower().partition('e')
        digits = mantissa.replace('.', '').lstrip('-').lstrip('0') or '0'
        if len(digits) > 128 or (exponent and (len(exponent.lstrip('+-')) > 3 or abs(int(exponent)) > 128)):
            raise Refused('publisher-reliability resource-limit: numeric token exceeds decimal bounds')
        number = Decimal(token)
        if abs(number.as_tuple().exponent) > 128:
            raise Refused('publisher-reliability resource-limit: decimal scale exceeds bounds')
        if number.is_signed() and number.is_zero():
            raise Refused('publisher-reliability: negative-zero monetary numeric token')
        if '.' not in token and not exponent:
            return int(token)
        value = float(number)
        if not math.isfinite(value) or Decimal(str(value)) != number:
            raise Refused('publisher-reliability: monetary numeric token is not engine-representable')
        return value
    def bounded(value, depth=0):
        if depth > 32:
            raise Refused('publisher-reliability resource-limit: record nesting exceeds 32')
        if isinstance(value, dict):
            for item in value.values():
                bounded(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                bounded(item, depth + 1)
    try:
        result = json.loads(raw, object_pairs_hook=unique, parse_float=numeric,
                            parse_int=numeric, parse_constant=nonfinite)
        bounded(result)
        return result
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refused('publisher-reliability: malformed JSON instrument') from error


def _canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    except (ValueError, OverflowError) as error:
        raise Refused('publisher-reliability: nonfinite or unrepresentable instrument') from error


def _git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(['git', '-C', str(root), *args], input=data,
            capture_output=True, timeout=120, env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1'))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refused('publisher-reliability: required Git operation unavailable') from error
    if result.returncode:
        raise Refused('publisher-reliability: required Git object unavailable (' + args[0] + ')')
    return result.stdout


def _relative(value):
    if (not isinstance(value, str) or not value or value.startswith('/') or '\\' in value or
            any(p in ('', '.', '..', '.git') for p in value.split('/')) or
            any(ord(c) < 32 for c in value)):
        raise Refused('publisher-reliability: unsafe repository-relative path')
    return value


def _reference(value):
    if (not isinstance(value, dict) or set(value) != _REF_KEYS or
            not isinstance(value.get('party'), str) or not _PARTY.fullmatch(value['party']) or
            not isinstance(value.get('tag'), str) or not _TAG.fullmatch(value['tag']) or
            any(x in value['tag'] for x in ('..', '//', '@{')) or value['tag'].endswith('.lock') or
            any(not isinstance(value.get(k), str) or not _SHA.fullmatch(value[k])
                for k in ('commit', 'git_blob'))):
        raise Refused('publisher-reliability: malformed exact SourceRef')
    _relative(value['path'])
    return value


def _origin(party: str) -> str:
    return f'https://github.com/policy-as-versioned-{party}/{party}'


def _canonical_origin(actual: str, party: str) -> bool:
    repository = f'policy-as-versioned-{party}/{party}'
    return actual in (_origin(party), _origin(party) + '.git',
                      'git@github.com:' + repository, 'git@github.com:' + repository + '.git',
                      'ssh://git@github.com/' + repository, 'ssh://git@github.com/' + repository + '.git')


def _regular_clone(root: Path, party: str):
    if not (root / '.git').is_dir() or (root / '.git').is_symlink() or root.is_symlink():
        raise Refused(f'publisher-reliability: canonical full regular source clone required for {party}')
    if (_git(root, 'rev-parse', '--show-toplevel').decode().strip() != str(root.resolve()) or
            _git(root, 'rev-parse', '--path-format=absolute', '--git-common-dir').decode().strip()
            != str((root / '.git').resolve()) or
            _git(root, 'rev-parse', '--is-shallow-repository').strip() != b'false' or
            (root / '.git/objects/info/alternates').exists() or
            list((root / '.git/objects/pack').glob('*.promisor'))):
        raise Refused('publisher-reliability: complete unshared source history is required')
    actual = _git(root, 'config', '--get', 'remote.origin.url').decode().strip()
    if not _canonical_origin(actual, party):
        raise Refused('publisher-reliability: source origin is not canonical for ' + party)


def _pack(root, tips, remaining):
    # Spool before decoding: an oversized source pack must not allocate an
    # unbounded stdout bytes object merely to discover its size afterwards.
    with tempfile.TemporaryFile() as packed:
        try:
            result = subprocess.run(['git', '-C', str(root), 'pack-objects', '--stdout', '--revs'],
                input=('\n'.join(tips) + '\n').encode(), stdout=packed, stderr=subprocess.PIPE,
                timeout=120, env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1'))
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Refused('publisher-reliability: original source closure could not be captured') from error
        if result.returncode:
            raise Refused('publisher-reliability: original source closure is incomplete')
        if packed.tell() > remaining:
            raise Refused('publisher-reliability resource-limit: captured Git closure exceeds 256 MiB')
        packed.seek(0)
        return packed.read()


def _capture(roots: dict[str, Path], required: set[str]) -> dict:
    records = {}
    total = 0
    for party, location in sorted(roots.items()):
        root = Path(location).resolve()
        # Ordinary nonparticipating fixture publishers need no monetary authority.
        if party not in required and not (root / '.git').is_dir():
            continue
        if not _PARTY.fullmatch(party):
            continue
        if party not in required:
            try:
                actual = _git(root, 'config', '--get', 'remote.origin.url').decode().strip()
            except Refused:
                continue
            if not _canonical_origin(actual, party):
                continue
        _regular_clone(root, party)
        main = _git(root, 'rev-parse', '--verify', 'refs/remotes/origin/main^{commit}').decode().strip()
        tags = {}
        for line in _git(root, 'for-each-ref', '--format=%(refname) %(objectname)', 'refs/tags').decode().splitlines():
            ref, oid = line.split()
            tags[ref.removeprefix('refs/tags/')] = oid
        packed = _pack(root, [main, *tags.values()], _LIMIT - total)
        total += len(packed)
        if total > _LIMIT:
            raise Refused('publisher-reliability resource-limit: captured Git closure exceeds 256 MiB')
        records[party] = {'origin': _origin(party), 'served_main': main, 'tags': tags,
                          'pack_sha256': hashlib.sha256(packed).hexdigest(),
                          'pack_base64': base64.b64encode(packed).decode()}
    missing = required - records.keys()
    if missing:
        raise Refused('publisher-reliability: canonical source checkout for ' + sorted(missing)[0] + ' is absent')
    return {'schema': 'publisher-reliability/source-closure-v1', 'sources': records}


def _restore(closure: dict, destination: Path) -> dict[str, Path]:
    if (not isinstance(closure, dict) or set(closure) != {'schema', 'sources'} or
            closure['schema'] != 'publisher-reliability/source-closure-v1' or
            not isinstance(closure['sources'], dict)):
        raise Refused('publisher-reliability: malformed original source closure')
    result = {}
    total = 0
    for party, record in closure['sources'].items():
        if (not isinstance(party, str) or not _PARTY.fullmatch(party) or not isinstance(record, dict) or
                set(record) != {'origin', 'served_main', 'tags', 'pack_sha256', 'pack_base64'} or
                record['origin'] != _origin(party) or not isinstance(record['served_main'], str) or
                not _SHA.fullmatch(record['served_main']) or not isinstance(record['tags'], dict) or
                not isinstance(record['pack_base64'], str) or len(record['pack_base64']) > (_LIMIT * 4 // 3 + 4)):
            raise Refused('publisher-reliability: malformed captured canonical source')
        try:
            packed = base64.b64decode(record['pack_base64'], validate=True)
        except (ValueError, TypeError) as error:
            raise Refused('publisher-reliability: invalid original Git pack encoding') from error
        total += len(packed)
        if total > _LIMIT or hashlib.sha256(packed).hexdigest() != record['pack_sha256']:
            raise Refused('publisher-reliability: original Git pack changed or exceeds resource limit')
        root = destination / party
        root.mkdir()
        _git(root, 'init', '-q', '-b', 'main')
        _git(root, 'index-pack', '--stdin', data=packed)
        _git(root, 'config', 'remote.origin.url', record['origin'])
        _git(root, 'update-ref', 'refs/remotes/origin/main', record['served_main'])
        _git(root, 'update-ref', 'refs/heads/main', record['served_main'])
        for tag, oid in record['tags'].items():
            if (not isinstance(tag, str) or not tag or
                    not isinstance(oid, str) or not _SHA.fullmatch(oid)):
                raise Refused('publisher-reliability: invalid original tag reference')
            _git(root, 'check-ref-format', 'refs/tags/' + tag)
            _git(root, 'update-ref', 'refs/tags/' + tag, oid)
        _git(root, 'fsck', '--full', '--no-reflogs')
        result[party] = root
    return result


def _verify_tag(repo: Path, party: str, tag: str, commit: str):
    """External certificate verifier; source tests replace only this boundary."""
    ref = 'refs/tags/' + tag
    oid = _git(repo, 'rev-parse', '--verify', ref).decode().strip()
    if _git(repo, 'cat-file', '-t', oid).strip() != b'tag':
        raise Refused('publisher-reliability: publication requires an original annotated signed tag')
    header = _git(repo, 'cat-file', 'tag', oid).split(b'\n\n', 1)[0].splitlines()
    if header[:3] != [f'object {commit}'.encode(), b'type commit', f'tag {tag}'.encode()]:
        raise Refused('publisher-reliability: original tag name/source differs from exact pin')
    identity = _origin(party) + '/.github/workflows/cut-release.yml@refs/heads/main'
    try:
        checked = subprocess.run(['gitsign', 'verify-tag', tag,
            '--certificate-identity=' + identity,
            '--certificate-oidc-issuer=https://token.actions.githubusercontent.com'], cwd=repo,
            capture_output=True, timeout=120,
            env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1', GITSIGN_REKOR_MODE='offline'))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refused('publisher-reliability: offline original certificate verifier unavailable') from error
    facts = (b'Good signature from', b'Validated Git signature: true',
             b'Validated Rekor entry: true', b'Validated Certificate claims: true')
    if checked.returncode or not all(fact in checked.stdout + checked.stderr for fact in facts):
        raise Refused('publisher-reliability: original certificate refuses pinned identity/issuer')
    if _git(repo, 'rev-parse', ref).decode().strip() != oid:
        raise Refused('publisher-reliability: original tag changed during admission')


class _Admission:
    def __init__(self, adopter: Path, roots: dict[str, Path], edges: list[dict], *,
                 replay=False, party_raw: bytes | None = None):
        self.adopter = Path(adopter)
        validator, self.declaration, self.party_raw = _party(self.adopter, party_raw)
        self.policies = (self.declaration.get('appetite') or {}).get('publisher_reliability', [])
        self.diagnostic: set[tuple[str, str, str]] = set()
        self.records: dict[tuple[str, str, str], dict] = {}
        self.closure = None
        self.temporary = None
        if not self.policies:
            return
        # The standalone public seam observes the same closed declaration
        # contract as compose(), without a second policy schema or dependency.
        errors = validator.validate_schema(self.declaration)
        if errors:
            raise Refused('publisher-reliability: invalid adopter declaration: ' + '; '.join(errors))
        required = {_reference(p['report'])['party'] for p in self.policies}
        if replay:
            path = self.adopter / PORTABLE
            if not path.is_file() or path.is_symlink() or path.stat().st_size > _LIMIT * 4 // 3 + 1048576:
                raise Refused('publisher-reliability: original portable Git closure is absent')
            # The pack envelope is larger than an individual signed JSON record.
            try:
                self.closure = _json(path.read_bytes(), limit=_LIMIT * 4 // 3 + 1048576)
            except (ValueError, OSError) as error:
                raise Refused('publisher-reliability: original portable Git closure is unreadable') from error
        else:
            roots = {**roots}
            adopter_party = self.declaration['party']
            if (self.adopter / '.git').is_dir():
                roots[adopter_party] = self.adopter
            self.closure = _capture(roots, required)
        self.temporary = tempfile.TemporaryDirectory(prefix='publisher-quality-')
        self.root = Path(self.temporary.name)
        try:
            sources = self.root / 'sources'
            sources.mkdir()
            self.sources = _restore(self.closure, sources)
            self.checked: dict[tuple[str, str], str] = {}
            self.reports: set[tuple[str, ...]] = set()
            for policy in self.policies:
                self._admit(policy, edges)
        except BaseException:
            try:
                self.close()
            except OSError:
                pass  # preserve the original admission refusal
            raise

    def close(self):
        if self.temporary is not None:
            temporary, self.temporary = self.temporary, None
            temporary.cleanup()

    def _read(self, ref, *, parse=True):
        _reference(ref)
        party, tag, commit = (ref[k] for k in ('party', 'tag', 'commit'))
        repo = self.sources.get(party)
        if repo is None:
            raise Refused('publisher-reliability: canonical source checkout for ' + party + ' is absent')
        key = (party, tag)
        if key in self.checked and self.checked[key] != commit:
            raise Refused('publisher-reliability: one original tag is bound to two commits')
        if key not in self.checked:
            _verify_tag(repo, party, tag, commit)
            main = _git(repo, 'rev-parse', 'refs/remotes/origin/main').decode().strip()
            _git(repo, 'merge-base', '--is-ancestor', commit, main)
            self.checked[key] = commit
        listing = _git(repo, 'ls-tree', commit, '--', ref['path']).decode().strip().split()
        if (len(listing) < 4 or listing[0] not in ('100644', '100755') or
                listing[1] != 'blob' or listing[2] != ref['git_blob']):
            raise Refused('publisher-reliability: exact regular source blob differs from signed pin')
        size = int(_git(repo, 'cat-file', '-s', ref['git_blob']))
        if size > 33554432:
            raise Refused('publisher-reliability resource-limit: source record exceeds 32 MiB')
        raw = _git(repo, 'cat-file', 'blob', ref['git_blob'])
        return _json(raw) if parse else raw

    def _admit(self, policy, edges):
        # The selected scorer must be authenticated before any of its code executes.
        ref = policy['report']
        report = self._read(ref)
        if (ref['party'] != 'nist' or not isinstance(report, dict) or
                report.get('name') != 'publisher-reliability' or report.get('kind') != 'feed' or
                report.get('published_by') != ref['party'] or
                not isinstance(report.get('version'), str) or
                ref['tag'] not in ('v' + report['version'], 'publisher-reliability/v' + report['version'])):
            raise Refused('publisher-reliability: selected scorer envelope/tag identity differs')
        matching_edges = [e for e in edges if e.get('party') == ref['party'] and
                          e.get('kind') == 'feed' and e.get('name') == 'publisher-reliability' and
                          str(e.get('version')).removeprefix('v') in
                          (report['version'], report['version'].split('.')[0])]
        if len(matching_edges) != 1:
            raise Refused('publisher-reliability: report must name one exact declared diagnostic subscription')
        scorer = self.sources[ref['party']]
        _git(scorer, 'checkout', '-q', '--detach', ref['commit'])
        script_ref = self._same_tree(ref, 'publisher-reliability/price_report.py')
        self._read(script_ref, parse=False)
        report_file = self.root / ('report-' + ref['git_blob'] + '.json')
        report_file.write_bytes(_canonical(report))
        report_key = tuple(ref[k] for k in sorted(_REF_KEYS))
        if report_key not in self.reports:
            rebuilt = self._execute([sys.executable, str(scorer / script_ref['path']), 'check',
                           '--root', str(scorer), '--report', str(report_file),
                           '--sources', str(self.root / 'sources')], cwd=scorer,
                          reason='monetary report authenticated reconstruction')
            if _json(rebuilt) != report:
                raise Refused('publisher-reliability: checker did not return the selected exact report')
            self.reports.add(report_key)
        payload = report['payload']
        rows = [row for row in payload['reports'] if row['profile'] == policy['profile']]
        if len(rows) != 1:
            raise Refused('publisher-reliability: report has no unique exact declared profile/cohort')
        row = rows[0]
        target, profile_ref = row['target'], policy['profile']
        envelope, profile = self._read(target), self._read(profile_ref)
        selected = policy['target_edge']
        if (target['party'] != selected['party'] or envelope.get('name') != selected['name'] or
                str(selected['version']).removeprefix('v') not in
                (envelope['version'], envelope['version'].split('.')[0]) or
                target['party'] != profile_ref['party'] or target['party'] == ref['party'] or
                profile['unit'] != policy['unit'] or row['unit'] != policy['unit'] or
                profile['criterion'] != policy['criterion'] or row['criterion'] != policy['criterion'] or
                profile['population']['aggregation'] != policy['aggregation']):
            raise Refused('publisher-reliability: exact target/profile/unit/aggregation differs from adopter policy')
        widening = self._read(policy['widening'])
        self._closed_record(ref, 'widening_declaration', widening)
        if (policy['widening']['party'] != target['party'] or widening['profile_id'] != profile['id'] or
                widening['unit'] != profile['unit'] or widening['authoritative_value_action'] != 'preserve'):
            raise Refused('publisher-reliability: publisher widening does not preserve exact profile authority/unit')
        # A missing native proof is an unavailable instrument, never evidence of pass.
        cage_link = envelope['payload'].get('release_cage')
        if cage_link is None or cage_link != widening['release_cage']:
            raise Refused('publisher-reliability: exact target has no matching native release-cage proof')
        cage_ref = self._same_tree(target, cage_link['path'], cage_link['git_blob'])
        cage = self._read(cage_ref)
        degraded = self._release(target, envelope, cage_ref, cage)
        key = (selected['party'], selected['name'], str(selected['version']))
        if key in self.records:
            raise Refused('publisher-reliability: duplicate policy for exact target edge')
        self.records[key] = {'policy': policy, 'report': row, 'profile': profile,
                             'target': target, 'envelope': envelope, 'widening': widening,
                             'degraded': degraded, 'cutoff': payload['cutoff']}
        e = matching_edges[0]
        self.diagnostic.add((e['party'], e['name'], str(e['version'])))

    def _closed_record(self, scorer, kind, document):
        # This is the selected signed scorer's exact versioned wire schema;
        # importing its runtime dependency remains lazy for absent policies.
        try:
            import jsonschema
        except ModuleNotFoundError as error:
            raise Refused('publisher-reliability missing-instrument: Python dependency jsonschema') from error
        schema = self._read(self._same_tree(scorer, 'publisher-reliability/price-schemas.json'))
        def local(value):
            if isinstance(value, dict):
                if '$ref' in value and not str(value['$ref']).startswith('#'):
                    raise Refused('publisher-reliability: external schema reference is not admitted offline')
                for item in value.values():
                    local(item)
            elif isinstance(value, list):
                for item in value:
                    local(item)
        local(schema)
        try:
            jsonschema.Draft7Validator({**schema, '$ref': '#/$defs/' + kind}).validate(document)
        except (jsonschema.ValidationError, jsonschema.SchemaError) as error:
            raise Refused('publisher-reliability: declared ' + kind + ' violates its closed signed schema') from error

    def bind_live(self, edge, feed_path, converter_path=None):
        key = (edge.get('party'), edge.get('name'), str(edge.get('version')))
        record = self.records.get(key)
        if record is None:
            if key not in self.diagnostic:
                return
            ref = next(p['report'] for p in self.policies if p['report']['party'] == edge['party'])
            if Path(feed_path).read_bytes() != self._read(ref, parse=False):
                raise Refused('publisher-reliability: diagnostic checkout differs from selected signed report')
            return
        target = record['target']
        if Path(feed_path).read_bytes() != self._read(target, parse=False):
            raise Refused('publisher-reliability: priced feed differs from exact signed report target')
        path = ('schema/to_fair_scenario.py' if edge['name'] == 'penalty-schema'
                else 'threat-register/to_fair_scenario.py')
        if converter_path is None or Path(converter_path).read_bytes() != self._read(
                self._same_tree(target, path), parse=False):
            raise Refused('publisher-reliability: priced converter differs from exact target source')

    def _same_tree(self, enclosing, path, oid=None):
        _relative(path)
        repo = self.sources[enclosing['party']]
        actual = _git(repo, 'rev-parse', '--verify', enclosing['commit'] + ':' + path).decode().strip()
        if oid is not None and actual != oid:
            raise Refused('publisher-reliability: same-tree dependency differs from its actual Git blob')
        return {**{k: enclosing[k] for k in ('party', 'tag', 'commit')},
                'path': path, 'git_blob': actual}

    def _execute(self, argv, *, cwd, reason):
        try:
            result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=300,
                env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1', GITSIGN_REKOR_MODE='offline'))
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Refused('publisher-reliability: ' + reason + ' unavailable') from error
        if result.returncode:
            detail = result.stderr.decode(errors='replace').strip()[-2000:]
            raise Refused('publisher-reliability: ' + reason + ' refused: ' + detail)
        if len(result.stdout) > 33554432:
            raise Refused('publisher-reliability resource-limit: converter/check output exceeds 32 MiB')
        return result.stdout

    def _release(self, target, envelope, cage_ref, cage):
        fields = {'schema', 'target_name', 'target_version', 'published_as', 'outcome', 'tier',
                  'declared_bump', 'computed_bump', 'suffix', 'native_evidence', 'gate_code'}
        if (not isinstance(cage, dict) or set(cage) != fields or
                cage['schema'] != 'publisher-release-cage/v1' or
                cage['target_name'] != envelope['name'] or cage['target_version'] != envelope['version'] or
                cage['published_as'] != target['tag'] or
                cage['declared_bump'] not in _RANK or cage['computed_bump'] not in _RANK):
            raise Refused('publisher-reliability: invalid exact target native release-cage record')
        degraded = cage['outcome'] == 'degraded'
        if degraded:
            valid = (cage['tier'] == 'quarantine' and cage['suffix'] == 'quarantine' and
                     _RANK[cage['declared_bump']] < _RANK[cage['computed_bump']])
        else:
            valid = (cage['outcome'] == 'passed' and cage['tier'] == 'baseline' and cage['suffix'] is None and
                     _RANK[cage['declared_bump']] >= _RANK[cage['computed_bump']])
        if not valid:
            raise Refused('publisher-reliability: native release outcome/tier/bump binding is inconsistent')
        for key in ('native_evidence', 'gate_code'):
            value = cage[key]
            if not isinstance(value, dict) or set(value) != {'path', 'git_blob'}:
                raise Refused('publisher-reliability: native release dependency is not an exact tree file')
            self._read(self._same_tree(target, value['path'], value['git_blob']), parse=False)
        native = self._read(self._same_tree(
            target, cage['native_evidence']['path'], cage['native_evidence']['git_blob']))
        self._authenticate_native_history(target, envelope, native)
        if cage['gate_code']['path'] != '.github/scripts/publisher-release-gate.py':
            raise Refused('publisher-reliability: unsupported native publisher release verifier')
        repo = self.sources[target['party']]
        _git(repo, 'checkout', '-q', '--detach', target['commit'])
        self._execute([sys.executable, str(repo / cage['gate_code']['path']), 'verify',
                       cage_ref['path'], target['tag']], cwd=repo,
                      reason='publisher native release-cage proof')
        return degraded

    def _authenticate_native_history(self, target, envelope, native):
        """The publisher's pure gate proves structure; certificates are checked here."""
        if (not isinstance(native, dict) or native.get('schema') != 'publisher-native-feed-gate/v1' or
                native.get('publisher') != target['party'] or
                native.get('target_name') != envelope['name'] or
                native.get('target_version') != envelope['version'] or
                native.get('published_as') != target['tag'] or
                not isinstance(native.get('captured_releases'), list) or
                not native['captured_releases']):
            raise Refused('publisher-reliability: native release history has no exact target-bound closure')
        identities = set()
        for release in native['captured_releases']:
            if (not isinstance(release, dict) or
                    set(release) != _REF_KEYS | {'tag_object', 'tagger_time'} or
                    not isinstance(release['tag_object'], str) or not _SHA.fullmatch(release['tag_object']) or
                    type(release['tagger_time']) is not int):
                raise Refused('publisher-reliability: native prior release is not an exact captured source')
            reference = _reference({key: release[key] for key in _REF_KEYS})
            if reference['party'] != target['party']:
                raise Refused('publisher-reliability: native prior release belongs to another publisher')
            identity = tuple(reference[key] for key in sorted(_REF_KEYS))
            if identity in identities:
                raise Refused('publisher-reliability: native captured release history is duplicated')
            identities.add(identity)
            # _read authenticates this exact original tag/commit/tree blob and
            # its canonical signer/issuer, independently of annotation shape.
            previous = self._read(reference)
            if (not isinstance(previous, dict) or previous.get('kind') != 'feed' or
                    previous.get('name') != envelope['name'] or previous.get('published_by') != target['party'] or
                    not isinstance(previous.get('version'), str) or reference['tag'] not in
                    ('v' + previous['version'], envelope['name'] + '/v' + previous['version'])):
                raise Refused('publisher-reliability: native prior source is not the same published feed')
            actual = _git(self.sources[reference['party']], 'rev-parse', '--verify',
                          'refs/tags/' + reference['tag']).decode().strip()
            if actual != release['tag_object']:
                raise Refused('publisher-reliability: native captured original tag object differs')
        predecessor = _reference(native.get('predecessor'))
        if (predecessor['party'] != target['party'] or
                tuple(predecessor[key] for key in sorted(_REF_KEYS)) not in identities):
            raise Refused('publisher-reliability: native predecessor is outside authenticated release history')

    def adjust(self, edge, base, context):
        key = (edge.get('party'), edge.get('name'), str(edge.get('version')))
        record = self.records.get(key)
        if record is None:
            return AdjustedScenario(copy.deepcopy(base), None)
        financial_date = context.get('financial_as_of')
        try:
            if not isinstance(financial_date, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', financial_date):
                raise ValueError('financial date requires ISO date')
            date.fromisoformat(financial_date)
        except ValueError as error:
            raise Refused('publisher-reliability: financial as-of must be an actual ISO date') from error
        policy, report = record['policy'], record['report']
        if context.get('native_currency') != policy['unit']['currency']:
            raise Refused('publisher-reliability: publisher native currency differs from the signed monetary unit')
        count = report['counts']['eligible']
        score = report['score']
        if type(count) is not int or count < 0:
            raise Refused('publisher-reliability: recomputed eligible count is invalid')
        causes = []
        if count == 0:
            state, reason = 'unmeasured', 'no eligible monetary forecast/resolution pairs'
        elif count < policy['minimum_cases']:
            state, reason = 'insufficient', 'eligible cases below the signed adopter minimum'
        else:
            if not isinstance(score, dict) or set(score) != {'numerator', 'denominator'}:
                raise Refused('publisher-reliability: measured report has no exact score')
            if max(len(str(score[k])) for k in score) > 2500:
                raise Refused('publisher-reliability resource-limit: exact score exceeds integer wire bound')
            exact = Fraction(int(score['numerator']), int(score['denominator']))
            if (exact.numerator > 0 or max(exact.numerator.bit_length(), exact.denominator.bit_length()) > 8192):
                raise Refused('publisher-reliability resource-limit: exact score exceeds its signed reward domain')
            bar = policy['bar']
            if (not isinstance(bar, str) or len(bar) > 260 or
                    not re.fullmatch(r'(0|-[1-9][0-9]*(\.[0-9]*[1-9])?|-0\.[0-9]*[1-9])', bar)):
                raise Refused('publisher-reliability: signed bar must be a canonical nonpositive decimal')
            if exact < Fraction(Decimal(bar)):
                causes.append('score-below-bar')
            state, reason = 'accepted', None
        if record['degraded']:
            causes.append('release-degraded')
        effective = copy.deepcopy(base)
        if causes:
            effective = self._widen(record, edge, base, context)
            state, reason = 'widened', 'publisher conservative target selected once by the listed causes'
        raw = (self.adopter / 'party.yaml').read_bytes()
        if raw != self.party_raw:
            raise Refused('publisher-reliability: adopter declaration changed during this composition')
        effect = {'schema': 'publisher-reliability/effect-v1', 'state': state, 'reason': reason,
                  'report': policy['report'], 'profile': policy['profile'],
                  'policy_source': {'path': 'party.yaml', 'git_blob': _blob(raw)},
                  'target': record['target'], 'criterion': policy['criterion'],
                  'eligible_cases': count, 'minimum_cases': policy['minimum_cases'],
                  'score': score, 'bar': policy['bar'], 'causes': causes,
                  'base': {'scenario': copy.deepcopy(base), 'uncaged_price': None, 'tier': None},
                  'effective': {'scenario': copy.deepcopy(effective), 'uncaged_price': None, 'tier': None},
                  'financial_as_of': context['financial_as_of'],
                  'reliability_evidence_as_of': record['cutoff']}
        return AdjustedScenario(effective, effect)

    def _widen(self, record, edge, base, context):
        policy, target = record['policy'], record['target']
        if edge['name'] not in ('penalty-schema', 'threat-register'):
            raise Refused('publisher-reliability: no publisher widening adapter for this feed')
        relative = ('schema/to_fair_scenario.py' if edge['name'] == 'penalty-schema'
                    else 'threat-register/to_fair_scenario.py')
        converter = self._read(self._same_tree(target, relative), parse=False)
        stage = Path(tempfile.mkdtemp(prefix='widen-', dir=self.root))
        script = stage / 'converter.py'
        script.write_bytes(converter)
        widening_ref = policy['widening']
        declaration = self._read(widening_ref, parse=False)
        destination = stage / _relative(widening_ref['path'])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(declaration)
        current = (self.adopter / 'party.yaml').read_bytes()
        if current != self.party_raw:
            raise Refused('publisher-reliability: adopter declaration changed during this composition')
        adopter_context = {'path': 'party.yaml', 'git_blob': _blob(current)}
        request = {'schema': 'publisher-reliability/widen-context-v1', 'target': target,
                   'profile': policy['profile'], 'widening': widening_ref,
                   'adopter_party': self.declaration['party'], 'adopter_context': adopter_context,
                   'base_scenario': base, 'state': 'warn', 'financial_as_of': context['financial_as_of']}
        payload = copy.deepcopy(record['envelope']['payload'])
        payload.setdefault('schema_version' if edge['name'] == 'penalty-schema' else 'feed_version', edge['version'])
        (stage / 'payload.json').write_bytes(_canonical(payload))
        (stage / 'context.json').write_bytes(_canonical(request))
        output = self._execute([sys.executable, str(script), 'widen-to', 'payload.json', 'context.json'],
                               cwd=stage, reason='publisher-owned widening converter')
        result = _json(output)
        expected = {'schema', 'target_id', 'profile_id', 'scenario', 'authority_action', 'affected_sources'}
        if (not isinstance(result, dict) or set(result) != expected or
                result['schema'] != 'publisher-reliability/widen-result-v1' or
                result['target_id'] != record['widening']['id'] or
                result['profile_id'] != record['profile']['id'] or result['authority_action'] != 'preserve' or
                result['affected_sources'] != record['widening']['affected_sources']):
            raise Refused('publisher-reliability: converter result differs from exact declared widening')
        _non_narrowing(base, result['scenario'], result['affected_sources'])
        return result['scenario']


def _blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def _money(value):
    if not _finite(value) or value < 0:
        raise Refused('publisher-reliability: actual FAIR price is not finite nonnegative money')
    decimal = Decimal(str(value))
    if len(decimal.as_tuple().digits) > 128 or abs(decimal.as_tuple().exponent) > 128:
        raise Refused('publisher-reliability resource-limit: actual price exceeds decimal wire bounds')
    result = format(decimal, 'f')
    return result.rstrip('0').rstrip('.') if '.' in result else result


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except (ValueError, OverflowError):
        return False


def finish(result, *, base_uncaged, effective_uncaged, base_price, effective_price,
           base_tier, effective_tier, order):
    """Bind diagnostic evidence to the existing engine's actual priced result."""
    if result.effect is None:
        return None
    if (effective_uncaged < base_uncaged or effective_price < base_price or
            order.index(effective_tier) < order.index(base_tier)):
        raise Refused('publisher-reliability: publisher target narrowed actual uncaged price or selected tier')
    result.effect['base'].update(uncaged_price=_money(base_price), tier=base_tier)
    result.effect['effective'].update(uncaged_price=_money(effective_price), tier=effective_tier)
    return result.effect


def _non_narrowing(base, target, affected):
    if (not isinstance(target, dict) or set(target) - {'version', 'name', 'warn', 'deny', 'note'} or
            any(target.get(k) != base.get(k) for k in ('version', 'name')) or not isinstance(affected, list) or
            len(set(affected)) != len(affected)):
        raise Refused('publisher-reliability: widening changed scenario identity or affected-source declaration')
    changed = set()
    for state in ('warn', 'deny'):
        if (set(target.get(state, {})) != {'lef', 'lm'} or target[state]['lef'] != base[state]['lef']):
            raise Refused('publisher-reliability: widening changed event frequency or source structure')
        before, after = base[state]['lm'], target[state]['lm']
        nested = isinstance(before, list) and bool(before) and isinstance(before[0], list)
        left, right = (before, after) if nested else ([before], [after])
        if not isinstance(right, list) or len(left) != len(right):
            raise Refused('publisher-reliability: widening changed LM source structure')
        for index, (old, new) in enumerate(zip(left, right)):
            if (not isinstance(new, list) or len(new) != 3 or any(not _finite(v) or v < 0 for v in new) or new != sorted(new) or
                    any(a < b for a, b in zip(new, old))):
                raise Refused('publisher-reliability: target LM must be finite ordered and non-narrowing')
            if new != old:
                changed.add('/' + state + '/lm' + ('/' + str(index) if nested else ''))
    if changed != set(affected):
        raise Refused('publisher-reliability: affected LM sources do not match actual widening')


def assess_and_adjust(*, adopter_dir: Path, source_roots: dict[str, Path], edge: dict,
                      base_scenario: dict, pricing_context: dict) -> AdjustedScenario:
    """Public seam: independently admit sources, then ask the publisher to widen."""
    _, declaration, raw = _party(Path(adopter_dir))
    admission = _Admission(Path(adopter_dir), source_roots, declaration.get('inherits', []),
                           party_raw=raw)
    try:
        if not admission.policies:
            return AdjustedScenario(copy.deepcopy(base_scenario), None)
        return admission.adjust(edge, base_scenario, pricing_context)
    finally:
        primary = sys.exception()
        try:
            admission.close()
        except OSError as error:
            if primary is None:
                raise Refused('publisher-reliability: private source cleanup failed') from error
