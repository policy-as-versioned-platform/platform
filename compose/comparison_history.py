"""Signed comparison inputs, independent of freshly rendered transition outputs.

The caller supplies current source identity and the existing recorded state. A
same-input repeat retains the before-state; a source change starts a comparison
from the existing after-state. These are historical inputs, never trusted deltas.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


class InvalidHistory(ValueError):
    pass


HEADER_FIELDS = ('parents', 'baseline', 'holes', 'selected-controls', 'ungoverned-namespaces')
PRICE_FIELDS = ('kind', 'source', 'name', 'proposed_tier', 'hole')
CAGE_FIELDS = ('party', 'rule', 'tier')


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def identity(adopter: Path, parents: list[dict], observations: list[dict], as_of: str | None, namespace_facts: object) -> str:
    # Source bytes, not checkout paths, Git HEAD, generated artefacts or Python
    # caches. Include all non-hidden source files: a source edit deliberately
    # starts a new comparison, even if it does not change the selected tier.
    sources = {}
    for path in sorted(adopter.rglob('*')):
        relative = path.relative_to(adopter)
        if any(part.startswith('.') or part == '__pycache__' for part in relative.parts):
            continue
        if relative.parts[0] == 'composed' or not path.is_file():
            continue
        sources[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return _digest({'sources': sources, 'parents': parents, 'observations': observations,
                    'as_of': as_of, 'namespace_facts': namespace_facts})


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(x, str) for x in value)


def _validate(before: object) -> None:
    if not isinstance(before, dict) or set(before) != {'header', 'prices', 'cages'}:
        raise InvalidHistory('invalid comparison history: incomplete before-state')
    header = before['header']
    if header is not None:
        if not isinstance(header, dict) or set(header) != set(HEADER_FIELDS):
            raise InvalidHistory('invalid comparison history: header fields')
        if header['baseline'] is not None and not isinstance(header['baseline'], str):
            raise InvalidHistory('invalid comparison history: baseline')
        if not all(_strings(header[k]) for k in HEADER_FIELDS[2:]):
            raise InvalidHistory('invalid comparison history: control/namespace lists')
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
    prior_prices = [{key: row.get(key) for key in PRICE_FIELDS} for row in prices]
    for row in prior_prices:
        if isinstance(row['hole'], dict):
            row['hole'] = {'status': row['hole'].get('status')}
    before = {'header': prior_header, 'prices': prior_prices,
              'cages': [{key: row.get(key) for key in CAGE_FIELDS} for row in cages]}
    _validate(before)
    return before


def resolve(current: str, header: dict | None, prices: list[dict], cages: list[dict], *, replay: bool) -> dict:
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
    if replay:
        raise InvalidHistory('comparison history does not match current source inputs')
    return {'schema': 1, 'after': current, 'before': project(header, prices, cages)}


def read_recorded(adopter: Path) -> tuple[dict | None, list[dict], list[dict]]:
    """Absent legacy evidence is empty; corrupt present evidence is not absence."""
    header_path = adopter / 'composed/HEADER.yaml'
    evidence_path = adopter / 'composed/evidence.json'
    try:
        header = yaml.safe_load(header_path.read_text()) if header_path.exists() else None
        evidence = json.loads(evidence_path.read_text()) if evidence_path.exists() else {}
        if header_path.exists() and not isinstance(header, dict):
            raise InvalidHistory('invalid comparison history: recorded header is not a mapping')
        if not isinstance(evidence, dict):
            raise InvalidHistory('invalid comparison history: recorded evidence is not a mapping')
        prices, cages = evidence.get('prices', []), evidence.get('cages', [])
        if not isinstance(prices, list) or not isinstance(cages, list) or not all(
                isinstance(row, dict) for row in prices + cages):
            raise InvalidHistory('invalid comparison history: recorded price/cage rows')
        return header, prices, cages
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise InvalidHistory(f'invalid comparison history: cannot read recorded inputs ({error})') from None
