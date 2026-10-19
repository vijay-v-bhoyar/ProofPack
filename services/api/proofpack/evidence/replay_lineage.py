"""Supplied private replay-output provenance, never ownership or removal authority."""
from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal
import json
import re

from proofpack.evidence.repository import Key, Row
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import ResourceBindings, decode


class ReplayHistoryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class ReplayRecord:
    key: Key
    revision: int
    sha256: str


@dataclass(frozen=True)
class ReplayLink:
    source: Key
    target: Key
    kind: str


@dataclass(frozen=True)
class ReplayOutputs:
    replay: ReplayRecord
    events: tuple[ReplayRecord, ...]
    bindings: ResourceBindings
    links: tuple[ReplayLink, ...]
    payload_bytes: int


def _number(value):
    if type(value) not in (int, Decimal) or (type(value) is Decimal and
            (not value.is_finite() or value != value.to_integral_value())):
        raise ValueError()
    value = int(value)
    if not 0 <= value <= 2**63 - 1:
        raise ValueError()
    return value


def _decimal(value):
    if type(value) is Decimal and value.is_finite() and value == value.to_integral_value():
        return int(value)
    raise ValueError()


def _encoded_size(data):
    _payload_sha256(data)  # Same storable canonical value domain as the writer.
    return len(json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False,
                          default=_decimal).encode())


def _sha(value):
    if type(value) is not str or re.fullmatch('[a-f0-9]{64}', value) is None:
        raise ValueError()
    return value


def _uuid(value):
    if type(value) is not str or re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', value) is None:
        raise ValueError()
    return value


def _record(row):
    return ReplayRecord(row.key, _number(row.revision), _payload_sha256(row.data))


def _row(row):
    if (not isinstance(row, Row) or not isinstance(row.key, Key) or type(row.data) is not dict
            or _number(row.revision) != 1):
        raise ValueError()
    return _record(row)


def _direct(root, event):
    value = event.data
    if set(value) != {'kind', 'inspection_id', 'observation_id', 'sequence', 'source_sha256', 'at_ms', 'resource_bindings'}:
        raise ValueError()
    if value['kind'] != 'observation_admitted':
        raise ValueError()
    expected = {name: _uuid(value[name]) for name in ('inspection_id', 'observation_id')}
    sequence = _number(value['sequence'])
    if sequence < 1:
        raise ValueError()
    expected['sequence'] = sequence
    _sha(value['source_sha256'])
    result = root.data['result']
    if set(result) != set(expected) or _number(result['sequence']) < 1 or result != expected:
        raise ValueError()
    if _number(value['at_ms']) > _number(root.data['at_ms']):
        raise ValueError()


def _declassification(row, access, operation):
    value = row.data
    if (set(value) != {'group_id', 'from_split', 'to_split', 'at_ms', 'reason', 'resource_bindings'}
            or operation != 'dataset-declassify:' + _sha(value['group_id'])
            or value['from_split'] not in {'DEVELOPMENT', 'VALIDATION', 'FROZEN_TEST'}
            or value['to_split'] != 'DEVELOPMENT' or type(value['reason']) is not str
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value['reason']) is None
            or access.data.get('details') != {'group_id': value['group_id'],
                'to_split': value['to_split'], 'reason': value['reason']}):
        raise ValueError()
    if _number(value['at_ms']) > _number(access.data['at_ms']):
        raise ValueError()


def discover(replay, rows, *, deployment, max_records, max_payload_bytes):
    """Complete inventory, typed business reconciliation and authorization are external."""
    if (type(rows) is not tuple or type(deployment) is not str
            or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}', deployment) is None
            or any(type(n) is not int or not 1 <= n <= 2**63 - 1 for n in (max_records, max_payload_bytes))):
        raise ValueError('explicit bounded replay-output inputs required')
    try:
        if len(rows) + 1 > max_records:
            raise ValueError()
        total = 0
        seen = {}
        for row in (replay, *rows):
            record = _row(row)
            total += _encoded_size(row.data)
            if total > max_payload_bytes or (row.key in seen and seen[row.key][0] != record):
                raise ValueError()
            seen[row.key] = (record, row)
        root = deepcopy(replay)
        if (root.key.table != 'state' or type(root.key.resource) is not str
                or re.fullmatch('idempotency#[a-f0-9]{64}', root.key.resource) is None
                or set(root.data) != {'body_hash', 'result', 'at_ms', 'resource_bindings'}
                or type(root.data['result']) is not dict):
            raise ValueError()
        _sha(root.data['body_hash'])
        replay_time = _number(root.data['at_ms'])
        binding = decode(root, deployment=deployment)
        peers = []
        for row in rows:
            row = deepcopy(row)
            if (row.key == root.key or row.key.table != 'events' or type(row.key.resource) is not str
                    or re.fullmatch('[a-z][a-z0-9-]{0,63}#[a-f0-9-]{36}', row.key.resource) is None):
                raise ValueError()
            prefix, ident = row.key.resource.split('#')
            _uuid(ident)
            if decode(row, deployment=deployment) != binding:
                raise ValueError()
            if row.key not in {p.key for p in peers}:
                peers.append(row)
        access = [p for p in peers if p.key.resource.startswith('access#')]
        if binding.operation == 'observation_admitted':
            if len(peers) != 1 or not peers[0].key.resource.startswith('capture#'):
                raise ValueError()
            _direct(root, peers[0])
        else:
            if len(access) != 1:
                raise ValueError()
            value = access[0].data
            required = {'kind', 'actor_scope', 'session_id', 'at_ms', 'resource_bindings'}
            if (set(value) not in (required, required | {'details'}) or value['kind'] != binding.operation
                    or type(value['actor_scope']) is not str or not 1 <= len(value['actor_scope']) <= 256
                    or ('details' in value and type(value['details']) is not dict)):
                raise ValueError()
            _uuid(value['session_id'])
            access_time = _number(value['at_ms'])
            if access_time > replay_time:
                raise ValueError()
            for row in peers:
                if row.key.resource.startswith('dataset-declassification#'):
                    _declassification(row, access[0], binding.operation)
                elif (type(row.data['kind']) is not str or not 1 <= len(row.data['kind']) <= 512
                        or _number(row.data['at_ms']) > access_time):
                    raise ValueError()
        records = tuple(_record(p) for p in sorted(peers, key=lambda p: (p.key.table, p.key.resource)))
        return ReplayOutputs(_record(root), records, binding,
                             tuple(ReplayLink(root.key, r.key, 'shared_transaction_output') for r in records), total)
    except (ValueError, TypeError, KeyError, AttributeError, ArithmeticError, RecursionError) as exc:
        raise ReplayHistoryHeld('intact bounded supplied replay-output provenance required') from None
