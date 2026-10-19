"""Private replay output provenance; synthetic metadata, never cleanup admission."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from decimal import Decimal
import json

import pytest
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

from proofpack.evidence.repository import Key, Row, Write
from proofpack.evidence.resource_bindings import prepare_linked, _payload_sha256
from proofpack.evidence.replay_lineage import discover, ReplayHistoryHeld


SESSION = '00000000-0000-4000-8000-000000000001'
INSPECTION = '00000000-0000-4000-8000-000000000002'
OBSERVATION = '00000000-0000-4000-8000-000000000003'
EVENT = '00000000-0000-4000-8000-000000000004'
REPLAY = Key('state', 'idempotency#' + 'a' * 64)


def family(*, direct=False, nested=False):
    operation = 'observation_admitted' if direct else 'inspection-disposition:' + INSPECTION
    result = {'observation_id': OBSERVATION, 'inspection_id': INSPECTION, 'sequence': 1} if direct else {'id': INSPECTION, 'private_note': 'PRIVATE-RESULT'}
    event = {'kind': 'observation_admitted', 'inspection_id': INSPECTION, 'observation_id': OBSERVATION,
             'sequence': 1, 'source_sha256': 'b' * 64, 'at_ms': 10} if direct else {
             'kind': operation, 'actor_scope': 'PRIVATE-ACTOR', 'session_id': SESSION, 'at_ms': 11,
             'details': {'note': 'PRIVATE-DETAIL'}}
    prefix = 'capture' if direct else 'access'
    writes = [Write(Key('state', 'inspection#' + INSPECTION), 1, {'id': INSPECTION}),
              Write(Key('events', prefix + '#' + EVENT), None, event),
              Write(REPLAY, None, {'body_hash': 'c' * 64, 'result': result, 'at_ms': 12})]
    if nested:
        writes.append(Write(Key('events', 'disposition#' + SESSION), None,
                            {'kind': 'disposition_recorded', 'at_ms': 10, 'note': 'PRIVATE-NESTED'}))
    prepared, _ = prepare_linked('demo', operation, writes,
                                (Row(Key('state', 'inspection#' + INSPECTION), 1, {'id': INSPECTION, 'before': True}),))
    rows = tuple(Row(w.key, 1 if w.expected_revision is None else w.expected_revision + 1, deepcopy(w.data)) for w in prepared)
    return next(r for r in rows if r.key == REPLAY), tuple(r for r in rows if r.key.table == 'events')


def read(root, rows, **kwargs):
    return discover(root, rows, deployment='demo', max_records=20, max_payload_bytes=100000, **kwargs)


@pytest.mark.parametrize('direct,nested', [(False, False), (False, True), (True, False)])
def test_actual_preparation_outputs_are_frozen_payload_free_references(direct, nested):
    root, rows = family(direct=direct, nested=nested)
    result = read(root, rows)
    assert result.replay.key == REPLAY and result.replay.sha256 == _payload_sha256(root.data)
    assert len(result.events) == len(rows) and len(result.links) == len(rows)
    assert result.bindings.writes[0].resource == 'inspection#' + INSPECTION
    assert not any(secret in repr(result) for secret in ('PRIVATE-', 'private_note', 'body_hash', 'source_sha256'))
    root.data['result']['new'] = 'mutation'
    assert result.replay.sha256 != _payload_sha256(root.data)
    with pytest.raises(FrozenInstanceError):
        result.replay.revision = 2


@pytest.mark.parametrize('direct', [False, True])
def test_storage_decimal_roundtrip_and_matching_duplicate_counting(direct):
    root, rows = family(direct=direct)
    def stored(row):
        return Row(row.key, Decimal(row.revision), TypeDeserializer().deserialize(TypeSerializer().serialize(row.data)))
    root, rows = stored(root), tuple(stored(r) for r in rows)
    result = read(root, rows + rows)
    assert len(result.events) == 1
    assert result.payload_bytes > 0
    assert result.payload_bytes == discover(root, rows, deployment='demo', max_records=2,
                                           max_payload_bytes=100000).payload_bytes + len_bytes(rows[0])


def len_bytes(row):
    return len(json.dumps(row.data, sort_keys=True, separators=(',', ':'),
                          default=lambda value: int(value)).encode())


@pytest.mark.parametrize('mutation', [
    'missing_result', 'extra', 'bad_hash', 'uppercase_hash', 'list_result', 'bool_time', 'negative_time',
    'future_access', 'wrong_operation', 'bad_session', 'empty_actor', 'long_actor', 'extra_access',
    'bad_details', 'wrong_envelope', 'missing_envelope', 'foreign_deployment', 'bad_event_key',
    'event_revision', 'replay_revision', 'bad_replay_key', 'event_missing_time', 'bool_event_time',
])
def test_invalid_or_foreign_output_holds_without_exposing_private_data(mutation):
    root, rows = family()
    event = rows[0]
    if mutation == 'missing_result': del root.data['result']
    elif mutation == 'extra': root.data['extra'] = 'PRIVATE-EXTRA'
    elif mutation == 'bad_hash': root.data['body_hash'] = 'x' * 64
    elif mutation == 'uppercase_hash': root.data['body_hash'] = 'A' * 64
    elif mutation == 'list_result': root.data['result'] = []
    elif mutation == 'bool_time': root.data['at_ms'] = True
    elif mutation == 'negative_time': root.data['at_ms'] = -1
    elif mutation == 'future_access': event.data['at_ms'] = 13
    elif mutation == 'wrong_operation': event.data['kind'] = 'different'
    elif mutation == 'bad_session': event.data['session_id'] = 'PRIVATE-INVALID'
    elif mutation == 'empty_actor': event.data['actor_scope'] = ''
    elif mutation == 'long_actor': event.data['actor_scope'] = 'x' * 257
    elif mutation == 'extra_access': event.data['extra'] = 'PRIVATE-EXTRA'
    elif mutation == 'bad_details': event.data['details'] = []
    elif mutation == 'wrong_envelope': event.data['resource_bindings']['operation'] = 'different'
    elif mutation == 'missing_envelope': del event.data['resource_bindings']
    elif mutation == 'foreign_deployment': root.data['resource_bindings']['deployment'] = 'foreign'
    elif mutation == 'bad_event_key': rows = (Row(Key('events', 'access#not-uuid'), 1, event.data),)
    elif mutation == 'event_revision': rows = (Row(event.key, 2, event.data),)
    elif mutation == 'replay_revision': root = Row(root.key, 2, root.data)
    elif mutation == 'bad_replay_key': root = Row(Key('state', 'idempotency#short'), 1, root.data)
    elif mutation == 'event_missing_time': del event.data['at_ms']
    elif mutation == 'bool_event_time': event.data['at_ms'] = True
    with pytest.raises(ReplayHistoryHeld) as error:
        read(root, rows)
    assert 'PRIVATE' not in str(error.value)


@pytest.mark.parametrize('mutation', ['no_peer', 'two_access', 'conflicting_duplicate', 'state_peer', 'nested_after_access'])
def test_missing_ambiguous_and_conflicting_peers_hold(mutation):
    root, rows = family(nested=mutation == 'nested_after_access')
    if mutation == 'no_peer': rows = ()
    elif mutation == 'two_access': rows += (Row(Key('events', 'access#' + SESSION), 1, deepcopy(rows[0].data)),)
    elif mutation == 'conflicting_duplicate':
        other = deepcopy(rows[0].data); other['at_ms'] = 10
        rows += (Row(rows[0].key, 1, other),)
    elif mutation == 'state_peer': rows += (Row(Key('state', 'arbitrary'), 1, {}),)
    elif mutation == 'nested_after_access': rows[1].data['at_ms'] = 12
    with pytest.raises(ReplayHistoryHeld): read(root, rows)


@pytest.mark.parametrize('mutation', ['wrong_inspection', 'wrong_observation', 'wrong_sequence', 'bool_sequence',
                                     'extra_result', 'extra_event', 'bad_source', 'wrong_kind', 'access_substitute', 'nested'])
def test_direct_admission_has_its_own_exact_schema_and_tuple(mutation):
    root, rows = family(direct=True)
    if mutation == 'wrong_inspection': root.data['result']['inspection_id'] = SESSION
    elif mutation == 'wrong_observation': root.data['result']['observation_id'] = SESSION
    elif mutation == 'wrong_sequence': root.data['result']['sequence'] = 2
    elif mutation == 'bool_sequence': root.data['result']['sequence'] = True
    elif mutation == 'extra_result': root.data['result']['extra'] = 1
    elif mutation == 'extra_event': rows[0].data['extra'] = 1
    elif mutation == 'bad_source': rows[0].data['source_sha256'] = 'INVALID'
    elif mutation == 'wrong_kind': rows[0].data['kind'] = 'different'
    elif mutation == 'access_substitute': rows = (Row(Key('events', 'access#' + EVENT), 1, rows[0].data),)
    elif mutation == 'nested': rows += (Row(Key('events', 'disposition#' + SESSION), 1, deepcopy(rows[0].data)),)
    with pytest.raises(ReplayHistoryHeld): read(root, rows)


def test_exact_record_and_byte_limits_count_every_input_position():
    root, rows = family()
    total = len_bytes(root) + len_bytes(rows[0])
    assert discover(root, rows, deployment='demo', max_records=2, max_payload_bytes=total).payload_bytes == total
    with pytest.raises(ReplayHistoryHeld):
        discover(root, rows, deployment='demo', max_records=1, max_payload_bytes=total)
    with pytest.raises(ReplayHistoryHeld):
        discover(root, rows, deployment='demo', max_records=2, max_payload_bytes=total-1)
    with pytest.raises(ReplayHistoryHeld):
        discover(root, rows + rows, deployment='demo', max_records=2, max_payload_bytes=total*2)


@pytest.mark.parametrize('argument,value', [('rows', []), ('max_records', True), ('max_records', 0),
                                          ('max_payload_bytes', 0), ('deployment', '')])
def test_explicit_bounded_inputs_required(argument, value):
    root, rows = family()
    options = dict(deployment='demo', max_records=20, max_payload_bytes=100000)
    if argument == 'rows': rows = value
    else: options[argument] = value
    with pytest.raises(ValueError): discover(root, rows, **options)


@pytest.mark.parametrize('mutation', ['root_without_binding', 'root_bool_revision', 'peer_bool_revision',
                                     'nonintegral_time', 'nonfinite_time', 'future_capture', 'nested_empty_kind',
                                     'different_business_digest', 'different_checked_revision', 'event_nonuuid_hyphens'])
def test_independent_storage_and_cross_output_boundaries(mutation):
    root, rows = family(direct=mutation == 'future_capture', nested=mutation == 'nested_empty_kind')
    if mutation == 'root_without_binding': del root.data['resource_bindings']
    elif mutation == 'root_bool_revision': root = Row(root.key, True, root.data)
    elif mutation == 'peer_bool_revision': rows = (Row(rows[0].key, True, rows[0].data),)
    elif mutation == 'nonintegral_time': root.data['at_ms'] = Decimal('12.5')
    elif mutation == 'nonfinite_time': root.data['at_ms'] = Decimal('NaN')
    elif mutation == 'future_capture': rows[0].data['at_ms'] = 13
    elif mutation == 'nested_empty_kind': rows[1].data['kind'] = ''
    elif mutation == 'different_business_digest': rows[0].data['resource_bindings']['writes'][0]['sha256'] = 'd'*64
    elif mutation == 'different_checked_revision': rows[0].data['resource_bindings']['checks'][0]['revision'] = 2
    elif mutation == 'event_nonuuid_hyphens': rows = (Row(Key('events', 'access#' + '-'*36), 1, rows[0].data),)
    with pytest.raises(ReplayHistoryHeld): read(root, rows)


def test_equal_timestamps_are_history_not_current_permission_or_ownership():
    root, rows = family(nested=True)
    for row in (root, *rows): row.data['at_ms'] = 0
    result = read(root, rows)
    assert len(result.events) == 2
    assert not any(hasattr(result, name) for name in ('authorized', 'owner', 'delete', 'current', 'result', 'at_ms'))
