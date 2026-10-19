"""Stored-schema compatibility and hostile inputs; no cleanup authorization."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from decimal import Decimal

import pytest
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

from proofpack.evidence.repository import Key, Row, Write
from proofpack.evidence.resource_bindings import prepare_linked
from proofpack.evidence.resource_lineage import decode, MissingResourceBindings, InvalidResourceBindings


def stored_output():
    event = Key('events', 'capture#output')
    writes, _ = prepare_linked('demo', 'observation_completed', (
        Write(Key('state', 'asset#one'), 3, {'sha256': '1'*64}),
        Write(event, None, {'private': 'not an exported result'}),
        Write(Key('state', 'idempotency#reply'), None, {'body_hash': '2'*64, 'result': {'id': 'one'}}),
    ), (Row(Key('state', 'asset#one'), 3, {'status': 'before'}),
        Row(Key('events', 'access#earlier'), 1, {'kind': 'before'})))
    output = next(w for w in writes if w.key == event)
    # Real serializer/deserializer represents nested numbers as Decimal.
    data = TypeDeserializer().deserialize(TypeSerializer().serialize(output.data))
    return Row(event, 1, data)


def test_actual_writer_storage_roundtrip_preserves_historical_links_without_payloads():
    row = stored_output()
    result = decode(row, deployment='demo')
    assert result.operation == 'observation_completed' and result.deployment == 'demo'
    assert [(r.key, r.previous_revision, r.revision) for r in result.writes] == [(Key('state', 'asset#one'), 3, 4)]
    assert [(r.key, r.revision) for r in result.checks] == [(Key('events', 'access#earlier'), 1), (Key('state', 'asset#one'), 3)]
    assert 'private' not in repr(result) and 'status' not in repr(result) and 'body_hash' not in repr(result)
    row.data['resource_bindings']['writes'][0]['resource'] = 'changed'
    assert result.writes[0].resource == 'asset#one'
    with pytest.raises(FrozenInstanceError):
        result.writes[0].revision = 55


def test_missing_legacy_binding_is_distinct_from_corrupt_binding():
    row = stored_output()
    del row.data['resource_bindings']
    with pytest.raises(MissingResourceBindings):
        decode(row, deployment='demo')
    row.data['resource_bindings'] = None
    with pytest.raises(InvalidResourceBindings):
        decode(row, deployment='demo')


@pytest.mark.parametrize('field,value', [
    ('schema_version', False), ('schema_version', True), ('schema_version', 0), ('schema_version', 2),
    ('schema_version', '1'), ('schema_version', 1.0), ('schema_version', Decimal('NaN')),
    ('deployment', 'foreign'), ('operation', ''), ('operation', 'x'*513),
    ('writes', ()), ('checks', {}), ('extra', 'secret'),
])
def test_unsupported_envelope_is_rejected_without_echoing_private_data(field, value):
    row = stored_output()
    row.data['resource_bindings'][field] = value
    with pytest.raises(InvalidResourceBindings) as error:
        decode(row, deployment='demo')
    assert 'secret' not in str(error.value)


@pytest.mark.parametrize('field,value', [
    ('table', 'foreign'), ('resource', ''), ('resource', 'x'*257), ('sha256', 'A'*64),
    ('sha256', 'not a digest'), ('revision', False), ('revision', '4'), ('revision', 4.0),
    ('revision', Decimal('4.1')), ('revision', Decimal('Infinity')), ('revision', 2**63),
    ('previous_revision', 0), ('previous_revision', True), ('previous_revision', 2**63-1),
    ('previous_revision', None), ('extra', 'private'),
])
def test_corrupt_write_reference_cannot_be_partially_admitted(field, value):
    row = stored_output()
    row.data['resource_bindings']['writes'][0][field] = value
    with pytest.raises(InvalidResourceBindings):
        decode(row, deployment='demo')


@pytest.mark.parametrize('fault', ['self', 'event_write', 'replay_write', 'duplicate_write', 'duplicate_check', 'unordered', 'overlap', 'empty'])
def test_invalid_graph_shape_is_rejected(fault):
    row = stored_output()
    envelope = row.data['resource_bindings']
    if fault == 'self':
        envelope['checks'][0]['resource'] = row.key.resource
    elif fault == 'event_write':
        envelope['writes'][0]['table'] = 'events'
    elif fault == 'replay_write':
        envelope['writes'][0]['resource'] = 'idempotency#sibling'
    elif fault == 'duplicate_write':
        envelope['writes'].append(deepcopy(envelope['writes'][0]))
    elif fault == 'duplicate_check':
        envelope['checks'].append(deepcopy(envelope['checks'][0]))
    elif fault == 'unordered':
        envelope['checks'].reverse()
    elif fault == 'overlap':
        envelope['checks'][1]['revision'] = 2
    else:
        envelope['writes'] = []; envelope['checks'] = []
    with pytest.raises(InvalidResourceBindings):
        decode(row, deployment='demo')


@pytest.mark.parametrize('key,revision', [(Key('state', 'asset#not-output'), 1), (Key('events', 'capture#output'), 2),
                                       (Key('events', 'capture#output'), True), (Key('foreign', 'one'), 1)])
def test_nonoutput_or_mutated_event_row_is_rejected(key, revision):
    with pytest.raises(InvalidResourceBindings):
        decode(Row(key, revision, stored_output().data), deployment='demo')


def test_replay_output_and_checked_acknowledgment_are_supported():
    output = Key('state', 'idempotency#reply')
    writes, _ = prepare_linked('demo', 'acknowledged', (Write(output, 1, {'result': {'id': 'same'}}),),
                               (Row(Key('state', 'purpose#one'), 5, {'allowed': False}),))
    result = decode(Row(output, 2, writes[0].data), deployment='demo')
    assert result.writes == () and result.checks[0].revision == 5


def test_maximum_99_resources_and_198_overlapping_historical_references():
    rows = tuple(Row(Key('state', f'asset#{i:03}'), 1, {'before': True}) for i in range(99))
    event = Key('events', 'capture#output')
    writes, _ = prepare_linked('demo', 'batch', (*[Write(r.key, 1, {'after': True}) for r in rows], Write(event, None, {})), rows)
    result = decode(Row(event, 1, writes[-1].data), deployment='demo')
    assert len(result.writes) == len(result.checks) == 99
    # A hundred distinct resources cannot fit even with just one output item.
    row = Row(event, 1, deepcopy(writes[-1].data))
    row.data['resource_bindings']['checks'].append({'table': 'state', 'resource': 'zz-extra', 'revision': 1, 'sha256': '0'*64})
    with pytest.raises(InvalidResourceBindings):
        decode(row, deployment='demo')


def test_combined_distinct_bound_and_encoded_size_are_checked():
    row = stored_output(); envelope = row.data['resource_bindings']
    envelope['checks'] = [{'table': 'state', 'resource': f'zz#{i:03}', 'revision': 1, 'sha256': '0'*64} for i in range(99)]
    with pytest.raises(InvalidResourceBindings):
        decode(row, deployment='demo')
    envelope['writes'] = []
    envelope['checks'] = [{'table': 'state', 'resource': '\u2603'*250+f'{i:06}', 'revision': 1, 'sha256': '0'*64} for i in range(99)]
    with pytest.raises(InvalidResourceBindings):
        decode(row, deployment='demo')
