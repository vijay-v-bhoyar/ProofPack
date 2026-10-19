"""Stable private metadata inputs under a caller-provided barrier, not a barrier proof."""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json

import boto3
from botocore.stub import Stubber
import pytest

from proofpack.auth.policy import Denied
from proofpack.evidence.inventory import collect, reconcile, InventoryLimits, InventoryHeld
from proofpack.evidence.repository import DynamoRepository, Key, Row, ErasureMarker, StoreUnavailable


LIMITS = InventoryLimits(100, 20, 1000, 1000000)


def setup(monkeypatch, count=2):
    repo = DynamoRepository(object(), deployment='demo', state_table='state-table', events_table='event-table')
    data = {Key('state', f'unknown#{i:04}'): Row(Key('state', f'unknown#{i:04}'), 1,
             {'secret': 'PRIVATE-PAYLOAD', 'count': i}) for i in range(count)}
    calls = {'pages': [], 'snapshots': []}
    def page(*, table, limit, start_resource=None):
        calls['pages'].append((table, limit, start_resource))
        values = sorted((r for k, r in data.items() if k.table == table and
                         (start_resource is None or k.resource > start_resource)), key=lambda r: r.key.resource)
        return values[:limit], values[limit-1].key.resource if len(values) > limit else None
    def snapshot(keys):
        calls['snapshots'].append(keys)
        return {key: data.get(key) for key in keys}
    monkeypatch.setattr(repo, 'partition_page', page)
    monkeypatch.setattr(repo, 'inventory_snapshot', snapshot)
    original = collect(repo, limits=LIMITS, deadline_ns=1000, checkpoint=lambda: None, tick=lambda: 1)
    calls['pages'].clear()
    return repo, data, calls, original


def run(repo, original, **kwargs):
    options = dict(limits=LIMITS, max_snapshot_batches=10, max_payload_bytes=1000000,
                   deadline_ns=1000, checkpoint=lambda: None, tick=lambda: 1)
    options.update(kwargs)
    return reconcile(repo, original, **options)


def resigned(original, **changes):
    value = replace(original, **changes)
    body = {'deployment': value.deployment, 'tables': dict(value.tables),
            'entries': [asdict(e) for e in value.entries]}
    encoded = json.dumps(body, sort_keys=True, separators=(',', ':')).encode()
    return replace(value, summary_bytes=len(encoded), summary_sha256=hashlib.sha256(encoded).hexdigest())


@pytest.mark.parametrize('count', [0, 1, 100, 101, 205])
def test_complete_followup_and_bounded_snapshot_batches(monkeypatch, count):
    repo, data, calls, original = setup(monkeypatch, count)
    result = run(repo, original)
    assert result.inventory == original
    assert len(result.rows) == count and result.markers == ()
    assert result.snapshot_batches == (count + 99) // 100
    assert [len(x) for x in calls['snapshots']] == [min(100, count-i) for i in range(0, count, 100)]
    assert len(calls['pages']) >= 2  # Empty state still requires both tables.
    assert 'PRIVATE-PAYLOAD' not in repr(result) and 'secret' not in repr(result)
    if count:
        key = result.rows[0].key
        data[key].data['secret'] = 'changed later'
        assert result.rows[0].data['secret'] == 'PRIVATE-PAYLOAD'


def test_markers_reconcile_as_minimal_status_without_rehydrating_removed_payload(monkeypatch):
    repo, data, calls, _ = setup(monkeypatch, 0)
    key = Key('state', 'erased#one')
    marker = ErasureMarker(key, 2, 'a'*64, repo._erasure_identity(key)); data[key] = marker
    original = collect(repo, limits=LIMITS, deadline_ns=1000, checkpoint=lambda: None, tick=lambda: 1)
    result = run(repo, original)
    assert result.markers == (marker,) and result.rows == () and result.payload_bytes == 0
    assert calls['snapshots'] == [(key,)] and not hasattr(result.markers[0], 'data')


def test_exact_payload_bytes_and_snapshot_budget_are_independent(monkeypatch):
    repo, data, calls, original = setup(monkeypatch, 101)
    size = sum(len(json.dumps(r.data, sort_keys=True, separators=(',', ':')).encode()) for r in data.values())
    assert run(repo, original, max_snapshot_batches=2, max_payload_bytes=size).payload_bytes == size
    with pytest.raises(InventoryHeld): run(repo, original, max_snapshot_batches=1)
    with pytest.raises(InventoryHeld): run(repo, original, max_payload_bytes=size-1)


@pytest.mark.parametrize('fault', ['missing', 'revision', 'payload', 'extra_response', 'wrong_identity',
                                   'marker_instead', 'unavailable', 'response_not_dict'])
def test_snapshot_faults_never_return_a_partial_readset(monkeypatch, fault):
    repo, data, calls, original = setup(monkeypatch)
    real = repo.inventory_snapshot
    def broken(keys):
        result = real(keys)
        key = keys[0]; row = result[key]
        if fault == 'missing': result[key] = None
        elif fault == 'revision': result[key] = Row(key, 2, row.data)
        elif fault == 'payload': result[key] = Row(key, 1, {'secret': 'ALTERED-PRIVATE'})
        elif fault == 'extra_response': result[Key('state', 'extra')] = None
        elif fault == 'wrong_identity': result[key] = Row(Key('state', 'other'), 1, row.data)
        elif fault == 'marker_instead': result[key] = ErasureMarker(key, 2, 'a'*64, repo._erasure_identity(key))
        elif fault == 'unavailable': raise StoreUnavailable('PRIVATE-provider-details')
        elif fault == 'response_not_dict': return []
        return result
    monkeypatch.setattr(repo, 'inventory_snapshot', broken)
    with pytest.raises(InventoryHeld) as error: run(repo, original)
    assert 'PRIVATE' not in str(error.value)


@pytest.mark.parametrize('fault', ['insert', 'delete', 'payload', 'revision'])
def test_followup_catches_unknown_family_changes_after_hydration(monkeypatch, fault):
    repo, data, calls, original = setup(monkeypatch)
    real = repo.inventory_snapshot
    def changed(keys):
        result = deepcopy(real(keys)); key = keys[0]
        if fault == 'insert':
            new = Key('events', 'unrecognized#late'); data[new] = Row(new, 1, {'late': True})
        elif fault == 'delete': del data[key]
        elif fault == 'payload': data[key] = Row(key, 1, {'changed': True})
        elif fault == 'revision': data[key] = Row(key, 2, data[key].data)
        return result
    monkeypatch.setattr(repo, 'inventory_snapshot', changed)
    with pytest.raises(InventoryHeld): run(repo, original)
    assert len(calls['snapshots']) == 1 and calls['pages']


@pytest.mark.parametrize('fault', ['hash', 'bytes', 'duplicate', 'order', 'kind', 'bool_revision',
                                   'foreign', 'tables', 'too_many', 'bad_digest'])
def test_malformed_summary_holds_before_any_read_even_when_resigned(monkeypatch, fault):
    repo, data, calls, original = setup(monkeypatch)
    if fault == 'hash': original = replace(original, summary_sha256='0'*64)
    elif fault == 'bytes': original = replace(original, summary_bytes=original.summary_bytes+1)
    elif fault == 'duplicate': original = resigned(original, entries=original.entries*2)
    elif fault == 'order': original = resigned(original, entries=tuple(reversed(original.entries)))
    elif fault == 'kind': original = resigned(original, entries=(replace(original.entries[0], kind='unknown'), *original.entries[1:]))
    elif fault == 'bool_revision': original = resigned(original, entries=(replace(original.entries[0], revision=True), *original.entries[1:]))
    elif fault == 'foreign': original = resigned(original, deployment='foreign')
    elif fault == 'tables': original = resigned(original, tables=(('events', 'wrong'), ('state', 'state-table')))
    elif fault == 'too_many': original = replace(original, pages=21)
    elif fault == 'bad_digest': original = resigned(original, entries=(replace(original.entries[0], payload_sha256='BAD'), *original.entries[1:]))
    with pytest.raises(InventoryHeld): run(repo, original)
    assert not calls['snapshots'] and not calls['pages']


def test_forged_omission_cannot_use_its_valid_hash_as_inventory_authority(monkeypatch):
    repo, data, calls, original = setup(monkeypatch)
    forged = resigned(original, entries=original.entries[:1])
    with pytest.raises(InventoryHeld): run(repo, forged)
    assert calls['snapshots'] and calls['pages']


@pytest.mark.parametrize('fault', ['initial_expiry', 'backwards_clock', 'denied_after_snapshot',
                                   'client_change', 'target_change'])
def test_admission_target_and_absolute_deadline_remain_required(monkeypatch, fault):
    repo, data, calls, original = setup(monkeypatch)
    if fault == 'initial_expiry':
        with pytest.raises(InventoryHeld): run(repo, original, tick=lambda: 1000)
        assert not calls['snapshots']
    elif fault == 'backwards_clock':
        times = iter([2, 1])
        with pytest.raises(InventoryHeld): run(repo, original, tick=lambda: next(times))
    else:
        def checkpoint():
            if calls['snapshots']:
                if fault == 'denied_after_snapshot': raise Denied('admission withdrawn')
                if fault == 'client_change': repo.client = object()
                if fault == 'target_change': repo.tables['state'] = 'other'
        with pytest.raises((InventoryHeld, Denied)): run(repo, original, checkpoint=checkpoint)


@pytest.mark.parametrize('field,value', [('max_payload_bytes', True), ('max_payload_bytes', 0),
    ('max_snapshot_batches', 0), ('deadline_ns', 0), ('checkpoint', None), ('tick', None), ('limits', None)])
def test_explicit_finite_admission_parameters_required(monkeypatch, field, value):
    repo, data, calls, original = setup(monkeypatch)
    with pytest.raises(ValueError): run(repo, original, **{field: value})
    assert not calls['snapshots'] and not calls['pages']


def test_repository_private_snapshot_uses_one_atomic_read_for_live_marker_and_absence():
    client = boto3.client('dynamodb', region_name='us-east-1', aws_access_key_id='synthetic', aws_secret_access_key='synthetic')
    repo = DynamoRepository(client, deployment='demo', state_table='state-table', events_table='event-table')
    keys = (Key('state', 'live'), Key('events', 'erased'), Key('state', 'absent'))
    def raw(key, revision, data):
        return {**repo.key(key), 'revision': {'N': str(revision)}, 'data': repo.serialize.serialize(data)}
    live = raw(keys[0], 1, {'secret': 'PRIVATE'})
    erased = raw(keys[1], 2, {})
    erased['payload_erasure'] = repo.serialize.serialize({'schema_version': 1, 'reference_sha256': 'a'*64,
                                                         'resource_sha256': repo._erasure_identity(keys[1])})
    with Stubber(client) as stub:
        stub.add_response('transact_get_items', {'Responses': [{'Item': live}, {'Item': erased}, {}]},
            {'TransactItems': [{'Get': {'TableName': repo.tables[k.table], 'Key': repo.key(k)}} for k in keys]})
        rows = repo.inventory_snapshot(keys)
        assert isinstance(rows[keys[0]], Row) and isinstance(rows[keys[1]], ErasureMarker) and rows[keys[2]] is None
        stub.assert_no_pending_responses()
    client.close()


def test_one_clock_sequence_is_monotonic_across_nested_followup_reads(monkeypatch):
    repo, data, calls, original = setup(monkeypatch)
    observed = []
    def tick():
        # Every component sees this one trusted clock; a backwards sample is invalid
        # even if it occurs between the collector's and reconciler's own samples.
        value = 4 if len(observed) == 5 else len(observed) + 1
        observed.append(value)
        return value
    with pytest.raises(InventoryHeld): run(repo, original, tick=tick)
    assert any(b < a for a, b in zip(observed, observed[1:]))


def test_target_changed_by_last_clock_callback_cannot_escape_delivery_guard(monkeypatch):
    from proofpack.evidence import inventory as module
    repo, data, calls, original = setup(monkeypatch)
    real_collect = module.collect
    finished = False
    def finish(*args, **kwargs):
        nonlocal finished
        result = real_collect(*args, **kwargs)
        finished = True
        return result
    monkeypatch.setattr(module, 'collect', finish)
    def tick():
        if finished: repo.client = object()
        return 1
    with pytest.raises(InventoryHeld): run(repo, original, tick=tick)


@pytest.mark.parametrize('keys', [None, (), [], (None,), (Key('foreign', 'x'),), (Key('state', ''),),
    (Key('state', 'x'*257),), (Key('state', True),), (Key('state', 'a'),)*2,
    tuple(Key('state', str(i)) for i in range(101))])
def test_private_snapshot_key_errors_deny_before_sdk_access(keys):
    repo = DynamoRepository(object(), deployment='demo', state_table='state-table', events_table='event-table')
    with pytest.raises(ValueError): repo.inventory_snapshot(keys)
