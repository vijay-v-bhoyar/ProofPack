"""Actual local capture intent target provenance; S3 protocol is intercepted."""
from dataclasses import asdict, replace
import pytest
from test_access_lifecycle import world, repository_factory, publication_case
from test_original_frames import original_case
from proofpack.calibrations.dependencies import digest
from proofpack.capture.publication import asset_key, intent_key
from proofpack.capture.service import observation_key
from proofpack.evidence.repository import Write, StoreUnavailable


def test_successful_crop_intent_keeps_original_storage_binding_through_linkage(world, publication_case):
    service, capture, started, operator, credentials, clock, registry, objects, purpose, observe = publication_case
    observe()
    expected = digest(asdict(objects.config))
    rows, cursor = world[1].query(prefix='object-intent#', limit=100)
    assert cursor is None and rows
    for row in rows:
        assert row.data['status'] == 'linked'
        assert row.data.get('storage_binding_sha256') == expected, 'unfinished capture intents must retain original storage target'
        key = asset_key(row.data['asset_id'])
        assert world[1].snapshot((key,))[key].data['storage_binding_sha256'] == expected


def intents(world):
    rows, cursor = world[1].query(prefix='object-intent#', limit=100)
    assert rows and cursor is None
    return rows


def test_original_and_crop_intents_share_the_original_storage_target(world, original_case):
    _, observe, _, objects, *_ = original_case
    observation, _, _ = observe(); expected = digest(asdict(objects.config)); rows = intents(world)
    assert len(rows) == 2
    assert {row.data['asset_id'] for row in rows} == {observation.data['asset_id'], observation.data['original_asset_id']}
    assert all(row.data['status'] == 'linked' and row.data['storage_binding_sha256'] == expected for row in rows)


def test_reserved_intent_has_target_even_if_storage_never_acknowledges(world, publication_case, monkeypatch):
    objects = publication_case[7]; expected = digest(asdict(objects.config))
    def unavailable(**kwargs):
        key = intent_key(kwargs['asset_id']); row = world[1].snapshot((key,))[key]
        assert row.data['status'] == 'reserved' and row.data['storage_binding_sha256'] == expected
        raise StoreUnavailable('synthetic unavailable before storage')
    monkeypatch.setattr(objects, 'put', unavailable)
    with pytest.raises(StoreUnavailable): publication_case[-1]()
    rows = intents(world)
    assert len(rows) == 1 and rows[0].data['status'] == 'reserved' and rows[0].data['storage_binding_sha256'] == expected
    key = observation_key(rows[0].data['observation_id'])
    assert world[1].snapshot((key,))[key].data['status'] == 'failed'


def test_config_change_after_reservation_prevents_a_storage_call(world, publication_case, monkeypatch):
    objects = publication_case[7]; expected = digest(asdict(objects.config)); transact = world[1].transact; changed = False
    def repoint(writes, checks=()):
        nonlocal changed
        result = transact(writes, checks)
        if not changed and any(w.key.resource.startswith('object-intent#') and w.expected_revision is None for w in writes):
            changed = True; objects.config = replace(objects.config, bucket='proofpack-other-synthetic')
        return result
    def forbidden(**kwargs): pytest.fail('changed target reached storage')
    monkeypatch.setattr(world[1], 'transact', repoint); monkeypatch.setattr(objects, 'put', forbidden)
    with pytest.raises(StoreUnavailable): publication_case[-1]()
    assert changed and intents(world)[0].data['storage_binding_sha256'] == expected


def test_config_change_after_upload_retains_unconfirmed_original_target_without_asset(world, publication_case):
    objects = publication_case[7]; expected = digest(asdict(objects.config))
    objects.after_put = lambda: setattr(objects, 'config', replace(objects.config, bucket='proofpack-other-synthetic'))
    with pytest.raises(StoreUnavailable): publication_case[-1]()
    rows = intents(world); assert len(rows) == 1 and len(objects.payloads) == 1
    assert rows[0].data['status'] == 'reserved' and rows[0].data['storage_binding_sha256'] == expected
    assert 'version_id' not in rows[0].data
    key = asset_key(rows[0].data['asset_id']); assert world[1].snapshot((key,))[key] is None


def test_conflicting_persisted_intent_cannot_be_advanced_as_valid_uploaded_metadata(world, publication_case):
    objects = publication_case[7]
    def tamper():
        ident = next(iter(objects.payloads)); key = intent_key(ident); row = world[1].snapshot((key,))[key]
        world[1].transact((Write(key, row.revision, {**row.data, 'storage_binding_sha256': 'f'*64}),))
    objects.after_put = tamper
    with pytest.raises(StoreUnavailable): publication_case[-1]()
    row = intents(world)[0]
    assert row.data['status'] == 'reserved' and 'version_id' not in row.data
    key = asset_key(row.data['asset_id']); assert world[1].snapshot((key,))[key] is None


def test_final_preparation_cannot_repoint_target_or_publish_an_asset(world, publication_case, monkeypatch):
    service = publication_case[0]; objects = publication_case[7]; expected = digest(asdict(objects.config))
    prepare = service.access._prepare_linked; changed = False
    def repoint(operation, writes, checks=()):
        nonlocal changed
        result = prepare(operation, writes, checks)
        if operation == 'observation_completed':
            changed = True; objects.config = replace(objects.config, bucket='proofpack-other-synthetic')
        return result
    monkeypatch.setattr(service.access, '_prepare_linked', repoint)
    with pytest.raises(StoreUnavailable): publication_case[-1]()
    row = intents(world)[0]; assert changed and row.data['status'] == 'uploaded' and row.data['storage_binding_sha256'] == expected
    key = asset_key(row.data['asset_id']); assert world[1].snapshot((key,))[key] is None
    events = world[1].query(prefix='capture#', table='events', limit=100)[0]
    assert all(event.data['kind'] != 'observation_completed' for event in events)


def test_second_original_upload_target_change_retains_both_intents_without_publication(world, original_case):
    _, observe, _, objects, *_ = original_case; expected = digest(asdict(objects.config)); calls = 0
    def repoint():
        nonlocal calls
        calls += 1
        if calls == 2: objects.config = replace(objects.config, bucket='proofpack-other-synthetic')
    objects.after_put = repoint
    with pytest.raises(StoreUnavailable): observe()
    rows = intents(world)
    assert calls == 2 and len(rows) == 2 and len(objects.payloads) == 2
    assert {r.data['status'] for r in rows} == {'reserved', 'uploaded'}
    assert all(r.data['storage_binding_sha256'] == expected for r in rows)
    assert all(world[1].snapshot((asset_key(r.data['asset_id']),))[asset_key(r.data['asset_id'])] is None for r in rows)
