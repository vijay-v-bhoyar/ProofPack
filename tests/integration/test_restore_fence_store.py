"""Actual local conditional fencing; release proof digests are TEST-INJECTED."""
from dataclasses import asdict, replace
from time import monotonic_ns
import hashlib
import json
import pytest

from test_access_lifecycle import repository_factory
from test_erasure_journal_store import journal_case
from test_restore_inventory_store import restore_case
from proofpack.evidence.restore_fence import RestoreFenceConfig, RestoreDataFence, PROOFS
from proofpack.evidence.repository import DynamoRepository, Write, Erase, ErasureMarker, StoreConflict, StoreUnavailable


@pytest.fixture
def fenced_case(restore_case):
    store, target, original, intent, keys, kw = restore_case
    client = target.client
    ids = tuple(sorted((role, client.describe_table(TableName=name)['Table']['TableId'])
                       for role, name in target.tables.items()))
    config = RestoreFenceConfig(store.journal.table, store.journal.table_arn, store.genesis_sha256,
        kw['expected_head'], 'a'*64, ids, 'b'*64, 15000)
    body = {'schema_version': 1, 'kind': 'restored-data-release', 'deployment': target.deployment,
        'target_tables': dict(target.tables), 'target_table_ids': dict(ids), 'journal_arn': config.journal_arn,
        'genesis_sha256': config.genesis_sha256, 'checkpoint': asdict(config.checkpoint),
        'artifact_sha256': config.artifact_sha256, 'writer_protocol': 'metadata-payload-erasure/v1',
        **{k: 'c'*64 for k in PROOFS}}
    encode = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    digest = hashlib.sha256(encode(['restored-data-release/v1', target.deployment, config.journal_arn, body]).encode()).hexdigest()
    config = replace(config, release_sha256=digest)
    fence = RestoreDataFence(client, deployment=target.deployment, state_table=target.tables['state'],
        events_table=target.tables['events'], config=config, tick=monotonic_ns)
    # Trusted host/coordinator simulation only: no genuine release writer exists yet.
    release_key = fence._gets()[2]['Get']['Key']
    client.put_item(TableName=config.journal_table,
                    Item={**release_key, 'body': {'S': encode(body)}, 'sha256': {'S': digest}})
    repo = DynamoRepository(client, deployment=target.deployment, state_table=target.tables['state'],
                            events_table=target.tables['events'], data_fence=fence)
    yield repo, fence, target, store, keys, intent


def test_actual_fenced_snapshot_and_transaction_preserve_protected_rows(fenced_case):
    repo, fence, target, store, keys, intent = fenced_case
    fence.verify_target()
    before = target.snapshot(keys)
    result = repo.snapshot(keys)
    assert result == before
    repo.transact((Write(keys[0], 1, {'changed': 'synthetic'}),), (before[keys[1]],))
    assert target.snapshot((keys[0],))[keys[0]].revision == 2
    fence.check()


@pytest.mark.parametrize('part', [0, 1, 2])
def test_actual_gate_change_at_commit_rejects_all_primary_writes_atomically(fenced_case, monkeypatch, part):
    repo, fence, target, store, keys, intent = fenced_case
    before = target.inventory_snapshot(keys); call = target.client._make_api_call; changed = False
    def quarantine(operation, parameters):
        nonlocal changed
        if (not changed and operation == 'TransactWriteItems'
                and any(v.get('ConditionCheck', {}).get('TableName') == fence.config.journal_table
                        for v in parameters['TransactItems'])):
            changed = True
            call('DeleteItem', fence._gets()[part]['Get'])
        return call(operation, parameters)
    monkeypatch.setattr(target.client, '_make_api_call', quarantine)
    with pytest.raises(StoreConflict): repo.transact((Write(keys[0], 1, {'must_not_commit': True}),))
    assert changed and target.inventory_snapshot(keys) == before


@pytest.mark.parametrize('operation', ['query', 'partition_page'])
def test_actual_query_revocation_withholds_data_before_delivery(fenced_case, monkeypatch, operation):
    repo, fence, target, store, keys, intent = fenced_case
    call = target.client._make_api_call; changed = False
    def revoke(operation_name, parameters):
        nonlocal changed
        result = call(operation_name, parameters)
        if not changed and operation_name == 'Query' and parameters['TableName'] in target.tables.values():
            changed = True; call('DeleteItem', fence._gets()[2]['Get'])
        return result
    monkeypatch.setattr(target.client, '_make_api_call', revoke)
    with pytest.raises(StoreUnavailable):
        if operation == 'query': repo.query(prefix='journal-fixture#')
        else: repo.partition_page(table='state')
    assert changed


def test_actual_same_name_wrong_creation_identity_cannot_consume_old_release(fenced_case):
    repo, fence, target, store, keys, intent = fenced_case
    config = replace(fence.config, target_table_ids=(('events', 'wrong-events-creation'), ('state', 'wrong-state-creation')))
    other = RestoreDataFence(target.client, deployment=target.deployment, state_table=target.tables['state'],
                             events_table=target.tables['events'], config=config, tick=monotonic_ns)
    guarded = DynamoRepository(target.client, deployment=target.deployment, state_table=target.tables['state'],
                                events_table=target.tables['events'], data_fence=other)
    with pytest.raises(StoreUnavailable): guarded.snapshot(keys)


def test_actual_fenced_internal_scrub_keeps_marker_and_never_resurrects(fenced_case):
    repo, fence, target, store, keys, intent = fenced_case
    repo.transact((Erase(keys[0], 1, intent.reference_sha256),))
    assert repo.snapshot((keys[0],))[keys[0]] is None
    marker = repo.inventory_snapshot((keys[0],))[keys[0]]
    assert type(marker) is ErasureMarker and repo.erasures((keys[0],))[keys[0]] == marker
    with pytest.raises(StoreConflict): repo.transact((Write(keys[0], None, {'resurrected': True}),))
    with pytest.raises(StoreConflict): repo.transact((Write(keys[0], marker.revision, {'resurrected': True}),))
