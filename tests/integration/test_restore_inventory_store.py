"""Owned local tables and synthetic backup provenance; no actual AWS restore."""
from dataclasses import asdict
from hashlib import sha256
from time import monotonic_ns
from uuid import uuid4
import pytest

from test_access_lifecycle import repository_factory
from test_erasure_journal_store import journal_case
from proofpack.evidence.repository import DynamoRepository, Write, Erase
from proofpack.evidence.inventory import InventoryLimits, InventoryPass, collect, _encoded
from proofpack.evidence.journal_anchors import JournalAnchorStore, JournalAnchorLimits
from proofpack.evidence.journal_scope import JournalScopeLimits, append_journal_scope, journal_scope_sha256
from proofpack.evidence.erasure_journal import JournalHeld
from proofpack.evidence.restore_inventory import RestoreInventoryLimits, read_restore_inventory


@pytest.fixture
def restore_case(journal_case):
    journal, client, original, intent, keys, before = journal_case
    store = JournalAnchorStore(journal, genesis_sha256='9'*64,
                              limits=JournalAnchorLimits(4, 8, 4096, 256, 10000))
    options = dict(deadline_ns=monotonic_ns()+20000000000, tick=monotonic_ns, checkpoint=lambda: None)
    root = store.initialize(**options)
    bounds = JournalScopeLimits(1, 4096, 12, 20)
    digest = journal_scope_sha256(journal, (intent,), limits=bounds, **options)
    append_journal_scope(journal, (intent,), expected_sha256=digest, limits=bounds, **options)
    head = store.seal((intent,), expected_head=root.checkpoint, scope_sha256=digest, **options).checkpoint
    limits = RestoreInventoryLimits(InventoryLimits(1, 12, 20, 20000), 1000, 100000)
    backup = collect(original, limits=limits.inventory, **options)
    suffix = uuid4().hex[:12]
    names = {'state': 'restore-state-'+suffix, 'events': 'restore-events-'+suffix}
    created = []
    try:
        arns = {}
        for role, name in names.items():
            client.create_table(TableName=name,
                KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
                AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}],
                BillingMode='PAY_PER_REQUEST')
            created.append(name)
            arns[role] = client.describe_table(TableName=name)['Table']['TableArn']
        target = DynamoRepository(client, deployment=original.deployment,
                                 state_table=names['state'], events_table=names['events'])
        target.transact(tuple(Write(key, None, before[key].data) for key in keys))
        kw = dict(expected_head=head, target_arns=tuple(sorted(arns.items())), backup_sha256='a'*64,
                  source_inventory=backup, artifact_sha256='b'*64, limits=limits, **options)
        yield store, target, original, intent, keys, kw
        assert original.inventory_snapshot(keys) == before
    finally:
        for name in created:
            client.delete_table(TableName=name)


def synthetic_backup(target, original, kw):
    """Construct explicit synthetic provenance for adverse marker/absence inputs."""
    inventory = collect(target, limits=kw['limits'].inventory,
                        **{k: kw[k] for k in ('deadline_ns', 'tick', 'checkpoint')})
    encoded = _encoded({'deployment': original.deployment, 'tables': original.tables,
                       'entries': [asdict(e) for e in inventory.entries]})
    return InventoryPass(original.deployment, tuple(sorted(original.tables.items())), inventory.entries,
                         inventory.pages, sha256(encoded).hexdigest(), len(encoded))


def test_actual_complete_restore_inventory_matches_distinct_tables_and_original_intent(restore_case):
    store, target, original, intent, keys, kw = restore_case
    before = target.inventory_snapshot(keys)
    result = read_restore_inventory(store, target, **kw)
    assert result.matches[0].status == 'pending_effect'
    assert result.matches[0].resource_sha256 == original._erasure_identity(keys[0])
    assert result.source_tables != result.target_tables
    assert result.source_inventory_sha256 != result.target_inventory_sha256
    assert not any((result.can_erase, result.can_release, result.restore_authorized, result.request_fulfilled))
    assert target.inventory_snapshot(keys) == before


def test_actual_marker_observation_does_not_prove_approved_cleanup(restore_case):
    store, target, original, intent, keys, kw = restore_case
    target.transact((Erase(keys[0], 1, intent.reference_sha256),))
    kw['source_inventory'] = synthetic_backup(target, original, kw)
    result = read_restore_inventory(store, target, **kw)
    assert result.matches[0].status == 'marker_observed'
    assert result.can_release is False and result.request_fulfilled is False
    assert target.erasures((keys[0],))[keys[0]].reference_sha256 == intent.reference_sha256


def test_actual_absence_is_unresolved_even_with_complete_synthetic_inventory(restore_case):
    store, target, original, intent, keys, kw = restore_case
    target.client.delete_item(TableName=target.tables[keys[0].table], Key=target.key(keys[0]))
    kw['source_inventory'] = synthetic_backup(target, original, kw)
    result = read_restore_inventory(store, target, **kw)
    assert result.matches[0].status == 'unresolved_absent'
    assert result.can_release is False and result.request_fulfilled is False


@pytest.mark.parametrize('fault', ['missing_target_row', 'wrong_arn', 'missing_intent'])
def test_actual_restore_inventory_rejects_incomplete_target_or_history(restore_case, fault):
    store, target, original, intent, keys, kw = restore_case
    if fault == 'missing_target_row':
        target.client.delete_item(TableName=target.tables[keys[0].table], Key=target.key(keys[0]))
    elif fault == 'wrong_arn':
        kw['target_arns'] = tuple((role, arn+'-wrong') for role, arn in kw['target_arns'])
    else:
        target.client.delete_item(TableName=store.journal.table,
                                 Key=store.journal._key(intent.reference_sha256, intent.resource_sha256))
    with pytest.raises(JournalHeld): read_restore_inventory(store, target, **kw)


def test_actual_target_change_between_pages_never_delivers_complete_result(restore_case, monkeypatch):
    store, target, original, intent, keys, kw = restore_case
    call = target.client._make_api_call
    changed = False
    def mutate(operation, parameters):
        nonlocal changed
        result = call(operation, parameters)
        if not changed and operation == 'Query' and parameters['TableName'] in target.tables.values():
            changed = True
            target.transact((Write(keys[0], 1, {'changed': 'synthetic'}),))
        return result
    monkeypatch.setattr(target.client, '_make_api_call', mutate)
    with pytest.raises(JournalHeld): read_restore_inventory(store, target, **kw)
