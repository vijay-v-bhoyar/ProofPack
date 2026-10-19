"""Complete model read sets; injected release proofs are not restore approval."""
from copy import deepcopy
import pytest

from test_restore_fence import world
from proofpack.evidence.repository import DynamoRepository, Key, Write, StoreUnavailable
from proofpack.evidence.inventory import InventoryLimits, InventoryHeld, collect, reconcile

LIMITS = InventoryLimits(100, 20, 1000, 1000000)


def setup(count):
    repo, fence, client, identities = world()
    # Keep the protected fixture; create only model primary records.
    client.items = {k: v for k, v in client.items.items() if k[0] == 'protected-journal'}
    plain = DynamoRepository(client, deployment=repo.deployment,
        state_table=repo.tables['state'], events_table=repo.tables['events'])
    for offset in range(0, count, 100):
        plain.transact(tuple(Write(Key('state', f'item#{i:04}'), None, {'private': 'NEVER_LOG', 'i': i})
            for i in range(offset, min(count, offset+100))))
    def query(**kw):
        client.calls.append(('query', deepcopy(kw)))
        start = kw.get('ExclusiveStartKey', {}).get('sk', {}).get('S', '')
        values = [deepcopy(item) for (table, pk, sk), item in sorted(client.items.items())
            if table == kw['TableName'] and pk == kw['ExpressionAttributeValues'][':deployment']['S'] and sk > start]
        page = values[:kw['Limit']]
        response = {'Items': page, 'Count': len(page), 'ScannedCount': len(page)}
        if len(values) > len(page): response['LastEvaluatedKey'] = {k: page[-1][k] for k in ('pk', 'sk')}
        return response
    client.query = query
    inventory = collect(repo, limits=LIMITS, deadline_ns=1000, tick=lambda: 1, checkpoint=lambda: None)
    assert len(inventory.entries) == count
    client.calls.clear()
    return repo, client, inventory


def run(repo, inventory, **changes):
    return reconcile(repo, inventory, **(dict(limits=LIMITS, max_snapshot_batches=10,
        max_payload_bytes=1000000, deadline_ns=1000, tick=lambda: 1, checkpoint=lambda: None) | changes))


@pytest.mark.parametrize('count', [0, 1, 97, 98, 194, 195])
def test_complete_fenced_readsets_use_exact97_key_batches(count):
    repo, client, inventory = setup(count)
    assert repo.snapshot_capacity == 97
    result = run(repo, inventory)
    assert len(result.rows) == count and result.markers == () and result.inventory == inventory
    assert result.snapshot_batches == (count+96)//97
    snapshots = [[v for v in kw['TransactItems'] if v['Get']['TableName'] != 'protected-journal']
                 for name, kw in client.calls if name == 'transact_get_items']
    sizes = [len(v) for v in snapshots if v]
    assert sizes == [min(97, count-i) for i in range(0, count, 97)]
    assert 'NEVER_LOG' not in repr(result)


def test_unfenced_capacity_is_still100_and_has_no_sdk_side_effect():
    repo = DynamoRepository(object(), deployment='demo', state_table='state-table', events_table='event-table')
    assert repo.snapshot_capacity == 100


def test_fenced_capacity_changes_no_batch_allowance_or_payload_limit():
    repo, client, inventory = setup(195)
    with pytest.raises(InventoryHeld, match='snapshot budget'):
        run(repo, inventory, max_snapshot_batches=2)
    assert client.calls == []
    result = run(repo, inventory, max_snapshot_batches=3)
    assert result.snapshot_batches == 3
    with pytest.raises(InventoryHeld, match='payload budget'):
        run(repo, inventory, max_payload_bytes=result.payload_bytes-1)


@pytest.mark.parametrize('bad', [True, False, 0, 101, 1.0, '97', None])
def test_invalid_adapter_capacity_is_held_before_snapshot_io(monkeypatch, bad):
    repo, client, inventory = setup(2)
    monkeypatch.setattr(DynamoRepository, 'snapshot_capacity', property(lambda self: bad), raising=False)
    with pytest.raises(InventoryHeld): run(repo, inventory)
    assert client.calls == []


@pytest.mark.parametrize('at', ['checkpoint', 'clock'])
def test_capacity_cannot_change_after_admission(monkeypatch, at):
    repo, client, inventory = setup(2); capacity = [97]; called = [False]
    monkeypatch.setattr(DynamoRepository, 'snapshot_capacity', property(lambda self: capacity[0]), raising=False)
    def change():
        if not called[0]: capacity[0] = 100; called[0] = True
    args = {'checkpoint': change} if at == 'checkpoint' else {'tick': lambda: (change(), 1)[1]}
    with pytest.raises(InventoryHeld): run(repo, inventory, **args)
    assert client.calls == []


def test_removed_fence_cannot_silently_raise_capacity_to100():
    repo, client, inventory = setup(2); repo.data_fence = None
    with pytest.raises(StoreUnavailable): _ = repo.snapshot_capacity
    with pytest.raises(InventoryHeld): run(repo, inventory)
    assert client.calls == []


def test_final_clock_capacity_change_withholds_complete_private_readset(monkeypatch):
    repo, client, inventory = setup(2); calls = [0]
    def clock(): calls[0] += 1; return 1
    run(repo, inventory, tick=clock); last = calls[0]
    repo, client, inventory = setup(2); calls[0] = 0; capacity = [97]
    monkeypatch.setattr(DynamoRepository, 'snapshot_capacity', property(lambda self: capacity[0]), raising=False)
    def changed_clock():
        calls[0] += 1
        if calls[0] == last: capacity[0] = 100
        return 1
    with pytest.raises(InventoryHeld): run(repo, inventory, tick=changed_clock)
