"""Actual local reads and erased markers; no distributed barrier or removal workflow proof."""
import pytest

from test_access_lifecycle import world, repository_factory
from proofpack.evidence.inventory import collect, reconcile, InventoryHeld, InventoryLimits
from proofpack.evidence.repository import Key, Write, Erase


LIMITS = InventoryLimits(50, 100, 1000, 2000000)


def inventory(repo):
    return collect(repo, limits=LIMITS, deadline_ns=1000, checkpoint=lambda: None, tick=lambda: 1)


def read(repo, original, **options):
    return reconcile(repo, original, limits=LIMITS, max_snapshot_batches=10,
                     max_payload_bytes=4000000, deadline_ns=1000,
                     checkpoint=lambda: None, tick=lambda: 1, **options)


def test_actual_empty_partition_still_requires_complete_followup(repository_factory):
    repo = repository_factory()
    original = inventory(repo)
    result = read(repo, original)
    assert original.entries == () and original.pages == 2
    assert result.rows == () and result.markers == () and result.snapshot_batches == 0


def test_actual_live_and_erased_metadata_keep_separate_visibility(world):
    repo = world[1]; key = Key('state', 'readset-erased#synthetic')
    repo.transact((Write(key, None, {'secret': 'REMOVED-PRIVATE'}),))
    repo.transact((Erase(key, 1, 'a'*64),))
    original = inventory(repo); result = read(repo, original)
    assert any(marker.key == key for marker in result.markers)
    assert all(row.key != key for row in result.rows)
    assert repo.snapshot((key,))[key] is None and repo.erasures((key,))[key] is not None
    assert 'REMOVED-PRIVATE' not in repr(result)
    assert any(row.key.table == 'events' for row in result.rows)


def test_actual_hydration_crosses_100_key_atomic_batch_boundary(repository_factory):
    repo = repository_factory()
    writes = tuple(Write(Key('state', f'unclassified#{i:04}'), None, {'ordinal': i}) for i in range(205))
    for start in range(0, len(writes), 100): repo.transact(writes[start:start+100])
    original = inventory(repo); result = read(repo, original)
    assert len(result.rows) == 205 and result.snapshot_batches == 3
    assert [int(row.data['ordinal']) for row in result.rows] == list(range(205))
    # Unknown families are retained for later classification, never silently ignored.
    assert all(entry.key.resource.startswith('unclassified#') for entry in result.inventory.entries)


@pytest.mark.parametrize('change', ['insert', 'update', 'erase'])
def test_actual_write_between_hydration_and_followup_holds(world, monkeypatch, change):
    repo = world[1]; key = Key('state', 'readset-source#synthetic')
    repo.transact((Write(key, None, {'secret': 'ORIGINAL-PRIVATE'}),))
    original = inventory(repo); snapshot = repo.inventory_snapshot; changed = False
    def between(keys):
        nonlocal changed
        rows = snapshot(keys)
        if not changed:
            changed = True
            if change == 'insert': repo.transact((Write(Key('events', 'unknown#late'), None, {'late': True}),))
            elif change == 'update': repo.transact((Write(key, 1, {'secret': 'CHANGED-PRIVATE'}),))
            else: repo.transact((Erase(key, 1, 'b'*64),))
        return rows
    monkeypatch.setattr(repo, 'inventory_snapshot', between)
    with pytest.raises(InventoryHeld): read(repo, original)
    assert changed
