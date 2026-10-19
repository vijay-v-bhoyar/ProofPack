"""Composed private inventory/provenance checks, without scope or cleanup authority."""
import weakref

import pytest

from test_inventory_readset import setup, run, LIMITS
from test_replay_copy_lineage import family, INSPECTION
from proofpack.evidence.inventory import collect, InventoryHeld
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.replay_lineage import discover, ReplayHistoryHeld


@pytest.mark.parametrize('direct,nested', [(False, False), (False, True), (True, False)])
def test_private_rehydration_supplies_exact_replay_outputs_without_public_payload(monkeypatch, direct, nested):
    repo, data, calls, _ = setup(monkeypatch, 0)
    root, peers = family(direct=direct, nested=nested)
    for row in (root, *peers): data[row.key] = row
    business = Key('state', 'inspection#'+INSPECTION)
    data[business] = Row(business, 2, {'id': INSPECTION})
    original = collect(repo, limits=LIMITS, deadline_ns=1000, checkpoint=lambda: None, tick=lambda: 1)
    admitted = run(repo, original)
    rows = {r.key: r for r in admitted.rows}
    parsed = discover(rows[root.key], tuple(rows[p.key] for p in peers), deployment='demo',
                      max_records=10, max_payload_bytes=100000)
    assert parsed.replay.sha256 == next(e.payload_sha256 for e in admitted.inventory.entries if e.key == root.key)
    assert {r.key for r in parsed.events} == {p.key for p in peers}
    assert 'PRIVATE-' not in repr(admitted) and 'PRIVATE-' not in repr(parsed)
    # This is provenance for supplied outputs, not raw historical business-family admission.
    assert not hasattr(parsed, 'owner') and not hasattr(admitted, 'delete')


def test_missing_supplied_event_holds_after_successful_inventory_rehydration(monkeypatch):
    repo, data, calls, _ = setup(monkeypatch, 0)
    root, peers = family()
    for row in (root, *peers): data[row.key] = row
    original = collect(repo, limits=LIMITS, deadline_ns=1000, checkpoint=lambda: None, tick=lambda: 1)
    admitted = run(repo, original)
    current = next(r for r in admitted.rows if r.key == root.key)
    with pytest.raises(ReplayHistoryHeld):
        discover(current, (), deployment='demo', max_records=10, max_payload_bytes=100000)


@pytest.mark.parametrize('consumer', ['collector', 'reconciler'])
def test_recycled_integer_identity_cannot_substitute_a_different_client(monkeypatch, consumer):
    repo, data, calls, original = setup(monkeypatch, 1)
    class Client:
        __slots__ = ('__weakref__',)
    repo.client = Client()
    previous = weakref.ref(repo.client)
    original_id = id(repo.client)
    changed = False
    observed = {}
    def checkpoint():
        nonlocal changed
        if changed or not (calls['pages'] if consumer == 'collector' else calls['snapshots']):
            return
        changed = True
        repo.client = None
        observed['original_retained'] = previous() is not None
        replacement = Client()
        repo.client = replacement
        observed['id_reused'] = id(replacement) == original_id
    with pytest.raises(InventoryHeld):
        if consumer == 'collector':
            collect(repo, limits=LIMITS, deadline_ns=1000, checkpoint=checkpoint, tick=lambda: 1)
        else:
            run(repo, original, checkpoint=checkpoint)
    assert changed
    # A changed ID must also hold; retaining the original is the portable protection
    # against reuse. This assertion cannot credit a failed fixture as a successful repair.
    assert observed['original_retained'] or observed['id_reused']


def test_collector_checks_target_after_its_final_clock_sample(monkeypatch):
    repo, data, calls, original = setup(monkeypatch, 1)
    samples = []
    collect(repo, limits=LIMITS, deadline_ns=1000, checkpoint=lambda: None,
            tick=lambda: (samples.append(1) or 1))
    total = len(samples)
    observed = 0
    def changed_at_delivery():
        nonlocal observed
        observed += 1
        if observed == total: repo.client = object()
        return 1
    with pytest.raises(InventoryHeld):
        collect(repo, limits=LIMITS, deadline_ns=1000, checkpoint=lambda: None, tick=changed_at_delivery)
    assert observed == total
