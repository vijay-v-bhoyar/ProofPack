"""Actual finite enumeration; checkpoints here are synthetic, not an installed barrier."""
import time
from dataclasses import replace
import pytest
from test_access_lifecycle import repository_factory
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import Key, Write, Erase
from proofpack.evidence.inventory import collect, InventoryLimits, InventoryHeld


def limits(page_size=1):
    return InventoryLimits(page_size, 20, 20, 10000)


def test_actual_two_table_inventory_is_deterministic_payload_free_and_deployment_scoped(repository_factory):
    repo = repository_factory(); other = repository_factory()
    key = Key('state', 'inspection#one'); removed = Key('state', 'unknown-family#removed')
    repo.transact((Write(key, None, {'private': 'NEVER_COPY_PAYLOAD'}), Write(removed, None, {'private': 'removed'}),
                   Write(Key('events', 'event#one'), None, {'kind': 'synthetic'})))
    repo.transact((Erase(removed, 1, 'a'*64),))
    other.transact((Write(key, None, {'foreign': True}),))
    first = collect(repo, limits=limits(), deadline_ns=time.monotonic_ns()+15000000000, checkpoint=lambda: None)
    second = collect(repo, limits=limits(2), deadline_ns=time.monotonic_ns()+15000000000, checkpoint=lambda: None)
    assert first.entries == second.entries and first.summary_sha256 == second.summary_sha256
    assert [entry.key for entry in first.entries] == [Key('events', 'event#one'), key, removed]
    assert first.entries[-1].kind == 'erased' and first.entries[-1].reference_sha256 == 'a'*64
    assert 'NEVER_COPY_PAYLOAD' not in repr(first) and 'foreign' not in repr(first)
    assert first.pages >= second.pages >= 2
    repo.transact((Write(key, 1, {'private': 'changed'}),))
    later = collect(repo, limits=limits(), deadline_ns=time.monotonic_ns()+15000000000, checkpoint=lambda: None)
    assert first.entries[1].revision == 1 and later.entries[1].revision == 2
    assert later.summary_sha256 != first.summary_sha256


def test_actual_read_followed_by_checkpoint_revocation_returns_no_inventory(repository_factory, monkeypatch):
    repo = repository_factory(); repo.transact((Write(Key('events', 'one'), None, {}),))
    original = repo.partition_page; allowed = True; calls = 0
    def read(**kwargs):
        nonlocal allowed, calls
        result = original(**kwargs); calls += 1; allowed = False
        return result
    def checkpoint():
        if not allowed: raise Denied('synthetic authority checkpoint revoked')
    monkeypatch.setattr(repo, 'partition_page', read)
    with pytest.raises(Denied):
        collect(repo, limits=limits(), deadline_ns=time.monotonic_ns()+15000000000, checkpoint=checkpoint)
    assert calls == 1


@pytest.mark.parametrize('budget', ['max_pages', 'max_records', 'max_summary_bytes'])
def test_real_inventory_budgets_are_independent_holds(repository_factory, budget):
    repo = repository_factory()
    repo.transact((Write(Key('events', 'event#one'), None, {}), Write(Key('state', 'row#one'), None, {})))
    with pytest.raises(InventoryHeld):
        collect(repo, limits=replace(limits(), **{budget: 1}), deadline_ns=time.monotonic_ns()+15000000000,
                checkpoint=lambda: None)
