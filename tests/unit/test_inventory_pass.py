from dataclasses import FrozenInstanceError
from hashlib import sha256

import pytest
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import DynamoRepository, Key, Row, ErasureMarker, StoreUnavailable
from proofpack.evidence import inventory
from proofpack.evidence.inventory import collect, InventoryLimits, InventoryHeld


def fixture(monkeypatch, callback=None):
    repo = DynamoRepository(object(), deployment='demo', state_table='state-table', events_table='event-table')
    rows = {'events': [Row(Key('events', 'event#a'), 1, {'secret': 'NEVER_COPY_PAYLOAD'})],
            'state': [Row(Key('state', 'unknown-family#one'), 2, {'count': 3})]}
    calls = []
    def page(**kwargs):
        calls.append(kwargs)
        if callback is not None:
            return callback(repo, kwargs, len(calls))
        return rows[kwargs['table']], None
    monkeypatch.setattr(repo, 'partition_page', page)
    return repo, rows, calls


def run(repo, **kwargs):
    return collect(repo, limits=kwargs.pop('limits', InventoryLimits(2, 10, 10, 10000)),
                   deadline_ns=kwargs.pop('deadline_ns', 100), checkpoint=kwargs.pop('checkpoint', lambda: None),
                   tick=kwargs.pop('tick', lambda: 1), **kwargs)


def test_two_table_summary_is_deterministic_frozen_and_does_not_copy_payload(monkeypatch):
    repo, rows, calls = fixture(monkeypatch)
    first = run(repo); second = run(repo)
    assert first == second and first.pages == 2
    assert [(r.key, r.revision) for r in first.entries] == [(Key('events', 'event#a'), 1), (Key('state', 'unknown-family#one'), 2)]
    assert first.entries[0].payload_sha256 == sha256(b'{"secret":"NEVER_COPY_PAYLOAD"}').hexdigest()
    assert 'NEVER_COPY_PAYLOAD' not in repr(first) and 'secret' not in repr(first)
    rows['events'][0].data['secret'] = 'changed'
    assert first.entries[0].payload_sha256 != run(repo).entries[0].payload_sha256
    with pytest.raises(FrozenInstanceError): first.entries[0].revision = 9
    assert calls[:2] == [{'table': 'events', 'limit': 2, 'start_resource': None}, {'table': 'state', 'limit': 2, 'start_resource': None}]


def test_marker_is_minimal_and_empty_tables_still_require_both_reads(monkeypatch):
    repo, rows, calls = fixture(monkeypatch)
    key = Key('state', 'erased#one')
    rows['events'] = []; rows['state'] = [ErasureMarker(key, 2, 'a'*64, repo._erasure_identity(key))]
    result = run(repo)
    assert result.entries[0].kind == 'erased' and result.entries[0].payload_sha256 is None
    assert result.entries[0].reference_sha256 == 'a'*64
    rows['state'] = []
    empty = run(repo)
    assert empty.entries == () and empty.pages == 2 and len(calls) == 4


@pytest.mark.parametrize('field,value', [('page_size', 0), ('page_size', 101), ('page_size', True),
    ('max_pages', 0), ('max_pages', 1.0), ('max_records', False), ('max_records', -1),
    ('max_summary_bytes', 0), ('max_summary_bytes', '100'), ('max_pages', 2**63)])
def test_explicit_finite_limits_are_required(field, value):
    values = dict(page_size=2, max_pages=10, max_records=10, max_summary_bytes=10000)
    values[field] = value
    with pytest.raises(ValueError): InventoryLimits(**values)


@pytest.mark.parametrize('fault', ['pages', 'records', 'bytes'])
def test_independent_budget_exhaustion_never_returns_partial_success(monkeypatch, fault):
    repo, rows, calls = fixture(monkeypatch)
    limits = InventoryLimits(2, 1 if fault == 'pages' else 10, 1 if fault == 'records' else 10, 1 if fault == 'bytes' else 10000)
    with pytest.raises(InventoryHeld): run(repo, limits=limits)
    assert len(calls) == (0 if fault == 'bytes' else 1 if fault == 'pages' else 2)


def test_exact_summary_byte_boundary_is_enforced(monkeypatch):
    repo, rows, calls = fixture(monkeypatch); size = run(repo).summary_bytes
    assert run(repo, limits=InventoryLimits(2, 10, 10, size)).summary_bytes == size
    with pytest.raises(InventoryHeld): run(repo, limits=InventoryLimits(2, 10, 10, size-1))


@pytest.mark.parametrize('at', [1, 3, 6])
def test_checkpoint_denial_before_after_or_final_never_returns_an_inventory(monkeypatch, at):
    repo, rows, calls = fixture(monkeypatch); checks = 0
    def checkpoint():
        nonlocal checks
        checks += 1
        if checks == at: raise Denied('trusted test checkpoint denied')
    with pytest.raises(Denied): run(repo, checkpoint=checkpoint)
    assert checks == at


@pytest.mark.parametrize('fault', ['deployment', 'tables', 'client'])
def test_target_cannot_change_during_a_page(monkeypatch, fault):
    def respond(repo, kwargs, number):
        if fault == 'deployment': repo.deployment = 'foreign'
        elif fault == 'tables': repo.tables['state'] = 'other-table'
        else: repo.client = object()
        return [], None
    repo, _, calls = fixture(monkeypatch, respond)
    with pytest.raises(InventoryHeld): run(repo)
    assert len(calls) == 1


@pytest.mark.parametrize('values', [[1, 2, 1], [1, 2, 100], [-1], [True]])
def test_deadline_or_clock_reversal_holds(monkeypatch, values):
    repo, _, _ = fixture(monkeypatch); sequence = iter(values)
    with pytest.raises(InventoryHeld): run(repo, tick=lambda: next(sequence))


def test_expiry_during_final_summary_preparation_holds(monkeypatch):
    repo, _, _ = fixture(monkeypatch); encode = inventory._encoded; clock = 1
    def delayed(value):
        nonlocal clock
        result = encode(value)
        if isinstance(value, dict) and value.get('entries'): clock = 100
        return result
    monkeypatch.setattr(inventory, '_encoded', delayed)
    with pytest.raises(InventoryHeld): run(repo, tick=lambda: clock)


@pytest.mark.parametrize('fault', ['duplicate', 'wrong_table', 'revision', 'payload', 'marker', 'cycle', 'wrong_page', 'unavailable'])
def test_invalid_records_pages_and_unavailable_storage_hold(monkeypatch, fault):
    def respond(repo, kwargs, number):
        key = Key(kwargs['table'], 'a')
        if fault == 'unavailable': raise StoreUnavailable('synthetic unavailable')
        if fault == 'wrong_page': return (), None
        if fault == 'cycle': return [], 'a'
        if fault == 'wrong_table': return [Row(Key('state', 'a'), 1, {})], None
        if fault == 'revision': return [Row(key, True, {})], None
        if fault == 'payload': return [Row(key, 1, {'float': 1.5})], None
        if fault == 'marker': return [ErasureMarker(key, 2, 'a'*64, 'b'*64)], None
        return [Row(key, 1, {}), Row(key, 1, {})], None
    repo, _, _ = fixture(monkeypatch, respond)
    with pytest.raises(InventoryHeld): run(repo)


def test_empty_advancing_page_is_not_mistaken_for_end_of_table(monkeypatch):
    def respond(repo, kwargs, number):
        return ([], 'a') if number == 1 else ([], None)
    repo, _, calls = fixture(monkeypatch, respond)
    result = run(repo)
    assert result.entries == () and result.pages == 3
    assert calls[1]['start_resource'] == 'a' and calls[2]['table'] == 'state'
