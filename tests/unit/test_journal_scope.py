"""Declared-scope readback with synthetic SDK faults; no cleanup authority."""
from copy import deepcopy
from dataclasses import replace
import importlib

import pytest
from test_erasure_journal import setup as journal_setup, append as append_intent
from proofpack.evidence.erasure_journal import JournalHeld, JournalConflict


def api():
    return importlib.import_module('proofpack.evidence.journal_scope')


def case():
    m = api()
    journal, client, repo, intent = journal_setup()
    intents = tuple(replace(intent, resource_sha256=v * 64) for v in ('1', '2', '3'))
    limits = m.JournalScopeLimits(3, 10000, 15, 11)
    return m, journal, client, repo, intents, limits


def options(limits, **changes):
    return {'limits': limits, 'deadline_ns': 1000, 'tick': lambda: 1,
            'checkpoint': lambda: None, **changes}


def prepare(journal, intents):
    for intent in intents:
        append_intent(journal, intent)


def test_known_complete_scope_reads_all_original_rows_and_grants_no_action():
    m, journal, client, _, intents, limits = case()
    digest = m.journal_scope_sha256(journal, intents, **options(limits))
    assert client.calls == []
    prepare(journal, intents)
    before = deepcopy(client.items)
    client.calls.clear()
    result = m.read_journal_scope(journal, intents, expected_sha256=digest, **options(limits))
    assert result.sha256 == digest and result.record_count == 3 and result.work == 11
    assert result.sdk_calls_reserved == len(client.calls) == 15
    assert result.declared_scope_complete and result.historical and result.read_only
    assert not any((result.can_erase, result.restore_authorized, result.request_fulfilled,
                    result.global_history_complete, result.independent_iam_verified))
    assert before == client.items
    assert not any(name == 'put_item' for name, _ in client.calls)
    assert all(intent.resource_sha256 not in repr(result) for intent in intents)


@pytest.mark.parametrize('fault', ['missing_final', 'different_original', 'corrupt_final'])
def test_no_partial_coverage_for_missing_or_wrong_original_record(fault):
    m, journal, client, _, intents, limits = case()
    digest = m.journal_scope_sha256(journal, intents, **options(limits))
    prepare(journal, intents[:-1])
    if fault != 'missing_final':
        append_intent(journal, replace(intents[-1], source_payload_sha256='f' * 64)
                      if fault == 'different_original' else intents[-1])
    if fault == 'corrupt_final':
        key = tuple(journal._key(intents[-1].reference_sha256, intents[-1].resource_sha256)[k]['S'] for k in ('pk', 'sk'))
        client.items[key]['sha256']['S'] = '0' * 64
    before = deepcopy(client.items)
    client.calls.clear()
    with pytest.raises(JournalHeld):
        m.read_journal_scope(journal, intents, expected_sha256=digest, **options(limits))
    assert client.items == before and len(client.calls) <= 15
    assert not any(name == 'put_item' for name, _ in client.calls)


def test_changed_expected_digest_conflicts_before_any_sdk_call():
    m, journal, client, _, intents, limits = case()
    with pytest.raises(JournalConflict):
        m.read_journal_scope(journal, intents, expected_sha256='f' * 64, **options(limits))
    assert client.calls == []


@pytest.mark.parametrize('fault', ['empty', 'list', 'duplicate', 'reversed', 'reference',
                                 'classification', 'confirmation', 'created_time', 'forged_revision'])
def test_invalid_declared_scope_never_reaches_storage(fault):
    m, journal, client, _, intents, limits = case()
    if fault == 'empty':
        intents = ()
    elif fault == 'list':
        intents = list(intents)
    elif fault == 'duplicate':
        intents = (intents[0], intents[0], intents[2])
    elif fault == 'reversed':
        intents = tuple(reversed(intents))
    else:
        field, value = {'reference': ('reference_sha256', 'f' * 64),
                        'classification': ('classification_sha256', 'f' * 64),
                        'confirmation': ('confirmation_sha256', 'f' * 64),
                        'created_time': ('created_at_ms', 101),
                        'forged_revision': ('source_revision', True)}[fault]
        if fault == 'forged_revision':
            object.__setattr__(intents[1], field, value)
        else:
            intents = (intents[0], replace(intents[1], **{field: value}), intents[2])
    with pytest.raises(ValueError):
        m.journal_scope_sha256(journal, intents, **options(limits))
    assert client.calls == []


@pytest.mark.parametrize('field', ['max_records', 'max_manifest_bytes', 'max_sdk_calls', 'max_work'])
@pytest.mark.parametrize('value', [True, 0, -1, 2**63])
def test_all_scope_limits_require_explicit_positive_exact_integers(field, value):
    m = api()
    values = dict(max_records=3, max_manifest_bytes=10000, max_sdk_calls=15, max_work=11)
    values[field] = value
    with pytest.raises(ValueError):
        m.JournalScopeLimits(**values)


@pytest.mark.parametrize('field,value', [('max_records', 2), ('max_sdk_calls', 14), ('max_work', 10)])
def test_scope_reserves_whole_original_read_before_any_io(field, value):
    m, journal, client, _, intents, limits = case()
    limits = replace(limits, **{field: value})
    with pytest.raises(JournalHeld):
        m.read_journal_scope(journal, intents, expected_sha256='f' * 64, **options(limits))
    assert client.calls == []


def test_exact_manifest_byte_limit_succeeds_and_one_below_holds_before_io():
    m, journal, client, _, intents, limits = case()
    digest = m.journal_scope_sha256(journal, intents, **options(limits))
    prepare(journal, intents)
    first = m.read_journal_scope(journal, intents, expected_sha256=digest, **options(limits))
    exact = replace(limits, max_manifest_bytes=first.manifest_bytes)
    assert m.read_journal_scope(journal, intents, expected_sha256=digest, **options(exact)).sha256 == digest
    client.calls.clear()
    with pytest.raises(JournalHeld):
        m.read_journal_scope(journal, intents, expected_sha256=digest,
                             **options(replace(exact, max_manifest_bytes=exact.max_manifest_bytes - 1)))
    assert client.calls == []


@pytest.mark.parametrize('fault', ['expiry', 'clock_reversal', 'scope_limits', 'journal_limits', 'target', 'late_intent'])
def test_late_completion_changes_never_return_coverage(monkeypatch, fault):
    m, journal, client, repo, intents, limits = case()
    digest = m.journal_scope_sha256(journal, intents, **options(limits))
    prepare(journal, intents)
    before = deepcopy(client.items)
    get = client.get_item
    clock = [1]
    count = [0]
    def changed(**kwargs):
        value = get(**kwargs)
        count[0] += 1
        if count[0] == 3:
            if fault == 'expiry': clock[0] = 1000
            elif fault == 'clock_reversal': clock[0] = 0
            elif fault == 'scope_limits': object.__setattr__(limits, 'max_sdk_calls', 16)
            elif fault == 'journal_limits': object.__setattr__(journal.limits, 'max_sdk_calls', 8)
            elif fault == 'target': repo.tables['events'] = 'foreign-events'
            elif fault == 'late_intent': object.__setattr__(intents[0], 'source_revision', True)
        return value
    monkeypatch.setattr(client, 'get_item', changed)
    with pytest.raises(JournalHeld):
        m.read_journal_scope(journal, intents, expected_sha256=digest, **options(limits, tick=lambda: clock[0]))
    assert client.items == before


def test_scope_digest_is_bound_to_original_storage_target():
    m, journal, _, _, intents, limits = case()
    expected = m.journal_scope_sha256(journal, intents, **options(limits))
    other, _, _, _ = journal_setup()
    # A separate valid deployment changes the binding, without SDK access.
    other.repository.deployment = 'other-deployment'
    from proofpack.evidence.erasure_journal import DynamoErasureJournal
    other = DynamoErasureJournal(other.repository, journal_table=other.table,
                                expected_table_arn=other.table_arn, limits=other.limits)
    assert m.journal_scope_sha256(other, intents, **options(limits)) != expected


def test_restored_manifest_mutation_cannot_hide_a_missing_original_member(monkeypatch):
    m, journal, client, _, intents, limits = case()
    digest = m.journal_scope_sha256(journal, intents, **options(limits))
    # The actual original second intent is absent. A different durable member
    # must not be substituted and then hidden by restoring the input later.
    prepare(journal, (intents[0], replace(intents[1], resource_sha256='4' * 64), intents[2]))
    before = deepcopy(client.items)
    get = client.get_item
    count = [0]
    def substitute(**kwargs):
        result = get(**kwargs)
        count[0] += 1
        if count[0] == 1:
            object.__setattr__(intents[1], 'resource_sha256', '4' * 64)
        elif count[0] == 3:
            object.__setattr__(intents[1], 'resource_sha256', '2' * 64)
        return result
    monkeypatch.setattr(client, 'get_item', substitute)
    with pytest.raises(JournalHeld):
        m.read_journal_scope(journal, intents, expected_sha256=digest, **options(limits))
    assert client.items == before
