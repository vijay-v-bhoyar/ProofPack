"""Real owned local journal reads; synthetic digests are not approval evidence."""
from dataclasses import replace
from copy import deepcopy
import pytest
from test_access_lifecycle import repository_factory
from test_erasure_journal_store import journal_case, append, raw
from proofpack.evidence.erasure_journal import JournalHeld, JournalConflict
from proofpack.evidence.journal_scope import JournalScopeLimits, journal_scope_sha256, read_journal_scope
from proofpack.evidence.resource_bindings import _payload_sha256


def scope_case(value):
    service, client, repo, intent, keys, before = value
    other = replace(intent, resource_sha256=repo._erasure_identity(keys[1]),
                    source_revision=before[keys[1]].revision,
                    source_payload_sha256=_payload_sha256(before[keys[1]].data))
    intents = tuple(sorted((intent, other), key=lambda item: item.resource_sha256))
    limits = JournalScopeLimits(2, 10000, 10, 8)
    options = dict(limits=limits, deadline_ns=1000, tick=lambda: 1, checkpoint=lambda: None)
    digest = journal_scope_sha256(service, intents, **options)
    return service, client, repo, intents, keys, before, options, digest


def test_actual_complete_scope_reads_every_original_and_changes_no_record(journal_case):
    service, client, repo, intents, keys, before, options, digest = scope_case(journal_case)
    for intent in intents:
        append(service, intent)
    original = [raw(client, service, item) for item in intents]
    result = read_journal_scope(service, intents, expected_sha256=digest, **options)
    assert result.sha256 == digest and result.record_count == 2 and result.work == 8
    assert result.sdk_calls_reserved == 10 and result.declared_scope_complete
    assert not any((result.can_erase, result.restore_authorized, result.request_fulfilled,
                    result.global_history_complete, result.independent_iam_verified))
    assert [raw(client, service, item) for item in intents] == original
    assert repo.inventory_snapshot(keys) == before


@pytest.mark.parametrize('fault', ['missing', 'different', 'corrupt', 'wrong_expected', 'expiry', 'cancelled'])
def test_actual_partial_or_late_scope_never_returns_complete_coverage(journal_case, monkeypatch, fault):
    service, client, repo, intents, keys, before, options, digest = scope_case(journal_case)
    append(service, intents[0])
    if fault != 'missing':
        append(service, replace(intents[1], source_payload_sha256='f' * 64)
               if fault == 'different' else intents[1])
    if fault == 'corrupt':
        item = deepcopy(raw(client, service, intents[1]))
        item['sha256']['S'] = '0' * 64
        client.put_item(TableName=service.table, Item=item)
    original = [raw(client, service, item) for item in intents]
    clock = [1]
    count = [0]
    call = client._make_api_call
    def actual_then_late(operation, parameters):
        result = call(operation, parameters)
        if operation == 'GetItem' and parameters.get('TableName') == service.table:
            count[0] += 1
            if count[0] == 2 and fault == 'expiry':
                clock[0] = 1000
        return result
    monkeypatch.setattr(client, '_make_api_call', actual_then_late)
    def checkpoint():
        if fault == 'cancelled' and count[0] >= 1:
            raise JournalHeld('synthetic current admission revoked')
    options.update(tick=lambda: clock[0], checkpoint=checkpoint)
    with pytest.raises(JournalConflict if fault == 'wrong_expected' else JournalHeld):
        read_journal_scope(service, intents, expected_sha256='f' * 64 if fault == 'wrong_expected' else digest, **options)
    assert [raw(client, service, item) for item in intents] == original
    assert repo.inventory_snapshot(keys) == before
