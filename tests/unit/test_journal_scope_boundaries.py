"""Additional scope boundaries; the original mutation oracle stays unchanged."""
from dataclasses import replace
import pytest
from test_journal_scope import case, options
from test_erasure_journal import setup as journal_setup
from proofpack.evidence.erasure_journal import JournalHeld


def test_order_validation_uses_the_values_actually_hashed(monkeypatch):
    m, journal, client, _, intents, limits = case()
    unsorted = (intents[0], intents[2], intents[1])
    body = m._body
    def change_after_validation(intent):
        result = body(intent)
        if intent is unsorted[1]:
            object.__setattr__(intent, 'resource_sha256', '2' * 64)
        elif intent is unsorted[2]:
            object.__setattr__(intent, 'resource_sha256', '3' * 64)
        return result
    monkeypatch.setattr(m, '_body', change_after_validation)
    with pytest.raises(ValueError):
        m.journal_scope_sha256(journal, unsorted, **options(limits))
    assert client.calls == []


def test_expired_original_deadline_denies_before_storage():
    m, journal, client, _, intents, limits = case()
    with pytest.raises(JournalHeld):
        m.journal_scope_sha256(journal, intents, **options(limits, tick=lambda: 1000))
    assert client.calls == []


def test_underlying_journal_read_must_fit_original_five_call_protocol():
    m, _, _, _, intents, limits = case()
    journal, client, _, _ = journal_setup(calls=4)
    with pytest.raises(JournalHeld):
        m.journal_scope_sha256(journal, intents, **options(limits))
    assert client.calls == []
