"""Synthetic approved-intent digests on an actual owned local store."""
from copy import deepcopy
from dataclasses import replace
import pytest
from botocore.exceptions import ReadTimeoutError
from test_access_lifecycle import repository_factory
from test_erasure_journal_store import journal_case, raw, append
from test_journal_scope_store import scope_case
from proofpack.evidence.journal_scope import append_journal_scope
from proofpack.evidence.erasure_journal import JournalHeld, JournalConflict


def ready(value):
    service,client,repo,intents,keys,before,options,digest=scope_case(value)
    options['limits']=replace(options['limits'],max_sdk_calls=24,max_work=12)
    return service,client,repo,intents,keys,before,options,digest


def run(v):return append_journal_scope(v[0],v[3],expected_sha256=v[7],**v[6])


def test_actual_scope_recording_and_retry_leave_primary_rows_and_original_journal_unchanged(journal_case):
    v=ready(journal_case);result=run(v)
    original=[raw(v[1],v[0],x) for x in v[3]]
    assert result.record_count==2 and result.work==12 and result.sdk_calls_reserved==24
    assert not result.read_only and result.declared_scope_complete
    assert not any((result.can_erase,result.restore_authorized,result.request_fulfilled,result.global_history_complete,result.independent_iam_verified))
    assert run(v)==result and [raw(v[1],v[0],x) for x in v[3]]==original
    assert v[2].inventory_snapshot(v[4])==v[5]


@pytest.mark.parametrize('fault',['lost_reply','cancelled','expired'])
def test_actual_partial_recording_preserves_history_and_explicit_retry_reconciles(journal_case,monkeypatch,fault):
    v=ready(journal_case);client=v[1];call=client._make_api_call;puts=[0];clock=[1]
    def actual(operation,parameters):
        result=call(operation,parameters)
        if operation=='PutItem' and parameters.get('TableName')==v[0].table:
            puts[0]+=1
            if fault=='expired':clock[0]=1000
            elif fault=='lost_reply':raise ReadTimeoutError(endpoint_url='http://synthetic-local-reply-loss')
            elif fault=='cancelled':raise JournalHeld('synthetic authority cancelled after durable put')
        return result
    monkeypatch.setattr(client,'_make_api_call',actual);v[6]['tick']=lambda:clock[0]
    if fault=='lost_reply':assert run(v).declared_scope_complete
    else:
        with pytest.raises(JournalHeld):run(v)
        assert puts[0]==1
    monkeypatch.setattr(client,'_make_api_call',call);clock[0]=1
    assert run(v).declared_scope_complete
    assert v[2].inventory_snapshot(v[4])==v[5]


def test_actual_conflicting_intent_is_preserved_without_scope_completion(journal_case):
    v=ready(journal_case);append(v[0],replace(v[3][0],source_payload_sha256='f'*64))
    before=[raw(v[1],v[0],x) for x in v[3]]
    with pytest.raises(JournalConflict):run(v)
    assert [raw(v[1],v[0],x) for x in v[3]]==before
    assert v[2].inventory_snapshot(v[4])==v[5]


def test_actual_wrong_manifest_never_records_an_intent(journal_case):
    v=ready(journal_case)
    with pytest.raises(JournalConflict):append_journal_scope(v[0],v[3],expected_sha256='f'*64,**v[6])
    assert all(raw(v[1],v[0],x) is None for x in v[3])
    assert v[2].inventory_snapshot(v[4])==v[5]
