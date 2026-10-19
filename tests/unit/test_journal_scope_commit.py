"""Declared intent recording on synthetic SDK protocol; no erasure authority."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
import pytest
from botocore.exceptions import ReadTimeoutError
from test_journal_scope import case, options
from proofpack.evidence.erasure_journal import JournalHeld, JournalConflict


def run_case():
    m,j,c,r,intents,_=case()
    bounds=m.JournalScopeLimits(3,10000,36,17)
    kw=options(bounds)
    expected=m.journal_scope_sha256(j,intents,**kw)
    return m,j,c,intents,kw,expected


def commit(v,**changes):
    m,j,c,intents,kw,expected=v
    return m.append_journal_scope(j,intents,expected_sha256=expected,**(kw|changes))


def test_complete_recording_and_exact_retry_do_not_rewrite_original_intents():
    v=run_case();m,j,c,intents,kw,expected=v
    result=commit(v);original=deepcopy(c.items)
    assert result.sha256==expected and result.record_count==3 and result.work==17
    assert result.sdk_calls_reserved==len(c.calls)==36
    assert result.historical and not result.read_only and result.declared_scope_complete
    assert all(getattr(result,k) is False for k in ('can_erase','restore_authorized','request_fulfilled','global_history_complete','independent_iam_verified'))
    c.calls.clear();assert commit(v)==result and c.items==original
    assert all(name!='put_item' for name,_ in c.calls)
    with pytest.raises(FrozenInstanceError):result.read_only=True


@pytest.mark.parametrize('field,value',[('max_records',2),('max_sdk_calls',35),('max_work',16)])
def test_full_original_reservation_is_required_before_any_storage_call(field,value):
    v=run_case()
    with pytest.raises(JournalHeld):commit(v,limits=replace(v[4]['limits'],**{field:value}))
    assert not v[2].calls and not v[2].items


def test_wrong_expected_manifest_denies_all_writes():
    v=run_case();m,j,c,intents,kw,_=v
    with pytest.raises(JournalConflict):m.append_journal_scope(j,intents,expected_sha256='f'*64,**kw)
    assert not c.calls and not c.items


def test_lost_put_reply_is_reconciled_from_exact_original_readback():
    v=run_case()
    def lost():raise ReadTimeoutError(endpoint_url='https://synthetic.invalid')
    v[2].after_put=lost
    assert commit(v).declared_scope_complete and len(v[2].items)==3


def test_partial_attempt_is_preserved_and_exact_explicit_retry_fills_missing_records():
    v=run_case();c=v[2]
    def stop():raise JournalHeld('synthetic stop after first durable put')
    c.after_put=stop
    with pytest.raises(JournalHeld):commit(v)
    assert len(c.items)==1
    original=deepcopy(c.items);c.after_put=None
    assert commit(v).declared_scope_complete and len(c.items)==3
    assert all(c.items[k]==row for k,row in original.items())


def test_conflicting_original_row_is_never_overwritten_or_accepted():
    from test_erasure_journal import append
    v=run_case();append(v[1],replace(v[3][0],source_payload_sha256='f'*64));before=deepcopy(v[2].items)
    with pytest.raises(JournalConflict):commit(v)
    assert v[2].items==before


@pytest.mark.parametrize('fault',['expiry','cancel','target'])
def test_original_context_change_after_partial_write_never_returns_success(fault):
    v=run_case();clock=[1];stopped=[False]
    def changed():
        stopped[0]=True
        if fault=='expiry':clock[0]=1000
        if fault=='target':v[1].table='different'
    def check():
        if stopped[0] and fault=='cancel':raise JournalHeld('synthetic cancelled authority')
    v[2].after_put=changed
    with pytest.raises(JournalHeld):commit(v,tick=lambda:clock[0],checkpoint=check)
    assert len(v[2].items)==1


def test_final_missing_readback_does_not_accept_successful_append_prefix(monkeypatch):
    v=run_case();c=v[2];original=c.get_item;gets=[0]
    def get(**kw):
        gets[0]+=1
        return {} if gets[0]>6 else original(**kw)
    monkeypatch.setattr(c,'get_item',get)
    with pytest.raises(JournalHeld):commit(v)
    assert len(c.items)==3


def test_every_item_is_preflighted_before_first_put(monkeypatch):
    v=run_case();j=v[1];original=type(j)._item
    def item(self,intent):
        if intent.resource_sha256==v[3][-1].resource_sha256:raise JournalHeld('synthetic complete item overflow')
        return original(self,intent)
    monkeypatch.setattr(type(j),'_item',item)
    with pytest.raises(JournalHeld):commit(v)
    assert not v[2].calls and not v[2].items


def test_restored_caller_mutation_cannot_replace_an_original_scope_member():
    v=run_case();c=v[2];second=v[3][1];old=second.resource_sha256;puts=[0]
    def change():
        puts[0]+=1
        object.__setattr__(second,'resource_sha256','4'*64 if puts[0]==1 else old)
    c.after_put=change
    result=commit(v)
    assert result.declared_scope_complete and second.resource_sha256==old
    assert all(k[1].startswith('resource#'+x.resource_sha256) for k,x in zip(sorted(c.items),v[3]))
