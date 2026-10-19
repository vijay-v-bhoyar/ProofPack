"""Genuine metadata/auth writers through the original held reader; no provider proof."""
from copy import deepcopy
from dataclasses import asdict, replace, FrozenInstanceError
from decimal import Decimal
import pytest

from test_owner_policy_obligations import configured, no_sdk
from test_owner_auth_review_host import bounds
from test_corpus_accounting import LIMITS
from test_owner_metadata import cancel, create
from proofpack.evidence.held_corpus import HeldCorpusHeld
from proofpack.evidence.metadata_history import MetadataHistoryLimits, MetadataHistoryHeld, validate
from proofpack.evidence.repository import Key, Row


def limits(): return MetadataHistoryLimits(1000,10_000_000,10000,200000,10_000_000,10,20)


def read(w, **changes):
    config=bounds()
    return w[2].read_metadata_accounting(**(dict(request_id=w[7]['id'],inspection_ids=tuple(w[7]['inspection_ids']),
        deadline_ns=10**12,accounting_limits=LIMITS,runtime_context_limits=config.runtime,
        access_context_limits=config.access,auth_history_limits=config.auth,metadata_history_limits=limits(),
        metadata_configuration_sha256=w[1]._configuration) | changes))


def test_current_request_has_content_membership_but_policy_stays_unresolved(monkeypatch):
    w=configured(monkeypatch);before=deepcopy(w[5]);result=read(w)
    history=result.corpus.metadata_history
    assert result.accounting.policy=='conservative-family-accounting-v6'
    assert history.policy=='held-metadata-request-history-v1'
    assert history.source_records==len(before) and len(history.records)==4
    assert {r.family for r in history.records}=={'metadata-request','metadata-operation','metadata-event','metadata-quota'}
    root=next(r for r in result.accounting.entries if r.reference.key.resource=='metadata-request#'+w[7]['id'])
    assert root.inspection_ids==tuple(w[7]['inspection_ids'])
    assert root.disposition=='UNRESOLVED' and root.reason=='METADATA_RETENTION_POLICY_REQUIRED'
    assert 'VALIDATED_METADATA_REQUEST_SCOPE' in root.policies
    opaque=[r for r in history.records if r.family!='metadata-request']
    assert all(not r.inspection_ids for r in opaque)
    assert all(v is False for v in (history.historical_authority_proven,history.policy_resolved,history.can_confirm_cleanup,history.request_fulfilled))
    assert history.read_only and w[5]==before and w[-1].wait_for_drain(0)
    assert not any(token in repr(history) for token in ['metadata-request#','idempotency#','inspection#','PRIVATE-PAYLOAD'])
    with pytest.raises(FrozenInstanceError): history.policy_resolved=True


def test_cancelled_history_and_exact_retries_do_not_refund_or_repeat_quota(monkeypatch):
    w=configured(monkeypatch)
    cancel(w[1],w[3],w[7])
    again=create(w[1],w[3],idempotency_key='next-history-request')
    w=(*w[:7],again,w[8]);before=deepcopy(w[5])
    result=read(w);history=result.corpus.metadata_history
    assert len(history.records)==9
    assert sum(r.family=='metadata-request' for r in history.records)==2
    assert history.historical_dependencies_unavailable>0
    quota=next(row for key,row in w[5].items() if key.resource.startswith('metadata-owner-quota#'))
    assert quota.revision==3 and quota.data['count']==3
    assert w[5]==before and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('field,metric',[
    ('max_records','source_records'),('max_payload_bytes','payload_bytes'),('max_dependencies','dependencies'),
    ('max_work','work'),('max_summary_bytes','summary_bytes')])
def test_independent_exact_and_one_below_history_bounds(monkeypatch,field,metric):
    w=configured(monkeypatch);observed=read(w).corpus.metadata_history
    exact=replace(limits(),**{field:getattr(observed,metric)})
    assert getattr(read(w,metadata_history_limits=exact).corpus.metadata_history,metric)==getattr(observed,metric)
    before=deepcopy(w[5])
    with pytest.raises(HeldCorpusHeld): read(w,metadata_history_limits=replace(exact,**{field:getattr(exact,field)-1}))
    assert w[5]==before and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('fault',['missing-event','duplicate-event','operation-result','operation-body','missing-quota','quota-count','quota-revision','future-event','creator-scope','unknown-kind'])
def test_incomplete_corrupt_or_conflicting_family_never_partially_delivers(monkeypatch,fault):
    w=configured(monkeypatch);rows=w[5]
    event=next(r for r in rows.values() if r.key.table=='events' and r.data.get('kind')=='owner-metadata-create')
    operation=next(r for r in rows.values() if r.key.table=='state' and r.key.resource.startswith('idempotency#')
                   and r.data.get('resource_bindings',{}).get('operation')=='owner-metadata-create')
    quota=next(r for r in rows.values() if r.key.resource.startswith('metadata-owner-quota#'))
    if fault=='missing-event': del rows[event.key]
    elif fault=='duplicate-event':
        from uuid import uuid4
        key=Key('events','access#'+str(uuid4()));rows[key]=Row(key,1,deepcopy(event.data))
    elif fault=='operation-result': rows[operation.key]=replace(operation,data={**operation.data,'result':{}})
    elif fault=='operation-body': rows[operation.key]=replace(operation,data={**operation.data,'body_hash':'0'*64})
    elif fault=='missing-quota': del rows[quota.key]
    elif fault=='quota-count': rows[quota.key]=replace(quota,data={**quota.data,'count':2})
    elif fault=='quota-revision': rows[quota.key]=replace(quota,revision=2)
    elif fault=='future-event': rows[event.key]=replace(event,data={**event.data,'at_ms':101})
    elif fault=='creator-scope': rows[event.key]=replace(event,data={**event.data,'actor_scope':'0'*64})
    else: rows[event.key]=replace(event,data={**event.data,'kind':'owner-metadata-unrecognized'})
    before=deepcopy(rows)
    with pytest.raises(HeldCorpusHeld): read(w)
    assert rows==before and w[-1].wait_for_drain(0)


def test_v5_is_unchanged_and_does_not_silently_enable_metadata_history(monkeypatch):
    w=configured(monkeypatch);config=bounds()
    result=w[2].read_auth_accounting(request_id=w[7]['id'],inspection_ids=tuple(w[7]['inspection_ids']),deadline_ns=10**12,
        accounting_limits=LIMITS,runtime_context_limits=config.runtime,access_context_limits=config.access,auth_history_limits=config.auth)
    assert result.accounting.policy=='conservative-family-accounting-v5' and result.corpus.metadata_history is None
    root=next(r for r in result.accounting.entries if r.reference.key.resource=='metadata-request#'+w[7]['id'])
    assert root.reason=='UNSUPPORTED_FAMILY_POLICY'


@pytest.mark.parametrize('bad',[True,0,1.0,'100',2**63])
@pytest.mark.parametrize('field',list(asdict(limits())))
def test_history_limits_are_exact_finite_and_explicit(field,bad):
    with pytest.raises(ValueError): replace(limits(),**{field:bad})


def test_decimal_store_payloads_match_exact_writer_hashes(monkeypatch):
    w=configured(monkeypatch)
    def native(value):
        if type(value) is int:return Decimal(value)
        if type(value) is dict:return {k:native(v) for k,v in value.items()}
        if type(value) is list:return [native(v) for v in value]
        return value
    for k,row in list(w[5].items()):w[5][k]=replace(row,data=native(row.data))
    result=read(w)
    assert len(result.corpus.metadata_history.records)==4 and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('field,bad',[
    ('policy_resolved',True),('can_confirm_cleanup',True),('request_fulfilled',True),
    ('records',()),('configuration_sha256','0'*64),('auth_history_sha256','1'*64)])
def test_final_validation_checkpoint_cannot_replace_original_history(monkeypatch,field,bad):
    w=configured(monkeypatch);result=read(w);history=result.corpus.metadata_history
    args=dict(scope_sha256=history.scope_sha256,requested_inspections=history.requested_inspections)
    calls=[]
    validate(history,result.corpus.inventory,result.corpus.proof,result.corpus.auth_history,
             **args,checkpoint=lambda:calls.append(1))
    count=[0]
    def change():
        count[0]+=1
        if count[0]==len(calls):object.__setattr__(history,field,bad)
    with pytest.raises(MetadataHistoryHeld):
        validate(history,result.corpus.inventory,result.corpus.proof,result.corpus.auth_history,**args,checkpoint=change)


def test_original_source_changed_after_derivation_is_reconciled_before_delivery(monkeypatch):
    import proofpack.evidence.held_corpus as held
    w=configured(monkeypatch);original=held.metadata_derive
    def changed(*args,**kwargs):
        result=original(*args,**kwargs)
        key=Key('state','metadata-request#'+w[7]['id'])
        w[5][key].data['created_at_ms']=99
        return result
    monkeypatch.setattr(held,'metadata_derive',changed)
    with pytest.raises(HeldCorpusHeld):read(w)
    assert w[-1].wait_for_drain(0)


def test_original_limits_changed_after_derivation_hold_before_delivery(monkeypatch):
    import proofpack.evidence.held_corpus as held
    w=configured(monkeypatch);original=held.metadata_derive;explicit=limits()
    def changed(*args,**kwargs):
        result=original(*args,**kwargs)
        object.__setattr__(explicit,'max_work',explicit.max_work+1)
        return result
    monkeypatch.setattr(held,'metadata_derive',changed)
    with pytest.raises(HeldCorpusHeld):read(w,metadata_history_limits=explicit)
    assert w[-1].wait_for_drain(0)
