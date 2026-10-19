"""Counterexamples for coherent original time and exact whole-inventory types."""
from dataclasses import asdict, replace
from decimal import Decimal
import hashlib
import pytest
from test_access_context import complete, read, limits, uid, REQUEST, no_sdk
from proofpack.evidence.repository import Key
from proofpack.evidence.held_corpus import HeldCorpusHeld


@pytest.mark.parametrize('expires', [3,10])
def test_session_expired_at_original_inspection_cannot_be_interpretation_context(monkeypatch, expires):
    reader,owner,_,data,_=complete(monkeypatch)
    key=Key('state','session#'+uid(5));row=data[key]
    data[key]=replace(row,data={**row.data,'expires_at_ms':expires})
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('revision', [True,1.0])
def test_rehashed_unselected_inventory_revision_still_requires_exact_integer(monkeypatch, revision):
    from proofpack.evidence.access_context import derive, AccessContextHeld
    from proofpack.evidence.inventory import _encoded
    reader,_,_,data,_=complete(monkeypatch);result=read(reader).corpus
    inventory=result.inventory
    entries=tuple(replace(e,revision=revision) if e.key==Key('state','access-head') else e for e in inventory.entries)
    assert any(type(e.revision)is not int for e in entries)
    payload=_encoded({'deployment':inventory.deployment,'tables':dict(inventory.tables),'entries':[asdict(e) for e in entries]})
    changed=replace(inventory,entries=entries,summary_bytes=len(payload),summary_sha256=hashlib.sha256(payload).hexdigest())
    with pytest.raises(AccessContextHeld):
        derive(tuple(data.values()),result.selection,changed,result.proof,requested_inspections=(uid(1),),
            scope_sha256=result.proof.scope_sha256,now_ms=500,limits=limits(),deadline_ns=1000,tick=lambda:1,checkpoint=lambda:None)


def test_actual_dynamodb_integral_payload_shape_is_interpreted_losslessly(monkeypatch):
    reader,owner,_,data,_=complete(monkeypatch)
    def stored(value):
        if type(value)is int:return Decimal(value)
        if type(value)is dict:return {k:stored(v) for k,v in value.items()}
        if type(value)is list:return [stored(v) for v in value]
        return value
    for key,row in tuple(data.items()):data[key]=replace(row,data=stored(row.data))
    result=read(reader)
    assert len(result.corpus.access_context.records)==4 and result.accounting.policy=='conservative-family-accounting-v4'
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('value',[True,1.0,Decimal('1.5'),Decimal('NaN'),Decimal('Infinity'),Decimal(2**63)])
def test_storage_normalization_cannot_promote_noninteger_or_out_of_range_version(monkeypatch,value):
    reader,owner,_,data,_=complete(monkeypatch)
    key=Key('state','session#'+uid(5));row=data[key]
    data[key]=replace(row,data={**row.data,'access_version':value})
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('change',[{}, {'notice_version':''}, {'notice_sha256':'invalid'}, {'notice_acknowledged_at_ms':0},
    {'notice_acknowledged_at_ms':11}, {'improvement_reuse':True}, {'publicity_reuse':1}, {'unknown_notice_copy':uid(1)}])
def test_exact_invited_notice_schema_is_recorded_context_without_new_reuse_grant(monkeypatch,change):
    reader,owner,_,data,_=complete(monkeypatch);key=Key('state','user#'+uid(6));row=data[key]
    notice={'notice_version':'synthetic-v1','notice_sha256':'a'*64,'notice_acknowledged_at_ms':Decimal(2),
        'improvement_reuse':False,'publicity_reuse':False}
    data[key]=replace(row,data={**row.data,**notice,**change})
    if change:
        with pytest.raises(HeldCorpusHeld):read(reader)
    else:
        context=read(reader).corpus.access_context
        assert key in {r.key for r in context.records} and context.can_confirm_cleanup is False
        assert data[key].data['improvement_reuse'] is False and data[key].data['publicity_reuse'] is False
    assert owner.wait_for_drain(0)


def test_partial_invitation_notice_schema_is_not_a_bootstrap_member(monkeypatch):
    reader,owner,_,data,_=complete(monkeypatch);key=Key('state','user#'+uid(6));row=data[key]
    data[key]=replace(row,data={**row.data,'notice_version':'synthetic-v1'})
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)
