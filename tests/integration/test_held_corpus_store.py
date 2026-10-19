"""Actual local metadata/vision, intercepted S3; not owner, AWS or human acceptance."""
from copy import deepcopy
from time import monotonic_ns
from uuid import uuid4
import pytest

from test_access_lifecycle import world,repository_factory,publication_case
from test_privacy_admission_store import setup
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key,Write
from proofpack.evidence.inventory import InventoryLimits
from proofpack.evidence.held_inventory import HeldInventoryLimits
from proofpack.evidence.inspection_corpus import InspectionCorpusLimits
from proofpack.evidence.dataset_corpus import DatasetCorpusLimits
from proofpack.evidence.replay_corpus import ReplayCorpusLimits
from proofpack.evidence.reference_corpus import ReferenceCorpusLimits
from proofpack.evidence.reference_lineage import ReferenceLimits
from proofpack.evidence import held_corpus
from proofpack.evidence.held_corpus import (
    HeldCorpusReader,HeldCorpusLimits,HeldCorpusHeld,inspection_scope,scope_sha256,
)
from proofpack.runtime.ownership import ResourceOwner


def prepared(world,publication_case):
    _,capture,started,operator,_,_,_,_,_,observe=publication_case
    observe()
    ident=started['inspection_id'];repository=world[1]
    work=repository.snapshot((Key('state','inspection#'+ident),))[Key('state','inspection#'+ident)]
    capture.stations.close(operator,inspection_id=ident,expected_version=work.revision,
        expected_epoch=int(work.data['station_epoch']),reason='synthetic private read preparation',
        disposition='cancelled',idempotency_key='close-for-private-corpus')
    admission,_=setup(world);owner=ResourceOwner();request=str(uuid4())
    inv=HeldInventoryLimits(InventoryLimits(100,50,2000,2_000_000),20,4_000_000)
    analysis=ReplayCorpusLimits(DatasetCorpusLimits(InspectionCorpusLimits(2000,4_000_000,30,200_000),
        10000,16_000_000,100,100),500,20)
    limits=HeldCorpusLimits(analysis,40,8_000_000,4_000_000,ReferenceCorpusLimits(100,ReferenceLimits(32,1_000_000,64,10000),200_000,2_000_000))
    scope=inspection_scope(repository.deployment,(ident,),max_inspections=30)
    admission.hold(request_id=request,scope_sha256=scope_sha256(scope))
    return HeldCorpusReader(admission,owner,inventory_limits=inv,limits=limits,tick=monotonic_ns),admission,owner,request,ident


def read(reader,request,ident):
    return reader.read(request_id=request,inspection_ids=(ident,),deadline_ns=monotonic_ns()+20_000_000_000)


def test_actual_closed_published_source_is_server_selected_without_writes_or_raw_result(world,publication_case,monkeypatch):
    reader,admission,owner,request,ident=prepared(world,publication_case)
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('private diagnostic wrote metadata'))
    result=read(reader,request,ident)
    inspections=result.selection.datasets.permissions.labels.inspections.families
    assert any(f.inspection_id==ident and f.requested and f.capture.records for f in inspections)
    assert result.proof==admission.drained(request_id=request,scope_sha256=scope_sha256(result.scope))
    assert result.snapshot_batches>=2 and result.payload_bytes>0 and owner.wait_for_drain(0)
    assert result.selection.residual and not hasattr(result,'read_set')
    assert 'deployments/' not in repr(result) and 'result_json' not in repr(result)


def test_actual_unknown_insertion_after_selection_is_rejected_by_final_reconciliation(world,publication_case,monkeypatch):
    reader,_,owner,request,ident=prepared(world,publication_case);original=held_corpus.derive;changed=False
    def selecting(*args,**kwargs):
        nonlocal changed
        result=original(*args,**kwargs)
        world[1].transact((Write(Key('state','unknown-phantom#'+str(uuid4())),None,{'private':'INSERTED_AFTER_SELECTION'}),))
        changed=True;return result
    monkeypatch.setattr(held_corpus,'derive',selecting)
    with pytest.raises(HeldCorpusHeld):read(reader,request,ident)
    assert changed and owner.wait_for_drain(0)


def test_actual_original_control_revision_cannot_be_replaced_after_selection(world,publication_case,monkeypatch):
    reader,_,owner,request,ident=prepared(world,publication_case);original=held_corpus.derive;changed=False
    def selecting(*args,**kwargs):
        nonlocal changed
        result=original(*args,**kwargs);row=world[1].snapshot((RUNTIME,))[RUNTIME]
        world[1].transact((Write(RUNTIME,row.revision,deepcopy(row.data)),));changed=True;return result
    monkeypatch.setattr(held_corpus,'derive',selecting)
    with pytest.raises(HeldCorpusHeld):read(reader,request,ident)
    assert changed and owner.wait_for_drain(0)


def test_actual_shared_client_cleanup_waits_for_selection_and_final_store_reads(world,publication_case,monkeypatch):
    reader,_,owner,request,ident=prepared(world,publication_case);original=held_corpus.derive
    client=world[1].client;close=client.close;call=client._make_api_call;closed=[]
    def guarded(*args,**kwargs):
        assert not closed,'SDK call after premature resource cleanup'
        return call(*args,**kwargs)
    def close_client():closed.append('closed');close()
    monkeypatch.setattr(client,'_make_api_call',guarded)
    def selecting(*args,**kwargs):
        assert not owner.wait_for_drain(0)
        owner.stop_accepting();owner.after_drain(close_client)
        result=original(*args,**kwargs);assert not closed;return result
    monkeypatch.setattr(held_corpus,'derive',selecting)
    result=read(reader,request,ident)
    assert result.selection and closed==['closed'] and owner.wait_for_drain(0)


def read_accounting(reader,request,ident):
    from proofpack.evidence.corpus_accounting import AccountingLimits
    return reader.read_accounting(request_id=request,inspection_ids=(ident,),
        deadline_ns=monotonic_ns()+20_000_000_000,
        accounting_limits=AccountingLimits(2000,30,10000,200000,4_000_000))


def test_actual_accounting_covers_every_inventory_record_without_writes(world,publication_case,monkeypatch):
    reader,_,owner,request,ident=prepared(world,publication_case)
    monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('accounting wrote metadata'))
    result=read_accounting(reader,request,ident)
    indexed={r.reference.key:r for r in result.accounting.entries}
    assert set(indexed)=={r.key for r in result.corpus.inventory.entries}
    assert indexed[Key('state','inspection#'+ident)].disposition=='AFFECTED'
    assert dict(result.accounting.counts)['UNRESOLVED']>0
    assert result.accounting.requested_inspections==(ident,) and owner.wait_for_drain(0)
    assert result.accounting.inventory_sha256==result.corpus.inventory.summary_sha256
    assert ident not in repr(result) and 'deployments/' not in repr(result)


def test_actual_unknown_insertion_after_accounting_is_held_before_delivery(world,publication_case,monkeypatch):
    reader,_,owner,request,ident=prepared(world,publication_case);original=held_corpus.account;changed=[]
    def accounting(*a,**k):
        result=original(*a,**k)
        world[1].transact((Write(Key('state','after-accounting#'+str(uuid4())),None,{'private':True}),))
        changed.append(True);return result
    monkeypatch.setattr(held_corpus,'account',accounting)
    with pytest.raises(HeldCorpusHeld):read_accounting(reader,request,ident)
    assert changed==[True] and owner.wait_for_drain(0)


def test_actual_accounting_retains_client_through_final_reads(world,publication_case,monkeypatch):
    reader,_,owner,request,ident=prepared(world,publication_case);original=held_corpus.account
    client=world[1].client;close=client.close;call=client._make_api_call;closed=[];after_account=[];post_calls=[]
    def guarded(*a,**k):
        assert not closed,'accounting closed the SDK client before final reads'
        if after_account:post_calls.append(True)
        return call(*a,**k)
    def close_client():closed.append(True);close()
    monkeypatch.setattr(client,'_make_api_call',guarded)
    def accounting(*a,**k):
        assert not owner.wait_for_drain(0);owner.stop_accepting();owner.after_drain(close_client)
        result=original(*a,**k);assert not closed;after_account.append(True);return result
    monkeypatch.setattr(held_corpus,'account',accounting)
    result=read_accounting(reader,request,ident)
    assert result.accounting.entries and after_account==[True] and post_calls
    assert closed==[True] and owner.wait_for_drain(0)
