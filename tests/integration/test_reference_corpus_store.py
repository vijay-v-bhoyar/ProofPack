"""Actual upload/store histories plus a disclosed synthetic empty inspection."""
from dataclasses import replace
from time import monotonic_ns
from uuid import uuid4
import pytest
from test_access_lifecycle import world,repository_factory
from test_references import reference_case,upload
from test_capture_lineage import family as inspection_fixture
from test_privacy_admission_store import setup as admission_setup
from proofpack.evidence.repository import Key,Write,StoreUnavailable
from proofpack.evidence.inventory import InventoryLimits
from proofpack.evidence.held_inventory import HeldInventoryLimits
from proofpack.evidence.inspection_corpus import InspectionCorpusLimits
from proofpack.evidence.dataset_corpus import DatasetCorpusLimits
from proofpack.evidence.replay_corpus import ReplayCorpusLimits
from proofpack.evidence.reference_lineage import ReferenceLimits
from proofpack.evidence.reference_corpus import ReferenceCorpusLimits
from proofpack.evidence.corpus_accounting import AccountingLimits
from proofpack.evidence import held_corpus
from proofpack.evidence.held_corpus import HeldCorpusReader,HeldCorpusLimits,HeldCorpusHeld,inspection_scope,scope_sha256
from proofpack.runtime.ownership import ResourceOwner


def prepare(world,*,max_references=100):
    root,_=inspection_fixture()
    # No physical/capture claim: this row supplies only an independent request scope.
    data={**root.data,'latest_input_sequence':0,'verified_sequence':0,'latest_observation_id':None}
    world[1].transact((Write(root.key,None,data),))
    admission,_=admission_setup(world);owner=ResourceOwner();request=str(uuid4())
    inv=HeldInventoryLimits(InventoryLimits(100,50,2000,2_000_000),20,4_000_000)
    analysis=ReplayCorpusLimits(DatasetCorpusLimits(InspectionCorpusLimits(2000,4_000_000,30,200_000),10000,16_000_000,100,100),500,20)
    refs=ReferenceCorpusLimits(max_references,ReferenceLimits(32,1_000_000,64,10000),200_000,2_000_000)
    limits=HeldCorpusLimits(analysis,40,8_000_000,4_000_000,refs)
    ident=root.data['id'];scope=inspection_scope(world[1].deployment,(ident,),max_inspections=30)
    admission.hold(request_id=request,scope_sha256=scope_sha256(scope))
    reader=HeldCorpusReader(admission,owner,inventory_limits=inv,limits=limits,tick=monotonic_ns)
    return reader,owner,request,ident


def read(prepared):
    reader,_,request,ident=prepared
    return reader.read_accounting(request_id=request,inspection_ids=(ident,),deadline_ns=monotonic_ns()+20_000_000_000,
        accounting_limits=AccountingLimits(2000,30,10000,200000,4_000_000))


def test_actual_two_uploads_are_server_discovered_and_unresolved_without_writes(world,reference_case,monkeypatch):
    uploaded=[upload(world,reference_case,key='ref-one'),upload(world,reference_case,key='ref-two')]
    prepared=prepare(world);monkeypatch.setattr(world[1],'transact',lambda *a,**k:pytest.fail('held reader wrote metadata'))
    result=read(prepared);assert result.corpus.references.family_count==2 and prepared[1].wait_for_drain(0)
    index={e.reference.key:e for e in result.accounting.entries}
    for item in uploaded:
        e=index[Key('state','asset#'+item['id'])]
        assert e.disposition=='UNRESOLVED' and e.inspection_ids==() and 'REFERENCE_UPLOAD_HISTORY' in e.policies
    assert len(index)==len(result.corpus.inventory.entries)
    assert all(f.state=='linked' and len(f.media)==1 for f in result.corpus.references.families)


def test_actual_interrupted_upload_keeps_written_object_and_unknown_origin(world,reference_case):
    def interrupted():raise StoreUnavailable('synthetic interruption after actual put/head')
    reference_case[2].after_put=interrupted
    with pytest.raises(StoreUnavailable):upload(world,reference_case,key='interrupted-ref')
    prepared=prepare(world);result=read(prepared)
    f,=result.corpus.references.families
    assert f.state=='needs_reconciliation' and not f.media and reference_case[2].payloads
    assert 'STORAGE_RECONCILIATION_REQUIRED' in f.obligations and 'INSPECTION_ORIGIN_NOT_RECORDED' in f.obligations
    assert prepared[1].wait_for_drain(0)


def test_actual_reference_root_bound_holds_complete_delivery(world,reference_case):
    upload(world,reference_case,key='ref-one');upload(world,reference_case,key='ref-two')
    prepared=prepare(world,max_references=1)
    with pytest.raises(HeldCorpusHeld):read(prepared)
    assert prepared[1].wait_for_drain(0)


def test_actual_phantom_after_reference_selection_holds_before_delivery(world,reference_case,monkeypatch):
    upload(world,reference_case);prepared=prepare(world);original=held_corpus.reference_derive;changed=[]
    def selected(*a,**k):
        result=original(*a,**k)
        world[1].transact((Write(Key('state','unknown#'+str(uuid4())),None,{'synthetic':'late'}),));changed.append(True)
        return result
    monkeypatch.setattr(held_corpus,'reference_derive',selected)
    with pytest.raises(HeldCorpusHeld):read(prepared)
    assert changed and prepared[1].wait_for_drain(0)
