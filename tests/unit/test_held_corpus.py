"""Real read protocols on modeled storage; never native/provider/owner proof."""
from copy import deepcopy
from dataclasses import replace,FrozenInstanceError
from types import SimpleNamespace
from threading import Thread,Event
import pytest
from botocore.client import BaseClient

from test_inventory_readset import setup
from test_privacy_admission import ModelRepository,ModelRuntime,ident
from test_replay_corpus import corpus,DEPLOYMENT,uid,LIMITS as ANALYSIS
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key,Row
from proofpack.evidence.inventory import InventoryLimits
from proofpack.evidence.held_inventory import HeldInventoryLimits
from proofpack.evidence.reference_corpus import ReferenceCorpusLimits
from proofpack.evidence.reference_lineage import ReferenceLimits
from proofpack.evidence.privacy_admission import PersistentAdmission,AdmissionLimits,GATE
from proofpack.runtime.ownership import ResourceOwner
from proofpack.evidence import held_corpus
from proofpack.evidence.held_corpus import (
    HeldCorpusReader,HeldCorpusLimits,HeldCorpusHeld,inspection_scope,scope_sha256,_metadata_digest,
)


INV=HeldInventoryLimits(InventoryLimits(100,20,1000,1_000_000),10,2_000_000)
BOUNDS=HeldCorpusLimits(ANALYSIS,20,4_000_000,2_000_000,ReferenceCorpusLimits(100,ReferenceLimits(32,1_000_000,64,10000),ANALYSIS.dataset.corpus.max_work,1_000_000))
REQUEST=ident(90)


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*args,**kwargs):raise AssertionError('model held-corpus check invoked SDK')
    monkeypatch.setattr(BaseClient,'_make_api_call',deny)


def world(monkeypatch,*,held=True):
    repo,data,calls,_=setup(monkeypatch,0);repo.deployment=DEPLOYMENT
    data.update((r.key,deepcopy(r)) for r in corpus())
    model=ModelRepository();model.rows=data;model.client=repo.client
    monkeypatch.setattr(repo,'snapshot',model.snapshot);monkeypatch.setattr(repo,'transact',model.transact)
    runtime=ModelRuntime(repo);clock=SimpleNamespace(value=100)
    data[RUNTIME]=Row(RUNTIME,1,{'instance_id':runtime.instance_id,'runtime_epoch':1,'inspection_enabled':False})
    admission=PersistentAdmission(runtime,limits=AdmissionLimits(8,1000),clock_ms=lambda:clock.value)
    admission.initialize('a'*64)
    scope=inspection_scope(DEPLOYMENT,(uid(1),),max_inspections=ANALYSIS.dataset.corpus.max_inspections)
    if held:admission.hold(request_id=REQUEST,scope_sha256=scope_sha256(scope))
    owner=ResourceOwner();reader=HeldCorpusReader(admission,owner,inventory_limits=INV,limits=BOUNDS,tick=lambda:1)
    return reader,admission,owner,repo,data,calls,clock


def read(reader,**changes):
    return reader.read(**(dict(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000)|changes))


def test_server_obtains_complete_inputs_and_reconciles_again_without_writes(monkeypatch):
    reader,admission,owner,repo,data,calls,_=world(monkeypatch)
    before=deepcopy(data);monkeypatch.setattr(repo,'transact',lambda *a,**k:pytest.fail('private read wrote metadata'))
    result=read(reader)
    assert result.proof==admission.drained(request_id=REQUEST,scope_sha256=scope_sha256(result.scope))
    assert len(result.selection.families)==6 and result.snapshot_batches==2 and len(calls['snapshots'])==2
    assert result.payload_bytes>0 and result.binding_bytes>0 and len(result.binding_sha256)==64
    assert data==before and owner.wait_for_drain(0) and reader.release_pending is False
    assert all(v not in repr(result) for v in ['Synthetic label note','separate-rights','deployments/'])
    assert not hasattr(result,'read_set') and not hasattr(result,'usable')
    with pytest.raises(FrozenInstanceError):result.payload_bytes=0


def test_identical_input_time_and_scope_have_deterministic_binding(monkeypatch):
    reader,*_=world(monkeypatch)
    assert read(reader)==read(reader)


@pytest.mark.parametrize('change',[{'request_id':ident(91)},{'inspection_ids':(uid(999),)}])
def test_wrong_held_request_or_derived_scope_cannot_read_inventory(monkeypatch,change):
    reader,_,owner,_,_,calls,_=world(monkeypatch)
    with pytest.raises(HeldCorpusHeld):read(reader,**change)
    assert calls['pages']==calls['snapshots']==[] and owner.wait_for_drain(0)


def test_open_gate_and_caller_data_cannot_replace_real_proof(monkeypatch):
    reader,_,owner,_,_,calls,_=world(monkeypatch,held=False)
    with pytest.raises(HeldCorpusHeld):read(reader)
    with pytest.raises(TypeError):reader.read(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,rows=())
    assert calls['pages']==calls['snapshots']==[] and owner.wait_for_drain(0)


@pytest.mark.parametrize('mutation',['known','unknown-update','phantom','remove'])
def test_record_changes_during_selection_are_detected_by_final_real_read(monkeypatch,mutation):
    reader,_,owner,_,data,_,_=world(monkeypatch);original=held_corpus.derive
    unknown=Key('state','future#source');data[unknown]=Row(unknown,1,{'secret':'kept'})
    def changed(*args,**kwargs):
        result=original(*args,**kwargs)
        if mutation=='phantom':data[Key('state','future#new')]=Row(Key('state','future#new'),1,{'secret':'new'})
        elif mutation=='remove':del data[unknown]
        elif mutation=='known':
            key=Key('state','inspection#'+uid(1));data[key]=replace(data[key],revision=data[key].revision+1)
        else:data[unknown]=replace(data[unknown],revision=2,data={'secret':'changed'})
        return result
    monkeypatch.setattr(held_corpus,'derive',changed)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_original_control_proof_is_not_replaced_after_selection(monkeypatch):
    reader,_,owner,_,data,_,_=world(monkeypatch);original=held_corpus.derive
    def changed(*args,**kwargs):
        result=original(*args,**kwargs);data[GATE]=replace(data[GATE],revision=data[GATE].revision+1);return result
    monkeypatch.setattr(held_corpus,'derive',changed)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_one_clock_includes_seed_selection_final_read_and_binding(monkeypatch):
    _,admission,owner,_,_,_,_=world(monkeypatch);original=held_corpus.derive;after=False
    def changed(*args,**kwargs):
        nonlocal after
        result=original(*args,**kwargs);after=True;return result
    monkeypatch.setattr(held_corpus,'derive',changed)
    reader=HeldCorpusReader(admission,owner,inventory_limits=INV,limits=BOUNDS,tick=lambda:99 if after else 100)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_outer_owner_stays_active_after_seed_through_shutdown_and_final_work(monkeypatch):
    reader,_,owner,_,_,_,_=world(monkeypatch);original=held_corpus.derive;closed=[]
    def selecting(*args,**kwargs):
        assert not owner.wait_for_drain(0)
        owner.stop_accepting();owner.after_drain(lambda:closed.append('closed'))
        result=original(*args,**kwargs)
        assert closed==[] and not owner.wait_for_drain(0)
        return result
    monkeypatch.setattr(held_corpus,'derive',selecting)
    result=read(reader)
    assert result.selection and closed==['closed'] and owner.wait_for_drain(0)


@pytest.mark.parametrize('field',['limits','inventory_limits','tick','resource_owner'])
def test_configuration_identity_change_during_selection_returns_no_artifact(monkeypatch,field):
    reader,_,owner,_,_,_,_=world(monkeypatch);original=held_corpus.derive
    def changed(*args,**kwargs):
        result=original(*args,**kwargs)
        value={'limits':replace(BOUNDS,max_binding_bytes=3_000_000),'inventory_limits':replace(INV,max_payload_bytes=1_000_000),
            'tick':lambda:1,'resource_owner':ResourceOwner()}[field]
        setattr(reader,field,value);return result
    monkeypatch.setattr(held_corpus,'derive',changed)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_target_client_change_after_selection_holds(monkeypatch):
    reader,_,owner,repo,_,_,_=world(monkeypatch);original=held_corpus.derive
    def changed(*args,**kwargs):
        result=original(*args,**kwargs);repo.client=object();return result
    monkeypatch.setattr(held_corpus,'derive',changed)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert owner.wait_for_drain(0)


def test_binding_budget_cannot_return_partial_selection(monkeypatch):
    reader,admission,owner,_,_,_,_=world(monkeypatch)
    small=HeldCorpusReader(admission,owner,inventory_limits=INV,limits=replace(BOUNDS,max_binding_bytes=1),tick=lambda:1)
    with pytest.raises(HeldCorpusHeld):read(small)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('error',[KeyboardInterrupt,SystemExit])
def test_uncertain_selection_preserves_owner_and_denies_another_read(monkeypatch,error):
    reader,_,owner,_,_,calls,_=world(monkeypatch)
    def interrupted(*args,**kwargs):raise error()
    monkeypatch.setattr(held_corpus,'derive',interrupted)
    with pytest.raises(error):read(reader)
    assert reader.release_pending and not owner.wait_for_drain(0)
    before=deepcopy(calls)
    with pytest.raises(HeldCorpusHeld):read(reader)
    assert calls==before


def test_known_completed_failure_releases_owner(monkeypatch):
    reader,_,owner,_,_,_,_=world(monkeypatch)
    def failed(*args,**kwargs):raise RuntimeError('known complete test failure')
    monkeypatch.setattr(held_corpus,'derive',failed)
    with pytest.raises(RuntimeError,match='known complete'):read(reader)
    assert owner.wait_for_drain(0) and not reader.release_pending


def test_concurrent_incarnation_is_denied_before_another_store_read(monkeypatch):
    reader,_,owner,_,_,calls,_=world(monkeypatch);original=held_corpus.derive
    entered=Event();release=Event();values=[]
    def blocked(*args,**kwargs):
        entered.set();assert release.wait(5);return original(*args,**kwargs)
    monkeypatch.setattr(held_corpus,'derive',blocked)
    thread=Thread(target=lambda:values.append(read(reader)));thread.start();assert entered.wait(5)
    try:
        before=deepcopy(calls)
        with pytest.raises(HeldCorpusHeld):read(reader)
        assert calls==before and not owner.wait_for_drain(0)
    finally:release.set();thread.join(5)
    assert not thread.is_alive() and len(values)==1 and owner.wait_for_drain(0)


@pytest.mark.parametrize('field,bad',[('max_total_snapshot_batches',True),('max_total_snapshot_batches',0),
    ('max_total_payload_bytes',False),('max_total_payload_bytes',-1),('max_binding_bytes',2**63)])
def test_bounds_reject_ambiguous_or_unbounded_values(field,bad):
    with pytest.raises(ValueError):replace(BOUNDS,**{field:bad})


@pytest.mark.parametrize('field,value',[('max_total_snapshot_batches',19),('max_total_payload_bytes',3_999_999)])
def test_constructor_rejects_insufficient_total_budget_before_io(monkeypatch,field,value):
    _,admission,owner,repo,_,calls,_=world(monkeypatch)
    monkeypatch.setattr(repo,'snapshot',lambda *a,**k:pytest.fail('constructor read metadata'))
    with pytest.raises(ValueError):HeldCorpusReader(admission,owner,inventory_limits=INV,limits=replace(BOUNDS,**{field:value}),tick=lambda:1)
    assert calls['pages']==calls['snapshots']==[]


@pytest.mark.parametrize('ids',[[],(),(uid(1),uid(1)),(uid(2),uid(1)),('bad',)])
def test_scope_is_typed_ordered_unique_and_cannot_be_arbitrary_keys(ids):
    with pytest.raises(ValueError):inspection_scope(DEPLOYMENT,ids,max_inspections=30)


def test_projection_exact_byte_boundary_and_raw_payload_denial():
    value=(1,'safe-metadata',inspection_scope(DEPLOYMENT,(uid(1),),max_inspections=1))
    size,sha=_metadata_digest(value,max_bytes=10000,tick=lambda:None)
    assert _metadata_digest(value,max_bytes=size,tick=lambda:None)==(size,sha)
    with pytest.raises(HeldCorpusHeld):_metadata_digest(value,max_bytes=size-1,tick=lambda:None)
    with pytest.raises(HeldCorpusHeld):_metadata_digest({'private':'RAW'},max_bytes=10000,tick=lambda:None)
