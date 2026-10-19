"""Real inventory protocol plus model admission; no actual store or owner authority."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from test_inventory_readset import setup, LIMITS
from test_privacy_admission import ModelRepository, ModelRuntime, ident
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.inventory import InventoryLimits
from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionLimits, GATE, REGISTRY
from proofpack.runtime.ownership import ResourceOwner
from proofpack.evidence.held_inventory import HeldInventoryReader, HeldInventoryLimits, HeldInventoryHeld
import proofpack.evidence.held_inventory as module


REQUEST = ident(90)
SCOPE = 'b'*64


def world(monkeypatch, count=2, *, held=True):
    repo,data,calls,_ = setup(monkeypatch,count)
    model = ModelRepository(); model.rows = data; model.client = repo.client
    monkeypatch.setattr(repo,'snapshot',model.snapshot)
    monkeypatch.setattr(repo,'transact',model.transact)
    runtime = ModelRuntime(repo); clock = SimpleNamespace(value=100)
    data[RUNTIME] = Row(RUNTIME,1,{'instance_id':runtime.instance_id,'runtime_epoch':1,'inspection_enabled':False})
    admission = PersistentAdmission(runtime,limits=AdmissionLimits(8,1000),clock_ms=lambda:clock.value)
    admission.initialize('a'*64)
    if held: admission.hold(request_id=REQUEST,scope_sha256=SCOPE)
    owner = ResourceOwner()
    limits = HeldInventoryLimits(LIMITS,10,1000000)
    reader = HeldInventoryReader(admission,owner,limits=limits,tick=lambda:1)
    return reader,admission,owner,repo,data,calls,clock


def read(reader, **changes):
    args=dict(request_id=REQUEST,scope_sha256=SCOPE,deadline_ns=1000);args.update(changes)
    return reader.read(**args)


def test_complete_bound_readset_is_detached_payload_private_and_read_only(monkeypatch):
    reader,admission,owner,repo,data,calls,clock = world(monkeypatch)
    before = deepcopy(data)
    monkeypatch.setattr(repo,'transact',lambda *a,**k:pytest.fail('inventory must not write'))
    result = read(reader)
    assert result.proof == admission.drained(request_id=REQUEST,scope_sha256=SCOPE)
    assert result.read_set.inventory == result.inventory
    assert {row.key for row in result.read_set.rows} == set(data)
    assert data == before and owner.wait_for_drain(0)
    assert 'PRIVATE-PAYLOAD' not in repr(result) and 'secret' not in repr(result)
    assert len(result.binding_sha256) == 64
    key=Key('state','unknown#0000');data[key].data['secret']='changed later'
    assert next(row for row in result.read_set.rows if row.key==key).data['secret']=='PRIVATE-PAYLOAD'


def test_identical_proof_and_inventory_have_a_repeatable_binding(monkeypatch):
    reader,*_ = world(monkeypatch)
    assert read(reader).binding_sha256 == read(reader).binding_sha256


@pytest.mark.parametrize('changes',[{'request_id':ident(91)},{'scope_sha256':'c'*64}])
def test_wrong_request_scope_cannot_substitute_for_the_original_hold(monkeypatch,changes):
    reader,admission,owner,repo,data,calls,clock = world(monkeypatch)
    with pytest.raises(HeldInventoryHeld): read(reader,**changes)
    assert calls['pages']==calls['snapshots']==[] and owner.wait_for_drain(0)


@pytest.mark.parametrize('condition',['open','active','expired_active','missing_gate'])
def test_real_drain_is_required_before_any_inventory_access(monkeypatch,condition):
    reader,admission,owner,repo,data,calls,clock = world(monkeypatch,held=False)
    if condition in {'active','expired_active'}:
        entry=admission.prepare(work_id=ident(12),kind='worker',lease_ms=100);admission.admit(entry)
    if condition!='open':admission.hold(request_id=REQUEST,scope_sha256=SCOPE)
    if condition=='expired_active':clock.value+=101
    if condition=='missing_gate':del data[GATE]
    with pytest.raises(HeldInventoryHeld): read(reader)
    assert calls['pages']==calls['snapshots']==[] and owner.wait_for_drain(0)


@pytest.mark.parametrize('field,value',[('inventory',None),('max_snapshot_batches',True),
    ('max_snapshot_batches',0),('max_payload_bytes',False),('max_payload_bytes',0)])
def test_explicit_typed_limits_have_no_boolean_or_unbounded_fallback(field,value):
    fields=dict(inventory=LIMITS,max_snapshot_batches=10,max_payload_bytes=1000000);fields[field]=value
    with pytest.raises(ValueError):HeldInventoryLimits(**fields)


@pytest.mark.parametrize('limit',[
    HeldInventoryLimits(InventoryLimits(1,2,1000,1000000),10,1000000),
    HeldInventoryLimits(InventoryLimits(100,20,3,1000000),10,1000000),
    HeldInventoryLimits(InventoryLimits(100,20,1000,1),10,1000000),
    HeldInventoryLimits(LIMITS,1,1000000),
    HeldInventoryLimits(LIMITS,10,1)])
def test_every_independent_inventory_budget_holds_without_partial_acceptance(monkeypatch,limit):
    reader,admission,owner,repo,data,calls,clock = world(monkeypatch,101)
    constrained=HeldInventoryReader(admission,owner,limits=limit,tick=lambda:1)
    with pytest.raises(HeldInventoryHeld):read(constrained)
    assert owner.wait_for_drain(0)


def test_prior_markers_are_retained_without_rehydrating_removed_payload(monkeypatch):
    reader,admission,owner,repo,data,calls,clock = world(monkeypatch,0)
    key=Key('state','erased#one');marker=ErasureMarker(key,2,'c'*64,repo._erasure_identity(key));data[key]=marker
    result=read(reader)
    assert result.read_set.markers==(marker,) and all(row.key!=key for row in result.read_set.rows)


@pytest.mark.parametrize('source',[GATE,REGISTRY,RUNTIME])
def test_control_revision_change_during_enumeration_cannot_be_rebased(monkeypatch,source):
    reader,admission,owner,repo,data,calls,clock = world(monkeypatch)
    page=repo.partition_page;changed=False
    def changed_page(**kwargs):
        nonlocal changed
        result=page(**kwargs)
        if not changed:
            changed=True;row=data[source];data[source]=Row(source,row.revision+1,deepcopy(row.data))
        return result
    monkeypatch.setattr(repo,'partition_page',changed_page)
    with pytest.raises(HeldInventoryHeld):read(reader)
    assert changed and owner.wait_for_drain(0)


def test_monotonic_clock_does_not_reset_between_collection_and_rehydration(monkeypatch):
    reader,admission,owner,repo,data,calls,clock = world(monkeypatch)
    reader=HeldInventoryReader(admission,owner,limits=reader.limits,tick=lambda:9 if calls['snapshots'] else 10)
    with pytest.raises(HeldInventoryHeld):read(reader)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['proof','deadline','target'])
def test_final_binding_preparation_cannot_hide_late_source_or_clock_change(monkeypatch,fault):
    reader,admission,owner,repo,data,calls,clock=world(monkeypatch);late=False
    reader=HeldInventoryReader(admission,owner,limits=reader.limits,tick=lambda:1000 if late and fault=='deadline' else 1)
    original=module._binding
    def binding(*args):
        nonlocal late
        result=original(*args);late=True
        if fault=='proof':data[RUNTIME]=replace(data[RUNTIME],revision=data[RUNTIME].revision+1)
        if fault=='target':repo.client=object()
        return result
    monkeypatch.setattr(module,'_binding',binding)
    with pytest.raises(HeldInventoryHeld):read(reader)
    assert late and owner.wait_for_drain(0)


def test_shutdown_cannot_close_resources_while_control_read_is_running(monkeypatch):
    reader,admission,owner,repo,data,calls,clock=world(monkeypatch);closed=[];page=repo.partition_page;stopped=False
    def stopping(**kwargs):
        nonlocal stopped
        if not stopped:
            stopped=True
            owner.stop_accepting();owner.after_drain(lambda:closed.append('after actual read'))
        assert not owner.wait_for_drain(0) and not closed
        return page(**kwargs)
    monkeypatch.setattr(repo,'partition_page',stopping)
    read(reader)
    assert closed==['after actual read'] and owner.wait_for_drain(0)


def test_termination_retains_unknown_local_ownership_and_refuses_another_read(monkeypatch):
    class Termination(BaseException):pass
    reader,admission,owner,repo,data,calls,clock=world(monkeypatch)
    def terminated(**kwargs):raise Termination()
    monkeypatch.setattr(repo,'partition_page',terminated)
    with pytest.raises(Termination):read(reader)
    assert reader.release_pending and not owner.wait_for_drain(0)
    with pytest.raises(HeldInventoryHeld):read(reader)


@pytest.mark.parametrize('deadline',[True,0,-1,1.5])
def test_deadline_requires_an_explicit_positive_exact_integer(monkeypatch,deadline):
    reader,*_=world(monkeypatch)
    with pytest.raises(ValueError):read(reader,deadline_ns=deadline)


@pytest.mark.parametrize('fault',['admission','owner','tick'])
def test_constructor_requires_exact_control_and_resource_owner_without_io(monkeypatch,fault):
    reader,admission,owner,repo,data,calls,clock=world(monkeypatch)
    with pytest.raises(ValueError):
        HeldInventoryReader(object() if fault=='admission' else admission,
            object() if fault=='owner' else owner,limits=reader.limits,tick=None if fault=='tick' else lambda:1)
    assert calls['pages']==calls['snapshots']==[]


@pytest.mark.parametrize('missing',[GATE,REGISTRY,RUNTIME])
def test_separate_proof_read_cannot_certify_an_inventory_missing_its_control(monkeypatch,missing):
    reader,admission,owner,repo,data,calls,clock=world(monkeypatch)
    page=repo.partition_page
    def incomplete(**kwargs):
        rows,cursor=page(**kwargs)
        return [row for row in rows if row.key!=missing],cursor
    monkeypatch.setattr(repo,'partition_page',incomplete)
    with pytest.raises(HeldInventoryHeld):read(reader)
    assert owner.wait_for_drain(0)
