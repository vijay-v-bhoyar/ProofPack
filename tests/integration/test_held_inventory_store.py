"""Owned-store read-set binding; not owner control-plane or deletion acceptance."""
from copy import deepcopy
from time import monotonic_ns
from uuid import uuid4

import pytest

from test_access_lifecycle import world, repository_factory
from test_privacy_admission_store import setup
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key, Write, Erase
from proofpack.evidence.inventory import InventoryLimits
from proofpack.evidence.held_inventory import HeldInventoryReader, HeldInventoryLimits, HeldInventoryHeld
from proofpack.runtime.ownership import ResourceOwner


def prepare(world, *, held=True):
    admission,runtime=setup(world);owner=ResourceOwner();request=str(uuid4())
    if held:admission.hold(request_id=request,scope_sha256='b'*64)
    limits=HeldInventoryLimits(InventoryLimits(25,50,1000,1000000),10,2000000)
    reader=HeldInventoryReader(admission,owner,limits=limits,tick=monotonic_ns)
    return reader,admission,owner,request


def read(reader,request):
    return reader.read(request_id=request,scope_sha256='b'*64,deadline_ns=monotonic_ns()+5000000000)


def test_actual_held_inventory_matches_exact_durable_controls_and_preserves_unknown_family(world):
    reader,admission,owner,request=prepare(world,held=False)
    key=Key('state','unknown-synthetic#'+str(uuid4()))
    admission.repository.transact((Write(key,None,{'secret':'PRIVATE-UNKNOWN'}),))
    admission.hold(request_id=request,scope_sha256='b'*64)
    result=read(reader,request)
    assert result.proof==admission.drained(request_id=request,scope_sha256='b'*64)
    assert {row.key for row in result.read_set.rows}=={entry.key for entry in result.inventory.entries if entry.kind=='live'}
    assert any(row.key==key for row in result.read_set.rows) and 'PRIVATE-UNKNOWN' not in repr(result)
    assert owner.wait_for_drain(0) and result.read_set.snapshot_batches>0


def test_actual_open_gate_cannot_be_replaced_with_a_caller_checkpoint(world,monkeypatch):
    reader,admission,owner,request=prepare(world,held=False)
    def forbidden(**kwargs):pytest.fail('open gate accessed inventory')
    monkeypatch.setattr(admission.repository,'partition_page',forbidden)
    with pytest.raises(HeldInventoryHeld):read(reader,request)
    assert owner.wait_for_drain(0)


def test_actual_control_read_performs_no_metadata_writes(world,monkeypatch):
    reader,admission,owner,request=prepare(world)
    monkeypatch.setattr(admission.repository,'transact',lambda *a,**k:pytest.fail('read-set operation wrote metadata'))
    assert read(reader,request).read_set.rows


def test_actual_erased_marker_survives_readset_without_original_payload(world):
    reader,admission,owner,request=prepare(world,held=False);repository=admission.repository
    key=Key('state','synthetic-private#'+str(uuid4()))
    repository.transact((Write(key,None,{'secret':'PRIVATE-REMOVED'}),))
    row=repository.snapshot((key,))[key]
    repository.transact((Erase(key,row.revision,'c'*64),))
    admission.hold(request_id=request,scope_sha256='b'*64)
    result=read(reader,request)
    assert any(marker.key==key for marker in result.read_set.markers)
    assert all(row.key!=key for row in result.read_set.rows) and 'PRIVATE-REMOVED' not in repr(result)


def test_actual_control_revision_change_mid_page_returns_no_accepted_readset(world,monkeypatch):
    reader,admission,owner,request=prepare(world);repository=admission.repository;page=repository.partition_page;changed=False
    def changed_page(**kwargs):
        nonlocal changed
        result=page(**kwargs)
        if not changed:
            changed=True;row=repository.snapshot((RUNTIME,))[RUNTIME]
            repository.transact((Write(RUNTIME,row.revision,deepcopy(row.data)),))
        return result
    monkeypatch.setattr(repository,'partition_page',changed_page)
    with pytest.raises(HeldInventoryHeld):read(reader,request)
    assert changed and owner.wait_for_drain(0)


def test_actual_phantom_between_enumeration_and_rehydration_holds_complete_followup(world,monkeypatch):
    reader,admission,owner,request=prepare(world);repository=admission.repository;snapshot=repository.inventory_snapshot;changed=False
    def changed_snapshot(keys):
        nonlocal changed
        if not changed:
            changed=True;repository.transact((Write(Key('state','unknown#'+str(uuid4())),None,{'synthetic':True}),))
        return snapshot(keys)
    monkeypatch.setattr(repository,'inventory_snapshot',changed_snapshot)
    with pytest.raises(HeldInventoryHeld):read(reader,request)
    assert changed and owner.wait_for_drain(0)
