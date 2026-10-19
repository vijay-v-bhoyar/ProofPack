"""Actual local owner/request transactions; synthetic identity and closed selectors."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from uuid import uuid4
from time import monotonic_ns
import pytest
from test_access_lifecycle import world,repository_factory,invite_and_join,proof
from test_privacy_admission_store import setup
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key,Write,StoreUnavailable,StoreConflict
from proofpack.evidence.owner_metadata import OwnerMetadataRequests,OwnerMetadataLimits,request_key
from proofpack.evidence.privacy_admission import AdmissionHeld,GATE,REGISTRY
from proofpack.runtime.ownership import ResourceOwner
from proofpack.runtime.control import DATA


def prepared(world):
    admission,_=setup(world);owner=ResourceOwner()
    service=OwnerMetadataRequests(world[0],admission,owner,limits=OwnerMetadataLimits(10,20,100,20000),tick_ns=monotonic_ns)
    ident=str(uuid4());world[1].transact((Write(Key('state','inspection#'+ident),None,{'id':ident,'state':'CLOSED','synthetic_selector':True}),))
    return service,owner,ident


def create(service,actor,ident,**changes):
    c=service.context(actor)
    return service.create(actor,**(dict(inspection_ids=(ident,),expected_gate_version=c['gate_version'],
        expected_control_version=c['control_version'],interruption_acknowledged=True,idempotency_key='native-owner-create')|changes))


def cancel(service,actor,r,**changes):
    return service.cancel(actor,**(dict(ident=r['id'],confirmed_scope_sha256=r['scope_sha256'],
        expected_request_version=r['state_version'],expected_gate_version=r['gate_version'],expected_control_version=r['control_version'],
        no_erasure_acknowledged=True,idempotency_key='native-owner-cancel')|changes))


def test_actual_atomic_hold_cancel_and_old_admission_invalidation(world):
    service,owner,ident=prepared(world);old=service.admission.prepare(work_id=str(uuid4()),kind='http',lease_ms=500)
    first=create(service,world[5],ident);assert first['status']=='held' and first['can_cancel']
    assert service.admission.drained(request_id=first['id'],scope_sha256=first['scope_sha256'])
    ended=cancel(service,world[5],first)
    assert ended['status']=='cancelled' and ended['gate_epoch']==first['gate_epoch']+1
    assert not ended['inspection_enabled'] and not ended['erasure_complete'] and not ended['request_fulfilled']
    with pytest.raises(AdmissionHeld):service.admission.admit(old)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('operation',['create','cancel'])
def test_actual_commit_then_lost_reply_recovers_same_original_request(world,monkeypatch,operation):
    service,owner,ident=prepared(world);first=None
    if operation=='cancel':first=create(service,world[5],ident)
    original=world[1].transact;lost=[]
    def unavailable(writes,checks=()):
        original(writes,checks)
        if not lost and any(w.key.resource.startswith('metadata-request#') for w in writes):
            lost.append(True);raise StoreUnavailable('synthetic response loss after actual commit')
    monkeypatch.setattr(world[1],'transact',unavailable)
    result=create(service,world[5],ident) if first is None else cancel(service,world[5],first)
    assert lost and result['status']==('held' if operation=='create' else 'cancelled')
    rows,cursor=world[1].query(prefix='metadata-request#',limit=10);assert len(rows)==1 and cursor is None
    assert owner.wait_for_drain(0)


def test_actual_operator_and_expired_mfa_have_no_control_plane_authority(world):
    service,owner,ident=prepared(world);_,_,operator,*_=invite_and_join(world)
    with pytest.raises(Denied):create(service,operator,ident)
    world[2].value+=600001
    with pytest.raises(Denied):create(service,world[5],ident)
    rows,_=world[1].query(prefix='metadata-request#',limit=10);assert not rows and owner.wait_for_drain(0)


def test_actual_unconfirmed_active_work_survives_expiry_and_blocks_cancel(world):
    service,owner,ident=prepared(world);work=service.admission.prepare(work_id=str(uuid4()),kind='worker',lease_ms=100)
    service.admission.admit(work);first=create(service,world[5],ident);world[2].value+=101
    with pytest.raises(AdmissionHeld):cancel(service,world[5],first)
    assert service.get(world[5],first['id'])['active_count']==1
    service.admission.release(work);ended=cancel(service,world[5],service.get(world[5],first['id']))
    assert ended['status']=='cancelled' and owner.wait_for_drain(0)


def test_actual_cancel_replay_cannot_reopen_another_request(world):
    service,owner,ident=prepared(world);first=create(service,world[5],ident);cancel(service,world[5],first)
    second=create(service,world[5],ident,idempotency_key='native-next-request')
    retry=cancel(service,world[5],first)
    assert retry['replayed'] and retry['status']=='cancelled' and not retry['current_hold']
    assert service.get(world[5],second['id'])['current_hold'] and owner.wait_for_drain(0)


def test_actual_reauthentication_reads_original_history_without_renewing_it(world):
    service,owner,ident=prepared(world);first=create(service,world[5],ident)
    credentials=world[0].login(proof(world[2]));actor=world[0].resolve(credentials.cookie)
    r=service.get(actor,first['id']);assert not r['original_owner_session'] and r['id']==first['id']
    assert cancel(service,actor,r)['status']=='cancelled' and owner.wait_for_drain(0)


def test_actual_selected_inspection_race_cannot_leave_unbound_hold(world,monkeypatch):
    service,owner,ident=prepared(world);original=service.access._prepare_linked;changed=[]
    def prepare(operation,writes,checks=()):
        result=original(operation,writes,checks)
        if operation=='owner-metadata-create':
            key=Key('state','inspection#'+ident);row=world[1].snapshot((key,))[key]
            world[1].transact((Write(key,row.revision,{**row.data,'state':'OBSERVING'}),));changed.append(True)
        return result
    monkeypatch.setattr(service.access,'_prepare_linked',prepare)
    with pytest.raises(StoreConflict):create(service,world[5],ident)
    assert changed
    rows,_=world[1].query(prefix='metadata-request#',limit=10);assert not rows
    assert service.context(world[5])['gate_phase']=='OPEN' and owner.wait_for_drain(0)


def test_actual_concurrent_duplicate_intents_share_one_request_and_quota(world):
    service,owner,ident=prepared(world);c=service.context(world[5]);barrier=Barrier(2)
    other=OwnerMetadataRequests(service.access,service.admission,owner,limits=service.limits,tick_ns=service.tick_ns)
    def call(instance):
        barrier.wait(timeout=5)
        return instance.create(world[5],inspection_ids=(ident,),expected_gate_version=c['gate_version'],
            expected_control_version=c['control_version'],interruption_acknowledged=True,idempotency_key='same-concurrent-intent')
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(call,[service,other]))
    assert results[0]['id']==results[1]['id']
    rows,_=world[1].query(prefix='metadata-request#',limit=10);assert len(rows)==1
    key=Key('state','metadata-owner-quota#'+world[5].scope)
    assert world[1].snapshot((key,))[key].data['count']==1 and owner.wait_for_drain(0)


def test_actual_shared_client_cleanup_waits_for_owner_delivery(world,monkeypatch):
    service,owner,ident=prepared(world);client=world[1].client;original_call=client._make_api_call;close=client.close;closed=[]
    def guarded(*a,**k):
        assert not closed,'owner call used client after local cleanup';return original_call(*a,**k)
    monkeypatch.setattr(client,'_make_api_call',guarded);original=service._heads
    def heads():
        result=original();owner.stop_accepting()
        def cleanup():closed.append(True);close()
        owner.after_drain(cleanup);assert not closed;return result
    monkeypatch.setattr(service,'_heads',heads)
    result=service.context(world[5])
    assert result['gate_phase']=='OPEN' and closed==[True] and owner.wait_for_drain(0)
