"""Adjacent original-owner lifetime, error precedence and retry-budget controls."""
from concurrent.futures import Future
import pytest
from test_worker_config_fence import setup
from proofpack.evidence.privacy_admission import AdmissionHeld, REGISTRY
from proofpack.evidence.repository import StoreConflict, StoreUnavailable
from proofpack.runtime.ownership import ResourceOwner

def test_acquire_callback_drift_releases_original_ticket_before_any_durable_work(monkeypatch):
    worker,service,repo,owner=setup();original=owner.acquire;calls=[]
    def acquire():
        ticket=original();worker.resource_owner=None;return ticket
    monkeypatch.setattr(owner,'acquire',acquire)
    with pytest.raises(AdmissionHeld):worker.run(lambda:calls.append(True))
    assert not calls and owner.wait_for_drain(0) and not repo.rows[REGISTRY].data['active']
    assert worker.release_pending

@pytest.mark.parametrize('error',[ValueError,KeyboardInterrupt])
def test_operation_failure_precedence_and_original_owner_survive_drift(error):
    worker,service,repo,owner=setup();foreign=ResourceOwner();foreign_ticket=foreign.acquire()
    def operation():
        worker.resource_owner=foreign;raise error('original operation failure')
    with pytest.raises(error,match='original operation failure'):worker.run(operation)
    assert worker.release_pending and len(repo.rows[REGISTRY].data['active'])==1
    assert owner.wait_for_drain(0)==(error is ValueError)
    assert not foreign.wait_for_drain(0)
    foreign.release(foreign_ticket)

def test_deferred_result_with_drift_keeps_original_owner_and_never_cancels_future():
    worker,service,repo,owner=setup();future=Future();foreign=ResourceOwner()
    def operation():worker.resource_owner=foreign;return future
    with pytest.raises(AdmissionHeld):worker.run(operation)
    assert worker.release_pending and not owner.wait_for_drain(0) and foreign.wait_for_drain(0)
    assert not future.cancelled() and len(repo.rows[REGISTRY].data['active'])==1

def test_normal_release_outage_keeps_durable_hold_but_completed_local_work_drains(monkeypatch):
    worker,service,repo,owner=setup();calls=[]
    def release(intent):calls.append(intent);raise StoreUnavailable('synthetic release outage')
    monkeypatch.setattr(service,'release',release)
    assert worker.run(lambda:'finished')=='finished'
    assert len(calls)==1 and worker.release_pending and len(repo.rows[REGISTRY].data['active'])==1
    assert owner.wait_for_drain(0)
    with pytest.raises(AdmissionHeld):worker.run(lambda:'forbidden')

def test_original_bookkeeping_ceiling_and_intent_identity_never_replay_business(monkeypatch):
    worker,service,repo,owner=setup();business=[];calls={'admit':[],'release':[]}
    for name in calls:
        original=getattr(service,name)
        def callback(intent,name=name,original=original):
            calls[name].append(intent)
            if len(calls[name])==1:raise StoreConflict('synthetic bounded contention')
            return original(intent)
        monkeypatch.setattr(service,name,callback)
    assert worker.run(lambda:business.append(True)) is None
    assert business==[True] and all(len(v)==2 and v[0] is v[1] for v in calls.values())
    assert calls['admit'][0] is calls['release'][0]
    assert not worker.release_pending and not repo.rows[REGISTRY].data['active'] and owner.wait_for_drain(0)

@pytest.mark.parametrize('drift',[False,True])
def test_release_failure_cannot_replace_original_business_exception(monkeypatch,drift):
    worker,service,repo,owner=setup()
    def operation():raise ValueError('original business failure')
    def release(intent):
        if drift:worker.attempts=3
        raise RuntimeError('synthetic release failure')
    monkeypatch.setattr(service,'release',release)
    with pytest.raises(ValueError,match='original business failure'):worker.run(operation)
    assert worker.release_pending and owner.wait_for_drain(0)
    assert len(repo.rows[REGISTRY].data['active'])==1
