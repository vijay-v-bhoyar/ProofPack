"""Original worker lifetime/budget regressions on modeled durable state."""
from concurrent.futures import Future
import pytest
from test_privacy_admission import world
from proofpack.evidence.privacy_workers import AdmittedWorker
from proofpack.evidence.privacy_admission import AdmissionHeld, REGISTRY
from proofpack.evidence.repository import StoreConflict
from proofpack.runtime.ownership import ResourceOwner

def setup():
    service,repo,runtime,clock=world();owner=ResourceOwner()
    return AdmittedWorker(service,lease_ms=500,attempts=2,resource_owner=owner),service,repo,owner

@pytest.mark.parametrize('field,value',[
    ('attempts',3),('attempts',True),('attempts',2.0),('lease_ms',600),
    ('lease_ms',500.0),('admission',None),('resource_owner',None),('resource_owner',ResourceOwner()),
])
def test_original_configuration_drift_denies_before_business_and_registry(field,value):
    worker,service,repo,owner=setup();before=dict(repo.rows);calls=[]
    setattr(worker,field,value)
    with pytest.raises(AdmissionHeld):worker.run(lambda:calls.append(True))
    assert not calls and repo.rows==before and owner.wait_for_drain(0)

@pytest.mark.parametrize('phase',['prepare','admit','checkpoint'])
def test_drift_from_admission_callback_prevents_business_and_keeps_original_work(monkeypatch,phase):
    worker,service,repo,owner=setup();original=getattr(service,phase);calls=[]
    def callback(*args,**kwargs):
        value=original(*args,**kwargs);worker.attempts=3;return value
    monkeypatch.setattr(service,phase,callback)
    with pytest.raises(AdmissionHeld):worker.run(lambda:calls.append(True))
    assert not calls and worker.release_pending and owner.wait_for_drain(0)
    assert bool(repo.rows[REGISTRY].data['active'])==(phase!='prepare')

@pytest.mark.parametrize('field',['attempts','lease_ms','admission','resource_owner'])
def test_business_drift_holds_original_registry_and_releases_only_original_local_owner(field):
    worker,service,repo,owner=setup();foreign=ResourceOwner();ticket=foreign.acquire();calls=[]
    def operation():
        calls.append(True)
        setattr(worker,field,{'attempts':3,'lease_ms':600,'admission':world()[0],'resource_owner':foreign}[field])
        return 'not-deliverable'
    with pytest.raises(AdmissionHeld):worker.run(operation)
    assert calls==[True] and worker.release_pending and len(repo.rows[REGISTRY].data['active'])==1
    assert owner.wait_for_drain(0) and not foreign.wait_for_drain(0)
    foreign.release(ticket)
    with pytest.raises(AdmissionHeld):worker.run(lambda:calls.append(False))
    assert calls==[True]

@pytest.mark.parametrize('phase',['admit','release'])
def test_configuration_drift_on_conflict_cannot_expand_retry_budget(monkeypatch,phase):
    worker,service,repo,owner=setup();calls=[];business=[]
    def conflict(intent):
        calls.append(intent);worker.attempts=3;raise StoreConflict('synthetic drift contention')
    monkeypatch.setattr(service,phase,conflict)
    with pytest.raises(AdmissionHeld):worker.run(lambda:business.append(True))
    assert len(calls)==1 and len(business)==(phase=='release')
    assert worker.release_pending and owner.wait_for_drain(0)
    assert len(repo.rows[REGISTRY].data['active'])==(phase=='release')

def test_drift_after_original_release_reports_hold_without_inventing_registration(monkeypatch):
    worker,service,repo,owner=setup();original=service.release;calls=[]
    def release(intent):
        calls.append(intent);result=original(intent);worker.attempts=3;return result
    monkeypatch.setattr(service,'release',release)
    with pytest.raises(AdmissionHeld):worker.run(lambda:'finished')
    assert len(calls)==1 and worker.release_pending and not repo.rows[REGISTRY].data['active']
    assert owner.wait_for_drain(0)

@pytest.mark.parametrize('deferred',[False,True])
def test_original_owner_remains_held_only_for_unconfirmed_execution(deferred):
    worker,service,repo,owner=setup();pending=Future()
    if deferred:
        with pytest.raises(AdmissionHeld):worker.run(lambda:pending)
        assert not owner.wait_for_drain(0) and worker.release_pending
        assert not pending.cancelled() and len(repo.rows[REGISTRY].data['active'])==1
    else:
        assert worker.run(lambda:'done')=='done'
        assert owner.wait_for_drain(0) and not repo.rows[REGISTRY].data['active']

def test_known_business_error_releases_original_owner_without_replaying():
    worker,service,repo,owner=setup();calls=[]
    def operation():calls.append(True);raise ValueError('synthetic business failure')
    with pytest.raises(ValueError,match='synthetic business failure'):worker.run(operation)
    assert calls==[True] and owner.wait_for_drain(0) and not repo.rows[REGISTRY].data['active']
