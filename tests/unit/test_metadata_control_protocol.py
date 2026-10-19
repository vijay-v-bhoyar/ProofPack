"""Control protocol on optimistic modeled state; no HTTP/provider or physical proof."""
from copy import deepcopy
from dataclasses import replace
import pytest
import proofpack.evidence.privacy_admission as protocol
from proofpack.evidence.privacy_admission import AdmissionHeld,GATE,REGISTRY
from proofpack.evidence.owner_metadata import OwnerMetadataRequests
from proofpack.evidence.repository import Row,StoreConflict
from test_privacy_admission import world,intent,hold,ident
from test_owner_metadata import world as owner_world,create,cancel,no_sdk


def control(service,number=21):
    return service._prepare_control(work_id=ident(number),lease_ms=500)


def bind(service,work):return protocol._bind_control(service,work)


def test_factory_clock_rejects_arbitrary_wrapper_and_later_clock_replacement():
    service,actor,repo,clock,owner,_=owner_world()
    service.admission.clock_ms=lambda:service.access.now()
    with pytest.raises(ValueError):OwnerMetadataRequests(service.access,service.admission,owner,limits=service.limits,tick_ns=service.tick_ns)
    service.admission.clock_ms=service.access.now
    current=OwnerMetadataRequests(service.access,service.admission,owner,limits=service.limits,tick_ns=service.tick_ns)
    assert current.context(actor)['gate_phase']=='OPEN'
    service.admission.clock_ms=service.access.now # Equal bound method, different pinned object.
    with pytest.raises(AdmissionHeld):current.context(actor)
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('held',[False,True])
def test_single_control_global_and_ordinary_cannot_use_its_intent(held):
    service,repo,runtime,clock=world()
    if held:hold(service)
    work=control(service);service._admit_control(work)
    assert repo.rows[REGISTRY].data['active'][work.work_id]['kind']=='control'
    with pytest.raises(AdmissionHeld):control(service,22)
    with pytest.raises(ValueError):service.prepare(work_id=ident(23),kind='control',lease_ms=500)
    for method in [service.admit,service.checkpoint,service.release]:
        with pytest.raises(AdmissionHeld):method(work)
    with pytest.raises(AdmissionHeld):
        with protocol.bind_admission(service,work):protocol.checkpoint_current()
    service._checkpoint_control(work)
    assert service._release_control(work) is True


def test_control_drain_requires_exact_bound_context_and_preserves_registration():
    service,repo,runtime,clock=world();work=control(service);service._admit_control(work);hold(service)
    before=deepcopy(repo.rows)
    with pytest.raises(AdmissionHeld):service.drained(request_id=ident(90),scope_sha256='b'*64)
    with bind(service,work):
        proof=service.drained(request_id=ident(90),scope_sha256='b'*64)
        service.assert_drained(proof)
        with pytest.raises(AdmissionHeld):
            with bind(service,work):pass
    assert repo.rows==before
    with pytest.raises(AdmissionHeld):service.assert_drained(proof)
    with pytest.raises(AdmissionHeld):
        with bind(service,replace(work,work_id=ident(22))):pass
    service._release_control(work)


@pytest.mark.parametrize('expired',[False,True])
def test_control_does_not_hide_other_work_or_auto_clear_expired_control(expired):
    service,repo,runtime,clock=world();ordinary=intent(service);service.admit(ordinary)
    work=control(service);service._admit_control(work);hold(service)
    if expired:clock.value=work.expires_at_ms
    with pytest.raises(AdmissionHeld):
        with bind(service,work):service.drained(request_id=ident(90),scope_sha256='b'*64)
    with pytest.raises(AdmissionHeld):control(service,22)
    assert len(repo.rows[REGISTRY].data['active'])==2
    service.release(ordinary);service._release_control(work)
    service.drained(request_id=ident(90),scope_sha256='b'*64)


def test_foreign_ordinary_work_can_be_reported_but_foreign_control_blocks_new_control():
    service,repo,runtime,clock=world();ordinary=intent(service);service.admit(ordinary)
    row=repo.rows[REGISTRY];data=deepcopy(row.data);data['active'][ordinary.work_id]['instance_id']=ident(55)
    repo.rows[REGISTRY]=Row(REGISTRY,row.revision+1,data)
    work=control(service);service._admit_control(work);hold(service)
    with bind(service,work):
        with pytest.raises(AdmissionHeld):service.drained(request_id=ident(90),scope_sha256='b'*64)
    service._release_control(work)
    row=repo.rows[REGISTRY];data=deepcopy(row.data);data['active']={work.work_id:{**protocol.asdict(work),'instance_id':ident(55)}}
    repo.rows[REGISTRY]=Row(REGISTRY,row.revision+1,data)
    with pytest.raises(AdmissionHeld):control(service,22)
    with pytest.raises(AdmissionHeld):service._release_control(work)


def test_cancel_preserves_own_control_across_epoch_until_actual_release():
    service,actor,repo,clock,owner,_=owner_world();admission=service.admission
    work=control(admission);admission._admit_control(work)
    with bind(admission,work):
        context=service.context(actor);assert context['active_count']==0
        created=create(service,actor);assert created['can_cancel'] and created['active_count']==0
        ended=cancel(service,actor,created)
        assert ended['status']=='cancelled' and not ended['inspection_enabled'] and not ended['erasure_complete']
        assert repo.rows[REGISTRY].data['active']=={work.work_id:protocol.asdict(work)}
        assert repo.rows[GATE].data['epoch']==work.gate_epoch+1
        admission._checkpoint_control(work)
        with pytest.raises(AdmissionHeld):control(admission,22)
    assert admission._release_control(work) and not repo.rows[REGISTRY].data['active']
    assert owner.wait_for_drain(0)


def test_unknown_control_commit_recovers_original_without_renewing_or_second_entry():
    service,repo,runtime,clock=world();work=control(service);repo.lose_reply=True
    assert service._admit_control(work)==work
    before=deepcopy(repo.rows);clock.value+=1
    assert service._admit_control(work)==work and repo.rows==before
    with pytest.raises(AdmissionHeld):service._admit_control(replace(work,expires_at_ms=work.expires_at_ms+1))
    repo.lose_reply=True;assert service._release_control(work) is False
    assert not repo.rows[REGISTRY].data['active']


def test_concurrent_control_admission_cannot_overwrite_registered_winner():
    service,repo,runtime,clock=world();a=control(service);b=control(service,22)
    repo.before_commit=lambda:service._admit_control(b)
    with pytest.raises((AdmissionHeld,StoreConflict)):service._admit_control(a)
    assert set(repo.rows[REGISTRY].data['active'])=={b.work_id}
