"""Actual loopback DynamoDB/ASGI; synthetic identities and intercepted STS only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace,asdict
from threading import Barrier
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from test_access_lifecycle import world,repository_factory,proof,ISSUER
from test_owner_metadata_store import prepared,create,cancel
from test_composition import composition_case,identity
from proofpack.auth.http import COOKIE
from proofpack.auth.service import BootstrapApproval
from proofpack.evidence.privacy_admission import AdmissionConfiguration,AdmissionHeld,REGISTRY,GATE,_bind_control
from proofpack.evidence.owner_metadata import OwnerMetadataLimits,OwnerMetadataRequests
from proofpack.evidence.repository import Key,Write,StoreConflict
from proofpack.runtime.composition import create_configured_app


def control(admission):return admission._prepare_control(work_id=str(uuid4()),lease_ms=500)


def test_actual_control_cancel_retains_registration_through_fence_and_exact_release(world):
    service,owner,ident=prepared(world);a=service.admission;work=control(a);a._admit_control(work)
    with _bind_control(a,work):
        request=create(service,world[5],ident);assert request['can_cancel'] and request['active_count']==0
        result=cancel(service,world[5],request)
        assert result['status']=='cancelled' and not result['inspection_enabled'] and not result['erasure_complete']
        row=world[1].snapshot((REGISTRY,))[REGISTRY]
        assert row.data['active']=={work.work_id:asdict(work)} and row.data['gate_epoch']==work.gate_epoch+1
        a._checkpoint_control(work)
    assert a._release_control(work) and owner.wait_for_drain(0)


def test_actual_control_serialization_uses_registry_conditional_write(world):
    service,owner,ident=prepared(world);a=service.admission;works=[control(a),control(a)];barrier=Barrier(2)
    def admit(work):
        barrier.wait(timeout=5)
        try:a._admit_control(work);return work
        except (AdmissionHeld,StoreConflict):return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(admit,works))
    winners=[w for w in results if w is not None];assert len(winners)==1
    assert set(world[1].snapshot((REGISTRY,))[REGISTRY].data['active'])=={winners[0].work_id}
    a._release_control(winners[0])


def test_actual_control_does_not_hide_expired_ordinary_work(world):
    service,owner,ident=prepared(world);a=service.admission
    ordinary=a.prepare(work_id=str(uuid4()),kind='worker',lease_ms=100);a.admit(ordinary)
    request=create(service,world[5],ident);world[2].value+=101
    work=control(a);a._admit_control(work)
    with _bind_control(a,work):
        assert service.get(world[5],request['id'])['active_count']==1
        with pytest.raises(AdmissionHeld):cancel(service,world[5],request)
        a.release(ordinary);ended=cancel(service,world[5],service.get(world[5],request['id']))
        assert ended['status']=='cancelled'
    a._release_control(work)


def test_actual_expired_control_blocks_replacement_until_confirmed_release(world):
    service,owner,ident=prepared(world);a=service.admission;work=control(a);a._admit_control(work)
    world[2].value=work.expires_at_ms
    with pytest.raises(AdmissionHeld):control(a)
    with pytest.raises(AdmissionHeld):a._checkpoint_control(work)
    assert a._release_control(work)
    a._admit_control(control(a))


def test_actual_factory_validated_clock_is_supported_without_relaxing_identity(world):
    service,owner,ident=prepared(world);service.admission.clock_ms=service.access.now
    service=OwnerMetadataRequests(service.access,service.admission,owner,limits=service.limits,tick_ns=service.tick_ns)
    assert create(service,world[5],ident)['status']=='held' and owner.wait_for_drain(0)


def test_configured_owner_http_uses_shared_services_and_survives_held_auth_read(composition_case):
    repository,config,clients,stub,clock=composition_case
    config=replace(config,auth=replace(config.auth,initial_owner_subject='owner',bootstrap_receipt_sha256='a'*64),
        metadata_admission=AdmissionConfiguration(8,20000,20000,15000,3,'c'*64),owner_metadata=OwnerMetadataLimits(10,20,100,20000))
    identity(stub);app=create_configured_app(config,clients,clock_ms=clock)
    access=app.state.access_service;runtime=app.state.runtime_control;admission=app.state.metadata_admission
    access.bootstrap(BootstrapApproval(ISSUER,'owner','a'*64),proof(clock));runtime.start();admission.initialize('c'*64)
    credentials=access.login(proof(clock));ident=str(uuid4())
    repository.transact((Write(Key('state','inspection#'+ident),None,{'id':ident,'state':'CLOSED','synthetic_selector':True}),))
    base='/api/v1/privacy/metadata-requests';headers={'Origin':config.app_origin,'X-CSRF-Token':credentials.csrf,'Idempotency-Key':'configured-owner-create'}
    assert app.state.owner_metadata_service.admission is admission
    assert app.state.owner_metadata_service.resource_owner is app.state.resource_owner
    with TestClient(app,base_url=config.app_origin) as client:
        client.cookies.set(COOKIE,credentials.cookie);context=client.get(base+'/context')
        assert context.status_code==200,context.text
        c=context.json();response=client.post(base,json=dict(inspection_ids=[ident],expected_gate_version=c['gate_version'],
            expected_control_version=c['control_version'],interruption_acknowledged=True),headers=headers)
        assert response.status_code==201,response.text
        request=response.json();assert request['can_cancel'] and not request['request_fulfilled']
        assert client.get('/api/v1/me').status_code==200
        assert client.get('/api/v1/users').status_code==503
        result=client.post(base+'/'+request['id']+'/cancel',json=dict(confirmed_scope_sha256=request['scope_sha256'],
            expected_request_version=request['state_version'],expected_gate_version=request['gate_version'],
            expected_control_version=request['control_version'],no_erasure_acknowledged=True),headers={**headers,'Idempotency-Key':'configured-owner-cancel'})
        assert result.status_code==200,result.text
        assert result.json()['status']=='cancelled' and not result.json()['inspection_enabled']
    assert not repository.snapshot((REGISTRY,))[REGISTRY].data['active']
    assert app.state.composition_status=='closed' and app.state.resource_owner.wait_for_drain(0)
