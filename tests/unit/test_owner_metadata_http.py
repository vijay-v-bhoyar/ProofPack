"""Real app routing/ASGI over modeled durable state and synthetic identity proofs."""
from copy import deepcopy
from dataclasses import replace
import anyio
import pytest
from fastapi.testclient import TestClient
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.evidence.privacy_admission import AdmissionConfiguration,REGISTRY,GATE,AdmissionHeld
from proofpack.evidence.privacy_http import MetadataAdmissionBoundary,_control_route
from proofpack.evidence.owner_metadata import OwnerMetadataRequests
from proofpack.evidence.repository import StoreUnavailable
from proofpack.runtime.ownership import ResourceOwner
from test_owner_metadata import world,create,no_sdk
from test_privacy_admission import ident,world as protocol_world,hold

ORIGIN='https://proofpack.example.invalid'
BASE='/api/v1/privacy/metadata-requests'


def client_world(*,enabled=True):
    service,actor,repo,clock,owner,proof=world()
    service.access.config=replace(service.access.config,notice_version='synthetic-v1',notice_text='Synthetic test notice; no real participant terms.')
    service=OwnerMetadataRequests(service.access,service.admission,owner,limits=service.limits,tick_ns=service.tick_ns)
    credentials=service.access.login(proof)
    config=AdmissionConfiguration(8,1000,500,500,3,'c'*64)
    app=create_app(owner_metadata_service=service if enabled else None,metadata_admission=service.admission,
        admission_configuration=config,resource_owner=owner,access_service=service.access,app_origin=ORIGIN,
        runtime_control=service.runtime,manage_service_lifecycle=False)
    client=TestClient(app,base_url=ORIGIN);client.cookies.set(COOKIE,credentials.cookie)
    headers={'Origin':ORIGIN,'X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-create'}
    return service,actor,repo,clock,owner,client,headers


def body(client):
    context=client.get(BASE+'/context');assert context.status_code==200,context.text
    data=context.json()
    return dict(inspection_ids=[ident(1)],expected_gate_version=data['gate_version'],
        expected_control_version=data['control_version'],interruption_acknowledged=True)


def test_app_owner_create_recover_cancel_while_held_without_enabling_or_erasing():
    service,actor,repo,clock,owner,client,headers=client_world()
    with client:
        request=body(client);first=client.post(BASE,json=request,headers=headers)
        assert first.status_code==201,first.text
        record=first.json();assert record['can_cancel'] and record['active_count']==0
        assert client.get('/api/v1/users').status_code==503
        for path in ['/api/v1/me','/api/v1/auth/session','/api/v1/auth/notice']:
            assert client.get(path).status_code==200
        assert client.get(BASE+'/'+record['id']).json()['status']=='held'
        replay=client.post(BASE,json=request,headers=headers)
        assert replay.status_code==201 and replay.json()['id']==record['id'] and replay.json()['replayed']
        cancel=dict(confirmed_scope_sha256=record['scope_sha256'],expected_request_version=record['state_version'],
            expected_gate_version=record['gate_version'],expected_control_version=record['control_version'],no_erasure_acknowledged=True)
        ended=client.post(BASE+'/'+record['id']+'/cancel',json=cancel,headers={**headers,'Idempotency-Key':'http-cancel'})
        assert ended.status_code==200,ended.text
        assert ended.json()['status']=='cancelled' and not ended.json()['inspection_enabled']
        assert not ended.json()['request_fulfilled'] and not ended.json()['erasure_complete']
        assert 'DO_NOT_DISCLOSE' not in first.text+ended.text
    assert not repo.rows[REGISTRY].data['active'] and owner.wait_for_drain(0)


@pytest.mark.parametrize('fault',['missing','wrong_origin','missing_csrf','forged_role','non_owner','stale_mfa','revoked'])
def test_owner_http_current_authority_and_write_guard(fault):
    service,actor,repo,clock,owner,client,headers=client_world()
    with client:
        request=body(client)
        if fault=='missing':client.cookies.clear()
        elif fault=='wrong_origin':headers['Origin']='https://foreign.invalid'
        elif fault=='missing_csrf':headers.pop('X-CSRF-Token')
        elif fault=='forged_role':client.cookies.clear();headers['x-user-role']='owner'
        elif fault=='stale_mfa':clock.value+=601000
        else:
            row=repo.rows[actor.member.key]
            changes={'roles':['operator']} if fault=='non_owner' else {'enabled':False}
            repo.rows[row.key]=replace(row,revision=row.revision+1,data={**row.data,**changes})
        result=client.post(BASE,json=request,headers=headers)
        assert result.status_code in {401,403}
    assert repo.rows[GATE].data['phase']=='OPEN' and not repo.rows[REGISTRY].data['active'] and owner.wait_for_drain(0)


@pytest.mark.parametrize('change',[{'expected_gate_version':True},{'expected_control_version':'1'},
    {'interruption_acknowledged':False},{'interruption_acknowledged':1},{'bypass':True},
    {'inspection_ids':[]},{'inspection_ids':[ident(1)]*65},{'inspection_ids':[ident(1),ident(1)]}])
def test_closed_strict_owner_body_denies_without_request(change):
    service,actor,repo,clock,owner,client,headers=client_world()
    with client:
        result=client.post(BASE,json={**body(client),**change},headers=headers)
        assert result.status_code in {400,403}
        oversized=client.post(BASE,content=b'x'*8193,headers={**headers,'Content-Type':'application/json'})
        assert oversized.status_code==413
    assert repo.rows[GATE].data['phase']=='OPEN' and not repo.rows[REGISTRY].data['active'] and owner.wait_for_drain(0)


@pytest.mark.parametrize('path,method',[(BASE+'/', 'POST'),(BASE+'/context/','GET'),
    (BASE+'/context','HEAD'),(BASE+'/context','POST'),('/api/v1/users','GET'),
    ('/api/v1/privacy/erase','POST'),('/api/v1/auth/session/','GET'),('/api/v1/admin/enable','POST')])
def test_held_control_dispatch_has_no_prefix_or_method_escape(path,method):
    service,actor,repo,clock,owner,client,headers=client_world()
    create(service,actor)
    with client:result=client.request(method,path,headers=headers,json={})
    assert result.status_code==503 and not repo.rows[REGISTRY].data['active'] and owner.wait_for_drain(0)


@pytest.mark.parametrize('raw',[b'/api/v1/privacy/metadata-requests/%63ontext',b'/api/v1//privacy/metadata-requests/context',None])
def test_canonical_raw_path_is_required_for_control_dispatch(raw):
    assert not _control_route({'path':BASE+'/context','raw_path':raw,'method':'GET'})


def test_control_is_explicit_opt_in_and_shared_owner_required():
    service,actor,repo,clock,owner,client,headers=client_world(enabled=False);create(service,actor)
    with client:assert client.get(BASE+'/context').status_code==503
    with pytest.raises(ValueError):create_app(owner_metadata_service=service)
    with pytest.raises(ValueError):MetadataAdmissionBoundary(lambda *a:None,admission=service.admission,lease_ms=500,attempts=1,owner_control=True)


def test_held_recovery_uses_existing_handlers_and_never_bootstraps_owner():
    service,actor,repo,clock,owner,client,headers=client_world();create(service,actor)
    with client:
        client.cookies.clear()
        assert client.get('/api/v1/me').status_code==401
        assert client.get(BASE+'/context').status_code==401
        callback=client.get('/api/v1/auth/callback?code=SECRET&state=STATE')
        assert callback.status_code==503 and 'SECRET' not in callback.text
        assert client.get('/api/v1/auth/login').status_code==503 # No provider configured, no fake recovery.
    assert repo.rows[GATE].data['phase']=='HELD' and not repo.rows[REGISTRY].data['active']


@pytest.mark.parametrize('failure',['release','cancel','expires'])
def test_control_resource_lifetime_through_send_and_uncertain_completion(monkeypatch,failure):
    admission,repo,runtime,clock=protocol_world();hold(admission);owner=ResourceOwner();messages=[]
    async def app(scope,receive,send):
        assert not owner.wait_for_drain(0)
        if failure=='cancel':raise anyio.get_cancelled_exc_class()()
        if failure=='expires':clock.value+=500
        await send({'type':'http.response.start','status':200,'headers':[]})
        await send({'type':'http.response.body','body':b'OK'})
    if failure=='release':
        def failed(intent):raise StoreUnavailable('private release uncertainty')
        monkeypatch.setattr(admission,'_release_control',failed)
    boundary=MetadataAdmissionBoundary(app,admission=admission,lease_ms=500,attempts=1,resource_owner=owner,owner_control=True)
    async def run():
        async def receive():return {'type':'http.request','body':b''}
        async def send(message):
            assert not owner.wait_for_drain(0)
            messages.append(deepcopy(message))
        scope={'type':'http','path':BASE+'/context','raw_path':(BASE+'/context').encode(),'method':'GET'}
        if failure=='cancel':
            with pytest.raises(anyio.get_cancelled_exc_class()):await boundary(scope,receive,send)
        else:await boundary(scope,receive,send)
    anyio.run(run)
    if failure=='expires':
        assert messages[0]['status']==503 and not repo.rows[REGISTRY].data['active'] and owner.wait_for_drain(0)
    else:
        assert repo.rows[REGISTRY].data['active'] and not owner.wait_for_drain(0)
