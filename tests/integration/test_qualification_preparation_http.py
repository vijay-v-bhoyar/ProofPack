"""Owned HTTP/driver integration; generated pixels, synthetic identity and S3."""
from types import SimpleNamespace
import time
import pytest
from fastapi.testclient import TestClient
from test_qualification_preparation import preparations,vision_case,world,repository_factory,publication_case,original_case
from test_access_lifecycle import invite_and_join
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Role
from proofpack.runtime.maintenance import MaintenanceDriver
from proofpack.stations.service import POLICY
from proofpack.evidence.repository import StoreUnavailable
from proofpack.planner import contract_registry

ORIGIN='https://proofpack.test'
BASE='/api/v1/qualification-preparations'


def app_for(service):
    evaluations=service.evaluations;datasets=evaluations.datasets
    return create_app(access_service=service.access,app_origin=ORIGIN,runtime_control=service.runtime,
        purpose_service=datasets.purposes,label_service=datasets.labels,asset_service=datasets.improvement.assets,
        improvement_service=datasets.improvement,dataset_service=datasets,policy_service=evaluations.policies,
        evaluation_service=evaluations,qualification_preparation_service=service,manage_service_lifecycle=False)


def headers(credentials,key,version=None):
    value={'Origin':ORIGIN,'X-CSRF-Token':credentials.csrf,'Idempotency-Key':key}
    if version is not None:value['If-Match']=str(version)
    return value


def test_http_manual_step_then_actual_shared_thread_completes_all_preparation_cases(world,vision_case,preparations):
    service,actor,request=preparations;credentials=vision_case[-1];app=app_for(service);before=world[1].snapshot((POLICY,))[POLICY]
    unused=SimpleNamespace(access=service.access,runtime=service.runtime,repository=service.repository)
    driver=MaintenanceDriver(service.access,service.runtime,unused,unused,enabled=True,poll_ms=250,page_size=25,
        steps_per_minute=120,drain_ms=5000,evaluations=service.evaluations,preparations=service)
    app.state.maintenance_driver=driver
    with TestClient(app,base_url=ORIGIN,cookies={COOKIE:credentials.cookie}) as client:
        options=client.get(BASE+'/options');assert options.status_code==200 and options.json()['software_cases']==170
        response=client.post(BASE,json=request.model_dump(mode='json'),headers=headers(credentials,'http-preparation'));assert response.status_code==201,response.text
        job=response.json();ident=job['id'];assert job['planned_count']==171
        assert client.get(BASE).json()['preparations'][0]['id']==ident
        assert client.get(BASE).json()['preparations'][0]['source_current'] is None
        assert client.get(BASE+'/'+ident+'/request').json()==request.model_dump(mode='json')
        response=client.post('/api/v1/jobs/'+ident+'/advance',json={},headers=headers(credentials,'manual-first',job['state_version']))
        assert response.status_code==200 and response.json()['prepared_count']==1
        assert app.state.qualification_preparation_service is driver.services['policy_qualification_preparation']
        advanced=False;driver.start();deadline=time.monotonic()+240
        try:
            while time.monotonic()<deadline:
                row=service._row(ident)
                if not advanced and row.data['processed']>=100 and row.data['status']=='queued':
                    world[2].value=(world[2]()//60000+1)*60000;advanced=True
                if row.data['status']=='completed':break
                if row.data['status'] in {'failed','cancelled','retired'}:pytest.fail('preparation stopped before completion')
                time.sleep(.03)
            else:pytest.fail('owned shared maintenance thread did not finish within its test guard')
        finally:assert driver.stop_and_drain()
        result=client.get(BASE+'/'+ident);assert result.status_code==200,result.text
        job=result.json();assert job['report_current'] and job['status']=='completed' and job['steps_reserved']==job['prepared_count']==171
        assert job['counts']=={'software_pass':170,'software_fail':0,'source_entries_verified':1}
        assert job['qualification_status']=='not_qualified' and not job['promotion_eligible']
        page=client.get(BASE+'/'+ident+'/entries',params={'start':170,'limit':1})
        assert page.status_code==200 and page.json()['entries'][0]['phase']=='source_evaluation_integrity'
        assert client.post('/api/v1/jobs/'+ident+'/cancel',json={},headers=headers(credentials,'cannot-cancel-completed',job['state_version'])).status_code==409
        response=client.post(BASE+'/'+ident+'/retire',json={'acknowledged':True,'reason':'completed-test'},headers=headers(credentials,'explicit-retire',job['state_version']))
        assert response.status_code==200 and response.json()['status']=='retired'
    assert world[1].snapshot((POLICY,))[POLICY]==before


def test_http_roles_discovery_write_guards_request_recovery_and_closed_service(world,vision_case,preparations,publication_case):
    service,actor,request=preparations;credentials=vision_case[-1];app=app_for(service)
    with TestClient(app,base_url=ORIGIN,cookies={COOKIE:credentials.cookie}) as client:
        assert client.post(BASE,json=request.model_dump(mode='json'),headers={**headers(credentials,'foreign'),'Origin':'https://foreign.test'}).status_code==403
        assert client.post(BASE,json=request.model_dump(mode='json'),headers={**headers(credentials,'csrf'),'X-CSRF-Token':'wrong'}).status_code==403
        assert client.post(BASE,json={**request.model_dump(mode='json'),'qualified':True},headers=headers(credentials,'forged')).status_code==400
        assert client.post(BASE,json={'padding':'x'*9000},headers=headers(credentials,'too-large')).status_code==413
        response=client.post(BASE,json=request.model_dump(mode='json'),headers=headers(credentials,'guarded'));assert response.status_code==201,response.text
        job=response.json();ident=job['id']
        assert client.post(BASE,json=request.model_dump(mode='json'),headers=headers(credentials,'guarded')).json()['id']==ident
        assert client.post(BASE,json={**request.model_dump(mode='json'),'source_report_sha256':'f'*64},headers=headers(credentials,'guarded')).status_code==409
        assert client.get(BASE,params={'scope':'owner'}).status_code==403
        assert client.get(BASE,params={'scope':'all'}).status_code==400
        assert client.get(BASE,params={'limit':21}).status_code==400
        assert client.get(BASE,params={'cursor':'not-a-uuid'}).status_code==400
        assert client.get(BASE+'/'+ident+'/entries',params={'limit':21}).status_code==400
        assert client.post('/api/v1/jobs/'+ident+'/advance',json={'force':True},headers=headers(credentials,'force',job['state_version'])).status_code==400
        assert client.post('/api/v1/jobs/'+ident+'/advance',json={},headers=headers(credentials,'stale',999)).status_code==409
        _,other_credentials,other,*_=invite_and_join(world,'other-http-preparer',roles=(Role.REVIEWER,))
        with TestClient(app,base_url=ORIGIN,cookies={COOKIE:other_credentials.cookie}) as other_client:
            assert other_client.get(BASE).json()['preparations']==[]
            assert other_client.get(BASE+'/'+ident).status_code==403
        with TestClient(app,base_url=ORIGIN,cookies={COOKIE:world[4].cookie}) as owner:
            assert owner.get(BASE,params={'scope':'owner'}).json()['preparations'][0]['id']==ident
            assert owner.get(BASE+'/'+ident).json()['counts'] is None
            assert owner.get(BASE+'/'+ident+'/request').status_code==403
            assert owner.get(BASE+'/'+ident+'/entries').status_code==403
            assert owner.post('/api/v1/jobs/'+ident+'/advance',json={},headers=headers(world[4],'owner-advance',job['state_version'])).status_code==403
            cancelled=owner.post('/api/v1/jobs/'+ident+'/cancel',json={},headers=headers(world[4],'owner-cancel',job['state_version']))
            assert cancelled.status_code==200 and cancelled.json()['status']=='cancelled'
        with TestClient(app,base_url=ORIGIN,cookies={COOKIE:publication_case[4].cookie}) as operator:
            assert operator.get(BASE+'/options').status_code==403
            assert operator.get(BASE).status_code==403
        disabled=create_app(access_service=world[0],app_origin=ORIGIN)
        with TestClient(disabled,base_url=ORIGIN,cookies={COOKIE:credentials.cookie}) as closed:
            assert closed.get(BASE+'/options').status_code==503


def test_disabled_automatic_maintenance_does_not_prevent_manual_http_step(vision_case,preparations):
    service,_,request=preparations;credentials=vision_case[-1];app=app_for(service)
    unused=SimpleNamespace(access=service.access,runtime=service.runtime,repository=service.repository)
    driver=MaintenanceDriver(service.access,service.runtime,unused,unused,enabled=False,poll_ms=250,page_size=25,
        steps_per_minute=120,drain_ms=5000,evaluations=service.evaluations,preparations=service)
    with TestClient(app,base_url=ORIGIN,cookies={COOKIE:credentials.cookie}) as client:
        job=client.post(BASE,json=request.model_dump(mode='json'),headers=headers(credentials,'manual-mode')).json()
        assert driver.poll_once() is False and service._row(job['id']).data['steps_reserved']==0
        result=client.post('/api/v1/jobs/'+job['id']+'/advance',json={},headers=headers(credentials,'manual-mode-step',job['state_version']))
        assert result.status_code==200 and result.json()['prepared_count']==1


def test_committed_http_create_lost_response_recovers_one_discoverable_job(vision_case,preparations,monkeypatch):
    service,_,request=preparations;credentials=vision_case[-1];app=app_for(service);commit=service.access._commit;fired=[False]
    def lost(writes,checks=()):
        result=commit(writes,checks)
        if not fired[0] and any(w.key.resource.startswith('qualification-preparation-catalog#') for w in writes):
            fired[0]=True;raise StoreUnavailable('synthetic committed response loss')
        return result
    monkeypatch.setattr(service.access,'_commit',lost)
    with TestClient(app,base_url=ORIGIN,cookies={COOKIE:credentials.cookie}) as client:
        assert client.post(BASE,json=request.model_dump(mode='json'),headers=headers(credentials,'uncertain-create')).status_code==503
        known=client.get(BASE).json()['preparations'];assert len(known)==1
        recovered=client.post(BASE,json=request.model_dump(mode='json'),headers=headers(credentials,'uncertain-create'))
        assert recovered.status_code==201 and recovered.json()['id']==known[0]['id'] and recovered.json()['steps_reserved']==0
        assert len(client.get(BASE).json()['preparations'])==1


def test_stopped_dispatch_and_new_driver_preserve_original_attempt_and_expiry(world,preparations,monkeypatch):
    service,actor,request=preparations;job=service.create(actor,request=request,idempotency_key='stopped-dispatch')
    unused=SimpleNamespace(access=service.access,runtime=service.runtime,repository=service.repository)
    def driver():return MaintenanceDriver(service.access,service.runtime,unused,unused,enabled=True,poll_ms=250,page_size=25,
        steps_per_minute=120,drain_ms=5000,evaluations=service.evaluations,preparations=service)
    current=driver();expiry=service._row(job['id']).data['expires_at_ms'];original=contract_registry.execute_case
    with monkeypatch.context() as boundary:
        def stop(case,spec):
            result=original(case,spec);current._stop.set();return result
        boundary.setattr(contract_registry,'execute_case',stop)
        assert current.poll_once() is False
    stopped=service._row(job['id']);assert stopped.data['steps_reserved']==1 and stopped.data['processed']==0
    assert current.stop_and_drain()
    with pytest.raises(RuntimeError):current.start()
    world[2].value+=service.config.lease_ms+1
    replacement=driver();assert replacement.poll_once() is True
    resumed=service._row(job['id']);assert resumed.data['steps_reserved']==2 and resumed.data['processed']==1 and resumed.data['expires_at_ms']==expiry
    assert replacement.stop_and_drain()
