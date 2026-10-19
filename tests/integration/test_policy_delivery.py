"""Qualification delivery under current source/configuration; no physical truth."""
from dataclasses import replace
import pytest
from test_policy_qualification import qualification,policies,world,repository_factory
from proofpack.evidence.repository import StoreConflict,StoreUnavailable


def test_qualification_job_cannot_report_current_after_last_authorization_changes_configuration(qualification,monkeypatch):
    service,actor,request,_=qualification
    job=service.create(actor,request=request,idempotency_key='delivery-boundary')
    original_commit=service.access._commit;original_fresh=service.access._fresh;armed=[False];changed=[False]
    def commit(*args,**kwargs):
        result=original_commit(*args,**kwargs);armed[0]=True;return result
    def fresh(*args,**kwargs):
        result=original_fresh(*args,**kwargs)
        if armed[0] and not changed[0]:
            changed[0]=True;service.config=replace(service.config,max_reserved_cases=service.config.max_reserved_cases+1)
        return result
    monkeypatch.setattr(service.access,'_commit',commit);monkeypatch.setattr(service.access,'_fresh',fresh)
    with pytest.raises((StoreConflict,StoreUnavailable)):service.job(actor,job['id'])
    assert changed[0]


from fastapi.testclient import TestClient
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Role
from proofpack.auth.service import RUNTIME
from proofpack.planner.activation import PolicyActivations,ActivationConfig
from proofpack.planner.active import ActivePolicies
from test_policy_candidates import invite_and_join

ORIGIN='https://proofpack.test'
BASE='/api/v1/policy-qualifications'


def installed_app(service):
    activation=PolicyActivations(service.policies,ActivationConfig(20,120,60000,80,service.registry_sha),service)
    active=ActivePolicies(activation)
    return create_app(access_service=service.access,app_origin=ORIGIN,runtime_control=service.runtime,policy_service=service.policies,
        policy_qualification_service=service,policy_activation_service=activation,active_policy_reader=active,manage_service_lifecycle=False)


def headers(credentials,key,version=None):
    result={'Origin':ORIGIN,'X-CSRF-Token':credentials.csrf,'Idempotency-Key':key}
    if version is not None:result['If-Match']=str(version)
    return result


def test_qualification_http_genuine_reports_owner_bootstrap_exact_retry_current_and_revocation(world,policies,qualification):
    service,actor,request,candidate=qualification;credentials=policies[-1];app=installed_app(service)
    with TestClient(app,base_url=ORIGIN,cookies={COOKIE:credentials.cookie}) as client:
        options=client.get(BASE+'/options');assert options.status_code==200 and options.json()['software_cases']==170
        response=client.post(BASE,json=request.model_dump(mode='json'),headers=headers(credentials,'http-qualify'));assert response.status_code==201,response.text
        job=response.json();ident=job['id'];assert not job['physical_truth_verified'] and not job['beta_eligible']
        assert client.get(BASE).json()['qualifications'][0]['id']==ident
        assert client.get(BASE).json()['qualifications'][0]['current'] is None
        assert client.get(BASE+'/'+ident+'/request').json()==request.model_dump(mode='json')
        while job['status']=='queued':
            response=client.post('/api/v1/jobs/'+ident+'/advance',json={},headers=headers(credentials,'http-step-'+str(job['state_version']),job['state_version']))
            assert response.status_code==200,response.text;job=response.json()
        assert job['status']=='completed' and job['qualification_status']=='qualified' and job['required_cases']==182
        entries=client.get(BASE+'/'+ident+'/entries').json();assert len(entries['entries'])==13
        software=[];start=0
        while start is not None:
            page=client.get(BASE+'/'+ident+'/software-cases',params={'start':start});assert page.status_code==200,page.text
            software.extend(page.json()['cases']);start=page.json()['next_index']
        assert len(software)==170 and all(c['status']=='PASS' for c in software)
        owner=world[4];runtime=world[1].snapshot((RUNTIME,))[RUNTIME]
        body={'operation':'bootstrap','policy_id':candidate['id'],'policy_revision':candidate['revision'],'policy_state_version':candidate['state_version'],
            'policy_revision_sha256':candidate['revision_sha256'],'qualification_id':ident,'qualification_report_sha256':job['report_sha256'],
            'expected_active_version':0,'expected_control_version':int(runtime.data['control_version']),'invalidation_acknowledged':True}
        path='/api/v1/policies/'+candidate['id']+'/bootstrap'
        assert client.post(path,json=body,headers=headers(credentials,'reviewer-cannot-activate',candidate['state_version'])).status_code==403
        client.cookies.set(COOKIE,owner.cookie)
        assert client.get('/api/v1/policies/active',params={'scope':'owner'}).json()['active_version']==0
        assert client.post(path,json=body,headers=headers(owner,'mismatched-header',candidate['state_version']+1)).status_code==400
        response=client.post(path,json=body,headers=headers(owner,'explicit-bootstrap',candidate['state_version']));assert response.status_code==200,response.text
        receipt=response.json();assert receipt['historical_receipt'] and not receipt['inspection_enablement_granted']
        assert client.post(path,json=body,headers=headers(owner,'explicit-bootstrap',candidate['state_version'])).json()==receipt
        current=client.get('/api/v1/policies/active',params={'scope':'owner'});assert current.status_code==200,current.text
        assert current.json()['current'] and current.json()['current_qualification_verified'] and not current.json()['inspection_enabled']
        assert client.get('/api/v1/policy-activations/'+receipt['transition_id']).json()['historical_receipt']
        assert client.get(BASE+'/'+ident+'/software-cases').status_code==403
        assert client.get(BASE,params={'scope':'owner'}).json()['qualifications'][0]['id']==ident
        assert client.get(BASE+'/'+ident+'/request').status_code==403
        response=client.post(BASE+'/'+ident+'/retire',json={'acknowledged':True,'reason':'http-test-finished'},headers=headers(owner,'retire-used-source',job['state_version']))
        assert response.status_code==200,response.text
        held=client.get('/api/v1/policies/active',params={'scope':'owner'});assert held.status_code==200,held.text
        assert not held.json()['current'] and held.json()['remaining_ms']==0


def test_qualification_http_strict_inputs_roles_catalog_retry_and_cancel(world,policies,qualification):
    service,actor,request,_=qualification;credentials=policies[-1];app=installed_app(service)
    with TestClient(app,base_url=ORIGIN,cookies={COOKIE:credentials.cookie}) as client:
        body=request.model_dump(mode='json')
        for extra in ['qualified','physical_truth_verified','independent_benchmark_qualified','current_policy']:
            assert client.post(BASE,json={**body,extra:True},headers=headers(credentials,'forged-'+extra)).status_code==400
        assert client.post(BASE,json={'padding':'x'*9000},headers=headers(credentials,'large')).status_code==413
        assert client.post(BASE,json=body,headers={**headers(credentials,'wrong-origin'),'Origin':'https://foreign.test'}).status_code==403
        assert client.post(BASE,json=body,headers={**headers(credentials,'wrong-csrf'),'X-CSRF-Token':'wrong'}).status_code==403
        assert client.get(BASE,params={'scope':'all'}).status_code==400
        assert client.get(BASE,params={'limit':21}).status_code==400
        assert client.get(BASE,params={'cursor':'not-a-uuid'}).status_code==400
        assert client.get(BASE,params={'scope':'owner'}).status_code==403
        job=client.post(BASE,json=body,headers=headers(credentials,'one-job')).json();ident=job['id']
        assert client.post(BASE,json=body,headers=headers(credentials,'one-job')).json()['id']==ident
        assert client.post(BASE,json={**body,'policy_revision_sha256':'a'*64},headers=headers(credentials,'one-job')).status_code==409
        assert client.post('/api/v1/jobs/'+ident+'/cancel',json={},headers=headers(credentials,'cancel',job['state_version'])).json()['status']=='cancelled'
        _,operator_credentials,*_=invite_and_join(world,'policy-http-operator',roles=(Role.OPERATOR,))
        client.cookies.set(COOKIE,operator_credentials.cookie)
        assert client.get(BASE).status_code==403
        assert client.get(BASE+'/'+ident).status_code==403
        assert client.get('/api/v1/policies/active',params={'scope':'owner'}).status_code==403
        summary=client.get('/api/v1/policies/active');assert summary.status_code==200,summary.text
        assert 'control_version' not in summary.json() and summary.json()['policy'] is None


@pytest.mark.parametrize('surface',['options','catalog','request','entries','software_cases'])
def test_qualification_metadata_and_details_fence_final_configuration(qualification,monkeypatch,surface):
    from test_policy_qualification import finish
    service,actor,request,_=qualification
    job=finish(qualification,'detail-fence') if surface in {'entries','software_cases'} else service.create(actor,request=request,idempotency_key='metadata-fence')
    original_commit=service.access._commit;original_fresh=service.access._fresh;original_sealed=service._sealed;armed=[False];changed=[False];committed=[False]
    def commit(*args,**kwargs):
        result=original_commit(*args,**kwargs);committed[0]=True
        if surface not in {'entries','software_cases'}:armed[0]=True
        return result
    def fresh(*args,**kwargs):
        result=original_fresh(*args,**kwargs)
        if armed[0] and not changed[0]:
            changed[0]=True;service.config=replace(service.config,max_reserved_cases=service.config.max_reserved_cases+1)
        return result
    def sealed(*args,**kwargs):
        result=original_sealed(*args,**kwargs)
        if committed[0]:armed[0]=True
        return result
    monkeypatch.setattr(service.access,'_commit',commit);monkeypatch.setattr(service.access,'_fresh',fresh);monkeypatch.setattr(service,'_sealed',sealed)
    call={'options':lambda:service.options(actor),'catalog':lambda:service.list(actor),
        'request':lambda:service.selections(actor,job['id']),'entries':lambda:service.entries(actor,job['id']),
        'software_cases':lambda:service.software_cases(actor,job['id'])}[surface]
    with pytest.raises((StoreConflict,StoreUnavailable)):call()
    assert changed[0]


def test_active_summary_fences_last_authorization_configuration_change(world,qualification,monkeypatch):
    service,*_=qualification;app=installed_app(service);activation=app.state.policy_activation_service
    original_commit=service.access._commit;original_fresh=service.access._fresh;armed=[False];changed=[False]
    def commit(*args,**kwargs):
        result=original_commit(*args,**kwargs);armed[0]=True;return result
    def fresh(*args,**kwargs):
        result=original_fresh(*args,**kwargs)
        if armed[0] and not changed[0]:
            changed[0]=True;activation.config=replace(activation.config,review_window_ms=59000)
        return result
    monkeypatch.setattr(service.access,'_commit',commit);monkeypatch.setattr(service.access,'_fresh',fresh)
    with pytest.raises(StoreConflict):activation.current(world[5],app.state.active_policy_reader,owner_view=True)
    assert changed[0]
