from dataclasses import replace
from threading import Event
from types import SimpleNamespace
from uuid import uuid4
import json
import pytest
from fastapi.testclient import TestClient
from test_manifests import manifest_case,world,repository_factory,publication_case,review_case,create,finish
from test_access_lifecycle import invite_and_join,proof
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied,Role
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.job_authority import resolve
from proofpack.evidence.repository import Write,StoreConflict,StoreUnavailable
from proofpack.planner.candidates import PolicyCandidates,PolicyCatalogConfig,PolicyDraft
from proofpack.review.evaluation_models import EvaluationRequest,EvaluationConfig
from proofpack.review.evaluations import PolicyEvaluations,report_key,entry_key
from proofpack.review.manifests import Consequence
from proofpack.runtime.control import DATA,RuntimeControl
from proofpack.runtime.maintenance import MaintenanceDriver
from proofpack.stations.service import POLICY


def definition():return PolicyDraft.model_validate_json(json.dumps({'name':'Diagnostic candidate','algorithm':'reason_priority_v1','priority':['PLACE_FLAT','SEPARATE_REGION','RECAPTURE']}))


@pytest.fixture
def evaluations(world,manifest_case):
    datasets,actor,credentials,item,grant,*_=manifest_case
    manifest=finish(datasets,actor,create(manifest_case))
    policies=PolicyCandidates(datasets.access,datasets.runtime,PolicyCatalogConfig(100,120,100))
    policy=policies.write(actor,request=definition(),idempotency_key='evaluation-policy')
    request=EvaluationRequest(runner='decision_replay_v1',policy_id=policy['id'],policy_revision=1,policy_state_version=policy['state_version'],
        policy_revision_sha256=policy['revision_sha256'],manifest_id=manifest['id'],manifest_sha256=manifest['manifest_sha256'],
        historical_diagnostic_acknowledged=True,frozen_holdout_acknowledged=False)
    return PolicyEvaluations(policies,datasets,EvaluationConfig(20,120,120,3600000,15000,3000)),actor,credentials,request,grant


def submit(case,key='evaluation'):
    service,actor,_,request,*_=case
    return service.create(actor,request=request,idempotency_key=key)


def test_actual_current_source_replay_is_durable_diagnostic_and_has_no_live_effect(world,evaluations):
    service,actor,_,request,*_=evaluations;before=world[1].snapshot((DATA,POLICY));job=submit(evaluations)
    assert job['status']=='queued' and resolve(service.access,service._row(job['id']).data).member.data['id']==actor.member.data['id']
    completed=finish(service,actor,job);assert completed['status']=='completed' and completed['prepared_count']==completed['steps_reserved']==1
    summary=service.summary(actor,job['id']);assert summary['result_header_current'] and summary['promotion_eligible'] is False
    for side in ('baseline','candidate'):assert sum(summary['counts'][side][k] for k in ('observed_match','counterfactual_unknown','no_recorded_outcome','not_actionable','incorrect_finding'))==1
    page=service.examples(actor,job['id']);assert len(page['examples'])==1 and page['next_index'] is None
    assert page['examples'][0]['policy_revision_sha256']==request.policy_revision_sha256 and page['examples'][0]['operator_effort_measured'] is False
    audits=world[1].query(prefix='dataset-access#',table='events',limit=20)[0]
    assert any(r.data.get('consumer_job_id')==job['id'] and r.data['kind']=='evaluation_examples_read' for r in audits)
    assert world[1].snapshot((DATA,POLICY))==before


def test_owner_summary_does_not_grant_reviewer_processing_or_example_access(world,evaluations):
    service,actor,_,request,*_=evaluations;job=finish(service,actor,submit(evaluations))
    view=service.summary(world[5],job['id']);assert view['counts'] is not None and not view['can_advance'] and view['can_retire']
    for call in (lambda:service.examples(world[5],job['id']),lambda:service.selections(world[5],job['id']),lambda:service.create(world[5],request=request,idempotency_key='owner')):
        with pytest.raises(Denied):call()
    _,_,operator,*_=invite_and_join(world,'eval-operator',roles=(Role.OPERATOR,))
    with pytest.raises(Denied):service.summary(operator,job['id'])


@pytest.mark.parametrize('change',['permission','label','policy','manifest','expiry','runtime'])
def test_changed_input_cannot_seal_a_result(world,evaluations,change):
    service,actor,_,request,grant=evaluations;job=submit(evaluations)
    if change=='permission':service.datasets.improvement.withdraw(world[5],grant['id'],expected_version=1,idempotency_key='withdraw-eval')
    elif change=='label':
        from test_labels import request_for
        from proofpack.review.labels import head_key
        selected=service.datasets._request(service.datasets._row(request.manifest_id)).selections[0]
        row=world[1].snapshot((head_key(selected.label_id),))[head_key(selected.label_id)]
        epoch=service.purposes.head();world[1].transact((Write(row.key,row.revision,{**row.data,'latest_revision':2}),service.purposes.advance(epoch)))
    elif change=='policy':service.policies.write(actor,request=definition(),ident=request.policy_id,expected_version=1,idempotency_key='new-candidate')
    elif change=='manifest':service.datasets.retire(actor,request.manifest_id,request=Consequence(acknowledged=True,reason='retired-input'),expected_version=3,idempotency_key='retire-input')
    elif change=='expiry':world[2].value=grant['expires_at_ms']
    else:RuntimeControl(world[0],instance_id=str(uuid4()),artifact_sha256='a'*64,controls_sha256='b'*64,environment='synthetic_demo').start()
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='held')
    assert world[1].snapshot((report_key(job['id']),))[report_key(job['id'])] is None
    assert service.summary(actor,job['id'])['counts'] is None


def test_cancel_during_source_work_fences_result_and_does_not_refund_attempt(world,evaluations,monkeypatch):
    service,actor,*_=evaluations;job=submit(evaluations);original=service._case
    def prepare(*args,**kwargs):
        current=service.job(actor,job['id']);service.cancel(world[5],job['id'],expected_version=current['state_version'],idempotency_key='cancel-during-source')
        return original(*args,**kwargs)
    monkeypatch.setattr(service,'_case',prepare)
    with pytest.raises(StoreConflict):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='racing-step')
    result=service.job(actor,job['id']);assert result['status']=='cancelled' and result['steps_reserved']==1 and result['prepared_count']==0
    assert world[1].snapshot((report_key(job['id']),))[report_key(job['id'])] is None


def test_retirement_is_explicit_and_invalidates_derived_use_without_erasing_history(world,evaluations):
    service,actor,*_=evaluations;job=finish(service,actor,submit(evaluations));epoch=service.purposes.head()
    with pytest.raises(StoreConflict):service.cancel(actor,job['id'],expected_version=job['state_version'],idempotency_key='not-retirement')
    retired=service.retire(world[5],job['id'],request=Consequence(acknowledged=True,reason='retire-diagnostic'),expected_version=job['state_version'],idempotency_key='retire')
    assert retired['status']=='retired' and service.purposes.head().data['epoch']==epoch.data['epoch']+1
    assert world[1].snapshot((report_key(job['id']),))[report_key(job['id'])] is not None
    assert service.summary(world[5],job['id'])['counts'] is None
    with pytest.raises((StoreConflict,StoreUnavailable)):service.examples(actor,job['id'])


def test_unknown_step_retry_keeps_original_budget_and_expiry(evaluations):
    service,actor,*_=evaluations;job=submit(evaluations);before=service._row(job['id']).data['expires_at_ms']
    result=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='same-step')
    replay=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='same-step')
    assert replay['id']==result['id'] and replay['steps_reserved']==1 and service._row(job['id']).data['expires_at_ms']==before


@pytest.mark.parametrize('change',['expiry','data','role'])
def test_result_delivery_rechecks_after_access_audit(world,evaluations,monkeypatch,change):
    service,actor,_,_,grant=evaluations;job=finish(service,actor,submit(evaluations));original=world[1].transact;fired=False
    def commit(writes,checks=()):
        nonlocal fired
        result=original(writes,checks)
        if not fired and any(w.key.resource.startswith('dataset-access#') and w.data.get('consumer_job_id')==job['id'] for w in writes):
            fired=True
            if change=='expiry':world[2].value=grant['expires_at_ms']
            elif change=='data':original((service.purposes.advance(service.purposes.head()),))
            else:world[0].change_access(world[5],user_id=actor.member.data['id'],roles=(Role.OPERATOR,),enabled=True,expected_version=1,idempotency_key='revoke-during-delivery')
        return result
    monkeypatch.setattr(world[1],'transact',commit)
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):service.examples(actor,job['id'])
    assert fired


def test_expiry_at_final_commit_cannot_publish_report(world,evaluations,monkeypatch):
    service,actor,_,_,grant=evaluations;job=submit(evaluations);snapshot=world[1].snapshot;fresh=world[0]._fresh;ready=False;fired=False
    def read(keys):
        nonlocal ready
        result=snapshot(keys)
        if keys==(entry_key(job['id'],0),):ready=True
        return result
    def authorize(*args,**kwargs):
        nonlocal fired
        if ready and not fired:fired=True;world[2].value=grant['expires_at_ms']
        return fresh(*args,**kwargs)
    monkeypatch.setattr(world[1],'snapshot',read);monkeypatch.setattr(world[0],'_fresh',authorize)
    with pytest.raises((StoreConflict,StoreUnavailable)):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='late')
    assert fired and snapshot((report_key(job['id']),))[report_key(job['id'])] is None


def test_shared_driver_uses_real_signed_reviewer_authority(world,evaluations,monkeypatch):
    service,actor,*_=evaluations;job=submit(evaluations);done=Event();original=service.advance
    def advance(*args,**kwargs):
        result=original(*args,**kwargs);done.set();return result
    monkeypatch.setattr(service,'advance',advance);fake=SimpleNamespace(access=service.access,runtime=service.runtime,repository=service.repository)
    driver=MaintenanceDriver(service.access,service.runtime,fake,fake,evaluations=service,enabled=True,poll_ms=250,page_size=5,steps_per_minute=60,drain_ms=1000)
    try:driver.start();assert done.wait(8)
    finally:assert driver.stop_and_drain()
    assert service.summary(actor,job['id'])['result_header_current']


def test_http_scoped_create_results_and_generic_job_routes(world,evaluations):
    service,actor,credentials,request,*_=evaluations
    app=create_app(access_service=world[0],app_origin='https://proofpack.test')
    app.state.evaluation_service=service
    headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'eval-http'}
    with TestClient(app,base_url='https://proofpack.test',cookies={COOKIE:credentials.cookie}) as client:
        created=client.post('/api/v1/evaluations',json=request.model_dump(mode='json'),headers=headers);assert created.status_code==201
        job=created.json();ident=job['id']
        response=client.post('/api/v1/jobs/'+ident+'/advance',json={},headers={**headers,'Idempotency-Key':'http-step','If-Match':str(job['state_version'])});assert response.status_code==200 and response.json()['status']=='completed'
        assert client.get('/api/v1/evaluations/'+ident).json()['result_header_current'] is True
        assert client.get('/api/v1/evaluations/'+ident+'/examples').status_code==200
        assert client.post('/api/v1/evaluations',json={**request.model_dump(mode='json'),'approved':True},headers=headers).status_code==400
        assert client.post('/api/v1/evaluations',json={'padding':'x'*9000},headers=headers).status_code==413
        assert client.post('/api/v1/evaluations',json=request.model_dump(mode='json'),headers={**headers,'Origin':'https://foreign.test'}).status_code==403


def test_source_failure_cannot_write_after_final_lease_deadline(world,evaluations,monkeypatch):
    service,actor,*_=evaluations;job=submit(evaluations);failed=False;authorized=False;fired=False
    original=service.access._fresh
    def source(*args,**kwargs):
        nonlocal failed
        failed=True;raise StoreUnavailable('injected missing source')
    def fresh(*args,**kwargs):
        nonlocal authorized
        value=original(*args,**kwargs)
        if failed:authorized=True
        return value
    def gate():
        nonlocal fired
        if failed and authorized and not fired:
            fired=True;world[2].value=int(service._row(job['id']).data['lease_until_ms'])
    monkeypatch.setattr(service,'_case',source);monkeypatch.setattr(service.access,'_fresh',fresh)
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):
        service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='expired-failure',execution_gate=gate)
    current=service._row(job['id'])
    assert fired and current.data['status']=='processing' and current.data['steps_reserved']==1
    assert current.data['failure_reason'] is None and current.data['processed']==0
    assert world[1].snapshot((report_key(job['id']),))[report_key(job['id'])] is None


def test_source_expiry_during_reservation_cannot_admit_a_step(world,evaluations,monkeypatch):
    service,actor,*_=evaluations;job=submit(evaluations);original=service.access._record;armed=False;fired=False
    def record(*args,**kwargs):
        nonlocal armed
        if args[1]=='evaluation-step:'+job['id']:armed=True
        return original(*args,**kwargs)
    def gate():
        nonlocal fired
        if armed and not fired:
            fired=True;world[2].value=int(service._row(job['id']).data['effective_deadline_ms'])
    monkeypatch.setattr(service.access,'_record',record)
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):
        service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='expired-admission',execution_gate=gate)
    current=service._row(job['id'])
    assert fired and current.data['status']=='queued' and current.data['steps_reserved']==0


@pytest.mark.parametrize('change',['expiry','data','origin_role'])
def test_owner_summary_rechecks_original_authority_after_audit(world,evaluations,monkeypatch,change):
    service,actor,*_=evaluations;job=finish(service,actor,submit(evaluations));original=world[1].transact;fired=False
    def commit(writes,checks=()):
        nonlocal fired
        result=original(writes,checks)
        if not fired and any(w.key.resource.startswith('evaluation-access#') and w.data.get('kind')=='evaluation_summary' for w in writes):
            fired=True
            if change=='expiry':world[2].value=int(service._row(job['id']).data['effective_deadline_ms'])
            elif change=='data':original((service.purposes.advance(service.purposes.head()),))
            else:world[0].change_access(world[5],user_id=actor.member.data['id'],roles=(Role.OPERATOR,),enabled=True,expected_version=1,idempotency_key='revoke-summary-origin')
        return result
    monkeypatch.setattr(world[1],'transact',commit)
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):service.summary(world[5],job['id'])
    assert fired


@pytest.mark.parametrize('change',['request','count','requestor','signature'])
def test_private_processing_reference_rejects_changed_immutable_scope(evaluations,change):
    service,actor,*_=evaluations;job=submit(evaluations);value=json.loads(canonical(service._row(job['id']).data))
    if change=='request':
        import hashlib
        request=json.loads(value['request_json']);request['policy_revision']=2
        value['request_json']=canonical(request);value['request_sha256']=hashlib.sha256(value['request_json'].encode()).hexdigest()
    elif change=='count':value['example_count']+=1
    elif change=='requestor':value['requested_by']=str(uuid4())
    else:value['processing_authority']['signature']='0'*64
    with pytest.raises(Denied):resolve(service.access,value)


def test_source_failure_retains_attempt_and_idempotent_cancel_path(evaluations,monkeypatch):
    service,actor,*_=evaluations;job=submit(evaluations)
    def missing(*args,**kwargs):raise StoreUnavailable('injected source withdrawal')
    monkeypatch.setattr(service,'_case',missing)
    failed=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='failed-source')
    assert failed['status']=='failed' and failed['failure_reason']=='SOURCE_OR_PERMISSION_HELD'
    assert failed['steps_reserved']==1 and failed['prepared_count']==0 and failed['can_cancel']
    retry=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='failed-source')
    assert retry['steps_reserved']==1 and service.summary(actor,job['id'])['counts'] is None
    cancelled=service.cancel(actor,job['id'],expected_version=failed['state_version'],idempotency_key='cancel-failed')
    assert cancelled['status']=='cancelled' and cancelled['steps_reserved']==1


def test_full_thousand_evaluation_steps_and_every_result_page(world,evaluations,monkeypatch):
    """Injected metadata isolates 1000-step durable protocol, not physical/source assurance."""
    from copy import deepcopy
    service,actor,_,request,*_=evaluations
    _,checks,policy,manifest,sealed=service._inputs(actor,request)
    sample,_,_=service._case(actor,request,policy,manifest,sealed,0,lambda:None)
    deadline=world[2]()+3600000
    injected=replace(sealed,data={**sealed.data,'example_count':1000,'expires_at_ms':deadline})
    monkeypatch.setattr(service,'_inputs',lambda current,selected:(service.access._fresh(current,Role.REVIEWER),checks,policy,manifest,injected))
    calls=[]
    def case(current,selected,candidate,source,header,index,gate):
        gate();calls.append(index);value=deepcopy(sample);value['capacity_fixture_index']=index
        return value,(),deadline
    monkeypatch.setattr(service,'_case',case)
    job=submit(evaluations,'thousand-evaluation')
    for index in range(1000):
        if index and index%100==0:world[2].value+=60000
        job=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='bulk-eval-'+str(index))
    assert calls==list(range(1000)) and job['status']=='completed' and job['prepared_count']==job['steps_reserved']==1000
    summary=service.summary(actor,job['id'])
    for side in ('baseline','candidate'):
        assert sum(summary['counts'][side][key] for key in ('observed_match','counterfactual_unknown','no_recorded_outcome','not_actionable','incorrect_finding'))==1000
    total=0;start=0
    while start is not None:
        page=service.examples(actor,job['id'],start=start)
        assert [item['index'] for item in page['examples']]==list(range(total,total+len(page['examples'])))
        total+=len(page['examples']);start=page['next_index']
    assert total==1000 and service.examples(actor,job['id'],start=999)['examples'][0]['index']==999


def test_abandoned_lease_consumes_original_budget_without_refund(world,evaluations,monkeypatch):
    original,actor,credentials,request,grant=evaluations
    service=PolicyEvaluations(original.policies,original.datasets,replace(original.config,max_steps=1));job=service.create(actor,request=request,idempotency_key='one-attempt')
    lease=service._lease
    def interrupted(*args,**kwargs):raise StoreUnavailable('injected interruption after reservation')
    monkeypatch.setattr(service,'_lease',interrupted)
    with pytest.raises(StoreUnavailable):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='abandoned')
    monkeypatch.setattr(service,'_lease',lease)
    pending=service._row(job['id']);deadline=int(pending.data['expires_at_ms']);world[2].value=int(pending.data['lease_until_ms'])
    failed=service.advance(actor,job['id'],expected_version=pending.revision,idempotency_key='exhausted')
    assert failed['status']=='failed' and failed['failure_reason']=='STEP_BUDGET_EXHAUSTED' and failed['steps_reserved']==1
    assert failed['prepared_count']==0 and service._row(job['id']).data['expires_at_ms']==deadline


def test_frozen_dataset_needs_distinct_diagnostic_acknowledgment(world,manifest_case):
    from proofpack.review.datasets import Split
    datasets,actor,*_=manifest_case;manifest=finish(datasets,actor,create(manifest_case,split=Split.FROZEN_TEST))
    policies=PolicyCandidates(datasets.access,datasets.runtime,PolicyCatalogConfig(100,120,100));policy=policies.write(actor,request=definition(),idempotency_key='frozen-policy')
    service=PolicyEvaluations(policies,datasets,EvaluationConfig(20,120,120,60000,15000,3000))
    request=EvaluationRequest(runner='decision_replay_v1',policy_id=policy['id'],policy_revision=1,policy_state_version=policy['state_version'],
        policy_revision_sha256=policy['revision_sha256'],manifest_id=manifest['id'],manifest_sha256=manifest['manifest_sha256'],
        historical_diagnostic_acknowledged=True,frozen_holdout_acknowledged=False)
    with pytest.raises(Denied):service.create(actor,request=request,idempotency_key='not-acknowledged')
    job=service.create(actor,request=request.model_copy(update={'frozen_holdout_acknowledged':True}),idempotency_key='frozen-diagnostic')
    assert job['status']=='queued' and job['independent_benchmark_qualified'] is False and job['promotion_eligible'] is False


@pytest.mark.parametrize('target',['header','entry','policy'])
def test_corrupt_immutable_dependencies_are_withheld(world,evaluations,target):
    service,actor,*_=evaluations;job=finish(service,actor,submit(evaluations))
    key=report_key(job['id']) if target=='header' else entry_key(job['id'],0) if target=='entry' else service.policies._load(job['policy_id'],1)[1].key
    row=world[1].snapshot((key,))[key];world[1].transact((Write(key,row.revision,{**row.data,'tampered':True}),))
    if target=='entry':
        with pytest.raises(StoreUnavailable):service.examples(actor,job['id'])
    else:assert service.summary(actor,job['id'])['counts'] is None
