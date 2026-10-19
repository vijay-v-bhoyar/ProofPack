"""Real local persistence/CV sources, synthetic identity and intercepted S3 only."""
from dataclasses import replace
from uuid import uuid4
import json
import pytest

from test_vision_replay import vision_case,world,repository_factory,publication_case,original_case
from test_manifests import finish
from test_access_lifecycle import invite_and_join
from proofpack.auth.policy import Denied,Role
from proofpack.evidence.repository import Write,StoreConflict,StoreUnavailable
from proofpack.evidence.job_authority import resolve
from proofpack.planner import contract_registry
from proofpack.planner.contract_suite import ContractSuiteConfig
from proofpack.review.evaluation_models import EvaluationConfig,EvaluationLimited
from proofpack.review.manifests import Consequence
from proofpack.review.qualification_preparation import QualificationPreparations,PreparationRequest,entry_key
from proofpack.stations.service import POLICY
from proofpack.runtime.control import DATA


@pytest.fixture
def preparations(world,vision_case):
    engine,actor,request,*_=vision_case;evaluations=engine.evaluations
    source=finish(evaluations,actor,evaluations.create(actor,request=request,idempotency_key='preparation-source'))
    config=EvaluationConfig(20,120,120,3600000,15000,340)
    service=QualificationPreparations(evaluations,config,ContractSuiteConfig(256,15000,8192,1048576))
    body=PreparationRequest(policy_id=request.policy_id,source_evaluation_id=source['id'],source_evaluation_state_version=source['state_version'],
        source_report_sha256=source['report_sha256'],preparation_only_acknowledged=True)
    return service,actor,body


def create(case,key='preparation'):
    service,actor,body=case
    return service.create(actor,request=body,idempotency_key=key)


def test_complete_all_cases_and_source_entry_restart_readback_chain_and_exit(world,preparations,monkeypatch):
    service,actor,body=preparations;before=world[1].snapshot((DATA,POLICY));job=create(preparations)
    assert job['planned_count']==171 and job['prepared_count']==job['steps_reserved']==0
    expiry=service._row(job['id']).data['expires_at_ms'];assert resolve(service.access,service._row(job['id']).data).member.data['id']==actor.member.data['id']
    for index in range(171):
        if index==50:service=QualificationPreparations(service.evaluations,service.config,service.suite_config)
        # Exercise real quota windows without extending the original source expiry.
        if index==100:world[2].value=(world[2]()//60000+1)*60000
        job=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='step-'+str(index))
    assert job['status']=='completed' and job['report_current'] and job['prepared_count']==job['steps_reserved']==171
    assert job['counts']=={'software_pass':170,'software_fail':0,'source_entries_verified':1}
    assert job['qualification_status']=='not_qualified' and job['promotion_eligible'] is False
    assert 'INDEPENDENT_QUALIFICATION_EVIDENCE_REQUIRED' in job['blocking_reasons']
    assert service._row(job['id']).data['expires_at_ms']==expiry and world[1].snapshot((DATA,POLICY))==before
    entries=[];start=0
    while start is not None:
        page=service.entries(actor,job['id'],start=start,limit=20);entries.extend(page['entries']);start=page['next_index']
    assert len(entries)==171 and entries[-1]['phase']=='source_evaluation_integrity' and entries[-1]['new_pixel_measurement'] is False
    owner=service.job(world[5],job['id']);assert owner['counts']==job['counts'] and not owner['can_advance']
    with pytest.raises(Denied):service.entries(world[5],job['id'])
    with pytest.raises(Denied):service.advance(world[5],job['id'],expected_version=job['state_version'],idempotency_key='owner')
    row=world[1].snapshot((entry_key(job['id'],0),))[entry_key(job['id'],0)]
    world[1].transact((Write(row.key,row.revision,{**row.data,'content_json':'{}'}),))
    with pytest.raises(StoreUnavailable):service.entries(actor,job['id'])
    original_commit=service.access._commit;expired=[False]
    def expire_after_read_audit(writes,checks=()):
        value=original_commit(writes,checks)
        if not expired[0] and any(w.key.resource.startswith('qualification-preparation-access#') for w in writes):
            expired[0]=True;world[2].value=int(expiry)
        return value
    monkeypatch.setattr(service.access,'_commit',expire_after_read_audit)
    with pytest.raises(StoreUnavailable):service.job(world[5],job['id'])
    retired=service.retire(world[5],job['id'],request=Consequence(reason='synthetic-preparation-retired',acknowledged=True),expected_version=job['state_version'],idempotency_key='retire')
    assert retired['status']=='retired' and not retired['report_current'] and world[1].snapshot((POLICY,))[POLICY]==before[POLICY]


def test_exact_intent_recovery_and_admission_denials(world,preparations):
    service,actor,body=preparations;first=create(preparations)
    assert create(preparations)['id']==first['id']
    with pytest.raises(StoreConflict):service.create(actor,request=body.model_copy(update={'source_report_sha256':'f'*64}),idempotency_key='preparation')
    with pytest.raises(StoreConflict):service.create(actor,request=body.model_copy(update={'source_report_sha256':'f'*64}),idempotency_key='wrong-source')
    with pytest.raises(Denied):service.create(world[5],request=body,idempotency_key='owner')
    _,_,other,*_=invite_and_join(world,'other-preparer',roles=(Role.REVIEWER,))
    with pytest.raises(Denied):service.create(other,request=body,idempotency_key='other')
    with pytest.raises(Denied):service.job(other,first['id'])
    small=QualificationPreparations(service.evaluations,replace(service.config,max_steps=170),service.suite_config)
    with pytest.raises(EvaluationLimited):small.create(actor,request=body,idempotency_key='short-original-budget')


def test_mid_step_cancel_consumes_attempt_and_no_case_or_report_is_published(world,preparations):
    service,actor,_=preparations;job=create(preparations);changed=[False]
    def cancel():
        current=service._row(job['id'])
        if current.data['status']=='processing' and not changed[0]:
            changed[0]=True;service.cancel(world[5],job['id'],expected_version=current.revision,idempotency_key='owner-stop')
    with pytest.raises(StoreConflict):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='interrupted-step',execution_gate=cancel)
    stopped=service.job(actor,job['id']);assert stopped['status']=='cancelled' and stopped['steps_reserved']==1 and stopped['prepared_count']==0 and not stopped['report_current']
    assert service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='interrupted-step')['status']=='cancelled'
    assert world[1].snapshot((entry_key(job['id'],0),))[entry_key(job['id'],0)] is None


def test_expiry_after_case_rejects_final_commit_without_refund(world,preparations,monkeypatch):
    service,actor,_=preparations;job=create(preparations);original=contract_registry.execute_case
    def expired(case,spec):
        result=original(case,spec);world[2].value=int(service._row(job['id']).data['expires_at_ms']);return result
    monkeypatch.setattr(contract_registry,'execute_case',expired)
    with pytest.raises(StoreUnavailable):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='expired-final')
    current=service._row(job['id']);assert current.data['steps_reserved']==1 and current.data['processed']==0
    assert world[1].snapshot((entry_key(job['id'],0),))[entry_key(job['id'],0)] is None


def test_candidate_change_holds_original_preparation_before_reservation(world,preparations):
    service,actor,body=preparations;job=create(preparations);policies=service.evaluations.policies
    existing=policies.get(actor,body.policy_id)
    from proofpack.planner.candidates import PolicyDraft
    policies.write(actor,request=PolicyDraft.model_validate_json(json.dumps({**existing['spec'],'name':'Changed after preparation'})),ident=body.policy_id,
        expected_version=existing['state_version'],idempotency_key='change-before-step')
    with pytest.raises(StoreConflict):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='held-step')
    assert service._row(job['id']).data['steps_reserved']==0 and not service.job(actor,job['id'])['source_current']


def test_software_failure_is_retained_in_durable_prefix(preparations,monkeypatch):
    service,actor,_=preparations;job=create(preparations)
    monkeypatch.setattr(contract_registry,'execute_case',lambda *args:'UNSAFE_ACTION')
    current=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='retained-failure')
    row=service._row(job['id']);assert row.data['counts']['software_fail']==1 and row.data['processed']==1
    assert not current['report_current'] and current['promotion_eligible'] is False
