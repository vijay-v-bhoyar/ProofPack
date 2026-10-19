"""Emitted qualification from actual software/CV execution; synthetic inputs only."""
from pathlib import Path
from dataclasses import replace
import json
import pytest
import yaml
from test_policy_candidates import policies,draft,world,repository_factory
from proofpack.auth.policy import Denied
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.evidence.job_authority import resolve
from proofpack.planner.activation import PolicyActivations,ActivationConfig,ActivationRequest
from proofpack.planner import contract_registry
from proofpack.review.policy_qualification import (PolicyQualifications,QualificationConfig,QualificationRequest,entry_key,software_page_key)
from proofpack.review.evaluation_models import EvaluationConfig,EvaluationLimited
from proofpack.planner.contract_suite import ContractSuiteConfig,ContractSuiteHeld
from proofpack.review.manifests import Consequence
from proofpack.runtime.control import DATA
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker_limits import WorkerLimits
from proofpack.stations.service import POLICY
from test_qualification_preparation import preparations,vision_case,publication_case,original_case
from proofpack.review.qualification_preparation import QualificationPreparations


@pytest.fixture
def qualification(policies):
    candidates,actor,_=policies;controls=yaml.safe_load(Path('docs/controls.yaml').read_text(encoding='utf-8'))
    registry=WorkerRegistry(WorkerLimits.from_controls(controls),max_processes=1)
    service=PolicyQualifications(candidates,registry,QualificationConfig(EvaluationConfig(20,120,120,3600000,15000,100),1000,15000),ContractSuiteConfig(256,15000,8192,1048576))
    candidate=candidates.write(actor,request=draft(),idempotency_key='genuine-default')
    request=QualificationRequest(mode='installed_default',policy_id=candidate['id'],policy_revision=1,policy_state_version=candidate['state_version'],
        policy_revision_sha256=candidate['revision_sha256'],synthetic_demo_acknowledged=True)
    try:yield service,actor,request,candidate
    finally:registry.close()


def finish(case,key='qualify'):
    service,actor,request,*_=case;job=service.create(actor,request=request,idempotency_key=key)
    for index in range(job['planned_steps']):job=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key=key+'-'+str(index))
    return job


def test_genuine_software_and_twelve_pixel_cases_emit_qualification_and_bootstrap_without_injected_report(world,qualification):
    service,actor,request,candidate=qualification;before=world[1].snapshot((POLICY,RUNTIME))
    job=finish(qualification)
    assert job['qualification_status']=='qualified' and job['steps_prepared']==job['steps_reserved']==13
    assert job['required_cases']==job['cases_reserved']==182 and not job['physical_truth_verified'] and not job['beta_eligible']
    assert world[1].snapshot((POLICY,RUNTIME))==before
    q=service.read_current(job['id']);assert q.qualification.data['completed_case_count']==182 and q.qualification.data['failed_case_count']==0
    entries=service.entries(actor,job['id']);assert len(entries['entries'])==13 and sum(v.get('new_pixel_measurement',False) for v in entries['entries'])==12
    software=[]
    for start in range(0,170,20):software.extend(service.software_cases(actor,job['id'],start=start)['cases'])
    assert [c['id'] for c in software]==[c.id for c in contract_registry.installed_cases()] and all(c['status']=='PASS' for c in software)
    assert service.job(world[5],job['id'])['counts']=={'passed':182,'failed':0,'unknown':0}
    with pytest.raises(Denied):service.entries(world[5],job['id'])
    activation=PolicyActivations(service.policies,ActivationConfig(20,120,60000,80,service.registry_sha),service)
    body=ActivationRequest(operation='bootstrap',policy_id=candidate['id'],policy_revision=1,policy_state_version=candidate['state_version'],
        policy_revision_sha256=candidate['revision_sha256'],qualification_id=job['id'],qualification_report_sha256=job['report_sha256'],
        expected_active_version=0,expected_control_version=int(before[RUNTIME].data['control_version']),invalidation_acknowledged=True)
    result=activation.transition(world[5],request=body,idempotency_key='genuine-bootstrap')
    roots=world[1].snapshot((POLICY,RUNTIME));assert roots[POLICY].data['qualification_id']==job['id'] and roots[RUNTIME].data['inspection_enabled'] is False
    assert result['historical_receipt'] and result['control_version']==int(before[RUNTIME].data['control_version'])+1
    with pytest.raises(StoreConflict):service.read_current(job['id'])  # historical execution control differs after explicit activation
    current=service.job(world[5],job['id']);epoch=world[1].snapshot((DATA,))[DATA]
    retired=service.retire(world[5],job['id'],request=Consequence(acknowledged=True,reason='demo-finished'),expected_version=current['state_version'],idempotency_key='retire-genuine')
    assert retired['status']=='retired' and not retired['report_current'] and int(world[1].snapshot((DATA,))[DATA].data['epoch'])==int(epoch.data['epoch'])+1


def test_complete_rejected_run_retains_failed_contracts_and_cannot_reach_activation(qualification,monkeypatch):
    service,actor,request,_=qualification;original=contract_registry.execute_case
    def wrong(case,spec):return 'UNSAFE_MUTATION' if case.id=='eligibility-000' else original(case,spec)
    monkeypatch.setattr(contract_registry,'execute_case',wrong)
    job=finish(qualification,'reject')
    assert job['qualification_status']=='rejected' and job['report_current'] and job['required_cases']==182
    with pytest.raises(Denied):service.read_current(job['id'])


def test_original_intent_authority_and_nonrefunded_reservation_survive_stopped_step(world,qualification):
    service,actor,request,_=qualification;job=service.create(actor,request=request,idempotency_key='admit')
    assert resolve(service.access,service._row(job['id']).data).member.data['id']==actor.member.data['id']
    calls=[0]
    def stop():calls[0]+=1;return calls[0]<3
    with pytest.raises(StoreUnavailable):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='stop',execution_gate=stop)
    row=service._row(job['id']);assert row.data['steps_reserved']==1 and row.data['cases_reserved']==170 and row.data['processed']==0
    assert service.create(actor,request=request,idempotency_key='admit')['id']==job['id']
    changed=request.model_copy(update={'policy_revision_sha256':'f'*64})
    with pytest.raises(StoreConflict):service.create(actor,request=changed,idempotency_key='admit')


def test_insufficient_budgets_or_nondefault_and_owner_only_grants_deny_admission(world,qualification):
    service,actor,request,_=qualification;small=PolicyQualifications(service.policies,service.registry,
        QualificationConfig(replace(service.config.jobs,max_steps=12),181,15000),service.suite_config)
    with pytest.raises(EvaluationLimited):small.create(actor,request=request,idempotency_key='too-small')
    with pytest.raises(Denied):service.create(world[5],request=request,idempotency_key='owner-only')
    candidate=service.policies.write(actor,request=draft(priority=('RECAPTURE','PLACE_FLAT','SEPARATE_REGION')),idempotency_key='custom')
    with pytest.raises(Denied):service.create(actor,request=request.model_copy(update={'policy_id':candidate['id'],'policy_revision_sha256':candidate['revision_sha256']}),idempotency_key='custom-default')


@pytest.mark.parametrize('publication_case',['synthetic_demo'],indirect=True)
@pytest.mark.parametrize('vision_case',['qualification_compatible'],indirect=True)
def test_candidate_qualification_verifies_all_preparation_pages_and_actual_source_regression(world,preparations):
    prep,actor,request=preparations;prepared=prep.create(actor,request=request,idempotency_key='candidate-prep')
    for index in range(prepared['planned_count']):
        if index==100:world[2].value=(world[2]()//60000+1)*60000
        prepared=prep.advance(actor,prepared['id'],expected_version=prepared['state_version'],idempotency_key='prep-'+str(index))
    candidate=prep.evaluations.policies.get(actor,request.policy_id)
    service=PolicyQualifications(prep.evaluations.policies,prep.evaluations.vision.registry,
        QualificationConfig(EvaluationConfig(20,120,120,3600000,15000,1200),2400,15000),prep.suite_config,prep)
    body=QualificationRequest(mode='candidate',policy_id=candidate['id'],policy_revision=candidate['revision'],policy_state_version=candidate['state_version'],
        policy_revision_sha256=candidate['revision_sha256'],preparation_id=prepared['id'],preparation_state_version=prepared['state_version'],
        preparation_report_sha256=prepared['report_sha256'],synthetic_demo_acknowledged=True)
    job=finish((service,actor,body,candidate),'candidate-qualify')
    assert job['qualification_status']=='qualified' and job['required_cases']==job['cases_reserved']==183
    assert job['planned_steps']==job['steps_prepared']==22
    report=service.read_current(job['id']);assert report.qualification.data['preparation_basis']=='current_reviewer_preparation'
    assert report.qualification.data['failed_case_count']==report.qualification.data['unknown_case_count']==0


def test_retirement_requires_true_consequence_acknowledgment(world,qualification):
    service,actor,*_=qualification;job=finish(qualification,'retirement-ack');before=world[1].snapshot((DATA,POLICY))
    with pytest.raises(Denied):service.retire(actor,job['id'],request=Consequence(acknowledged=False,reason='not-agreed'),expected_version=job['state_version'],idempotency_key='not-agreed')
    assert world[1].snapshot((DATA,POLICY))==before and service._row(job['id']).data['status']=='completed'


def test_cancellation_during_software_phase_retains_reserved_cases_and_no_qualification(qualification):
    service,actor,request,*_=qualification;job=service.create(actor,request=request,idempotency_key='cancellable');calls=[0]
    def cancel():
        calls[0]+=1
        if calls[0]==4:
            quota=Key('state','policy-qualification-step-quota#'+actor.scope);rate=service.repository.snapshot((quota,))[quota]
            service.repository.transact((Write(quota,rate.revision,{**rate.data,'count':service.config.jobs.step_attempts_per_minute}),))
            current=service._row(job['id']);service.cancel(actor,job['id'],expected_version=current.revision,idempotency_key='cancel-in-flight')
            return False
        return True
    with pytest.raises((StoreUnavailable,StoreConflict,ContractSuiteHeld)):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='step-cancelled',execution_gate=cancel)
    current=service.job(actor,job['id']);assert current['status']=='cancelled' and current['cases_reserved']==170 and current['steps_reserved']==1
    assert not current['report_current'] and current['counts'] is None
    end=Key('state','policy-qualification-end-quota#'+actor.scope);assert service.repository.snapshot((end,))[end].data['count']==1
