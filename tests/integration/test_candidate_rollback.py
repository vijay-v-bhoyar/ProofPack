"""Full synthetic image/preparation/qualification rollback; no physical/provider proof."""
import pytest
from test_vision_replay import vision_case, world, repository_factory, publication_case, original_case
from test_policy_rollback import activate
from test_policy_qualification import finish as finish_qualification
from test_manifests import finish as finish_job
from test_policy_candidates import draft
from proofpack.auth.policy import Denied, Role
from proofpack.evidence.repository import StoreConflict, StoreUnavailable
from proofpack.planner.activation import PolicyActivations, ActivationConfig
from proofpack.planner.active import ActivePolicies
from proofpack.planner.contract_suite import ContractSuiteConfig
from proofpack.review.policy_qualification import PolicyQualifications, QualificationConfig, QualificationRequest
from proofpack.review.qualification_preparation import QualificationPreparations, PreparationRequest
from proofpack.review.evaluation_models import EvaluationConfig
from proofpack.stations.service import POLICY


@pytest.mark.parametrize('publication_case',['synthetic_demo'],indirect=True)
@pytest.mark.parametrize('vision_case',['qualification_compatible'],indirect=True)
def test_candidate_rollback_revalidates_actual_image_preparation_and_consumed_source_chain(world,vision_case):
    engine,actor,image,*_=vision_case
    evaluations=engine.evaluations;policies=evaluations.policies
    suite=ContractSuiteConfig(256,15000,8192,1048576)
    preparations=QualificationPreparations(evaluations,EvaluationConfig(20,120,120,3600000,15000,340),suite)
    writer=PolicyQualifications(policies,engine.registry,
        QualificationConfig(EvaluationConfig(20,120,120,3600000,15000,1200),2400,15000),suite,preparations)
    activation=PolicyActivations(policies,ActivationConfig(20,120,60000,80,writer.registry_sha),writer)
    first=policies.get(actor,image.policy_id)
    ordinary=QualificationRequest(mode='installed_default',policy_id=first['id'],policy_revision=first['revision'],
        policy_state_version=first['state_version'],policy_revision_sha256=first['revision_sha256'],synthetic_demo_acknowledged=True)
    # Remove only the legacy TEST-INJECTED policy seed required for upstream image capture,
    # as in test_active_policy. All following activations use genuinely executed reports.
    repo=world[1];repo.client.delete_item(TableName=repo.tables[POLICY.table],Key=repo.key(POLICY))
    a=activate(world,activation,first,finish_qualification((writer,actor,ordinary),'image-first'),'bootstrap','image-bootstrap')
    second=policies.write(actor,request=draft('Second image default'),ident=first['id'],
        expected_version=first['state_version'],idempotency_key='image-revision')
    second_request=ordinary.model_copy(update={'policy_revision':second['revision'],
        'policy_state_version':second['state_version'],'policy_revision_sha256':second['revision_sha256']})
    b=activate(world,activation,second,finish_qualification((writer,actor,second_request),'image-second'),'promote','image-promote')
    target={'active_version':b['active_version'],'activation_id':b['transition_id'],'predecessor_activation_id':a['transition_id']}
    image_request=type(image).model_validate({**image.model_dump(),'policy_state_version':second['state_version'],'rollback_target':target})
    evaluated=finish_job(evaluations,actor,evaluations.create(actor,request=image_request,idempotency_key='rollback-image'))
    body=PreparationRequest(policy_id=first['id'],source_evaluation_id=evaluated['id'],
        source_evaluation_state_version=evaluated['state_version'],source_report_sha256=evaluated['report_sha256'],
        preparation_only_acknowledged=True)
    prepared=preparations.create(actor,request=body,idempotency_key='rollback-preparation')
    for index in range(prepared['planned_count']):
        if index==100:world[2].value=(world[2]()//60000+1)*60000
        prepared=preparations.advance(actor,prepared['id'],expected_version=prepared['state_version'],idempotency_key='prepare-'+str(index))
    request=QualificationRequest(mode='candidate',policy_id=first['id'],policy_revision=first['revision'],
        policy_state_version=second['state_version'],policy_revision_sha256=first['revision_sha256'],
        preparation_id=prepared['id'],preparation_state_version=prepared['state_version'],
        preparation_report_sha256=prepared['report_sha256'],synthetic_demo_acknowledged=True,rollback_target=target)
    job=finish_qualification((writer,actor,request),'image-rollback-qualification')
    assert job['qualification_status']=='qualified' and job['required_cases']==183
    assert writer.read_current(job['id']).qualification.data['rollback_target']==target
    rolled=activate(world,activation,{**first,'state_version':second['state_version']},job,'rollback','image-rollback',a['transition_id'])
    current=ActivePolicies(activation).read_current()
    assert current.policy.data['activation_id']==rolled['transition_id'] and current.policy.data['policy_revision']==first['revision']
    # Consumption is internal source revalidation, not a fresh promotion report.
    with pytest.raises(StoreConflict):writer.read_current(job['id'])
    world[0].change_access(world[5],user_id=actor.member.data['id'],roles=(Role.REVIEWER,),enabled=False,
        expected_version=int(actor.member.data['access_version']),idempotency_key='revoke-rollback-reviewer')
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):ActivePolicies(activation).read_current()
