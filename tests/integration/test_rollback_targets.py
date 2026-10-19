"""Real transaction checks using TEST-INJECTED activation assurance, not genuine qualification."""
from uuid import uuid4
import pytest
from test_policy_activation import activation, policies, world, repository_factory, new
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import StoreConflict,StoreUnavailable,Write
from proofpack.planner.activation import activation_key
from proofpack.planner.rollback import rollback_checks
from proofpack.review.policy_qualification import QualificationRequest
from proofpack.stations.service import POLICY


@pytest.fixture
def target_case(world,activation):
    service,_,issue,candidates,actor=activation
    first=new(activation)
    a=service.transition(world[5],request=issue(first),idempotency_key='a')
    second=new(activation)
    b=service.transition(world[5],request=issue(second),idempotency_key='b')
    target={'active_version':b['active_version'],'activation_id':b['transition_id'],'predecessor_activation_id':a['transition_id']}
    request=QualificationRequest(mode='installed_default',policy_id=first['id'],policy_revision=first['revision'],
        policy_state_version=first['state_version'],policy_revision_sha256=first['revision_sha256'],
        synthetic_demo_acknowledged=True,rollback_target=target)
    return candidates,request,service,first,second,issue


def test_exact_target_supplies_head_and_both_immutable_event_checks(target_case):
    candidates,request,*_=target_case
    checks=rollback_checks(candidates,request)
    assert set(checks)=={POLICY,activation_key(request.rollback_target.activation_id),activation_key(request.rollback_target.predecessor_activation_id)}


@pytest.mark.parametrize('patch',[{'active_version':3},{'activation_id':str(uuid4())},{'predecessor_activation_id':str(uuid4())}])
def test_forged_or_stale_target_is_denied(target_case,patch):
    candidates,request,*_=target_case
    target=type(request.rollback_target).model_validate({**request.rollback_target.model_dump(),**patch})
    with pytest.raises((StoreConflict,StoreUnavailable)):
        rollback_checks(candidates,request.model_copy(update={'rollback_target':target}))


@pytest.mark.parametrize('patch',[{'policy_id':str(uuid4())},{'policy_revision':2},{'policy_revision_sha256':'f'*64}])
def test_target_cannot_select_another_candidate_revision_or_digest(target_case,patch):
    candidates,request,*_=target_case
    with pytest.raises(StoreConflict):rollback_checks(candidates,request.model_copy(update=patch))


def test_another_transition_invalidates_unconsumed_target(world,target_case):
    candidates,request,service,first,second,issue=target_case
    service.transition(world[5],request=issue(second),idempotency_key='another')
    with pytest.raises(StoreConflict):rollback_checks(candidates,request)


def test_rehashed_but_incomplete_anchor_is_unavailable(world,target_case):
    candidates,request,*_=target_case
    key=activation_key(request.rollback_target.activation_id);row=world[1].snapshot((key,))[key]
    bad={k:v for k,v in row.data.items() if k not in {'predecessor_activation_id','sha256'}};bad['sha256']=digest(bad)
    world[1].transact((Write(key,row.revision,bad),))
    with pytest.raises(StoreUnavailable):rollback_checks(candidates,request)


def test_rollback_only_report_cannot_authorize_normal_promotion(world,target_case):
    candidates,request,service,first,second,issue=target_case
    body=issue(second,rollback_target=request.rollback_target.model_dump(mode='json'))
    before=world[1].snapshot((POLICY,))[POLICY]
    with pytest.raises(StoreConflict,match='rollback-only'):
        service.transition(world[5],request=body,idempotency_key='wrong-purpose')
    assert world[1].snapshot((POLICY,))[POLICY]==before


def test_normal_report_cannot_supply_rollback_authority(world,target_case):
    candidates,request,service,first,second,issue=target_case
    body=issue(first).model_copy(update={'operation':'rollback',
        'predecessor_activation_id':request.rollback_target.predecessor_activation_id})
    before=world[1].snapshot((POLICY,))[POLICY]
    with pytest.raises(StoreConflict,match='rollback-only'):
        service.transition(world[5],request=body,idempotency_key='missing-purpose')
    assert world[1].snapshot((POLICY,))[POLICY]==before
