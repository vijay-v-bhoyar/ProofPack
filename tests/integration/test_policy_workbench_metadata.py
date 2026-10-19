"""Permitted identity/purpose metadata; no source or app role escalation."""
import pytest
from test_policy_qualification import qualification, policies, world, repository_factory
from test_policy_activation import activation, new
from proofpack.auth.policy import Denied


def test_qualification_detail_binds_candidate_purpose_and_available_actions(world,qualification):
    service,actor,request,_=qualification
    job=service.create(actor,request=request,idempotency_key='metadata')
    for member in (actor,world[5]):
        detail=service.job(member,job['id'])
        for key in ('policy_id','policy_revision','policy_state_version','policy_revision_sha256','mode'):
            assert detail[key]==getattr(request,key)
        assert detail['rollback_target'] is None and detail['preparation_id'] is None
        assert detail['lease_remaining_ms']==0 and detail['can_cancel'] and not detail['can_retire']
        assert detail['can_advance'] is (member is actor)
    with pytest.raises(Denied):service.selections(world[5],job['id'])
    catalog=service.list(world[5],owner_view=True)['qualifications'][0]
    assert catalog['policy_state_version']==request.policy_state_version and catalog['rollback_target'] is None


def test_historical_activation_receipt_identifies_exact_candidate_and_qualification(world,activation):
    service,_,issue,*_=activation
    candidate=new(activation);request=issue(candidate)
    result=service.transition(world[5],request=request,idempotency_key='metadata-bootstrap')
    receipt=service.receipt(world[5],result['transition_id'])
    for key in ('policy_revision_sha256','qualification_id','qualification_report_sha256','policy_state_version'):
        assert receipt[key]==getattr(request,key)
    assert receipt['active_version']==1 and receipt['previous_active_version']==0
    assert receipt['historical_receipt'] and not receipt['current_qualification_verified']
    assert not receipt['inspection_enablement_granted'] and 'owner_session_id' not in receipt


@pytest.mark.parametrize('value',[None,0,True,'1',9007199254740992])
def test_present_candidate_state_in_activation_provenance_must_be_valid(world,activation,value):
    from proofpack.planner.activation import activation_key
    from proofpack.calibrations.dependencies import digest
    from proofpack.evidence.repository import Row,StoreUnavailable
    service,_,issue,*_=activation
    result=service.transition(world[5],request=issue(new(activation)),idempotency_key='optional-version')
    row=world[1].snapshot((activation_key(result['transition_id']),))[activation_key(result['transition_id'])]
    data={**row.data,'policy_state_version':value};data['sha256']=digest({k:v for k,v in data.items() if k!='sha256'})
    with pytest.raises(StoreUnavailable):service._intact(Row(row.key,1,data),'policy_activation')


def test_legacy_historical_receipt_never_invents_unrecorded_candidate_state(world,activation):
    from uuid import uuid4
    from proofpack.planner.activation import activation_key
    from proofpack.calibrations.dependencies import digest
    from proofpack.evidence.repository import Write
    service,_,issue,*_=activation
    result=service.transition(world[5],request=issue(new(activation)),idempotency_key='legacy-base')
    row=world[1].snapshot((activation_key(result['transition_id']),))[activation_key(result['transition_id'])]
    # Explicitly injected older event schema, never a current policy head or qualification.
    ident=str(uuid4());data={k:v for k,v in row.data.items() if k not in {'policy_state_version','sha256'}}
    data['activation_id']=ident;data['sha256']=digest(data)
    world[1].transact((Write(activation_key(ident),None,data),))
    old=service.receipt(world[5],ident)
    assert old['policy_state_version'] is None and old['historical_receipt'] and not old['current_qualification_verified']
