"""Genuinely emitted local qualification consumed by an exact active event.

Images, identities, source rights and readiness are synthetic; no hosted/physical
qualification or enabled production inspection is claimed.
"""
from dataclasses import replace
import pytest
from test_policy_qualification import (qualification,policies,world,repository_factory,finish,
    preparations,vision_case,publication_case,original_case)
from test_policy_candidates import draft,invite_and_join
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,user_key
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Write,StoreConflict,StoreUnavailable
from proofpack.planner.activation import PolicyActivations,ActivationConfig,ActivationRequest,activation_key,qualification_key,qualification_head
from proofpack.planner.active import ActivePolicies,ActivePolicySnapshot
from proofpack.planner.consumption import consumption
from proofpack.review.policy_qualification import PolicyQualifications,QualificationConfig,QualificationRequest
from proofpack.review.evaluation_models import EvaluationConfig
from proofpack.runtime.control import DATA
from proofpack.stations.service import POLICY


def bootstrap(world,case,job):
    service,actor,request,candidate=case
    activation=PolicyActivations(service.policies,ActivationConfig(20,120,60000,80,service.registry_sha),service)
    runtime=world[1].snapshot((RUNTIME,))[RUNTIME]
    body=ActivationRequest(operation='bootstrap',policy_id=candidate['id'],policy_revision=candidate['revision'],
        policy_state_version=candidate['state_version'],policy_revision_sha256=candidate['revision_sha256'],
        qualification_id=job['id'],qualification_report_sha256=job['report_sha256'],expected_active_version=0,
        expected_control_version=int(runtime.data['control_version']),invalidation_acknowledged=True)
    result=activation.transition(world[5],request=body,idempotency_key='consume-bootstrap')
    return ActivePolicies(activation),body,result


@pytest.fixture
def active(world,qualification):
    job=finish(qualification,'active-source')
    reader,body,result=bootstrap(world,qualification,job)
    return reader,body,result,job


def test_genuine_active_use_allows_later_drafts_controls_and_owner_logout_without_reusable_promotion(world,qualification,active):
    service,actor,_,candidate=qualification;reader,body,result,job=active
    current=reader.read_current();assert type(current) is ActivePolicySnapshot
    assert current.definition==draft() and current.policy.data['qualification_id']==job['id']
    assert current.expires_at_ms==service._row(job['id']).data['expires_at_ms']
    assert len({r.key for r in current.dependencies})==len(current.dependencies)<=90
    with pytest.raises(StoreConflict):service.read_current(job['id'])
    # A changed draft is metadata only; it does not switch the qualified behavior.
    service.policies.write(actor,request=draft('Next revision',('RECAPTURE','SEPARATE_REGION','PLACE_FLAT')),
        ident=candidate['id'],expected_version=candidate['state_version'],idempotency_key='later-draft')
    with pytest.raises(StoreConflict):current.final_guard()
    after=reader.read_current();assert after.definition==current.definition and after.policy==current.policy
    runtime=world[1].snapshot((RUNTIME,))[RUNTIME]
    service.runtime.disable(world[5],expected_version=int(runtime.data['control_version']),reason='inspection-paused',idempotency_key='later-disable')
    with pytest.raises(StoreConflict):after.final_guard()
    assert reader.read_current().expires_at_ms==current.expires_at_ms
    # Unrelated access-head changes are revalidated rather than frozen forever.
    invite_and_join(world,'unrelated-member',roles=(Role.OPERATOR,))
    assert reader.read_current().definition==current.definition
    world[0].logout(world[4].cookie,world[4].csrf)
    assert reader.read_current().policy==current.policy  # approving account remains; old login need not
    with pytest.raises(StoreConflict):service.read_current(job['id'])


@pytest.mark.parametrize('change',['data','runtime','owner_access','owner_role','qualification_job','qualification_head','event','policy','report','expiry','registry','configuration'])
def test_active_policy_rejects_stale_or_changed_authority(world,qualification,active,change):
    service,_,_,candidate=qualification;reader,body,result,job=active;repo=world[1]
    snapshot=reader.read_current()
    if change=='expiry':world[2].value=snapshot.expires_at_ms
    elif change=='registry':reader.activations.config=replace(reader.activations.config,qualification_registry_sha256='f'*64)
    elif change=='configuration':service.configuration='f'*64
    else:
        key={
            'data':DATA,'runtime':RUNTIME,'owner_access':user_key(world[5].member.data['id']),
            'owner_role':user_key(world[5].member.data['id']),'qualification_job':service._row(job['id']).key,
            'qualification_head':qualification_head(candidate['id'],candidate['revision']),
            'event':activation_key(result['transition_id']),'policy':POLICY,'report':qualification_key(job['id'])}[change]
        row=repo.snapshot((key,))[key];data=dict(row.data)
        if change=='data':data['epoch']=int(data['epoch'])+1
        elif change=='runtime':data['instance_id']='00000000-0000-4000-8000-000000000099'
        elif change=='owner_access':data['access_version']=int(data['access_version'])+1
        elif change=='owner_role':data['roles']=[Role.REVIEWER.value]
        elif change=='qualification_job':data['status']='retired'
        elif change=='qualification_head':data['status']='pending'
        else:data['sha256']='f'*64
        repo.transact((Write(key,row.revision,data),))
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):reader.read_current()
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):snapshot.final_guard()


def test_final_snapshot_fences_source_changes_during_delivery(world,qualification,active,monkeypatch):
    service,*_=qualification;reader,*_=active;original=service._sealed;fired=False
    def sealed(*args,**kwargs):
        nonlocal fired
        value=original(*args,**kwargs)
        if not fired:
            fired=True;row=world[1].snapshot((DATA,))[DATA]
            world[1].transact((Write(DATA,row.revision,{**row.data,'epoch':int(row.data['epoch'])+1}),))
        return value
    monkeypatch.setattr(service,'_sealed',sealed)
    with pytest.raises(StoreConflict):reader.read_current()
    assert fired


@pytest.mark.parametrize('value',[True,False,{},'allow-stale-control'])
def test_consumption_is_never_a_request_supplied_override(value):
    with pytest.raises(ValueError):consumption(value)


@pytest.mark.parametrize('change',['data','activation_configuration','qualification_configuration','expiry'])
def test_last_authorization_read_cannot_deliver_stale_active_policy(world,qualification,active,monkeypatch,change):
    import sys
    service,*_=qualification;reader,*_=active;original=service.access._fresh;calls=0
    deadline=service._row(active[3]['id']).data['expires_at_ms']
    def fresh(*args,**kwargs):
        nonlocal calls
        result=original(*args,**kwargs)
        if sys._getframe(1).f_globals.get('__name__')=='proofpack.planner.active':
            calls+=1
            if calls==2:  # final validation pass, immediately after the real authorization read
                if change=='data':
                    row=world[1].snapshot((DATA,))[DATA]
                    world[1].transact((Write(DATA,row.revision,{**row.data,'epoch':int(row.data['epoch'])+1}),))
                elif change=='activation_configuration':reader.activations.config=replace(reader.activations.config,reads_per_minute=119)
                elif change=='qualification_configuration':service.configuration='f'*64
                else:world[2].value=deadline
        return result
    monkeypatch.setattr(service.access,'_fresh',fresh)
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):reader.read_current()
    assert calls==2


@pytest.mark.parametrize('publication_case',['synthetic_demo'],indirect=True)
@pytest.mark.parametrize('vision_case',['qualification_compatible'],indirect=True)
def test_candidate_active_reader_revalidates_real_preparation_evaluation_permissions_and_original_reviewer(world,preparations):
    prep,actor,request=preparations;prepared=prep.create(actor,request=request,idempotency_key='active-candidate-prep')
    for index in range(prepared['planned_count']):
        if index==100:world[2].value=(world[2]()//60000+1)*60000
        prepared=prep.advance(actor,prepared['id'],expected_version=prepared['state_version'],idempotency_key='active-prep-'+str(index))
    policies=prep.evaluations.policies;candidate=policies.get(actor,request.policy_id)
    service=PolicyQualifications(policies,prep.evaluations.vision.registry,
        QualificationConfig(EvaluationConfig(20,120,120,3600000,15000,1200),2400,15000),prep.suite_config,prep)
    body=QualificationRequest(mode='candidate',policy_id=candidate['id'],policy_revision=candidate['revision'],policy_state_version=candidate['state_version'],
        policy_revision_sha256=candidate['revision_sha256'],preparation_id=prepared['id'],preparation_state_version=prepared['state_version'],
        preparation_report_sha256=prepared['report_sha256'],synthetic_demo_acknowledged=True)
    case=(service,actor,body,candidate);job=finish(case,'active-candidate-qualify')
    assert job['qualification_status']=='qualified' and job['required_cases']==183
    # Remove only the legacy TEST-INJECTED policy seed used for upstream captures.
    # Bootstrap itself uses the genuine report and real transition transaction.
    repo=world[1];repo.client.delete_item(TableName=repo.tables[POLICY.table],Key=repo.key(POLICY))
    reader,_,_=bootstrap(world,case,job)
    current=reader.read_current();assert current.policy.data['qualification_id']==job['id']
    policies.write(actor,request=draft('Unactivated candidate'),ident=candidate['id'],expected_version=candidate['state_version'],idempotency_key='candidate-next-draft')
    assert reader.read_current().policy==current.policy
    with pytest.raises(StoreConflict):service.read_current(job['id'])
    world[0].change_access(world[5],user_id=actor.member.data['id'],roles=(Role.REVIEWER,),enabled=False,
        expected_version=int(actor.member.data['access_version']),idempotency_key='revoke-original-reviewer')
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):reader.read_current()
