"""Live policy integration with disclosed synthetic assurance and local stores."""
import pytest
import json
from uuid import uuid4
from test_access_lifecycle import world,repository_factory,station_world,acquire_station,start_station,capture_world
from proofpack.stations.service import StationService
from proofpack.evidence.repository import StoreUnavailable

from test_vision_replay import vision_case,publication_case,original_case
from test_policy_qualification import finish as finish_qualification
from test_manifests import finish as finish_evaluation
from test_access_lifecycle import synthetic_readiness,synthetic_recipe_qualification,inspection_key,capture_permit,admit_frame
from proofpack.auth.policy import Denied
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key,Write,StoreConflict
from proofpack.calibrations.dependencies import digest
from proofpack.planner.activation import PolicyActivations,ActivationConfig,ActivationRequest,qualification_head
from proofpack.planner.active import ActivePolicies
from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.policy import DEFAULT_PRIORITY
from proofpack.planner.contract_suite import ContractSuiteConfig
from proofpack.review.policy_qualification import PolicyQualifications,QualificationConfig,QualificationRequest
from proofpack.review.qualification_preparation import QualificationPreparations,PreparationRequest
from proofpack.review.evaluation_models import EvaluationConfig
from proofpack.runtime.control import DATA
from proofpack.stations.service import POLICY
from proofpack.capture.service import CaptureService,observation_key
from proofpack.capture.service import permit_key
from proofpack.capture.observations import ObservationService
from proofpack.capture.publication import action_key,asset_key,intent_key


def fresh_operating_references(world,old,work):
    """New TEST-INJECTED recipe/calibration witnesses; never renew old evidence."""
    from proofpack.vision.calibration import CalibrationProfile
    from proofpack.recipes.service import revision_key
    repo=world[1];epoch=int(repo.snapshot((DATA,))[DATA].data['epoch'])
    oldcal=repo.snapshot((Key('state','calibration-active#'+work.data['calibration_profile_id']),))[Key('state','calibration-active#'+work.data['calibration_profile_id'])]
    profile=CalibrationProfile.model_validate_json(oldcal.data['profile_json']).model_copy(update={'profile_id':'live-'+str(uuid4())})
    source=repo.snapshot((revision_key(work.data['recipe_id'],int(work.data['recipe_revision'])),))[revision_key(work.data['recipe_id'],int(work.data['recipe_revision']))]
    content=json.loads(source.data['recipe_json']);content.pop('recipe_id');content.pop('revision')
    purpose,asset,receipt,report_id=(str(uuid4()) for _ in range(4))
    content.update(name='Fresh synthetic operating recipe',calibration_profile_id=profile.profile_id,reference_asset_ids=[asset])
    created=old.stations.recipes.create(world[5],content=content,idempotency_key='live-operating-recipe')
    manifest=[{'asset_id':asset,'purpose_id':purpose,'asset_state_version':1,'purpose_state_version':1,'sha256':'d'*64}]
    expiry=world[2]()+60000
    report={'id':report_id,'calibration_id':profile.profile_id,'revision':profile.revision,'profile_sha256':profile.content_hash,'passed':True,
        'reference_manifest':manifest,'data_epoch':epoch,'environment':'synthetic_demo','artifact_sha256':'a'*64,'expires_at_ms':expiry,
        'physical_truth_verified':False,'fixture_origin':'TEST_INJECTED_OPERATING_WITNESS'};report['sha256']=digest(report)
    repo.transact((
        Write(Key('state','purpose#'+purpose),None,{'allowed_uses':['operation'],'withdrawn':False,'expires_at_ms':expiry}),
        Write(Key('state','asset#'+asset),None,{'sha256':'d'*64,'purpose_id':purpose,'status':'committed','read_denied':False,'data_origin':'synthetic','expires_at_ms':expiry}),
        Write(Key('state','calibration-active#'+profile.profile_id),None,{'status':'approved','environment':'synthetic_demo','data_origin':'synthetic',
            'profile_sha256':profile.content_hash,'dependency_receipt_id':receipt,'profile_json':profile.model_dump_json()}),
        Write(Key('state','calibration-dependencies#'+receipt),None,{'environment':'synthetic_demo','profile_sha256':profile.content_hash,
            'profile_state_version':1,'data_epoch':epoch,'expires_at_ms':expiry,'reference_manifest':manifest,'report_id':report_id,'report_sha256':report['sha256']}),
        Write(Key('state','calibration-report#'+report_id),None,report)))
    qid,_=synthetic_recipe_qualification(world,old.stations.recipes,created,content,changes={'data_epoch':epoch})
    old.stations.recipes.approve(world[5],recipe_id=created['id'],expected_version=created['state_version'],qualification_id=qid,idempotency_key='live-operating-approve')
    return created,profile


def test_station_without_policy_reader_cannot_admit_metadata_only_policy(world,recipe):
    stations,enrolled,created,operator,*_=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0])
    closed=StationService(stations.access,stations.runtime,stations.recipes,tick_ns=stations.tick_ns)
    with pytest.raises(StoreUnavailable):start_station(closed,operator,enrolled[0],created,key='no-policy-reader')


@pytest.mark.parametrize('kind',['missing_head','wrong_definition','expired','untyped'])
def test_station_rejects_incomplete_or_misbound_reader_snapshot(world,recipe,monkeypatch,kind):
    from dataclasses import replace
    stations,enrolled,created,operator,*_=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);value=stations.policy_reader.read_current()
    if kind=='missing_head':value=replace(value,dependencies=tuple(row for row in value.dependencies if row.key!=POLICY))
    elif kind=='wrong_definition':value=replace(value,definition=value.definition.model_copy(update={'name':'unbound-name'}))
    elif kind=='expired':value=replace(value,expires_at_ms=world[2]())
    else:value={'status':'qualified'}
    monkeypatch.setattr(stations.policy_reader,'read_current',lambda:value)
    with pytest.raises((StoreUnavailable,StoreConflict)):start_station(stations,operator,enrolled[0],created,key='bad-snapshot')


def test_permit_readback_does_not_restore_nonce_for_different_policy(world,recipe):
    capture,started,operator,_,_=capture_world(world,recipe)
    first=capture_permit(capture,started,operator);key=permit_key(first['permit_id']);row=world[1].snapshot((key,))[key]
    world[1].transact((Write(key,row.revision,{**row.data,'policy_provenance':{}}),))
    again=capture_permit(capture,started,operator)
    assert not again['usable'] and again['nonce'] is None


def test_last_actor_read_cannot_commit_permit_after_reader_configuration_changes(world,recipe,monkeypatch):
    import sys
    capture,started,operator,_,_=capture_world(world,recipe);access=world[0];original=access._fresh;fired=False
    def fresh(*args,**kwargs):
        nonlocal fired
        value=original(*args,**kwargs);frame=sys._getframe(1)
        if (not fired and frame.f_code.co_name=='_record' and frame.f_locals.get('operation','').startswith('capture-permit:')):
            fired=True;capture.stations.policy_reader.runtime=object()
        return value
    monkeypatch.setattr(access,'_fresh',fresh)
    with pytest.raises(StoreUnavailable):capture_permit(capture,started,operator)
    assert fired and world[1].query(prefix='capture-permit#',limit=20)[0]==[]
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data.get('pending_permit_id') is None


@pytest.mark.parametrize('publication_case',['synthetic_demo'],indirect=True)
@pytest.mark.parametrize('vision_case',['qualification_compatible'],indirect=True)
def test_genuine_promoted_policy_binds_live_capture_action_and_final_source_revocation(world,vision_case,publication_case,monkeypatch):
    """Actual software/CV reports and storage protocol; readiness is TEST-INJECTED.

    The spy observes the priority argument only, never substitutes worker/action
    outcomes. No physical qualification or improved packing outcome is implied.
    """
    from proofpack.capture import publication as publication_module
    from proofpack.vision.fixtures import make_fixture
    import cv2
    engine,reviewer,source_request,*_=vision_case;evaluations=engine.evaluations;policies=evaluations.policies
    old,_,old_started,operator,_,clock,registry,objects,purpose,_=publication_case
    repo=world[1];key=inspection_key(old_started['inspection_id']);work=repo.snapshot((key,))[key]
    with pytest.raises(StoreUnavailable):old.stations.recipes.active_snapshot(work.data['recipe_id'])
    old.stations.close(operator,inspection_id=work.data['id'],expected_version=work.revision,expected_epoch=int(work.data['station_epoch']),
        reason='genuine-policy-transition',disposition='cancelled',idempotency_key='close-old-policy-fixture')
    registry.retire(old_started['station_id'])
    suite=ContractSuiteConfig(256,15000,8192,1048576)
    config=QualificationConfig(EvaluationConfig(20,120,120,3600000,15000,1200),2400,15000)
    default=policies.get(reviewer,source_request.policy_id)
    default_reader=PolicyQualifications(policies,registry,config,suite)
    default_request=QualificationRequest(mode='installed_default',policy_id=default['id'],policy_revision=default['revision'],
        policy_state_version=default['state_version'],policy_revision_sha256=default['revision_sha256'],synthetic_demo_acknowledged=True)
    default_job=finish_qualification((default_reader,reviewer,default_request,default),'live-default')
    assert default_job['qualification_status']=='qualified'
    # Remove only the legacy test seed; subsequent heads/events use real transitions.
    repo.client.delete_item(TableName=repo.tables[POLICY.table],Key=repo.key(POLICY))
    limits=ActivationConfig(20,120,60000,80,default_reader.registry_sha)
    def activate(service,candidate,job,operation):
        roots=repo.snapshot((POLICY,RUNTIME));active=roots[POLICY]
        request=ActivationRequest(operation=operation,policy_id=candidate['id'],policy_revision=candidate['revision'],
            policy_state_version=candidate['state_version'],policy_revision_sha256=candidate['revision_sha256'],
            qualification_id=job['id'],qualification_report_sha256=job['report_sha256'],expected_active_version=0 if active is None else active.revision,
            expected_control_version=int(roots[RUNTIME].data['control_version']),invalidation_acknowledged=True)
        result=service.transition(world[5],request=request,idempotency_key='live-'+operation)
        assert repo.snapshot((RUNTIME,))[RUNTIME].data['inspection_enabled'] is False
        return result
    activate(PolicyActivations(policies,limits,default_reader),default,default_job,'bootstrap')
    priority=('RECAPTURE','PLACE_FLAT','SEPARATE_REGION')
    candidate=policies.write(reviewer,request=PolicyDraft.model_validate_json(json.dumps(
        {'name':'Live qualified priority','algorithm':'reason_priority_v1','priority':priority})),idempotency_key='live-candidate')
    source=source_request.model_copy(update={'policy_id':candidate['id'],'policy_revision':candidate['revision'],
        'policy_state_version':candidate['state_version'],'policy_revision_sha256':candidate['revision_sha256']})
    evaluated=finish_evaluation(evaluations,reviewer,evaluations.create(reviewer,request=source,idempotency_key='live-source'))
    prep=QualificationPreparations(evaluations,EvaluationConfig(20,120,120,3600000,15000,340),suite)
    request=PreparationRequest(policy_id=candidate['id'],source_evaluation_id=evaluated['id'],source_evaluation_state_version=evaluated['state_version'],
        source_report_sha256=evaluated['report_sha256'],preparation_only_acknowledged=True)
    prepared=prep.create(reviewer,request=request,idempotency_key='live-preparation')
    for index in range(prepared['planned_count']):
        if index==100:world[2].value=(world[2]()//60000+1)*60000
        prepared=prep.advance(reviewer,prepared['id'],expected_version=prepared['state_version'],idempotency_key='live-prep-'+str(index))
    qualified=PolicyQualifications(policies,registry,config,suite,prep)
    request=QualificationRequest(mode='candidate',policy_id=candidate['id'],policy_revision=candidate['revision'],policy_state_version=candidate['state_version'],
        policy_revision_sha256=candidate['revision_sha256'],preparation_id=prepared['id'],preparation_state_version=prepared['state_version'],
        preparation_report_sha256=prepared['report_sha256'],synthetic_demo_acknowledged=True)
    job=finish_qualification((qualified,reviewer,request,candidate),'live-qualified-candidate')
    assert job['qualification_status']=='qualified' and job['required_cases']==183
    activations=PolicyActivations(policies,limits,qualified);transition=activate(activations,candidate,job,'promote')
    # This private readiness fixture does not establish genuine hosted readiness.
    runtime=old.stations.runtime;row=repo.snapshot((RUNTIME,))[RUNTIME]
    rid,*_=synthetic_readiness(world,runtime,environment='synthetic_demo',data_epoch=int(repo.snapshot((DATA,))[DATA].data['epoch']))
    runtime.enable(world[5],expected_version=int(row.data['control_version']),receipt_id=rid,idempotency_key='live-local-enable')
    stations=StationService(world[0],runtime,old.stations.recipes,tick_ns=clock,policy_reader=ActivePolicies(activations))
    capture=CaptureService(stations,worker_guard=registry.guard,tick_ns=clock)
    live=ObservationService(capture,registry,objects=objects,purpose_id=purpose.resource.removeprefix('purpose#'))
    recipe_row,profile=fresh_operating_references(world,old,work)
    station=stations.enroll(world[5],name='Fresh synthetic live station',calibration_profile_id=profile.profile_id,idempotency_key='live-new-station')
    acquire_station(stations,operator,station,key='live-acquire')
    started=start_station(stations,operator,station,recipe_row,key='qualified-live')
    live.prepare(operator,inspection_id=started['inspection_id'],expected_version=1,idempotency_key='live-warm')
    seen=[];choose=publication_module.choose_action
    def observed_choice(reasons,*,priority):
        seen.append(priority);return choose(reasons,priority=priority)
    monkeypatch.setattr(publication_module,'choose_action',observed_choice)
    admissions=[]
    def observe(condition):
        clock.value+=500000000;world[2].value+=500
        current=repo.snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
        permit=capture_permit(capture,started,operator,version=current.revision,key='qualified-'+str(current.revision))
        frame,_=make_fixture(0,condition,seed=1);ok,data=cv2.imencode('.png',frame);assert ok
        admission=admit_frame(capture,started,operator,permit,payload=data.tobytes());admissions.append(admission)
        return live.process(operator,observation_id=admission['id'],payload=data.tobytes())
    status=observe('missing');assert status['effective_state']=='ACTION_REQUIRED' and status['action']['kind']=='RECAPTURE'
    assert seen[-1]==tuple(priority) and seen[-1]!=DEFAULT_PRIORITY
    current=repo.snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    provenance=stations._policy_provenance(repo.snapshot((POLICY,))[POLICY])
    assert current.data['policy_provenance']==provenance and provenance['activation_id']==transition['transition_id']
    action=repo.snapshot((action_key(status['action']['id']),))[action_key(status['action']['id'])]
    observation=repo.snapshot((observation_key(admissions[-1]['id']),))[observation_key(admissions[-1]['id'])]
    assert action.data['policy_provenance']==observation.data['policy_provenance']==provenance
    args={'inspection_id':started['inspection_id'],'action_id':action.data['id'],'expected_version':status['state_version'],'idempotency_key':'live-ack'}
    live.acknowledge(operator,**args);live.acknowledge(operator,**args)
    for expected in ['OBSERVING','OBSERVING','PASSED_CURRENT']:
        assert observe('complete')['effective_state']==expected
    headkey=qualification_head(candidate['id'],candidate['revision'])
    def revoke_source():
        head=repo.snapshot((headkey,))[headkey]
        repo.transact((Write(headkey,head.revision,{**head.data,'status':'pending'}),))
    objects.after_put=revoke_source
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):observe('complete')
    failed=admissions[-1];ob=repo.snapshot((observation_key(failed['id']),))[observation_key(failed['id'])]
    assert ob.data['status']!='completed' and repo.snapshot((asset_key(failed['id']),))[asset_key(failed['id'])] is None
    assert repo.snapshot((intent_key(failed['id']),))[intent_key(failed['id'])].data['status']=='uploaded'
    assert runtime.enabled_snapshot()[RUNTIME].data['inspection_enabled'] is True
    invalid=live.status(operator,started['inspection_id'])
    assert invalid['effective_state']=='INVALIDATED' and invalid['remaining_lease_ms']==0 and invalid['action'] is None
