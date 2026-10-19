"""Actual CV and local durable sources; SDK/identity fixtures, no AWS or physical truth."""
from dataclasses import replace
import hashlib
import json
from uuid import uuid4
import pytest

from test_original_frames import world,repository_factory,publication_case,original_case
from test_access_lifecycle import invite_and_join
from test_manifests import finish,config
from proofpack.auth.policy import Denied,Role
from proofpack.evidence.improvement import ImprovementPermissions,ImprovementConfig,ImprovementPreview,ImprovementConfirmation
from proofpack.evidence.repository import Key,Write,StoreUnavailable,StoreConflict
from proofpack.planner.candidates import PolicyCandidates,PolicyCatalogConfig,PolicyDraft
from proofpack.planner.policy import DEFAULT_PRIORITY
from proofpack.recipes.models import PartClass
from proofpack.recipes.service import RecipeService,revision_key
from proofpack.review.labels import OutcomeLabels,ReviewTuple,LabelRequest,GroundCount
from proofpack.review.manifests import DatasetManifests,ManifestRequest,Selection,PermissionBinding
from proofpack.review.datasets import Split
from proofpack.review.evaluations import PolicyEvaluations
from proofpack.review.evaluation_models import EvaluationConfig
from proofpack.review.vision_replay import VisionReprocessor,VisionReplayRequest,VisionReplayConfig
from proofpack.stations.service import inspection_key,POLICY


@pytest.fixture
def vision_case(world,original_case,publication_case,request):
    reads,observe,operator,objects,purpose,started,capture=original_case
    variant=getattr(request,'param',None)
    ob,payload,status=observe(retain=variant!='crop_only',condition='post_pass_removal' if variant=='two_frames' else 'overlap' if variant=='unknown' else 'complete');repo=world[1]
    after=None;action=None
    if variant=='two_frames':
        action=status['action'];assert action is not None
        publication_case[0].publisher.acknowledge(operator,inspection_id=started['inspection_id'],action_id=action['id'],
            expected_version=status['state_version'],idempotency_key='pixel-tuple-ack')
        after,_,_=observe()
    if variant=='legacy_geometry':
        key=Key('state','asset#'+ob.data['original_asset_id']);row=repo.snapshot((key,))[key];data=dict(row.data);data.pop('replay_profile_json')
        repo.transact((Write(key,row.revision,data),))
    registry=publication_case[6]
    # Release this one-slot fixture's live warm worker explicitly; no new pool or auto restart.
    registry.retire(started['station_id'])
    _,credentials,reviewer,_,_=invite_and_join(world,'pixel-reviewer',roles=(Role.REVIEWER,))
    labels=OutcomeLabels(reads.purposes,writes_per_minute=8,max_duration_ms=60000,review_validity_ms=30000)
    tuple_=ReviewTuple(before_observation_id=ob.data['id'],**({} if after is None else {'action_id':action['id'],'after_observation_id':after.data['id']}));context=labels.context(reviewer,tuple_)
    label=labels.write(reviewer,request=LabelRequest(**tuple_.model_dump(),source_context_sha256=context['source_context_sha256'],
        data_epoch=context['data_epoch'],outcome='unresolved',ground_truth_counts=tuple(GroundCount(part_class=p,count=1) for p in PartClass),
        method='synthetic_fixture',duration_ms=1000,independence_declared=False,note='Synthetic fresh pixel comparison'),idempotency_key='pixel-label')
    permissions=ImprovementPermissions(reads,ImprovementConfig('pixel-test','Separate synthetic source/review permission.',60000,8,30000))
    ids=tuple(x['asset_id'] for x in label['source_context']['sources'])
    preview=permissions.preview(world[5],request=ImprovementPreview(asset_ids=ids),idempotency_key='pixel-rights-preview')
    grant=permissions.confirm(world[5],request=ImprovementConfirmation(preview_id=preview['id'],confirmed_scope_sha256=preview['scope_sha256'],
        documented_permission_reference='synthetic-pixel-rights',notice_version=preview['notice']['version'],notice_sha256=preview['notice']['sha256'],
        optional_improvement_acknowledged=True,limitations_acknowledged=True,derived_review_metadata_acknowledged=True,expires_at_ms=world[2]()+40000),
        expected_version=preview['state_version'],idempotency_key='pixel-rights')
    datasets=DatasetManifests(labels,permissions,config())
    selection=Selection(label_id=label['id'],label_revision=1,split=Split.DEVELOPMENT,permissions=(PermissionBinding(id=grant['id'],state_version=grant['state_version']),))
    manifest=datasets.create(reviewer,request=ManifestRequest(selections=(selection,),historical_diagnostic_acknowledged=True,frozen_holdout_acknowledged=False),idempotency_key='pixel-dataset')
    manifest=finish(datasets,reviewer,manifest);assert manifest['status']=='completed'
    policies=PolicyCandidates(world[0],datasets.runtime,PolicyCatalogConfig(100,120,100))
    policy=policies.write(reviewer,request=PolicyDraft(name='Pixel policy',algorithm='reason_priority_v1',priority=DEFAULT_PRIORITY),idempotency_key='pixel-policy')
    source=label['source_context'];key=revision_key(source['recipe_id'],source['recipe_revision']);row=repo.snapshot((key,))[key]
    recipe=json.loads(row.data['recipe_json']);recipe.pop('recipe_id');recipe.pop('revision');recipe['name']='Pixel candidate'
    # A changed recipe must change actual findings, not merely replay old findings.
    if variant!='qualification_compatible':recipe['constraints'][0]['expected_count']=2
    recipes=RecipeService(world[0],environment=datasets.runtime.environment,artifact_sha256=datasets.runtime.artifact_sha256)
    candidate=recipes.create(world[5],content=recipe,idempotency_key='pixel-recipe')
    key=revision_key(candidate['id'],candidate['revision']);candidate_row=repo.snapshot((key,))[key]
    req=VisionReplayRequest(runner='vision_replay_v1',policy_id=policy['id'],policy_revision=1,policy_state_version=policy['state_version'],
        policy_revision_sha256=policy['revision_sha256'],manifest_id=manifest['id'],manifest_sha256=manifest['manifest_sha256'],
        historical_diagnostic_acknowledged=True,frozen_holdout_acknowledged=False,candidate_recipe_id=candidate['id'],
        candidate_recipe_revision=1,candidate_recipe_state_version=candidate['state_version'],candidate_recipe_sha256=candidate_row.data['sha256'],vision_measurement_acknowledged=True)
    evaluations=PolicyEvaluations(policies,datasets,EvaluationConfig(20,120,120,3600000,15000,3000),vision_registry=registry,vision_config=VisionReplayConfig())
    engine=evaluations.vision
    return engine,reviewer,req,ob,payload,objects,grant,started,credentials


def test_full_original_pixels_are_measured_for_both_recipes_without_live_mutation(world,vision_case):
    engine,actor,request,ob,payload,objects,grant,started,*_=vision_case
    key=inspection_key(started['inspection_id']);before=world[1].snapshot((key,POLICY))
    value,checks,deadline=engine.measure(actor,request=request,index=0)
    assert value['runner']=='vision_replay_v1' and value['pixel_measurement_performed']
    assert value['original_frames']==1 and value['measurement_count']==2
    for side in ('baseline','candidate'):
        result=value[side]['measurements'][0]
        assert result['source_sha256']==hashlib.sha256(payload).hexdigest() and result['original_asset_id']==ob.data['original_asset_id']
        assert result['counts_match_declared_truth'] and result['count_comparison_observable']
        assert not result['physical_truth_verified'] and not result['dimension_truth_accuracy_measured']
    assert value['baseline']['measurements'][0]['findings'][0]=='SATISFIED'
    assert value['candidate']['measurements'][0]['findings'][0]=='VIOLATED'
    assert value['baseline']['recipe_sha256']!=value['candidate']['recipe_sha256']
    assert world[1].snapshot((key,POLICY))==before and not value['machine_pass'] and not value['promotion_eligible']
    assert not value['independent_benchmark_qualified'] and deadline>world[2]() and engine.registry._diagnostics=={}
    text=json.dumps(value)
    for private in ('object_key','object_version','replay_profile_json','evidence_jpeg_base64'):assert private not in text


@pytest.mark.parametrize('vision_case',['crop_only','legacy_geometry'],indirect=True)
def test_crop_only_or_missing_original_geometry_cannot_be_silently_reprocessed(vision_case):
    engine,actor,request,*_=vision_case
    with pytest.raises(StoreUnavailable):engine.measure(actor,request=request,index=0)
    assert engine.registry._diagnostics=={}


@pytest.mark.parametrize('fault',['recipe_hash','recipe_version','permission','source_after_read','cancellation','window'])
def test_stale_or_lost_vision_authority_cannot_return_measurements(world,vision_case,fault):
    engine,actor,request,ob,payload,objects,grant,started,*_=vision_case;cancel=[False]
    if fault=='recipe_hash':request=request.model_copy(update={'candidate_recipe_sha256':'f'*64})
    elif fault=='recipe_version':request=request.model_copy(update={'candidate_recipe_state_version':2})
    elif fault=='permission':engine.datasets.improvement.withdraw(world[5],grant['id'],expected_version=grant['state_version'],idempotency_key='pixel-withdraw')
    elif fault=='source_after_read':
        def changed():
            key=Key('state','asset#'+ob.data['original_asset_id']);row=world[1].snapshot((key,))[key]
            world[1].transact((Write(key,row.revision,{**row.data,'read_denied':True}),))
        objects.after_get=changed
    elif fault=='cancellation':objects.after_get=lambda:cancel.__setitem__(0,True)
    else:
        tick=[0]
        engine.tick=lambda:tick[0]
        objects.after_get=lambda:tick.__setitem__(0,engine.config.max_case_ms*1000000)
    def gate():
        if cancel[0]:raise StoreConflict('synthetic evaluation canceled')
    with pytest.raises((Denied,StoreUnavailable,StoreConflict)):engine.measure(actor,request=request,index=0,execution_gate=gate)
    assert engine.registry._diagnostics=={}


def test_durable_vision_job_uses_same_bounded_lifecycle_and_source_bound_report(world,vision_case):
    engine,actor,request,ob,payload,objects,grant,started,*_=vision_case;service=engine.evaluations
    key=inspection_key(started['inspection_id']);before=world[1].snapshot((key,POLICY))
    job=service.create(actor,request=request,idempotency_key='vision-job')
    assert job['runner']=='vision_replay_v1' and job['steps_reserved']==0 and job['can_advance']
    result=finish(service,actor,job);assert result['status']=='completed' and result['steps_reserved']==result['prepared_count']==1
    summary=service.summary(actor,job['id']);assert summary['result_header_current'] and summary['pixel_measurement_performed']
    assert summary['counts']['baseline']['measurements']==summary['counts']['candidate']['measurements']==1
    assert summary['counts']['baseline']['count_matches']==summary['counts']['candidate']['count_matches']==1
    page=service.examples(actor,job['id']);assert page['examples'][0]['runner']=='vision_replay_v1'
    assert page['examples'][0]['measurement_count']==2 and not page['promotion_eligible']
    assert world[1].snapshot((key,POLICY))==before
    _,_,other,_,_=invite_and_join(world,'other-pixel-reviewer',roles=(Role.REVIEWER,))
    for reader in (world[5],other):
        with pytest.raises(Denied):service.examples(reader,job['id'])
        with pytest.raises(Denied):service.selections(reader,job['id'])
    assert service.summary(world[5],job['id'])['result_header_current']


def test_vision_job_http_requires_explicit_configuration_and_returns_exact_mode(world,vision_case):
    from fastapi.testclient import TestClient
    from proofpack.app import create_app
    from proofpack.auth.http import COOKIE
    engine,actor,request,*_=vision_case;service=engine.evaluations;credentials=vision_case[-1]
    headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'vision-http'}
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,evaluation_service=service,
        policy_service=service.policies,dataset_service=service.datasets,label_service=service.datasets.labels,
        improvement_service=service.datasets.improvement,asset_service=engine.assets,purpose_service=engine.assets.purposes)
    with TestClient(app,base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        assert client.get('/api/v1/evaluations/options').json()['runners']==['decision_replay_v1','vision_replay_v1']
        response=client.post('/api/v1/evaluations',json=request.model_dump(mode='json'),headers=headers)
        assert response.status_code==201,response.text
        result=response.json();assert result['runner']=='vision_replay_v1' and result['candidate_recipe_sha256']==request.candidate_recipe_sha256
        retry=client.post('/api/v1/evaluations',json=request.model_dump(mode='json'),headers=headers)
        assert retry.json()['id']==result['id'] and retry.json()['steps_reserved']==0
    disabled=PolicyEvaluations(service.policies,service.datasets,service.config)
    before=world[1].query(prefix='evaluation-catalog#',limit=20)[0]
    with pytest.raises(StoreUnavailable):disabled.create(actor,request=request,idempotency_key='not-configured')
    assert world[1].query(prefix='evaluation-catalog#',limit=20)[0]==before


def test_durable_vision_report_preserves_fractional_dimension_intervals(world,vision_case):
    from proofpack.review.evaluations import entry_key
    engine,actor,request,*_=vision_case;service=engine.evaluations
    job=service.create(actor,request=request,idempotency_key='fractional-job');finish(service,actor,job)
    key=entry_key(job['id'],0);row=world[1].snapshot((key,))[key]
    assert 'content_json' in row.data and 'content' not in row.data
    stored=json.loads(row.data['content_json']);public=service.examples(actor,job['id'])['examples'][0]
    intervals=[c['dimension_interval_mm'] for m in stored['baseline']['measurements'] for c in m['candidates']]
    assert intervals and any(value!=int(value) for pair in intervals for value in pair)
    assert public['baseline']['measurements']==stored['baseline']['measurements']


@pytest.mark.parametrize('fault',['permission','cancel','lease','source'])
def test_authority_loss_after_real_worker_measurement_never_publishes_case(world,vision_case,monkeypatch,fault):
    from proofpack.review.evaluations import job_key,entry_key,report_key
    from proofpack.vision.worker import VisionWorker
    engine,actor,request,ob,payload,objects,grant,*_=vision_case;service=engine.evaluations
    job=service.create(actor,request=request,idempotency_key='during-worker-'+fault);original=VisionWorker.analyze;calls=[]
    def analyze(worker,*args,**kwargs):
        result=original(worker,*args,**kwargs);calls.append(result.source_sha256)
        if len(calls)==1:
            if fault=='permission':service.datasets.improvement.withdraw(world[5],grant['id'],expected_version=grant['state_version'],idempotency_key='during-worker-withdraw')
            elif fault=='source':
                key=Key('state','asset#'+ob.data['original_asset_id']);row=world[1].snapshot((key,))[key]
                world[1].transact((Write(key,row.revision,{**row.data,'read_denied':True}),))
            elif fault=='cancel':
                current=service.job(actor,job['id']);service.cancel(actor,job['id'],expected_version=current['state_version'],idempotency_key='during-worker-cancel')
            else:world[2].value+=service.config.lease_ms
        return result
    monkeypatch.setattr(VisionWorker,'analyze',analyze)
    try:service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='during-worker-step')
    except (Denied,StoreConflict,StoreUnavailable):pass
    current=world[1].snapshot((job_key(job['id']),entry_key(job['id'],0),report_key(job['id'])))
    row=current[job_key(job['id'])]
    assert len(calls)==1 and row.data['steps_reserved']==1 and row.data['processed']==0
    assert current[entry_key(job['id'],0)] is None and current[report_key(job['id'])] is None
    assert engine.registry._diagnostics=={}


def test_vision_job_dispatch_uses_existing_signed_authority_and_shared_driver(world,vision_case):
    from types import SimpleNamespace
    from proofpack.runtime.maintenance import MaintenanceDriver
    engine,actor,request,*_=vision_case;service=engine.evaluations
    job=service.create(actor,request=request,idempotency_key='vision-driver')
    fake=SimpleNamespace(access=service.access,runtime=service.runtime,repository=service.repository)
    driver=MaintenanceDriver(service.access,service.runtime,fake,fake,evaluations=service,
        enabled=True,poll_ms=250,page_size=5,steps_per_minute=60,drain_ms=1000)
    assert driver.services['policy_evaluation'] is service and driver.poll_once()
    result=service.summary(actor,job['id'])
    assert result['status']=='completed' and result['steps_reserved']==1 and result['pixel_measurement_performed']


@pytest.mark.parametrize('vision_case',['two_frames'],indirect=True)
def test_before_after_originals_use_four_equal_bounded_calls_and_separate_tracking(vision_case,monkeypatch):
    from proofpack.vision.worker import VisionWorker
    engine,actor,request,*_=vision_case;calls=[];analyze=VisionWorker.analyze
    def measured(worker,payload,recipe,profile,**kwargs):
        calls.append((recipe.recipe_id,kwargs['sequence'],kwargs['inspection_id'],hashlib.sha256(payload).hexdigest()))
        return analyze(worker,payload,recipe,profile,**kwargs)
    monkeypatch.setattr(VisionWorker,'analyze',measured)
    value,_,_=engine.measure(actor,request=request,index=0)
    assert value['original_frames']==2 and value['measurement_count']==len(calls)==4
    assert [c[1] for c in calls]==[1,2,1,2]
    assert calls[0][2]==calls[1][2] and calls[2][2]==calls[3][2] and calls[0][2]!=calls[2][2]
    assert calls[0][3]==calls[2][3] and calls[1][3]==calls[3][3] and calls[0][3]!=calls[1][3]
    assert calls[0][0]==calls[1][0] and calls[2][0]==calls[3][0]==request.candidate_recipe_id


@pytest.mark.parametrize('vision_case',['unknown'],indirect=True)
def test_real_overlap_stays_unknown_in_durable_pixel_counts(vision_case):
    engine,actor,request,*_=vision_case;service=engine.evaluations
    job=service.create(actor,request=request,idempotency_key='unknown-pixels');finish(service,actor,job)
    summary=service.summary(actor,job['id']);page=service.examples(actor,job['id'])
    for side in ('baseline','candidate'):
        counts=summary['counts'][side]
        assert counts['measurements']==counts['unobservable_frames']==1
        assert counts['observable_frames']==counts['count_matches']==counts['count_mismatches']==0
        measured=page['examples'][0][side]['measurements'][0]
        assert measured['counts_match_declared_truth'] is None and not measured['count_comparison_observable']


def test_busy_shared_pool_fails_closed_without_refunding_attempt(vision_case):
    engine,actor,request,*_=vision_case;service=engine.evaluations
    job=service.create(actor,request=request,idempotency_key='busy-pixels')
    with engine.registry.diagnostic(runtime_id=engine.runtime.instance_id):
        result=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='busy-pixel-step')
    assert result['status']=='failed' and result['failure_reason']=='VISION_WORKER_UNAVAILABLE'
    assert result['steps_reserved']==1 and result['prepared_count']==0 and engine.registry._diagnostics=={}


@pytest.mark.parametrize('fault',['source','deadline'])
def test_final_vision_commit_rechecks_original_source_and_effective_deadline(world,vision_case,monkeypatch,fault):
    from proofpack.review.evaluations import entry_key,report_key
    engine,actor,request,ob,*_=vision_case;service=engine.evaluations
    job=service.create(actor,request=request,idempotency_key='final-pixels-'+fault)
    snapshot=world[1].snapshot;fresh=world[0]._fresh;ready=False;fired=False
    def read(keys):
        nonlocal ready
        result=snapshot(keys)
        if keys==(entry_key(job['id'],0),):ready=True
        return result
    def authorize(*args,**kwargs):
        nonlocal fired
        if ready and not fired:
            fired=True
            if fault=='source':
                key=Key('state','asset#'+ob.data['original_asset_id']);row=snapshot((key,))[key]
                world[1].transact((Write(key,row.revision,{**row.data,'read_denied':True}),))
            else:world[2].value=service._row(job['id']).data['effective_deadline_ms']
        return fresh(*args,**kwargs)
    monkeypatch.setattr(world[1],'snapshot',read);monkeypatch.setattr(world[0],'_fresh',authorize)
    with pytest.raises((Denied,StoreUnavailable,StoreConflict)):
        service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='final-pixel-step')
    assert fired and snapshot((entry_key(job['id'],0),report_key(job['id'])))[entry_key(job['id'],0)] is None
    assert snapshot((report_key(job['id']),))[report_key(job['id'])] is None and service._row(job['id']).data['steps_reserved']==1


def test_completed_report_uses_dependency_expiry_not_expired_execution_window(world,vision_case):
    engine,actor,request,*_=vision_case;service=engine.evaluations
    job=finish(service,actor,service.create(actor,request=request,idempotency_key='report-dependency-lifetime'))
    started=world[2]();world[2].value=started+engine.config.max_case_ms+1
    assert service.summary(actor,job['id'])['result_header_current'] is True
    assert len(service.examples(actor,job['id'])['examples'])==1
    world[2].value=int(service._row(job['id']).data['effective_deadline_ms'])
    assert service.summary(actor,job['id'])['result_header_current'] is False


def test_separate_report_lifetime_does_not_extend_case_window_at_final_commit(world,vision_case,monkeypatch):
    from proofpack.review.evaluations import entry_key,report_key
    engine,actor,request,*_=vision_case
    service=PolicyEvaluations(engine.evaluations.policies,engine.datasets,engine.evaluations.config,
        vision_registry=engine.registry,vision_config=VisionReplayConfig(max_case_ms=5000))
    job=service.create(actor,request=request,idempotency_key='shorter-case-window');created=world[2]();snapshot=world[1].snapshot;fresh=world[0]._fresh;ready=[False];fired=[False]
    def read(keys):
        result=snapshot(keys)
        if keys==(entry_key(job['id'],0),):ready[0]=True
        return result
    def expire(*args,**kwargs):
        if ready[0] and not fired[0]:fired[0]=True;world[2].value=created+5000
        return fresh(*args,**kwargs)
    monkeypatch.setattr(world[1],'snapshot',read);monkeypatch.setattr(world[0],'_fresh',expire)
    with pytest.raises((StoreConflict,StoreUnavailable,Denied)):
        service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='past-case-window')
    assert fired[0] and snapshot((entry_key(job['id'],0),report_key(job['id'])))[entry_key(job['id'],0)] is None
    assert snapshot((report_key(job['id']),))[report_key(job['id'])] is None
