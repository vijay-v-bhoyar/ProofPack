"""Real local OpenCV/database diagnostics, synthetic sources and intercepted S3."""
import json
from uuid import uuid4
import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

from test_access_lifecycle import world,repository_factory,invite_and_join,recipe_world,synthetic_recipe_qualification
from test_references import reference_case,upload
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied,Role
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Key,Write,StoreUnavailable,StoreConflict
from proofpack.recipes.service import RecipeService,catalog_key,qualification_key
from proofpack.recipes.qualification import RecipeQualifications,RecipeQualificationLimited,job_key,report_key
from proofpack.recipes.qualification_models import RecipeQualificationRequest
from proofpack.runtime.control import DATA
from proofpack.vision.fixtures import make_fixture,synthetic_profile,demo_recipe


@pytest.fixture
def qualification_case(world,reference_case):
    purposes,references,objects,metadata,image=reference_case
    positive=upload(world,reference_case,key='recipe-complete')
    missing,truth=make_fixture(0,'missing',seed=7);ok,encoded=cv2.imencode('.png',missing);assert ok
    negative=upload(world,reference_case,key='recipe-missing',payload=encoded.tobytes())
    ok,encoded=cv2.imencode('.png',np.full((64,64,3),255,np.uint8));assert ok
    challenge=upload(world,reference_case,key='recipe-challenge',payload=encoded.tobytes())
    profile=synthetic_profile();recipes=RecipeService(world[0],environment='test',artifact_sha256='a'*64)
    content=demo_recipe().model_dump(mode='json');content.pop('recipe_id');content.pop('revision');content['reference_asset_ids']=[positive['id']]
    created=recipes.create(world[5],content=content,idempotency_key='diagnostic-recipe')
    data=purposes.head();source,asset,receipt,expires=references.snapshot(world[5],positive['id']);purpose=source[Key('state','purpose#'+asset.data['purpose_id'])]
    manifest=[{'asset_id':asset.data['id'],'purpose_id':purpose.data['id'],'asset_state_version':asset.revision,'purpose_state_version':purpose.revision,'sha256':asset.data['sha256']}]
    rid=str(uuid4());dependency=str(uuid4());calreport={'id':rid,'calibration_id':profile.profile_id,'revision':profile.revision,
        'profile_sha256':profile.content_hash,'passed':True,'reference_manifest':manifest,'data_epoch':int(data.data['epoch']),
        'environment':'test','artifact_sha256':'a'*64,'expires_at_ms':expires};calreport['sha256']=digest(calreport)
    world[1].transact((Write(Key('state','calibration-active#'+profile.profile_id),None,{'status':'approved','environment':'test','data_origin':'synthetic',
        'profile_json':profile.model_dump_json(),'profile_sha256':profile.content_hash,'dependency_receipt_id':dependency}),
        Write(Key('state','calibration-dependencies#'+dependency),None,{'environment':'test','profile_sha256':profile.content_hash,
            'profile_state_version':1,'data_epoch':int(data.data['epoch']),'expires_at_ms':expires,'reference_manifest':manifest,'report_id':rid,'report_sha256':calreport['sha256']}),
        Write(Key('state','calibration-report#'+rid),None,calreport)))
    body={'cases':[{'asset_id':positive['id'],'kind':'complete','expected_findings':['SATISFIED']*4,'expected_counts':[1]*4},
        {'asset_id':negative['id'],'kind':'incorrect','expected_findings':['VIOLATED','SATISFIED','SATISFIED','SATISFIED'],'expected_counts':[0,1,1,1]},
        {'asset_id':challenge['id'],'kind':'challenge','expected_findings':['UNOBSERVABLE']*4,'expected_counts':[0]*4}]}
    service=RecipeQualifications(recipes,references,runs_per_minute=8,max_ms=15000)
    return service,created,RecipeQualificationRequest.model_validate_json(json.dumps(body)),objects


def run(world,case,*,key='qualify',request=None):
    service,created,spec,objects=case
    return service.run(world[5],ident=created['id'],expected_version=1,request=request or spec,idempotency_key=key)


def test_actual_case_measurements_complete_report_separate_approval_and_missing_dependency_denial(world,qualification_case):
    service,created,spec,objects=qualification_case;job=run(world,qualification_case)
    assert job['status']=='completed' and job['report_id']==job['id']
    report=service.report(world[5],created['id'],job['id'])
    assert report['passed'] and report['diagnostic_passed'] and all(r['matched'] for r in report['results'])
    assert report['physical_truth_verified'] is False and report['independence_verified'] is False
    assert service.recipes.list(world[5],view='approved')['recipes']==[]
    q=service.recipes.qualification(world[5],recipe_id=created['id'],qualification_id=job['id'])
    assert q['eligible_for_approval'] and q['state_version']==3
    assert run(world,qualification_case)==job
    service.recipes.approve(world[5],recipe_id=created['id'],expected_version=3,qualification_id=job['id'],idempotency_key='approve-diagnostic')
    rows,recipe,deadline=service.recipes.active_snapshot(created['id']);original=world[1].snapshot
    calkey=next(k for k in rows if k.resource.startswith('calibration-report#'))
    for missing in (report_key(job['id']),calkey):
        def snapshot(keys,missing=missing):
            result=original(keys)
            if missing in result:result[missing]=None
            return result
        world[1].snapshot=snapshot
        with pytest.raises(StoreUnavailable):service.recipes.active_snapshot(created['id'])
    world[1].snapshot=original


def test_failed_declared_case_is_retained_and_cannot_be_approved(world,qualification_case):
    service,created,spec,objects=qualification_case;body=spec.model_dump(mode='json');body['cases'][1]['expected_counts'][0]=2
    job=run(world,qualification_case,request=RecipeQualificationRequest.model_validate_json(json.dumps(body)))
    report=service.report(world[5],created['id'],job['id']);assert report['passed'] is False and report['results'][1]['matched'] is False
    with pytest.raises(StoreUnavailable):service.recipes.approve(world[5],recipe_id=created['id'],expected_version=3,qualification_id=job['id'],idempotency_key='bad-approve')


@pytest.mark.parametrize('fault',['purpose','epoch','expiry','role','draft'])
def test_source_or_actor_loss_during_slow_reads_prevents_publication_and_retry_does_not_rerun(world,qualification_case,fault):
    service,created,spec,objects=qualification_case;repo=world[1];calls=0
    def changed():
        nonlocal calls
        calls+=1
        if fault=='purpose':
            key=Key('state','asset#'+spec.cases[0].asset_id);asset=repo.snapshot((key,))[key];key=Key('state','purpose#'+asset.data['purpose_id']);row=repo.snapshot((key,))[key]
            repo.transact((Write(key,row.revision,{**row.data,'withdrawn':True}),))
        elif fault=='epoch':row=service.purposes.head();repo.transact((service.purposes.advance(row),))
        elif fault=='expiry':world[2].value+=15001
        elif fault=='draft':
            content=service.recipes.draft(world[5],created['id'])['content'];content['name']='Changed during qualification'
            service.recipes.save(world[5],recipe_id=created['id'],expected_version=2,content=content,idempotency_key='concurrent-draft')
        else:world[0].logout(world[4].cookie,world[4].csrf)
    objects.after_get=changed
    with pytest.raises((StoreUnavailable,StoreConflict,Denied)):run(world,qualification_case)
    assert repo.query(prefix='recipe-qualification#',limit=20)[0]==[]
    if fault!='role':assert run(world,qualification_case)['status']=='failed' and calls==1


def test_qualification_is_owner_only_and_uses_configured_allowance(world,qualification_case):
    service,created,spec,objects=qualification_case
    _,_,reviewer,_,_=invite_and_join(world,'qualification-reviewer',roles=(Role.REVIEWER,))
    with pytest.raises(Denied):service.run(reviewer,ident=created['id'],expected_version=1,request=spec,idempotency_key='reviewer')
    service.runs_per_minute=1;job=run(world,qualification_case)
    assert service.report(reviewer,created['id'],job['id'])['passed']
    with pytest.raises(RecipeQualificationLimited):service.run(world[5],ident=created['id'],expected_version=3,request=spec,idempotency_key='new-run')


@pytest.mark.parametrize('fault',['missing_report','corrupt_report','changed_manifest','changed_calibration'])
def test_private_recipe_witness_requires_intact_matching_report_and_calibration(world,recipe,fault):
    recipes,created,content=recipe_world(world,recipe);qid,qdata=synthetic_recipe_qualification(world,recipes,created,content);repo=world[1]
    if fault=='missing_report':
        original=repo.snapshot
        def snapshot(keys):
            result=original(keys)
            if report_key(qid) in result:result[report_key(qid)]=None
            return result
        repo.snapshot=snapshot
    elif fault=='corrupt_report':
        key=report_key(qid);row=repo.snapshot((key,))[key];repo.transact((Write(key,row.revision,{**row.data,'passed':False}),))
    elif fault=='changed_manifest':
        key=qualification_key(qid);row=repo.snapshot((key,))[key];repo.transact((Write(key,row.revision,{**row.data,'case_manifest':[qdata['reference_manifest'][0]]}),))
    else:
        key=Key('state','calibration-active#'+content['calibration_profile_id']);row=repo.snapshot((key,))[key];repo.transact((Write(key,row.revision,{**row.data,'restored':True}),))
    with pytest.raises(StoreUnavailable):recipes.approve(world[5],recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='report-fault')


def test_http_rejects_client_certification_and_returns_real_job_report(world,qualification_case):
    service,created,spec,objects=qualification_case
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,recipe_service=service.recipes,
        purpose_service=service.purposes,reference_service=service.references,recipe_qualification_service=service)
    url='/api/v1/recipes/'+created['id']+'/qualify';headers={'Origin':'https://proofpack.test','X-CSRF-Token':world[4].csrf,'Idempotency-Key':'http-qualify','If-Match':'1'}
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.post(url,json=spec.model_dump(mode='json'),headers=headers).status_code==401
        client.cookies.set(COOKIE,world[4].cookie)
        assert client.post(url,json={**spec.model_dump(mode='json'),'passed':True},headers=headers).status_code==400
        result=client.post(url,json=spec.model_dump(mode='json'),headers=headers);assert result.status_code==201
        job=result.json();assert job['status']=='completed' and result.headers['cache-control']=='no-store'
        assert client.get('/api/v1/recipe-qualification-jobs/'+job['id']).json()['id']==job['id']
        assert client.get('/api/v1/recipes/'+created['id']+'/qualification-reports/'+job['id']).json()['passed']
        service.runs_per_minute=1
        limited=client.post(url,json=spec.model_dump(mode='json'),headers={**headers,'Idempotency-Key':'limited-new-run','If-Match':'3'})
        assert limited.status_code==429 and limited.json()['code']=='RECIPE_QUALIFICATION_LIMIT' and limited.headers['retry-after']=='60'


def test_successful_owner_claimed_physical_scenes_cannot_create_public_physical_approval(world,qualification_case,monkeypatch):
    """Private calibration stand-in tests withholding only; no physical assurance is established."""
    from proofpack.recipes.models import Origin
    import proofpack.recipes.qualification as module
    service,created,spec,objects=qualification_case;repo=world[1]
    content=service.recipes.draft(world[5],created['id'])['content'];content['data_origin']='physical'
    service.recipes.save(world[5],recipe_id=created['id'],expected_version=1,content=content,idempotency_key='owner-claimed-physical')
    for case in spec.cases:
        key=Key('state','asset#'+case.asset_id);row=repo.snapshot((key,))[key]
        repo.transact((Write(key,row.revision,{**row.data,'data_origin':'physical'}),))
    profile=synthetic_profile().model_copy(update={'data_origin':Origin.PHYSICAL})
    key=Key('state','calibration-active#'+profile.profile_id);row=repo.snapshot((key,))[key]
    repo.transact((Write(key,row.revision,{**row.data,'data_origin':'physical','profile_json':profile.model_dump_json(),'profile_sha256':profile.content_hash}),))
    calibration=repo.snapshot((key,))[key]
    monkeypatch.setattr(module,'active_calibration',lambda *args:({key:calibration},calibration,world[2]()+30000))
    job=service.run(world[5],ident=created['id'],expected_version=2,request=spec,idempotency_key='physical-diagnostic')
    report=service.report(world[5],created['id'],job['id'])
    assert report['diagnostic_passed'] and report['passed'] is False and report['physical_truth_verified'] is False
    with pytest.raises(StoreUnavailable):service.recipes.approve(world[5],recipe_id=created['id'],expected_version=4,qualification_id=job['id'],idempotency_key='no-physical-shortcut')


def test_pending_job_blocks_conflicting_run_and_duplicate_returns_existing_job(world,qualification_case):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    service,created,spec,objects=qualification_case;entered=Event();release=Event();once=False
    def paused():
        nonlocal once
        if not once:
            once=True;entered.set();assert release.wait(15)
    objects.after_get=paused
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(run,world,qualification_case)
        try:
            assert entered.wait(10)
            duplicate=run(world,qualification_case);assert duplicate['status']=='processing'
            with pytest.raises(StoreConflict):service.run(world[5],ident=created['id'],expected_version=2,request=spec,idempotency_key='conflicting-run')
        finally:release.set()
        completed=future.result(timeout=20)
    assert completed['id']==duplicate['id'] and completed['status']=='completed'


def test_lost_reservation_confirmation_does_not_reexecute_and_requires_explicit_new_run_after_expiry(world,qualification_case):
    service,created,spec,objects=qualification_case;original=world[0]._record;lost=False
    def record(*args,**kwargs):
        nonlocal lost
        result=original(*args,**kwargs)
        if not lost and args[1].startswith('recipe-qualify:'):
            lost=True;raise StoreUnavailable('Synthetic lost reservation confirmation')
        return result
    world[0]._record=record
    with pytest.raises(StoreUnavailable):run(world,qualification_case)
    job=run(world,qualification_case);assert job['status']=='processing'
    assert world[1].query(prefix='recipe-qualification#',limit=20)[0]==[]
    world[2].value+=15001
    assert run(world,qualification_case)['status']=='expired'
    newer=service.run(world[5],ident=created['id'],expected_version=2,request=spec,idempotency_key='explicit-new-run')
    assert newer['status']=='completed' and newer['id']!=job['id']


def test_lost_completion_confirmation_preserves_one_completed_report_and_replays_without_measurement(world,qualification_case):
    service,created,spec,objects=qualification_case;original=world[0]._commit;lost=False;reads=0
    def counted():
        nonlocal reads
        reads+=1
    objects.after_get=counted
    def commit(writes,*args,**kwargs):
        nonlocal lost
        result=original(writes,*args,**kwargs)
        if not lost and any(w.key.resource.startswith('recipe-qualification#') for w in writes):
            lost=True;raise StoreUnavailable('Synthetic lost completion confirmation')
        return result
    world[0]._commit=commit
    with pytest.raises(StoreUnavailable):run(world,qualification_case)
    result=run(world,qualification_case)
    assert result['status']=='completed' and reads==3
    assert service.report(world[5],created['id'],result['id'])['passed']


def test_changed_operational_notice_invalidates_an_otherwise_intact_private_qualification(world,recipe):
    from dataclasses import replace
    service,created,content=recipe_world(world,recipe);qid,qdata=synthetic_recipe_qualification(world,service,created,content)
    service.approve(world[5],recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='notice-baseline')
    service.access.config=replace(service.access.config,notice_version='changed-notice')
    with pytest.raises(StoreUnavailable):service.active_snapshot(created['id'])


def test_newer_failed_run_prevents_approval_with_older_passing_qualification(world,qualification_case):
    service,created,spec,objects=qualification_case;first=run(world,qualification_case)
    body=spec.model_dump(mode='json');body['cases'][1]['expected_counts'][0]=2
    newer=service.run(world[5],ident=created['id'],expected_version=3,request=RecipeQualificationRequest.model_validate_json(json.dumps(body)),idempotency_key='newer-failed-comparison')
    assert service.report(world[5],created['id'],newer['id'])['passed'] is False
    with pytest.raises(StoreUnavailable):service.recipes.approve(world[5],recipe_id=created['id'],expected_version=5,qualification_id=first['id'],idempotency_key='no-old-pass-bypass')
    older=service.recipes.qualification(world[5],recipe_id=created['id'],qualification_id=first['id'])
    assert older['passed'] and older['eligible_for_approval'] is False and 'SUPERSEDED_QUALIFICATION' in older['reason_codes']
    assert service.report(world[5],created['id'],first['id'])['eligible_for_approval'] is False


def test_pending_new_run_holds_older_approval_without_discarding_its_report(world,qualification_case):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    service,created,spec,objects=qualification_case;first=run(world,qualification_case);entered=Event();release=Event();paused=False
    def wait_for_review():
        nonlocal paused
        if not paused:paused=True;entered.set();assert release.wait(15)
    objects.after_get=wait_for_review
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(service.run,world[5],ident=created['id'],expected_version=3,request=spec,idempotency_key='pending-new-run')
        try:
            assert entered.wait(10)
            with pytest.raises(StoreUnavailable):service.recipes.approve(world[5],recipe_id=created['id'],expected_version=4,qualification_id=first['id'],idempotency_key='hold-old-pass')
        finally:release.set()
        newer=future.result(timeout=20)
    assert newer['status']=='completed' and service.report(world[5],created['id'],newer['id'])['passed']
