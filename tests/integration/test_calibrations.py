"""Actual local calibration CV/database paths; intercepted S3 and synthetic scene truth."""
import hashlib
import json
from uuid import uuid4

import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

from test_access_lifecycle import world,repository_factory,invite_and_join
from test_references import reference_case,upload
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied,Role
from proofpack.calibrations.models import Enrollment,DiagnosticCase,QualificationRequest,PhysicalReview
from proofpack.calibrations.service import CalibrationService,active_key,catalog_key,revision_key,report_key,digest
from proofpack.recipes.models import Origin
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.runtime.control import DATA
from proofpack.vision.calibration_diagnostics import CalibrationSettings


@pytest.fixture
def calibration_case(world,reference_case,request):
    purposes,references,objects,metadata,image=reference_case
    metadata=metadata.model_copy(update={'data_origin':getattr(request,'param',metadata.data_origin)})
    positive=upload(world,reference_case,key='positive',metadata=metadata)
    ok,blank=cv2.imencode('.png',np.full((64,64,3),255,np.uint8));assert ok
    negative=upload(world,reference_case,key='negative',payload=blank.tobytes(),metadata=metadata)
    service=CalibrationService(references,max_runs_per_minute=8,max_diagnostic_ms=15000)
    enrollment=Enrollment(name='Synthetic camera enrollment',camera_id='fixture-camera',mat_version='desktop-v1',reference_asset_id=positive['id'],
        data_origin=metadata.data_origin,settings=CalibrationSettings(max_displacement_px=2.,max_reprojection_error_px=1.,measurement_error_mm=.5,
            min_area_px=30.,min_blur_variance=1.,threshold_gray=127))
    cases=QualificationRequest(cases=(DiagnosticCase(asset_id=positive['id'],expected='supported'),DiagnosticCase(asset_id=negative['id'],expected='rejected')))
    return service,enrollment,cases,positive,negative


def enrolled(world,case):
    service,request,cases,positive,negative=case
    job=service.enroll(world[5],request=request,idempotency_key='enroll')
    assert job['status']=='completed'
    return job['calibration_id'],service.draft(world[5],job['calibration_id'])


def qualified(world,case):
    service,request,cases,positive,negative=case;ident,draft=enrolled(world,case)
    assert draft['profile'] is not None,draft
    job=service.qualify(world[5],ident=ident,expected_version=draft['state_version'],request=cases,idempotency_key='qualify')
    return ident,service.draft(world[5],ident),job


def test_actual_enrollment_detects_and_binds_profile_without_client_corners_or_activation(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft=enrolled(world,calibration_case)
    assert draft['status']=='draft' and draft['profile']['camera_id']==request.camera_id
    assert draft['enrollment']['accepted'] is True and draft['enrollment']['source_sha256']==positive['sha256']
    assert draft['enrollment']['physical_truth_verified'] is False and draft['current']['effective_approved'] is False
    assert len(draft['profile']['enrolled_image_corners'])==4 and world[1].snapshot((active_key(ident),))[active_key(ident)] is None
    retry=service.enroll(world[5],request=request,idempotency_key='enroll');assert retry['calibration_id']==ident
    assert len(world[1].query(prefix='calibration#',limit=20)[0])==1


def test_actual_positive_negative_diagnostic_report_approves_only_matching_nonbeta_scope(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    report=service.report(world[5],ident,job['report_id']);assert report['passed'] is True and report['eligible_for_approval'] is True
    assert [case['diagnostic']['accepted'] for case in report['results']]==[True,False]
    assert report['physical_truth_verified'] is False and report['independence_verified'] is False
    current=service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=report['id'],idempotency_key='approve')
    assert current['current']['effective_approved'] is True
    assert service.list(world[5],view='approved')['calibrations'][0]['id']==ident
    from proofpack.calibrations.dependencies import active_calibration
    rows,active,deadline=active_calibration(world[1],world[0],service.runtime,ident)
    assert active.data['profile_sha256']==draft['profile_sha256'] and deadline>world[2]()
    replay=service.qualify(world[5],ident=ident,expected_version=1,request=cases,idempotency_key='qualify')
    # Original If-Match was one; approval advanced the head but replay never reruns.
    assert replay['id']==job['id']


def test_failed_diagnostic_is_preserved_and_cannot_activate(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft=enrolled(world,calibration_case)
    wrong=QualificationRequest(cases=(DiagnosticCase(asset_id=positive['id'],expected='rejected'),DiagnosticCase(asset_id=negative['id'],expected='supported')))
    job=service.qualify(world[5],ident=ident,expected_version=draft['state_version'],request=wrong,idempotency_key='wrong-case-labels')
    report=service.report(world[5],ident,job['report_id']);assert report['passed'] is False and not report['eligible_for_approval']
    with pytest.raises(Denied):service.approve(world[5],ident=ident,expected_version=report['state_version'],report_id=report['id'],idempotency_key='approve-failed')
    assert world[1].snapshot((active_key(ident),))[active_key(ident)] is None


def test_missing_qualification_report_withdraws_effective_calibration(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],idempotency_key='approve')
    repository=world[1];key=report_key(job['report_id'])
    # Isolated local-store loss injection, simulating an incomplete restore.
    repository.client.delete_item(TableName=repository.tables[key.table],Key=repository.key(key))
    assert service.draft(world[5],ident)['current']['effective_approved'] is False
    assert service.list(world[5],view='approved')['calibrations']==[]
    from proofpack.calibrations.dependencies import active_calibration
    with pytest.raises(StoreUnavailable):active_calibration(repository,world[0],service.runtime,ident)


def replace_private_data(repository,key,data,*,revision=1):
    """Local corruption/partial-restore fault; never an application write route."""
    repository.client.update_item(TableName=repository.tables[key.table],Key=repository.key(key),
        UpdateExpression='SET #data=:data, #revision=:revision',
        ExpressionAttributeNames={'#data':'data','#revision':'revision'},
        ExpressionAttributeValues={':data':repository.serialize.serialize(data),':revision':{'N':str(revision)}})


@pytest.mark.parametrize('fault',['content_hash','immutable_revision','id','calibration_id','profile_sha256','revision',
    'passed','environment','artifact_sha256','data_epoch','reference_manifest','expires_at_ms','missing_receipt_report'])
def test_corrupt_or_mismatched_report_cannot_support_effective_calibration(world,calibration_case,fault):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],idempotency_key='approve')
    repo=world[1];active=repo.snapshot((active_key(ident),))[active_key(ident)]
    receiptkey=Key('state','calibration-dependencies#'+active.data['dependency_receipt_id']);rkey=report_key(job['report_id'])
    rows=repo.snapshot((receiptkey,rkey));receipt=dict(rows[receiptkey].data);report=dict(rows[rkey].data)
    faults={'id':str(uuid4()),'calibration_id':str(uuid4()),'profile_sha256':'e'*64,'revision':2,'passed':False,
        'environment':'other','artifact_sha256':'e'*64,'data_epoch':2,'reference_manifest':[], 'expires_at_ms':world[2]()}
    if fault=='content_hash':report['passed']=False  # Original hash must detect changed content.
    elif fault=='missing_receipt_report':receipt.pop('report_id')
    elif fault!='immutable_revision':
        report[fault]=faults[fault]
        # Simulate a coherent wrong restore, so binding checks cannot rely only on the checksum.
        report['sha256']=digest({k:v for k,v in report.items() if k!='sha256'});receipt['report_sha256']=report['sha256']
    replace_private_data(repo,rkey,report,revision=2 if fault=='immutable_revision' else 1)
    replace_private_data(repo,receiptkey,receipt)
    assert service.draft(world[5],ident)['current']['effective_approved'] is False
    assert service.list(world[5],view='approved')['calibrations']==[]


def test_report_disappearing_before_final_read_cannot_return_approval(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],idempotency_key='approve')
    repo=world[1];rkey=report_key(job['report_id']);original=repo.snapshot;reads=0
    def snapshot(keys):
        nonlocal reads
        if rkey in keys:
            reads+=1
            if reads==2:repo.client.delete_item(TableName=repo.tables[rkey.table],Key=repo.key(rkey))
        return original(keys)
    repo.snapshot=snapshot
    with pytest.raises(StoreConflict):service.draft(world[5],ident)
    assert reads==2


def test_save_is_immutable_and_idempotent_and_does_not_silently_replace_active_profile(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    approved=service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],idempotency_key='approve')
    first=world[1].snapshot((revision_key(ident,1),))[revision_key(ident,1)]
    changed=request.model_copy(update={'name':'Next camera draft'})
    saved=service.enroll(world[5],request=changed,ident=ident,expected_version=approved['state_version'],idempotency_key='save')
    current=service.draft(world[5],ident)
    assert current['latest_revision']==2 and current['report_id'] is None and current['current']['active_revision']==1
    assert world[1].snapshot((first.key,))[first.key]==first
    assert service.enroll(world[5],request=changed,ident=ident,expected_version=approved['state_version'],idempotency_key='save')['id']==saved['id']


def test_withdrawn_sources_invalidate_report_and_approved_calibration(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],idempotency_key='approve')
    service.purposes.withdraw(world[5],ident=positive['purpose_id'],expected_version=1,idempotency_key='withdraw')
    assert service.draft(world[5],ident)['current']['effective_approved'] is False
    with pytest.raises(StoreUnavailable):service.report(world[5],ident,job['report_id'])


def test_revocation_during_reference_fetch_cannot_publish_enrollment(world,calibration_case):
    service,request,cases,positive,negative=calibration_case
    service.objects.after_get=lambda:world[0].revoke_sessions(world[5],user_id=world[3],expected_version=1,idempotency_key='revoke')
    with pytest.raises(Denied):service.enroll(world[5],request=request,idempotency_key='revoked-enroll')
    assert world[1].query(prefix='calibration#',limit=20)[0]==[]
    jobs=world[1].query(prefix='calibration-job#',limit=20)[0];assert jobs[0].data['status']=='failed'


def test_retirement_invalidates_active_binding_and_preserves_immutable_report(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    approved=service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],idempotency_key='approve')
    report=world[1].snapshot((report_key(job['report_id']),))[report_key(job['report_id'])]
    retired=service.retire(world[5],ident=ident,expected_version=approved['state_version'],reason='camera moved',idempotency_key='retire')
    assert retired['retired'] is True and retired['current']['effective_approved'] is False
    assert world[1].snapshot((report.key,))[report.key]==report


def test_calibration_http_requires_roles_csrf_versions_and_rejects_client_pass_fields(world,calibration_case):
    service,request,cases,positive,negative=calibration_case
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,purpose_service=service.purposes,reference_service=service.references,calibration_service=service)
    _,credentials,operator,_,_=invite_and_join(world)
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.get('/api/v1/calibrations/mat').status_code==401
        client.cookies.set(COOKIE,credentials.cookie);assert client.get('/api/v1/calibrations/mat').status_code==200
        assert client.get('/api/v1/calibrations?view=candidates').status_code==403
        assert client.post('/api/v1/calibrations',json=request.model_dump(mode='json'),headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'operator'}).status_code==403
        client.cookies.set(COOKIE,world[4].cookie);headers={'Origin':'https://proofpack.test','X-CSRF-Token':world[4].csrf,'Idempotency-Key':'http-enroll'}
        assert client.post('/api/v1/calibrations',json={**request.model_dump(mode='json'),'passed':True},headers=headers).status_code==400
        response=client.post('/api/v1/calibrations',json=request.model_dump(mode='json'),headers=headers);assert response.status_code==201,response.text
        ident=response.json()['calibration_id'];draft=client.get('/api/v1/calibrations/'+ident+'/draft').json()
        assert draft['enrollment']['accepted'] is True


def test_retirement_during_reenrollment_cannot_resurrect_or_publish_a_new_revision(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    approved=service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],idempotency_key='approve')
    def retire_during_get():
        service.objects.after_get=None
        current=world[1].snapshot((catalog_key(ident),))[catalog_key(ident)]
        service.retire(world[5],ident=ident,expected_version=current.revision,reason='stop during enrollment',idempotency_key='stop-mid-enrollment')
    service.objects.after_get=retire_during_get
    with pytest.raises(StoreConflict):service.enroll(world[5],request=request.model_copy(update={'name':'Next draft'}),ident=ident,expected_version=approved['state_version'],idempotency_key='interrupted-save')
    current=service.draft(world[5],ident)
    assert current['retired'] is True and current['status']=='retired' and current['current']['effective_approved'] is False
    assert world[1].snapshot((revision_key(ident,2),))[revision_key(ident,2)] is None


@pytest.mark.parametrize('calibration_case',[Origin.PHYSICAL],indirect=True)
def test_declared_physical_origin_and_passing_geometry_do_not_supply_physical_assurance(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    report=service.report(world[5],ident,job['report_id'])
    assert report['passed'] and report['requires_physical_assurance'] and not report['eligible_for_approval']
    assert positive['physical_truth_verified'] is False
    with pytest.raises(Denied):service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],idempotency_key='no-physical-proof')
    assert world[1].snapshot((active_key(ident),))[active_key(ident)] is None


def synthetic_private_assurance(world,case,ident,job,*,changes=None):
    """Private synthetic binding fixture; not actual ruler/lens/physical evidence."""
    service,request,cases,positive,negative=case
    reviewer,_,_,_,_=invite_and_join(world,subject='physical-review-fixture',roles=(Role.REVIEWER,))
    draft=service.draft(world[5],ident);report=world[1].snapshot((report_key(job['report_id']),))[report_key(job['report_id'])].data
    review=PhysicalReview(ruler_nominal_mm=100.,ruler_measured_mm=100.,ruler_uncertainty_mm=.1,lens_residual_px=.1,
        lens_evidence_asset_ids=(positive['id'],),scope_evidence_asset_ids=(positive['id'],negative['id']),camera_id=request.camera_id,
        reviewed_by=reviewer,reviewer_access_version=1,independence_verified=True).model_copy(update=changes or {})
    text=review.model_dump_json();ident_assurance=str(uuid4())
    record={'status':'approved','profile_sha256':draft['profile_sha256'],'report_sha256':report['sha256'],
        'source_manifest_sha256':digest(report['reference_manifest']),'review_json':text,'review_sha256':hashlib.sha256(text.encode()).hexdigest(),
        'environment':service.runtime.environment,'artifact_sha256':service.runtime.artifact_sha256,'data_epoch':report['data_epoch'],
        'expires_at_ms':world[2]()+40000,'checks':{name:True for name in ('measured_ruler','lens','physical_sources','scope_review')}}
    world[1].transact((Write(Key('state','physical-calibration-assurance#'+ident_assurance),None,record),))
    return ident_assurance,reviewer


@pytest.mark.parametrize('calibration_case',[Origin.PHYSICAL],indirect=True)
def test_private_physical_binding_is_targeted_and_reviewer_revocation_withdraws_effective_approval(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    assurance,reviewer=synthetic_private_assurance(world,calibration_case,ident,job)
    approved=service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],physical_assurance_id=assurance,idempotency_key='physical-fixture-approve')
    assert approved['current']['effective_approved'] is True
    world[0].change_access(world[5],user_id=reviewer,roles=[],enabled=False,expected_version=1,idempotency_key='disable-reviewer')
    assert service.draft(world[5],ident)['current']['effective_approved'] is False
    assert service.list(world[5],view='approved')['calibrations']==[]
    replay=service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],physical_assurance_id=assurance,idempotency_key='physical-fixture-approve')
    assert replay['current']['effective_approved'] is False


@pytest.mark.parametrize('calibration_case',[Origin.PHYSICAL],indirect=True)
@pytest.mark.parametrize('changes',[{'ruler_measured_mm':80.},{'lens_residual_px':2.},{'scope_evidence_asset_ids':('foreign',)},{'reviewed_by':'00000000-0000-4000-8000-000000000099'}])
def test_private_physical_flags_cannot_replace_valid_ruler_lens_source_and_reviewer_bindings(world,calibration_case,changes):
    service,request,cases,positive,negative=calibration_case;ident,draft,job=qualified(world,calibration_case)
    assurance,reviewer=synthetic_private_assurance(world,calibration_case,ident,job,changes=changes)
    with pytest.raises(StoreUnavailable):service.approve(world[5],ident=ident,expected_version=draft['state_version'],report_id=job['report_id'],physical_assurance_id=assurance,idempotency_key='bad-physical-fixture')
    assert world[1].snapshot((active_key(ident),))[active_key(ident)] is None


def test_retirement_during_qualification_keeps_retired_state_and_publishes_no_new_report(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft=enrolled(world,calibration_case)
    def stop():
        service.objects.after_get=None;head=world[1].snapshot((catalog_key(ident),))[catalog_key(ident)]
        service.retire(world[5],ident=ident,expected_version=head.revision,reason='retired during test',idempotency_key='stop-qualify')
    service.objects.after_get=stop
    with pytest.raises(StoreConflict):service.qualify(world[5],ident=ident,expected_version=draft['state_version'],request=cases,idempotency_key='interrupted-qualify')
    assert service.draft(world[5],ident)['status']=='retired'
    assert world[1].query(prefix='calibration-report#',limit=20)[0]==[]


def test_data_epoch_change_during_diagnostic_cannot_publish_report(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;ident,draft=enrolled(world,calibration_case);reads=0
    def changed():
        nonlocal reads
        reads+=1
        if reads==2:
            row=world[1].snapshot((DATA,))[DATA];world[1].transact((Write(DATA,row.revision,{**row.data,'epoch':row.data['epoch']+1}),))
    service.objects.after_get=changed
    with pytest.raises(StoreConflict):service.qualify(world[5],ident=ident,expected_version=draft['state_version'],request=cases,idempotency_key='epoch-changed')
    assert world[1].query(prefix='calibration-report#',limit=20)[0]==[]
    assert service.draft(world[5],ident)['status']=='qualification_failed'


def test_diagnostic_deadline_failure_is_not_reprocessed_by_an_exact_retry(world,calibration_case):
    service,request,cases,positive,negative=calibration_case;reads=0
    def expire():
        nonlocal reads
        reads+=1;world[2].value+=15001
    service.objects.after_get=expire
    with pytest.raises(StoreUnavailable):service.enroll(world[5],request=request,idempotency_key='deadline')
    assert world[1].query(prefix='calibration#',limit=20)[0]==[]
    retry=service.enroll(world[5],request=request,idempotency_key='deadline')
    assert retry['status']=='failed' and reads==1


def test_runtime_replacement_during_reference_fetch_cannot_publish_old_enrollment(world,calibration_case):
    from test_access_lifecycle import runtime_service
    service,request,cases,positive,negative=calibration_case
    service.objects.after_get=lambda:runtime_service(world).start()
    with pytest.raises(StoreConflict):service.enroll(world[5],request=request,idempotency_key='old-runtime')
    assert world[1].query(prefix='calibration#',limit=20)[0]==[]
    assert world[1].query(prefix='calibration-job#',limit=20)[0][0].data['status']=='failed'


def test_quota_denial_does_not_create_unbounded_jobs_and_exact_retry_consumes_no_new_allowance(world,calibration_case):
    from proofpack.calibrations.service import CalibrationRateLimited
    original,request,cases,positive,negative=calibration_case
    service=CalibrationService(original.references,max_runs_per_minute=1,max_diagnostic_ms=15000)
    first=service.enroll(world[5],request=request,idempotency_key='one-allowed')
    assert service.enroll(world[5],request=request,idempotency_key='one-allowed')['id']==first['id']
    with pytest.raises(CalibrationRateLimited):service.enroll(world[5],request=request,idempotency_key='over-allowance')
    assert len(world[1].query(prefix='calibration-job#',limit=20)[0])==1
