"""Owned database and exact SDK erasure protocol; no real AWS or full erasure proof."""
from dataclasses import replace
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from test_access_lifecycle import world,repository_factory,publication_case,invite_and_join,proof
from test_references import reference_case,upload
from test_asset_reads import frame_read_case
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied,Role
from proofpack.evidence.objects import EvidenceObjects,ReferenceObjects
from proofpack.evidence.erasure import AssetErasure,ErasureLimited,job_key,preview_key
from proofpack.evidence.erasure_models import ErasurePreview,ErasureConfirmation
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.runtime.control import DATA
from proofpack.runtime.control import RuntimeControl


@pytest.fixture
def erasure_case(world,reference_case):
    purposes,references,objects,metadata,image=reference_case;asset=upload(world,reference_case)
    service=AssetErasure(purposes,EvidenceObjects(objects.client,objects.config),objects,review_ms=30000,jobs_per_minute=8,lease_ms=15000,version_page_size=3)
    return service,asset['id'],objects.stub,references


def reviewed(world,case):
    service,ident,stub,references=case
    preview=service.preview(world[5],request=ErasurePreview(asset_ids=(ident,)),idempotency_key='preview')
    request=ErasureConfirmation(preview_id=preview['id'],confirmed_digest=preview['scope_sha256'],erase_asset_versions_acknowledged=True,understands_remaining_metadata_and_backups=True)
    return preview,request


def commit(world,case):
    preview,request=reviewed(world,case)
    return case[0].confirm(world[5],request=request,expected_version=preview['state_version'],idempotency_key='confirm')


def test_cleanup_reference_is_private_and_manual_lease_refresh_does_not_widen_scope(world,erasure_case):
    from proofpack.evidence.job_authority import resolve
    service=erasure_case[0];job=commit(world,erasure_case)
    row=world[1].snapshot((job_key(job['id']),))[job_key(job['id'])]
    original=row.data['processing_authority']
    assert resolve(service.access,row.data).member.data['id']==world[3]
    assert 'processing_authority' not in job and 'cookie_ref' not in str(job)
    world[2].value+=1
    list_page(erasure_case)
    result=service.advance(world[5],job['id'],expected_version=job['state_version'],idempotency_key='authority-step')
    current=world[1].snapshot((job_key(job['id']),))[job_key(job['id'])]
    assert result['status']=='metadata_pending' and not result['erasure_complete']
    assert current.data['scope']==row.data['scope']
    assert current.data['processing_authority']['body']['issued_at_ms']==world[2]()
    assert current.data['processing_authority']['body']['expires_at_ms']==original['body']['expires_at_ms']


def list_page(case,versions=(),*,foreign=False,truncated=False):
    service,ident,stub,references=case;kind='reference';key=service.objects.store(kind).key(ident)
    stub.add_response('list_object_versions',{'IsTruncated':truncated,'Versions':[{'Key':key+('-foreign' if foreign else ''),'VersionId':v} for v in versions]},
        {'Bucket':service.objects.config.bucket,'ExpectedBucketOwner':service.objects.config.account_id,'Prefix':key,'MaxKeys':3})


def delete_page(case,versions,*,partial=False,lost=False):
    service,ident,stub,references=case;key=service.objects.references.key(ident);items=[{'Key':key,'VersionId':v} for v in versions]
    params={'Bucket':service.objects.config.bucket,'ExpectedBucketOwner':service.objects.config.account_id,'Delete':{'Objects':items,'Quiet':False}}
    if lost:stub.add_client_error('delete_objects',service_error_code='ServiceUnavailable',http_status_code=503,expected_params=params)
    else:stub.add_response('delete_objects',{'Deleted':items[:-1] if partial else items,'Errors':[{**items[-1],'Code':'AccessDenied','Message':'Synthetic retained version'}] if partial else []},params)


def step(world,case,job,key):return case[0].advance(world[5],job['id'],expected_version=job['state_version'],idempotency_key=key)


def test_review_commit_denies_immediately_and_version_cleanup_never_claims_full_erasure(world,erasure_case):
    service,ident,stub,references=erasure_case;preview,request=reviewed(world,erasure_case);before=service.purposes.head()
    assert preview['can_confirm'] and references.get(world[5],ident)['read_denied'] is False
    job=service.confirm(world[5],request=request,expected_version=1,idempotency_key='confirm')
    assert service.purposes.head().data['epoch']==before.data['epoch']+1
    with pytest.raises(StoreUnavailable):references.get(world[5],ident)
    assert service.confirm(world[5],request=request,expected_version=1,idempotency_key='confirm')['id']==job['id']
    assert service.purposes.head().data['epoch']==before.data['epoch']+1
    list_page(erasure_case,('v1','null'));delete_page(erasure_case,('v1','null'))
    job=step(world,erasure_case,job,'batch');assert job['status']=='queued' and job['assets'][0]['delete_acknowledgments']==2
    list_page(erasure_case)
    job=step(world,erasure_case,job,'verify');assert job['status']=='metadata_pending' and job['assets'][0]['live_versions_removed']
    assert job['assets'][0]['checked_at_ms']==world[2]() and job['erasure_complete'] is False
    assert not job['dependent_metadata_erased'] and not job['backups_erased'] and not job['downloaded_copies_recalled']
    assert service.advance(world[5],job['id'],expected_version=1,idempotency_key='batch')['status']=='metadata_pending'
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('fault',['digest','version','expiry','asset','epoch','other_owner'])
def test_stale_changed_or_reassigned_review_cannot_commit_denial(world,erasure_case,fault):
    service,ident,stub,references=erasure_case;preview,request=reviewed(world,erasure_case);actor=world[5];expected=1
    if fault=='digest':request=request.model_copy(update={'confirmed_digest':'f'*64})
    elif fault=='version':expected=2
    elif fault=='expiry':world[2].value+=30000
    elif fault=='epoch':row=service.purposes.head();world[1].transact((service.purposes.advance(row),))
    elif fault=='asset':
        key=Key('state','asset#'+ident);row=world[1].snapshot((key,))[key];world[1].transact((Write(key,row.revision,{**row.data,'changed':True}),))
    else:_,_,actor,_,_=invite_and_join(world,'other-erasure-owner',roles=(Role.OWNER,),mfa=True)
    with pytest.raises((StoreConflict,Denied)):service.confirm(actor,request=request,expected_version=expected,idempotency_key='confirm')
    assert world[1].snapshot((Key('state','asset#'+ident),))[Key('state','asset#'+ident)].data['read_denied'] is False


@pytest.mark.parametrize('fault',['partial','lost','foreign'])
def test_partial_unknown_or_foreign_storage_results_keep_denial_and_require_relisting(world,erasure_case,fault):
    service,ident,stub,references=erasure_case;job=commit(world,erasure_case)
    list_page(erasure_case,('v1','v2'),foreign=fault=='foreign')
    if fault!='foreign':delete_page(erasure_case,('v1','v2'),partial=fault=='partial',lost=fault=='lost')
    job=step(world,erasure_case,job,'first-step');assert job['status']=='queued' and job['last_error'] and job['erasure_complete'] is False
    with pytest.raises(StoreUnavailable):references.get(world[5],ident)
    assert service.advance(world[5],job['id'],expected_version=1,idempotency_key='first-step')['state_version']==job['state_version']
    list_page(erasure_case)
    assert step(world,erasure_case,job,'relist')['status']=='metadata_pending'
    stub.assert_no_pending_responses()


def test_original_storage_binding_missing_or_changed_cannot_be_repointed_to_new_bucket(world,erasure_case):
    service,ident,stub,references=erasure_case;key=Key('state','asset#'+ident);row=world[1].snapshot((key,))[key]
    world[1].transact((Write(key,row.revision,{k:v for k,v in row.data.items() if k!='storage_binding_sha256'}),))
    with pytest.raises(StoreUnavailable):reviewed(world,erasure_case)
    assert world[1].snapshot((key,))[key].data['read_denied'] is False


def test_erasure_admission_and_reads_are_owner_only(world,erasure_case):
    service,ident,stub,references=erasure_case
    _,_,reviewer,_,_=invite_and_join(world,'privacy-reviewer',roles=(Role.REVIEWER,))
    with pytest.raises(Denied):service.preview(reviewer,request=ErasurePreview(asset_ids=(ident,)),idempotency_key='reviewer')
    job=commit(world,erasure_case)
    with pytest.raises(Denied):service.job(reviewer,job['id'])
    with pytest.raises(Denied):service.advance(reviewer,job['id'],expected_version=1,idempotency_key='reviewer-step')


def test_committed_frame_is_immediately_unreadable_to_its_operator_and_reviewer(world,frame_read_case):
    reads,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case
    service=AssetErasure(reads.purposes,objects,ReferenceObjects(objects.client,objects.config),review_ms=30000,jobs_per_minute=8,lease_ms=15000,version_page_size=3)
    ident=asset.data['id'];assert reads.read(operator,ident)['can_download']
    preview=service.preview(world[5],request=ErasurePreview(asset_ids=(ident,)),idempotency_key='frame-preview')
    confirmation=ErasureConfirmation(preview_id=preview['id'],confirmed_digest=preview['scope_sha256'],erase_asset_versions_acknowledged=True,understands_remaining_metadata_and_backups=True)
    service.confirm(world[5],request=confirmation,expected_version=1,idempotency_key='frame-denial')
    for actor in (operator,reviewer):
        with pytest.raises(StoreUnavailable):reads.read(actor,ident,binary=True)


def test_http_requires_strict_acknowledgment_and_committed_jobs_cannot_be_cancelled(world,erasure_case):
    service,ident,stub,references=erasure_case
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,purpose_service=service.purposes,erasure_service=service)
    headers={'Origin':'https://proofpack.test','X-CSRF-Token':world[4].csrf,'Idempotency-Key':'http-preview'}
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.post('/api/v1/privacy/deletion-previews',json={'asset_ids':[ident]},headers=headers).status_code==401
        client.cookies.set(COOKIE,world[4].cookie)
        preview=client.post('/api/v1/privacy/deletion-previews',json={'asset_ids':[ident]},headers=headers).json()
        body={'preview_id':preview['id'],'confirmed_digest':preview['scope_sha256'],'erase_asset_versions_acknowledged':1,'understands_remaining_metadata_and_backups':True}
        confirm_headers={**headers,'Idempotency-Key':'http-confirm','If-Match':'1'}
        assert client.post('/api/v1/privacy/deletions',json=body,headers=confirm_headers).status_code==400
        body['erase_asset_versions_acknowledged']=True
        result=client.post('/api/v1/privacy/deletions',json=body,headers=confirm_headers);assert result.status_code==201 and result.headers['cache-control']=='no-store'
        job=result.json();assert client.get('/api/v1/jobs/'+job['id']).json()['erasure_complete'] is False
        assert client.post('/api/v1/jobs/'+job['id']+'/cancel',json={},headers={**confirm_headers,'Idempotency-Key':'no-cancel'}).status_code==409


@pytest.mark.parametrize('phase',['asset_lookup','final_authorization'])
def test_review_expiring_during_confirmation_cannot_commit_denial(world,erasure_case,phase):
    service,ident,stub,references=erasure_case;preview,request=reviewed(world,erasure_case)
    if phase=='asset_lookup':
        original=service._asset
        def asset(value):
            result=original(value);world[2].value+=30000;return result
        service._asset=asset
    else:
        original=world[0]._fresh;calls=0
        def fresh(actor,role=None,**kwargs):
            nonlocal calls
            result=original(actor,role,**kwargs)
            if role==Role.OWNER:
                calls+=1
                if calls==2:world[2].value+=30000
            return result
        world[0]._fresh=fresh
    with pytest.raises(StoreConflict):service.confirm(world[5],request=request,expected_version=1,idempotency_key='expired-during-confirmation')
    key=Key('state','asset#'+ident);assert world[1].snapshot((key,))[key].data['read_denied'] is False


def test_changed_storage_configuration_cannot_repoint_a_committed_job(world,erasure_case):
    service,ident,stub,references=erasure_case;job=commit(world,erasure_case)
    config=replace(service.objects.config,bucket='different-owned-bucket')
    changed=AssetErasure(service.purposes,EvidenceObjects(service.objects.frames.client,config),ReferenceObjects(service.objects.references.client,config),
        review_ms=30000,jobs_per_minute=8,lease_ms=15000,version_page_size=3)
    assert changed.job(world[5],job['id'])['target_matches_current_config'] is False
    with pytest.raises(StoreUnavailable):changed.advance(world[5],job['id'],expected_version=job['state_version'],idempotency_key='changed-storage')
    assert service.job(world[5],job['id'])['state_version']==job['state_version']


def test_confirmation_commit_with_lost_reply_replays_one_denial_and_one_job(world,erasure_case,monkeypatch):
    service,ident,stub,references=erasure_case;preview,request=reviewed(world,erasure_case);epoch=service.purposes.head().data['epoch']
    original=service.access._record
    def lost(*args,**kwargs):
        result=original(*args,**kwargs)
        if args[1]=='erasure-confirm':raise StoreUnavailable('synthetic lost acknowledgment after commit')
        return result
    monkeypatch.setattr(service.access,'_record',lost)
    with pytest.raises(StoreUnavailable):service.confirm(world[5],request=request,expected_version=1,idempotency_key='lost-confirm')
    monkeypatch.setattr(service.access,'_record',original)
    recovered=service.preview_read(world[5],preview['id']);assert recovered['status']=='committed'
    result=service.confirm(world[5],request=request,expected_version=1,idempotency_key='lost-confirm')
    assert result['id']==recovered['job_id'] and service.purposes.head().data['epoch']==epoch+1


def test_lost_step_completion_replays_durable_progress_without_another_storage_call(world,erasure_case,monkeypatch):
    service,ident,stub,references=erasure_case;job=commit(world,erasure_case);list_page(erasure_case)
    original=service.repository.transact
    def lost(writes,*args,**kwargs):
        result=original(writes,*args,**kwargs)
        if any(w.key.resource.startswith('erasure#') for w in writes):raise StoreUnavailable('synthetic lost completion after commit')
        return result
    monkeypatch.setattr(service.repository,'transact',lost)
    with pytest.raises(StoreUnavailable):step(world,erasure_case,job,'lost-step')
    monkeypatch.setattr(service.repository,'transact',original)
    result=step(world,erasure_case,job,'lost-step')
    assert result['status']=='metadata_pending' and result['assets'][0]['live_versions_removed']
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('fault',['expired','superseded'])
def test_old_step_lease_cannot_publish_and_expired_job_can_be_resumed(world,erasure_case,monkeypatch,fault):
    service,ident,stub,references=erasure_case;job=commit(world,erasure_case);list_page(erasure_case)
    original=service.objects.list
    def interrupt(*args):
        page=original(*args)
        if fault=='expired':world[2].value+=15000
        else:
            key=job_key(job['id']);row=service.repository.snapshot((key,))[key]
            service.repository.transact((Write(key,row.revision,{**row.data,'lease_token':str(uuid4()),'lease_until_ms':world[2]()+15000}),))
        return page
    monkeypatch.setattr(service.objects,'list',interrupt)
    with pytest.raises(StoreConflict):step(world,erasure_case,job,'old-worker')
    current=service.job(world[5],job['id']);assert current['status']=='processing' and not current['assets'][0]['live_versions_removed']
    assert step(world,erasure_case,job,'old-worker')['state_version']==current['state_version']
    if fault=='superseded':
        with pytest.raises(StoreConflict):step(world,erasure_case,current,'active-lease')
        world[2].value+=15000
    monkeypatch.setattr(service.objects,'list',original);list_page(erasure_case)
    result=step(world,erasure_case,service.job(world[5],job['id']),'new-worker')
    assert result['status']=='metadata_pending' and result['assets'][0]['live_versions_removed']


def test_already_authorized_cleanup_can_finish_after_requestor_logout_without_new_authority(world,erasure_case,monkeypatch):
    service,ident,stub,references=erasure_case;job=commit(world,erasure_case);list_page(erasure_case)
    original=service.objects.list
    def logout(*args):
        page=original(*args);service.access.logout(world[4].cookie,world[4].csrf);return page
    monkeypatch.setattr(service.objects,'list',logout)
    with pytest.raises(Denied):step(world,erasure_case,job,'authorized-before-logout')
    row=service.repository.snapshot((job_key(job['id']),))[job_key(job['id'])]
    assert row.data['status']=='metadata_pending' and row.data['progress'][ident]['live_versions_removed']
    with pytest.raises(Denied):service.job(world[5],job['id'])


def test_preview_confirmation_and_step_allowances_are_independent_and_durable(world,erasure_case):
    service,ident,stub,references=erasure_case;service.jobs_per_minute=1
    preview,request=reviewed(world,erasure_case)
    with pytest.raises(ErasureLimited):service.preview(world[5],request=ErasurePreview(asset_ids=(ident,)),idempotency_key='second-preview')
    job=service.confirm(world[5],request=request,expected_version=preview['state_version'],idempotency_key='independent-confirm')
    list_page(erasure_case);job=step(world,erasure_case,job,'independent-step')
    with pytest.raises(ErasureLimited):step(world,erasure_case,job,'second-step')
    assert service.job(world[5],job['id'])['status']=='metadata_pending'
    stub.assert_no_pending_responses()


def test_owner_grant_change_during_final_authorization_prevents_denial_commit(world,erasure_case,monkeypatch):
    service,ident,stub,references=erasure_case;preview,request=reviewed(world,erasure_case);epoch=service.purposes.head().data['epoch']
    original=service.access._fresh;calls=0
    def change(actor,role=None,**kwargs):
        nonlocal calls
        result=original(actor,role,**kwargs)
        if role==Role.OWNER:
            calls+=1
            if calls==2:
                row=result.member
                service.repository.transact((Write(row.key,row.revision,{**row.data,'roles':[],'access_version':row.data['access_version']+1}),))
        return result
    monkeypatch.setattr(service.access,'_fresh',change)
    with pytest.raises((StoreConflict,Denied)):service.confirm(world[5],request=request,expected_version=1,idempotency_key='role-changed-before-commit')
    key=Key('state','asset#'+ident)
    assert service.repository.snapshot((key,))[key].data['read_denied'] is False
    assert service.purposes.head().data['epoch']==epoch


@pytest.mark.parametrize('phase',['after_list','before_progress_commit'])
def test_replaced_runtime_cannot_complete_an_old_service_lease(world,erasure_case,monkeypatch,phase):
    service,ident,stub,references=erasure_case;job=commit(world,erasure_case);list_page(erasure_case)
    replacement=RuntimeControl(service.access,instance_id=str(uuid4()),artifact_sha256=service.runtime.artifact_sha256,
        controls_sha256=service.runtime.controls_sha256,environment=service.runtime.environment)
    if phase=='after_list':
        original=service.objects.list
        def replace_after_list(*args):
            result=original(*args);replacement.start();return result
        monkeypatch.setattr(service.objects,'list',replace_after_list)
    else:
        original=service.repository.transact;replaced=False
        def replace_before_commit(writes,*args,**kwargs):
            nonlocal replaced
            if not replaced and any(w.key.resource.startswith('erasure#') for w in writes):
                replaced=True;replacement.start()
            return original(writes,*args,**kwargs)
        monkeypatch.setattr(service.repository,'transact',replace_before_commit)
    with pytest.raises((StoreConflict,Denied)):
        step(world,erasure_case,job,'old-runtime-worker')
    row=service.repository.snapshot((job_key(job['id']),))[job_key(job['id'])]
    assert row.data['status']=='processing' and row.data['progress'][ident]['live_versions_removed'] is False
