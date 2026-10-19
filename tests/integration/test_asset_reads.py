"""Actual local CV/store paths, private synthetic authority and intercepted S3 only."""
import asyncio
import hashlib
from threading import Event
from uuid import uuid4

from fastapi.testclient import TestClient
import httpx
import pytest

from test_access_lifecycle import world,repository_factory,publication_case,invite_and_join,proof
from test_references import reference_case,upload
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import digest,ResourceUnavailable
from proofpack.evidence.objects import EvidenceObjects,ReferenceObjects
from proofpack.evidence.purposes import DataPurposes
from proofpack.evidence.reads import AssetReads,AssetReadLimited
from proofpack.evidence.repository import Key,StoreUnavailable,StoreConflict,Write
from proofpack.runtime.control import DATA


@pytest.fixture
def frame_read_case(world,publication_case):
    observations,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    _,admission,_=observe();repo=world[1]
    observation=repo.snapshot((Key('state','observation#'+admission['id']),))[Key('state','observation#'+admission['id'])]
    asset=repo.snapshot((Key('state','asset#'+observation.data['asset_id']),))[Key('state','asset#'+observation.data['asset_id'])]
    purposes=DataPurposes(world[0],capture.stations.runtime,max_lifetime_ms=120000)
    row=repo.snapshot((purpose,))[purpose];data=purposes.head()
    # Upgrade the deliberately abbreviated publication-purpose fixture to the full
    # synthetic attestation shape; never independent consent/rights/physical proof.
    repo.transact((Write(purpose,row.revision,{**row.data,'authority_basis':'owner_attestation','rights_independently_verified':False,
        'optional_improvement':False,'optional_publicity':False,'notice_version':world[0].config.notice_version,
        'notice_sha256':digest(world[0].config.notice_text)}),purposes.advance(data)))
    _,review_credentials,reviewer,_,_=invite_and_join(world,'image-reviewer',roles=(Role.REVIEWER,))
    reads=AssetReads(purposes,objects,ReferenceObjects(objects.client,objects.config),reads_per_minute=16,max_concurrent=1,read_window_ms=5000)
    return reads,asset,operator,credentials,reviewer,review_credentials,objects,purpose


def test_own_operator_and_reviewer_receive_exact_historical_cropped_evidence(world,frame_read_case):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case
    for actor in (operator,reviewer):
        metadata=service.read(actor,asset.data['id'])
        body,receipt,version,binding,remaining=service.read(actor,asset.data['id'],binary=True)
        assert body==objects.payloads[asset.data['id']] and hashlib.sha256(body).hexdigest()==metadata['sha256']
        assert binding==metadata['binding_sha256'] and version==metadata['state_version'] and remaining>0
        assert metadata['historical'] and metadata['machine_pass'] is False and metadata['can_download']
        assert 'object_key' not in metadata and 'object_version' not in metadata and metadata['storage_verified'] is False
    events=world[1].query(prefix='asset-read#',table='events',limit=20)[0]
    assert sum(item.data['kind']=='asset_download_ready' for item in events)==2


def test_owner_metadata_is_not_blanket_frame_media_privilege_and_other_operator_is_denied(world,frame_read_case):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case
    assert service.read(world[5],asset.data['id'])['can_download'] is False
    with pytest.raises(Denied):service.read(world[5],asset.data['id'],binary=True)
    _,_,other,_,_=invite_and_join(world,'other-operator')
    for binary in (False,True):
        with pytest.raises(Denied):service.read(other,asset.data['id'],binary=binary)


@pytest.mark.parametrize('fault',['withdraw','expire','read_denied','notice','context','foreign_key','epoch'])
def test_missing_changed_or_foreign_source_prevents_delivery(world,frame_read_case,fault):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case;repo=world[1]
    if fault in {'withdraw','expire','notice'}:
        row=repo.snapshot((purpose,))[purpose];values={'withdrawn':True} if fault=='withdraw' else {'expires_at_ms':world[2]()} if fault=='expire' else {'notice_sha256':'e'*64}
    elif fault=='epoch':
        row=repo.snapshot((Key('state','inspection#'+service.read(operator,asset.data['id'])['inspection_id']),))[Key('state','inspection#'+service.read(operator,asset.data['id'])['inspection_id'])]
        values={'station_epoch':99}
    else:row=asset;values={'read_denied':True} if fault=='read_denied' else {'context_sha256':'e'*64} if fault=='context' else {'object_key':'foreign/key'}
    repo.transact((Write(row.key,row.revision,{**row.data,**values}),))
    with pytest.raises((StoreUnavailable,StoreConflict)):service.read(operator,asset.data['id'],binary=True)


@pytest.mark.parametrize('fault',['purpose','session','data','expiry','budget','checksum'])
def test_authority_loss_or_corrupt_bytes_during_object_read_cannot_be_delivered(world,frame_read_case,fault):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case;repo=world[1]
    def changed():
        if fault=='purpose':
            row=repo.snapshot((purpose,))[purpose];repo.transact((Write(row.key,row.revision,{**row.data,'withdrawn':True}),))
        elif fault=='session':world[0].logout(credentials.cookie,credentials.csrf)
        elif fault=='data':row=service.purposes.head();repo.transact((service.purposes.advance(row),))
        elif fault=='expiry':world[2].value+=60000
        elif fault=='budget':tick[0]+=5000000000
    tick=[0];service.tick=lambda:tick[0];objects.after_get=changed
    if fault=='checksum':objects.payloads[asset.data['id']]=b'not-the-committed-image'
    with pytest.raises((StoreUnavailable,StoreConflict,Denied)):service.read(operator,asset.data['id'],binary=True)
    events=repo.query(prefix='asset-read#',table='events',limit=20)[0]
    assert not any(row.data['kind']=='asset_download_ready' for row in events)


def test_durable_read_quota_denies_before_second_storage_request(world,frame_read_case):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case;service.reads_per_minute=1;calls=[]
    objects.after_get=lambda:calls.append(True)
    service.read(operator,asset.data['id'],binary=True)
    with pytest.raises(AssetReadLimited):service.read(operator,asset.data['id'],binary=True)
    assert calls==[True]


def test_reference_owner_and_reviewer_can_read_but_foreign_owner_cannot(world,reference_case):
    purposes,references,objects,metadata,image=reference_case;asset=upload(world,reference_case)
    service=AssetReads(purposes,EvidenceObjects(objects.client,objects.config),objects,reads_per_minute=16,max_concurrent=1,read_window_ms=5000)
    view=service.read(world[5],asset['id']);payload,*_=service.read(world[5],asset['id'],binary=True)
    assert view['kind']=='reference' and payload==objects.payloads[asset['id']]
    _,_,reviewer,_,_=invite_and_join(world,'reference-reader',roles=(Role.REVIEWER,))
    assert service.read(reviewer,asset['id'],binary=True)[0]==payload
    _,_,other,_,_=invite_and_join(world,'other-owner',roles=(Role.OWNER,),mfa=True)
    assert service.read(other,asset['id'])['can_download'] is False
    with pytest.raises(Denied):service.read(other,asset['id'],binary=True)


def test_http_bytes_are_no_store_same_origin_bound_and_range_is_rejected(world,frame_read_case):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,purpose_service=service.purposes,asset_service=service)
    url='/api/v1/assets/'+asset.data['id']
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.get(url).status_code==401
        client.cookies.set(COOKIE,credentials.cookie);view=client.get(url).json()
        assert client.get(url+'/download',headers={'Range':'bytes=0-2'}).status_code==400
        response=client.get(url+'/download');assert response.status_code==200
        assert response.headers['cache-control']=='no-store' and response.headers['cross-origin-resource-policy']=='same-origin'
        assert response.headers['x-evidence-binding-sha256']==view['binding_sha256']
        assert response.headers['x-asset-id']==asset.data['id'] and response.headers['x-evidence-historical']=='true'
        assert response.content==objects.payloads[asset.data['id']] and 'amazonaws' not in response.headers['content-disposition']


def test_cancelled_http_read_keeps_capacity_until_its_actual_worker_thread_finishes(world,frame_read_case):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case
    entered=Event();release=Event();finished=Event();original_get=objects.get;original_read=service.read
    def blocked(receipt):
        entered.set();assert release.wait(10);return original_get(receipt)
    def read(*args,**kwargs):
        try:return original_read(*args,**kwargs)
        finally:finished.set()
    objects.get=blocked;service.read=read
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,purpose_service=service.purposes,asset_service=service)
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://proofpack.test',cookies={COOKIE:credentials.cookie}) as client:
            task=asyncio.create_task(client.get('/api/v1/assets/'+asset.data['id']+'/download'))
            assert await asyncio.to_thread(entered.wait,5)
            task.cancel()
            try:
                with pytest.raises(AssetReadLimited):original_read(operator,asset.data['id'])
            finally:release.set()
            try:await task
            except asyncio.CancelledError:pass
            assert await asyncio.to_thread(finished.wait,10)
    try:asyncio.run(scenario())
    finally:release.set()
    objects.get=original_get;service.read=original_read
    assert service.read(operator,asset.data['id'])['id']==asset.data['id']


def test_latest_lookup_is_scoped_and_cannot_return_a_replaced_inspection_pointer(world,frame_read_case):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case;repo=world[1]
    metadata=service.read(operator,asset.data['id']);inspection=metadata['inspection_id']
    assert service.latest(operator,inspection)['id']==asset.data['id']
    _,_,other,_,_=invite_and_join(world,'unrelated-operator')
    with pytest.raises(Denied):service.latest(other,inspection)
    original=service._snapshot
    def snapshot(*args,**kwargs):
        key=Key('state','inspection#'+inspection);row=repo.snapshot((key,))[key]
        repo.transact((Write(key,row.revision,{**row.data,'latest_observation_id':None}),))
        return original(*args,**kwargs)
    service._snapshot=snapshot
    with pytest.raises(StoreConflict):service.latest(operator,inspection)


def test_expiry_after_final_auth_check_cannot_return_bytes_with_nonpositive_validity(world,frame_read_case):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case
    original=service._final;calls=0
    def final(*args,**kwargs):
        nonlocal calls
        result=original(*args,**kwargs);calls+=1
        if calls==3:world[2].value+=60000
        return result
    service._final=final
    with pytest.raises(StoreUnavailable):service.read(operator,asset.data['id'],binary=True)


def test_missing_asset_attempt_consumes_authenticated_read_allowance(world,frame_read_case):
    service,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case;service.reads_per_minute=1
    with pytest.raises(ResourceUnavailable):service.read(operator,str(uuid4()))
    with pytest.raises(AssetReadLimited):service.read(operator,asset.data['id'],binary=True)


@pytest.mark.parametrize('permission_reference',['different-permission',None,''])
def test_reference_permission_reference_must_match_its_current_purpose(world,reference_case,permission_reference):
    purposes,references,objects,metadata,image=reference_case;asset=upload(world,reference_case)
    service=AssetReads(purposes,EvidenceObjects(objects.client,objects.config),objects,reads_per_minute=16,max_concurrent=1,read_window_ms=5000)
    key=Key('state','asset#'+asset['id']);row=world[1].snapshot((key,))[key]
    world[1].transact((Write(key,row.revision,{**row.data,'source_permission_reference':permission_reference}),))
    with pytest.raises(StoreUnavailable):service.read(world[5],asset['id'],binary=True)
