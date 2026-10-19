"""Real local database/decoder with intercepted S3; no AWS/physical rights proof."""
from dataclasses import replace
import hashlib
import json
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from fastapi.testclient import TestClient
import pytest

from test_access_lifecycle import world,repository_factory,runtime_service,invite_and_join
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import digest
from proofpack.evidence.objects import EvidenceObjects,ReferenceObjects,ObjectConfig
from proofpack.evidence.purposes import DataPurposes,PurposeRequest,purpose_key
from proofpack.evidence.references import ReferenceAssets,ReferenceRateLimited,ReferenceRequest
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.recipes.models import Origin
from proofpack.runtime.control import DATA
from proofpack.vision.fixtures import make_fixture
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker import WorkerBusy
from proofpack.vision.worker_limits import WorkerLimits


@pytest.fixture
def reference_case(world):
    access,repo,clock,uid,credentials,owner=world
    runtime=runtime_service(world);runtime.start();purposes=DataPurposes(access,runtime,max_lifetime_ms=120000)
    request=PurposeRequest(notice_version=access.config.notice_version,notice_sha256=digest(access.config.notice_text),
        source_permission_reference='source-owned-1',operational_use_acknowledged=True,expires_at_ms=clock()+60000)
    purpose=purposes.create(owner,request=request,idempotency_key='purpose-initial')
    config=ObjectConfig(repo.deployment,'proofpack-reference-test','000000000000','us-east-1',
        'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-4000-8000-000000000001')
    client=boto3.client('s3',region_name=config.region,aws_access_key_id='synthetic',aws_secret_access_key='synthetic',
        config=Config(connect_timeout=2,read_timeout=3,retries={'total_max_attempts':1}))
    stub=Stubber(client);stub.activate()
    class ProtocolObjects(ReferenceObjects):
        def __init__(self):super().__init__(client,config);self.calls=0;self.after_put=None;self.payload=None;self.corrupt=False;self.payloads={};self.heads={};self.after_get=None
        def put(self,**kwargs):
            self.calls+=1;payload=kwargs['payload'];self.payload=payload;ident=kwargs['asset_id'];version='version-'+ident
            source=hashlib.sha256(payload).hexdigest();context=kwargs['context_sha256']
            head={'VersionId':version,'ContentLength':len(payload),'ContentType':kwargs['content_type'],'ServerSideEncryption':'aws:kms',
                'SSEKMSKeyId':config.kms_key_arn,'ChecksumSHA256':self._checksum(source),
                'Metadata':{'source-sha256':source,'context-sha256':context}}
            self.payloads[ident]=payload;self.heads[ident]=head
            stub.add_response('put_object',{key:head[key] for key in ('VersionId','ServerSideEncryption','SSEKMSKeyId','ChecksumSHA256')},
                {**self._params(ident),'Body':payload,'ContentLength':len(payload),'ContentType':kwargs['content_type'],'IfNoneMatch':'*',
                 'ChecksumSHA256':self._checksum(source),'ServerSideEncryption':'aws:kms','SSEKMSKeyId':config.kms_key_arn,'Metadata':head['Metadata']})
            stub.add_response('head_object',head,{**self._params(ident,version),'ChecksumMode':'ENABLED'})
            receipt=super().put(**kwargs)
            if self.after_put:self.after_put()
            if self.corrupt=='key':return replace(receipt,key='foreign/key')
            return replace(receipt,context_sha256='f'*64) if self.corrupt else receipt
        def get(self,receipt):
            from io import BytesIO
            from botocore.response import StreamingBody
            payload=self.payloads[receipt.asset_id]
            stub.add_response('get_object',{**self.heads[receipt.asset_id],'Body':StreamingBody(BytesIO(payload),len(payload))},
                {**self._params(receipt.asset_id,receipt.version_id),'ChecksumMode':'ENABLED'})
            result=super().get(receipt)
            if self.after_get:self.after_get()
            return result
        def validate(self,receipt):
            stub.add_response('head_object',self.heads[receipt.asset_id],{**self._params(receipt.asset_id,receipt.version_id),'ChecksumMode':'ENABLED'})
            return super().validate(receipt)
    objects=ProtocolObjects();objects.stub=stub;registry=WorkerRegistry(WorkerLimits(512,30,750,5000,2097152,65536,262144,4096,30,12,0),max_processes=2)
    references=ReferenceAssets(purposes,objects,registry,max_uploads_per_minute=3)
    import cv2
    frame,_=make_fixture(0,'complete',seed=3);ok,image=cv2.imencode('.png',frame);assert ok
    metadata=ReferenceRequest(purpose_id=purpose['id'],source_permission_reference='source-owned-1',data_origin=Origin.SYNTHETIC,expires_at_ms=clock()+50000)
    try:yield purposes,references,objects,metadata,image.tobytes()
    finally:references.close();registry.close();stub.assert_no_pending_responses();stub.deactivate();client.close()


def upload(world,case,*,key='upload',payload=None,metadata=None):
    purposes,references,objects,request,image=case;owner=world[5];ticket=references.begin(owner)
    try:return references.upload(owner,ticket=ticket,request=metadata or request,payload=image if payload is None else payload,content_type='image/png',idempotency_key=key)
    finally:references.end(ticket)


def test_purpose_notice_acknowledgment_and_epoch_advance_are_explicit_and_idempotent(world,reference_case):
    purposes,references,objects,request,image=reference_case;repo=world[1];owner=world[5]
    original=repo.snapshot((DATA,))[DATA]
    body=PurposeRequest(notice_version=purposes.access.config.notice_version,notice_sha256=digest(purposes.access.config.notice_text),
        source_permission_reference='source-owned-2',operational_use_acknowledged=True,expires_at_ms=world[2]()+30000)
    result=purposes.create(owner,request=body,idempotency_key='another-purpose');current=repo.snapshot((DATA,))[DATA]
    assert current.data['epoch']==original.data['epoch']+1
    assert purposes.create(owner,request=body,idempotency_key='another-purpose')==result
    assert repo.snapshot((DATA,))[DATA]==current
    assert result['allowed_uses']==['operation'] and result['rights_independently_verified'] is False
    assert result['optional_improvement'] is result['optional_publicity'] is False
    for changes in ({'operational_use_acknowledged':False},{'notice_sha256':'f'*64},{'expires_at_ms':world[2]()+120001}):
        with pytest.raises((ValueError,Denied)):purposes.create(owner,request=body.model_copy(update=changes),idempotency_key=str(uuid4()))
    assert repo.snapshot((DATA,))[DATA]==current


def test_reference_is_canonical_private_and_body_bound_retry_never_rewrites(world,reference_case):
    purposes,references,objects,request,image=reference_case;result=upload(world,reference_case)
    assert result['operation_status']=='committed' and result['replayed'] is False
    assert result['source_sha256']==hashlib.sha256(image).hexdigest()
    assert result['sha256']==hashlib.sha256(objects.payload).hexdigest() and objects.payload.startswith(b'\xff\xd8\xff')
    assert result['source_sha256']!=result['sha256'] and result['physical_truth_verified'] is False
    assert result['origin_basis']=='owner_declaration' and 'object_receipt' not in result and 'key' not in result
    ticket=references.begin(world[5])
    try:
        replay=references.upload(world[5],ticket=ticket,request=request,payload=image,content_type='image/png',idempotency_key='upload')
        assert replay['id']==result['id'] and replay['replayed'] is True and objects.calls==1
        with pytest.raises(StoreConflict):references.upload(world[5],ticket=ticket,request=request,payload=image+b'changed',content_type='image/png',idempotency_key='upload')
        assert objects.calls==1
    finally:references.end(ticket)
    intent=world[1].snapshot((Key('state','reference-intent#'+result['id']),))[Key('state','reference-intent#'+result['id'])]
    assert intent.data['status']=='linked'


@pytest.mark.parametrize('failure',['withdraw','revoke','corrupt','uncertain','data','foreign_key'])
def test_failed_or_revoked_reference_publication_leaves_only_private_reconciliation_intent(world,reference_case,failure):
    purposes,references,objects,request,image=reference_case;access,repo,clock,uid,credentials,owner=world
    if failure=='withdraw':objects.after_put=lambda:purposes.withdraw(owner,ident=request.purpose_id,expected_version=1,idempotency_key='withdraw')
    elif failure=='revoke':objects.after_put=lambda:access.revoke_sessions(owner,user_id=uid,expected_version=1,idempotency_key='revoke-owner')
    elif failure=='corrupt':objects.corrupt=True
    elif failure=='foreign_key':objects.corrupt='key'
    elif failure=='data':
        def change_data():
            row=repo.snapshot((DATA,))[DATA];repo.transact((Write(DATA,row.revision,{**row.data,'epoch':row.data['epoch']+1}),))
        objects.after_put=change_data
    else:
        def lost_ack():raise StoreUnavailable('synthetic lost acknowledgement')
        objects.after_put=lost_ack
    with pytest.raises((Denied,StoreUnavailable,StoreConflict)):upload(world,reference_case)
    assert objects.calls==1
    intents,_=repo.query(prefix='reference-intent#',limit=10);assert len(intents)==1 and intents[0].data['status']=='needs_reconciliation'
    ident=intents[0].data['asset_id'];assert repo.snapshot((Key('state','asset#'+ident),))[Key('state','asset#'+ident)] is None


def test_invalid_decoder_input_is_failed_once_and_cannot_be_reprocessed_by_retry(world,reference_case):
    purposes,references,objects,request,image=reference_case;bad=b'\x89PNG\r\n\x1a\ninvalid'
    with pytest.raises(StoreUnavailable):upload(world,reference_case,payload=bad)
    replay=upload(world,reference_case,payload=bad)
    assert replay['operation_status']=='failed' and replay['requires_reconciliation'] is True and objects.calls==0


def test_purpose_withdrawal_immediately_denies_reference_use_and_is_versioned(world,reference_case):
    purposes,references,objects,request,image=reference_case;result=upload(world,reference_case);repo=world[1];owner=world[5]
    before=repo.snapshot((DATA,))[DATA]
    with pytest.raises(StoreConflict):purposes.withdraw(owner,ident=request.purpose_id,expected_version=2,idempotency_key='stale')
    withdrawn=purposes.withdraw(owner,ident=request.purpose_id,expected_version=1,idempotency_key='withdraw')
    assert withdrawn['withdrawn'] is True and repo.snapshot((DATA,))[DATA].data['epoch']==before.data['epoch']+1
    with pytest.raises(StoreUnavailable):references.get(owner,result['id'])
    assert purposes.withdraw(owner,ident=request.purpose_id,expected_version=1,idempotency_key='withdraw')['withdrawn'] is True


def test_intake_quota_is_durable_and_uses_shared_decoder_capacity_without_stealing(world,reference_case):
    purposes,references,objects,request,image=reference_case;registry=references.registry;runtime=purposes.runtime.instance_id
    station=str(uuid4());registry.prepare(station_id=station,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
    ticket=references.begin(world[5])
    try:
        with pytest.raises(WorkerBusy):registry.prepare(station_id=str(uuid4()),epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
        registry.guard(station,1,runtime)
    finally:references.end(ticket)
    registry.guard(station,1,runtime)
    for _ in range(2):
        ticket=references.begin(world[5]);references.end(ticket)
    with pytest.raises(ReferenceRateLimited):references.begin(world[5])


def test_reference_http_checks_authority_before_reading_image_and_commits_only_verified_bytes(world,reference_case,monkeypatch):
    purposes,references,objects,metadata,image=reference_case;access,repo,clock,uid,credentials,owner=world
    member,operator_credentials,operator,_,_=invite_and_join(world)
    import proofpack.evidence.http as http
    original=http.receive_upload
    async def forbidden(*args,**kwargs):raise AssertionError('unauthorized image body was read')
    monkeypatch.setattr(http,'receive_upload',forbidden)
    app=create_app(access_service=access,app_origin='https://proofpack.test',runtime_control=purposes.runtime,purpose_service=purposes,reference_service=references)
    with TestClient(app,base_url='https://proofpack.test') as client:
        headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-upload'}
        assert client.post('/api/v1/reference-assets',content=b'unread',headers=headers).status_code==401
        client.cookies.set(COOKIE,operator_credentials.cookie)
        assert client.post('/api/v1/reference-assets',content=b'unread',headers={**headers,'X-CSRF-Token':operator_credentials.csrf}).status_code==403
        client.cookies.set(COOKIE,credentials.cookie)
        assert client.post('/api/v1/reference-assets',content=b'unread',headers={**headers,'Origin':'https://evil.invalid'}).status_code==403
        monkeypatch.setattr(http,'receive_upload',original)
        response=client.post('/api/v1/reference-assets',files={'image':('ignored.png',image,'image/png')},data={'metadata':metadata.model_dump_json()},headers=headers)
        assert response.status_code==201,response.text
        ident=response.json()['id'];assert client.get('/api/v1/reference-assets/'+ident).status_code==200
        assert objects.calls==1


def test_data_authority_bootstrap_is_once_only_and_missing_history_denies_restart(world):
    runtime=runtime_service(world);runtime.start();repo=world[1];first=repo.snapshot((DATA,))[DATA]
    assert first.data['epoch']==1 and runtime.start()==runtime.handle and repo.snapshot((DATA,))[DATA]==first
    repo.client.delete_item(TableName=repo.tables['state'],Key=repo.key(DATA))
    with pytest.raises(StoreUnavailable):runtime.start()
    with pytest.raises(StoreUnavailable):runtime_service(world).start()
    assert repo.snapshot((DATA,))[DATA] is None


def test_purpose_options_and_page_reads_do_not_grant_use_or_change_epoch(world,reference_case):
    purposes,references,objects,request,image=reference_case;repo=world[1];owner=world[5];before=repo.snapshot((DATA,))[DATA]
    options=purposes.options(owner);assert options['max_lifetime_ms']==120000 and options['server_time_ms']==world[2]()
    page=purposes.list(owner,limit=1);assert len(page['purposes'])==1 and page['purposes'][0]['id']==request.purpose_id
    assert repo.snapshot((DATA,))[DATA]==before
    with pytest.raises(ValueError):purposes.list(owner,limit=21)
    with pytest.raises(ValueError):purposes.list(owner,cursor='foreign/path')
    _,_,operator,_,_=invite_and_join(world)
    with pytest.raises(Denied):purposes.options(operator)
    with pytest.raises(Denied):purposes.list(operator)


def test_reference_metadata_whitelists_fields_instead_of_exposing_new_private_columns(world,reference_case):
    purposes,references,objects,request,image=reference_case;result=upload(world,reference_case);repo=world[1]
    key=Key('state','asset#'+result['id']);row=repo.snapshot((key,))[key]
    repo.transact((Write(key,row.revision,{**row.data,'key':'private-internal-key','version_id':'private-version','private_diagnostic':'hidden'}),))
    view=references.get(world[5],result['id'])
    assert all(name not in view for name in ('object_receipt','key','version_id','private_diagnostic'))


@pytest.mark.parametrize('phase',['begin','processing','processing_failure'])
def test_cancelled_http_retains_its_owned_capacity_until_the_actual_thread_finishes(world,reference_case,phase):
    import asyncio
    from threading import Event
    import httpx
    purposes,references,objects,metadata,image=reference_case
    started=Event();release=Event();ended=Event();ticket=object();ends=[]
    class Registry:
        def close(self):pass
    class PendingReference:
        registry=Registry()
        def __init__(self):self.purposes=purposes
        def begin(self,actor):
            if phase=='begin':started.set();assert release.wait(3)
            return ticket
        def upload(self,*args,**kwargs):
            started.set();assert release.wait(3)
            if phase=='processing_failure':raise StoreUnavailable('synthetic interrupted storage')
            return {'id':str(uuid4()),'operation_status':'committed'}
        def end(self,value):assert value is ticket;ends.append(value);ended.set()
        def close(self):release.set()
    fake=PendingReference();app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=purposes.runtime,purpose_service=purposes,reference_service=fake)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url='https://proofpack.test',cookies={COOKIE:world[4].cookie}) as client:
            task=asyncio.create_task(client.post('/api/v1/reference-assets',files={'image':('ref.png',image,'image/png')},data={'metadata':metadata.model_dump_json()},
                headers={'Origin':'https://proofpack.test','X-CSRF-Token':world[4].csrf,'Idempotency-Key':'cancel-'+phase}))
            try:
                assert await asyncio.to_thread(started.wait,2)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):await task
                assert not ended.is_set() and ends==[]
                release.set();assert await asyncio.to_thread(ended.wait,2)
                assert ends==[ticket]
            finally:release.set()
    asyncio.run(run())


@pytest.mark.parametrize('change',['purpose','permission','expiry'])
def test_foreign_or_unpermitted_reference_never_reserves_or_writes_object(world,reference_case,change):
    purposes,references,objects,request,image=reference_case
    changes={'purpose':{'purpose_id':str(uuid4())},'permission':{'source_permission_reference':'other-permission'},'expiry':{'expires_at_ms':world[2]()+60001}}
    with pytest.raises(StoreUnavailable):upload(world,reference_case,metadata=request.model_copy(update=changes[change]))
    assert objects.calls==0 and world[1].query(prefix='reference-intent#',limit=10)[0]==[]


def test_reference_expiry_boundary_does_not_renew_original_asset_or_replay(world,reference_case):
    purposes,references,objects,request,image=reference_case;result=upload(world,reference_case);owner=world[5]
    world[2].value+=49999;assert references.get(owner,result['id'])['expires_at_ms']==request.expires_at_ms
    world[2].value+=1
    with pytest.raises(StoreUnavailable):references.get(owner,result['id'])
    with pytest.raises(StoreUnavailable):upload(world,reference_case)
    assert objects.calls==1


def test_concurrent_same_body_reference_reservation_has_one_decoder_and_object_writer(world,reference_case,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    purposes,references,objects,request,image=reference_case;owner=world[5];repo=world[1]
    tickets=[references.begin(owner),references.begin(owner)];barrier=Barrier(2);original=repo.transact
    def race(writes,checks=()):
        if any(item.key.resource.startswith('reference-intent#') and item.expected_revision is None for item in writes):barrier.wait(timeout=3)
        return original(writes,checks)
    monkeypatch.setattr(repo,'transact',race)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(references.upload,owner,ticket=ticket,request=request,payload=image,content_type='image/png',idempotency_key='concurrent-upload') for ticket in tickets]
            results=[future.result(timeout=10) for future in futures]
        assert results[0]['id']==results[1]['id'] and objects.calls==1
        assert any(item['operation_status']=='committed' and item['replayed'] is False for item in results)
        assert sum(item['replayed'] is True for item in results)==1
        intents,_=repo.query(prefix='reference-intent#',limit=10);assert len(intents)==1 and intents[0].data['status']=='linked'
    finally:
        for ticket in tickets:references.end(ticket)


def test_atomic_reference_link_failure_cannot_leave_a_public_asset_or_advanced_epoch(world,reference_case,monkeypatch):
    purposes,references,objects,request,image=reference_case;repo=world[1];before=repo.snapshot((DATA,))[DATA];original=repo.transact
    def reject_link(writes,checks=()):
        if any(item.key.resource.startswith('asset#') and item.data.get('kind')=='reference' for item in writes):raise StoreConflict('synthetic atomic link rejection')
        return original(writes,checks)
    monkeypatch.setattr(repo,'transact',reject_link)
    with pytest.raises(StoreConflict):upload(world,reference_case)
    assert objects.calls==1 and repo.snapshot((DATA,))[DATA]==before
    intents,_=repo.query(prefix='reference-intent#',limit=10);assert len(intents)==1 and intents[0].data['status']=='needs_reconciliation'
    asset=Key('state','asset#'+intents[0].data['asset_id']);assert repo.snapshot((asset,))[asset] is None


def test_reference_service_rejects_an_inspection_frame_storage_adapter(world,reference_case):
    purposes,references,objects,request,image=reference_case
    frames=EvidenceObjects(objects.client,objects.config)
    with pytest.raises(ValueError):ReferenceAssets(purposes,frames,references.registry,max_uploads_per_minute=3)
