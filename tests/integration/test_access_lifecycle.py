"""Actual DynamoDB Local lifecycle tests; provider proofs are synthetic trusted-adapter fixtures.

These test persistent transactions, not Cognito token validation, live AWS or email delivery.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import hashlib
from threading import Barrier
from uuid import uuid4
from urllib.parse import urlsplit
import os

import boto3
from botocore.config import Config
import pytest
from fastapi.testclient import TestClient

from proofpack.auth.policy import Denied,Role,require
from proofpack.auth.service import AccessService,AuthConfig,BootstrapApproval,HEAD,IdentityProof,invitation_key,user_key
from proofpack.auth.service import digest
from proofpack.evidence.repository import DynamoRepository,StoreConflict,Write
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.oauth import AuthRateLimited,OAuthConfig,OAuthFlows
from proofpack.auth.signin_http import FLOW_COOKIE
from proofpack.auth.cognito import CognitoConfig,CognitoProvider,CognitoTokens
from proofpack.auth.signin import SignInService
from proofpack.runtime.control import CHECKS,DATA,RuntimeControl,readiness_digest
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Key,StoreUnavailable
from proofpack.recipes.service import RecipeService,catalog_key,active_key,revision_key,qualification_key
from proofpack.recipes.models import Qualification,Origin
from proofpack.stations.service import StationService,StationRateLimited,station_key,inspection_key,POLICY,ALLOCATION
from proofpack.capture.service import CaptureService,permit_key,observation_key
from proofpack.capture.observations import ObservationService
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker_limits import WorkerLimits
from proofpack.vision.fixtures import synthetic_profile

ISSUER='https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Synthetic'


class CaptureClock:
    def __init__(self):self.value=5000000000
    def __call__(self):return self.value


def observation_world(world,recipe,*,objects=None,purpose_id=None,environment="test"):
    profile=synthetic_profile()
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe,profile=profile,environment=environment)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    registry=WorkerRegistry(WorkerLimits(512,30,750,5000,2097152,65536,262144,4096,30,12,0),max_processes=1)
    clock=CaptureClock();capture=CaptureService(stations,worker_guard=registry.guard,tick_ns=clock)
    return ObservationService(capture,registry,objects=objects,purpose_id=purpose_id),capture,started,operator,credentials,clock,registry


@pytest.fixture
def publication_case(world,recipe,request):
    """Real local CV/database, S3 SDK protocol interception; not AWS durability."""
    from botocore.stub import Stubber
    from proofpack.evidence.objects import EvidenceObjects,ObjectConfig
    config=ObjectConfig(world[1].deployment,'proofpack-synthetic-test','000000000000','us-east-1',
        'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-4000-8000-000000000001')
    client=boto3.client('s3',region_name=config.region,aws_access_key_id='synthetic',aws_secret_access_key='synthetic',
        config=Config(connect_timeout=2,read_timeout=3,retries={'total_max_attempts':1}))
    stub=Stubber(client);stub.activate()
    class ProtocolObjects(EvidenceObjects):
        def __init__(self):
            super().__init__(client,config);self.heads={};self.payloads={};self.after_put=None;self.after_get=None;self.unavailable=False
        def put(self,**kwargs):
            if self.unavailable:raise StoreUnavailable('synthetic storage outage')
            payload=kwargs['payload'];source=hashlib.sha256(payload).hexdigest();context=kwargs['context_sha256'];ident=kwargs['asset_id']
            version='version-'+ident
            head={'VersionId':version,'ContentLength':len(payload),'ContentType':kwargs['content_type'],
                'ServerSideEncryption':'aws:kms','SSEKMSKeyId':config.kms_key_arn,'ChecksumSHA256':self._checksum(source),
                'Metadata':{'source-sha256':source,'context-sha256':context}}
            self.heads[ident]=head;self.payloads[ident]=payload
            stub.add_response('put_object',{k:head[k] for k in ('VersionId','ServerSideEncryption','SSEKMSKeyId','ChecksumSHA256')},
                {**self._params(ident),'Body':payload,'ContentLength':len(payload),'ContentType':kwargs['content_type'],
                 'IfNoneMatch':'*','ChecksumSHA256':self._checksum(source),'ServerSideEncryption':'aws:kms',
                 'SSEKMSKeyId':config.kms_key_arn,'Metadata':head['Metadata']})
            stub.add_response('head_object',head,{**self._params(ident,version),'ChecksumMode':'ENABLED'})
            receipt=super().put(**kwargs)
            if self.after_put:self.after_put()
            return receipt
        def get(self,receipt):
            from io import BytesIO
            from botocore.response import StreamingBody
            if self.unavailable:raise StoreUnavailable('synthetic storage outage')
            payload=self.payloads[receipt.asset_id]
            stub.add_response('get_object',{**self.heads[receipt.asset_id],'Body':StreamingBody(BytesIO(payload),len(payload))},
                {**self._params(receipt.asset_id,receipt.version_id),'ChecksumMode':'ENABLED'})
            result=super().get(receipt)
            if self.after_get:self.after_get()
            return result
        def validate(self,receipt):
            if self.unavailable:raise StoreUnavailable('synthetic storage outage')
            stub.add_response('head_object',self.heads[receipt.asset_id],
                {**self._params(receipt.asset_id,receipt.version_id),'ChecksumMode':'ENABLED'})
            return super().validate(receipt)
    objects=ProtocolObjects();objects.stub=stub;purpose_id=str(uuid4());purpose=Key('state','purpose#'+purpose_id)
    world[1].transact((Write(purpose,None,{'allowed_uses':['operation'],'withdrawn':False,'expires_at_ms':world[2]()+60000}),))
    setup=observation_world(world,recipe,objects=objects,purpose_id=purpose_id,environment=getattr(request,"param","test"))
    service,capture,started,operator,credentials,clock,registry=setup
    def observe(condition='complete',*,advance=True):
        import cv2
        from proofpack.vision.fixtures import make_fixture
        if advance:clock.value+=500000000;world[2].value+=500
        work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
        permit=capture_permit(capture,started,operator,version=work.revision,key='publication-'+str(work.revision))
        frame,_=make_fixture(0,condition,seed=1)
        ok,encoded=cv2.imencode('.png',frame);assert ok
        payload=encoded.tobytes();admission=admit_frame(capture,started,operator,permit,payload=payload)
        return service.process(operator,observation_id=admission['id'],payload=payload),admission,payload
    try:
        service.prepare(operator,inspection_id=started['inspection_id'],expected_version=1,idempotency_key='warm-publication')
        yield service,capture,started,operator,credentials,clock,registry,objects,purpose,observe
    finally:registry.close();stub.assert_no_pending_responses();stub.deactivate();client.close()


def test_publication_real_cv_evidence_first_stable_pass_then_removal_and_ack(world,publication_case):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    from proofpack.capture.publication import asset_key,intent_key,action_key
    for expected in ('OBSERVING','OBSERVING','PASSED_CURRENT'):
        status,admission,payload=observe()
        assert status['effective_state']==expected
        obs=world[1].snapshot((observation_key(admission['id']),))[observation_key(admission['id'])]
        asset=world[1].snapshot((asset_key(obs.data['asset_id']),))[asset_key(obs.data['asset_id'])]
        assert asset.data['input_sha256']==hashlib.sha256(payload).hexdigest() and asset.data['sha256']!=hashlib.sha256(payload).hexdigest()
        assert asset.data['derivation']=='rectified_roi_jpeg' and asset.data['content_type']=='image/jpeg'
        assert world[1].snapshot((intent_key(obs.data['asset_id']),))[intent_key(obs.data['asset_id'])].data['status']=='linked'
        assert 'evidence_jpeg_base64' not in json.loads(obs.data['result_json'])
    assert 0<status['remaining_lease_ms']<=1000
    status,admission,_=observe('post_pass_removal')
    assert status['effective_state']=='ACTION_REQUIRED' and status['remaining_lease_ms']==0
    action=status['action'];assert action is not None
    stations=capture.stations
    app=create_app(access_service=world[0],runtime_control=stations.runtime,recipe_service=stations.recipes,
        station_service=stations,capture_service=capture,observation_service=service,app_origin='https://proofpack.test')
    with TestClient(app,base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        assert client.get('/api/v1/inspections/'+started['inspection_id']).json()['effective_state']=='ACTION_REQUIRED'
        path='/api/v1/inspections/'+started['inspection_id']+'/actions/'+action['id']+'/complete'
        headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'ack-correction',
            'If-Match':str(status['state_version'])}
        assert client.post(path,json={'passed':True},headers=headers).status_code==400
        assert client.post(path,json={},headers={**headers,'Origin':'https://evil.invalid'}).status_code==403
        assert client.post(path,json={},headers={**headers,'If-Match':'1'}).status_code==409
        response=client.post(path,json={},headers=headers);assert response.status_code==200
        ack=response.json()
    assert ack['effective_state']=='OBSERVING' and ack['remaining_lease_ms']==0 and ack['action'] is None
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['corrections']==1 and work.data['stable_ticks_ns']==[]
    assert world[1].snapshot((action_key(action['id']),))[action_key(action['id'])].data['status']=='acknowledged'


@pytest.mark.parametrize('fault',['store','expired','purpose','logout','commit'])
def test_publication_failure_never_commits_a_pass(world,publication_case,fault):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    if fault=='store':objects.unavailable=True
    elif fault=='expired':objects.after_put=lambda:setattr(clock,'value',clock.value+1000000000)
    elif fault=='purpose':
        def withdraw():
            row=world[1].snapshot((purpose,))[purpose]
            world[1].transact((Write(purpose,row.revision,{**row.data,'withdrawn':True}),))
        objects.after_put=withdraw
    elif fault=='logout':objects.after_put=lambda:service.access.logout(credentials.cookie,csrf=credentials.csrf)
    else:
        transact=world[1].transact
        def reject_publication(writes,checks=()):
            if any(write.data.get('derivation')=='rectified_roi_jpeg' for write in writes):
                raise StoreConflict('synthetic final publication conflict')
            return transact(writes,checks)
        world[1].transact=reject_publication
    with pytest.raises((Denied,StoreUnavailable,StoreConflict)):observe()
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['state'] in {'INVALIDATED','REVIEW_REQUIRED'}
    assert work.data['verified_sequence']==0 and work.data['deadline_tick_ns']==0 and work.data['corrections']==0
    if fault=='commit':
        ident=work.data['failure_reason'];assert ident=='authority_changed'
        # Uploaded output remains in its private reconciliation intent, not a linked asset.
        assert objects.heads
        from proofpack.capture.publication import intent_key,asset_key
        for observation_id in objects.heads:
            intent=world[1].snapshot((intent_key(observation_id),))[intent_key(observation_id)]
            assert intent.data['status']=='uploaded' and intent.data['version_id']
            assert world[1].snapshot((asset_key(observation_id),))[asset_key(observation_id)] is None


@pytest.mark.parametrize('fault',['calibration','coverage'])
def test_publication_rejects_worker_result_with_wrong_profile_or_missing_constraint(world,publication_case,monkeypatch,fault):
    from proofpack.vision.worker import VisionWorker
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    analyze=VisionWorker.analyze
    def changed(worker,*args,**kwargs):
        result=analyze(worker,*args,**kwargs)
        return result.model_copy(update={'calibration_hash':'f'*64} if fault=='calibration' else {'findings':result.findings[:-1]})
    monkeypatch.setattr(VisionWorker,'analyze',changed)
    with pytest.raises(Denied):observe()
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['state']=='REVIEW_REQUIRED' and work.data['verified_sequence']==0
    assert not objects.heads


@pytest.mark.parametrize('fault',['expired','store','purpose','asset','missing_pointer','atomic_race'])
def test_publication_current_status_withdraws_on_expiry_storage_or_permission_loss(world,publication_case,fault):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    for _ in range(3):status,admission,_=observe()
    assert status['effective_state']=='PASSED_CURRENT'
    if fault=='expired':clock.value+=1000000000
    elif fault=='store':objects.unavailable=True
    elif fault=='purpose':
        row=world[1].snapshot((purpose,))[purpose]
        world[1].transact((Write(purpose,row.revision,{**row.data,'withdrawn':True}),))
    elif fault=='asset':
        from proofpack.capture.publication import asset_key
        key=asset_key(admission['id']);row=world[1].snapshot((key,))[key]
        world[1].transact((Write(key,row.revision,{**row.data,'read_denied':True}),))
    elif fault=='missing_pointer':
        key=inspection_key(started['inspection_id']);row=world[1].snapshot((key,))[key]
        world[1].transact((Write(key,row.revision,{**row.data,'latest_observation_id':None}),))
    else:
        snapshot=world[1].snapshot;changed=False
        def race(keys):
            nonlocal changed
            if len(keys)>10 and observation_key(admission['id']) in keys and not changed:
                changed=True;row=snapshot((purpose,))[purpose]
                world[1].transact((Write(purpose,row.revision,{**row.data,'withdrawn':True}),))
            return snapshot(keys)
        world[1].snapshot=race
    status=service.status(operator,started['inspection_id'])
    assert status['effective_state']=='INVALIDATED' and status['remaining_lease_ms']==0


def test_publication_third_correction_requires_review_and_duplicate_ack_does_not_recharge(world,publication_case):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    for number in range(2):
        status,_,_=observe('missing')
        assert status['effective_state']=='ACTION_REQUIRED'
        args={'inspection_id':started['inspection_id'],'action_id':status['action']['id'],
            'expected_version':status['state_version'],'idempotency_key':'ack-'+str(number)}
        service.acknowledge(operator,**args);service.acknowledge(operator,**args)
        key=inspection_key(started['inspection_id'])
        assert world[1].snapshot((key,))[key].data['corrections']==number+1
    status,_,_=observe('missing')
    assert status['effective_state']=='REVIEW_REQUIRED' and status['remaining_lease_ms']==0
    assert world[1].snapshot((key,))[key].data['corrections']==2


@pytest.fixture
def http_publication(world,publication_case):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    stations=capture.stations
    app=create_app(access_service=world[0],runtime_control=stations.runtime,recipe_service=stations.recipes,
        station_service=stations,capture_service=capture,observation_service=service,app_origin='https://proofpack.test')
    def request(condition='complete'):
        import cv2
        from proofpack.vision.fixtures import make_fixture
        clock.value+=500000000;world[2].value+=500
        key=inspection_key(started['inspection_id']);work=world[1].snapshot((key,))[key]
        permit=capture_permit(capture,started,operator,version=work.revision,key='http-input-'+str(work.revision))
        frame,_=make_fixture(0,condition,seed=1);ok,encoded=cv2.imencode('.png',frame);assert ok
        return {'url':'/api/v1/inspections/'+started['inspection_id']+'/observations',
            'data':{'permit_id':permit['permit_id'],'nonce':permit['nonce'],'sequence':str(permit['sequence'])},
            'files':{'image':('capture.png',encoded.tobytes(),'image/png')},
            'headers':{'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'upload-'+permit['permit_id'],
                'If-Match':str(permit['inspection_state_version'])}}
    with TestClient(app,base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        yield client,request


def test_http_upload_real_pipeline_retry_does_not_reprocess_or_extend_lease(world,publication_case,http_publication):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    client,request=http_publication
    for expected in ('OBSERVING','OBSERVING','PASSED_CURRENT'):
        args=request();response=client.post(**args);assert response.status_code==200,response.text
        output=response.json();assert output['status']['effective_state']==expected and not output['replayed']
        assert output['operation_status']=='completed' and output['measurement']['findings']==['SATISFIED']*4
        assert not {'payload','nonce','object_key','object_version','evidence_jpeg_base64'}&set(output)
    assert len(objects.heads)==3
    key=inspection_key(started['inspection_id']);work=world[1].snapshot((key,))[key]
    duplicate=client.post(**args);assert duplicate.status_code==200
    assert duplicate.json()['replayed'] and duplicate.json()['observation_id']==output['observation_id']
    assert world[1].snapshot((key,))[key]==work and len(objects.heads)==3
    changed={**args,'files':{'image':('capture.png',args['files']['image'][1]+b'changed','image/png')}}
    assert client.post(**changed).status_code==409
    clock.value+=1000000000
    late=client.post(**args);assert late.status_code==200 and late.json()['status']['effective_state']=='INVALIDATED'
    assert late.json()['status']['remaining_lease_ms']==0 and len(objects.heads)==3


def test_http_upload_authority_and_parser_failures_leave_permit_unconsumed(world,publication_case,http_publication):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    client,request=http_publication;args=request()
    headers=args['headers']
    assert client.post(**{**args,'headers':{**headers,'Origin':'https://evil.invalid'}}).status_code==403
    assert client.post(**{**args,'headers':{**headers,'X-CSRF-Token':'wrong'}}).status_code==403
    client.cookies.set(COOKIE,world[4].cookie)
    assert client.post(**args).status_code==403
    client.cookies.clear();assert client.post(**args).status_code==401
    client.cookies.set(COOKIE,credentials.cookie)
    assert client.post(**{**args,'data':{**args['data'],'passed':'true'}}).status_code==400
    assert client.post(**{**args,'files':{'image':('capture.png',b'not an image','image/png')}}).status_code==415
    row=world[1].snapshot((permit_key(args['data']['permit_id']),))[permit_key(args['data']['permit_id'])]
    assert row.data['status']=='issued' and not objects.heads and service._uploads=={}
    assert client.post(**args).status_code==200


def test_http_upload_pending_idempotent_reference_does_not_restart_processing(world,publication_case,http_publication,monkeypatch):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    client,request=http_publication;args=request()
    admitted=capture.admit(operator,inspection_id=started['inspection_id'],expected_version=int(args['headers']['If-Match']),
        permit_id=args['data']['permit_id'],nonce=args['data']['nonce'],sequence=int(args['data']['sequence']),
        payload=args['files']['image'][1],content_type='image/png',idempotency_key=args['headers']['Idempotency-Key'])
    def forbidden(*args,**kwargs):raise AssertionError('retry must not process admitted bytes again')
    monkeypatch.setattr(service,'process',forbidden)
    response=client.post(**args);assert response.status_code==200,response.text
    assert response.json()['replayed'] and response.json()['observation_id']==admitted['id']
    assert response.json()['operation_status']=='admitted' and response.json()['measurement'] is None
    assert not objects.heads


def test_http_upload_busy_gate_precedes_body_and_releases_exact_ticket(world,publication_case,http_publication):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    client,request=http_publication;args=request();ticket=service.begin_upload(operator,started['inspection_id'])
    try:
        response=client.post(args['url'],content=b'invalid body must not be parsed',headers={**args['headers'],'Content-Type':'application/json'})
        assert response.status_code==409 and len(service._uploads)==1
        service.end_upload('not-an-owned-ticket');assert len(service._uploads)==1
    finally:service.end_upload(ticket)
    assert service._uploads=={} and client.post(**args).status_code==200


def test_http_upload_same_person_new_session_cannot_replay_originating_work(world,publication_case,http_publication):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    client,request=http_publication;args=request()
    response=client.post(**args);assert response.status_code==200
    again=service.access.login(proof(world[2],'operator',mfa=False))
    client.cookies.set(COOKIE,again.cookie)
    args['headers']={**args['headers'],'X-CSRF-Token':again.csrf}
    assert client.post(**args).status_code==403 and len(objects.heads)==1
    assert service._uploads=={}


def test_http_upload_expired_permit_does_not_decode_or_consume(world,publication_case,http_publication):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    client,request=http_publication;args=request();clock.value+=1000000000
    response=client.post(**args);assert response.status_code==403
    key=inspection_key(started['inspection_id']);work=world[1].snapshot((key,))[key]
    assert work.data['latest_input_sequence']==0 and work.data['verified_sequence']==0
    assert not objects.heads and service._uploads=={}


def test_capture_context_is_originating_operator_geometry_without_private_media(world,publication_case,http_publication):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    client,_=http_publication;path='/api/v1/inspections/'+started['inspection_id']+'/capture-context'
    response=client.get(path);assert response.status_code==200,response.text
    context=response.json()
    assert context['frame_width']==800 and context['frame_height']==500
    # Nominal analytic placement differs slightly from enrolled subpixel corners.
    # Use the profile's stated pixel envelope, not an invented 0.05-pixel oracle.
    for point,expected in zip(context['work_polygon'],[(100,100),(699,100),(699,399),(100,399)],strict=True):
        assert [point[0]*800,point[1]*500]==pytest.approx(expected,abs=synthetic_profile().max_reprojection_error_px)
    assert context['capture_transform']=='center_crop_resize_no_upscale' and context['context_version']==1
    assert context['data_origin']=='synthetic' and len(context['constraints'])==4
    assert not {'profile_json','object_key','object_version','nonce','csrf_token','reference_asset_ids'}&set(context)
    client.cookies.set(COOKIE,world[4].cookie);assert client.get(path).status_code==403
    newer=service.access.login(proof(world[2],'operator',mfa=False));client.cookies.set(COOKIE,newer.cookie)
    assert client.get(path).status_code==403


@pytest.mark.parametrize('fault',['purpose','profile','atomic_race'])
def test_capture_context_denies_unavailable_or_changed_dependencies(world,publication_case,fault):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    if fault=='purpose':
        row=world[1].snapshot((purpose,))[purpose]
        world[1].transact((Write(purpose,row.revision,{**row.data,'withdrawn':True}),))
    elif fault=='profile':
        key=inspection_key(started['inspection_id']);work=world[1].snapshot((key,))[key]
        calkey=Key('state','calibration-active#'+work.data['calibration_profile_id']);row=world[1].snapshot((calkey,))[calkey]
        world[1].transact((Write(calkey,row.revision,{**row.data,'profile_json':'{}'}),))
    else:
        snapshot=world[1].snapshot;reads=0
        def race(keys):
            nonlocal reads
            if len(keys)>10 and purpose in keys:
                reads+=1
                row=snapshot((purpose,))[purpose]
                world[1].transact((Write(purpose,row.revision,{**row.data,'withdrawn':True}),))
            return snapshot(keys)
        world[1].snapshot=race
    with pytest.raises((Denied,StoreUnavailable,StoreConflict,ValueError)):service.context(operator,started['inspection_id'])


def test_idempotent_admission_concurrency_never_consumes_twice(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    permit=capture_permit(capture,started,operator)
    args={'inspection_id':started['inspection_id'],'expected_version':permit['inspection_state_version'],
        'permit_id':permit['permit_id'],'nonce':permit['nonce'],'sequence':permit['sequence'],'payload':b'synthetic trusted internal bytes',
        'content_type':'image/png','idempotency_key':'same-upload'}
    barrier=Barrier(2)
    def race():
        barrier.wait()
        try:return capture.admit(operator,**args)
        except StoreConflict:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:race(),range(2)))
    accepted=[result for result in results if result is not None];assert accepted
    replay=capture.admit(operator,**args)
    assert replay['replayed'] and all(result['id']==replay['id'] for result in accepted)
    key=inspection_key(started['inspection_id']);assert world[1].snapshot((key,))[key].data['latest_input_sequence']==1


@pytest.mark.parametrize('changed_body',[False,True])
def test_admission_resolves_exact_operation_when_permit_consumed_between_reads(world,recipe,changed_body):
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    permit=capture_permit(capture,started,operator)
    arguments={'inspection_id':started['inspection_id'],'expected_version':permit['inspection_state_version'],
        'permit_id':permit['permit_id'],'nonce':permit['nonce'],'sequence':permit['sequence'],'payload':b'original synthetic internal bytes',
        'content_type':'image/png','idempotency_key':'interleaved-upload'}
    snapshot=world[1].snapshot;committed=[];triggered=False
    def interleave(keys):
        nonlocal triggered
        if tuple(keys)==(permit_key(permit['permit_id']),) and not triggered:
            triggered=True;committed.append(capture.admit(operator,**arguments))
        return snapshot(keys)
    world[1].snapshot=interleave
    if changed_body:
        with pytest.raises(StoreConflict):capture.admit(operator,**{**arguments,'payload':b'changed synthetic internal bytes'})
    else:
        result=capture.admit(operator,**arguments)
        assert result['replayed'] and result['id']==committed[0]['id']
    assert triggered and len(committed)==1
    key=inspection_key(started['inspection_id'])
    assert snapshot((key,))[key].data['latest_input_sequence']==1


def test_owner_privilege_expires_at_recent_mfa_bound_without_revoking_member_session(world):
    access,repo,clock,uid,credentials,owner=world
    clock.value+=600000
    assert access.list_users(owner)['users']
    clock.value+=1
    assert access.me(owner)['id']==uid
    with pytest.raises(Denied):access.list_users(owner)
    renewed=access.resolve(access.login(proof(clock)).cookie)
    assert access.list_users(renewed)['users']


def test_restricted_session_view_exposes_bound_invitation_without_capability(world):
    access,repo,clock,uid,credentials,owner=world
    member,full,operator,restricted,invitation=invite_and_join(world)
    assert access.session_view(operator)['status']=='member'
    pending=access.create_invitation(owner,target_subject='pending',target_email='pending@example.invalid',roles=[Role.OPERATOR],ttl_seconds=60,idempotency_key='pending-view')
    invited=access.login(proof(clock,'pending',mfa=False),invitation_id=pending['id'])
    view=access.session_view(access.resolve(invited.cookie,allow_invitee=True))
    assert view['status']=='invitation_pending' and view['invitation_id']==pending['id']
    assert set(view)=={'status','invitation_id','session_id','csrf_token'}
    assert pending['capability'] not in json.dumps(view)


def test_transfer_review_only_bound_people_and_recent_target_can_accept(world):
    access,repo,clock,uid,credentials,owner=world
    member,full,operator,_,_=invite_and_join(world)
    transfer=access.begin_transfer(owner,target_id=member,expected_target_version=1,idempotency_key='preview-transfer')
    assert access.read_transfer(owner,transfer['id'])['eligible_for_accept'] is False
    view=access.read_transfer(operator,transfer['id'])
    assert view['requires_recent_mfa'] and not view['eligible_for_accept']
    target=access.resolve(access.login(proof(clock,'operator',mfa=True)).cookie)
    assert access.read_transfer(target,transfer['id'])['eligible_for_accept'] is True
    other,_,unrelated,_,_=invite_and_join(world,subject='unrelated')
    from proofpack.auth.service import ResourceUnavailable
    with pytest.raises(ResourceUnavailable):access.read_transfer(unrelated,transfer['id'])


def test_transfer_source_read_rechecks_recent_owner_mfa_after_snapshot(world,monkeypatch):
    access,repo,clock,uid,credentials,owner=world
    member,_,operator,_,_=invite_and_join(world)
    transfer=access.begin_transfer(owner,target_id=member,expected_target_version=1,idempotency_key='mfa-read-race')
    original=access._fresh;calls=0
    def expiring(actor,role=None,**kwargs):
        nonlocal calls
        calls+=1
        if calls==3:clock.value+=600001
        return original(actor,role,**kwargs)
    monkeypatch.setattr(access,'_fresh',expiring)
    with pytest.raises(Denied):access.read_transfer(owner,transfer['id'])


def test_transfer_target_preview_rechecks_mfa_age_after_final_auth_read(world,monkeypatch):
    access,repo,clock,uid,credentials,owner=world
    member,_,operator,_,_=invite_and_join(world,mfa=True)
    transfer=access.begin_transfer(owner,target_id=member,expected_target_version=1,idempotency_key='target-mfa-read-race')
    original=access._fresh;calls=0
    def expiring(actor,role=None,**kwargs):
        nonlocal calls
        calls+=1
        if calls==2:clock.value+=600001
        return original(actor,role,**kwargs)
    monkeypatch.setattr(access,'_fresh',expiring)
    view=access.read_transfer(operator,transfer['id'])
    assert view['requires_recent_mfa'] and not view['eligible_for_accept']


def test_qualification_review_preserves_failed_result_and_denies_activation(world,recipe):
    service,created,content=recipe_world(world,recipe);owner=world[5]
    qid,data=synthetic_recipe_qualification(world,service,created,content)
    assert service.qualification(owner,recipe_id=created['id'],qualification_id=qid)['eligible_for_approval']
    qid,data=synthetic_recipe_qualification(world,service,created,content,passed=False)
    view=service.qualification(owner,recipe_id=created['id'],qualification_id=qid)
    assert view['passed'] is False and view['eligible_for_approval'] is False
    assert view['reason_codes']==['FAILED_QUALIFICATION']
    with pytest.raises((ValueError,Denied,StoreUnavailable)):
        service.approve(owner,recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='failed-approve')


def test_readiness_review_does_not_enable_or_extend_expired_receipt(world):
    control=runtime_service(world);control.start();owner=world[5]
    ident,data,review=synthetic_readiness(world,control)
    view=control.readiness(owner,ident)
    assert view['eligible_for_enable'] and view['remaining_validity_ms']==60000
    assert control.read(owner)['inspection_enabled'] is False
    world[2].value+=60000
    with pytest.raises((Denied,StoreUnavailable)):control.readiness(owner,ident)
    assert control.read(owner)['inspection_enabled'] is False


def test_owner_review_http_reads_require_identity_and_never_change_runtime(world,recipe):
    access,repo,clock,uid,credentials,owner=world
    recipes,created,content=recipe_world(world,recipe)
    qid,_=synthetic_recipe_qualification(world,recipes,created,content)
    control=runtime_service(world);control.start();receipt,_,_=synthetic_readiness(world,control)
    member,full,operator,_,_=invite_and_join(world)
    transfer=access.begin_transfer(owner,target_id=member,expected_target_version=1,idempotency_key='http-review-transfer')
    app=create_app(access_service=access,app_origin='https://proofpack.test',recipe_service=recipes,runtime_control=control)
    paths=['/api/v1/auth/session',f'/api/v1/owner-transfers/{transfer["id"]}',
        f'/api/v1/recipes/{created["id"]}/qualifications/{qid}',f'/api/v1/admin/readiness/{receipt}']
    with TestClient(app,base_url='https://proofpack.test') as client:
        for path in paths:assert client.get(path).status_code==401
        client.cookies.set(COOKIE,credentials.cookie)
        for path in paths:assert client.get(path).status_code==200
        assert control.read(owner)['inspection_enabled'] is False
        client.cookies.set(COOKIE,full.cookie)
        assert client.get(paths[1]).status_code==200
        assert client.get(paths[2]).status_code==403
        assert client.get(paths[3]).status_code==403
def test_publication_rechecks_lease_after_last_authentication_read(world,publication_case,monkeypatch):
    service,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    for _ in range(3):status,_,_=observe()
    assert status['effective_state']=='PASSED_CURRENT'
    validated=False;advanced=False;validate=objects.validate;fresh=service.access._fresh
    def after_head(receipt):
        nonlocal validated
        result=validate(receipt);validated=True;return result
    def delayed_auth(*args,**kwargs):
        nonlocal advanced
        result=fresh(*args,**kwargs)
        if validated and not advanced:advanced=True;clock.value+=1000000000
        return result
    monkeypatch.setattr(objects,'validate',after_head);monkeypatch.setattr(service.access,'_fresh',delayed_auth)
    status=service.status(operator,started['inspection_id'])
    assert advanced and status['effective_state']=='INVALIDATED' and status['remaining_lease_ms']==0


def test_real_warm_prepare_bound_to_authority_and_failure_preserves_budget_fences_once(world,recipe):
    service,capture,started,operator,credentials,clock,registry=observation_world(world,recipe)
    with registry:
        with pytest.raises(StoreUnavailable):capture_permit(capture,started,operator)
        ready=service.prepare(operator,inspection_id=started['inspection_id'],expected_version=1,idempotency_key='prepare')
        assert ready['ready'] and 'worker_id' not in ready
        assert service.prepare(operator,inspection_id=started['inspection_id'],expected_version=1,idempotency_key='prepare')['ready']
        permit=capture_permit(capture,started,operator);admitted=admit_frame(capture,started,operator,permit)
        key=inspection_key(started['inspection_id']);work=world[1].snapshot((key,))[key]
        world[1].transact((Write(key,work.revision,{**work.data,'corrections':2}),))
        failed=service.fail(admitted['id'],reason='worker_unavailable')
        assert failed['status']=='failed'
        work=world[1].snapshot((key,))[key]
        assert work.data['state']=='REVIEW_REQUIRED' and work.data['corrections']==2 and work.data['pending_sequence'] is None
        station=capture.stations.view(world[5],work.data['station_id'])
        assert station['epoch']==2
        assert service.fail(admitted['id'],reason='worker_unavailable')['status']=='failed'
        assert capture.stations.view(world[5],work.data['station_id'])['epoch']==2
        with pytest.raises(Denied):service.prepare(operator,inspection_id=started['inspection_id'],expected_version=work.revision,idempotency_key='cannot-reset')
        with pytest.raises(StoreConflict):capture.stations.close(operator,inspection_id=started['inspection_id'],expected_version=work.revision,
            expected_epoch=2,reason='needs review',disposition=None,idempotency_key='no-disposition')


def test_expired_observation_failure_clears_pending_and_recovers_without_budget_reset(world,recipe):
    service,capture,started,operator,credentials,clock,registry=observation_world(world,recipe)
    with registry:
        service.prepare(operator,inspection_id=started['inspection_id'],expected_version=1,idempotency_key='prepare')
        permit=capture_permit(capture,started,operator);admitted=admit_frame(capture,started,operator,permit)
        clock.value+=1000000000;world[2].value+=1000
        assert service.fail(admitted['id'],reason='observation_expired')['status']=='failed'
        work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
        assert work.data['state']=='INVALIDATED' and work.data['latest_input_sequence']==1
        assert capture.stations.view(operator,work.data['station_id'])['epoch']==1
        recovered=capture_permit(capture,started,operator,version=work.revision,key='recover')
        assert recovered['sequence']==2 and recovered['usable']


def test_old_failure_after_close_and_new_worker_does_not_touch_new_work(world,recipe):
    service,capture,started,operator,credentials,clock,registry=observation_world(world,recipe)
    with registry:
        service.prepare(operator,inspection_id=started['inspection_id'],expected_version=1,idempotency_key='prepare')
        permit=capture_permit(capture,started,operator);admitted=admit_frame(capture,started,operator,permit)
        closed=capture.stations.close(operator,inspection_id=started['inspection_id'],expected_version=3,expected_epoch=1,
            reason='cancel old work',disposition='cancelled',idempotency_key='close')
        old=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
        newer=capture.stations.start(operator,station_id=old.data['station_id'],expected_version=closed['current']['state_version'],
            expected_epoch=2,recipe_id=old.data['recipe_id'],kit_id='next-kit',idempotency_key='next-kit')
        service.prepare(operator,inspection_id=newer['inspection_id'],expected_version=1,idempotency_key='prepare-next')
        assert service.fail(admitted['id'],reason='worker_unavailable')['status']=='discarded'
        registry.guard(old.data['station_id'],2,old.data['runtime_instance_id'])
        assert capture.stations.view(world[5],old.data['station_id'])['active_inspection_id']==newer['inspection_id']


def test_failure_cleanup_after_operator_logout_only_withdraws_own_work(world,recipe):
    service,capture,started,operator,credentials,clock,registry=observation_world(world,recipe)
    with registry:
        service.prepare(operator,inspection_id=started['inspection_id'],expected_version=1,idempotency_key='prepare')
        permit=capture_permit(capture,started,operator);admitted=admit_frame(capture,started,operator,permit)
        world[0].logout(credentials.cookie,credentials.csrf)
        assert service.fail(admitted['id'],reason='evidence_unavailable')['status']=='failed'
        assert capture.stations.inspection(world[5],started['inspection_id'])['effective_state']=='INVALIDATED'
        with pytest.raises(Denied):capture_permit(capture,started,operator,version=4,key='revoked')


def test_prepare_http_requires_auth_csrf_profile_and_rejects_client_ready_flags(world,recipe):
    service,capture,started,operator,credentials,clock,registry=observation_world(world,recipe)
    stations=capture.stations
    app=create_app(access_service=world[0],runtime_control=stations.runtime,recipe_service=stations.recipes,
        station_service=stations,capture_service=capture,observation_service=service,app_origin='https://proofpack.test')
    with registry:
        with TestClient(app,base_url='https://proofpack.test') as client:
            client.cookies.set(COOKIE,credentials.cookie)
            path='/api/v1/inspections/'+started['inspection_id']+'/prepare-capture'
            headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-warm','If-Match':'1'}
            assert client.post(path,json={'ready':True},headers=headers).status_code==400
            assert client.post(path,json={},headers={**headers,'Origin':'https://evil.invalid'}).status_code==403
            warmed=client.post(path,json={},headers=headers)
            assert warmed.status_code==200 and warmed.json()['ready'] and 'worker_id' not in warmed.json()
        assert registry._closed and registry._bindings=={}


def capture_world(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    clock=CaptureClock()
    # Protocol-only trusted worker boundary, explicitly not actual warm CV proof.
    capture=CaptureService(stations,worker_guard=lambda station,epoch,runtime:None,tick_ns=clock)
    return capture,started,operator,credentials,clock


def capture_permit(capture,started,operator,*,version=1,key='permit'):
    return capture.issue(operator,inspection_id=started['inspection_id'],expected_version=version,expected_epoch=1,idempotency_key=key)


def admit_frame(capture,started,operator,permit,*,payload=b'synthetic unprocessed frame'):
    return capture.admit(operator,inspection_id=started['inspection_id'],expected_version=permit['inspection_state_version'],
        permit_id=permit['permit_id'],nonce=permit['nonce'],sequence=permit['sequence'],payload=payload)


def test_capture_one_use_admission_hashes_actual_bytes_without_claiming_evidence(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    permit=capture_permit(capture,started,operator)
    assert permit['usable'] and permit['remaining_acceptance_ms']==1000 and permit['sequence']==1
    assert capture_permit(capture,started,operator)['nonce']==permit['nonce']
    with pytest.raises(StoreConflict):capture_permit(capture,started,operator,version=2,key='parallel-permit')
    observed=admit_frame(capture,started,operator,permit)
    assert observed['verified'] is False and observed['evidence_durable'] is False and observed['sequence']==1
    import hashlib
    assert observed['source_sha256']==hashlib.sha256(b'synthetic unprocessed frame').hexdigest()
    rows,_=world[1].query(prefix='observation#');assert len(rows)==1
    assert 'synthetic unprocessed frame' not in json.dumps(rows[0].data,default=str)
    saved=world[1].snapshot((permit_key(permit['permit_id']),))[permit_key(permit['permit_id'])]
    assert permit['nonce'] not in json.dumps(saved.data,default=str) and saved.data['status']=='consumed'
    with pytest.raises(StoreConflict):admit_frame(capture,started,operator,permit)
    with pytest.raises(StoreConflict):capture_permit(capture,started,operator,version=3,key='while-admitted')
    assert capture.stations.inspection(world[5],started['inspection_id'])['remaining_lease_ms']==0


def test_capture_default_worker_boundary_is_closed_and_boolean_not_attestation(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    missing=CaptureService(capture.stations,tick_ns=clock)
    with pytest.raises(StoreUnavailable):capture_permit(missing,started,operator)
    flag=CaptureService(capture.stations,worker_guard=lambda *args:True,tick_ns=clock)
    with pytest.raises(StoreUnavailable):capture_permit(flag,started,operator)
    assert world[1].query(prefix='capture-permit#')[0]==[]


def test_capture_age_expiry_replacement_never_extends_original_or_admitted_sequence(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    first=capture_permit(capture,started,operator)
    clock.value+=1000000000;world[2].value+=1000
    with pytest.raises(Denied):admit_frame(capture,started,operator,first)
    expired=capture_permit(capture,started,operator)
    assert expired['usable'] is False and expired['nonce'] is None and expired['remaining_acceptance_ms']==0
    second=capture_permit(capture,started,operator,version=2,key='retake')
    assert second['permit_id']!=first['permit_id'] and second['sequence']==1
    assert world[1].snapshot((permit_key(first['permit_id']),))[permit_key(first['permit_id'])].data['status']=='expired'
    with pytest.raises(StoreConflict):admit_frame(capture,started,operator,{**first,'inspection_state_version':3})
    assert admit_frame(capture,started,operator,second)['sequence']==1


def test_capture_wrong_nonce_sequence_and_clock_rollback_do_not_consume(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    permit=capture_permit(capture,started,operator)
    for changes in ({'nonce':'x'*43},{'sequence':2}):
        with pytest.raises(Denied):admit_frame(capture,started,operator,{**permit,**changes})
    clock.value-=1
    with pytest.raises(StoreUnavailable):admit_frame(capture,started,operator,permit)
    assert world[1].snapshot((permit_key(permit['permit_id']),))[permit_key(permit['permit_id'])].data['status']=='issued'


def test_capture_other_operator_same_user_new_session_and_review_state_deny(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    _,_,other,*_=invite_and_join(world,'other')
    with pytest.raises(Denied):capture_permit(capture,started,other)
    newer=world[0].login(proof(world[2],'operator',mfa=False))
    with pytest.raises(Denied):capture_permit(capture,started,world[0].resolve(newer.cookie))
    key=inspection_key(started['inspection_id']);row=world[1].snapshot((key,))[key]
    world[1].transact((Write(key,row.revision,{**row.data,'state':'REVIEW_REQUIRED'}),))
    with pytest.raises(StoreConflict):capture_permit(capture,started,operator,version=2)


def test_capture_concurrent_admission_consumes_once_and_creates_one_reservation(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe);permit=capture_permit(capture,started,operator)
    repo=world[1];original=repo.transact;barrier=Barrier(2)
    def transact(*args,**kwargs):barrier.wait(timeout=5);return original(*args,**kwargs)
    repo.transact=transact
    def admit():
        try:return admit_frame(capture,started,operator,permit)
        except StoreConflict:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:admit(),range(2)))
    repo.transact=original
    assert sum(result is not None for result in results)==1
    assert len(repo.query(prefix='observation#')[0])==1


def test_capture_logout_before_admission_commit_denies_without_consuming(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe);permit=capture_permit(capture,started,operator)
    repo=world[1];original=repo.transact;revoked=False
    def transact(*args,**kwargs):
        nonlocal revoked
        if not revoked:revoked=True;world[0].logout(credentials.cookie,credentials.csrf)
        return original(*args,**kwargs)
    repo.transact=transact
    with pytest.raises(StoreConflict):admit_frame(capture,started,operator,permit)
    assert repo.snapshot((permit_key(permit['permit_id']),))[permit_key(permit['permit_id'])].data['status']=='issued'
    assert repo.query(prefix='observation#')[0]==[]


def test_capture_permit_http_scope_csrf_and_no_public_observation_bypass(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe);stations=capture.stations
    app=create_app(access_service=world[0],runtime_control=stations.runtime,recipe_service=stations.recipes,
        station_service=stations,capture_service=capture,app_origin='https://proofpack.test')
    with TestClient(app,base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        path='/api/v1/inspections/'+started['inspection_id']+'/capture-permits'
        headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-permit','If-Match':'1'}
        assert client.post(path,json={'expected_epoch':1},headers={**headers,'Origin':'https://evil.invalid'}).status_code==403
        result=client.post(path,json={'expected_epoch':1},headers=headers)
        assert result.status_code==201 and result.json()['usable'] and result.headers['cache-control']=='no-store'
        assert client.post(path,json={'expected_epoch':1,'passed':True},headers=headers).status_code==400
        assert client.post('/api/v1/inspections/'+started['inspection_id']+'/observations',json={'passed':True},headers=headers).status_code==503


def test_capture_concurrent_idempotent_issue_returns_only_committed_nonce(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe)
    repo=world[1];original=repo.transact;barrier=Barrier(2)
    def transact(*args,**kwargs):barrier.wait(timeout=5);return original(*args,**kwargs)
    repo.transact=transact
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:capture_permit(capture,started,operator),range(2)))
    repo.transact=original
    assert results[0]['permit_id']==results[1]['permit_id'] and results[0]['nonce']==results[1]['nonce']
    assert len(repo.query(prefix='capture-permit#')[0])==1


def test_capture_upload_quota_denial_does_not_consume_permit(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe);permit=capture_permit(capture,started,operator)
    station=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])].data['station_id']
    world[1].transact((Write(Key('state','upload-quota#'+station),None,{'second':world[2]()//1000,'count':3}),))
    with pytest.raises(StationRateLimited):admit_frame(capture,started,operator,permit)
    assert world[1].snapshot((permit_key(permit['permit_id']),))[permit_key(permit['permit_id'])].data['status']=='issued'
    assert world[1].query(prefix='observation#')[0]==[]


def test_capture_expiring_during_admission_checks_cannot_consume(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe);permit=capture_permit(capture,started,operator)
    repo=world[1];original=repo.snapshot
    def snapshot(keys):
        rows=original(keys)
        if any(key.resource.startswith('upload-quota#') for key in keys):clock.value+=1000000000
        return rows
    repo.snapshot=snapshot
    with pytest.raises(Denied):admit_frame(capture,started,operator,permit)
    assert repo.query(prefix='observation#')[0]==[]


def test_capture_commit_returning_after_deadline_never_reports_processing_freshness(world,recipe):
    capture,started,operator,credentials,clock=capture_world(world,recipe);permit=capture_permit(capture,started,operator)
    repo=world[1];original=repo.transact
    def transact(writes,*args,**kwargs):
        result=original(writes,*args,**kwargs)
        if any(write.key.resource.startswith('observation#') for write in writes):clock.value+=1000000000
        return result
    repo.transact=transact
    admitted=admit_frame(capture,started,operator,permit)
    assert admitted['fresh_for_processing'] is False and admitted['verified'] is False and admitted['evidence_durable'] is False


class InjectedPolicyReader:
    """Explicit TEST-INJECTED assurance for existing component fixtures only.

    No software/image qualification runs here. Production construction never
    imports this class; genuine policy consumption has separate actual-run tests.
    """
    def __init__(self,access,runtime):self.access=access;self.runtime=runtime;self.repository=access.repository

    def read_current(self):
        from proofpack.planner.active import ActivePolicySnapshot
        from proofpack.planner.candidates import PolicyDraft
        from proofpack.calibrations.dependencies import canonical
        roots=self.repository.snapshot((POLICY,RUNTIME,DATA));policy=roots[POLICY]
        if (policy is None or policy.data.get('test_injected_policy') is not True or policy.data['status']!='approved'
                or policy.data['mode']!='deterministic_policy' or policy.data['environment']!=self.runtime.environment
                or policy.data['artifact_sha256']!=self.runtime.artifact_sha256 or policy.data['data_epoch']!=roots[DATA].data['epoch']):
            raise StoreUnavailable('current injected fixture policy required')
        expiry=int(policy.data['expires_at_ms'])
        def guard():
            current=self.repository.snapshot(tuple(roots))
            if current!=roots or not self.runtime.matches(roots[RUNTIME]) or self.access.now()>=expiry:
                raise StoreUnavailable('injected policy fixture changed or expired')
        guard()
        return ActivePolicySnapshot(policy,PolicyDraft.model_validate_json(canonical(policy.data['definition'])),tuple(roots.values()),expiry,guard)


def station_world(world,recipe,*,station_count=1,profile=None,environment="test"):
    """Synthetic private evidence only; no calibrated hardware, blob or beta proof."""
    from proofpack.calibrations.dependencies import digest as policy_digest
    access,repo,clock,uid,credentials,owner=world
    recipes,created,content=recipe_world(world,recipe,environment=environment,dimension_interval=profile is None)
    receipt_id=str(uuid4());purpose=str(uuid4());asset=content['reference_asset_ids'][0]
    calkey=Key('state','calibration-active#'+content['calibration_profile_id'])
    calhash='c'*64 if profile is None else profile.content_hash
    calextra={} if profile is None else {'profile_json':profile.model_dump_json()}
    from proofpack.calibrations.dependencies import digest
    report_id=str(uuid4())
    manifest=[{'asset_id':asset,'purpose_id':purpose,'asset_state_version':1,'purpose_state_version':1,'sha256':'d'*64}]
    existing_data=repo.snapshot((DATA,))[DATA]
    data_epoch=1 if existing_data is None else int(existing_data.data['epoch'])
    report={'id':report_id,'calibration_id':content['calibration_profile_id'],'revision':1 if profile is None else profile.revision,
        'profile_sha256':calhash,'passed':True,'reference_manifest':manifest,'data_epoch':data_epoch,
        'environment':environment,'artifact_sha256':'a'*64,'expires_at_ms':clock()+60000}
    report['sha256']=digest(report)
    repo.transact((*( (Write(DATA,None,{'epoch':1}),) if existing_data is None else () ),
        Write(Key('state','purpose#'+purpose),None,{'allowed_uses':['operation'],'withdrawn':False,'expires_at_ms':clock()+60000}),
        Write(Key('state','asset#'+asset),None,{'sha256':'d'*64,'purpose_id':purpose,'status':'committed',
            'read_denied':False,'data_origin':content['data_origin'],'expires_at_ms':clock()+60000}),
        Write(calkey,None,{'status':'approved','environment':environment,'data_origin':content['data_origin'],
            'profile_sha256':calhash,'dependency_receipt_id':receipt_id,**calextra}),
        Write(Key('state','calibration-dependencies#'+receipt_id),None,{'environment':environment,'profile_sha256':calhash,
            'profile_state_version':1,'data_epoch':data_epoch,'expires_at_ms':clock()+60000,'reference_manifest':manifest,
            'report_id':report_id,'report_sha256':report['sha256']}),
        Write(Key('state','calibration-report#'+report_id),None,report),
        Write(POLICY,None,{'status':'approved','mode':'deterministic_policy','environment':environment,
            'artifact_sha256':'a'*64,'controls_sha256':'b'*64,'data_epoch':data_epoch,'expires_at_ms':clock()+60000,
            'test_injected_policy':True,'policy_id':str(uuid4()),'policy_revision':1,'policy_revision_sha256':'c'*64,
            'activation_id':str(uuid4()),'activation_sha256':'d'*64,'qualification_id':str(uuid4()),'qualification_report_sha256':'e'*64,
            'definition':{'name':'Injected policy fixture','algorithm':'reason_priority_v1','priority':['SEPARATE_REGION','PLACE_FLAT','RECAPTURE']},
            'behavior_sha256':policy_digest({'algorithm':'reason_priority_v1','priority':['SEPARATE_REGION','PLACE_FLAT','RECAPTURE']})})))
    qid,qdata=synthetic_recipe_qualification(world,recipes,created,content)
    recipes.approve(owner,recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='station-recipe-approve')
    runtime=runtime_service(world,environment=environment);runtime.start();rid,*_=synthetic_readiness(world,runtime,environment=environment)
    runtime.enable(owner,expected_version=runtime.read(owner)['control_version'],receipt_id=rid,idempotency_key='station-runtime-enable')
    stations=StationService(access,runtime,recipes,tick_ns=lambda:5000000000,policy_reader=InjectedPolicyReader(access,runtime))
    enrolled=[stations.enroll(owner,name='Station '+str(index+1),calibration_profile_id=content['calibration_profile_id'],
        idempotency_key='enroll-'+str(index)) for index in range(station_count)]
    _,op_credentials,operator,*_=invite_and_join(world)
    return stations,enrolled,created,operator,op_credentials,content


def acquire_station(stations,operator,station,*,key='acquire'):
    view=stations.view(operator,station['station_id'])
    return stations.change(operator,station_id=view['id'],expected_version=view['state_version'],expected_epoch=view['epoch'],
        expected_owner_session_id=view['owner_session_id'],operation='acquire',idempotency_key=key)


def start_station(stations,operator,station,recipe,*,key='start'):
    view=stations.view(operator,station['station_id'])
    return stations.start(operator,station_id=view['id'],expected_version=view['state_version'],expected_epoch=view['epoch'],
        recipe_id=recipe['id'],kit_id='kit-'+key,idempotency_key=key)


def test_station_ownership_is_explicit_fenced_and_does_not_consume_capacity(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    with pytest.raises(Denied):acquire_station(stations,world[5],enrolled[0])
    acquired=acquire_station(stations,operator,enrolled[0]);assert acquired['epoch']==1
    assert world[1].snapshot((ALLOCATION,))[ALLOCATION].data['slots']=={}
    _,_,other,*_=invite_and_join(world,'other')
    current=stations.view(other,enrolled[0]['station_id'])
    kwargs={'station_id':current['id'],'expected_version':current['state_version'],'expected_epoch':current['epoch'],
        'expected_owner_session_id':current['owner_session_id'],'operation':'acquire'}
    with pytest.raises(Denied):stations.change(other,**kwargs,idempotency_key='silent-steal')
    taken=stations.change(other,**kwargs,takeover_ack=True,reason='supervised shift change',idempotency_key='takeover')
    assert taken['epoch']==2 and taken['current']['owned_by_current_session']
    # Historical first request cannot reclaim the old epoch/session.
    old=stations.change(operator,station_id=current['id'],expected_version=1,expected_epoch=0,
        expected_owner_session_id=None,operation='acquire',idempotency_key='acquire')
    assert old['epoch']==1 and old['current']['epoch']==2 and old['current']['owned_by_current_session'] is False


def test_station_two_slot_limit_close_once_and_start_after_capacity_release(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe,station_count=3)
    for index,station in enumerate(enrolled):acquire_station(stations,operator,station,key='acquire-'+str(index))
    first=start_station(stations,operator,enrolled[0],created,key='one')
    second=start_station(stations,operator,enrolled[1],created,key='two')
    assert stations.inspection(world[5],first['inspection_id'])['effective_state']=='CREATED'
    with pytest.raises(StoreConflict):start_station(stations,operator,enrolled[2],created,key='third-denied')
    closed=stations.close(operator,inspection_id=first['inspection_id'],expected_version=1,expected_epoch=1,
        reason='next kit',disposition=None,idempotency_key='close-one')
    assert closed['current']['owned_by_current_session'] and closed['current']['active_inspection_id'] is None
    assert stations.inspection(world[5],first['inspection_id'])['effective_state']=='CLOSED'
    stations.close(operator,inspection_id=first['inspection_id'],expected_version=1,expected_epoch=1,
        reason='next kit',disposition=None,idempotency_key='close-one')
    third=start_station(stations,operator,enrolled[2],created,key='three')
    assert len(world[1].snapshot((ALLOCATION,))[ALLOCATION].data['slots'])==2
    assert third['inspection_id']!=first['inspection_id']


def test_station_takeover_requires_disposition_and_atomically_closes_prior_work(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    repo=world[1];key=inspection_key(started['inspection_id']);work=repo.snapshot((key,))[key]
    repo.transact((Write(key,work.revision,{**work.data,'state':'REVIEW_REQUIRED'}),))
    _,_,other,*_=invite_and_join(world,'other')
    current=stations.view(other,enrolled[0]['station_id'])
    args={'station_id':current['id'],'expected_version':current['state_version'],'expected_epoch':1,
        'expected_owner_session_id':operator.session.data['id'],'takeover_ack':True,'reason':'reviewed transfer','operation':'acquire'}
    with pytest.raises(StoreConflict):stations.change(other,**args,idempotency_key='missing-disposition')
    result=stations.change(other,**args,disposition='human_accepted',idempotency_key='reviewed-takeover')
    assert result['epoch']==2 and result['current']['active_inspection_id'] is None
    assert repo.snapshot((ALLOCATION,))[ALLOCATION].data['slots']=={}
    historical=stations.inspection(world[5],started['inspection_id'])
    assert historical['effective_state']=='CLOSED' and historical['disposition']=='human_accepted' and historical['remaining_lease_ms']==0


def test_station_release_works_with_disabled_inspection_and_fences_originating_work(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    stations.runtime.disable(world[5],expected_version=3,reason='supervised stop',idempotency_key='runtime-stop')
    assert stations.inspection(world[5],started['inspection_id'])['effective_state']=='INVALIDATED'
    view=stations.view(operator,enrolled[0]['station_id'])
    released=stations.change(operator,station_id=view['id'],expected_version=view['state_version'],expected_epoch=1,
        operation='release',idempotency_key='release')
    assert released['current']['owner_session_id'] is None and released['epoch']==2
    assert world[1].snapshot((ALLOCATION,))[ALLOCATION].data['slots']=={}


def test_station_restart_preserves_reservations_until_explicit_cleanup(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    newer=runtime_service(world);newer.start()
    assert len(world[1].snapshot((ALLOCATION,))[ALLOCATION].data['slots'])==1
    assert stations.inspection(world[5],started['inspection_id'])['effective_state']=='INVALIDATED'
    with pytest.raises(Denied):acquire_station(stations,operator,enrolled[0],key='old-runtime-acquire')
    view=stations.view(operator,enrolled[0]['station_id'])
    stations.change(operator,station_id=view['id'],expected_version=view['state_version'],expected_epoch=1,operation='release',idempotency_key='old-runtime-release')
    assert world[1].snapshot((ALLOCATION,))[ALLOCATION].data['slots']=={}


def test_station_control_quota_denies_without_mutation_and_resumes_next_second(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);ident=enrolled[0]['station_id']
    for index in range(7):
        current=stations.view(operator,ident)
        stations.change(operator,station_id=ident,expected_version=current['state_version'],expected_epoch=1,operation='heartbeat',idempotency_key='beat-'+str(index))
    current=stations.view(operator,ident)
    with pytest.raises(StationRateLimited):stations.change(operator,station_id=ident,expected_version=current['state_version'],expected_epoch=1,operation='heartbeat',idempotency_key='too-fast')
    assert stations.view(operator,ident)['state_version']==current['state_version']
    world[2].value+=1000
    result=stations.change(operator,station_id=ident,expected_version=current['state_version'],expected_epoch=1,operation='heartbeat',idempotency_key='next-second')
    assert result['current']['epoch']==1


def test_station_origin_logout_and_dependency_withdrawal_invalidate_reads(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    world[0].logout(credentials.cookie,credentials.csrf)
    assert stations.inspection(world[5],started['inspection_id'])['effective_state']=='INVALIDATED'
    asset=world[1].snapshot((Key('state','asset#'+content['reference_asset_ids'][0]),))[Key('state','asset#'+content['reference_asset_ids'][0])]
    purpose=Key('state','purpose#'+asset.data['purpose_id']);row=world[1].snapshot((purpose,))[purpose]
    world[1].transact((Write(purpose,row.revision,{**row.data,'withdrawn':True}),))
    with pytest.raises(StoreUnavailable):stations.enroll(world[5],name='denied profile',calibration_profile_id=content['calibration_profile_id'],idempotency_key='withdrawn')


def test_station_final_capacity_slot_race_has_one_winner_no_orphan_inspection(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe,station_count=3)
    for index,station in enumerate(enrolled):acquire_station(stations,operator,station,key='acquire-'+str(index))
    start_station(stations,operator,enrolled[0],created,key='first')
    repo=world[1];original=repo.transact;barrier=Barrier(2)
    def transact(*args,**kwargs):barrier.wait(timeout=5);return original(*args,**kwargs)
    repo.transact=transact
    def start(index):
        try:return start_station(stations,operator,enrolled[index],created,key='racing-'+str(index))
        except StoreConflict:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(start,(1,2)))
    repo.transact=original
    assert sum(value is not None for value in results)==1
    assert len(repo.snapshot((ALLOCATION,))[ALLOCATION].data['slots'])==2
    inspections,_=repo.query(prefix='inspection#');assert len(inspections)==2


def test_station_operator_logout_before_start_commit_prevents_slot_reservation(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);repo=world[1];original=repo.transact;revoked=False
    def transact(*args,**kwargs):
        nonlocal revoked
        if not revoked:revoked=True;world[0].logout(credentials.cookie,credentials.csrf)
        return original(*args,**kwargs)
    repo.transact=transact
    with pytest.raises(StoreConflict):start_station(stations,operator,enrolled[0],created)
    assert repo.snapshot((ALLOCATION,))[ALLOCATION].data['slots']=={}
    inspections,_=repo.query(prefix='inspection#');assert inspections==[]


def test_station_http_roles_origin_versions_and_created_only_inspection(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    app=create_app(access_service=world[0],runtime_control=stations.runtime,recipe_service=stations.recipes,
        station_service=stations,app_origin='https://proofpack.test')
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.get('/api/v1/stations').status_code==401
        client.cookies.set(COOKIE,credentials.cookie)
        assert client.get('/api/v1/stations').status_code==200
        sid=enrolled[0]['station_id'];headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-acquire','If-Match':'1'}
        body={'expected_epoch':0,'expected_owner_session_id':None}
        assert client.post('/api/v1/stations/'+sid+'/acquire',json=body,headers={**headers,'Origin':'https://evil.invalid'}).status_code==403
        acquired=client.post('/api/v1/stations/'+sid+'/acquire',json=body,headers=headers)
        assert acquired.status_code==200 and acquired.json()['epoch']==1
        start={'station_id':sid,'expected_version':2,'expected_epoch':1,'recipe_id':created['id'],'kit_id':'opaque-kit'}
        post=client.post('/api/v1/inspections',json=start,headers={**headers,'Idempotency-Key':'http-start'})
        assert post.status_code==201
        ident=post.json()['inspection_id'];status=client.get('/api/v1/inspections/'+ident)
        assert status.status_code==200 and status.json()['effective_state']=='CREATED' and status.json()['remaining_lease_ms']==0
        assert client.post('/api/v1/inspections',json={**start,'passed':True},headers=headers).status_code==400
        close=client.post('/api/v1/inspections/'+ident+'/close',json={'expected_epoch':1,'reason':'finished demo'},headers={**headers,'Idempotency-Key':'http-close'})
        assert close.status_code==200 and close.json()['current']['epoch']==2
        assert client.get('/api/v1/inspections/'+ident).json()['effective_state']=='CLOSED'


def test_station_profile_change_atomically_closes_work_and_clears_ownership(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    current=stations.view(world[5],enrolled[0]['station_id'])
    changed=stations.change(world[5],station_id=current['id'],expected_version=current['state_version'],
        operation='profile',name='Requalified setup',calibration_profile_id=content['calibration_profile_id'],idempotency_key='profile-change')
    assert changed['epoch']==2 and changed['current']['owner_session_id'] is None
    assert stations.inspection(world[5],started['inspection_id'])['effective_state']=='CLOSED'
    assert world[1].snapshot((ALLOCATION,))[ALLOCATION].data['slots']=={}


def test_station_wrong_owner_and_stale_epoch_cannot_release(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);_,_,other,*_=invite_and_join(world,'other')
    current=stations.view(operator,enrolled[0]['station_id'])
    args={'station_id':current['id'],'expected_version':current['state_version'],'operation':'release'}
    with pytest.raises(Denied):stations.change(other,**args,expected_epoch=1,idempotency_key='foreign-release')
    with pytest.raises(StoreConflict):stations.change(operator,**args,expected_epoch=0,idempotency_key='old-fence')
    assert stations.view(operator,current['id'])['epoch']==1


def test_station_failed_policy_and_postcommit_expiry_never_publish_current_pass(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);repo=world[1];policy=repo.snapshot((POLICY,))[POLICY]
    repo.transact((Write(POLICY,policy.revision,{**policy.data,'status':'retired'}),))
    with pytest.raises(StoreUnavailable):start_station(stations,operator,enrolled[0],created,key='bad-policy')
    policy=repo.snapshot((POLICY,))[POLICY];repo.transact((Write(POLICY,policy.revision,{**policy.data,'status':'approved'}),))
    original=repo.transact
    def slow(*args,**kwargs):
        result=original(*args,**kwargs);world[2].value+=60000;return result
    repo.transact=slow
    started=start_station(stations,operator,enrolled[0],created,key='slow-start')
    assert stations.inspection(world[5],started['inspection_id'])['effective_state']=='INVALIDATED'


def test_runtime_never_recreates_missing_allocation_after_initial_epoch(world):
    repo=world[1];row=repo.snapshot((RUNTIME,))[RUNTIME]
    repo.transact((Write(RUNTIME,row.revision,{**row.data,'runtime_epoch':1}),))
    with pytest.raises(StoreUnavailable):runtime_service(world).start()
    assert repo.snapshot((ALLOCATION,))[ALLOCATION] is None


def test_station_beta_calibration_reader_rejects_synthetic_origin_even_with_matching_private_receipt(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    repo=world[1];calkey=Key('state','calibration-active#'+content['calibration_profile_id']);cal=repo.snapshot((calkey,))[calkey]
    old=Key('state','calibration-dependencies#'+cal.data['dependency_receipt_id']);receipt=repo.snapshot((old,))[old];newid=str(uuid4())
    repo.transact((Write(calkey,cal.revision,{**cal.data,'environment':'beta','dependency_receipt_id':newid}),
        Write(Key('state','calibration-dependencies#'+newid),None,{**receipt.data,'environment':'beta','profile_state_version':cal.revision+1})))
    runtime=runtime_service(world,environment='beta')
    recipes=RecipeService(world[0],environment='beta',artifact_sha256='a'*64)
    beta=StationService(world[0],runtime,recipes)
    with pytest.raises(StoreUnavailable):beta._calibration(content['calibration_profile_id'])


def test_station_status_final_snapshot_rechecks_originating_session(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    repo=world[1];original=repo.snapshot;revoked=False
    def snapshot(keys):
        nonlocal revoked
        rows=original(keys)
        if not revoked and POLICY in keys and inspection_key(started['inspection_id']) in keys:
            revoked=True;world[0].logout(credentials.cookie,credentials.csrf)
        return rows
    repo.snapshot=snapshot
    assert stations.inspection(world[5],started['inspection_id'])['effective_state']=='INVALIDATED'


def recipe_world(world,recipe,*,environment='test',dimension_interval=True):
    service=RecipeService(world[0],environment=environment,artifact_sha256='a'*64)
    content={key:value for key,value in recipe.model_dump(mode='json').items() if key not in {'recipe_id','revision'}}
    content['reference_asset_ids']=[str(uuid4())]
    if dimension_interval:content['constraints'][0]['dimension_mm']={'minimum':1.25,'maximum':3.75}
    created=service.create(world[5],content=content,idempotency_key='recipe-create')
    return service,created,content


def synthetic_recipe_qualification(world,service,created,content,*,changes=None,passed=True):
    """Private synthetic metadata witnesses, not physical/S3 qualification evidence."""
    access,repo,clock,uid,credentials,owner=world
    ident=created['id'];number=created['revision'];qid=str(uuid4());purpose_id=str(uuid4())
    rev=repo.snapshot((revision_key(ident,number),))[revision_key(ident,number)]
    data=repo.snapshot((DATA,))[DATA]
    if data is None:repo.transact((Write(DATA,None,{'epoch':1}),))
    calkey=Key('state','calibration-active#'+content['calibration_profile_id'])
    cal=repo.snapshot((calkey,))[calkey]
    if cal is None:
        repo.transact((Write(calkey,None,{'status':'approved','profile_sha256':'c'*64,
            'environment':service.environment,'data_origin':content['data_origin']}),))
        cal=repo.snapshot((calkey,))[calkey]
    manifest=[];writes=[]
    writes.append(Write(Key('state','purpose#'+purpose_id),None,{'allowed_uses':['operation'],'withdrawn':False,'expires_at_ms':clock()+60000}))
    for asset_id in content['reference_asset_ids']:
        assetkey=Key('state','asset#'+asset_id);asset=repo.snapshot((assetkey,))[assetkey]
        if asset is None:
            writes.append(Write(assetkey,None,{'sha256':'d'*64,'purpose_id':purpose_id,'status':'committed',
                'read_denied':False,'data_origin':content['data_origin'],'expires_at_ms':clock()+60000}))
            manifest.append({'asset_id':asset_id,'purpose_id':purpose_id,'asset_state_version':1,'purpose_state_version':1,'sha256':'d'*64})
        else:
            old_purpose=repo.snapshot((Key('state','purpose#'+asset.data['purpose_id']),))[Key('state','purpose#'+asset.data['purpose_id'])]
            manifest.append({'asset_id':asset_id,'purpose_id':asset.data['purpose_id'],'asset_state_version':asset.revision,
                'purpose_state_version':old_purpose.revision,'sha256':asset.data['sha256']})
    qualification=Qualification(run_id=qid,recipe_id=ident,recipe_revision=number,
        calibration_profile_id=content['calibration_profile_id'],data_origin=Origin(content['data_origin']),
        passed=passed,artifact_sha256=service.artifact_sha256,reviewer_id=uid)
    qdata={'qualification_json':qualification.model_dump_json(),'recipe_sha256':rev.data['sha256'],
        'environment':service.environment,'data_epoch':1 if data is None else int(data.data['epoch']),'calibration_state_version':cal.revision,
        'calibration_sha256':cal.data['profile_sha256'],'reference_manifest':manifest,'expires_at_ms':clock()+60000,**(changes or {})}
    from proofpack.calibrations.dependencies import digest as record_digest
    qdata.update({'notice_version':access.config.notice_version,'notice_sha256':digest(access.config.notice_text),'case_manifest':[],'calibration_dependencies':[{'table':'state','resource':cal.key.resource,'revision':cal.revision,'sha256':record_digest(cal.data)}],'report_id':qid})
    report={**qdata,'id':qid,'recipe_id':ident,'recipe_revision':number,'passed':passed,'diagnostic_passed':passed,
        'results':[{'synthetic_private_assurance_fixture':True}],'physical_truth_verified':False,'independence_verified':False}
    report['sha256']=record_digest(report);qdata['report_sha256']=report['sha256']
    writes.append(Write(Key('state','recipe-qualification-report#'+qid),None,report))
    writes.append(Write(qualification_key(qid),None,qdata));repo.transact(tuple(writes))
    return qid,qdata


def test_recipe_immutable_json_draft_versions_and_idempotent_creation(world,recipe):
    service,created,content=recipe_world(world,recipe);repo=world[1];owner=world[5]
    assert service.create(owner,content=content,idempotency_key='recipe-create')['id']==created['id']
    with pytest.raises(StoreConflict):service.create(owner,content={**content,'name':'different'},idempotency_key='recipe-create')
    first=repo.snapshot((revision_key(created['id'],1),))[revision_key(created['id'],1)]
    saved=service.save(owner,recipe_id=created['id'],expected_version=1,content={**content,'name':'Second draft'},idempotency_key='save')
    assert saved['revision']==2 and saved['state_version']==2
    assert repo.snapshot((first.key,))[first.key]==first
    assert service.draft(owner,created['id'])['content']['constraints'][0]['dimension_mm']['minimum']==1.25
    with pytest.raises(StoreConflict):service.save(owner,recipe_id=created['id'],expected_version=1,content=content,idempotency_key='stale')
    assert service.list(owner,view='approved')['recipes']==[]


def test_recipe_approval_edit_retire_and_historical_replay_never_reactivate(world,recipe):
    service,created,content=recipe_world(world,recipe);owner=world[5];ident=created['id']
    qid,qdata=synthetic_recipe_qualification(world,service,created,content)
    approved=service.approve(owner,recipe_id=ident,expected_version=1,qualification_id=qid,idempotency_key='approve')
    assert approved['current']['effective_approved'] and approved['current']['active_revision']==1
    saved=service.save(owner,recipe_id=ident,expected_version=2,content={**content,'name':'Private unfinished candidate'},idempotency_key='save')
    assert saved['revision']==2 and saved['current']['active_revision']==1
    rows,active,deadline=service.active_snapshot(ident);assert active.name==content['name']
    public=service.list(owner)['recipes'][0]
    assert public['name']==content['name'] and 'latest_revision' not in public
    with pytest.raises(StoreUnavailable):service.approve(owner,recipe_id=ident,expected_version=3,qualification_id=qid,idempotency_key='old-qualification')
    retired=service.retire(owner,recipe_id=ident,expected_version=3,reason='qualification needs new run',idempotency_key='retire')
    assert retired['current']['effective_approved'] is False
    replay=service.approve(owner,recipe_id=ident,expected_version=1,qualification_id=qid,idempotency_key='approve')
    assert replay['operation']=='approved' and replay['current']['effective_approved'] is False
    assert service.list(owner)['recipes']==[]


@pytest.mark.parametrize('dependency',['purpose','asset','calibration','data','qualification'])
def test_recipe_active_reads_deny_changed_dependencies(world,recipe,dependency):
    service,created,content=recipe_world(world,recipe);owner=world[5];repo=world[1]
    qid,qdata=synthetic_recipe_qualification(world,service,created,content)
    service.approve(owner,recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='approve')
    manifest=qdata['reference_manifest'][0]
    key={'purpose':Key('state','purpose#'+manifest['purpose_id']),'asset':Key('state','asset#'+manifest['asset_id']),
        'calibration':Key('state','calibration-active#'+content['calibration_profile_id']),'data':DATA,'qualification':qualification_key(qid)}[dependency]
    row=repo.snapshot((key,))[key]
    changed={'purpose':{'withdrawn':True},'asset':{'read_denied':True},'calibration':{'status':'retired'},
        'data':{'epoch':2},'qualification':{'recipe_sha256':'0'*64}}[dependency]
    repo.transact((Write(key,row.revision,{**row.data,**changed}),))
    with pytest.raises(StoreUnavailable):service.active_snapshot(created['id'])
    assert service.list(owner)['recipes']==[]


def test_recipe_reference_deadline_denies_without_sweeper_and_beta_rejects_synthetic(world,recipe):
    service,created,content=recipe_world(world,recipe,environment='beta');qid,qdata=synthetic_recipe_qualification(world,service,created,content)
    with pytest.raises(StoreUnavailable):service.approve(world[5],recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='beta-synthetic')
    # A test service cannot reuse a differently scoped qualification either.
    test=RecipeService(world[0],environment='test',artifact_sha256='a'*64)
    with pytest.raises(StoreUnavailable):test.approve(world[5],recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='wrong-environment')


def test_recipe_approved_reference_expiry_hides_effective_approval(world,recipe):
    service,created,content=recipe_world(world,recipe);qid,qdata=synthetic_recipe_qualification(world,service,created,content)
    service.approve(world[5],recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='approve')
    world[2].value=qdata['expires_at_ms']
    with pytest.raises(StoreUnavailable):service.active_snapshot(created['id'])
    assert service.list(world[5])['recipes']==[]


def test_recipe_candidate_read_roles_and_cursor_scope(world,recipe):
    service,created,content=recipe_world(world,recipe);owner=world[5]
    service.create(owner,content={**content,'name':'Another draft'},idempotency_key='another')
    page=service.list(owner,view='candidates',limit=1);assert len(page['recipes'])==1 and page['next_cursor']
    assert len(service.list(owner,view='candidates',limit=1,cursor=page['next_cursor'])['recipes'])==1
    uid,credentials,operator,*_=invite_and_join(world)
    with pytest.raises(Denied):service.draft(operator,created['id'])
    with pytest.raises(Denied):service.list(operator,view='candidates')
    with pytest.raises(Denied):service.list(operator,cursor=page['next_cursor'])
    uid,credentials,reviewer,*_=invite_and_join(world,'reviewer',roles=(Role.REVIEWER,))
    assert service.draft(reviewer,created['id'])['revision']==1
    with pytest.raises(Denied):service.create(reviewer,content=content,idempotency_key='escalate')
    with pytest.raises(Denied):service.list(reviewer,view='candidates',cursor=page['next_cursor'])
    world[2].value+=300000
    with pytest.raises(Denied):service.list(owner,view='candidates',cursor=page['next_cursor'])


def test_recipe_http_drafts_validation_csrf_versions_and_no_client_pass_flags(world,recipe):
    service,created,content=recipe_world(world,recipe);access,repo,clock,uid,credentials,owner=world
    app=create_app(access_service=access,app_origin='https://proofpack.test',recipe_service=service)
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.get('/api/v1/recipes').status_code==401
        client.cookies.set(COOKIE,credentials.cookie)
        assert client.get('/api/v1/recipes?view=candidates').status_code==200
        headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-create'}
        assert client.post('/api/v1/recipes',json={'content':content},headers={**headers,'Origin':'https://evil.invalid'}).status_code==403
        response=client.post('/api/v1/recipes',json={'content':content},headers=headers)
        assert response.status_code==201
        ident=response.json()['id']
        assert client.get('/api/v1/recipes/'+ident+'/draft').json()['content']==content
        update={**headers,'If-Match':'1','Idempotency-Key':'http-save'}
        assert client.put('/api/v1/recipes/'+ident+'/draft',json={'content':{**content,'name':'Updated'}},headers=update).status_code==200
        assert client.put('/api/v1/recipes/'+ident+'/draft',json={'content':content},headers={**update,'Idempotency-Key':'stale-save'}).status_code==409
        assert client.post('/api/v1/recipes/'+ident+'/approve',json={'qualification_id':str(uuid4()),'passed':True},headers=update).status_code==400
        assert client.post('/api/v1/recipes',json={'content':{**content,'recipe_id':'client-owned'}},headers={**headers,'Idempotency-Key':'bad-id'}).status_code==400
        bad={**content,'constraints':[{**content['constraints'][0],'expected_count':True}]}
        assert client.post('/api/v1/recipes',json={'content':bad},headers={**headers,'Idempotency-Key':'bad-count'}).status_code==400
        assert client.post('/api/v1/recipes',json={'content':{**content,'name':'x'*9000}},headers=headers).status_code==413


def test_recipe_approval_journals_exact_revision_qualification_and_validity(world,recipe):
    service,created,content=recipe_world(world,recipe);qid,qdata=synthetic_recipe_qualification(world,service,created,content)
    service.approve(world[5],recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='approve')
    events,_=world[1].query(prefix='access#',table='events')
    approvals=[row for row in events if row.data['kind']=='recipe-approve:'+created['id']]
    assert len(approvals)==1
    details=approvals[0].data['details']
    assert details['qualification_id']==qid and details['recipe_sha256']==qdata['recipe_sha256']
    assert details['revision']==1 and details['valid_until_ms']==qdata['expires_at_ms'] and details['data_epoch']==1
    service.approve(world[5],recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='approve')
    events,_=world[1].query(prefix='access#',table='events')
    assert sum(row.data['kind']=='recipe-approve:'+created['id'] for row in events)==1


def test_recipe_approval_racing_purpose_withdrawal_cannot_commit(world,recipe):
    service,created,content=recipe_world(world,recipe);qid,qdata=synthetic_recipe_qualification(world,service,created,content)
    repo=world[1];original=repo.transact;changed=False;purpose=Key('state','purpose#'+qdata['reference_manifest'][0]['purpose_id'])
    def transact(*args,**kwargs):
        nonlocal changed
        if not changed:
            changed=True;row=repo.snapshot((purpose,))[purpose]
            original((Write(purpose,row.revision,{**row.data,'withdrawn':True}),))
        return original(*args,**kwargs)
    repo.transact=transact
    with pytest.raises(StoreConflict):service.approve(world[5],recipe_id=created['id'],expected_version=1,qualification_id=qid,idempotency_key='racing-approve')
    assert repo.snapshot((active_key(created['id']),))[active_key(created['id'])] is None


def test_concurrent_recipe_saves_preserve_one_version_and_no_orphan_revision(world,recipe):
    service,created,content=recipe_world(world,recipe);repo=world[1];original=repo.transact;barrier=Barrier(2)
    def transact(*args,**kwargs):
        barrier.wait(timeout=5);return original(*args,**kwargs)
    repo.transact=transact
    def save(name):
        try:return service.save(world[5],recipe_id=created['id'],expected_version=1,content={**content,'name':name},idempotency_key=name)
        except StoreConflict:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(save,('first','second')))
    repo.transact=original
    assert sum(value is not None for value in results)==1
    versions,_=repo.query(prefix='recipe-revision#'+created['id']);assert len(versions)==2
    assert service.draft(world[5],created['id'])['revision']==2


@pytest.mark.parametrize('cursor',['é.'+'a'*43,'abc.é','abc.'+'a'*43+'='])
def test_recipe_and_access_cursor_syntax_rejects_non_ascii_before_signature_comparison(world,recipe,cursor):
    service,created,content=recipe_world(world,recipe)
    with pytest.raises(ValueError):service.list(world[5],view='candidates',cursor=cursor)
    with pytest.raises(ValueError):world[0].list_users(world[5],cursor=cursor)
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',recipe_service=service)
    with TestClient(app,base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,world[4].cookie)
        assert client.get('/api/v1/recipes',params={'view':'candidates','cursor':cursor}).status_code==400
        assert client.get('/api/v1/users',params={'cursor':cursor}).status_code==400


def runtime_service(world,**changes):
    config={'instance_id':str(uuid4()),'artifact_sha256':'a'*64,'controls_sha256':'b'*64,'environment':'test',**changes}
    return RuntimeControl(world[0],**config)


def synthetic_readiness(world,control,**changes):
    """Inject explicit synthetic assurance rows; never a production evidence writer."""
    service,repo,clock,uid,credentials,owner=world
    row=repo.snapshot((RUNTIME,))[RUNTIME]
    data_head=repo.snapshot((DATA,))[DATA]
    if data_head is None:repo.transact((Write(DATA,None,{'epoch':1}),))
    ident=str(uuid4())
    data={'deployment':repo.deployment,'environment':'test','runtime_epoch':int(row.data['runtime_epoch']),
        'instance_id':control.instance_id,'artifact_sha256':control.artifact_sha256,'controls_sha256':control.controls_sha256,
        'control_version':int(row.data['control_version']),'data_epoch':1 if data_head is None else int(data_head.data['epoch']),'issued_at_ms':clock(),
        'expires_at_ms':clock()+60000,'checks':{name:True for name in CHECKS},**changes}
    review={'receipt_sha256':readiness_digest(data),'owner_user_id':uid,'owner_access_version':owner.member.data['access_version'],
        'approved':True}
    repo.transact((Write(Key('state','readiness#'+ident),None,data),Write(Key('state','readiness-review#'+ident),None,review)))
    return ident,data,review


def test_runtime_start_is_durable_monotone_disabled_and_old_replay_cannot_reclaim(world):
    first=runtime_service(world);handle=first.start();service,repo,clock,uid,credentials,owner=world
    assert handle.epoch==1 and first.read(owner)['inspection_enabled'] is False
    same=runtime_service(world,instance_id=handle.instance_id)
    assert same.start()==handle and same.read(owner)['control_version']==2
    with pytest.raises(StoreConflict):runtime_service(world,instance_id=handle.instance_id,artifact_sha256='c'*64).start()
    second=runtime_service(world);new_handle=second.start();assert new_handle.epoch==2
    assert first.start()==handle and first.read(owner)['local_instance_current'] is False
    assert second.read(owner)['local_instance_current'] is True
    assert first.read(owner)['runtime_epoch']==2


def test_runtime_starts_without_bootstrap_but_never_creates_owner(world,repository_factory):
    repo=repository_factory();clock=Clock()
    access=AccessService(repo,AuthConfig(repo.deployment,ISSUER,b'synthetic-key-for-runtime-only-123456'),clock_ms=clock)
    control=RuntimeControl(access,instance_id=str(uuid4()),artifact_sha256='a'*64,controls_sha256='b'*64,environment='test')
    assert control.start().epoch==1
    assert repo.snapshot((HEAD,))[HEAD] is None


def test_runtime_enable_needs_reviewed_receipt_and_disable_replay_never_reenables(world):
    control=runtime_service(world);control.start();owner=world[5]
    with pytest.raises(StoreUnavailable):control.enable(owner,expected_version=2,receipt_id=str(uuid4()),idempotency_key='missing')
    ident,*_=synthetic_readiness(world,control)
    enabled=control.enable(owner,expected_version=2,receipt_id=ident,idempotency_key='enable')
    assert enabled['control_version']==3 and enabled['current']['inspection_enabled'] is True
    assert control.enabled_snapshot()[RUNTIME].data['inspection_enabled'] is True
    disabled=control.disable(owner,expected_version=3,reason='operator reported capture issue',idempotency_key='disable')
    assert disabled['control_version']==4 and disabled['current']['inspection_enabled'] is False
    replay=control.enable(owner,expected_version=2,receipt_id=ident,idempotency_key='enable')
    assert replay['operation']=='enabled' and replay['current']['inspection_enabled'] is False
    assert replay['current']['control_version']==4
    assert control.disable(owner,expected_version=3,reason='operator reported capture issue',idempotency_key='disable')['current']['control_version']==4
    with pytest.raises(StoreConflict):control.disable(owner,expected_version=4,reason='different reason',idempotency_key='disable')
    with pytest.raises(Denied):control.enabled_snapshot()


@pytest.mark.parametrize('changes',[{'environment':'beta'},{'artifact_sha256':'c'*64},{'controls_sha256':'d'*64},
    {'data_epoch':2},{'runtime_epoch':99},{'control_version':1},{'instance_id':str(uuid4())},
    {'issued_at_ms':1000001},{'expires_at_ms':1000000},{'expires_at_ms':1060001},
    {'checks':{name:False for name in CHECKS}},{'checks':list(CHECKS)},{'checks':{}},{'checks':None}])
def test_runtime_failed_mismatched_or_expired_readiness_cannot_enable(world,changes):
    control=runtime_service(world);control.start();ident,*_=synthetic_readiness(world,control,**changes)
    with pytest.raises(StoreUnavailable):control.enable(world[5],expected_version=2,receipt_id=ident,idempotency_key='bad')
    assert control.read(world[5])['inspection_enabled'] is False


def test_runtime_admission_expires_even_without_sweeper_and_clock_cannot_revive(world):
    control=runtime_service(world);control.start();ident,data,_=synthetic_readiness(world,control)
    control.enable(world[5],expected_version=2,receipt_id=ident,idempotency_key='enable')
    world[2].value=data['expires_at_ms']
    assert control.read(world[5])['inspection_enabled'] is False
    with pytest.raises(StoreUnavailable):control.enabled_snapshot()
    world[2].value=data['issued_at_ms']-1
    with pytest.raises(StoreUnavailable):control.enabled_snapshot()


@pytest.mark.parametrize('target',['data','receipt','review','owner'])
def test_runtime_current_read_and_admission_deny_changed_dependencies(world,target):
    control=runtime_service(world);control.start();ident,data,review=synthetic_readiness(world,control)
    control.enable(world[5],expected_version=2,receipt_id=ident,idempotency_key='enable')
    service,repo,clock,uid,credentials,owner=world
    key={'data':DATA,'receipt':Key('state','readiness#'+ident),'review':Key('state','readiness-review#'+ident),'owner':user_key(uid)}[target]
    row=repo.snapshot((key,))[key]
    changed={'data':{'epoch':2},'receipt':{'checks':{name:False for name in CHECKS}},
        'review':{'approved':False},'owner':{'access_version':int(owner.member.data['access_version'])+1}}[target]
    repo.transact((Write(key,row.revision,{**row.data,**changed}),))
    with pytest.raises(StoreUnavailable):control.enabled_snapshot()
    if target!='owner':assert control.read(owner)['inspection_enabled'] is False


def test_superseded_runtime_can_disable_but_cannot_enable_new_incarnation(world):
    old=runtime_service(world);old.start();new=runtime_service(world);new.start()
    ident,*_=synthetic_readiness(world,new)
    with pytest.raises(Denied):old.enable(world[5],expected_version=3,receipt_id=ident,idempotency_key='old-enable')
    assert new.enable(world[5],expected_version=3,receipt_id=ident,idempotency_key='new-enable')['current']['inspection_enabled'] is True
    result=old.disable(world[5],expected_version=4,reason='emergency stop',idempotency_key='stop')
    assert result['current']['inspection_enabled'] is False and new.read(world[5])['inspection_enabled'] is False


def test_runtime_http_owner_origin_csrf_version_and_no_client_readiness_assertion(world):
    control=runtime_service(world);control.start();service,repo,clock,uid,credentials,owner=world
    app=create_app(access_service=service,app_origin='https://proofpack.test',runtime_control=control)
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.get('/api/v1/admin/runtime').status_code==401
        client.cookies.set(COOKIE,credentials.cookie)
        assert client.get('/api/v1/admin/runtime').json()['control_version']==2
        headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-disable','If-Match':'2'}
        assert client.post('/api/v1/admin/disable-inspection',json={'reason':'emergency stop'},headers={**headers,'Origin':'https://evil.invalid'}).status_code==403
        response=client.post('/api/v1/admin/disable-inspection',json={'reason':'emergency stop'},headers=headers)
        assert response.status_code==200 and response.json()['control_version']==3
        assert client.post('/api/v1/admin/enable-inspection',json={'receipt_id':str(uuid4()),'ready':True},headers={**headers,'If-Match':'3'}).status_code==400
        assert client.post('/api/v1/admin/enable-inspection',json={'receipt_id':str(uuid4())},headers={**headers,'If-Match':'3','Idempotency-Key':'missing-evidence'}).status_code==503
        assert client.post('/api/v1/admin/disable-inspection',json={'reason':'x'*9000},headers=headers).status_code==413
        assert client.get('/health/ready').status_code==503


def test_concurrent_runtime_starts_have_one_conditional_winner_without_orphan_markers(world):
    repo=world[1];first=runtime_service(world);second=runtime_service(world)
    original=repo.snapshot;barrier=Barrier(2)
    def snapshot(*args,**kwargs):
        rows=original(*args,**kwargs);barrier.wait(timeout=5);return rows
    repo.snapshot=snapshot
    def start(control):
        try:return control.start()
        except StoreConflict:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(start,(first,second)))
    repo.snapshot=original
    assert sum(value is not None for value in results)==1
    assert repo.snapshot((RUNTIME,))[RUNTIME].data['runtime_epoch']==1
    markers,_=repo.query(prefix='runtime-start#');assert len(markers)==1


def test_concurrent_enable_disable_cannot_both_commit_same_control_version(world):
    control=runtime_service(world);control.start();ident,*_=synthetic_readiness(world,control)
    repo=world[1];original=repo.transact;barrier=Barrier(2)
    def transact(*args,**kwargs):
        barrier.wait(timeout=5);return original(*args,**kwargs)
    repo.transact=transact
    def enable():
        try:return control.enable(world[5],expected_version=2,receipt_id=ident,idempotency_key='racing-enable')
        except StoreConflict:return None
    def disable():
        try:return control.disable(world[5],expected_version=2,reason='racing emergency stop',idempotency_key='racing-disable')
        except StoreConflict:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=[future.result() for future in (pool.submit(enable),pool.submit(disable))]
    repo.transact=original
    assert sum(value is not None for value in results)==1
    assert control.read(world[5])['control_version']==3


def test_logout_before_runtime_enable_commit_prevents_control_change(world):
    control=runtime_service(world);control.start();ident,*_=synthetic_readiness(world,control)
    service,repo,clock,uid,credentials,owner=world;original=repo.transact;revoked=False
    def transact(*args,**kwargs):
        nonlocal revoked
        if not revoked:
            revoked=True;service.logout(credentials.cookie,credentials.csrf)
        return original(*args,**kwargs)
    repo.transact=transact
    with pytest.raises(StoreConflict):control.enable(owner,expected_version=2,receipt_id=ident,idempotency_key='revoked-enable')
    assert repo.snapshot((RUNTIME,))[RUNTIME].data['inspection_enabled'] is False


def test_receipt_expiring_during_enable_commit_is_never_effectively_enabled(world):
    control=runtime_service(world);control.start();ident,data,_=synthetic_readiness(world,control)
    repo=world[1];original=repo.transact
    def transact(*args,**kwargs):
        result=original(*args,**kwargs);world[2].value=data['expires_at_ms'];return result
    repo.transact=transact
    result=control.enable(world[5],expected_version=2,receipt_id=ident,idempotency_key='slow-enable')
    assert result['operation']=='enabled' and result['current']['inspection_enabled'] is False
    with pytest.raises(StoreUnavailable):control.enabled_snapshot()


@pytest.mark.parametrize('role',[Role.OPERATOR,Role.REVIEWER])
def test_runtime_read_and_control_do_not_inherit_owner_permission(world,role):
    control=runtime_service(world);control.start()
    uid,credentials,actor,*_=invite_and_join(world,roles=(role,))
    with pytest.raises(Denied):control.read(actor)
    with pytest.raises(Denied):control.disable(actor,expected_version=2,reason='role escalation attempt',idempotency_key='forbidden')
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=control)
    with TestClient(app,base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        assert client.get('/api/v1/me').status_code==200
        result=client.get('/api/v1/admin/runtime')
        assert result.status_code==403 and 'artifact_sha256' not in result.text


def oauth(repo, clock, **changes):
    config=OAuthConfig(repo.deployment,'https://synthetic.auth.us-east-1.amazoncognito.com',
        'syntheticClient','https://proofpack.example.invalid/api/v1/auth/callback',b'local-only-oauth-fixture-private-key')
    return OAuthFlows(repo,replace(config,**changes),clock_ms=clock)


def oauth_query(start):
    from urllib.parse import parse_qs
    return {key:values[0] for key,values in parse_qs(urlsplit(start.authorization_url).query).items()}


@pytest.fixture(scope='module')
def oauth_signing_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537,key_size=2048)


def signed_provider(world,oauth_signing_key,*,subject='owner',claims_changes=None,invitation_id=None):
    import httpx,jwt
    from urllib.parse import parse_qs
    service,repo,clock,*_=world;flows=oauth(repo,clock);start=flows.begin(invitation_id=invitation_id);query=oauth_query(start)
    keys={'keys':[{**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(oauth_signing_key.public_key())),
        'kid':'synthetic-signing-key','alg':'RS256','use':'sig'}]}
    calls=[]
    def handler(request):
        calls.append(request.method)
        if request.method=='POST':
            assert parse_qs(request.content.decode())['code_verifier']
            claims={'iss':ISSUER,'aud':flows.config.client_id,'sub':subject,'exp':clock()//1000+3600,
                'iat':clock()//1000,'auth_time':clock()//1000,'nonce':query['nonce'],'token_use':'id',
                'email':subject+'@example.invalid','email_verified':True,'name':subject+' synthetic',
                'acr':'urn:cognito:loa:4','amr':['pwd','otp','mfa'],**(claims_changes or {})}
            data={'token_type':'Bearer','id_token':jwt.encode(claims,oauth_signing_key,algorithm='RS256',headers={'kid':'synthetic-signing-key'})}
        else:data=keys
        return httpx.Response(200,headers={'content-type':'application/json'},stream=httpx.ByteStream(json.dumps(data).encode()))
    tokens=CognitoTokens(CognitoConfig(ISSUER,flows.config.client_id),clock_ms=clock)
    provider=CognitoProvider(flows.config,tokens,transport=httpx.MockTransport(handler))
    return SignInService(flows,provider,service),start,query,calls


def test_signed_oauth_flow_creates_only_existing_member_session(world,oauth_signing_key):
    service,repo,clock,uid,*_=world;signin,start,query,calls=signed_provider(world,oauth_signing_key)
    credentials=signin.complete(state=query['state'],browser_cookie=start.browser_cookie,code='synthetic-code')
    actor=service.resolve(credentials.cookie)
    assert actor.member.data['id']==uid and actor.principal.subject=='owner' and actor.principal.mfa_verified
    assert calls==['POST','GET']
    with pytest.raises(Denied):signin.complete(state=query['state'],browser_cookie=start.browser_cookie,code='synthetic-code')
    assert calls==['POST','GET']  # Replay cannot repeat provider exchange or create another session.


def test_signed_unknown_identity_cannot_bootstrap_owner_or_join(world,oauth_signing_key):
    signin,start,query,calls=signed_provider(world,oauth_signing_key,subject='outsider')
    with pytest.raises(Denied):signin.complete(state=query['state'],browser_cookie=start.browser_cookie,code='synthetic-code')
    service,repo,*_=world;members,_=repo.query(prefix='user#');assert len(members)==1


def test_invalid_signed_nonce_creates_no_session(world,oauth_signing_key):
    signin,start,query,calls=signed_provider(world,oauth_signing_key,claims_changes={'nonce':'wrong-nonce'})
    service,repo,*_=world;before,_=repo.query(prefix='session#')
    with pytest.raises(Denied):signin.complete(state=query['state'],browser_cookie=start.browser_cookie,code='synthetic-code')
    after,_=repo.query(prefix='session#');assert len(before)==len(after)


def test_provider_error_consumes_flow_without_exchange_or_session(world,oauth_signing_key):
    signin,start,query,calls=signed_provider(world,oauth_signing_key)
    with pytest.raises(Denied) as error:signin.complete(state=query['state'],browser_cookie=start.browser_cookie,provider_error='sensitive provider text')
    assert 'sensitive' not in str(error.value) and calls==[]
    with pytest.raises(Denied):signin.complete(state=query['state'],browser_cookie=start.browser_cookie,code='synthetic-code')
    assert calls==[]


def test_signed_invitee_remains_restricted_until_notice_and_acceptance(world,oauth_signing_key):
    service,repo,clock,uid,credentials,owner=world
    invitation=service.create_invitation(owner,target_subject='invitee',target_email='invitee@example.invalid',
        roles=(Role.OPERATOR,),ttl_seconds=60,idempotency_key='signed-invitation')
    signin,start,query,calls=signed_provider(world,oauth_signing_key,subject='invitee',invitation_id=invitation['id'])
    restricted=signin.complete(state=query['state'],browser_cookie=start.browser_cookie,code='synthetic-code')
    assert restricted.restricted
    with pytest.raises(Denied):service.resolve(restricted.cookie)
    actor=service.resolve(restricted.cookie,allow_invitee=True)
    assert service.read_invitation(actor,invitation_id=invitation['id'])['status']=='pending'


def test_signed_disabled_identity_cannot_create_new_session(world,oauth_signing_key):
    service,repo,clock,uid,credentials,owner=world
    target,_,actor,*_=invite_and_join(world)
    service.change_access(owner,user_id=target,roles=(Role.OPERATOR,),enabled=False,
        expected_version=service.public_user(actor.member)['access_version'],idempotency_key='disable-before-provider-login')
    signin,start,query,calls=signed_provider(world,oauth_signing_key,subject='operator')
    before,_=repo.query(prefix='session#')
    with pytest.raises(Denied):signin.complete(state=query['state'],browser_cookie=start.browser_cookie,code='synthetic-code')
    after,_=repo.query(prefix='session#');assert len(after)==len(before)


def http_oauth(world,key,**changes):
    signin,_,query,calls=signed_provider(world,key,**changes)
    app=create_app(access_service=world[0],app_origin='https://proofpack.example.invalid',signin_service=signin)
    return TestClient(app,base_url='https://proofpack.example.invalid',follow_redirects=False),signin,query,calls


def start_http(client,query,path='/api/v1/auth/login'):
    from urllib.parse import parse_qs
    start=client.get(path)
    assert start.status_code==303
    query.clear();query.update({k:v[0] for k,v in parse_qs(urlsplit(start.headers['location']).query).items()})
    return start


def test_http_signin_fixed_redirect_secure_cookies_and_authenticated_session(world,oauth_signing_key):
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    with client:
        start=start_http(client,query)
        header=start.headers['set-cookie']
        assert FLOW_COOKIE in header and 'HttpOnly' in header and 'Secure' in header
        assert 'SameSite=lax' in header and 'Path=/' in header and 'Max-Age=300' in header and 'Domain=' not in header
        old_cookie=world[4].cookie
        client.cookies.set(COOKIE,old_cookie,domain='proofpack.example.invalid',path='/')
        callback=client.get('/api/v1/auth/callback',params={'state':query['state'],'code':'synthetic-code'})
        assert callback.status_code==303 and callback.headers['location']=='https://proofpack.example.invalid/'
        cookies=callback.headers.get_list('set-cookie')
        assert any(FLOW_COOKIE in value and 'Max-Age=0' in value for value in cookies)
        assert any(COOKIE+'=' in value and 'Secure' in value and 'HttpOnly' in value for value in cookies)
        assert client.cookies.get(COOKIE)!=old_cookie and client.cookies.get(FLOW_COOKIE) is None
        me=client.get('/api/v1/me');assert me.status_code==200 and me.json()['id']==world[3]
        assert 'no-store' in callback.headers['cache-control'] and callback.headers['referrer-policy']=='no-referrer'
        assert client.get('/health/ready').status_code==503
        assert calls==['POST','GET']


def test_http_callback_wrong_browser_clears_flow_but_does_not_consume_legitimate_flow(world,oauth_signing_key):
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    with client:
        start_http(client,query);browser=client.cookies.get(FLOW_COOKIE)
        client.cookies.clear()
        response=client.get('/api/v1/auth/callback',params={'state':query['state'],'code':'synthetic-code'})
        assert response.status_code==403 and calls==[] and client.cookies.get(COOKIE) is None
        assert any(FLOW_COOKIE in value and 'Max-Age=0' in value for value in response.headers.get_list('set-cookie'))
        client.cookies.set(FLOW_COOKIE,browser,domain='proofpack.example.invalid',path='/')
        assert client.get('/api/v1/auth/callback',params={'state':query['state'],'code':'synthetic-code'}).status_code==303


@pytest.mark.parametrize('suffix',['next=https://evil.example.invalid','mfa=true','invitation_id=bad','state=ignored'])
def test_http_login_rejects_unknown_redirect_or_malformed_fields(world,oauth_signing_key,suffix):
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    with client:
        before,_=world[1].query(prefix='oauth-flow#')
        response=client.get('/api/v1/auth/login?'+suffix)
        after,_=world[1].query(prefix='oauth-flow#')
        assert response.status_code==400 and 'location' not in response.headers and len(before)==len(after) and calls==[]


@pytest.mark.parametrize('suffix',['state=a&state=b&code=c','state=a&code=c&next=bad','state=%XX&code=c',
    'state=a&code='+('x'*4096),'state=a&code=c&error=denied','state=a','state=a&code=%00'])
def test_http_callback_malformed_fields_never_echo_or_contact_provider(world,oauth_signing_key,suffix):
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    with client:
        result=client.get('/api/v1/auth/callback?'+suffix)
        assert result.status_code==400 and calls==[]
        assert suffix not in result.text and 'location' not in result.headers
        assert result.headers['cache-control']=='no-store'


def test_http_provider_error_keeps_existing_session_and_consumes_flow(world,oauth_signing_key):
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    with client:
        start_http(client,query)
        client.cookies.set(COOKIE,world[4].cookie,domain='proofpack.example.invalid',path='/')
        browser=client.cookies.get(FLOW_COOKIE)
        result=client.get('/api/v1/auth/callback',params={'state':query['state'],'error':'access_denied','error_description':'sensitive provider message'})
        assert result.status_code==403 and 'sensitive' not in result.text and calls==[]
        assert client.cookies.get(COOKIE)==world[4].cookie and client.cookies.get(FLOW_COOKIE) is None
        client.cookies.set(FLOW_COOKIE,browser,domain='proofpack.example.invalid',path='/')
        assert client.get('/api/v1/auth/callback',params={'state':query['state'],'code':'synthetic-code'}).status_code==403
        assert calls==[]


def test_http_logout_cancels_pending_browser_signin(world,oauth_signing_key):
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    with client:
        start_http(client,query)
        client.cookies.set(COOKIE,world[4].cookie,domain='proofpack.example.invalid',path='/')
        response=client.post('/api/v1/auth/logout',headers={'Origin':'https://proofpack.example.invalid',
            'X-CSRF-Token':world[4].csrf,'Idempotency-Key':'cancel-pending-login'})
        assert response.status_code==204
        assert client.cookies.get(COOKIE) is None and client.cookies.get(FLOW_COOKIE) is None
        assert client.get('/api/v1/auth/callback',params={'state':query['state'],'code':'synthetic-code'}).status_code==403
        assert calls==[] and client.get('/api/v1/me').status_code==401


def test_http_signed_invitee_can_read_only_bound_onboarding_scope(world,oauth_signing_key):
    service,repo,clock,uid,credentials,owner=world
    invitation=service.create_invitation(owner,target_subject='invitee',target_email='invitee@example.invalid',
        roles=(Role.OPERATOR,),ttl_seconds=60,idempotency_key='http-signed-invitation')
    client,signin,query,calls=http_oauth(world,oauth_signing_key,subject='invitee')
    with client:
        start_http(client,query,'/api/v1/auth/login?invitation_id='+invitation['id'])
        result=client.get('/api/v1/auth/callback',params={'state':query['state'],'code':'synthetic-code'})
        assert result.status_code==303
        assert client.get('/api/v1/me').status_code==403 and client.get('/api/v1/users').status_code==403
        assert client.get('/api/v1/auth/notice').status_code==200
        assert client.get('/api/v1/invitations/'+invitation['id']).status_code==200


def test_http_provider_dependency_failure_clears_flow_without_new_session(world,oauth_signing_key):
    import httpx
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    def unavailable(request):raise httpx.ConnectTimeout('synthetic-sensitive-provider-detail')
    signin.provider.transport=httpx.MockTransport(unavailable)
    with client:
        start_http(client,query)
        result=client.get('/api/v1/auth/callback',params={'state':query['state'],'code':'synthetic-code'})
        assert result.status_code==503 and 'sensitive' not in result.text
        assert client.cookies.get(FLOW_COOKIE) is None and client.cookies.get(COOKIE) is None


@pytest.mark.parametrize('claims_changes',[{'amr':[]},{'auth_time':399}])
def test_http_mfa_request_requires_signed_recent_totp_before_session(world,oauth_signing_key,claims_changes):
    client,signin,query,calls=http_oauth(world,oauth_signing_key,claims_changes=claims_changes)
    with client:
        start_http(client,query,'/api/v1/auth/login?mfa=required')
        assert query['acr_values']=='urn:cognito:loa:4' and query['max_age']=='600'
        before,_=world[1].query(prefix='session#')
        result=client.get('/api/v1/auth/callback',params={'state':query['state'],'code':'synthetic-code'})
        after,_=world[1].query(prefix='session#')
        assert result.status_code==403 and client.cookies.get(COOKIE) is None and len(before)==len(after)


def test_http_mfa_request_with_signed_recent_totp_can_sign_in(world,oauth_signing_key):
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    with client:
        start_http(client,query,'/api/v1/auth/login?mfa=required')
        assert client.get('/api/v1/auth/callback',params={'state':query['state'],'code':'synthetic-code'}).status_code==303
        assert client.get('/api/v1/users').status_code==200


def test_http_signin_requires_exact_https_origin_and_dependency_binding(world,oauth_signing_key):
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    with client:
        assert client.get('/api/v1/auth/login',headers={'Host':'evil.example.invalid'}).status_code==403
        assert client.get('http://proofpack.example.invalid/api/v1/auth/login').status_code==403
    with pytest.raises(ValueError):create_app(access_service=world[0],app_origin='https://other.example.invalid',signin_service=signin)
    with TestClient(create_app(),base_url='https://proofpack.example.invalid') as unconfigured:
        assert unconfigured.get('/api/v1/auth/login').status_code==503
        result=unconfigured.get('/api/v1/auth/callback?code=synthetic-code&state='+'n'*43)
        assert result.status_code==503 and 'synthetic-code' not in result.text


def test_oauth_login_quota_persists_across_services_and_denial_creates_no_flow(repository_factory):
    repo=repository_factory();clock=Clock();flows=oauth(repo,clock,login_starts_per_minute=1)
    flows.begin()
    with pytest.raises(AuthRateLimited):oauth(repo,clock,login_starts_per_minute=1).begin()
    rows,_=repo.query(prefix='oauth-flow#');assert len(rows)==1
    clock.value=(clock.value//60000+1)*60000
    oauth(repo,clock,login_starts_per_minute=1).begin()
    rows,_=repo.query(prefix='oauth-flow#');assert len(rows)==2


def test_oauth_callback_quota_and_clock_rollback_fail_closed(repository_factory):
    repo=repository_factory();clock=Clock();flows=oauth(repo,clock,callback_attempts_per_minute=1)
    flows.admit_callback()
    with pytest.raises(AuthRateLimited):oauth(repo,clock,callback_attempts_per_minute=1).admit_callback()
    clock.value-=60000
    from proofpack.evidence.repository import StoreUnavailable
    with pytest.raises(StoreUnavailable):flows.admit_callback()


def test_http_durable_quota_denial_returns_429_without_provider_call(world,oauth_signing_key):
    client,signin,query,calls=http_oauth(world,oauth_signing_key)
    # The helper already created one flow. A stricter local fixture reuses its
    # durable counter; changing service objects cannot reset admission.
    flows=OAuthFlows(world[1],replace(signin.flows.config,login_starts_per_minute=1),clock_ms=world[2])
    provider=CognitoProvider(flows.config,signin.provider.tokens,transport=signin.provider.transport)
    limited=SignInService(flows,provider,world[0])
    app=create_app(access_service=world[0],app_origin='https://proofpack.example.invalid',signin_service=limited)
    with TestClient(app,base_url='https://proofpack.example.invalid') as browser:
        response=browser.get('/api/v1/auth/login')
        assert response.status_code==429 and 1<=int(response.headers['retry-after'])<=60
        assert 'location' not in response.headers and calls==[]


def test_concurrent_oauth_login_quota_has_one_winner_and_no_orphan_flow(repository_factory):
    repo=repository_factory();clock=Clock();flows=oauth(repo,clock,login_starts_per_minute=1)
    barrier=Barrier(2);original=repo.snapshot
    def snapshot(*args,**kwargs):
        rows=original(*args,**kwargs);barrier.wait(timeout=5);return rows
    repo.snapshot=snapshot
    def begin():
        try:return flows.begin()
        except AuthRateLimited:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:begin(),range(2)))
    repo.snapshot=original
    assert sum(value is not None for value in results)==1
    rows,_=repo.query(prefix='oauth-flow#');assert len(rows)==1


def test_oauth_pkce_nonce_restart_and_one_time_claim(repository_factory):
    import base64,hashlib
    repo=repository_factory();clock=Clock();flows=oauth(repo,clock)
    invitation=str(uuid4());start=flows.begin(invitation_id=invitation);query=oauth_query(start)
    assert query['response_type']=='code' and query['code_challenge_method']=='S256'
    assert query['scope']=='openid email profile' and query['prompt']=='login'
    assert query['redirect_uri']==flows.config.redirect_uri
    # A separate service object reads the same durable flow after a process restart.
    material=oauth(repo,clock).consume(state=query['state'],browser_cookie=start.browser_cookie)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(material.code_verifier.encode()).digest()).decode().rstrip('=')
    assert challenge==query['code_challenge'] and material.expected_nonce==query['nonce']
    assert material.invitation_id==invitation and material.expires_at_ms==start.expires_at_ms
    assert start.browser_cookie not in repr(start) and start.authorization_url not in repr(start)
    assert material.code_verifier not in repr(material) and material.expected_nonce not in repr(material)
    rows,_=repo.query(prefix='oauth-flow#');stored=json.dumps(rows[0].data,default=str)
    for secret in (query['state'],start.browser_cookie,material.code_verifier,material.expected_nonce):assert secret not in stored
    with pytest.raises(Denied):oauth(repo,clock).consume(state=query['state'],browser_cookie=start.browser_cookie)


def test_oauth_wrong_browser_does_not_burn_flow_or_cross_bind_invitation(repository_factory):
    repo=repository_factory();clock=Clock();flows=oauth(repo,clock)
    first=flows.begin(invitation_id=str(uuid4()));second=flows.begin();query=oauth_query(first)
    for state,cookie in ((query['state'],second.browser_cookie),('x'*43,first.browser_cookie),('',first.browser_cookie),(query['state'],None)):
        with pytest.raises(Denied):flows.consume(state=state,browser_cookie=cookie)
    assert flows.consume(state=query['state'],browser_cookie=first.browser_cookie).invitation_id is not None
    assert flows.consume(state=oauth_query(second)['state'],browser_cookie=second.browser_cookie).invitation_id is None


@pytest.mark.parametrize('change',[{'client_id':'differentClient'},
    {'provider_origin':'https://different.example.invalid'},
    {'redirect_uri':'https://different.example.invalid/api/v1/auth/callback'},
    {'private_key':b'different-local-fixture-private-key'}, {'flow_ttl_seconds':299}])
def test_oauth_configuration_or_key_change_denies_pending_flow(repository_factory,change):
    repo=repository_factory();clock=Clock();flows=oauth(repo,clock);start=flows.begin();query=oauth_query(start)
    with pytest.raises(Denied):oauth(repo,clock,**change).consume(state=query['state'],browser_cookie=start.browser_cookie)
    # A mismatched consumer cannot destroy the original valid flow.
    flows.consume(state=query['state'],browser_cookie=start.browser_cookie)


@pytest.mark.parametrize('offset',[-1,300000])
def test_oauth_exact_expiry_and_clock_rollback_deny(repository_factory,offset):
    repo=repository_factory();clock=Clock();flows=oauth(repo,clock);start=flows.begin();query=oauth_query(start)
    clock.value+=offset
    with pytest.raises(Denied):flows.consume(state=query['state'],browser_cookie=start.browser_cookie)


def test_oauth_expiry_during_transaction_consumes_without_returning_exchange_material(repository_factory):
    repo=repository_factory();clock=Clock();flows=oauth(repo,clock);start=flows.begin();query=oauth_query(start)
    original=repo.transact
    def slow_transaction(*args,**kwargs):
        original(*args,**kwargs);clock.value=start.expires_at_ms
    repo.transact=slow_transaction
    with pytest.raises(Denied):flows.consume(state=query['state'],browser_cookie=start.browser_cookie)
    rows,_=repo.query(prefix='oauth-flow#');assert rows[0].data['status']=='consumed'


def test_oauth_concurrent_callbacks_only_one_gets_exchange_material(repository_factory):
    repo=repository_factory();clock=Clock();flows=oauth(repo,clock);start=flows.begin();query=oauth_query(start)
    barrier=Barrier(2);original=repo.snapshot
    def snapshot(*args,**kwargs):
        result=original(*args,**kwargs);barrier.wait(timeout=5);return result
    repo.snapshot=snapshot
    def callback():
        try:return flows.consume(state=query['state'],browser_cookie=start.browser_cookie)
        except Denied:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:callback(),range(2)))
    assert sum(result is not None for result in results)==1


@pytest.fixture(scope='module')
def repository_factory():
    # Fixed loopback endpoint and explicit dummy keys prevent account/metadata access.
    endpoint=os.environ.get('PROOFPACK_TEST_DYNAMO_URL','http://127.0.0.1:8001')
    parsed=urlsplit(endpoint)
    if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise RuntimeError('test database must be an explicit loopback emulator')
    client=boto3.client('dynamodb',region_name='us-east-1',endpoint_url=endpoint,
        aws_access_key_id='localtest',aws_secret_access_key='localtest',
        config=Config(connect_timeout=1,read_timeout=5,retries={'max_attempts':0}))
    suffix=uuid4().hex[:12];state='proofpack-test-state-'+suffix;events='proofpack-test-events-'+suffix
    created=[]
    try:
        for name in (state,events):
            client.create_table(TableName=name,KeySchema=[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],
                AttributeDefinitions=[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'}],BillingMode='PAY_PER_REQUEST')
            created.append(name)
        yield lambda:DynamoRepository(client,deployment=str(uuid4()),state_table=state,events_table=events)
    finally:
        for name in created:client.delete_table(TableName=name)


class Clock:
    def __init__(self):self.value=1000000
    def __call__(self):return self.value


def proof(clock,subject='owner',*,mfa=True,email=None):
    return IdentityProof(ISSUER,subject,email or subject+'@example.invalid',True,mfa,clock(),clock()+3600000,subject+' synthetic')


@pytest.fixture
def world(repository_factory):
    repo=repository_factory();clock=Clock()
    config=AuthConfig(repo.deployment,ISSUER,b'synthetic-test-key-not-a-real-secret'*2,
        initial_owner_subject='owner',bootstrap_receipt_sha256='a'*64,
        notice_version='synthetic-v1',notice_text='Synthetic operational notice, not participant consent.')
    service=AccessService(repo,config,clock_ms=clock)
    uid=service.bootstrap(BootstrapApproval(ISSUER,'owner','a'*64),proof(clock))
    credentials=service.login(proof(clock));actor=service.resolve(credentials.cookie)
    return service,repo,clock,uid,credentials,actor


def invite_and_join(world,subject='operator',*,roles=(Role.OPERATOR,),mfa=False):
    service,repo,clock,uid,credentials,owner=world
    invitation=service.create_invitation(owner,target_subject=subject,target_email=subject+'@example.invalid',
        roles=roles,ttl_seconds=60,idempotency_key='invite-'+subject)
    identity=proof(clock,subject,mfa=mfa)
    restricted=service.login(identity,invitation_id=invitation['id'])
    invitee=service.resolve(restricted.cookie,allow_invitee=True)
    accepted=service.accept_invitation(invitee,invitation_id=invitation['id'],capability=invitation['capability'],idempotency_key='accept-'+subject,
        notice_version=service.config.notice_version,notice_sha256=digest(service.config.notice_text))
    full=service.login(identity)
    return accepted['user_id'],full,service.resolve(full.cookie),restricted,invitation


def test_only_pinned_mfa_bootstrap_principal_gets_initial_owner(world):
    service,repo,clock,uid,credentials,owner=world
    assert service.bootstrap(BootstrapApproval(ISSUER,'owner','a'*64),proof(clock))==uid
    with pytest.raises(Denied):service.bootstrap(BootstrapApproval(ISSUER,'outsider','b'*64),proof(clock,'outsider'))
    with pytest.raises(Denied):service.login(proof(clock,'outsider'))
    with pytest.raises(Denied):require(owner.principal,Role.OPERATOR,deployment=repo.deployment,now=clock()/1000)
    no_mfa=service.login(proof(clock,mfa=False))
    with pytest.raises(Denied):service.list_users(service.resolve(no_mfa.cookie))


def test_invitee_cannot_use_app_until_acceptance_and_fresh_login(world):
    service,repo,clock,uid,credentials,owner=world
    member,full,operator,restricted,invitation=invite_and_join(world)
    assert full.cookie!=restricted.cookie and full.session_id!=restricted.session_id
    with pytest.raises(Denied):service.resolve(restricted.cookie,allow_invitee=True)
    assert service.me(operator)['id']==member
    assert service.me(operator)['roles']==['operator']
    with pytest.raises(Denied):service.list_users(operator)
    assert {u['id'] for u in service.list_users(owner)['users']}=={uid,member}


@pytest.mark.parametrize('mutation', ['subject','issuer','email','unverified','expired'])
def test_invitation_identity_binding_and_freshness(world,mutation):
    service,repo,clock,uid,credentials,owner=world
    invitation=service.create_invitation(owner,target_subject='operator',target_email='operator@example.invalid',
        roles=[Role.OPERATOR],ttl_seconds=60,idempotency_key='invite')
    identity=proof(clock,'operator',mfa=False)
    if mutation=='subject':identity=replace(identity,subject='other')
    elif mutation=='issuer':identity=replace(identity,issuer='https://other.example.invalid')
    elif mutation=='email':identity=replace(identity,email='other@example.invalid')
    elif mutation=='unverified':identity=replace(identity,email_verified=False)
    else:identity=replace(identity,expires_at_ms=clock())
    with pytest.raises(Denied):service.login(identity,invitation_id=invitation['id'])


def test_capacity_idempotency_expiry_and_release_once(world):
    service,repo,clock,uid,credentials,owner=world
    invitations=[]
    for n in range(4):
        invitations.append(service.create_invitation(owner,target_subject=f'p{n}',target_email=f'p{n}@example.invalid',
            roles=[Role.OPERATOR],ttl_seconds=10,idempotency_key=f'invite-{n}'))
    repeated=service.create_invitation(owner,target_subject='p0',target_email='p0@example.invalid',
            roles=[Role.OPERATOR],ttl_seconds=10,idempotency_key='invite-0')
    assert repeated==invitations[0]
    with pytest.raises(StoreConflict):service.create_invitation(owner,target_subject='p5',target_email='p5@example.invalid',roles=[],ttl_seconds=10,idempotency_key='extra')
    with pytest.raises(StoreConflict):service.create_invitation(owner,target_subject='different',target_email='different@example.invalid',roles=[],ttl_seconds=10,idempotency_key='invite-0')
    first=invitations[0]
    result=service.revoke_invitation(owner,invitation_id=first['id'],expected_revision=1,idempotency_key='revoke')
    assert service.revoke_invitation(owner,invitation_id=first['id'],expected_revision=1,idempotency_key='revoke')==result
    assert len(repo.snapshot((HEAD,))[HEAD].data['pending_invitation_ids'])==3
    clock.value+=11000
    service.create_invitation(owner,target_subject='new',target_email='new@example.invalid',roles=[],ttl_seconds=10,idempotency_key='new')
    head=repo.snapshot((HEAD,))[HEAD]
    assert len(head.data['pending_invitation_ids'])==1
    with pytest.raises(Denied):service.login(proof(clock,'p1'),invitation_id=invitations[1]['id'])


def test_wrong_capability_does_not_consume_invitation(world):
    service,repo,clock,uid,credentials,owner=world
    invitation=service.create_invitation(owner,target_subject='p',target_email='p@example.invalid',roles=[],ttl_seconds=10,idempotency_key='invite')
    restricted=service.login(proof(clock,'p'),invitation_id=invitation['id'])
    invitee=service.resolve(restricted.cookie,allow_invitee=True)
    with pytest.raises(Denied):service.accept_invitation(invitee,invitation_id=invitation['id'],capability='wrong',idempotency_key='wrong',
        notice_version=service.config.notice_version,notice_sha256=digest(service.config.notice_text))
    assert repo.snapshot((invitation_key(invitation['id']),))[invitation_key(invitation['id'])].data['status']=='pending'
    accepted=service.accept_invitation(invitee,invitation_id=invitation['id'],capability=invitation['capability'],idempotency_key='correct',
        notice_version=service.config.notice_version,notice_sha256=digest(service.config.notice_text))
    full=service.login(proof(clock,'p'))
    assert service.accept_invitation(service.resolve(full.cookie),invitation_id=invitation['id'],capability=invitation['capability'],idempotency_key='correct',
        notice_version=service.config.notice_version,notice_sha256=digest(service.config.notice_text))==accepted


def test_revoke_disable_and_reenable_never_revive_old_sessions(world):
    service,repo,clock,uid,credentials,owner=world
    member,full,operator,_,_=invite_and_join(world)
    service.revoke_sessions(owner,user_id=member,expected_version=1,idempotency_key='revoke')
    with pytest.raises(Denied):service.resolve(full.cookie)
    fresh=service.login(proof(clock,'operator',mfa=False));assert service.resolve(fresh.cookie)
    service.change_access(owner,user_id=member,roles=[Role.OPERATOR],enabled=False,expected_version=2,idempotency_key='disable')
    assert next(u for u in service.list_users(owner)['users'] if u['id']==member)['enabled'] is False
    with pytest.raises(Denied):service.resolve(fresh.cookie)
    with pytest.raises(Denied):service.login(proof(clock,'operator'))
    service.change_access(owner,user_id=member,roles=[Role.REVIEWER],enabled=True,expected_version=3,idempotency_key='enable')
    with pytest.raises(Denied):service.resolve(fresh.cookie)
    final=service.resolve(service.login(proof(clock,'operator',mfa=False)).cookie)
    assert service.me(final)['roles']==['reviewer']


def test_expired_logout_is_allowed_but_still_needs_csrf(world):
    service,repo,clock,uid,credentials,owner=world
    clock.value=credentials.expires_at_ms
    with pytest.raises(Denied):service.resolve(credentials.cookie)
    with pytest.raises(Denied):service.logout(credentials.cookie,'wrong')
    service.logout(credentials.cookie,credentials.csrf)
    service.logout(credentials.cookie,credentials.csrf)
    assert repo.snapshot((owner.session.key,))[owner.session.key].data['active'] is False


def test_last_owner_and_mfa_target_rules(world):
    service,repo,clock,uid,credentials,owner=world
    with pytest.raises(Denied):service.change_access(owner,user_id=uid,roles=[],enabled=True,expected_version=1,idempotency_key='remove-last')
    member,full,operator,_,_=invite_and_join(world)
    with pytest.raises(Denied):service.change_access(owner,user_id=member,roles=[Role.OWNER],enabled=True,expected_version=1,idempotency_key='no-mfa')
    transfer=service.begin_transfer(owner,target_id=member,expected_target_version=1,idempotency_key='transfer')
    with pytest.raises(Denied):service.accept_transfer(operator,transfer_id=transfer['id'],idempotency_key='accept')
    mfa=service.resolve(service.login(proof(clock,'operator',mfa=True)).cookie)
    result=service.accept_transfer(mfa,transfer_id=transfer['id'],idempotency_key='accept')
    assert result['owner_id']==member
    with pytest.raises(Denied):service.resolve(credentials.cookie)
    with pytest.raises(Denied):service.resolve(full.cookie)
    new_owner=service.resolve(service.login(proof(clock,'operator',mfa=True)).cookie)
    assert service.me(new_owner)['roles']==['operator','owner']


def test_sensitive_commit_rechecks_originating_session(world,monkeypatch):
    service,repo,clock,uid,credentials,owner=world
    original=repo.transact;revoked=False
    def race(writes,checks=()):
        nonlocal revoked
        if not revoked and any(w.key.table=='events' and w.data.get('kind')=='invite' for w in writes):
            revoked=True;service.logout(credentials.cookie,credentials.csrf)
        return original(writes,checks)
    monkeypatch.setattr(repo,'transact',race)
    with pytest.raises(StoreConflict):service.create_invitation(owner,target_subject='p',target_email='p@example.invalid',roles=[],ttl_seconds=10,idempotency_key='race')
    assert repo.snapshot((HEAD,))[HEAD].data['pending_invitation_ids']==[]


def test_cookie_capability_and_csrf_values_are_not_stored_as_plaintext(world):
    service,repo,clock,uid,credentials,owner=world
    invitation=service.create_invitation(owner,target_subject='p',target_email='p@example.invalid',roles=[],ttl_seconds=10,idempotency_key='secret-test')
    stored=json.dumps(repo.client.scan(TableName=repo.tables['state'])['Items'])
    assert credentials.cookie not in stored and credentials.csrf not in stored and invitation['capability'] not in stored
    assert service.config.capability_key.decode() not in stored


def test_concurrent_owners_cannot_remove_every_owner(world,monkeypatch):
    service,repo,clock,uid,credentials,owner=world
    other_id,_,other,_,_=invite_and_join(world,'other',roles=[Role.OWNER],mfa=True)
    original=repo.transact;barrier=Barrier(2)
    def synchronized(writes,checks=()):
        if any(w.key==HEAD for w in writes):barrier.wait(timeout=5)
        return original(writes,checks)
    monkeypatch.setattr(repo,'transact',synchronized)
    def disable(actor,target,key):
        try:
            service.change_access(actor,user_id=target,roles=[],enabled=False,expected_version=1,idempotency_key=key)
            return 'committed'
        except (StoreConflict,Denied):return 'denied'
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures=[executor.submit(disable,owner,other_id,'one'),executor.submit(disable,other,uid,'two')]
        outcomes=[f.result(timeout=10) for f in futures]
    assert outcomes.count('committed')==1
    assert len(repo.snapshot((HEAD,))[HEAD].data['owner_ids'])==1


def test_user_pagination_is_scoped_signed_and_contains_disabled_members(world):
    service,repo,clock,uid,credentials,owner=world
    member,_,_,_,_=invite_and_join(world)
    first=service.list_users(owner,limit=1)
    assert len(first['users'])==1 and first['next_cursor']
    second=service.list_users(owner,limit=1,cursor=first['next_cursor'])
    assert {first['users'][0]['id'],second['users'][0]['id']}=={uid,member}
    with pytest.raises(ValueError):service.list_users(owner,cursor=first['next_cursor'][:-1]+'!')
    tampered=first['next_cursor'][:-1]+('A' if first['next_cursor'][-1]!='A' else 'B')
    with pytest.raises(Denied):service.list_users(owner,cursor=tampered)
    with pytest.raises(ValueError):service.list_users(owner,limit=101)


def test_new_service_instance_reads_persisted_membership_and_sessions(world):
    service,repo,clock,uid,credentials,owner=world
    restarted=AccessService(repo,service.config,clock_ms=clock)
    assert restarted.me(restarted.resolve(credentials.cookie))['id']==uid


def test_http_requires_session_origin_csrf_idempotency_and_explicit_roles(world):
    service,repo,clock,uid,credentials,owner=world
    app=create_app(access_service=service,app_origin='https://proofpack.test')
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.get('/api/v1/me').status_code==401
        wrong_method=client.post('/api/v1/auth/login',json={'subject':'owner','mfa_verified':True})
        assert wrong_method.status_code==405 and wrong_method.json()['code']=='REQUEST_DENIED'
        assert 'GET' in wrong_method.headers['allow']
        assert client.get('/api/v1/me').status_code==401
        client.cookies.set(COOKIE,credentials.cookie)
        current=client.get('/api/v1/me')
        assert current.status_code==200 and current.json()['id']==uid
        assert current.json()['csrf_token']==credentials.csrf
        assert current.headers['cache-control']=='no-store'
        body={'target_subject':'p','target_email':'p@example.invalid','roles':['operator'],'ttl_seconds':60}
        headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-invite'}
        assert client.post('/api/v1/invitations',headers={**headers,'Origin':'https://evil.invalid'},json=body).status_code==403
        assert client.post('/api/v1/invitations',headers={**headers,'X-CSRF-Token':'wrong'},json=body).status_code==403
        assert client.post('/api/v1/invitations',headers={k:v for k,v in headers.items() if k!='Idempotency-Key'},json=body).status_code==400
        made=client.post('/api/v1/invitations',headers=headers,json=body)
        assert made.status_code==201
        assert client.post('/api/v1/invitations',headers=headers,json=body).json()==made.json()
        assert client.post('/api/v1/invitations',headers=headers,json={**body,'roles':['reviewer']}).status_code==409
        assert client.get('/health/ready').status_code==503


def test_http_role_denial_validation_privacy_and_streamed_body_bound(world):
    service,repo,clock,uid,credentials,owner=world
    _,full,_,_,_=invite_and_join(world)
    with TestClient(create_app(access_service=service,app_origin='https://proofpack.test'),base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,full.cookie)
        assert client.get('/api/v1/users').status_code==403
        client.cookies.set(COOKIE,credentials.cookie)
        headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'bad-body'}
        sensitive='private-value-not-to-echo'
        invalid=client.post('/api/v1/invitations',headers=headers,json={'capability':sensitive,'passed':True})
        assert invalid.status_code==400 and sensitive not in invalid.text
        oversized=client.post('/api/v1/invitations',headers={**headers,'Content-Type':'application/json'},content=iter([b'{"x":"',b'A'*9000,b'"}']))
        assert oversized.status_code==413 and oversized.json()['code']=='BODY_LIMIT'
        assert oversized.headers['cache-control']=='no-store'


def test_http_logout_clears_host_cookie_after_expiry_without_regrant(world):
    service,repo,clock,uid,credentials,owner=world
    clock.value=credentials.expires_at_ms
    with TestClient(create_app(access_service=service,app_origin='https://proofpack.test'),base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        response=client.post('/api/v1/auth/logout',headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'logout'})
        assert response.status_code==204
        cookie=response.headers['set-cookie']
        assert 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=lax' in cookie and 'Max-Age=0' in cookie
        assert client.get('/api/v1/me').status_code==401


def test_http_invitee_notice_and_metadata_scope_and_acceptance(world):
    service,repo,clock,uid,credentials,owner=world
    first=service.create_invitation(owner,target_subject='p',target_email='p@example.invalid',roles=['operator'],ttl_seconds=60,idempotency_key='one')
    second=service.create_invitation(owner,target_subject='q',target_email='q@example.invalid',roles=[],ttl_seconds=60,idempotency_key='two')
    restricted=service.login(proof(clock,'p',mfa=False),invitation_id=first['id'])
    with TestClient(create_app(access_service=service,app_origin='https://proofpack.test'),base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,restricted.cookie)
        notice=client.get('/api/v1/auth/notice')
        assert notice.status_code==200
        metadata=client.get('/api/v1/invitations/'+first['id'])
        assert metadata.status_code==200 and metadata.json()['state_version']==1
        assert 'capability' not in metadata.json() and 'target_email_hash' not in metadata.json()
        # Object-scope denial is 404 per the API contract; it must not reveal existence.
        assert client.get('/api/v1/invitations/'+second['id']).status_code==404
        assert client.get('/api/v1/invitations').status_code==403
        headers={'Origin':'https://proofpack.test','X-CSRF-Token':restricted.csrf,'Idempotency-Key':'accept'}
        body={'capability':first['capability'],'notice_version':notice.json()['version'],'notice_sha256':notice.json()['sha256']}
        assert client.post('/api/v1/invitations/'+first['id']+'/accept',headers=headers,json={**body,'notice_sha256':'f'*64}).status_code==403
        accepted=client.post('/api/v1/invitations/'+first['id']+'/accept',headers=headers,json=body)
        assert accepted.status_code==200 and accepted.json()['sign_in_required']
        assert 'Max-Age=0' in accepted.headers['set-cookie']
        member=repo.snapshot((user_key(accepted.json()['user_id']),))[user_key(accepted.json()['user_id'])]
        assert member.data['notice_sha256']==notice.json()['sha256'] and not member.data['improvement_reuse']


def test_owner_invitation_metadata_list_never_returns_capabilities(world):
    service,repo,clock,uid,credentials,owner=world
    for name in ('p','q'):
        service.create_invitation(owner,target_subject=name,target_email=name+'@example.invalid',roles=[],ttl_seconds=60,idempotency_key=name)
    first=service.list_invitations(owner,limit=1)
    assert first['next_cursor'] and len(first['invitations'])==1
    second=service.list_invitations(owner,limit=1,cursor=first['next_cursor'])
    assert first['invitations'][0]['id']!=second['invitations'][0]['id']
    assert all('capability' not in row and 'capability_hash' not in row for row in first['invitations']+second['invitations'])
    with pytest.raises(Denied):service.list_users(owner,cursor=first['next_cursor'])


def test_http_decline_releases_slot_without_notice_or_membership(world):
    service,repo,clock,uid,credentials,owner=world
    invitation=service.create_invitation(owner,target_subject='p',target_email='p@example.invalid',roles=['owner'],ttl_seconds=60,idempotency_key='one')
    restricted=service.login(proof(clock,'p',mfa=False),invitation_id=invitation['id'])
    no_notice=AccessService(repo,replace(service.config,notice_version=None,notice_text=None),clock_ms=clock)
    with TestClient(create_app(access_service=no_notice,app_origin='https://proofpack.test'),base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,restricted.cookie)
        response=client.post('/api/v1/invitations/'+invitation['id']+'/decline',headers={
            'Origin':'https://proofpack.test','X-CSRF-Token':restricted.csrf,'Idempotency-Key':'decline'})
        assert response.status_code==200 and response.json()['status']=='declined'
        assert 'Max-Age=0' in response.headers['set-cookie']
    head=repo.snapshot((HEAD,))[HEAD].data
    assert head['pending_invitation_ids']==[] and head['enabled_user_ids']==[uid]
    assert service.read_invitation(owner,invitation_id=invitation['id'])['status']=='declined'
    with pytest.raises(Denied):service.resolve(restricted.cookie,allow_invitee=True)
    with pytest.raises(Denied):service.login(proof(clock,'p'),invitation_id=invitation['id'])


def test_concurrent_identical_invites_return_the_same_committed_capability(world,monkeypatch):
    service,repo,clock,uid,credentials,owner=world
    original=repo.transact;barrier=Barrier(2)
    def synchronized(writes,checks=()):
        if any(w.key==HEAD for w in writes):barrier.wait(timeout=5)
        return original(writes,checks)
    monkeypatch.setattr(repo,'transact',synchronized)
    def invite():return service.create_invitation(owner,target_subject='p',target_email='p@example.invalid',roles=[],ttl_seconds=60,idempotency_key='same')
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures=[executor.submit(invite),executor.submit(invite)]
        results=[f.result(timeout=10) for f in futures]
    assert results[0]==results[1]
    assert repo.snapshot((HEAD,))[HEAD].data['pending_invitation_ids']==[results[0]['id']]


def test_station_enrollment_commit_requires_its_calibration_report_to_still_exist(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    repo=world[1];calkey=Key('state','calibration-active#'+content['calibration_profile_id'])
    active=repo.snapshot((calkey,))[calkey];dkey=Key('state','calibration-dependencies#'+active.data['dependency_receipt_id'])
    dependency=repo.snapshot((dkey,))[dkey];rkey=Key('state','calibration-report#'+dependency.data['report_id'])
    before=repo.query(prefix='station#',limit=20)[0];original=repo.transact;injected=False
    def transact(writes,checks=()):
        nonlocal injected
        if any(write.key.resource.startswith('station#') for write in writes):
            assert any(row.key==rkey for row in checks)
            repo.client.delete_item(TableName=repo.tables[rkey.table],Key=repo.key(rkey));injected=True
        return original(writes,checks)
    repo.transact=transact
    with pytest.raises(StoreConflict):
        stations.enroll(world[5],name='Lost-report station',calibration_profile_id=content['calibration_profile_id'],idempotency_key='missing-report-at-commit')
    assert injected and repo.query(prefix='station#',limit=20)[0]==before
