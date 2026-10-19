"""Real local CV/capture/evidence, synthetic rights/clocks, intercepted S3."""
import hashlib
import json
import cv2
import pytest
from fastapi.testclient import TestClient
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from test_access_lifecycle import world, repository_factory, publication_case, capture_permit, admit_frame, invite_and_join
from proofpack.auth.policy import Role, Denied
from proofpack.auth.service import digest
from proofpack.recipes.models import Constraint, Interval, PartClass
from proofpack.vision.fixtures import blank_mat, demo_recipe
from proofpack.evidence.repository import Write, StoreUnavailable
from proofpack.evidence.purposes import DataPurposes
from proofpack.evidence.objects import ReferenceObjects
from proofpack.evidence.reads import AssetReads
from proofpack.capture.publication import asset_key, action_key
from proofpack.capture.service import observation_key
from proofpack.stations.service import inspection_key
from proofpack.evidence.exports import InspectionExports, manifest_key
from proofpack.evidence.export_models import ExportRequest


@pytest.fixture(params=['overlap','flat_reference'])
def mode(request): return request.param


@pytest.fixture
def recipe(mode):
    selected = Constraint(constraint_id='measured-part',part_class_id=PartClass.WASHER if mode=='overlap' else PartClass.BOLT,
        expected_count=2 if mode=='overlap' else 1,required_visibility='Authored planar synthetic silhouette only',
        flat_reference_aspect_ratio=None if mode=='overlap' else Interval(minimum=4.5,maximum=7.5))
    return demo_recipe(0).model_copy(update={'constraints':(selected,)})


def frame(mode,corrected):
    image=blank_mat()
    if mode=='overlap':
        for center in ((220,220),(320 if corrected else 260,220)):
            cv2.circle(image,center,24,(0,0,0),-1);cv2.circle(image,center,8,(255,255,255),-1)
    else:cv2.rectangle(image,(220,210),(340 if corrected else 290,230),(0,0,0),-1)
    ok,encoded=cv2.imencode('.png',image);assert ok
    return encoded.tobytes()


def observe(world,case,payload):
    service,capture,started,operator,_,clock,*_=case
    clock.value+=500000000;world[2].value+=500
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    permit=capture_permit(capture,started,operator,version=work.revision,key='measured-cue-'+str(work.revision))
    admission=admit_frame(capture,started,operator,permit,payload=payload)
    return service.process(operator,observation_id=admission['id'],payload=payload),admission


def reads_for_history(world,case):
    _,capture,_,_,_,_,_,objects,purpose,_=case
    purposes=DataPurposes(world[0],capture.stations.runtime,max_lifetime_ms=120000)
    row=world[1].snapshot((purpose,))[purpose];head=purposes.head()
    # Complete the abbreviated synthetic publication-rights fixture. This is not
    # participant consent. Advancing DATA must invalidate any prior live result.
    world[1].transact((Write(purpose,row.revision,{**row.data,'authority_basis':'owner_attestation','rights_independently_verified':False,
        'optional_improvement':False,'optional_publicity':False,'notice_version':world[0].config.notice_version,
        'notice_sha256':digest(world[0].config.notice_text)}),purposes.advance(head)))
    return AssetReads(purposes,objects,ReferenceObjects(objects.client,objects.config),reads_per_minute=32,max_concurrent=1,read_window_ms=5000)


def test_measured_action_ack_fresh_correction_and_exact_private_crop_reference(world,publication_case,mode):
    service,_,started,operator,_,_,_,objects,_,_=publication_case
    status,admission=observe(world,publication_case,frame(mode,False))
    kind='SEPARATE_REGION' if mode=='overlap' else 'PLACE_FLAT'
    assert status['effective_state']=='ACTION_REQUIRED' and status['action']['kind']==kind and status['action']['correction_reference_available']
    assert status['remaining_lease_ms']==0
    row=world[1].snapshot((observation_key(admission['id']),))[observation_key(admission['id'])]
    asset=world[1].snapshot((asset_key(row.data['asset_id']),))[asset_key(row.data['asset_id'])]
    action=world[1].snapshot((action_key(status['action']['id']),))[action_key(status['action']['id'])]
    assert row.data['correction_basis_sha256']==asset.data['correction_basis_sha256']==action.data['correction_basis_sha256']
    assert action.data['target_candidate_indices']==[0]
    ack=service.acknowledge(operator,inspection_id=started['inspection_id'],action_id=status['action']['id'],expected_version=status['state_version'],idempotency_key='ack-measured-cue')
    assert ack['effective_state']=='OBSERVING' and ack['remaining_lease_ms']==0
    for expected in ('OBSERVING','OBSERVING','PASSED_CURRENT'):
        fresh,_=observe(world,publication_case,frame(mode,True))
        assert fresh['effective_state']==expected
    work=world[1].snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data['corrections']==1
    reads=reads_for_history(world,publication_case)
    assert service.status(operator,started['inspection_id'])['effective_state']=='INVALIDATED'
    metadata=reads.read(operator,asset.data['id']);geometry=metadata['correction_reference']
    assert metadata['historical'] and not metadata['machine_pass'] and geometry['observation_id']==admission['id']
    assert geometry['width']==600 and geometry['height']==300 and len(geometry['regions'])==1
    payload,receipt,*_=reads.read(operator,asset.data['id'],binary=True)
    decoded=cv2.imdecode(__import__('numpy').frombuffer(payload,__import__('numpy').uint8),cv2.IMREAD_COLOR)
    assert decoded.shape[:2]==(300,600) and hashlib.sha256(payload).hexdigest()==geometry['crop_sha256']==receipt.source_sha256
    region=geometry['regions'][0];x,y,w,h=region['box']
    assert (decoded[y:y+h,x:x+w]<64).any()
    owner=reads.read(world[5],asset.data['id'])
    assert not owner['can_download'] and 'correction_reference' not in owner
    with pytest.raises(Denied):reads.read(world[5],asset.data['id'],binary=True)
    _,_,reviewer,*_=invite_and_join(world,'measured-image-reviewer',roles=(Role.REVIEWER,))
    assert reads.read(reviewer,asset.data['id'])['correction_reference']==geometry


def test_changed_measured_result_cannot_reuse_an_image_binding(world,publication_case,mode):
    _,admission=observe(world,publication_case,frame(mode,False))
    reads=reads_for_history(world,publication_case)
    row=world[1].snapshot((observation_key(admission['id']),))[observation_key(admission['id'])]
    import json
    result=json.loads(row.data['result_json']);result['candidates'][0]['box'][0]+=1
    world[1].transact((Write(row.key,row.revision,{**row.data,'result_json':json.dumps(result)}),))
    for binary in (False,True):
        with pytest.raises(StoreUnavailable):reads.read(publication_case[3],row.data['asset_id'],binary=binary)


def correction_export(world,case,mode,selected):
    status,admission=observe(world,case,frame(mode,False))
    reads=reads_for_history(world,case)
    source=world[1].snapshot((observation_key(admission['id']),))[observation_key(admission['id'])]
    exports=InspectionExports(reads,jobs_per_minute=20,job_lifetime_ms=60000,lease_ms=15000,page_size=25,max_scan_rows=500,max_records=128,
        max_assets=3,ticket_ms=30000,download_ms=20000,max_concurrent=2)
    work=world[1].snapshot((inspection_key(case[2]['inspection_id']),))[inspection_key(case[2]['inspection_id'])]
    job=exports.create(case[3],work.data['id'],request=ExportRequest(selected_asset_ids=(source.data['asset_id'],) if selected else (),historical_export_acknowledged=True),
        expected_version=work.revision,idempotency_key='measured-export')
    return exports,job,source,status


def finish_export(exports,job,actor):
    for attempt in range(20):
        if job['status']=='completed':return job
        assert job['status']=='queued',job
        job=exports.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='measured-export-step-'+str(attempt))
    raise AssertionError('finite export did not complete')


@pytest.mark.parametrize('selected',[False,True])
def test_measured_export_preserves_verified_basis_action_targets_and_no_coordinates(world,publication_case,mode,selected):
    exports,job,source,status=correction_export(world,publication_case,mode,selected)
    done=finish_export(exports,job,publication_case[3]);key=manifest_key(done['id'])
    value=json.loads(world[1].snapshot((key,))[key].data['json'])
    recorded=next(ob for ob in value['observations'] if ob['id']==source.data['id'])
    measured=recorded['measured_correction']
    assert measured['basis_sha256']==source.data['correction_basis_sha256']
    kind=status['action']['kind'];assert measured['targets'][kind]==[0]
    event=next(e for e in value['events'] if e['kind']=='observation_completed' and e['observation_id']==source.data['id'])
    assert event['correction_basis_sha256']==measured['basis_sha256']
    assert event['action_id']==status['action']['id'] and event['action_kind']==kind and event['target_candidate_indices']==[0]
    assert 'box' not in json.dumps(measured) and 'result_json' not in json.dumps(value)
    assert value['historical'] and not value['current_approval'] and not value['physical_truth_verified']


@pytest.mark.parametrize('change',['missing_event_basis','changed_event_basis','targets','kind'])
def test_measured_export_rejects_unbound_or_changed_action_summary(world,publication_case,mode,change):
    exports,job,source,_=correction_export(world,publication_case,mode,False)
    events,_=world[1].query(prefix='capture#',table='events')
    event=next(e for e in events if e.data.get('observation_id')==source.data['id'] and e.data.get('kind')=='observation_completed')
    assert event.data['correction_basis_sha256']==source.data['correction_basis_sha256']
    changed={**event.data}
    if change=='missing_event_basis':changed.pop('correction_basis_sha256',None)
    if change=='changed_event_basis':changed['correction_basis_sha256']='f'*64
    if change=='targets':changed['target_candidate_indices']=[29]
    if change=='kind':changed['action_kind']='SHIP'
    world[1].transact((Write(event.key,event.revision,changed),))
    with pytest.raises(StoreUnavailable):finish_export(exports,job,publication_case[3])


@pytest.mark.parametrize('change',['different_allowed_action','changed_action_row','missing_observation_basis'])
def test_measured_export_requires_the_actual_recorded_action_and_observation(world,publication_case,mode,change):
    exports,job,source,status=correction_export(world,publication_case,mode,False)
    if change=='missing_observation_basis':
        changed={**source.data};changed.pop('correction_basis_sha256')
        world[1].transact((Write(source.key,source.revision,changed),))
    elif change=='changed_action_row':
        key=action_key(status['action']['id']);action=world[1].snapshot((key,))[key]
        world[1].transact((Write(key,action.revision,{**action.data,'kind':'RECAPTURE','target_candidate_indices':[]}),))
    else:
        events,_=world[1].query(prefix='capture#',table='events')
        event=next(e for e in events if e.data.get('observation_id')==source.data['id'] and e.data.get('kind')=='observation_completed')
        world[1].transact((Write(event.key,event.revision,{**event.data,'action_kind':'RECAPTURE','target_candidate_indices':[]}),))
    with pytest.raises(StoreUnavailable):finish_export(exports,job,publication_case[3])


def test_actual_http_measured_upload_status_and_protected_historical_crop(world,publication_case,mode):
    service,capture,started,operator,credentials,clock,_,objects,_,_=publication_case
    purposes=DataPurposes(world[0],capture.stations.runtime,max_lifetime_ms=120000)
    reads=AssetReads(purposes,objects,ReferenceObjects(objects.client,objects.config),reads_per_minute=32,max_concurrent=1,read_window_ms=5000)
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=reads.runtime,
        recipe_service=capture.stations.recipes,station_service=capture.stations,capture_service=capture,
        observation_service=service,purpose_service=purposes,asset_service=reads)
    clock.value+=500000000;world[2].value+=500
    permit=capture_permit(capture,started,operator,version=1,key='http-measured-cue')
    with TestClient(app,base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        response=client.post('/api/v1/inspections/'+started['inspection_id']+'/observations',
            data={'permit_id':permit['permit_id'],'nonce':permit['nonce'],'sequence':str(permit['sequence'])},
            files={'image':('capture.png',frame(mode,False),'image/png')},
            headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-measured-upload',
                'If-Match':str(permit['inspection_state_version'])})
        assert response.status_code==200,response.text
        output=response.json();action=output['status']['action']
        assert output['status']['effective_state']=='ACTION_REQUIRED' and action['correction_reference_available']
        assert action['observation_id']==output['observation_id']
        assert action['kind']==('SEPARATE_REGION' if mode=='overlap' else 'PLACE_FLAT')
        assert 'box' not in json.dumps(action) and output['status']['remaining_lease_ms']==0
        current=client.get('/api/v1/inspections/'+started['inspection_id']);assert current.status_code==200,current.text
        assert current.json()['action']==action
        # Complete the same disclosed synthetic rights fixture and advance DATA.
        # This intentionally ends current reliance before the historical read.
        reads_for_history(world,publication_case)
        held=client.get('/api/v1/inspections/'+started['inspection_id']);assert held.status_code==200,held.text
        assert held.json()['effective_state']=='INVALIDATED' and held.json()['remaining_lease_ms']==0
        metadata=client.get('/api/v1/inspections/'+started['inspection_id']+'/evidence');assert metadata.status_code==200,metadata.text
        value=metadata.json();reference=value['correction_reference']
        assert value['observation_id']==reference['observation_id']==output['observation_id']
        assert reference['crop_sha256']==value['sha256'] and reference['regions'][0]['candidate_index']==0
        image=client.get('/api/v1/assets/'+value['id']+'/download');assert image.status_code==200,image.text
        assert image.headers['cache-control']=='no-store' and image.headers['x-evidence-historical']=='true'
        assert image.headers['x-content-sha256']==hashlib.sha256(image.content).hexdigest()==reference['crop_sha256']
        assert 'object_key' not in metadata.text and 'result_json' not in metadata.text
