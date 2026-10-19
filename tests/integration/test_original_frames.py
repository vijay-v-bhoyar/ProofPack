"""Synthetic image, local OpenCV/DynamoDB and intercepted S3; no physical/AWS proof."""
import hashlib
from uuid import uuid4

import cv2
import pytest

from test_access_lifecycle import world,repository_factory,publication_case,invite_and_join
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import digest
from proofpack.auth.service import ResourceUnavailable
from proofpack.evidence.objects import ReferenceObjects
from proofpack.evidence.originals import ORIGINAL_NOTICE_VERSION,ORIGINAL_NOTICE_TEXT,ORIGINAL_NOTICE_SHA256,original_asset_id
from proofpack.evidence.purposes import DataPurposes
from proofpack.evidence.reads import AssetReads
from proofpack.evidence.erasure import AssetErasure
from proofpack.evidence.erasure_models import ErasurePreview,ErasureConfirmation
from proofpack.evidence.repository import Key,Write,StoreUnavailable,StoreConflict
from proofpack.capture.service import observation_key
from proofpack.stations.service import inspection_key,StationRateLimited
from proofpack.vision.fixtures import make_fixture


@pytest.fixture
def original_case(world,publication_case):
    observations,capture,started,operator,credentials,clock,registry,objects,purpose,_=publication_case
    repo=world[1];row=repo.snapshot((purpose,))[purpose]
    # Complete synthetic attestation in the abbreviated publication fixture.
    # This is deliberately not customer permission or independent physical truth.
    repo.transact((Write(purpose,row.revision,{**row.data,'id':purpose.resource.split('#',1)[1],
        'authority_basis':'owner_attestation','rights_independently_verified':False,
        'optional_improvement':False,'optional_publicity':False,'notice_version':world[0].config.notice_version,
        'notice_sha256':digest(world[0].config.notice_text),'source_permission_reference':'synthetic-originals',
        'owner_user_id':world[5].member.data['id'],'owner_access_version':int(world[5].member.data['access_version']),
        'original_capture_retention_allowed':True,'original_capture_notice_version':ORIGINAL_NOTICE_VERSION,
        'original_capture_notice_sha256':ORIGINAL_NOTICE_SHA256,'original_capture_notice_text':ORIGINAL_NOTICE_TEXT}),))
    purposes=DataPurposes(world[0],capture.stations.runtime,max_lifetime_ms=120000)
    reads=AssetReads(purposes,objects,ReferenceObjects(objects.client,objects.config),reads_per_minute=60,max_concurrent=1,read_window_ms=5000)
    def observe(*,retain=True,condition='complete'):
        work=repo.snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
        permit=capture.issue(operator,inspection_id=started['inspection_id'],expected_version=work.revision,
            expected_epoch=1,idempotency_key='original-'+str(work.revision),retain_original_frame=retain)
        frame,_=make_fixture(0,condition,seed=1);ok,encoded=cv2.imencode('.png',frame);assert ok
        payload=encoded.tobytes()
        admission=capture.admit(operator,inspection_id=started['inspection_id'],expected_version=permit['inspection_state_version'],
            permit_id=permit['permit_id'],nonce=permit['nonce'],sequence=permit['sequence'],payload=payload,content_type='image/png')
        status=observations.process(operator,observation_id=admission['id'],payload=payload)
        ob=repo.snapshot((observation_key(admission['id']),))[observation_key(admission['id'])]
        return ob,payload,status
    return reads,observe,operator,objects,purpose,started,capture


def test_selected_original_is_exact_separate_committed_source_and_role_scoped(world,original_case):
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,payload,status=observe();ident=original_asset_id(ob.data['id'])
    assert ob.data['status']=='completed' and ob.data['original_asset_id']==ident!=ob.data['asset_id']
    assert objects.payloads[ident]==payload and hashlib.sha256(payload).hexdigest()==ob.data['original_evidence_sha256']
    metadata=reads.read(operator,ident)
    assert metadata['derivation']=='original_transmitted_frame' and metadata['historical'] and not metadata['machine_pass']
    assert reads.read(operator,ident,binary=True)[0]==payload
    assert reads.read(world[5],ident)['can_download'] is False
    with pytest.raises(Denied):reads.read(world[5],ident,binary=True)
    _,_,reviewer,_,_=invite_and_join(world,'original-reviewer',roles=(Role.REVIEWER,))
    assert reads.read(reviewer,ident,binary=True)[0]==payload
    _,_,other,_,_=invite_and_join(world,'original-other')
    with pytest.raises(Denied):reads.read(other,ident)


@pytest.mark.parametrize('fault',['selection','id','source','context','calibration','purpose','crop_binding'])
def test_original_requires_intact_completed_source_and_calibration(world,original_case,fault):
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,payload,_=observe();repo=world[1];ident=original_asset_id(ob.data['id'])
    if fault in {'selection','id','source','crop_binding'}:
        row=ob;change={'selection':{'retain_original_frame':False},'id':{'original_asset_id':str(uuid4())},
            'source':{'source_sha256':'f'*64},'crop_binding':{'asset_id':ident}}[fault]
    else:
        key=Key('state','asset#'+ident);row=repo.snapshot((key,))[key]
        change={'context':{'context_sha256':'f'*64},'calibration':{'calibration_sha256':'f'*64},'purpose':{'purpose_id':str(uuid4())}}[fault]
    repo.transact((Write(row.key,row.revision,{**row.data,**change}),))
    with pytest.raises((StoreUnavailable,StoreConflict)):reads.read(operator,ident,binary=True)


@pytest.mark.parametrize('fault',['withdraw','data','expiry'])
def test_original_authority_loss_during_storage_read_never_delivers(world,original_case,fault):
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,_,_=observe();repo=world[1];ident=original_asset_id(ob.data['id'])
    def changed():
        if fault=='withdraw':
            row=repo.snapshot((purpose,))[purpose];repo.transact((Write(purpose,row.revision,{**row.data,'withdrawn':True}),))
        elif fault=='data':repo.transact((reads.purposes.advance(reads.purposes.head()),))
        else:world[2].value+=60000
    objects.after_get=changed
    with pytest.raises((StoreUnavailable,StoreConflict,Denied)):reads.read(operator,ident,binary=True)
    events=repo.query(prefix='asset-read#',table='events',limit=30)[0]
    assert not any(x.data['kind']=='asset_download_ready' for x in events)


def test_selected_original_cleanup_denies_immediately_without_claiming_complete_erasure(world,original_case):
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,_,_=observe();ident=original_asset_id(ob.data['id']);head=reads.purposes.head()
    erasure=AssetErasure(reads.purposes,objects,reads.references,review_ms=30000,jobs_per_minute=8,lease_ms=15000,version_page_size=3)
    preview=erasure.preview(world[5],request=ErasurePreview(asset_ids=(ident,)),idempotency_key='original-preview')
    assert preview['scope']['assets'][0]['kind']=='frame'
    confirm=ErasureConfirmation(preview_id=preview['id'],confirmed_digest=preview['scope_sha256'],
        erase_asset_versions_acknowledged=True,understands_remaining_metadata_and_backups=True)
    job=erasure.confirm(world[5],request=confirm,expected_version=preview['state_version'],idempotency_key='original-erase')
    assert not job['erasure_complete'] and reads.purposes.head().data['epoch']==head.data['epoch']+1
    with pytest.raises(StoreUnavailable):reads.read(operator,ident,binary=True)


def test_original_discovery_is_bounded_and_does_not_scan_or_grant_owner_bytes(world,original_case):
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,_,_=observe();repo=world[1];query=repo.query
    def no_scan(*args,**kwargs):raise AssertionError('original discovery must not scan')
    repo.query=no_scan
    try:
        page=reads.originals(operator,started['inspection_id'])
        assert len(page['originals'])==1 and page['originals'][0]['id']==ob.data['original_asset_id']
        assert page['originals'][0]['can_download'] and page['machine_pass'] is False
        assert reads.originals(world[5],started['inspection_id'])['originals'][0]['can_download'] is False
    finally:repo.query=query


@pytest.mark.parametrize('fault',['duplicate','too_many','unreserved','foreign','late_change'])
def test_original_discovery_rejects_malformed_or_changed_history(world,original_case,fault):
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,_,_=observe();repo=world[1];key=inspection_key(started['inspection_id']);row=repo.snapshot((key,))[key]
    ids=row.data['original_asset_ids']
    changes={'duplicate':{'original_asset_ids':ids*2},'too_many':{'original_asset_ids':[str(uuid4()) for _ in range(4)]},
        'unreserved':{'original_attempts_reserved':0},'foreign':{'original_asset_ids':[str(uuid4())]}}
    if fault!='late_change':repo.transact((Write(key,row.revision,{**row.data,**changes[fault]}),))
    else:
        audit=reads._audit
        def changed(*args,**kwargs):
            audit(*args,**kwargs)
            if args[3]=='inspection_originals_metadata_read':repo.transact((Write(key,row.revision,{**row.data,'original_asset_ids':[]}),))
        reads._audit=changed
    with pytest.raises((StoreUnavailable,StoreConflict,ResourceUnavailable)):reads.originals(operator,started['inspection_id'])


def test_original_discovery_http_requires_identity_and_returns_only_metadata(world,original_case,publication_case):
    from fastapi.testclient import TestClient
    from proofpack.app import create_app
    from proofpack.auth.http import COOKIE
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,_,_=observe()
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=reads.runtime,
        purpose_service=reads.purposes,asset_service=reads)
    with TestClient(app,base_url='https://proofpack.test') as client:
        url='/api/v1/inspections/'+started['inspection_id']+'/evidence/originals'
        assert client.get(url).status_code==401
        client.cookies.set(COOKIE,publication_case[4].cookie)
        response=client.get(url);assert response.status_code==200
        assert response.json()['originals'][0]['id']==ob.data['original_asset_id']
        assert response.headers['cache-control']=='no-store'
        assert 'object_key' not in response.text and 'object_version' not in response.text


def test_original_permit_attempts_are_atomic_nonrefundable_and_exact_retry_does_not_charge_twice(world,original_case,publication_case):
    reads,observe,operator,objects,purpose,started,capture=original_case;repo=world[1]
    key=inspection_key(started['inspection_id']);tick=publication_case[5]
    for number in range(3):
        work=repo.snapshot((key,))[key]
        args={'inspection_id':started['inspection_id'],'expected_version':work.revision,'expected_epoch':1,
            'idempotency_key':'slot-'+str(number),'retain_original_frame':True}
        permit=capture.issue(operator,**args)
        assert permit['retain_original_frame'] is True and permit['usable']
        assert capture.issue(operator,**args)['permit_id']==permit['permit_id']
        assert repo.snapshot((key,))[key].data['original_attempts_reserved']==number+1
        with pytest.raises(StoreConflict):capture.issue(operator,**{**args,'retain_original_frame':False})
        world[2].value+=1001;tick.value+=1001000000
    work=repo.snapshot((key,))[key]
    with pytest.raises(StationRateLimited):capture.issue(operator,inspection_id=started['inspection_id'],
        expected_version=work.revision,expected_epoch=1,idempotency_key='fourth',retain_original_frame=True)


def test_original_permit_retry_cannot_return_a_usable_nonce_after_retention_permission_changes(world,original_case):
    reads,observe,operator,objects,purpose,started,capture=original_case;repo=world[1]
    work=repo.snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    args={'inspection_id':started['inspection_id'],'expected_version':work.revision,'expected_epoch':1,
        'idempotency_key':'bound-original','retain_original_frame':True}
    assert capture.issue(operator,**args)['usable']
    row=repo.snapshot((purpose,))[purpose]
    repo.transact((Write(purpose,row.revision,{**row.data,'source_permission_reference':'changed-reference'}),))
    view=capture.issue(operator,**args)
    assert view['usable'] is False and view['nonce'] is None and view['remaining_acceptance_ms']==0


def test_review_context_preserves_original_provenance_without_granting_improvement(world,original_case):
    from proofpack.review.labels import OutcomeLabels,ReviewTuple
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,_,_=observe();_,_,reviewer,_,_=invite_and_join(world,'original-label-reviewer',roles=(Role.REVIEWER,))
    labels=OutcomeLabels(reads.purposes,writes_per_minute=8,max_duration_ms=60000,review_validity_ms=30000)
    context=labels.context(reviewer,ReviewTuple(before_observation_id=ob.data['id']))
    sources={x['asset_id']:x for x in context['sources']}
    assert set(sources)=={ob.data['asset_id'],ob.data['original_asset_id']}
    original=sources[ob.data['original_asset_id']]
    assert original['derivation']=='original_transmitted_frame' and original['input_sha256']==ob.data['source_sha256']
    assert original['context_sha256']==ob.data['context_sha256'] and original['calibration_sha256']
    assert not context['optional_improvement'] and not context['physical_truth_verified'] and not context['independence_verified']


@pytest.mark.parametrize('selected',[True,False])
def test_original_export_preserves_completion_link_and_explicit_omission(world,original_case,selected):
    import io,json
    from zipfile import ZipFile
    from proofpack.evidence.exports import InspectionExports
    from proofpack.evidence.export_models import ExportRequest,ExportTicketRequest
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,payload,_=observe();ident=started['inspection_id'];key=inspection_key(ident);work=world[1].snapshot((key,))[key]
    exports=InspectionExports(reads,jobs_per_minute=8,job_lifetime_ms=60000,lease_ms=15000,
        page_size=25,max_scan_rows=500,max_records=128,max_assets=3,ticket_ms=30000,download_ms=20000,max_concurrent=2)
    job=exports.create(operator,ident,request=ExportRequest(selected_asset_ids=(ob.data['original_asset_id'],) if selected else (),
        historical_export_acknowledged=True),expected_version=work.revision,idempotency_key='original-export')
    for attempt in range(20):
        if job['status']=='completed':break
        assert job['status']=='queued',job
        job=exports.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='original-export-step-'+str(attempt))
    assert job['status']=='completed'
    token=exports.ticket(operator,job['id'],request=ExportTicketRequest(historical_export_acknowledged=True),
        expected_version=job['state_version'],idempotency_key='original-export-ticket')
    body,_,_=exports.download(operator,job['id'],token['ticket'])
    with ZipFile(io.BytesIO(body)) as archive:
        manifest=json.loads(archive.read('manifest.json'));record=manifest['observations'][0]
        assert record['original_asset_id']==ob.data['original_asset_id'] and record['original_evidence_sha256']==ob.data['source_sha256']
        media={x['id']:x for x in manifest['media']}
        assert media[ob.data['asset_id']]['omitted'] is True
        if selected:assert archive.read(media[ob.data['original_asset_id']]['file'])==payload
        else:assert media[ob.data['original_asset_id']]=={'id':ob.data['original_asset_id'],'omitted':True,'reason':'not_selected'}


@pytest.mark.parametrize('cover_original',[True,False])
def test_dataset_requires_separate_optional_source_and_review_permission_for_original(world,original_case,cover_original):
    from proofpack.review.labels import OutcomeLabels,ReviewTuple,LabelRequest,GroundCount
    from proofpack.recipes.models import PartClass
    from proofpack.evidence.improvement import ImprovementPermissions,ImprovementConfig,ImprovementPreview,ImprovementConfirmation
    from proofpack.review.manifests import DatasetManifests,DatasetConfig,ManifestRequest,Selection,PermissionBinding
    from proofpack.review.datasets import Split
    reads,observe,operator,objects,purpose,started,capture=original_case
    ob,_,_=observe();_,_,reviewer,_,_=invite_and_join(world,'original-dataset-reviewer',roles=(Role.REVIEWER,))
    labels=OutcomeLabels(reads.purposes,writes_per_minute=8,max_duration_ms=60000,review_validity_ms=30000)
    tuple_=ReviewTuple(before_observation_id=ob.data['id']);context=labels.context(reviewer,tuple_)
    label=labels.write(reviewer,request=LabelRequest(**tuple_.model_dump(),source_context_sha256=context['source_context_sha256'],
        data_epoch=context['data_epoch'],outcome='unresolved',ground_truth_counts=tuple(GroundCount(part_class=p,count=1) for p in PartClass),
        method='synthetic_fixture',duration_ms=1000,independence_declared=False,note='Synthetic original-frame test'),idempotency_key='original-label')
    permissions=ImprovementPermissions(reads,ImprovementConfig('synthetic-original-test','Separate synthetic reuse notice.',60000,8,30000))
    ids=(ob.data['asset_id'],ob.data['original_asset_id']) if cover_original else (ob.data['asset_id'],)
    preview=permissions.preview(world[5],request=ImprovementPreview(asset_ids=ids),idempotency_key='original-reuse-preview')
    grant=permissions.confirm(world[5],request=ImprovementConfirmation(preview_id=preview['id'],confirmed_scope_sha256=preview['scope_sha256'],
        documented_permission_reference='synthetic-original-optional-rights',notice_version=preview['notice']['version'],notice_sha256=preview['notice']['sha256'],
        optional_improvement_acknowledged=True,limitations_acknowledged=True,derived_review_metadata_acknowledged=True,expires_at_ms=world[2]()+40000),
        expected_version=preview['state_version'],idempotency_key='original-reuse-confirm')
    datasets=DatasetManifests(labels,permissions,DatasetConfig(1000,20,120,3600000,15000,3000,120))
    selection=Selection(label_id=label['id'],label_revision=1,split=Split.DEVELOPMENT,
        permissions=(PermissionBinding(id=grant['id'],state_version=grant['state_version']),))
    job=datasets.create(reviewer,request=ManifestRequest(selections=(selection,),historical_diagnostic_acknowledged=True,
        frozen_holdout_acknowledged=False),idempotency_key='original-dataset')
    for attempt in range(8):
        if job['status'] not in {'queued','processing'}:break
        job=datasets.advance(reviewer,job['id'],expected_version=job['state_version'],idempotency_key='original-dataset-step-'+str(attempt))
    if cover_original:
        assert job['status']=='completed' and job['receipt_usable']
        entry=datasets.examples(reviewer,job['id'])['examples'][0]
        assert {x['asset_id'] for x in entry['sources']}==set(ids)
        assert not entry['physical_truth_verified'] and not entry['independence_verified']
    else:assert job['status']=='failed' and job['prepared_count']==0 and not job['receipt_usable']


@pytest.mark.parametrize('fault',['storage','receipt_id','receipt_context','receipt_size','withdraw_after_crop','withdraw_after_original'])
def test_partial_original_storage_or_changed_permission_cannot_publish_any_asset(world,original_case,fault):
    from dataclasses import replace
    reads,observe,operator,objects,purpose,started,capture=original_case;repo=world[1];put=objects.put;calls=[]
    existing_assets=repo.query(prefix='asset#',limit=20)[0]
    def changed(**kwargs):
        calls.append(kwargs['asset_id'])
        if fault=='storage' and len(calls)==2:raise StoreUnavailable('synthetic original write outage')
        receipt=put(**kwargs)
        if (fault=='withdraw_after_crop' and len(calls)==1) or (fault=='withdraw_after_original' and len(calls)==2):
            row=repo.snapshot((purpose,))[purpose];repo.transact((Write(purpose,row.revision,{**row.data,'withdrawn':True}),))
        if len(calls)==2:
            if fault=='receipt_id':return replace(receipt,asset_id=str(uuid4()))
            if fault=='receipt_context':return replace(receipt,context_sha256='f'*64)
            if fault=='receipt_size':return replace(receipt,byte_length=receipt.byte_length+1)
        return receipt
    objects.put=changed
    with pytest.raises((Denied,StoreUnavailable,StoreConflict)):observe()
    assert repo.query(prefix='asset#',limit=20)[0]==existing_assets
    work=repo.snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
    assert work.data.get('original_asset_ids',[])==[] and work.data['original_attempts_reserved']==1
    assert work.data['state']!='PASSED_CURRENT'
    events=repo.query(prefix='capture#',table='events',limit=30)[0]
    assert not any(x.data['kind']=='observation_completed' for x in events)
