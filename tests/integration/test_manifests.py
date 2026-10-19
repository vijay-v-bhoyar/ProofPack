"""Real local manifest state and actual source guards; bulk capacity uses injected metadata."""
from dataclasses import asdict,replace
from types import SimpleNamespace
from threading import Event
from uuid import uuid4, UUID
import json
import pytest
from fastapi.testclient import TestClient
from test_access_lifecycle import world, repository_factory, publication_case, invite_and_join, proof
from test_labels import review_case, request_for
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied, Role
from proofpack.auth.service import digest as text_digest
from proofpack.app import create_app
from proofpack.evidence.improvement import ImprovementPermissions, ImprovementConfig, ImprovementPreview, ImprovementConfirmation
from proofpack.evidence.objects import ReferenceObjects
from proofpack.evidence.purposes import DataPurposes
from proofpack.evidence.reads import AssetReads
from proofpack.evidence.repository import Write, Key, StoreConflict, StoreUnavailable
from proofpack.review.manifests import DatasetManifests, DatasetConfig, ManifestRequest, Selection, PermissionBinding, Consequence, manifest_key, entry_key, group_key
from proofpack.review.datasets import Split
from proofpack.runtime.control import RuntimeControl, DATA
from proofpack.runtime.maintenance import MaintenanceDriver


def config(**changes):
    return replace(DatasetConfig(1000,20,120,3600000,15000,3000,120),**changes)


def test_example_preserves_authorized_source_rows_for_the_final_atomic_fence(world,manifest_case):
    service,actor,_,selection,*_=manifest_case
    content,checks,_,_=service._example(actor,selection)
    keys={row.key for row in checks}
    assert all(Key('state','asset#'+source['asset_id']) in keys for source in content['sources'])


def selection(label,permission,split=Split.DEVELOPMENT):
    return Selection(label_id=label,label_revision=1,split=split,permissions=(PermissionBinding(id=permission,state_version=1),))


def request(items):
    return ManifestRequest(selections=tuple(items),historical_diagnostic_acknowledged=True,frozen_holdout_acknowledged=True)


@pytest.fixture
def manifest_case(world,review_case,publication_case):
    labels,reviewer,credentials,_,_,purpose=review_case
    row=world[1].snapshot((purpose,))[purpose];epoch=labels.purposes.head()
    # Complete the abbreviated capture fixture with synthetic documented authority.
    world[1].transact((Write(purpose,row.revision,{**row.data,'id':purpose.resource.split('#')[1],
        'authority_basis':'owner_attestation','rights_independently_verified':False,'optional_improvement':False,'optional_publicity':False,
        'notice_version':world[0].config.notice_version,'notice_sha256':text_digest(world[0].config.notice_text),'source_permission_reference':'synthetic-original-frame-rights'}),labels.purposes.advance(epoch)))
    label=labels.write(reviewer,request=request_for(review_case),idempotency_key='dataset-label')
    objects=publication_case[7]
    reads=AssetReads(labels.purposes,objects,ReferenceObjects(objects.client,objects.config),reads_per_minute=16,max_concurrent=1,read_window_ms=5000)
    permissions=ImprovementPermissions(reads,ImprovementConfig('synthetic-dataset-v1','Separate synthetic optional notice.',60000,8,30000))
    ids=tuple(s['asset_id'] for s in label['source_context']['sources'])
    preview=permissions.preview(world[5],request=ImprovementPreview(asset_ids=ids),idempotency_key='dataset-rights-preview')
    grant=permissions.confirm(world[5],request=ImprovementConfirmation(preview_id=preview['id'],confirmed_scope_sha256=preview['scope_sha256'],
        documented_permission_reference='synthetic-optional-data-rights',notice_version=preview['notice']['version'],notice_sha256=preview['notice']['sha256'],
        optional_improvement_acknowledged=True,limitations_acknowledged=True,derived_review_metadata_acknowledged=True,expires_at_ms=world[2]()+40000),expected_version=preview['state_version'],idempotency_key='dataset-rights-confirm')
    return DatasetManifests(labels,permissions,config()),reviewer,credentials,selection(label['id'],grant['id']),grant,review_case


def create(case,*,split=None,key='dataset'):
    service,actor,_,item,*_=case
    if split is not None:item=item.model_copy(update={'split':split})
    return service.create(actor,request=request((item,)),idempotency_key=key)


def finish(service,actor,job):
    while job['status'] in {'queued','processing'}:
        job=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='step-'+str(job['state_version']))
    return job


def test_real_label_permission_group_chain_and_access_audit(world,manifest_case):
    service,actor,*_=manifest_case;job=create(manifest_case,split=Split.FROZEN_TEST);result=finish(service,actor,job)
    assert result['status']=='completed' and result['receipt_usable'] and result['prepared_count']==1
    page=service.examples(actor,result['id']);entry=page['examples'][0]
    assert entry['split']=='FROZEN_TEST' and entry['data_origin']=='synthetic'
    assert page['prior_exposure_unknown'] and not page['independent_benchmark_qualified'] and not entry['physical_truth_verified']
    assert len(entry['groups'])==3 and len(entry['sources'])==2
    assert service.selections(actor,result['id'])==request((manifest_case[3].model_copy(update={'split':Split.FROZEN_TEST}),)).model_dump(mode='json')
    assert len(world[1].query(prefix='dataset-access#',table='events',limit=20)[0])==2
    assert len(service.list(actor)['datasets'])==1
    for private in ('object_key','object_version','cookie_ref','processing_authority','session_id'):assert private not in json.dumps(page)


def test_cross_manifest_split_conflict_and_explicit_declassification_hold_old_receipt(world,manifest_case):
    service,actor,*_=manifest_case;first=finish(service,actor,create(manifest_case,split=Split.FROZEN_TEST))
    page=service.examples(actor,first['id']);group=page['examples'][0]['groups'][0]['id']
    second=finish(service,actor,create(manifest_case,split=Split.DEVELOPMENT,key='conflicting'))
    assert second['status']=='failed' and second['failure_reason']=='SPLIT_CONFLICT'
    with pytest.raises(Denied):service.declassify(actor,group,request=Consequence(acknowledged=True,reason='used-in-development'),expected_version=1,idempotency_key='not-owner')
    old=service.purposes.head();changed=service.declassify(world[5],group,request=Consequence(acknowledged=True,reason='used-in-development'),expected_version=1,idempotency_key='declassify')
    assert changed['split']=='DEVELOPMENT' and changed['generation']==2 and service.purposes.head().data['epoch']==old.data['epoch']+1
    assert not service.job(actor,first['id'])['receipt_usable']
    with pytest.raises((StoreConflict,StoreUnavailable)):service.examples(actor,first['id'])


@pytest.mark.parametrize('change',['permission','label','epoch'])
def test_stale_source_or_permission_never_prepares(world,manifest_case,change):
    service,actor,_,_,grant,review=manifest_case;job=create(manifest_case)
    if change=='permission':service.improvement.withdraw(world[5],grant['id'],expected_version=1,idempotency_key='withdraw')
    elif change=='label':
        label=service.labels.get(actor,manifest_case[3].label_id)
        service.labels.write(actor,request=request_for(review,note='Corrected synthetic outcome'),ident=label['id'],expected_version=label['state_version'],idempotency_key='correct')
    else:world[1].transact((service.purposes.advance(service.purposes.head()),))
    with pytest.raises(StoreConflict):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='stale')
    assert not service.job(actor,job['id'])['can_advance'] and world[1].snapshot((manifest_key(job['id']),))[manifest_key(job['id'])] is None
    assert service.cancel(actor,job['id'],expected_version=job['state_version'],idempotency_key='cancel')['status']=='cancelled'


def test_missing_or_corrupt_entry_blocks_delivery_and_read_audit(world,manifest_case):
    service,actor,*_=manifest_case;job=finish(service,actor,create(manifest_case));key=entry_key(job['id'],0);row=world[1].snapshot((key,))[key]
    world[1].transact((Write(key,row.revision,{**row.data,'content_sha256':'0'*64}),))
    with pytest.raises(StoreUnavailable):service.examples(actor,job['id'])
    assert world[1].query(prefix='dataset-access#',table='events',limit=20)[0]==[]


def test_cancel_during_source_check_fences_progress(world,manifest_case,monkeypatch):
    service,actor,*_=manifest_case;job=create(manifest_case);original=service._example
    def example(*args):
        result=original(*args);row=service._row(job['id'])
        service.cancel(actor,job['id'],expected_version=row.revision,idempotency_key='cancel-inflight');return result
    monkeypatch.setattr(service,'_example',example)
    with pytest.raises(StoreConflict):service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='cancelled-step')
    assert service.job(actor,job['id'])['status']=='cancelled' and world[1].snapshot((entry_key(job['id'],0),))[entry_key(job['id'],0)] is None


def test_owner_has_restricted_job_status_but_cannot_submit_or_read_examples(world,manifest_case):
    service,actor,*_=manifest_case;job=finish(service,actor,create(manifest_case))
    assert service.job(world[5],job['id'])['example_count']==1
    with pytest.raises(Denied):service.create(world[5],request=request((manifest_case[3],)),idempotency_key='owner-submit')
    with pytest.raises(Denied):service.examples(world[5],job['id'])
    old=service.purposes.head()
    retired=service.retire(world[5],job['id'],request=Consequence(acknowledged=True,reason='benchmark-retired'),expected_version=job['state_version'],idempotency_key='retire')
    assert retired['status']=='retired' and not retired['receipt_usable'] and service.purposes.head().data['epoch']==old.data['epoch']+1


@pytest.fixture
def capacity_case(world,monkeypatch):
    """Injected metadata isolates capacity/lease protocol from source-authorization tests."""
    access,repo,*_=world;runtime=RuntimeControl(access,instance_id=str(uuid4()),artifact_sha256='a'*64,controls_sha256='b'*64,environment='synthetic_demo');runtime.start()
    _,_,actor,*_=invite_and_join(world,'capacity-reviewer',roles=(Role.REVIEWER,))
    purposes=DataPurposes(access,runtime,max_lifetime_ms=3600000)
    labels=SimpleNamespace(access=access,repository=repo,runtime=runtime,purposes=purposes)
    permissions=SimpleNamespace(access=access,repository=repo,runtime=runtime,configuration='a'*64,
        config=ImprovementConfig('capacity-v1','Synthetic capacity stub only.',3600000,8,30000))
    service=DatasetManifests(labels,permissions,config());calls=[]
    def example(actor,item,gate):
        gate();calls.append(item.label_id)
        return {'label_id':item.label_id,'split':item.split.value,'data_origin':'synthetic','prior_exposure_unknown':True,
            'physical_truth_verified':False,'independence_verified':False,'independent_benchmark_qualified':False},[],[],1000000+3600000
    monkeypatch.setattr(service,'_example',example)
    return service,actor,calls


def test_full_thousand_example_capacity_and_paged_chain_without_truncation(world,capacity_case):
    service,actor,calls=capacity_case;permission=str(uuid4());items=[selection(str(UUID(int=i+1)),permission) for i in range(1000)]
    job=service.create(actor,request=request(items),idempotency_key='thousand')
    for i in range(1000):
        if i and i%100==0:world[2].value+=60000
        job=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='capacity-'+str(i))
    assert job['status']=='completed' and job['prepared_count']==1000 and len(calls)==1000
    total=0;start=0
    while start is not None:
        page=service.examples(actor,job['id'],start=start);total+=len(page['examples']);start=page['next_index']
    assert total==1000 and service.examples(actor,job['id'],start=999)['examples'][0]['index']==999


@pytest.mark.parametrize('budget,status',[(2,'failed'),(3,'completed')])
def test_runtime_revalidation_preserves_nonrefundable_budget_and_original_expiry(world,capacity_case,budget,status):
    base,actor,calls=capacity_case
    service=DatasetManifests(base.labels,base.improvement,replace(base.config,max_steps=budget));service._example=base._example
    job=service.create(actor,request=request([selection(str(uuid4()),str(uuid4())) for _ in range(2)]),idempotency_key='restart')
    job=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='first');old=service._row(job['id']).data['expires_at_ms']
    service.runtime.start()  # same identity replays; use a distinct process incarnation below
    newer=RuntimeControl(world[0],instance_id=str(uuid4()),artifact_sha256='a'*64,controls_sha256='b'*64,environment='synthetic_demo');newer.start()
    service.runtime=newer;service.labels.runtime=newer;service.improvement.runtime=newer
    job=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='rescan')
    assert job['prepared_count']==1 and job['steps_reserved']==2
    job=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='last')
    assert job['status']==status and service._row(job['id']).data['expires_at_ms']==old
    assert len(calls)==(2 if budget==2 else 3)


def test_dataset_dispatch_uses_real_reviewer_scope_in_background(world,manifest_case,monkeypatch):
    service,actor,*_=manifest_case;job=create(manifest_case);done=Event();original=service.advance
    def advance(*args,**kwargs):
        value=original(*args,**kwargs);done.set();return value
    monkeypatch.setattr(service,'advance',advance)
    fake=SimpleNamespace(access=service.access,runtime=service.runtime,repository=service.repository)
    driver=MaintenanceDriver(service.access,service.runtime,fake,fake,datasets=service,enabled=True,poll_ms=250,page_size=5,steps_per_minute=60,drain_ms=1000)
    try:driver.start();assert done.wait(8)
    finally:assert driver.stop_and_drain()
    assert service.job(actor,job['id'])['receipt_usable']


def test_http_accepts_full_thousand_request_but_keeps_other_json_limits(world,capacity_case):
    from proofpack.evidence.job_authority import resolve
    service,actor,_=capacity_case;credentials=world[0].login(proof(world[2],'capacity-reviewer',mfa=False));actor=world[0].resolve(credentials.cookie)
    app=create_app(access_service=world[0],app_origin='https://proofpack.test')
    app.state.dataset_service=service
    body=request([selection(str(UUID(int=i+1)),str(uuid4())) for i in range(1000)]).model_dump(mode='json')
    headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'large-http'}
    with TestClient(app,base_url='https://proofpack.test',cookies={COOKIE:credentials.cookie}) as client:
        response=client.post('/api/v1/datasets/manifests',json=body,headers=headers)
        assert response.status_code==201 and response.json()['example_count']==1000
        row=service._row(response.json()['id']);assert resolve(world[0],row.data).member.data['id']==actor.member.data['id']
        assert client.post('/api/v1/datasets/manifests',json={'padding':'x'*262145},headers=headers).status_code==413
        assert client.post('/api/v1/labels',json={'padding':'x'*9000},headers=headers).status_code==413


def test_unknown_step_retry_does_not_consume_another_attempt_or_renew_expiry(world,manifest_case):
    service,actor,*_=manifest_case;job=create(manifest_case);before=service._row(job['id']).data['expires_at_ms']
    result=service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='lost-step')
    assert service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='lost-step')==result
    assert result['steps_reserved']==1 and service._row(job['id']).data['expires_at_ms']==before


@pytest.mark.parametrize('change',['expiry','withdrawal','role'])
def test_source_delivery_expiry_and_access_revocation_are_rechecked(world,manifest_case,change):
    service,actor,_,_,grant,*_=manifest_case;job=finish(service,actor,create(manifest_case))
    if change=='expiry':world[2].value+=40000
    elif change=='withdrawal':service.improvement.withdraw(world[5],grant['id'],expected_version=1,idempotency_key='after-sealing')
    else:world[0].change_access(world[5],user_id=actor.member.data['id'],roles=(Role.OPERATOR,),enabled=True,expected_version=1,idempotency_key='role-lost')
    with pytest.raises((Denied,StoreConflict)):service.examples(actor,job['id'])
    assert world[1].query(prefix='dataset-access#',table='events',limit=20)[0]==[]


def test_source_image_permission_does_not_implicitly_allow_review_metadata(world,manifest_case):
    service,actor,_,item,grant,*_=manifest_case;permissions=service.improvement
    preview=permissions.preview(world[5],request=ImprovementPreview(asset_ids=tuple(a['id'] for a in grant['assets'])),idempotency_key='images-only-preview')
    image_only=permissions.confirm(world[5],request=ImprovementConfirmation(preview_id=preview['id'],confirmed_scope_sha256=preview['scope_sha256'],
        documented_permission_reference='images-only-synthetic-rights',notice_version=preview['notice']['version'],notice_sha256=preview['notice']['sha256'],
        optional_improvement_acknowledged=True,limitations_acknowledged=True,expires_at_ms=world[2]()+30000),expected_version=preview['state_version'],idempotency_key='images-only')
    assert image_only['derived_review_metadata_allowed'] is False
    new=service.create(actor,request=request((selection(item.label_id,image_only['id']),)),idempotency_key='no-label-rights')
    failed=finish(service,actor,new)
    assert failed['status']=='failed' and failed['failure_reason']=='SOURCE_OR_PERMISSION_HELD' and failed['prepared_count']==0


def test_another_reviewer_can_read_but_action_hints_and_writes_remain_denied(world,manifest_case):
    service,actor,*_=manifest_case;job=finish(service,actor,create(manifest_case))
    _,_,other,*_=invite_and_join(world,'readonly-data-reviewer',roles=(Role.REVIEWER,))
    summary=service.job(other,job['id']);assert not summary['can_cancel'] and not summary['can_retire'] and not summary['can_advance']
    assert service.examples(other,job['id'])['examples']
    with pytest.raises(Denied):service.retire(other,job['id'],request=Consequence(acknowledged=True,reason='not-authorized'),expected_version=job['state_version'],idempotency_key='other-retire')


@pytest.mark.parametrize('lease_ms',[15000,60000],ids=['lease-expiry','permission-expiry'])
def test_final_commit_rechecks_deadlines_after_slow_authority(world,manifest_case,monkeypatch,lease_ms):
    base,actor,_,item,grant,*_=manifest_case
    service=DatasetManifests(base.labels,base.improvement,replace(base.config,lease_ms=lease_ms))
    job=service.create(actor,request=request((item,)),idempotency_key='late-commit')
    snapshot=service.repository.snapshot;fresh=service.access._fresh;ready=False;triggered=False
    def read(keys):
        nonlocal ready
        result=snapshot(keys)
        if keys==(entry_key(job['id'],0),):ready=True
        return result
    def authorize(*args,**kwargs):
        nonlocal triggered
        if ready and not triggered:
            triggered=True
            world[2].value=int(service._row(job['id']).data['lease_until_ms']) if lease_ms==15000 else grant['expires_at_ms']
        return fresh(*args,**kwargs)
    monkeypatch.setattr(service.repository,'snapshot',read);monkeypatch.setattr(service.access,'_fresh',authorize)
    with pytest.raises((StoreConflict,StoreUnavailable)):
        service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='late-step')
    assert triggered
    assert snapshot((manifest_key(job['id']),))[manifest_key(job['id'])] is None


@pytest.mark.parametrize('change',['expiry','epoch','role'])
def test_delivery_rechecks_after_slow_audit(world,manifest_case,monkeypatch,change):
    service,actor,_,_,grant,*_=manifest_case;job=finish(service,actor,create(manifest_case))
    transact=service.repository.transact;triggered=False
    def write(writes,checks=()):
        nonlocal triggered
        result=transact(writes,checks)
        if not triggered and any(w.key.resource.startswith('dataset-access#') for w in writes):
            triggered=True
            if change=='expiry':world[2].value=grant['expires_at_ms']
            elif change=='epoch':transact((service.purposes.advance(service.purposes.head()),))
            else:service.access.change_access(world[5],user_id=actor.member.data['id'],roles=(Role.OPERATOR,),enabled=True,expected_version=1,idempotency_key='late-audit-role')
        return result
    monkeypatch.setattr(service.repository,'transact',write)
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):service.examples(actor,job['id'])
    assert triggered
    # An admission was logged; this is not proof that a page was delivered or read.
    assert len(service.repository.query(prefix='dataset-access#',table='events',limit=20)[0])==1


@pytest.mark.parametrize('boundary',['lease','effective'])
def test_terminal_source_failure_rechecks_final_lease(world,manifest_case,monkeypatch,boundary):
    service,actor,*_=manifest_case;job=create(manifest_case);failed=False;authorized=False;fired=False
    if boundary=='effective':
        row=service._row(job['id']);world[1].transact((Write(row.key,row.revision,{**row.data,'effective_deadline_ms':world[2]()+1000,'validation_runtime':asdict(service.runtime.handle)}),))
        job=service.job(actor,job['id'])
    original=service.access._fresh
    def missing(*args,**kwargs):
        nonlocal failed
        failed=True;raise StoreUnavailable('injected missing dataset source')
    def fresh(*args,**kwargs):
        nonlocal authorized
        value=original(*args,**kwargs)
        if failed:authorized=True
        return value
    def gate():
        nonlocal fired
        if failed and authorized and not fired:
            fired=True;world[2].value=int(service._row(job['id']).data['lease_until_ms' if boundary=='lease' else 'effective_deadline_ms'])
    monkeypatch.setattr(service,'_example',missing);monkeypatch.setattr(service.access,'_fresh',fresh)
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):
        service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='late-failure',execution_gate=gate)
    current=service._row(job['id'])
    assert fired and current.data['status']=='processing' and current.data['steps_reserved']==1
    assert current.data['failure_reason'] is None and current.data['processed']==0
    assert world[1].snapshot((manifest_key(job['id']),))[manifest_key(job['id'])] is None


@pytest.mark.parametrize('boundary',['job','effective'])
def test_expired_reservation_cannot_consume_dataset_step(world,manifest_case,monkeypatch,boundary):
    service,actor,*_=manifest_case;job=create(manifest_case);original=service.access._record;armed=False;fired=False
    if boundary=='effective':
        row=service._row(job['id']);world[1].transact((Write(row.key,row.revision,{**row.data,'effective_deadline_ms':world[2]()+1000,'validation_runtime':asdict(service.runtime.handle)}),))
        job=service.job(actor,job['id'])
    def record(*args,**kwargs):
        nonlocal armed
        if args[1]=='dataset-step:'+job['id']:armed=True
        return original(*args,**kwargs)
    def gate():
        nonlocal fired
        if armed and not fired:
            fired=True;world[2].value=int(service._row(job['id']).data['expires_at_ms' if boundary=='job' else 'effective_deadline_ms'])
    monkeypatch.setattr(service.access,'_record',record)
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):
        service.advance(actor,job['id'],expected_version=job['state_version'],idempotency_key='expired-reservation',execution_gate=gate)
    current=service._row(job['id'])
    assert fired and current.data['status']=='queued' and current.data['steps_reserved']==0
