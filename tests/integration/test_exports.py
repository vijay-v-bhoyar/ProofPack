"""Owned local state and intercepted retained media, never actual AWS/export value proof."""
import hashlib
import io
import json
from dataclasses import replace
from uuid import uuid4
from zipfile import ZipFile
import pytest
from fastapi.testclient import TestClient
from test_access_lifecycle import world,repository_factory,publication_case,invite_and_join,proof
from test_asset_reads import frame_read_case
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied,Role
from proofpack.evidence.exports import InspectionExports,ExportLimited,manifest_key,ticket_key
from proofpack.evidence.export_models import ExportRequest,ExportTicketRequest
from proofpack.evidence.erasure import job_key
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.runtime.control import RuntimeControl


@pytest.fixture
def export_case(world,frame_read_case):
    reads,asset,operator,credentials,reviewer,review_credentials,objects,purpose=frame_read_case
    service=InspectionExports(reads,jobs_per_minute=20,job_lifetime_ms=60000,lease_ms=15000,page_size=25,max_scan_rows=500,max_records=128,
        max_assets=3,ticket_ms=30000,download_ms=20000,max_concurrent=2)
    observation=world[1].snapshot((Key('state','observation#'+asset.data['observation_id']),))[Key('state','observation#'+asset.data['observation_id'])]
    return service,observation.data['inspection_id'],asset,operator,credentials,reviewer,review_credentials,objects


def test_handoff_export_without_complete_schema_marker_is_held(world,export_case,publication_case):
    from test_handoff_exports import start_handoff
    start_handoff(world,export_case,publication_case)
    service=export_case[0];job=create(export_case,selected=False)
    row=service._row(job['id']);data={k:v for k,v in row.data.items() if k!='support_handoff_schema'}
    service.repository.transact((Write(row.key,row.revision,data),))
    view=service.job(export_case[3],job['id'])
    assert not view['can_advance'] and not view['can_issue_ticket']
    with pytest.raises(StoreUnavailable):service.advance(export_case[3],job['id'],expected_version=view['state_version'],idempotency_key='legacy-missing-support-schema')


def create(case,*,actor=None,selected=True,key='create-export'):
    service,ident,asset,operator,*_=case;work=service.repository.snapshot((Key('state','inspection#'+ident),))[Key('state','inspection#'+ident)]
    return service.create(actor or operator,ident,request=ExportRequest(selected_asset_ids=(asset.data['id'],) if selected else (),historical_export_acknowledged=True),expected_version=work.revision,idempotency_key=key)


def complete(case,job=None,actor=None):
    service,_,_,operator,*_=case;job=job or create(case,actor=actor)
    for attempt in range(20):
        if job['status']=='completed':return job
        assert job['status']=='queued',job
        job=service.advance(actor or operator,job['id'],expected_version=job['state_version'],idempotency_key='step-'+str(attempt)+'-'+job['id'])
    raise AssertionError('finite fixture preparation did not finish')


def ticket(case,job,*,actor=None,key='ticket'):
    return case[0].ticket(actor or case[3],job['id'],request=ExportTicketRequest(historical_export_acknowledged=True),expected_version=job['state_version'],idempotency_key=key)


def test_private_dispatch_reference_creation_unchanged_retry_and_explicit_rebind(world,export_case):
    from proofpack.evidence.job_authority import resolve
    service,_,_,operator,*_=export_case
    job=create(export_case,selected=False)
    row=service._row(job['id']);original=row.data['processing_authority']
    assert resolve(service.access,row.data).session.data['id']==operator.session.data['id']
    assert 'processing_authority' not in job and 'cookie_ref' not in json.dumps(job)
    world[2].value+=1
    assert create(export_case,selected=False)['id']==job['id']
    assert service._row(job['id']).data['processing_authority']==original
    first=service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='authority-step')
    refreshed=service._row(job['id']).data['processing_authority']
    assert refreshed['body']['issued_at_ms']==world[2]() and refreshed!=original
    assert refreshed['body']['expires_at_ms']==original['body']['expires_at_ms']
    world[2].value+=1
    replay=service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='authority-step')
    assert replay['state_version']==first['state_version']
    assert service._row(job['id']).data['processing_authority']==refreshed


def test_complete_export_preserves_source_hashes_historical_labels_and_exact_media(world,export_case):
    service,ident,asset,operator,credentials,reviewer,review_credentials,objects=export_case
    recorded,_=service.repository.query(prefix='access#',table='events',limit=100)
    private_bindings={row.key.resource.split('#')[-1] for row in recorded
        if row.data.get('details',{}).get('inspection_id')==ident and 'resource_bindings' in row.data}
    assert private_bindings,'exercise actual private resource bindings rather than absent metadata'
    captures,_=service.repository.query(prefix='capture#',table='events',limit=100)
    capture_bindings={row.key.resource.split('#')[-1] for row in captures
        if row.data.get('inspection_id')==ident and 'resource_bindings' in row.data}
    assert capture_bindings,'exercise direct capture bindings as well as shared access bindings'
    job=complete(export_case);assert job['can_issue_ticket'] and not job['current_approval'] and job['historical']
    token=ticket(export_case,job);payload,manifest_hash,remaining=service.download(operator,job['id'],token['ticket'])
    with ZipFile(io.BytesIO(payload)) as archive:
        text=archive.read('manifest.json');manifest=json.loads(text)
        assert hashlib.sha256(text).hexdigest()==manifest_hash==job['manifest_sha256']
        assert manifest['historical'] and manifest['current_approval'] is False and not manifest['capture_authenticity_verified']
        assert manifest['inspection_id']==ident and not manifest['optional_publicity'] and not manifest['optional_improvement']
        assert len(manifest['observations'])==1 and manifest['sources'] and manifest['events']
        assert private_bindings & {event['id'] for event in manifest['events']}
        assert capture_bindings & {event['id'] for event in manifest['events']}
        media=manifest['media'][0];assert archive.read(media['file'])==objects.payloads[asset.data['id']]
        assert media['sha256']==hashlib.sha256(objects.payloads[asset.data['id']]).hexdigest()
        for secret in ['actor_scope','session_id','object_key','object_version','capability','source_permission_reference','resource_bindings']:
            assert secret not in text.decode()
    assert remaining>0 and len(payload)<8388608
    with pytest.raises(Denied):service.download(operator,job['id'],token['ticket'])
    assert service.repository.snapshot((ticket_key(token['id']),))[ticket_key(token['id'])].data['ready'] is True


def test_metadata_only_archive_omits_media_and_never_reads_storage(world,export_case,monkeypatch):
    service,_,asset,operator,*_=export_case
    monkeypatch.setattr(service.assets.frames,'get',lambda *args:pytest.fail('metadata export must not read media'))
    job=complete(export_case,create(export_case,selected=False));token=ticket(export_case,job)
    body,_,_=service.download(operator,job['id'],token['ticket'])
    with ZipFile(io.BytesIO(body)) as archive:
        assert archive.namelist()==['manifest.json'];manifest=json.loads(archive.read('manifest.json'))
        assert manifest['media']==[{'id':asset.data['id'],'omitted':True,'reason':'not_selected'}]


def test_owner_cannot_export_media_without_explicit_role_and_unrelated_operator_is_denied(world,export_case):
    with pytest.raises(Denied):create(export_case,actor=world[5])
    _,_,other,_,_=invite_and_join(world,'export-other')
    with pytest.raises(Denied):create(export_case,actor=other)
    job=create(export_case);view=export_case[0].job(world[5],job['id'])
    assert not view['can_advance'] and not view['can_issue_ticket'] and view['selected_asset_ids']==[]
    with pytest.raises(Denied):ticket(export_case,job,actor=world[5])


def test_reviewer_exports_own_job_but_cannot_read_another_requestors_archive(world,export_case):
    service,_,_,operator,_,reviewer,*_=export_case
    job=complete(export_case,actor=reviewer);value=ticket(export_case,job,actor=reviewer)
    with pytest.raises(Denied):service.download(operator,job['id'],value['ticket'])
    assert service.download(reviewer,job['id'],value['ticket'])[0]


@pytest.mark.parametrize('fault',['inspection','epoch','source','expiry'])
def test_changed_scope_or_expiry_blocks_progress_and_ticket(world,export_case,fault):
    service,ident,asset,operator,*_=export_case;job=complete(export_case)
    if fault=='inspection':key=Key('state','inspection#'+ident)
    elif fault=='source':key=Key('state','observation#'+asset.data['observation_id'])
    elif fault=='epoch':key=service.purposes.head().key
    else:key=None;world[2].value+=60000
    if key:
        row=service.repository.snapshot((key,))[key];value={**row.data,'epoch':row.data['epoch']+1} if fault=='epoch' else {**row.data,'tampered':True}
        service.repository.transact((Write(key,row.revision,value),))
    with pytest.raises((StoreConflict,StoreUnavailable)):ticket(export_case,job)
    assert not service.job(operator,job['id'])['can_issue_ticket']


def test_cancel_completed_export_invalidates_ticket_and_retains_truthful_history(world,export_case):
    service,_,_,operator,*_=export_case;job=complete(export_case);value=ticket(export_case,job)
    cancelled=service.cancel(world[5],job['id'],expected_version=job['state_version'],idempotency_key='owner-cancel')
    assert cancelled['status']=='cancelled' and not cancelled['can_issue_ticket']
    with pytest.raises(StoreConflict):service.download(operator,job['id'],value['ticket'])
    assert service.repository.snapshot((manifest_key(job['id']),))[manifest_key(job['id'])] is not None
    assert service.cancel(world[5],job['id'],expected_version=job['state_version'],idempotency_key='owner-cancel')['state_version']==cancelled['state_version']


def test_create_step_and_ticket_retries_reuse_original_durable_intent(world,export_case):
    service,_,_,operator,*_=export_case;job=create(export_case)
    assert create(export_case)['id']==job['id']
    first=service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='same-step')
    assert service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='same-step')['state_version']==first['state_version']
    job=complete(export_case,first);one=ticket(export_case,job);two=ticket(export_case,job)
    assert one==two
    with pytest.raises(StoreConflict):ticket(export_case,{**job,'state_version':job['state_version']+1})


@pytest.mark.parametrize('limit',['max_scan_rows','max_records'])
def test_limit_exhaustion_fails_job_instead_of_publishing_a_truncated_manifest(world,export_case,limit):
    service,_,_,operator,*_=export_case;setattr(service,limit,1);job=create(export_case)
    for attempt in range(10):
        if job['status']=='failed':break
        job=service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='limited-'+str(attempt))
    assert job['status']=='failed' and job['failure_reason']=='EXPORT_LIMIT_EXCEEDED' and not job['can_issue_ticket']
    assert service.repository.snapshot((manifest_key(job['id']),))[manifest_key(job['id'])] is None


def test_http_uses_family_dispatch_safe_headers_and_bounded_bodies(world,export_case):
    service,ident,asset,operator,credentials,*_=export_case
    app=create_app(access_service=service.access,app_origin='https://proofpack.test',runtime_control=service.runtime,purpose_service=service.purposes,asset_service=service.assets,export_service=service)
    with TestClient(app,base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie);headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-export','If-Match':'3'}
        key=Key('state','inspection#'+ident);headers['If-Match']=str(service.repository.snapshot((key,))[key].revision)
        body={'selected_asset_ids':[asset.data['id']],'historical_export_acknowledged':True}
        response=client.post('/api/v1/inspections/'+ident+'/exports',headers=headers,json=body);assert response.status_code==201,response.text
        job=response.json()
        assert client.get('/api/v1/jobs/'+job['id']).status_code==200
        job=complete(export_case,job);headers.update({'If-Match':str(job['state_version']),'Idempotency-Key':'http-ticket'})
        value=client.post('/api/v1/jobs/'+job['id']+'/download-tickets',headers=headers,json={'historical_export_acknowledged':True});assert value.status_code==201,value.text
        ticket_headers={'X-Export-Ticket':value.json()['ticket']}
        assert client.get('/api/v1/jobs/'+job['id']+'/download',headers={**ticket_headers,'Range':'bytes=0-4'}).status_code==400
        response=client.get('/api/v1/jobs/'+job['id']+'/download',headers=ticket_headers)
        assert response.status_code==200 and response.headers['content-type']=='application/zip'
        assert response.headers['x-content-sha256']==hashlib.sha256(response.content).hexdigest() and response.headers['cache-control']=='no-store'
        for path in ['/jobs/'+job['id']+'/cancel','/privacy/deletion-previews','/inspections/'+ident+'/exports']:
            assert client.post('/api/v1'+path,headers=headers,content=b'x'*8193).status_code==413


def test_lost_committed_ticket_response_replays_same_capability_without_renewing_expiry(world,export_case,monkeypatch):
    service=export_case[0];job=complete(export_case);original=service.access._record
    def lose(*args,**kwargs):
        result=original(*args,**kwargs)
        if args[1].startswith('export-ticket:'):raise StoreUnavailable('synthetic lost ticket reply after commit')
        return result
    monkeypatch.setattr(service.access,'_record',lose)
    with pytest.raises(StoreUnavailable):ticket(export_case,job)
    monkeypatch.setattr(service.access,'_record',original)
    one=ticket(export_case,job);world[2].value+=1000;two=ticket(export_case,job)
    assert one['ticket']==two['ticket'] and one['remaining_ms']-two['remaining_ms']==1000
    assert service.repository.snapshot((ticket_key(one['id']),))[ticket_key(one['id'])].revision==1


def test_cancellation_during_media_read_returns_no_archive_and_does_not_recall_copies(world,export_case,monkeypatch):
    service,_,_,operator,*_=export_case;job=complete(export_case);value=ticket(export_case,job);original=service.assets.frames.get
    def cancel(receipt):
        payload=original(receipt);service.cancel(world[5],job['id'],expected_version=job['state_version'],idempotency_key='during-download');return payload
    monkeypatch.setattr(service.assets.frames,'get',cancel)
    with pytest.raises(StoreConflict):service.download(operator,job['id'],value['ticket'])
    record=service.repository.snapshot((ticket_key(value['id']),))[ticket_key(value['id'])]
    assert record.data['consumed'] is True and record.data['ready'] is False


@pytest.mark.parametrize('fault',['token','expiry','manifest'])
def test_invalid_expired_ticket_or_corrupt_manifest_cannot_disclose_archive(world,export_case,fault):
    service,_,_,operator,*_=export_case;job=complete(export_case);value=ticket(export_case,job);capability=value['ticket']
    if fault=='token':capability=capability[:-1]+('a' if capability[-1]!='a' else 'b')
    elif fault=='expiry':world[2].value+=30000
    else:
        key=manifest_key(job['id']);row=service.repository.snapshot((key,))[key]
        service.repository.transact((Write(key,row.revision,{**row.data,'json':'{}'}),))
    with pytest.raises((Denied,StoreUnavailable)):service.download(operator,job['id'],capability)


@pytest.mark.parametrize('phase',['during_page','before_progress'])
def test_runtime_replacement_fences_old_export_worker(world,export_case,monkeypatch,phase):
    service,_,_,operator,*_=export_case;job=create(export_case)
    replacement=RuntimeControl(service.access,instance_id=str(uuid4()),artifact_sha256=service.runtime.artifact_sha256,
        controls_sha256=service.runtime.controls_sha256,environment=service.runtime.environment)
    if phase=='during_page':
        original=service.repository.query
        def replace_page(*args,**kwargs):
            page=original(*args,**kwargs);replacement.start();return page
        monkeypatch.setattr(service.repository,'query',replace_page)
    else:
        original=service.repository.transact;changed=False
        def replace_commit(writes,*args,**kwargs):
            nonlocal changed
            if not changed and any(w.key.resource.startswith('export#') and w.data['kind']=='export_progress' for w in writes):
                changed=True;replacement.start()
            return original(writes,*args,**kwargs)
        monkeypatch.setattr(service.repository,'transact',replace_commit)
    with pytest.raises((StoreUnavailable,StoreConflict)):service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='old-runtime')
    row=service.repository.snapshot((job_key(job['id']),))[job_key(job['id'])]
    assert row.data['status']=='processing' and row.data['stage']==0


def test_active_expired_and_duplicate_leases_do_not_repeat_one_preparation_attempt(world,export_case,monkeypatch):
    service,_,_,operator,*_=export_case;job=create(export_case);original=service.repository.query
    def expire(*args,**kwargs):
        page=original(*args,**kwargs);world[2].value+=15000;return page
    monkeypatch.setattr(service.repository,'query',expire)
    with pytest.raises(StoreConflict):service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='expired-step')
    current=service.job(operator,job['id']);assert current['status']=='processing' and current['can_advance']
    assert service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='expired-step')['state_version']==current['state_version']
    monkeypatch.setattr(service.repository,'query',original)
    assert service.advance(operator,job['id'],expected_version=current['state_version'],idempotency_key='new-step')['status']=='queued'


def test_constructor_slots_are_held_through_failure_and_consumed_ticket_cannot_retry_blindly(world,export_case,monkeypatch):
    service,_,_,operator,*_=export_case;job=complete(export_case);value=ticket(export_case,job)
    assert service.slots.acquire(False) and service.slots.acquire(False)
    with pytest.raises(ExportLimited):service.download(operator,job['id'],value['ticket'])
    service.slots.release();service.slots.release()

    monkeypatch.setattr(service.assets.frames,'get',lambda *args:(_ for _ in ()).throw(StoreUnavailable('synthetic storage uncertainty')))
    with pytest.raises(StoreUnavailable):service.download(operator,job['id'],value['ticket'])
    with pytest.raises(Denied):service.download(operator,job['id'],value['ticket'])
    assert service.slots.acquire(False) and service.slots.acquire(False)
    service.slots.release();service.slots.release()


def test_missing_completion_event_cannot_be_exported_as_complete_history(world,export_case,monkeypatch):
    service=export_case[0];original=service.repository.query
    def missing(*args,**kwargs):
        rows,cursor=original(*args,**kwargs)
        return [r for r in rows if r.data.get('kind')!='observation_completed'],cursor
    monkeypatch.setattr(service.repository,'query',missing)
    with pytest.raises(StoreUnavailable):complete(export_case)


def test_corrupt_human_decision_digest_cannot_be_exported_as_valid_history(world,export_case,publication_case):
    service,ident,asset,operator,*_=export_case;stations=publication_case[1].stations
    work=service.repository.snapshot((Key('state','inspection#'+ident),))[Key('state','inspection#'+ident)]
    station=stations.view(operator,work.data['station_id'])
    result=stations.record_disposition(operator,inspection_id=ident,expected_version=work.revision,expected_epoch=station['epoch'],
        disposition='reject',reason='Synthetic manual handling',human_check_confirmed=False,idempotency_key='before-export')
    key=Key('state','human-disposition#'+ident+'#'+result['id']);row=service.repository.snapshot((key,))[key]
    service.repository.transact((Write(key,row.revision,{**row.data,'reason':'Changed without the original content digest'}),))
    with pytest.raises(StoreUnavailable):complete(export_case)


def test_valid_human_corrections_export_as_separate_historical_lineage(world,export_case,publication_case):
    service,ident,asset,operator,*_=export_case;stations=publication_case[1].stations
    for index,disposition in enumerate(['reject','human_accepted']):
        key=Key('state','inspection#'+ident);work=service.repository.snapshot((key,))[key];station=stations.view(operator,work.data['station_id'])
        stations.record_disposition(operator,inspection_id=ident,expected_version=work.revision,expected_epoch=station['epoch'],disposition=disposition,
            reason='Synthetic independent manual handling '+str(index),human_check_confirmed=disposition=='human_accepted',idempotency_key='decision-'+str(index))
    job=complete(export_case);record=service.repository.snapshot((manifest_key(job['id']),))[manifest_key(job['id'])];value=json.loads(record.data['json'])
    assert len(value['human_decisions'])==2 and value['human_disposition']=='human_accepted' and value['current_approval'] is False
    assert value['data_origins']==['synthetic'] and value['physical_truth_verified'] is False


def test_missing_completed_manifest_denies_ticket_and_readiness(world,export_case,monkeypatch):
    service,_,_,operator,*_=export_case;job=complete(export_case);original=service.repository.snapshot;key=manifest_key(job['id'])
    def missing(keys):
        result=original(keys)
        if key in result:result[key]=None
        return result
    monkeypatch.setattr(service.repository,'snapshot',missing)
    assert service.job(operator,job['id'])['can_issue_ticket'] is False
    with pytest.raises(StoreUnavailable):ticket(export_case,job)


def test_recorded_export_discovery_and_context_do_not_grant_other_requestor_access(world,export_case):
    service,ident,asset,operator,_,reviewer,*_=export_case
    context=service.context(operator,ident);assert context['latest_asset_id']==asset.data['id'] and context['current_approval'] is False
    job=create(export_case);listed=service.list(operator,ident)
    assert [v['id'] for v in listed['jobs']]==[job['id']] and service.list(reviewer,ident)['jobs']==[]
    with pytest.raises(Denied):service.list(world[5],ident)


def test_cursor_is_signed_and_bound_to_inspection_requestor(world,export_case):
    service,ident,asset,operator,_,reviewer,*_=export_case;create(export_case)
    writes=tuple(Write(job_key(str(uuid4())),None,{'kind':'asset_erasure'}) for _ in range(21));service.repository.transact(writes)
    first=service.list(operator,ident);cursor=first['next_cursor'];assert cursor
    assert service.list(operator,ident,cursor=cursor)['inspection_id']==ident
    with pytest.raises(ValueError):service.list(operator,ident,cursor=cursor+'x')
    with pytest.raises(ValueError):service.list(reviewer,ident,cursor=cursor)


def test_deleted_unselected_media_has_explicit_omission_without_fetch(world,export_case,monkeypatch):
    service,_,asset,operator,*_=export_case;row=service.repository.snapshot((asset.key,))[asset.key];data=service.purposes.head()
    service.repository.transact((Write(row.key,row.revision,{**row.data,'read_denied':True,'status':'deleted'}),service.purposes.advance(data)))
    monkeypatch.setattr(service.assets.frames,'get',lambda *args:pytest.fail('deleted image must not be fetched'))
    job=complete(export_case,create(export_case,selected=False));record=service.repository.snapshot((manifest_key(job['id']),))[manifest_key(job['id'])]
    assert json.loads(record.data['json'])['media']==[{'id':asset.data['id'],'omitted':True,'reason':'unavailable_or_deleted'}]


def test_capability_key_rotation_invalidates_prior_job_and_ticket_configuration(world,export_case):
    service,_,_,operator,*_=export_case;job=complete(export_case);value=ticket(export_case,job)
    service.access.config=replace(service.access.config,capability_key=b'new-synthetic-export-key-not-real'*2)
    changed=InspectionExports(service.assets,jobs_per_minute=20,job_lifetime_ms=60000,lease_ms=15000,page_size=25,max_scan_rows=500,max_records=128,
        max_assets=3,ticket_ms=30000,download_ms=20000,max_concurrent=2)
    assert changed.job(operator,job['id'])['can_issue_ticket'] is False
    with pytest.raises(StoreConflict):changed.download(operator,job['id'],value['ticket'])


def test_scan_allowance_is_reserved_before_query_and_not_refunded_after_unknown_expired_steps(world,export_case,monkeypatch):
    service,_,_,operator,*_=export_case;service.max_scan_rows=2;service.page_size=1;job=create(export_case);original=service.repository.query;calls=[]
    def expire(*args,**kwargs):
        calls.append(kwargs['limit']);result=original(*args,**kwargs);world[2].value+=15000;return result
    monkeypatch.setattr(service.repository,'query',expire)
    for attempt in range(2):
        before=job
        with pytest.raises(StoreConflict):service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='uncertain-scan-'+str(attempt))
        job=service.job(operator,job['id'])
        assert service.advance(operator,job['id'],expected_version=before['state_version'],idempotency_key='uncertain-scan-'+str(attempt))['state_version']==job['state_version']
    assert job['scan_rows_reserved']==2 and calls==[1,1]
    before=job;job=service.advance(operator,job['id'],expected_version=job['state_version'],idempotency_key='exhausted-scan')
    assert job['status']=='failed' and job['failure_reason']=='EXPORT_LIMIT_EXCEEDED' and calls==[1,1]
    assert service.advance(operator,job['id'],expected_version=before['state_version'],idempotency_key='exhausted-scan')['status']=='failed'


def test_expired_construction_budget_rejects_before_ticket_consumption_or_media_reads(world,export_case,monkeypatch):
    service,_,_,operator,*_=export_case;job=complete(export_case);value=ticket(export_case,job);ticks=iter([0,30000000000])
    monkeypatch.setattr(service,'_tick',lambda:next(ticks))
    monkeypatch.setattr(service.assets.frames,'get',lambda *args:pytest.fail('expired construction must not fetch media'))
    with pytest.raises(StoreUnavailable):service.download(operator,job['id'],value['ticket'])
    assert service.repository.snapshot((ticket_key(value['id']),))[ticket_key(value['id'])].data['consumed'] is False
