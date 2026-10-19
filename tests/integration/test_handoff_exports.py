"""Actual local transaction/export lineage; synthetic people and retained media."""
import json
from zipfile import ZipFile
import io
from uuid import uuid4
import pytest
from test_access_lifecycle import world,repository_factory,publication_case,invite_and_join
from test_asset_reads import frame_read_case
from test_exports import export_case,create,complete,ticket
from proofpack.stations.handoffs import InspectionHandoffs,HandoffLimits,HandoffRequest,HandoffResponse,HandoffCancel,handoff_key
from proofpack.evidence.repository import Key,Write,StoreUnavailable,StoreConflict
from proofpack.auth.policy import Denied,Role
from proofpack.calibrations.dependencies import digest

def start_handoff(world,case,publication_case,*,lifetime=3600000,retention=30*86400000):
    service,ident,_,operator,_,reviewer,*_=case
    handoffs=InspectionHandoffs(publication_case[1].stations,limits=HandoffLimits(4,lifetime,60,5000,20,retention))
    work=world[1].snapshot((Key('state','inspection#'+ident),))[Key('state','inspection#'+ident)]
    sent=handoffs.request(operator,ident,expected_version=work.revision,request=HandoffRequest(recipient_user_id=reviewer.member.data['id'],expected_epoch=int(work.data['station_epoch']),reason_code='support_needed',stop_acknowledged=True),idempotency_key='handoff-export-source')
    return handoffs,sent

def archive(case,job,*,actor=None):
    actor=actor or case[3];grant=ticket(case,job,actor=actor);data,_,_=case[0].download(actor,job['id'],grant['ticket'])
    with ZipFile(io.BytesIO(data)) as z:return json.loads(z.read('manifest.json'))

def test_complete_handoff_request_and_acceptance_are_exported_without_private_authority(world,export_case,publication_case):
    handoffs,sent=start_handoff(world,export_case,publication_case);reviewer=export_case[5]
    accepted=handoffs.respond(reviewer,sent['inspection_id'],sent['id'],expected_version=sent['state_version'],response=HandoffResponse(decision='accepted',request_sha256=sent['request_sha256'],expected_inspection_version=sent['inspection_state_version'],acknowledge_no_capture_transfer=True),idempotency_key='accept-export-source')
    manifest=archive(export_case,complete(export_case,create(export_case,selected=False)))
    records=manifest['support_handoffs'];assert len(records)==1 and records[0]['id']==sent['id']
    assert records[0]['recorded_status']=='accepted' and records[0]['request_sha256']==accepted['request_sha256']
    assert records[0]['decision']['kind']=='accepted' and records[0]['decision']['actor_user_id']==reviewer.member.data['id']
    assert records[0]['historical'] is True and records[0]['machine_approval'] is False and records[0]['capture_transferred'] is False
    assert manifest['support_handoff_state']['accepted_handoff_id']==sent['id'] and manifest['support_handoff_state']['request_count']==1
    text=json.dumps(manifest)
    assert all(x not in text for x in ('cookie#','sender_session_id','actor_session_id','sender_cookie_resource','sender_access_version','handoff-inbox#','pending_eligible'))

@pytest.mark.parametrize('fault',['missing','foreign-record','request-digest','latest-pointer','count','event','accepted-pointer','predecessor'])
def test_incomplete_or_corrupt_handoff_history_never_yields_an_archive(world,export_case,publication_case,fault):
    handoffs,sent=start_handoff(world,export_case,publication_case);repo=world[1]
    if fault=='missing':
        key=handoff_key(sent['inspection_id'],sent['id']);repo.client.delete_item(TableName=repo.tables['state'],Key=repo.key(key))
    elif fault in {'foreign-record','request-digest','predecessor'}:
        key=handoff_key(sent['inspection_id'],sent['id']);row=repo.snapshot((key,))[key]
        data={**row.data,'request_sha256':'f'*64} if fault=='request-digest' else {**row.data,'inspection_id':str(uuid4())}
        if fault=='predecessor':
            request={**row.data['request'],'previous_accepted_handoff_id':str(uuid4())};data={**row.data,'request':request,'request_sha256':digest(request)}
        repo.transact((Write(key,row.revision,data),))
    elif fault in {'latest-pointer','count','accepted-pointer'}:
        key=Key('state','inspection#'+sent['inspection_id']);row=repo.snapshot((key,))[key]
        data={**row.data,'latest_handoff_id':str(uuid4())} if fault=='latest-pointer' else {**row.data,'handoff_count':2}
        if fault=='accepted-pointer':data={**row.data,'accepted_handoff_id':str(uuid4()),'accepted_recipient_user_id':export_case[5].member.data['id']}
        repo.transact((Write(key,row.revision,data),))
    else:
        rows,_=repo.query(prefix='access#',table='events',limit=100)
        row=next(r for r in rows if r.data.get('details',{}).get('handoff_id')==sent['id'] and r.data['kind'].startswith('handoff-request:'))
        repo.transact((Write(row.key,row.revision,{**row.data,'kind':'unrelated-event'}),))
    with pytest.raises((StoreUnavailable,StoreConflict,Denied)):
        archive(export_case,complete(export_case,create(export_case,selected=False)))

def test_support_decision_change_at_ticket_commit_is_atomically_fenced(world,export_case,publication_case,monkeypatch):
    handoffs,sent=start_handoff(world,export_case,publication_case);job=complete(export_case,create(export_case,selected=False));service=export_case[0]
    original=service.access._commit;changed=[]
    def commit(writes,checks=()):
        if not changed and any(w.key.resource.startswith('export-ticket#') and w.expected_revision is None for w in writes):
            changed.append(True)
            handoffs.cancel(export_case[3],sent['inspection_id'],sent['id'],expected_version=1,request=HandoffCancel(request_sha256=sent['request_sha256']),idempotency_key='cancel-before-ticket-commit')
        return original(writes,checks)
    monkeypatch.setattr(service.access,'_commit',commit)
    with pytest.raises(StoreConflict):ticket(export_case,job)
    assert changed
    tickets,_=service.repository.query(prefix='export-ticket#',limit=20)
    assert not tickets,'a changed mutable support source must prevent ticket creation, not just deny later readback'

@pytest.mark.parametrize('outcome',['pending','declined','cancelled'])
def test_unaccepted_historical_support_never_claims_an_accepted_assignment(world,export_case,publication_case,outcome):
    handoffs,sent=start_handoff(world,export_case,publication_case)
    if outcome=='declined':
        handoffs.respond(export_case[5],sent['inspection_id'],sent['id'],expected_version=1,response=HandoffResponse(decision='declined',request_sha256=sent['request_sha256'],expected_inspection_version=sent['inspection_state_version'],acknowledge_no_capture_transfer=True),idempotency_key='decline-source')
    elif outcome=='cancelled':
        handoffs.cancel(export_case[3],sent['inspection_id'],sent['id'],expected_version=1,request=HandoffCancel(request_sha256=sent['request_sha256']),idempotency_key='cancel-source')
    manifest=archive(export_case,complete(export_case,create(export_case,selected=False)))
    assert manifest['support_handoffs'][0]['recorded_status']==outcome
    assert manifest['support_handoff_state']['accepted_handoff_id'] is None and manifest['support_handoff_state']['recorded_recipient_user_id'] is None

def test_expired_pending_request_can_have_complete_explicit_supersession_history(world,export_case,publication_case):
    handoffs,sent=start_handoff(world,export_case,publication_case,lifetime=1000);world[2].value+=1001
    work=world[1].snapshot((Key('state','inspection#'+sent['inspection_id']),))[Key('state','inspection#'+sent['inspection_id'])]
    next_request=handoffs.request(export_case[3],sent['inspection_id'],expected_version=work.revision,request=HandoffRequest(recipient_user_id=export_case[5].member.data['id'],expected_epoch=int(work.data['station_epoch']),reason_code='support_needed',stop_acknowledged=True),idempotency_key='explicit-successor-request')
    manifest=archive(export_case,complete(export_case,create(export_case,selected=False)));records=manifest['support_handoffs']
    assert [r['recorded_status'] for r in records]==['superseded','pending']
    assert records[0]['decision']['successor_id']==next_request['id'] and manifest['support_handoff_state']['request_count']==2

def test_successor_chain_is_complete_for_originator_but_not_disclosed_to_unrelated_reviewers(world,export_case,publication_case):
    handoffs,sent=start_handoff(world,export_case,publication_case)
    accepted=handoffs.respond(export_case[5],sent['inspection_id'],sent['id'],expected_version=1,response=HandoffResponse(decision='accepted',request_sha256=sent['request_sha256'],expected_inspection_version=sent['inspection_state_version'],acknowledge_no_capture_transfer=True),idempotency_key='accept-before-successor')
    next_uid,_,next_reviewer,*_=invite_and_join(world,'support-successor',roles=(Role.REVIEWER,))
    successor=handoffs.request(export_case[5],sent['inspection_id'],expected_version=accepted['inspection_state_version'],request=HandoffRequest(recipient_user_id=next_uid,expected_epoch=sent['request']['station_epoch'],reason_code='support_needed',stop_acknowledged=True),idempotency_key='reviewer-successor')
    handoffs.respond(next_reviewer,sent['inspection_id'],successor['id'],expected_version=1,response=HandoffResponse(decision='accepted',request_sha256=successor['request_sha256'],expected_inspection_version=successor['inspection_state_version'],acknowledge_no_capture_transfer=True),idempotency_key='accept-successor')
    manifest=archive(export_case,complete(export_case,create(export_case,selected=False)))
    assert len(manifest['support_handoffs'])==2 and manifest['support_handoffs'][1]['request']['previous_accepted_handoff_id']==sent['id']
    assert manifest['support_handoff_state']['accepted_handoff_id']==successor['id']
    # The newest recipient may read their request, but has no detail scope for the earlier one.
    job=create(export_case,actor=next_reviewer,selected=False,key='narrow-reviewer-export')
    with pytest.raises(Denied):complete(export_case,job,actor=next_reviewer)

def test_general_review_permission_alone_cannot_export_private_support_history(world,export_case,publication_case):
    start_handoff(world,export_case,publication_case);_,_,outsider,*_=invite_and_join(world,'other-export-reviewer',roles=(Role.REVIEWER,))
    job=create(export_case,actor=outsider,selected=False)
    with pytest.raises(Denied):complete(export_case,job,actor=outsider)
    assert export_case[0].job(outsider,job['id'])['can_issue_ticket'] is False

def test_earliest_support_metadata_expiry_shortens_export_and_ticket_without_renewal(world,export_case,publication_case):
    start_handoff(world,export_case,publication_case,lifetime=1000,retention=1000)
    job=complete(export_case,create(export_case,selected=False));grant=ticket(export_case,job)
    assert 0<job['remaining_ms']<=1000 and 0<grant['remaining_ms']<=1000
    world[2].value+=1001
    with pytest.raises(StoreUnavailable):export_case[0].download(export_case[3],job['id'],grant['ticket'])

def test_changed_pending_source_holds_old_export_but_new_explicit_job_can_record_cancellation(world,export_case,publication_case):
    handoffs,sent=start_handoff(world,export_case,publication_case);job=complete(export_case,create(export_case,selected=False));grant=ticket(export_case,job)
    handoffs.cancel(export_case[3],sent['inspection_id'],sent['id'],expected_version=1,request=HandoffCancel(request_sha256=sent['request_sha256']),idempotency_key='later-cancel')
    assert not export_case[0].job(export_case[3],job['id'])['can_issue_ticket']
    with pytest.raises(StoreConflict):export_case[0].download(export_case[3],job['id'],grant['ticket'])
    fresh=complete(export_case,create(export_case,selected=False,key='fresh-after-cancel'))
    assert archive(export_case,fresh)['support_handoffs'][0]['recorded_status']=='cancelled'

def test_pending_support_change_during_media_read_cannot_deliver_an_old_archive(world,export_case,publication_case,monkeypatch):
    handoffs,sent=start_handoff(world,export_case,publication_case);job=complete(export_case);grant=ticket(export_case,job)
    original=export_case[0].assets.frames.get;changed=[]
    def get(receipt):
        if not changed:
            changed.append(True);handoffs.cancel(export_case[3],sent['inspection_id'],sent['id'],expected_version=1,request=HandoffCancel(request_sha256=sent['request_sha256']),idempotency_key='during-media-read')
        return original(receipt)
    monkeypatch.setattr(export_case[0].assets.frames,'get',get)
    with pytest.raises(StoreConflict):export_case[0].download(export_case[3],job['id'],grant['ticket'])
    assert changed

def test_actual_http_handoff_to_complete_metadata_archive_retains_separate_decisions(world,export_case,publication_case):
    from fastapi.testclient import TestClient
    from proofpack.app import create_app
    from proofpack.auth.http import COOKIE
    from test_handoff_http import post_headers
    service,ident,_,operator,credentials,reviewer,review_credentials,*_=export_case
    handoffs=InspectionHandoffs(publication_case[1].stations,limits=HandoffLimits(4,3600000,60,5000,20,30*86400000))
    app=create_app(access_service=service.access,app_origin='https://proofpack.test',runtime_control=service.runtime,purpose_service=service.purposes,
        asset_service=service.assets,export_service=service,station_service=handoffs.stations,recipe_service=handoffs.stations.recipes,handoff_service=handoffs)
    with TestClient(app,base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE,credentials.cookie)
        work=service.repository.snapshot((Key('state','inspection#'+ident),))[Key('state','inspection#'+ident)]
        created=client.post('/api/v1/inspections/'+ident+'/handoffs',headers=post_headers(credentials,'http-support',work.revision),
            json={'recipient_user_id':reviewer.member.data['id'],'expected_epoch':int(work.data['station_epoch']),'reason_code':'support_needed','stop_acknowledged':True})
        assert created.status_code==201,created.text;sent=created.json()
        client.cookies.set(COOKIE,review_credentials.cookie)
        accepted=client.post('/api/v1/inspections/'+ident+'/handoffs/'+sent['id']+'/respond',headers=post_headers(review_credentials,'http-review',sent['state_version']),
            json={'decision':'accepted','request_sha256':sent['request_sha256'],'expected_inspection_version':sent['inspection_state_version'],'acknowledge_no_capture_transfer':True})
        assert accepted.status_code==200,accepted.text
        assert not accepted.json()['capture_transferred'] and accepted.json()['acknowledged']
        client.cookies.set(COOKIE,credentials.cookie)
        response=client.post('/api/v1/inspections/'+ident+'/exports',headers=post_headers(credentials,'http-support-export',accepted.json()['inspection_state_version']),
            json={'selected_asset_ids':[],'historical_export_acknowledged':True})
        assert response.status_code==201,response.text;job=response.json()
        for step in range(20):
            if job['status']=='completed':break
            response=client.post('/api/v1/jobs/'+job['id']+'/advance',headers=post_headers(credentials,'http-support-step-'+str(step),job['state_version']),json={})
            assert response.status_code==200,response.text;job=response.json()
        assert job['status']=='completed' and job['can_issue_ticket']
        response=client.post('/api/v1/jobs/'+job['id']+'/download-tickets',headers=post_headers(credentials,'http-support-ticket',job['state_version']),json={'historical_export_acknowledged':True})
        assert response.status_code==201,response.text
        downloaded=client.get('/api/v1/jobs/'+job['id']+'/download',headers={'X-Export-Ticket':response.json()['ticket']})
        assert downloaded.status_code==200 and downloaded.headers['cache-control']=='no-store'
        with ZipFile(io.BytesIO(downloaded.content)) as archive_file:
            manifest=json.loads(archive_file.read('manifest.json'))
        assert manifest['support_handoffs'][0]['recorded_status']=='accepted' and manifest['current_approval'] is False
        assert manifest['support_handoff_state']['capture_transferred'] is False and manifest['human_decisions']==[]

def test_rehashed_support_state_must_match_the_actual_inspection_pointers(world,export_case,publication_case):
    import hashlib
    from proofpack.evidence.exports import manifest_key
    from proofpack.calibrations.dependencies import canonical
    _,sent=start_handoff(world,export_case,publication_case)
    service=export_case[0];job=complete(export_case,create(export_case,selected=False));row=service._row(job['id'])
    key=manifest_key(job['id']);stored=service.repository.snapshot((key,))[key]
    value=json.loads(stored.data['json'])
    invented={**value['support_handoff_state'],'accepted_handoff_id':sent['id'],'recorded_recipient_user_id':export_case[5].member.data['id']}
    value['support_handoff_state']=invented;text=canonical(value);signature=hashlib.sha256(text.encode()).hexdigest()
    service.repository.transact((Write(row.key,row.revision,{**row.data,'handoff_state':invented,'manifest_sha256':signature}),
        Write(key,stored.revision,{**stored.data,'json':text,'sha256':signature})))
    view=service.job(export_case[3],job['id'])
    assert view['can_issue_ticket'] is False,'a copied summary cannot invent acceptance absent from the actual inspection'
    with pytest.raises(StoreUnavailable):ticket(export_case,view)
