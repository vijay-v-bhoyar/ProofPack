"""Operational review on actual local CV/database, intercepted S3 and synthetic people."""
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from test_access_lifecycle import world,repository_factory,publication_case,invite_and_join
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied,Role
from proofpack.capture.service import observation_key
from proofpack.evidence.purposes import DataPurposes
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.review.labels import OutcomeLabels,ReviewTuple,LabelRequest,GroundCount,head_key,label_revision_key,ReviewRateLimited
from proofpack.recipes.models import PartClass
from proofpack.runtime.control import DATA
from proofpack.stations.service import inspection_key


@pytest.fixture
def review_case(world,publication_case):
    observations,capture,started,operator,credentials,clock,registry,objects,purpose,observe=publication_case
    before,admission,_=observe('post_pass_removal');action=before['action']
    assert action is not None
    observations.publisher.acknowledge(operator,inspection_id=started['inspection_id'],action_id=action['id'],
        expected_version=before['state_version'],idempotency_key='ack-for-review')
    after,admission_after,_=observe()
    _,reviewer_credentials,reviewer,_,_=invite_and_join(world,'reviewer',roles=(Role.REVIEWER,))
    purposes=DataPurposes(world[0],capture.stations.runtime,max_lifetime_ms=60000)
    labels=OutcomeLabels(purposes,writes_per_minute=8,max_duration_ms=60000,review_validity_ms=30000)
    tuple_=ReviewTuple(before_observation_id=admission['id'],action_id=action['id'],after_observation_id=admission_after['id'])
    return labels,reviewer,reviewer_credentials,tuple_,started,purpose


def request_for(case,*,tuple_=None,**changes):
    service,reviewer,credentials,source,started,purpose=case;source=tuple_ or source
    context=service.context(reviewer,source)
    return LabelRequest(**source.model_dump(),source_context_sha256=context['source_context_sha256'],data_epoch=context['data_epoch'],
        outcome=changes.pop('outcome','resolved'),ground_truth_counts=tuple(GroundCount(part_class=part,count=1) for part in PartClass),
        method='synthetic_fixture',duration_ms=1000,independence_declared=True,note=changes.pop('note','Synthetic fixture manual review'),**changes)


def test_label_create_revision_history_and_retry_preserve_source_and_advance_data(world,review_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case;request=request_for(review_case)
    data=world[1].snapshot((DATA,))[DATA]
    first=service.write(reviewer,request=request,idempotency_key='label')
    assert first['revision']==1 and first['machine_pass'] is False and first['historical'] is True
    assert first['independence_declared'] and first['independence_verified'] is False and first['physical_truth_verified'] is False
    assert first['optional_improvement'] is False and first['source_context']['artifact_sha256']=='a'*64
    assert world[1].snapshot((DATA,))[DATA].data['epoch']==data.data['epoch']+1
    retry=service.write(reviewer,request=request,idempotency_key='label');assert retry['sha256']==first['sha256']
    revised=service.write(reviewer,request=request_for(review_case,outcome='unresolved',note='Correction retained'),ident=first['id'],expected_version=1,idempotency_key='correct')
    assert revised['revision']==2 and revised['previous_sha256']==first['sha256']
    assert service.get(reviewer,first['id'],revision=1)['sha256']==first['sha256']
    with pytest.raises(StoreConflict):service.write(reviewer,request=request_for(review_case),ident=first['id'],expected_version=1,idempotency_key='stale-correction')
    assert service.list(world[5])['labels'][0]['id']==first['id']
    assert 'object_key' not in json.dumps(first) and 'object_version' not in json.dumps(first)


def test_label_write_requires_explicit_reviewer_not_owner_or_operator(world,review_case,publication_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case;request=request_for(review_case)
    for actor in (world[5],publication_case[3]):
        with pytest.raises(Denied):service.write(actor,request=request,idempotency_key='forbidden')
    with pytest.raises(Denied):service.context(publication_case[3],tuple_)


@pytest.mark.parametrize('fault',['withdrawn','expired','read_denied','wrong_hash','source_changed','no_artifact','unacknowledged','after_before','wrong_inspection','context_changed','station_mismatch','calibration_mismatch'])
def test_unavailable_or_wrong_source_cannot_be_labeled(world,review_case,fault):
    service,reviewer,credentials,tuple_,started,purpose=review_case;request=request_for(review_case);repo=world[1]
    observation=repo.snapshot((observation_key(tuple_.before_observation_id),))[observation_key(tuple_.before_observation_id)]
    akey=Key('state','asset#'+observation.data['asset_id']);asset=repo.snapshot((akey,))[akey]
    if fault in {'withdrawn','expired'}:
        row=repo.snapshot((purpose,))[purpose];values={'withdrawn':True} if fault=='withdrawn' else {'expires_at_ms':world[2]()}
    elif fault in {'read_denied','wrong_hash'}:row=asset;values={'read_denied':True} if fault=='read_denied' else {'sha256':'e'*64}
    elif fault=='source_changed':row=observation;values={'source_sha256':'f'*64}
    elif fault=='context_changed':row=observation;values={'context_sha256':'f'*64}
    elif fault=='station_mismatch':row=observation;values={'station_epoch':99}
    elif fault=='calibration_mismatch':
        row=observation;result=json.loads(row.data['result_json']);result['calibration_hash']='e'*64;values={'result_json':json.dumps(result)}
    elif fault=='no_artifact':
        row=repo.snapshot((inspection_key(started['inspection_id']),))[inspection_key(started['inspection_id'])]
        values={**row.data};values.pop('artifact_sha256');repo.transact((Write(row.key,row.revision,values),))
        with pytest.raises(StoreUnavailable):service.write(reviewer,request=request,idempotency_key='fault')
        return
    elif fault=='unacknowledged':row=repo.snapshot((Key('state','action#'+tuple_.action_id),))[Key('state','action#'+tuple_.action_id)];values={'status':'pending'}
    else:
        row=repo.snapshot((observation_key(tuple_.after_observation_id),))[observation_key(tuple_.after_observation_id)]
        values={'sequence':1} if fault=='after_before' else {'inspection_id':str(uuid4())}
    repo.transact((Write(row.key,row.revision,{**row.data,**values}),))
    with pytest.raises((StoreUnavailable,StoreConflict)):service.write(reviewer,request=request,idempotency_key='fault')
    assert repo.query(prefix='label#',limit=20)[0]==[]


def test_changed_data_review_and_revoked_reviewer_cannot_write(world,review_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case;request=request_for(review_case);repo=world[1]
    data=repo.snapshot((DATA,))[DATA];repo.transact((service.purposes.advance(data),))
    with pytest.raises(StoreConflict):service.write(reviewer,request=request,idempotency_key='old-preview')
    request=request_for(review_case)
    world[0].revoke_sessions(world[5],user_id=reviewer.member.data['id'],expected_version=1,idempotency_key='revoke-reviewer')
    with pytest.raises(Denied):service.write(reviewer,request=request,idempotency_key='revoked')


def test_label_quota_exact_retry_and_no_retargeting(world,review_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case;service.writes_per_minute=1
    request=request_for(review_case);label=service.write(reviewer,request=request,idempotency_key='one')
    assert service.write(reviewer,request=request,idempotency_key='one')['id']==label['id']
    with pytest.raises(ReviewRateLimited):service.write(reviewer,request=request_for(review_case),idempotency_key='two')
    single=ReviewTuple(before_observation_id=tuple_.before_observation_id)
    with pytest.raises(Denied):service.write(reviewer,request=request_for(review_case,tuple_=single,outcome='incorrect_finding'),
        ident=label['id'],expected_version=1,idempotency_key='retarget')


def test_label_source_revocation_at_commit_never_publishes(world,review_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case;request=request_for(review_case);repo=world[1];original=repo.transact
    def transact(writes,checks=()):
        if any(write.key.resource.startswith('label#') for write in writes):
            row=repo.snapshot((purpose,))[purpose];original((Write(row.key,row.revision,{**row.data,'withdrawn':True}),))
        return original(writes,checks)
    repo.transact=transact
    with pytest.raises(StoreConflict):service.write(reviewer,request=request,idempotency_key='raced')
    assert repo.query(prefix='label#',limit=20)[0]==[]


def test_label_http_scope_body_limits_and_client_certification_denials(world,review_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,purpose_service=service.purposes,label_service=service)
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.get('/api/v1/labels').status_code==401
        client.cookies.set(COOKIE,credentials.cookie);headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-label'}
        body=request_for(review_case).model_dump(mode='json')
        assert client.post('/api/v1/labels',json=body,headers={'Idempotency-Key':'missing-csrf'}).status_code==403
        assert client.post('/api/v1/labels',content=b'x'*8193,headers=headers).status_code==413
        assert client.post('/api/v1/labels',json={**body,'independence_verified':True},headers=headers).status_code==400
        result=client.post('/api/v1/labels',json=body,headers=headers);assert result.status_code==201,result.text
        ident=result.json()['id'];assert client.get('/api/v1/labels/'+ident).json()['machine_pass'] is False
        client.cookies.set(COOKIE,world[4].cookie)
        assert client.get('/api/v1/labels/'+ident).status_code==200
        assert client.post('/api/v1/labels',json=body,headers={**headers,'X-CSRF-Token':world[4].csrf}).status_code==403


def test_concurrent_identical_label_creations_return_the_same_committed_revision(world,review_case):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    service,reviewer,credentials,tuple_,started,purpose=review_case;request=request_for(review_case)
    repo=world[1];original=repo.transact;barrier=Barrier(2)
    def transact(writes,checks=()):
        if any(write.key.resource.startswith('label#') for write in writes):barrier.wait(timeout=10)
        return original(writes,checks)
    repo.transact=transact
    with ThreadPoolExecutor(max_workers=2) as executor:
        calls=[executor.submit(service.write,reviewer,request=request,idempotency_key='concurrent') for _ in range(2)]
        results=[call.result(timeout=20) for call in calls]
    assert results[0]['id']==results[1]['id'] and results[0]['sha256']==results[1]['sha256']
    assert len(repo.query(prefix='label#',limit=20)[0])==1


def test_withdrawal_denies_saved_label_and_hides_it_from_current_list(world,review_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case
    label=service.write(reviewer,request=request_for(review_case),idempotency_key='before-withdrawal')
    repo=world[1];row=repo.snapshot((purpose,))[purpose];repo.transact((Write(row.key,row.revision,{**row.data,'withdrawn':True}),))
    with pytest.raises(StoreUnavailable):service.get(reviewer,label['id'])
    assert service.list(reviewer)['labels']==[]
    assert repo.snapshot((label_revision_key(label['id'],1),))[label_revision_key(label['id'],1)] is not None


def test_closed_inspection_can_be_reviewed_without_relying_on_current_approval(world,review_case,publication_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case;stations=publication_case[1].stations
    key=inspection_key(started['inspection_id']);work=world[1].snapshot((key,))[key]
    stations.close(publication_case[3],inspection_id=started['inspection_id'],expected_version=work.revision,
        expected_epoch=int(work.data['station_epoch']),reason='manual check complete',disposition='human_accepted',idempotency_key='close-before-review')
    label=service.write(reviewer,request=request_for(review_case),idempotency_key='historical-review')
    assert label['historical'] and label['machine_pass'] is False
    assert world[1].snapshot((key,))[key].data['state']=='CLOSED'


def test_missing_previous_revision_denies_lineage_instead_of_replacing_history(world,review_case):
    service,reviewer,credentials,tuple_,started,purpose=review_case;first=service.write(reviewer,request=request_for(review_case),idempotency_key='first')
    second=service.write(reviewer,request=request_for(review_case,note='Corrected count judgment'),ident=first['id'],expected_version=1,idempotency_key='second')
    key=label_revision_key(first['id'],1);repo=world[1];repo.client.delete_item(TableName=repo.tables[key.table],Key=repo.key(key))
    with pytest.raises(StoreUnavailable):service.get(reviewer,second['id'])
