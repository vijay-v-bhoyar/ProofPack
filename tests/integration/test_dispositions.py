"""Local human-decision transactions; no real operator or independent truth."""
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_access_lifecycle import world,repository_factory,station_world,acquire_station,start_station,invite_and_join
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied,Role
from proofpack.evidence.repository import Key,Write,StoreConflict,StoreUnavailable
from proofpack.stations.service import inspection_key


@pytest.fixture
def decision_case(world,recipe):
    stations,enrolled,created,operator,credentials,content=station_world(world,recipe)
    acquire_station(stations,operator,enrolled[0]);started=start_station(stations,operator,enrolled[0],created)
    args={'inspection_id':started['inspection_id'],'expected_version':1,'expected_epoch':1,'disposition':'rework',
          'reason':'Manual check found a missing part','human_check_confirmed':False,'idempotency_key':'manual-decision'}
    return stations,operator,credentials,args


def test_append_replay_correction_and_close_keep_separate_immutable_human_history(world,decision_case):
    service,operator,credentials,args=decision_case;repo=world[1];key=inspection_key(args['inspection_id']);before=repo.snapshot((key,))[key]
    assert service.latest_disposition(operator,args['inspection_id'])['decision'] is None
    first=service.record_disposition(operator,**args);after=repo.snapshot((key,))[key]
    assert first['decision']['machine_approval'] is False and first['decision']['independent_truth_verified'] is False
    assert {k:v for k,v in after.data.items() if k not in {'disposition','latest_disposition_id'}}=={k:v for k,v in before.data.items() if k!='disposition'}
    assert service.record_disposition(operator,**args)==first
    second=service.record_disposition(operator,**{**args,'expected_version':2,'disposition':'human_accepted','human_check_confirmed':True,'idempotency_key':'correction'})
    assert second['decision']['previous_id']==first['id']
    service.close(operator,inspection_id=args['inspection_id'],expected_version=3,expected_epoch=1,reason='Manual decision completed',disposition='cancelled',idempotency_key='close-after-human')
    current=service.latest_disposition(world[5],args['inspection_id'])
    assert current['decision']==second['decision'] and current['current_disposition']=='cancelled'
    assert service.record_disposition(operator,**args)==first
    old=repo.snapshot((Key('state','human-disposition#'+args['inspection_id']+'#'+first['id']),))
    assert next(iter(old.values())).revision==1
    with pytest.raises(StoreConflict):service.record_disposition(operator,**{**args,'expected_version':4,'idempotency_key':'after-close'})


@pytest.mark.parametrize('field,value',[('disposition','passed'),('disposition',None),('reason','  '),('reason','x'*121),('human_check_confirmed',1)])
def test_invalid_human_decisions_never_create_a_record(world,decision_case,field,value):
    service,operator,credentials,args=decision_case
    with pytest.raises(ValueError):service.record_disposition(operator,**{**args,field:value})
    assert service.latest_disposition(operator,args['inspection_id'])['decision'] is None


def test_acceptance_needs_manual_check_and_reused_intent_cannot_change_decision(world,decision_case):
    service,operator,credentials,args=decision_case
    with pytest.raises(ValueError):service.record_disposition(operator,**{**args,'disposition':'human_accepted'})
    service.record_disposition(operator,**args)
    with pytest.raises(StoreConflict):service.record_disposition(operator,**{**args,'reason':'Changed decision body'})


@pytest.mark.parametrize('fault',['version','epoch','pending','closed','session','foreign'])
def test_stale_pending_closed_and_foreign_writes_fail(world,decision_case,fault):
    service,operator,credentials,args=decision_case;repo=world[1];key=inspection_key(args['inspection_id']);work=repo.snapshot((key,))[key]
    if fault=='version':args['expected_version']=99
    elif fault=='epoch':args['expected_epoch']=99
    elif fault in {'pending','closed'}:
        repo.transact((Write(key,work.revision,{**work.data,**({'pending_sequence':1} if fault=='pending' else {'state':'CLOSED'})}),));args['expected_version']=2
    elif fault=='session':world[0].logout(credentials.cookie,credentials.csrf)
    else:_,_,operator,_,_=invite_and_join(world,'foreign-decision')
    with pytest.raises((Denied,StoreConflict)):service.record_disposition(operator,**args)


def test_owner_alone_cannot_write_reviewer_reads_and_other_operator_cannot(world,decision_case):
    service,operator,credentials,args=decision_case
    with pytest.raises(Denied):service.record_disposition(world[5],**args)
    service.record_disposition(operator,**args)
    _,_,reviewer,_,_=invite_and_join(world,'decision-reviewer',roles=(Role.REVIEWER,))
    assert service.latest_disposition(reviewer,args['inspection_id'])['decision']['disposition']=='rework'
    _,_,other,_,_=invite_and_join(world,'decision-other')
    with pytest.raises(Denied):service.latest_disposition(other,args['inspection_id'])


@pytest.mark.parametrize('fault',['missing','corrupt','pointer'])
def test_readback_rejects_missing_corrupt_and_rebound_records(world,decision_case,fault):
    service,operator,credentials,args=decision_case;result=service.record_disposition(operator,**args);repo=world[1]
    key=inspection_key(args['inspection_id']);work=repo.snapshot((key,))[key]
    if fault=='missing':repo.transact((Write(key,work.revision,{**work.data,'latest_disposition_id':str(uuid4())}),))
    else:
        key=Key('state','human-disposition#'+args['inspection_id']+'#'+result['id']);row=repo.snapshot((key,))[key]
        repo.transact((Write(key,row.revision,{**row.data,('reason' if fault=='corrupt' else 'inspection_id'):('Changed' if fault=='corrupt' else str(uuid4()))}),))
    with pytest.raises(StoreUnavailable):service.latest_disposition(operator,args['inspection_id'])


def test_manual_handling_is_available_while_runtime_disabled(world,decision_case):
    service,operator,credentials,args=decision_case
    service.runtime.disable(world[5],expected_version=3,reason='Safety stop',idempotency_key='manual-runtime-stop')
    assert service.record_disposition(operator,**args)['decision']['disposition']=='rework'
    assert service.inspection(operator,args['inspection_id'])['effective_state']=='INVALIDATED'


def test_http_requires_session_csrf_version_and_strict_confirmation(world,decision_case):
    service,operator,credentials,args=decision_case;url='/api/v1/inspections/'+args['inspection_id']+'/dispositions'
    app=create_app(access_service=world[0],app_origin='https://proofpack.test',station_service=service,runtime_control=service.runtime,recipe_service=service.recipes)
    body={k:v for k,v in args.items() if k not in {'inspection_id','expected_version','idempotency_key'}}
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert client.post(url,json=body).status_code==401
        client.cookies.set(COOKIE,credentials.cookie)
        assert client.post(url,json=body,headers={'Origin':'https://proofpack.test','Idempotency-Key':'no-csrf','If-Match':'1'}).status_code==403
        headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-decision','If-Match':'1'}
        assert client.post(url,json={**body,'human_check_confirmed':1},headers=headers).status_code==400
        response=client.post(url,json=body,headers=headers);assert response.status_code==201
        assert response.headers['cache-control']=='no-store'
        read=client.get(url+'/latest');assert read.status_code==200 and read.json()['decision']['id']==response.json()['id']
        assert read.json()['machine_approval'] is False


def test_concurrent_duplicate_creates_one_human_record(world,decision_case):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    service,operator,credentials,args=decision_case;gate=Barrier(2)
    def submit():
        gate.wait(timeout=5)
        return service.record_disposition(operator,**args)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:submit(),range(2)))
    assert results[0]==results[1]
    assert world[1].snapshot((inspection_key(args['inspection_id']),))[inspection_key(args['inspection_id'])].revision==2


def test_role_loss_at_commit_cannot_record_human_handling(world,decision_case):
    from proofpack.auth.service import user_key
    service,operator,credentials,args=decision_case;repo=world[1];original=repo.transact;changed=False
    def transact(writes,*rest,**kwargs):
        nonlocal changed
        if not changed and any(w.key.resource.startswith('human-disposition#') for w in writes):
            changed=True;key=user_key(operator.member.data['id']);row=repo.snapshot((key,))[key]
            original((Write(key,row.revision,{**row.data,'enabled':False,'access_version':row.data['access_version']+1}),))
        return original(writes,*rest,**kwargs)
    repo.transact=transact
    with pytest.raises((Denied,StoreConflict)):service.record_disposition(operator,**args)
    work=repo.snapshot((inspection_key(args['inspection_id']),))[inspection_key(args['inspection_id'])]
    assert work.data.get('latest_disposition_id') is None


def test_revoked_session_during_readback_cannot_return_record(world,decision_case):
    service,operator,credentials,args=decision_case;service.record_disposition(operator,**args)
    repo=world[1];original=repo.snapshot;changed=False
    def snapshot(keys):
        nonlocal changed
        if not changed and len(keys)>2 and any(k.resource.startswith('human-disposition#') for k in keys):
            changed=True;world[0].logout(credentials.cookie,credentials.csrf)
        return original(keys)
    repo.snapshot=snapshot
    with pytest.raises((Denied,StoreConflict)):service.latest_disposition(operator,args['inspection_id'])


def test_lost_prior_human_history_cannot_be_silently_repaired_by_an_append(world,decision_case):
    service,operator,credentials,args=decision_case;service.record_disposition(operator,**args)
    repo=world[1];key=inspection_key(args['inspection_id']);work=repo.snapshot((key,))[key]
    repo.transact((Write(key,work.revision,{**work.data,'latest_disposition_id':str(uuid4())}),))
    with pytest.raises(StoreUnavailable):service.record_disposition(operator,**{**args,'expected_version':3,'idempotency_key':'broken-lineage'})


def test_station_control_allowance_applies_to_new_human_decisions(world,decision_case):
    from proofpack.stations.service import StationRateLimited
    service,operator,credentials,args=decision_case;repo=world[1];work=repo.snapshot((inspection_key(args['inspection_id']),))[inspection_key(args['inspection_id'])]
    key=Key('state','station-quota#'+work.data['station_id']);row=repo.snapshot((key,))[key]
    repo.transact((Write(key,row.revision,{'second':world[2]()//1000,'count':8}),))
    with pytest.raises(StationRateLimited):service.record_disposition(operator,**args)


def test_lost_confirmation_after_actual_commit_replays_one_immutable_effect(world,decision_case):
    service,operator,credentials,args=decision_case;access=world[0];original=access._record;lost=False
    def record(*positional,**kwargs):
        nonlocal lost
        result=original(*positional,**kwargs)
        if not lost and positional[1].startswith('inspection-disposition:'):
            lost=True;raise StoreUnavailable('Simulated lost confirmation after durable commit')
        return result
    access._record=record
    with pytest.raises(StoreUnavailable):service.record_disposition(operator,**args)
    result=service.record_disposition(operator,**args)
    assert service.latest_disposition(operator,args['inspection_id'])['decision']['id']==result['id']
    assert world[1].snapshot((inspection_key(args['inspection_id']),))[inspection_key(args['inspection_id'])].revision==2


def test_combined_owner_operator_keeps_own_operator_read_after_owner_mfa_ages(world,recipe):
    service,enrolled,created,operator,credentials,content=station_world(world,recipe)
    _,_,combined,_,_=invite_and_join(world,'combined-human',roles=(Role.OWNER,Role.OPERATOR),mfa=True)
    acquire_station(service,combined,enrolled[0]);started=start_station(service,combined,enrolled[0],created)
    record=service.record_disposition(combined,inspection_id=started['inspection_id'],expected_version=1,expected_epoch=1,
        disposition='rework',reason='Actual human handling',human_check_confirmed=False,idempotency_key='combined-human')
    world[2].value+=600001
    assert service.latest_disposition(combined,started['inspection_id'])['decision']['id']==record['id']
    with pytest.raises(Denied):service.latest_disposition(world[5],started['inspection_id'])
