from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Lock
from uuid import uuid4
import json
import pytest
from fastapi.testclient import TestClient
from test_access_lifecycle import world, repository_factory, invite_and_join, proof
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Denied, Role
from proofpack.evidence.repository import Key, Write, StoreConflict, StoreUnavailable
from proofpack.planner.candidates import PolicyCandidates, PolicyCatalogConfig, PolicyDraft, PolicyLimited, head_key, revision_key
from proofpack.runtime.control import RuntimeControl, DATA
from proofpack.stations.service import POLICY


def draft(name='Kit priority',priority=('SEPARATE_REGION','PLACE_FLAT','RECAPTURE')):
    return PolicyDraft.model_validate_json(json.dumps({'name':name,'algorithm':'reason_priority_v1','priority':priority}))


@pytest.fixture
def policies(world):
    access=world[0];runtime=RuntimeControl(access,instance_id=str(uuid4()),artifact_sha256='a'*64,controls_sha256='b'*64,environment='synthetic_demo');runtime.start()
    _,credentials,reviewer,*_=invite_and_join(world,'policy-reviewer',roles=(Role.REVIEWER,))
    return PolicyCandidates(access,runtime,PolicyCatalogConfig(100,120,100)),reviewer,credentials


def test_durable_revision_history_and_no_activation_or_data_effect(world,policies):
    service,actor,_=policies;before=world[1].snapshot((DATA,POLICY))
    first=service.write(actor,request=draft(),idempotency_key='new-policy')
    assert first['status']=='draft' and first['evaluation_status']=='NOT_VERIFIED' and first['promotion_available'] is False
    changed=service.write(actor,request=draft('Changed',('PLACE_FLAT','RECAPTURE','SEPARATE_REGION')),ident=first['id'],expected_version=1,idempotency_key='revision')
    assert changed['revision']==2 and changed['state_version']==2 and changed['previous_sha256']==first['revision_sha256']
    old=service.get(actor,first['id'],revision=1)
    assert old['revision_sha256']==first['revision_sha256'] and old['can_revise'] is False
    assert service.get(world[5],first['id'])['spec']==changed['spec']
    assert world[1].snapshot((DATA,POLICY))==before
    assert len(world[1].query(prefix='policy-catalog#',limit=20)[0])==1


def test_immutable_retry_returns_original_revision_and_changed_intent_conflicts(policies):
    service,actor,_=policies;first=service.write(actor,request=draft(),idempotency_key='once')
    service.write(actor,request=draft('Second'),ident=first['id'],expected_version=1,idempotency_key='second')
    replay=service.write(actor,request=draft(),idempotency_key='once')
    assert replay['id']==first['id'] and replay['revision']==1 and replay['latest_revision']==2
    with pytest.raises(StoreConflict):service.write(actor,request=draft('Altered'),idempotency_key='once')
    with pytest.raises(StoreConflict):service.write(actor,request=draft('Stale'),ident=first['id'],expected_version=1,idempotency_key='stale')


def test_committed_write_with_lost_response_reuses_the_original_record(world,policies,monkeypatch):
    service,actor,_=policies;original=service.access._commit;lost=False
    def commit(writes,checks=()):
        nonlocal lost
        value=original(writes,checks)
        if not lost and any(w.key.resource.startswith('policy-candidate#') for w in writes):
            lost=True;raise StoreUnavailable('synthetic response lost after commit')
        return value
    monkeypatch.setattr(service.access,'_commit',commit)
    with pytest.raises(StoreUnavailable):service.write(actor,request=draft(),idempotency_key='lost')
    retry=service.write(actor,request=draft(),idempotency_key='lost')
    assert retry['revision']==1 and lost
    assert len(world[1].query(prefix='policy-catalog#',limit=20)[0])==1


def test_new_session_does_not_reset_write_allowance(world,policies):
    base,actor,_=policies;service=PolicyCandidates(base.access,base.runtime,replace(base.config,writes_per_minute=1))
    service.write(actor,request=draft(),idempotency_key='first-session')
    credentials=world[0].login(proof(world[2],'policy-reviewer',mfa=False));new_actor=world[0].resolve(credentials.cookie)
    with pytest.raises(PolicyLimited):service.write(new_actor,request=draft(),idempotency_key='new-session')


def test_expired_session_at_final_write_fence_cannot_create_candidate(world,policies,monkeypatch):
    service,actor,_=policies;original=service.access._record
    def record(*args,**kwargs):
        checkpoint=kwargs['before_commit']
        def expire():world[2].value=int(actor.session.data['expires_at_ms']);checkpoint()
        return original(*args,**{**kwargs,'before_commit':expire})
    monkeypatch.setattr(service.access,'_record',record)
    with pytest.raises(Denied):service.write(actor,request=draft(),idempotency_key='deadline')
    assert world[1].query(prefix='policy-catalog#',limit=20)[0]==[]


def test_owner_operator_foreign_and_revoked_scope(world,policies,repository_factory):
    service,actor,_=policies;first=service.write(actor,request=draft(),idempotency_key='scope')
    assert service.get(world[5],first['id'])['can_revise'] is False
    with pytest.raises(Denied):service.write(world[5],request=draft(),idempotency_key='owner-write')
    _,_,operator,*_=invite_and_join(world,'only-operator',roles=(Role.OPERATOR,))
    with pytest.raises(Denied):service.get(operator,first['id'])
    with pytest.raises(Denied):service.list(operator)
    other=repository_factory();foreign=replace(actor,cookie=actor.cookie)
    # The record is absent in a separate deployment, even under the same tables.
    from proofpack.auth.service import AccessService
    access=AccessService(other,replace(world[0].config,deployment=other.deployment),clock_ms=world[2])
    runtime=RuntimeControl(access,instance_id=str(uuid4()),artifact_sha256='a'*64,controls_sha256='b'*64,environment='synthetic_demo');runtime.start()
    with pytest.raises(Denied):PolicyCandidates(access,runtime,service.config).get(foreign,first['id'])
    world[0].change_access(world[5],user_id=actor.member.data['id'],roles=(Role.REVIEWER,),enabled=False,expected_version=1,idempotency_key='disable-reviewer')
    with pytest.raises(Denied):service.get(actor,first['id'])
    with pytest.raises(Denied):service.write(actor,request=draft(),idempotency_key='after-revoke')


@pytest.mark.parametrize('field',['spec','sha256','previous_sha256'])
def test_corrupt_immutable_revision_is_not_delivered(world,policies,field):
    service,actor,_=policies;first=service.write(actor,request=draft(),idempotency_key='corrupt')
    key=revision_key(first['id'],1);row=world[1].snapshot((key,))[key]
    data={**row.data,field: {'name':'forged'} if field=='spec' else '0'*64}
    world[1].transact((Write(key,row.revision,data),))
    with pytest.raises(StoreUnavailable):service.get(actor,first['id'])
    with pytest.raises(StoreUnavailable):service.list(actor)


def test_catalog_pages_and_durable_bounds(policies,world):
    base,actor,_=policies;service=PolicyCandidates(base.access,base.runtime,replace(base.config,max_revisions=1))
    ids={service.write(actor,request=draft('Policy '+str(i)),idempotency_key='page-'+str(i))['id'] for i in range(3)}
    page=service.list(actor,limit=2);second=service.list(actor,limit=2,cursor=page['next_cursor'])
    assert {p['id'] for p in page['policies']+second['policies']}==ids and second['next_cursor'] is None
    assert all(p['can_revise'] is False for p in page['policies'])
    with pytest.raises(PolicyLimited):service.write(actor,request=draft('No revision'),ident=next(iter(ids)),expected_version=1,idempotency_key='max')
    with pytest.raises(ValueError):service.list(actor,limit=21)
    limited=PolicyCandidates(base.access,base.runtime,replace(base.config,writes_per_minute=1))
    with pytest.raises(PolicyLimited):limited.write(actor,request=draft(),idempotency_key='rate')


def test_concurrent_revision_cannot_overwrite_another_author(world,policies,monkeypatch):
    service,actor,_=policies;first=service.write(actor,request=draft(),idempotency_key='race')
    original=world[1].transact;barrier=Barrier(2)
    def commit(writes,checks=()):
        if any(w.key==head_key(first['id']) for w in writes):barrier.wait(timeout=10)
        return original(writes,checks)
    monkeypatch.setattr(world[1],'transact',commit)
    def write(n):
        try:return service.write(actor,request=draft('Attempt '+str(n)),ident=first['id'],expected_version=1,idempotency_key='race-'+str(n))
        except StoreConflict:return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(write,range(2)))
    assert sum(r is not None for r in results)==1
    assert service.get(actor,first['id'])['revision']==2


def test_concurrent_create_retry_returns_the_original_idempotent_identifier(world,policies,monkeypatch):
    service,actor,_=policies;original=world[1].transact;read=service.get;barrier=Barrier(2);lock=Lock()
    def commit(writes,checks=()):
        if any(w.key.resource.startswith('policy-candidate#') for w in writes):barrier.wait(timeout=10)
        return original(writes,checks)
    def sequential_read(*args,**kwargs):
        # Isolate duplicate-create resolution from the independent read-quota CAS.
        with lock:return read(*args,**kwargs)
    monkeypatch.setattr(world[1],'transact',commit);monkeypatch.setattr(service,'get',sequential_read)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:service.write(actor,request=draft(),idempotency_key='same-concurrent-intent'),range(2)))
    assert results[0]['id']==results[1]['id'] and results[0]['revision']==results[1]['revision']==1
    assert len(world[1].query(prefix='policy-catalog#',limit=20)[0])==1


@pytest.mark.parametrize('change',['runtime','role','session_expiry','owner_mfa'])
def test_final_delivery_rechecks_after_audit(world,policies,monkeypatch,change):
    service,actor,_=policies;first=service.write(actor,request=draft(),idempotency_key='late-read')
    if change=='owner_mfa':actor=world[5]
    original=world[1].transact;triggered=False
    def commit(writes,checks=()):
        nonlocal triggered
        value=original(writes,checks)
        if not triggered and any(w.key.resource.startswith('policy-read#') for w in writes):
            triggered=True
            if change=='runtime':
                newer=RuntimeControl(world[0],instance_id=str(uuid4()),artifact_sha256='a'*64,controls_sha256='b'*64,environment='synthetic_demo');newer.start()
            elif change=='role':world[0].change_access(world[5],user_id=actor.member.data['id'],roles=(Role.OPERATOR,),enabled=True,expected_version=1,idempotency_key='late-role')
            elif change=='session_expiry':world[2].value=int(actor.session.data['expires_at_ms'])
            else:world[2].value+=600001
        return value
    monkeypatch.setattr(world[1],'transact',commit)
    with pytest.raises((Denied,StoreConflict,StoreUnavailable)):service.get(actor,first['id'])
    assert triggered


def test_host_binding_changes_hold_revision_but_preserve_historical_metadata(policies):
    service,actor,_=policies;first=service.write(actor,request=draft(),idempotency_key='binding')
    changed=PolicyCandidates(service.access,service.runtime,replace(service.config,max_revisions=99))
    assert changed.get(actor,first['id'])['can_revise'] is False
    with pytest.raises(StoreConflict):changed.write(actor,request=draft('Changed'),ident=first['id'],expected_version=1,idempotency_key='binding-revision')


def test_http_body_csrf_scope_and_no_promotion(world,policies):
    service,actor,credentials=policies;app=create_app(access_service=world[0],app_origin='https://proofpack.test',runtime_control=service.runtime,policy_service=service)
    headers={'Origin':'https://proofpack.test','X-CSRF-Token':credentials.csrf,'Idempotency-Key':'http-create'}
    with TestClient(app,base_url='https://proofpack.test',cookies={COOKIE:credentials.cookie}) as client:
        body=draft().model_dump(mode='json');response=client.post('/api/v1/policies',json=body,headers=headers)
        assert response.status_code==201 and response.json()['revision']==1
        ident=response.json()['id']
        assert client.get('/api/v1/policies/'+ident).status_code==200
        assert client.post('/api/v1/policies/'+ident+'/revisions',json=body,headers={**headers,'If-Match':'1','Idempotency-Key':'http-revision'}).status_code==201
        assert client.post('/api/v1/policies',json={**body,'approved':True},headers=headers).status_code==400
        assert len(service.list(actor)['policies'])==1
        assert client.post('/api/v1/policies',json={'padding':'x'*9000},headers=headers).status_code==413
        assert client.post('/api/v1/policies',json=body,headers={**headers,'Origin':'https://foreign.test'}).status_code==403
        before=world[1].snapshot((POLICY,))
        response=client.post('/api/v1/policies/'+ident+'/promote',json={},headers=headers)
        assert response.status_code==503 and response.json()['code']=='DEPENDENCY_UNAVAILABLE'
        assert world[1].snapshot((POLICY,))==before
        assert world[1].query(prefix='policy-activation#',limit=20)[0]==[]
