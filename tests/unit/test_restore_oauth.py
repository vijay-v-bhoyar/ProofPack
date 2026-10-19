"""Real OAuth source writers on a synthetic protected store; no provider proof."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from urllib.parse import parse_qs, urlsplit
import pytest

from restore_consumer_model import auth_world
from proofpack.auth.oauth import OAuthConfig, OAuthFlows, AuthRateLimited
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import DynamoRepository, Key, StoreUnavailable
from proofpack.evidence.restore_fence import RestoreDataFence


def setup():
    access,fence,client,identities,proof,clock=auth_world()
    config=OAuthConfig(access.repository.deployment,'https://provider.example.test','syntheticclient',
        'https://proofpack.example.test/api/v1/auth/callback',b'z'*32)
    return access.repository,fence,client,identities,clock,config


def flows(repo,clock,config):
    return OAuthFlows(repo,config,clock_ms=lambda:clock[0])


def parts(started):
    return parse_qs(urlsplit(started.authorization_url).query)['state'][0],started.browser_cookie


def row(repo,client,state):
    key=Key('state','oauth-flow#'+hashlib.sha256(state.encode()).hexdigest())
    return client.items[client.identity(repo.tables['state'],repo.key(key))]


def rotate(repo,fence,client,identities):
    raw=client.items[identities[2]];body=json.loads(raw['body']['S'])
    body['runtime_generation_sha256']='d'*64
    encode=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)
    digest=hashlib.sha256(encode(['restored-data-release/v1',repo.deployment,fence.config.journal_arn,body]).encode()).hexdigest()
    raw['body']['S']=encode(body);raw['sha256']['S']=digest
    current=RestoreDataFence(client,deployment=repo.deployment,state_table=repo.tables['state'],events_table=repo.tables['events'],
        config=replace(fence.config,release_sha256=digest),tick=lambda:1)
    return DynamoRepository(client,deployment=repo.deployment,state_table=repo.tables['state'],events_table=repo.tables['events'],data_fence=current)


def test_fenced_constructor_has_no_reads_and_current_generation_flow_keeps_closed_shape_and_mfa():
    repo,fence,client,ids,clock,config=setup();client.calls.clear()
    service=flows(repo,clock,config)
    assert client.calls==[]
    started=service.begin(invitation_id='00000000-0000-4000-8000-000000000001',require_mfa=True)
    state,cookie=parts(started);data=row(repo,client,state)['data']['M']
    assert data['configuration']['S']!=service.binding
    assert set(data)=={'browser_hash','configuration','created_at_ms','expires_at_ms','require_mfa','invitation_id','status'}
    material=service.consume(state=state,browser_cookie=cookie)
    assert material.require_mfa is True
    assert material.invitation_id=='00000000-0000-4000-8000-000000000001'
    assert material.expires_at_ms==started.expires_at_ms
    with pytest.raises(Denied):service.consume(state=state,browser_cookie=cookie)


def test_new_release_rejects_restored_flow_without_consuming_then_allows_fresh_flow():
    repo,fence,client,ids,clock,config=setup();old=flows(repo,clock,config)
    state,cookie=parts(old.begin());current_repo=rotate(repo,fence,client,ids);current=flows(current_repo,clock,config)
    before=deepcopy(client.items)
    with pytest.raises(Denied):current.consume(state=state,browser_cookie=cookie)
    assert client.items==before and row(repo,client,state)['data']['M']['status']=={'S':'pending'}
    with pytest.raises(StoreUnavailable):old.begin()
    fresh_state,fresh_cookie=parts(current.begin())
    assert current.consume(state=fresh_state,browser_cookie=fresh_cookie).require_mfa is False


@pytest.mark.parametrize('protected_first',[False,True],ids=['legacy-to-protected','protected-to-unfenced'])
def test_pending_flow_cannot_cross_unfenced_and_protected_consumers(protected_first):
    repo,fence,client,ids,clock,config=setup()
    plain=DynamoRepository(client,deployment=repo.deployment,state_table=repo.tables['state'],events_table=repo.tables['events'])
    writer,reader=(repo,plain) if protected_first else (plain,repo)
    state,cookie=parts(flows(writer,clock,config).begin())
    before=deepcopy(client.items)
    with pytest.raises(Denied):flows(reader,clock,config).consume(state=state,browser_cookie=cookie)
    assert client.items==before


@pytest.mark.parametrize('operation',['begin','consume'])
def test_missing_release_holds_before_any_flow_write(operation):
    repo,fence,client,ids,clock,config=setup();service=flows(repo,clock,config)
    state,cookie=parts(service.begin());del client.items[ids[2]];before=deepcopy(client.items);client.calls.clear()
    with pytest.raises(StoreUnavailable):
        if operation=='begin':service.begin()
        else:service.consume(state=state,browser_cookie=cookie)
    assert client.items==before
    assert not any(name=='transact_write_items' for name,_ in client.calls)


@pytest.mark.parametrize('operation',['begin','consume'])
def test_release_revoked_after_commit_withholds_redirect_or_exchange_material(operation):
    repo,fence,client,ids,clock,config=setup();service=flows(repo,clock,config)
    state,cookie=parts(service.begin());original=client.transact_write_items;commits=[]
    def revoke(**kwargs):
        result=original(**kwargs);commits.append(deepcopy(kwargs));client.items.pop(ids[2]);return result
    client.transact_write_items=revoke
    with pytest.raises(StoreUnavailable):
        if operation=='begin':service.begin()
        else:service.consume(state=state,browser_cookie=cookie)
    assert len(commits)==1
    if operation=='consume':
        assert row(repo,client,state)['data']['M']['status']=={'S':'consumed'}
    assert client.items.get(ids[2]) is None


@pytest.mark.parametrize('operation',['begin','consume'])
def test_protected_commit_condition_cannot_be_replaced_by_configuration_precheck(operation):
    repo,fence,client,ids,clock,config=setup();service=flows(repo,clock,config)
    state,cookie=parts(service.begin());before=deepcopy(client.items)
    client.before_commit=lambda:client.items.pop(ids[2],None)
    with pytest.raises((Denied,AuthRateLimited)):
        if operation=='begin':service.begin()
        else:service.consume(state=state,browser_cookie=cookie)
    before.pop(ids[2])
    assert client.items==before
