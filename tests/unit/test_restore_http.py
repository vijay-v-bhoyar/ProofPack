"""ASGI restore delivery/ownership on synthetic protected state, no browser proof."""
import asyncio
from copy import deepcopy
from threading import Event
import pytest

from test_restore_fence import world
from proofpack.evidence.restore_http import RestoreDataBoundary
from proofpack.runtime.ownership import ResourceOwner


def scope(path='/',method='GET'):
    return {'type':'http','method':method,'path':path,'raw_path':path.encode(), 'headers':[],
            'query_string':b'', 'extensions':{'http.response.pathsend':{},'http.response.zerocopysend':{}}}


async def call(boundary, request):
    messages=[]
    async def receive(): return {'type':'http.request','body':b'','more_body':False}
    async def send(message): messages.append(deepcopy(message))
    await boundary(request,receive,send)
    return messages


def setup(app,max_active=2):
    repo,fence,client,identities=world();owner=ResourceOwner()
    return RestoreDataBoundary(app,fence=fence,resource_owner=owner,max_active=max_active),client,identities,owner


@pytest.mark.parametrize('path,method',[('/','GET'),('/assets/app.js','GET'),('/api/v1/me','GET'),
    ('/api/v1/auth/login','GET'),('/api/v1/auth/callback','GET'),('/api/v1/auth/logout','POST'),
    ('/health/ready','GET'),('/api/v1/privacy/metadata-requests/context','HEAD')])
def test_missing_release_denies_before_data_auth_or_static_handler(path,method):
    reached=[]
    async def forbidden(*args):reached.append(True);pytest.fail('held release reached downstream handler')
    boundary,client,identities,owner=setup(forbidden);del client.items[identities[2]]
    result=asyncio.run(call(boundary,scope(path,method)))
    assert result[0]['status']==503 and not reached
    assert b'NEVER_RETURN' not in result[-1]['body']
    assert result[-1]['body']==b'' if method=='HEAD' else b'RESTORE_ADMISSION_HELD' in result[-1]['body']
    assert not any(k in {b'set-cookie',b'location'} for k,v in result[0]['headers'])
    assert owner.wait_for_drain(0)


def test_valid_release_checks_each_delivery_and_removes_untracked_send_extensions():
    received=[]
    async def app(request,receive,send):
        received.append(request)
        await send({'type':'http.response.start','status':200,'headers':[]})
        await send({'type':'http.response.body','body':b'authorized','more_body':False})
    boundary,client,identities,owner=setup(app)
    result=asyncio.run(call(boundary,scope('/api/v1/me')))
    assert result[0]['status']==200 and result[-1]['body']==b'authorized'
    assert received[0]['extensions']=={}
    assert sum(name=='transact_get_items' for name,kw in client.calls)==3
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('method',['GET','HEAD'])
def test_fixed_liveness_has_complete_security_headers_and_no_sdk_work(method):
    async def forbidden(*args):pytest.fail('liveness reached downstream')
    boundary,client,identities,owner=setup(forbidden);del client.items[identities[2]]
    result=asyncio.run(call(boundary,scope('/health/live',method)))
    assert result[0]['status']==200 and client.calls==[] and owner.wait_for_drain(0)
    headers=dict(result[0]['headers'])
    assert headers[b'cache-control']==b'no-store'
    assert headers[b'content-security-policy']==b"default-src 'none'; frame-ancestors 'none'"
    assert headers[b'referrer-policy']==b'no-referrer' and headers[b'x-frame-options']==b'DENY'
    assert result[-1]['body']==(b'{"status":"ok"}' if method=='GET' else b'')


@pytest.mark.parametrize('at',['before_start','after_headers','after_first_body'])
def test_revocation_withholds_unsent_data_without_fabricating_a_successful_replacement(at):
    client=None;identities=None
    async def app(request,receive,send):
        if at=='before_start':client.items.pop(identities[2])
        await send({'type':'http.response.start','status':200,'headers':[]})
        if at=='after_headers':client.items.pop(identities[2])
        await send({'type':'http.response.body','body':b'FIRST','more_body':at=='after_first_body'})
        if at=='after_first_body':
            client.items.pop(identities[2])
            await send({'type':'http.response.body','body':b'MUST_WITHHOLD','more_body':False})
    boundary,client,identities,owner=setup(app)
    result=asyncio.run(call(boundary,scope('/api/v1/me')))
    body=b''.join(v.get('body',b'') for v in result)
    assert b'MUST_WITHHOLD' not in body and owner.wait_for_drain(0)
    assert result[0]['status']==(503 if at=='before_start' else 200)
    if at=='after_headers':assert body==b''
    if at=='after_first_body':assert body==b'FIRST'


def test_unsupported_pathsend_never_exposes_the_path_or_file():
    async def app(request,receive,send):await send({'type':'http.response.pathsend','path':'PRIVATE-NOT-ALLOWED'})
    boundary,client,identities,owner=setup(app)
    result=asyncio.run(call(boundary,scope('/assets/private')))
    assert result[0]['status']==503 and b'PRIVATE-NOT-ALLOWED' not in result[-1]['body']
    assert owner.wait_for_drain(0)


def test_changed_transport_configuration_has_sanitized_held_response():
    async def forbidden(*args):pytest.fail('changed transport reached downstream')
    boundary,client,identities,owner=setup(forbidden);boundary.max_active=True
    result=asyncio.run(call(boundary,scope('/api/v1/me')))
    assert result[0]['status']==503 and client.calls==[] and owner.wait_for_drain(0)


def test_stopping_resource_owner_denies_before_sdk_or_handler():
    async def forbidden(*args):pytest.fail('stopping owner reached downstream')
    boundary,client,identities,owner=setup(forbidden);owner.stop_accepting()
    result=asyncio.run(call(boundary,scope('/api/v1/me')))
    assert result[0]['status']==503 and client.calls==[] and owner.wait_for_drain(0)


def test_websocket_closes_without_data_or_sdk():
    async def forbidden(*args):pytest.fail('unsupported websocket reached downstream')
    boundary,client,identities,owner=setup(forbidden)
    result=asyncio.run(call(boundary,{'type':'websocket'}))
    assert result==[{'type':'websocket.close','code':1013}] and client.calls==[]


def test_cancelled_waiter_cannot_release_a_still_running_native_check():
    entered=Event();release=Event();done=Event();reached=[]
    async def app(*args):reached.append(True)
    boundary,client,identities,owner=setup(app,max_active=1)
    def blocked(parameters,result):
        entered.set()
        try:assert release.wait(5)
        finally:done.set()
    client.after_get=blocked
    async def run():
        task=asyncio.create_task(call(boundary,scope('/api/v1/me')))
        try:
            assert await asyncio.to_thread(entered.wait,2)
            task.cancel();await asyncio.sleep(0)
            assert not owner.wait_for_drain(0)
            second=await call(boundary,scope('/api/v1/me'))
            assert second[0]['status']==503 and not reached
        finally:
            release.set()
            try:await task
            except asyncio.CancelledError:pass
        assert await asyncio.to_thread(done.wait,2)
        assert await asyncio.to_thread(owner.wait_for_drain,2000)
    asyncio.run(run())
