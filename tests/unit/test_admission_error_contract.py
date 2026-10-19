"""Raw ASGI maintenance errors follow the established minimized API contract."""
import json,re
import anyio
import pytest
from test_privacy_admission import world,hold
from proofpack.evidence.privacy_http import MetadataAdmissionBoundary
from proofpack.evidence.repository import StoreUnavailable,StoreConflict


def run(service,*,method='GET'):
    messages=[];reached=[]
    async def app(*a):reached.append(True)
    async def receive():return {'type':'http.request','body':b'','more_body':False}
    async def send(message):messages.append(message)
    boundary=MetadataAdmissionBoundary(app,admission=service,lease_ms=500,attempts=3)
    scope={'type':'http','method':method,'path':'/private','raw_path':b'/private',
        'headers':[(b'x-request-id',b'CALLER-SECRET')],'state':{'request_id':'CALLER-STATE'}}
    anyio.run(boundary,scope,receive,send)
    assert not reached
    start=messages[0];assert start['status']==503
    return {k.decode():v.decode() for k,v in start['headers']},b''.join(m.get('body',b'') for m in messages)


@pytest.mark.parametrize('fault',['held','unavailable','conflict'])
def test_pre_admission_failures_have_closed_flat_redacted_retryable_envelope(monkeypatch,fault):
    service,*_=world()
    if fault=='held':hold(service)
    else:
        def fail(**kw):raise (StoreUnavailable if fault=='unavailable' else StoreConflict)('PRIVATE-ROW session#secret')
        monkeypatch.setattr(service,'prepare',fail)
    headers,body=run(service);data=json.loads(body)
    assert set(data)=={'code','safe_message','request_id','retryable'}
    assert data['code']=='METADATA_MAINTENANCE' and data['retryable'] is True
    assert re.fullmatch('[a-f0-9]{24}',data['request_id'])
    assert headers['x-request-id']==data['request_id'] and int(headers['content-length'])==len(body)
    assert not any(secret in body.decode() for secret in ['PRIVATE-ROW','session#','CALLER-SECRET','CALLER-STATE'])
    assert headers['cache-control']=='no-store' and headers['x-content-type-options']=='nosniff'
    assert headers['referrer-policy']=='no-referrer' and headers['x-frame-options']=='DENY'
    assert "default-src 'none'" in headers['content-security-policy']


def test_admission_head_denial_has_no_body_and_describes_get_representation():
    service,*_=world();hold(service)
    headers,body=run(service,method='HEAD')
    assert body==b'' and int(headers['content-length'])>0
    assert re.fullmatch('[a-f0-9]{24}',headers['x-request-id'])


def test_separate_denials_receive_distinct_server_correlation_ids():
    service,*_=world();hold(service)
    first=json.loads(run(service)[1]);second=json.loads(run(service)[1])
    assert first['request_id']!=second['request_id']
