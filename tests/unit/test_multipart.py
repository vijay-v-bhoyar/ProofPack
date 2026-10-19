"""Parser bounds/protocol tests; no image decoding, users or network calls."""
import asyncio
from uuid import uuid4
import pytest
from starlette.requests import Request
from starlette.exceptions import HTTPException
from proofpack.capture.multipart import ImageMultipart,MAX_BODY,MAX_IMAGE,receive_upload

BOUNDARY='proofpack-test-boundary'
PNG=b'\x89PNG\r\n\x1a\nsynthetic-format-prefix-only'


def body(*,image=PNG,fields=None,mime='image/png',extra=b'',filename='../../ignored.png'):
    fields=fields if fields is not None else [('permit_id',str(uuid4())),('nonce','a'*43),('sequence','1')]
    chunks=[b'--'+BOUNDARY.encode()+b'\r\nContent-Disposition: form-data; name="'+name.encode()+b'"\r\n\r\n'+value.encode()+b'\r\n' for name,value in fields]
    chunks.append(b'--'+BOUNDARY.encode()+b'\r\nContent-Disposition: form-data; name="image"; filename="'+filename.encode()+b'"\r\nContent-Type: '+mime.encode()+b'\r\n\r\n'+image+b'\r\n')
    return b''.join(chunks)+extra+b'--'+BOUNDARY.encode()+b'--\r\n'


def parse(raw,step=31):
    parser=ImageMultipart('multipart/form-data; boundary='+BOUNDARY)
    for offset in range(0,len(raw),step):parser.write(raw[offset:offset+step])
    return parser.finish()


@pytest.mark.parametrize('step',[1,2,17,4096])
def test_streaming_arbitrary_chunk_boundaries_preserve_bytes_and_hide_nonce(step):
    raw=body();result=parse(raw,step)
    assert result.payload==PNG and result.sequence==1 and result.content_type=='image/png'
    assert 'a'*43 not in repr(result) and 'synthetic-format' not in repr(result) and 'ignored.png' not in repr(result)


@pytest.mark.parametrize('change',[lambda raw:raw[:-5],lambda raw:b'preamble'+raw,
    lambda raw:raw.replace(b'name="nonce"',b'name="passed"'),
    lambda raw:raw.replace(b'name="nonce"',b'name="sequence"'),
    lambda raw:raw.replace(b'\r\nContent-Type: image/png',b'\r\nContent-Type: image/png\r\nContent-Type: image/png'),
    lambda raw:raw.replace(b'\r\nContent-Type: image/png',b'\r\nContent-Transfer-Encoding: base64\r\nContent-Type: image/png')])
def test_malformed_duplicate_unknown_or_encoded_parts_fail(change):
    with pytest.raises(HTTPException) as error:parse(change(body()))
    assert error.value.status_code==400


@pytest.mark.parametrize('mime,image',[('image/jpeg',PNG),('image/png',b'bad'),('text/plain',PNG),('multipart/mixed',PNG)])
def test_unsupported_type_or_wrong_signature_fail_before_decoder(mime,image):
    with pytest.raises(HTTPException) as error:parse(body(mime=mime,image=image))
    assert error.value.status_code==415


@pytest.mark.parametrize('fields',[
    [('permit_id','not-a-uuid'),('nonce','a'*43),('sequence','1')],
    [('permit_id',str(uuid4())),('nonce','a'*44),('sequence','1')],
    [('permit_id',str(uuid4())),('nonce','a'*43),('sequence','01')],
    [('permit_id',str(uuid4())),('nonce','a'*43),('sequence','0')],
    [('permit_id',str(uuid4())),('nonce','a'*43),('sequence','1'*65)],
    [('permit_id',str(uuid4())),('nonce','a'*43)],
])
def test_metadata_identity_and_size_are_bounded(fields):
    with pytest.raises(HTTPException):parse(body(fields=fields))


def test_image_and_total_wire_sizes_enforced_independently():
    assert len(parse(body(image=PNG+b'x'*(MAX_IMAGE-len(PNG))),4096).payload)==MAX_IMAGE
    with pytest.raises(HTTPException) as error:parse(body(image=PNG+b'x'*MAX_IMAGE),4096)
    assert error.value.status_code==413
    parser=ImageMultipart('multipart/form-data; boundary='+BOUNDARY)
    with pytest.raises(HTTPException) as error:parser.write(b'x'*(MAX_BODY+1))
    assert error.value.status_code==413


@pytest.mark.parametrize('content_type',['application/json','multipart/form-data','multipart/form-data; boundary=""',
    'multipart/form-data; boundary='+('x'*71),'multipart/form-data; boundary=a; boundary=b'])
def test_only_bounded_unambiguous_top_level_boundary(content_type):
    with pytest.raises(HTTPException):ImageMultipart(content_type)


def request(raw,headers=None,*,disconnect=False):
    events=iter([{'type':'http.disconnect'}] if disconnect else [{'type':'http.request','body':raw,'more_body':False}])
    async def receive():return next(events)
    scope={'type':'http','method':'POST','headers':headers if headers is not None else [(b'content-type',('multipart/form-data; boundary='+BOUNDARY).encode())]}
    return Request(scope,receive)


@pytest.mark.parametrize('headers',[
    [(b'content-type',b'application/json')],
    [(b'content-type',b'multipart/form-data; boundary=a'),(b'content-type',b'multipart/form-data; boundary=b')],
    [(b'content-type',b'multipart/form-data; boundary=a'),(b'content-encoding',b'gzip')],
    [(b'content-type',b'multipart/form-data; boundary=a'),(b'content-length',str(MAX_BODY+1).encode())],
    [(b'content-type',b'multipart/form-data; boundary=a'),(b'content-length',b'1'),(b'transfer-encoding',b'chunked')],
])
def test_request_headers_rejected_before_body_is_consumed(headers):
    async def forbidden():raise AssertionError('body must not be read')
    req=Request({'type':'http','method':'POST','headers':headers},forbidden)
    with pytest.raises(HTTPException):asyncio.run(receive_upload(req))


def test_chunked_body_and_client_disconnect():
    result=asyncio.run(receive_upload(request(body())))
    assert result.payload==PNG
    with pytest.raises(HTTPException):asyncio.run(receive_upload(request(b'',disconnect=True)))


def test_receive_deadline_is_five_seconds_and_returns_408(monkeypatch):
    import proofpack.capture.multipart as module
    timeout=asyncio.timeout;durations=[]
    def short_clock(seconds):durations.append(seconds);return timeout(.001)
    monkeypatch.setattr(module.asyncio,'timeout',short_clock)
    async def receive():
        await asyncio.sleep(.02)
        return {'type':'http.request','body':b'', 'more_body':False}
    req=Request({'type':'http','method':'POST','headers':[(b'content-type',('multipart/form-data; boundary='+BOUNDARY).encode())]},receive)
    with pytest.raises(HTTPException) as error:asyncio.run(receive_upload(req))
    assert error.value.status_code==408 and durations==[5]
