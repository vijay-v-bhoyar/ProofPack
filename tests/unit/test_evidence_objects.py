"""Exact SDK protocol tests. Stubber intercepts every call; no AWS bucket is used."""
from dataclasses import replace
import base64
import hashlib
import io
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.response import StreamingBody
from botocore.stub import Stubber
import pytest

from proofpack.evidence.objects import ObjectConfig,ObjectReceipt,EvidenceObjects
from proofpack.evidence.repository import StoreConflict,StoreUnavailable


def world():
    config=ObjectConfig('synthetic-test','proofpack-synthetic-test','000000000000','us-east-1',
        'arn:aws:kms:us-east-1:000000000000:key/11111111-2222-3333-4444-555555555555')
    client=boto3.client('s3',region_name='us-east-1',aws_access_key_id='synthetic',aws_secret_access_key='synthetic',
        config=Config(connect_timeout=2,read_timeout=3,retries={'max_attempts':0}))
    return EvidenceObjects(client,config),Stubber(client)


def fixture(store):
    # Storage is format-agnostic: actual JPEG/PNG validation belongs to the decoder.
    payload=b'synthetic-storage-protocol-bytes';ident=str(uuid4());source=hashlib.sha256(payload).hexdigest()
    receipt=ObjectReceipt(ident,store.key(ident),'synthetic-version',source,'a'*64,len(payload),'image/png')
    checksum=base64.b64encode(bytes.fromhex(source)).decode()
    params={'Bucket':store.config.bucket,'Key':receipt.key,'ExpectedBucketOwner':store.config.account_id}
    put={**params,'Body':payload,'ContentLength':len(payload),'ContentType':'image/png','IfNoneMatch':'*',
        'ChecksumSHA256':checksum,'ServerSideEncryption':'aws:kms','SSEKMSKeyId':store.config.kms_key_arn,
        'Metadata':{'source-sha256':source,'context-sha256':'a'*64}}
    ack={'VersionId':receipt.version_id,'ChecksumSHA256':checksum,'ServerSideEncryption':'aws:kms','SSEKMSKeyId':store.config.kms_key_arn}
    head={**ack,'ContentLength':len(payload),'ContentType':'image/png','Metadata':put['Metadata'],'ETag':'not-a-content-hash'}
    return payload,receipt,put,ack,head


def test_versioned_conditional_encrypted_write_head_and_exact_byte_read():
    store,stub=world();payload,receipt,put,ack,head=fixture(store)
    params={**store._params(receipt.asset_id,receipt.version_id),'ChecksumMode':'ENABLED'}
    stub.add_response('put_object',ack,put);stub.add_response('head_object',head,params)
    stream=io.BytesIO(payload);body=StreamingBody(stream,len(payload))
    stub.add_response('get_object',{**head,'Body':body},params)
    with stub:
        actual=store.put(asset_id=receipt.asset_id,payload=payload,content_type='image/png',context_sha256='a'*64)
        assert actual==receipt and receipt.key not in repr(receipt) and receipt.version_id not in repr(receipt)
        assert store.get(actual)==payload
    assert stream.closed
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('field,value',[('VersionId','null'),('VersionId',None),('ChecksumSHA256','wrong'),
    ('ServerSideEncryption','AES256'),('SSEKMSKeyId','wrong-key')])
def test_write_ack_must_prove_version_checksum_and_encryption(field,value):
    store,stub=world();payload,receipt,put,ack,head=fixture(store)
    if value is None:ack.pop(field)
    else:ack[field]=value
    stub.add_response('put_object',ack,put)
    with stub,pytest.raises(StoreUnavailable):store.put(asset_id=receipt.asset_id,payload=payload,content_type='image/png',context_sha256='a'*64)
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('changes',[{'ContentLength':999},{'ContentType':'text/plain'},{'ChecksumSHA256':'wrong'},
    {'VersionId':'other-version'},{'Metadata':{'source-sha256':'a'*64,'context-sha256':'b'*64}}])
def test_head_verification_failure_produces_no_receipt(changes):
    store,stub=world();payload,receipt,put,ack,head=fixture(store)
    stub.add_response('put_object',ack,put)
    stub.add_response('head_object',{**head,**changes},{**store._params(receipt.asset_id,receipt.version_id),'ChecksumMode':'ENABLED'})
    with stub,pytest.raises(StoreUnavailable):store.put(asset_id=receipt.asset_id,payload=payload,content_type='image/png',context_sha256='a'*64)


@pytest.mark.parametrize('code,status',[('PreconditionFailed',412),('ConditionalRequestConflict',409),('AccessDenied',403),('ServiceUnavailable',503)])
def test_write_failure_is_not_retried_or_reported_durable(code,status):
    store,stub=world();payload,receipt,put,ack,head=fixture(store)
    stub.add_client_error('put_object',service_error_code=code,http_status_code=status,expected_params=put)
    with stub,pytest.raises(StoreConflict if status in {409,412} else StoreUnavailable):
        store.put(asset_id=receipt.asset_id,payload=payload,content_type='image/png',context_sha256='a'*64)
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('bytes_mode',['wrong-hash','oversized','truncated'])
def test_reads_validate_bytes_and_always_close_body(bytes_mode):
    store,stub=world();payload,receipt,put,ack,head=fixture(store)
    data={'wrong-hash':b'x'*len(payload),'oversized':payload+b'extra','truncated':payload[:-1]}[bytes_mode]
    stream=io.BytesIO(data);body=StreamingBody(stream,len(data))
    stub.add_response('get_object',{**head,'Body':body},{**store._params(receipt.asset_id,receipt.version_id),'ChecksumMode':'ENABLED'})
    with stub,pytest.raises(StoreUnavailable):store.get(receipt)
    assert stream.closed


def test_read_cannot_select_arbitrary_key_or_unversioned_object():
    store,stub=world();payload,receipt,put,ack,head=fixture(store)
    with stub:
        with pytest.raises(ValueError):store.get(replace(receipt,key='other-deployment/private'))
        with pytest.raises(StoreUnavailable):store.get(replace(receipt,version_id='null'))
        with pytest.raises(ValueError):store.put(asset_id='../escape',payload=payload,content_type='image/png',context_sha256='a'*64)


def test_validate_checks_exact_owned_version_checksum_and_metadata():
    store,stub=world();payload,receipt,put,ack,head=fixture(store)
    stub.add_response('head_object',head,{**store._params(receipt.asset_id,receipt.version_id),'ChecksumMode':'ENABLED'})
    with stub:assert store.validate(receipt) is None
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('changes',[{'ContentLength':999},{'ContentType':'text/plain'},{'ChecksumSHA256':'wrong'},
    {'VersionId':'other-version'},{'Metadata':{}},{'SSEKMSKeyId':'wrong-key'}])
def test_validate_rejects_changed_object_metadata(changes):
    store,stub=world();payload,receipt,put,ack,head=fixture(store)
    stub.add_response('head_object',{**head,**changes},{**store._params(receipt.asset_id,receipt.version_id),'ChecksumMode':'ENABLED'})
    with stub,pytest.raises(StoreUnavailable):store.validate(receipt)
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('changes',[{'key':'other-deployment/private'},{'context_sha256':'not-a-digest'},
    {'content_type':'text/plain'},{'source_sha256':'not-a-digest'},{'byte_length':True}])
def test_validate_rejects_malformed_receipts_before_storage(changes):
    store,stub=world();payload,receipt,put,ack,head=fixture(store)
    with stub,pytest.raises(ValueError):store.validate(replace(receipt,**changes))


@pytest.mark.parametrize('changes',[{'deployment':'../escape'},{'bucket':'https://evil.invalid'}, {'account_id':'bad'},
    {'kms_key_arn':'arn:aws:kms:us-east-2:000000000000:key/11111111-2222-3333-4444-555555555555'}])
def test_object_target_configuration_is_explicit(changes):
    store,stub=world()
    with pytest.raises(ValueError):replace(store.config,**changes)


def test_reference_namespace_is_distinct_and_cannot_validate_a_frame_receipt():
    from proofpack.evidence.objects import ReferenceObjects
    frame,stub=world();reference=ReferenceObjects(frame.client,frame.config);ident=str(uuid4())
    with stub:
        assert reference.key(ident)=='deployments/synthetic-test/references/'+ident
        assert frame.key(ident)=='deployments/synthetic-test/frames/'+ident
        receipt=ObjectReceipt(ident,frame.key(ident),'version','a'*64,'b'*64,20,'image/jpeg')
        with pytest.raises(ValueError):reference.validate(receipt)
        stub.assert_no_pending_responses()
    frame.client.close()
