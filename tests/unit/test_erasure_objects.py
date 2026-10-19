import json
import boto3
from botocore.config import Config
from botocore.stub import Stubber
import pytest
from pydantic import ValidationError
from proofpack.evidence.erasure_objects import ErasureObjects
from proofpack.evidence.erasure_models import ErasureConfirmation,ErasurePreview
from proofpack.evidence.objects import EvidenceObjects,ReferenceObjects,ObjectConfig
from proofpack.evidence.repository import StoreUnavailable

ID='10000000-0000-4000-8000-000000000001'


@pytest.fixture
def store():
    config=ObjectConfig('test-deployment','proofpack-erasure-test','000000000000','us-east-1','arn:aws:kms:us-east-1:000000000000:key/00000000-0000-4000-8000-000000000001')
    client=boto3.client('s3',region_name='us-east-1',aws_access_key_id='localtest',aws_secret_access_key='localtest',config=Config(connect_timeout=2,read_timeout=3,retries={'total_max_attempts':1}))
    stub=Stubber(client);stub.activate();objects=ErasureObjects(EvidenceObjects(client,config),ReferenceObjects(client,config),page_size=3)
    try:yield objects,stub,client
    finally:stub.deactivate();client.close()


def params(objects):return {'Bucket':objects.config.bucket,'ExpectedBucketOwner':objects.config.account_id,'Prefix':objects.frames.key(ID),'MaxKeys':3}


def test_list_and_delete_exact_versions_including_markers_and_legacy_null(store):
    objects,stub,client=store;key=objects.frames.key(ID)
    stub.add_response('list_object_versions',{'IsTruncated':False,'Versions':[{'Key':key,'VersionId':'v1'},{'Key':key,'VersionId':'null'}],'DeleteMarkers':[{'Key':key,'VersionId':'marker'}]},params(objects))
    page=objects.list('frame',ID);assert page.versions==('v1','null','marker')
    expected={'Bucket':objects.config.bucket,'ExpectedBucketOwner':objects.config.account_id,'Delete':{'Objects':[{'Key':key,'VersionId':v} for v in page.versions],'Quiet':False}}
    stub.add_response('delete_objects',{'Deleted':expected['Delete']['Objects']},expected)
    assert objects.delete('frame',ID,page.versions)==(3,False);stub.assert_no_pending_responses()


@pytest.mark.parametrize('fault',['foreign','duplicate','missing_version','empty_truncated','oversize','missing_truncated'])
def test_ambiguous_or_foreign_listing_never_becomes_an_owned_page(store,fault):
    objects,stub,client=store;key=objects.frames.key(ID);response={'IsTruncated':False,'Versions':[{'Key':key,'VersionId':'v1'}]}
    if fault=='foreign':response['Versions'][0]['Key']=key+'-foreign'
    elif fault=='duplicate':response['Versions']*=2
    elif fault=='missing_version':response['Versions'][0].pop('VersionId')
    elif fault=='empty_truncated':response={'IsTruncated':True}
    elif fault=='oversize':response['Versions']=[{'Key':key,'VersionId':str(i)} for i in range(4)]
    else:response.pop('IsTruncated')
    stub.add_response('list_object_versions',response,params(objects))
    with pytest.raises(StoreUnavailable):objects.list('frame',ID)
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('fault',['foreign','missing','duplicate','partial','transport'])
def test_delete_results_cannot_claim_unrequested_or_unacknowledged_success(store,fault):
    objects,stub,client=store;key=objects.frames.key(ID);entries=[{'Key':key,'VersionId':'v1'},{'Key':key,'VersionId':'v2'}]
    expected={'Bucket':objects.config.bucket,'ExpectedBucketOwner':objects.config.account_id,'Delete':{'Objects':entries,'Quiet':False}}
    response={'Deleted':entries}
    if fault=='foreign':response={'Deleted':[{'Key':key+'-foreign','VersionId':'v1'},entries[1]]}
    elif fault=='missing':response={'Deleted':[entries[0]]}
    elif fault=='duplicate':response={'Deleted':[entries[0],entries[0]]}
    elif fault=='partial':response={'Deleted':[entries[0]],'Errors':[{**entries[1],'Code':'AccessDenied','Message':'synthetic retained version'}]}
    if fault=='transport':stub.add_client_error('delete_objects',service_error_code='ServiceUnavailable',http_status_code=503,expected_params=expected)
    else:stub.add_response('delete_objects',response,expected)
    if fault=='partial':assert objects.delete('frame',ID,('v1','v2'))==(1,True)
    else:
        with pytest.raises(StoreUnavailable):objects.delete('frame',ID,('v1','v2'))
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('value',[1,False,'true',None])
def test_irreversible_confirmation_requires_actual_true_booleans(value):
    body={'preview_id':ID,'confirmed_digest':'a'*64,'erase_asset_versions_acknowledged':value,'understands_remaining_metadata_and_backups':True}
    with pytest.raises((ValidationError,ValueError)):ErasureConfirmation.model_validate_json(json.dumps(body))


def test_preview_rejects_duplicate_or_unbounded_asset_scopes():
    for ids in ([],[ID,ID],[ID]*17):
        with pytest.raises(ValidationError):ErasurePreview.model_validate_json(json.dumps({'asset_ids':ids}))
