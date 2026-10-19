from copy import deepcopy
import hashlib,json
from uuid import uuid4
import pytest
from pydantic import ValidationError
from proofpack.evidence.job_authority import scope_sha256
from proofpack.review.qualification_preparation import PreparationRequest,KIND


def body():return {'policy_id':str(uuid4()),'source_evaluation_id':str(uuid4()),'source_evaluation_state_version':3,
    'source_report_sha256':'a'*64,'preparation_only_acknowledged':True}


@pytest.mark.parametrize('field,value',[
    ('preparation_only_acknowledged',False),('preparation_only_acknowledged',1),('preparation_only_acknowledged','true'),
    ('source_evaluation_state_version',True),('source_evaluation_state_version',0),('source_evaluation_state_version','3'),
    ('source_report_sha256','z'*64),('source_report_sha256','a'*63),('policy_id','not-a-uuid')])
def test_preparation_request_rejects_coercion_missing_scope_and_acknowledgment(field,value):
    with pytest.raises(ValidationError):PreparationRequest.model_validate_json(json.dumps({**body(),field:value}))


@pytest.mark.parametrize('extra',['passed','qualified','promotion_eligible','source_measurements','case_ids','runtime_epoch'])
def test_request_cannot_supply_result_or_execution_authority(extra):
    with pytest.raises(ValidationError):PreparationRequest.model_validate_json(json.dumps({**body(),extra:True}))


def job():
    text=json.dumps(body());return {'id':str(uuid4()),'kind':KIND,'requested_by':str(uuid4()),'configuration':'a'*64,'data_epoch':1,
        'artifact_sha256':'b'*64,'controls_sha256':'c'*64,'environment':'synthetic_demo','created_at_ms':1000,'expires_at_ms':2000,
        'request_json':text,'request_sha256':hashlib.sha256(text.encode()).hexdigest(),'example_count':171,
        'validation_runtime':{'instance_id':str(uuid4()),'epoch':1,'artifact_sha256':'b'*64},'control_version':1,
        'registry_sha256':'d'*64,'implementation_sha256':'e'*64,'software_cases':170,'source_examples':1}


@pytest.mark.parametrize('field',['validation_runtime','control_version','registry_sha256','implementation_sha256','software_cases','source_examples'])
def test_processing_scope_binds_every_immutable_preparation_context(field):
    original=job();changed=deepcopy(original)
    if isinstance(changed[field],dict):changed[field]['epoch']+=1
    elif type(changed[field]) is int:changed[field]+=1
    else:changed[field]='f'*64
    assert scope_sha256(changed)!=scope_sha256(original)


def test_progress_and_lease_updates_do_not_extend_or_change_original_signed_scope():
    original=job();changed={**original,'processed':100,'steps_reserved':107,'lease_token':str(uuid4()),'lease_until_ms':1999,'status':'processing'}
    assert scope_sha256(changed)==scope_sha256(original)
    changed['expires_at_ms']+=1
    assert scope_sha256(changed)!=scope_sha256(original)
