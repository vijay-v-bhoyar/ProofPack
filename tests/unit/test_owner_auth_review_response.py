"""Version-discriminated HTTP response contract; no runtime or provider proof."""
from copy import deepcopy
import pytest
from pydantic import TypeAdapter,ValidationError
from proofpack.evidence.owner_metadata_http import ReviewResponse


def response(auth=True):
    value=dict(id='00000000-0000-0000-0000-000000000001',scope_sha256='a'*64,request_version=1,gate_version=2,
        control_version=3,accounting_policy='conservative-family-accounting-v5' if auth else 'conservative-family-accounting-v1',
        counts=dict(AFFECTED=1,SHARED=0,CONTEXT=2,UNRELATED=0,UNRESOLVED=3),total_records=6,
        historical=True,read_only=True,can_confirm_cleanup=False,erasure_complete=False,request_fulfilled=False)
    if auth:value.update(auth_history_policy_resolved=False,historical_auth_authority_proven=False)
    return value


@pytest.mark.parametrize('auth',[False,True])
def test_exact_v1_and_v5_responses_preserve_every_required_field(auth):
    value=response(auth);result=TypeAdapter(ReviewResponse).validate_python(value)
    assert result.model_dump()==value


@pytest.mark.parametrize('fault',['missing_policy','missing_authority','policy_true','authority_true','policy_zero',
    'authority_string','unknown_version','v1_extra','private','count_bool','sum','cleanup','fulfilled'])
def test_response_cannot_drop_mandatory_flags_downgrade_or_imply_authority(fault):
    value=response()
    if fault=='missing_policy':del value['auth_history_policy_resolved']
    elif fault=='missing_authority':del value['historical_auth_authority_proven']
    elif fault=='policy_true':value['auth_history_policy_resolved']=True
    elif fault=='authority_true':value['historical_auth_authority_proven']=True
    elif fault=='policy_zero':value['auth_history_policy_resolved']=0
    elif fault=='authority_string':value['historical_auth_authority_proven']='false'
    elif fault=='unknown_version':value['accounting_policy']='conservative-family-accounting-v4'
    elif fault=='v1_extra':value['accounting_policy']='conservative-family-accounting-v1'
    elif fault=='private':value['auth_records']=['cookie#private']
    elif fault=='count_bool':value['counts']['UNRESOLVED']=True
    elif fault=='sum':value['total_records']=5
    elif fault=='cleanup':value['can_confirm_cleanup']=True
    elif fault=='fulfilled':value['request_fulfilled']=True
    with pytest.raises(ValidationError):TypeAdapter(ReviewResponse).validate_python(value)
