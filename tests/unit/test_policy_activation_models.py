from dataclasses import replace
import json
import pytest
from proofpack.planner.activation import ActivationConfig,ActivationRequest

BODY={'operation':'bootstrap','policy_id':'a1000000-0000-4000-8000-000000000001','policy_revision':1,'policy_state_version':1,
    'policy_revision_sha256':'a'*64,'qualification_id':'b1000000-0000-4000-8000-000000000001','qualification_report_sha256':'b'*64,
    'expected_active_version':0,'expected_control_version':1,'invalidation_acknowledged':True}


@pytest.mark.parametrize('field,value',[
    ('invalidation_acknowledged',False),('invalidation_acknowledged',1),('invalidation_acknowledged','true'),
    ('policy_revision',True),('policy_revision','1'),('policy_revision',1001),('policy_state_version',0),
    ('expected_active_version',True),('expected_active_version',1),('expected_control_version',0),
    ('operation','force'),('operation','rollback'),('predecessor_activation_id',BODY['policy_id']),
    ('qualification_report_sha256','not-a-hash'),('qualified',True),('physical_truth_verified',True),('priority',['REVIEW'])])
def test_activation_request_rejects_coercion_scope_forgery_and_incoherent_transitions(field,value):
    with pytest.raises(ValueError):ActivationRequest.model_validate_json(json.dumps({**BODY,field:value}))


@pytest.mark.parametrize('field,value',[
    ('writes_per_minute',0),('writes_per_minute',21),('writes_per_minute',True),('reads_per_minute',121),
    ('review_window_ms',999),('review_window_ms',60001),('max_qualification_rows',81),('qualification_registry_sha256','x')])
def test_activation_configuration_requires_exact_explicit_bounds(field,value):
    config=ActivationConfig(20,120,60000,80,'c'*64)
    with pytest.raises(ValueError):replace(config,**{field:value})


def test_strict_promote_and_rollback_bind_existing_head_and_exact_predecessor():
    assert ActivationRequest.model_validate_json(json.dumps(BODY)).operation=='bootstrap'
    changed={**BODY,'operation':'promote','expected_active_version':1}
    assert ActivationRequest.model_validate_json(json.dumps(changed)).operation=='promote'
    changed.update(operation='rollback',predecessor_activation_id=BODY['policy_id'])
    assert ActivationRequest.model_validate_json(json.dumps(changed)).operation=='rollback'
