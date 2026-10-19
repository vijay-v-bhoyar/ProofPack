import json
from types import SimpleNamespace
from uuid import uuid4
import pytest
from proofpack.evidence.originals import original_profile
from proofpack.evidence.repository import StoreUnavailable
from proofpack.review.evaluation_models import EvaluationRequest,parse_evaluation_request
from proofpack.review.vision_replay import VisionReplayRequest,VisionReplayConfig
from proofpack.vision.fixtures import synthetic_profile


def body():
    return {'runner':'vision_replay_v1','policy_id':str(uuid4()),'policy_revision':1,'policy_state_version':1,
        'policy_revision_sha256':'a'*64,'manifest_id':str(uuid4()),'manifest_sha256':'b'*64,
        'historical_diagnostic_acknowledged':True,'frozen_holdout_acknowledged':False,
        'candidate_recipe_id':str(uuid4()),'candidate_recipe_revision':1,'candidate_recipe_state_version':1,
        'candidate_recipe_sha256':'c'*64,'vision_measurement_acknowledged':True}


def test_exact_vision_request_and_legacy_decision_request_keep_distinct_schemas():
    value=body();request=parse_evaluation_request(json.dumps(value));assert isinstance(request,VisionReplayRequest)
    decision={k:v for k,v in value.items() if not k.startswith('candidate_recipe_') and k!='vision_measurement_acknowledged'}
    decision['runner']='decision_replay_v1';old=parse_evaluation_request(json.dumps(decision))
    assert type(old) is EvaluationRequest and old.model_dump()==decision
    with pytest.raises(ValueError):parse_evaluation_request(json.dumps({**value,'runner':'decision_replay_v1'}))


@pytest.mark.parametrize('change',[{'vision_measurement_acknowledged':False},{'vision_measurement_acknowledged':1},
    {'candidate_recipe_state_version':True},{'candidate_recipe_revision':0},{'candidate_recipe_sha256':'bad'},
    {'runner':'arbitrary-code'},{'path':'C:/private/image.png'},{'profile_override':{}},{'source_url':'https://example.test/image'}])
def test_unapproved_ambiguous_or_caller_supplied_vision_inputs_are_rejected(change):
    with pytest.raises(ValueError):parse_evaluation_request(json.dumps({**body(),**change}))


@pytest.mark.parametrize('change',[{'max_case_ms':0},{'max_case_ms':60001},{'max_case_ms':True},
    {'max_report_bytes':0},{'max_report_bytes':32769},{'max_report_bytes':False}])
def test_vision_case_and_report_bounds_cannot_be_widened_or_coerced(change):
    with pytest.raises(ValueError):VisionReplayConfig(**change)


def test_replay_geometry_is_the_exact_server_snapshot_not_a_hash_substitute():
    profile=synthetic_profile();data={'replay_profile_json':profile.model_dump_json(),'calibration_sha256':profile.content_hash,'data_origin':'synthetic'}
    assert original_profile(SimpleNamespace(data=data)).content_hash==profile.content_hash
    for change in ({'replay_profile_json':None},{'replay_profile_json':'{}'},{'replay_profile_json':'x'*65537},
                   {'calibration_sha256':'f'*64},{'data_origin':'physical'}):
        with pytest.raises(StoreUnavailable):original_profile(SimpleNamespace(data={**data,**change}))
    with pytest.raises(StoreUnavailable):original_profile(SimpleNamespace(data={k:v for k,v in data.items() if k!='replay_profile_json'}))
