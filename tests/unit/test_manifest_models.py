from dataclasses import replace
from uuid import uuid4
import json
import pytest
from pydantic import ValidationError
from proofpack.review.manifests import DatasetConfig,ManifestRequest,Consequence


def sample():return {'label_id':str(uuid4()),'label_revision':1,'split':'DEVELOPMENT','permissions':[{'id':str(uuid4()),'state_version':1}]}


@pytest.mark.parametrize('changes',[{'max_examples':0},{'max_examples':1001},{'jobs_per_minute':21},{'step_attempts_per_minute':121},
    {'lifetime_ms':999},{'lease_ms':60001},{'max_steps':True},{'max_steps':10001},{'reads_per_minute':0}])
def test_explicit_manifest_bounds(changes):
    with pytest.raises(ValueError):replace(DatasetConfig(1000,20,120,3600000,15000,3000,120),**changes)


@pytest.mark.parametrize('change',['duplicate','too_many','missing_permission','extra_source','unknown_split','frozen_ack','coerced_ack','invalid_version'])
def test_manifest_has_no_client_groups_truth_or_unbounded_selections(change):
    item=sample();body={'selections':[item],'historical_diagnostic_acknowledged':True,'frozen_holdout_acknowledged':False}
    if change=='duplicate':body['selections']*=2
    elif change=='too_many':body['selections']=[sample() for _ in range(1001)]
    elif change=='missing_permission':item['permissions']=[]
    elif change=='extra_source':item['kit_group']='caller-supplied'
    elif change=='unknown_split':item['split']='TRAINING'
    elif change=='frozen_ack':item['split']='FROZEN_TEST'
    elif change=='coerced_ack':body['historical_diagnostic_acknowledged']='true'
    else:item['permissions'][0]['state_version']=True
    with pytest.raises(ValidationError):ManifestRequest.model_validate_json(json.dumps(body))


def test_declassification_has_no_split_upgrade_or_self_certification():
    with pytest.raises(ValidationError):Consequence(acknowledged=True,reason='retire',split='FROZEN_TEST')
