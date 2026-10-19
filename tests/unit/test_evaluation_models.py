from copy import deepcopy
from dataclasses import replace
import json
import pytest
from proofpack.planner.candidates import PolicyDraft
from proofpack.review.evaluation_models import EvaluationConfig,EvaluationRequest,replay_decision

BEFORE='a0000000-0000-4000-8000-000000000001';AFTER='a0000000-0000-4000-8000-000000000002';ACTION='b0000000-0000-4000-8000-000000000001'


def label():
    before={'observation_id':BEFORE,'sequence':1,'findings':['UNOBSERVABLE'],'reason_codes':['overlap','not_flat'],
        'quality_ok':True,'unknown_regions':1,'calibration_sha256':'a'*64}
    return {'outcome':'resolved','duration_ms':1234,'method':'synthetic_fixture','source_context':{
        'tuple':{'before_observation_id':BEFORE,'action_id':ACTION,'after_observation_id':AFTER},
        'action':{'id':ACTION,'kind':'SEPARATE_REGION'},'observations':[before,{**before,'observation_id':AFTER,'sequence':2,'findings':['SATISFIED'],'reason_codes':[],'unknown_regions':0}]}}


def spec(priority=('PLACE_FLAT','SEPARATE_REGION','RECAPTURE')):
    return PolicyDraft.model_validate_json(json.dumps({'name':'Candidate','algorithm':'reason_priority_v1','priority':priority}))


def test_changed_action_never_invents_the_recorded_action_outcome_or_operator_rate():
    result=replay_decision(label(),spec())
    assert result['baseline']=={'action':'SEPARATE_REGION','classification':'observed_match','declared_resolved':True}
    assert result['candidate']=={'action':'PLACE_FLAT','classification':'counterfactual_unknown','declared_resolved':None}
    assert result['declared_review_duration_ms']==1234 and result['operator_effort_measured'] is False
    assert result['promotion_eligible'] is False and result['independent_benchmark_qualified'] is False
    assert not any('throughput' in key or 'accuracy' in key for key in result)


@pytest.mark.parametrize('change,classification',[
    ('unresolved','observed_match'),('incorrect','incorrect_finding'),('no_tuple','no_recorded_outcome'),
    ('satisfied','not_actionable'),('unknown_reason','no_recorded_outcome')])
def test_every_case_remains_explicit_even_without_an_observed_resolution(change,classification):
    value=label()
    if change=='unresolved':value['outcome']='unresolved'
    elif change=='incorrect':value['outcome']='incorrect_finding'
    elif change=='no_tuple':
        value['outcome']='unresolved';value['source_context'].pop('action');value['source_context']['tuple'].update(action_id=None,after_observation_id=None);value['source_context']['observations']=value['source_context']['observations'][:1]
    elif change=='satisfied':value['source_context']['observations'][0].update(findings=['SATISFIED'],unknown_regions=0,reason_codes=[])
    else:value['source_context']['observations'][0]['reason_codes']=['unsupported']
    result=replay_decision(value,spec(('SEPARATE_REGION','PLACE_FLAT','RECAPTURE')))
    assert result['baseline']['classification']==classification and result['candidate']['classification']==classification
    assert result['baseline']['declared_resolved'] is (False if change=='unresolved' else None)


@pytest.mark.parametrize('change',['before','after','action','order','too_many','duration','quality','reason'])
def test_forged_or_unbounded_historical_input_is_rejected(change):
    value=label();context=value['source_context']
    if change=='before':context['tuple']['before_observation_id']=AFTER
    elif change=='after':context['tuple']['after_observation_id']=BEFORE
    elif change=='action':context['action']['id']=BEFORE
    elif change=='order':context['observations'][1]['sequence']=1
    elif change=='too_many':context['observations']*=3
    elif change=='duration':value['duration_ms']=True
    elif change=='quality':context['observations'][0]['quality_ok']=1
    else:context['observations'][0]['reason_codes']=['x'*65]
    with pytest.raises(ValueError):replay_decision(value,spec())


def request(**changes):
    return EvaluationRequest.model_validate_json(json.dumps({'runner':'decision_replay_v1','policy_id':BEFORE,'policy_revision':1,
        'policy_state_version':1,'policy_revision_sha256':'a'*64,'manifest_id':AFTER,'manifest_sha256':'b'*64,
        'historical_diagnostic_acknowledged':True,'frozen_holdout_acknowledged':False,**changes}))


@pytest.mark.parametrize('change',[{'runner':'execute_code'},{'policy_revision':True},{'policy_state_version':0},
    {'policy_revision_sha256':'bad'},{'historical_diagnostic_acknowledged':1},{'historical_diagnostic_acknowledged':False},
    {'frozen_holdout_acknowledged':0},{'groups':[]},{'approved':True},{'metrics':{}},{'budget':9999},{'url':'https://example.invalid'}])
def test_client_cannot_supply_authority_truth_metrics_or_unsafe_scope(change):
    with pytest.raises(ValueError):request(**change)


@pytest.mark.parametrize('name,value',[('jobs_per_minute',21),('step_attempts_per_minute',0),('reads_per_minute',121),
    ('lifetime_ms',3600001),('lease_ms',999),('max_steps',10001),('max_steps',True)])
def test_missing_or_excessive_installation_capacity_is_not_accepted(name,value):
    with pytest.raises(ValueError):replace(EvaluationConfig(8,120,120,60000,15000,3000),**{name:value})
