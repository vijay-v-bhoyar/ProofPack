"""Synthetic semantic facts only; real report admission is tested separately."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import json
import pytest
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Key,Row,StoreConflict,StoreUnavailable
from proofpack.planner.consumption import PolicyConsumption


def facts(report_patch=None,event_patch=None,runtime_patch=None):
    common={'policy_id':'00000000-0000-4000-8000-000000000001','policy_revision':1,'policy_revision_sha256':'a'*64,
        'behavior_sha256':'b'*64,'registry_sha256':'c'*64,'installed_sha256':'d'*64,'environment':'synthetic_demo',
        'artifact_sha256':'e'*64,'controls_sha256':'f'*64,'runtime_epoch':1,'data_epoch':1}
    q={'schema_version':1,'runner':'policy_qualification_v1',**common,'id':'00000000-0000-4000-8000-000000000002',
        'scope':'synthetic_demo_only','status':'qualified','control_version':1,'issued_at_ms':10,'expires_at_ms':1000,
        'required_case_count':182,'completed_case_count':182,'passed_case_count':182,'failed_case_count':0,'unknown_case_count':0,
        'physical_truth_verified':False,'independent_benchmark_qualified':False,'operator_effort_measured':False,'beta_eligible':False,
        **(report_patch or {})};q['sha256']=digest(q)
    event={**common,'kind':'policy_activation','activation_id':'00000000-0000-4000-8000-000000000003',
        'qualification_id':q['id'],'qualification_report_sha256':q['sha256'],'previous_control_version':1,'control_version':2,
        'issued_at_ms':20,'expires_at_ms':1000,**(event_patch or {})};event['sha256']=digest(event)
    p={k:v for k,v in event.items() if k not in {'kind','sha256','previous_control_version'}}
    p.update(kind='active_policy',status='approved',mode='deterministic_policy',activation_sha256=event['sha256']);p['sha256']=digest(p)
    job={'kind':'policy_qualification','id':q['id'],'status':'completed','report_sha256':q['sha256'],'control_version':1,
        'request_json':json.dumps({'mode':'installed_default','preparation_id':None})}
    runtime={**common,'control_version':3,**(runtime_patch or {})}
    def row(name,data):return Row(Key('state',name),1,data)
    return PolicyConsumption(row('policy',p),row('event',event),row('report',q),row('job',job),row('runtime',runtime),row('data',{'epoch':1}))


def test_consumed_context_keeps_original_control_and_exact_revision():
    value=facts();event=value.event.data
    request=SimpleNamespace(policy_id=event['policy_id'],policy_revision=1,policy_revision_sha256=event['policy_revision_sha256'],policy_state_version=1)
    value.candidate(request,Row(Key('state','candidate'),2,{'latest_revision':2}),Row(Key('state','revision'),1,{'sha256':event['policy_revision_sha256']}))
    assert value.execution_control(value.job,value.runtime)==1  # current runtime control is three


@pytest.mark.parametrize('patch',[{'schema_version':True},{'runner':'diagnostic_only'},{'scope':'physical'},{'status':'rejected'},
    {'environment':'test'},{'required_case_count':True},{'completed_case_count':181},{'passed_case_count':181},
    {'failed_case_count':1},{'unknown_case_count':1},{'control_version':2},{'runtime_epoch':2},
    {'physical_truth_verified':True},{'independent_benchmark_qualified':True},{'operator_effort_measured':True},{'beta_eligible':True}])
def test_even_internally_consistent_report_hashes_cannot_expand_consumed_scope(patch):
    with pytest.raises(StoreUnavailable):facts(report_patch=patch)


@pytest.mark.parametrize('patch',[{'control_version':3},{'previous_control_version':0},{'expires_at_ms':1001},{'issued_at_ms':9}])
def test_exact_adjacent_transition_and_original_lifetime_are_required(patch):
    with pytest.raises(StoreUnavailable):facts(event_patch=patch)


def test_consumption_cannot_account_for_runtime_control_rollback():
    with pytest.raises(StoreUnavailable):facts(runtime_patch={'control_version':1})


@pytest.mark.parametrize('change',['id','kind','control','runtime'])
def test_execution_control_exception_is_scoped_to_exact_consumed_jobs(change):
    value=facts();job=deepcopy(value.job);runtime=value.runtime
    if change=='id':job.data['id']='foreign-job'
    elif change=='kind':job.data['kind']='policy_evaluation'
    elif change=='control':job.data['control_version']=3
    else:runtime=replace(runtime,revision=2)
    with pytest.raises(StoreConflict):value.execution_control(job,runtime)


@pytest.mark.parametrize('field,new',[('policy_id','foreign-policy'),('policy_revision',2),('policy_revision_sha256','f'*64),('policy_state_version',3)])
def test_later_draft_head_does_not_allow_another_qualified_revision(field,new):
    value=facts();event=value.event.data
    request={'policy_id':event['policy_id'],'policy_revision':1,'policy_revision_sha256':event['policy_revision_sha256'],'policy_state_version':1}
    request[field]=new
    with pytest.raises(StoreConflict):value.candidate(SimpleNamespace(**request),Row(Key('state','candidate'),2,{'latest_revision':2}),Row(Key('state','revision'),1,{'sha256':event['policy_revision_sha256']}))
