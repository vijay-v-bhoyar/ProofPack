from dataclasses import replace
import hashlib,json
import pytest
from types import SimpleNamespace
from dataclasses import asdict
from proofpack.review.policy_qualification import QualificationRequest,QualificationConfig
from proofpack.review.policy_qualification import PolicyQualifications
from proofpack.planner import contract_registry
from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.policy import DEFAULT_PRIORITY
from proofpack.calibrations.dependencies import canonical
from proofpack.evidence.repository import StoreUnavailable
from proofpack.review.evaluation_models import EvaluationConfig
from proofpack.evidence.job_authority import scope_sha256

BODY={'mode':'installed_default','policy_id':'a1000000-0000-4000-8000-000000000001','policy_revision':1,'policy_state_version':1,
    'policy_revision_sha256':'a'*64,'synthetic_demo_acknowledged':True}


@pytest.mark.parametrize('field,value',[
    ('synthetic_demo_acknowledged',False),('synthetic_demo_acknowledged',1),('synthetic_demo_acknowledged','true'),
    ('policy_revision',True),('policy_revision','1'),('policy_revision',1001),('policy_state_version',0),
    ('mode','candidate'),('mode','physical'),('qualified',True),('promotion_eligible',True),('independent_benchmark_qualified',True),
    ('preparation_id',BODY['policy_id']),('preparation_state_version',1),('preparation_report_sha256','b'*64),('policy_revision_sha256','bad')])
def test_qualification_request_rejects_coercion_incoherent_sources_and_success_flags(field,value):
    with pytest.raises(ValueError):QualificationRequest.model_validate_json(json.dumps({**BODY,field:value}))


def test_candidate_request_requires_all_exact_preparation_bindings():
    body={**BODY,'mode':'candidate','preparation_id':BODY['policy_id'],'preparation_state_version':2,'preparation_report_sha256':'b'*64}
    assert QualificationRequest.model_validate_json(json.dumps(body)).mode=='candidate'
    for key in ('preparation_id','preparation_state_version','preparation_report_sha256'):
        with pytest.raises(ValueError):QualificationRequest.model_validate_json(json.dumps({k:v for k,v in body.items() if k!=key}))


@pytest.mark.parametrize('cases,window',[(True,15000),(0,15000),(10001,15000),(1000,True),(1000,999),(1000,15001)])
def test_qualification_config_requires_explicit_original_case_and_time_bounds(cases,window):
    with pytest.raises(ValueError):QualificationConfig(EvaluationConfig(20,120,120,3600000,15000,1200),cases,window)


def job():
    text=json.dumps(BODY,sort_keys=True)
    return {'id':BODY['policy_id'],'kind':'policy_qualification','requested_by':BODY['policy_id'],'configuration':'a'*64,'data_epoch':1,
        'artifact_sha256':'a'*64,'controls_sha256':'b'*64,'environment':'synthetic_demo','created_at_ms':1,'expires_at_ms':1000,
        'request_json':text,'request_sha256':hashlib.sha256(text.encode()).hexdigest(),'example_count':13,'validation_runtime':{'runtime_epoch':1},
        'control_version':1,'registry_sha256':'c'*64,'software_cases':170,'source_examples':0,'preparation_count':0,'preparation_pages':0,
        'required_case_count':182,'golden_cases':12,'golden_manifest_sha256':'d'*64}


@pytest.mark.parametrize('field',['validation_runtime','control_version','registry_sha256','software_cases','source_examples','preparation_count',
    'preparation_pages','required_case_count','golden_cases','golden_manifest_sha256'])
def test_processing_authority_binds_entire_original_qualification_plan(field):
    original=job();changed=dict(original);value=changed[field]
    changed[field]={'runtime_epoch':2} if isinstance(value,dict) else 'f'*64 if isinstance(value,str) else value+1
    assert scope_sha256(changed)!=scope_sha256(original)


def test_qualification_progress_does_not_renew_original_signed_scope():
    original=job();changed={**original,'processed':7,'steps_reserved':8,'cases_reserved':177,'lease_until_ms':200,'status':'processing'}
    assert scope_sha256(original)==scope_sha256(changed)


def test_candidate_preparation_case_identity_survives_json_roundtrip_but_not_altered_values():
    service=object.__new__(PolicyQualifications);service.cases=contract_registry.installed_cases()
    spec=PolicyDraft(name='Roundtrip',algorithm='reason_priority_v1',priority=DEFAULT_PRIORITY)
    entries=[]
    for case in service.cases[:20]:
        expected=contract_registry.expected_result(case,spec)
        entries.append(json.loads(canonical({'phase':'software_contract','case':asdict(case),'expected':expected,'actual':expected,'passed':True,'error':None})))
    service.preparations=SimpleNamespace(entries=lambda *args,**kwargs:{'entries':entries})
    service._request=lambda row:SimpleNamespace(mode='candidate',preparation_id=BODY['policy_id'])
    row=SimpleNamespace(data={'preparation_pages':9,'source_examples':1})
    result=service._execute(None,row,SimpleNamespace(data={'spec':spec.model_dump(mode='json')}),0,lambda:None)
    assert result[1:4]==(20,0,0)
    entries[0]['case']['id']='different-case'
    with pytest.raises(StoreUnavailable):service._execute(None,row,SimpleNamespace(data={'spec':spec.model_dump(mode='json')}),0,lambda:None)
