"""Protected app/ASGI/domain/private-reader protocol over modeled storage only."""
from dataclasses import replace
from fastapi.testclient import TestClient
import pytest
from test_owner_accounting_review import world,no_sdk
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.service import IdentityProof
from proofpack.evidence.privacy_admission import AdmissionConfiguration,REGISTRY
from proofpack.evidence.privacy_http import _control_route,MetadataAdmissionBoundary
from proofpack.evidence.held_corpus import HeldCorpusHeld

ORIGIN='https://proofpack.example.invalid'
BASE='/api/v1/privacy/metadata-requests'


def client_world(monkeypatch,*,enabled=True):
    w=world(monkeypatch,max_lease_ms=20000);review,requests,reader,actor,repo,data,clock,original,owner=w
    cfg=requests.access.config
    proof=IdentityProof(cfg.issuer,'owner','owner@example.invalid',True,True,clock.value,clock.value+3_600_000,'Synthetic owner')
    credentials=requests.access.login(proof)
    app=create_app(owner_metadata_service=requests,owner_metadata_review_service=review if enabled else None,
        metadata_admission=requests.admission,admission_configuration=AdmissionConfiguration(8,20000,20000,500,3,'c'*64),
        resource_owner=owner,access_service=requests.access,app_origin=ORIGIN,runtime_control=requests.runtime,manage_service_lifecycle=False)
    client=TestClient(app,base_url=ORIGIN);client.cookies.set(COOKIE,credentials.cookie)
    body={'expected_request_version':original['state_version'],'expected_gate_version':original['gate_version'],
        'expected_control_version':original['control_version']}
    return w,client,{'Origin':ORIGIN,'X-CSRF-Token':credentials.csrf},BASE+'/'+original['id']+'/review',body


def test_held_review_uses_actual_private_reader_and_exact_control_lifetime(monkeypatch):
    w,client,headers,path,body=client_world(monkeypatch);before={k:v for k,v in w[5].items() if k!=REGISTRY}
    with client:
        response=client.post(path,json=body,headers=headers)
        assert response.status_code==200,response.text
        result=response.json()
        assert result['id']==w[7]['id'] and result['scope_sha256']==w[7]['scope_sha256']
        assert sum(result['counts'].values())==result['total_records']
        assert result['counts']['AFFECTED']>0 and result['counts']['UNRESOLVED']>0
        assert result['historical'] is True and result['read_only'] is True
        assert all(result[k] is False for k in ['can_confirm_cleanup','erasure_complete','request_fulfilled'])
        assert not any(secret in response.text for secret in ['session#','idempotency#','DO_NOT_DISCLOSE','example.invalid'])
        assert client.get('/api/v1/users').status_code==503
    assert before=={k:v for k,v in w[5].items() if k!=REGISTRY}
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('fault',['missing','csrf','origin','role','mfa','revoked'])
def test_http_authority_and_origin_are_enforced_before_inventory(monkeypatch,fault):
    w,client,headers,path,body=client_world(monkeypatch)
    monkeypatch.setattr(w[2],'read_accounting',lambda **kw:pytest.fail('denied request reached private inventory'))
    if fault=='missing':client.cookies.clear()
    elif fault=='csrf':headers.pop('X-CSRF-Token')
    elif fault=='origin':headers['Origin']='https://foreign.invalid'
    elif fault=='mfa':w[6].value+=601000
    else:
        row=w[5][w[3].member.key];values={'roles':['operator']} if fault=='role' else {'enabled':False}
        w[5][row.key]=replace(row,revision=row.revision+1,data={**row.data,**values})
    with client:response=client.post(path,json=body,headers=headers)
    assert response.status_code in {401,403},response.text
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('update',[{'expected_request_version':True},{'expected_gate_version':'1'},
    {'expected_control_version':0},{'expected_control_version':2**53},{'inspection_ids':[]},{'proof':{}},
    {'can_confirm_cleanup':True},{'scope_sha256':'a'*64}])
def test_review_body_is_closed_and_strict(monkeypatch,update):
    w,client,headers,path,body=client_world(monkeypatch)
    monkeypatch.setattr(w[2],'read_accounting',lambda **kw:pytest.fail('malformed request reached inventory'))
    with client:response=client.post(path,json=body|update,headers=headers)
    assert response.status_code==400,response.text
    assert response.json()['code']=='INVALID_REQUEST' and response.json()['retryable'] is False
    assert set(response.json())=={'code','safe_message','request_id','retryable'}
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)


def test_held_inventory_failure_is_minimized_and_never_a_success(monkeypatch):
    w,client,headers,path,body=client_world(monkeypatch)
    def held(**kw):raise HeldCorpusHeld('PRIVATE-ROW session#secret idempotency#secret')
    monkeypatch.setattr(w[2],'read_accounting',held)
    with client:response=client.post(path,json=body,headers=headers)
    assert response.status_code==503 and response.json()['code']=='METADATA_REVIEW_HELD'
    assert set(response.json())=={'code','safe_message','request_id','retryable'} and response.json()['retryable'] is True
    assert not any(s in response.text for s in ['PRIVATE-ROW','session#','idempotency#'])
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)


def test_disabled_review_retains_ordinary_held_admission(monkeypatch):
    w,client,headers,path,body=client_world(monkeypatch,enabled=False)
    with client:response=client.post(path,json=body,headers=headers)
    assert response.status_code==503
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)


def test_review_preserves_existing_body_and_stale_version_guards(monkeypatch):
    w,client,headers,path,body=client_world(monkeypatch)
    with client:
        assert client.post(path,json=body|{'expected_request_version':999},headers=headers).status_code==409
        assert client.post(path,content=b'x'*8193,headers=headers|{'Content-Type':'application/json'}).status_code==413
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('method',['GET','PUT','DELETE','PATCH','HEAD','OPTIONS'])
def test_only_explicit_post_review_uses_control_admission(method):
    path=BASE+'/00000000-0000-0000-0000-000000000001/review'
    assert not _control_route({'method':method,'path':path,'raw_path':path.encode()},owner_review=True)


@pytest.mark.parametrize('change',['disabled','encoded','uppercase','suffix','slash','foreign'])
def test_review_control_selector_never_accepts_alternate_or_unconfigured_paths(change):
    path=BASE+'/00000000-0000-0000-0000-00000000000a/review';raw=path.encode();enabled=True
    if change=='disabled':enabled=False
    elif change=='encoded':raw=raw.replace(b'review',b'%72eview')
    elif change=='uppercase':path=path.replace('000a/','000A/');raw=path.encode()
    elif change=='suffix':path+='/cleanup';raw=path.encode()
    elif change=='slash':path+='/';raw=path.encode()
    else:path='/api/v1/privacy/jobs/'+path.split('/')[-2]+'/review';raw=path.encode()
    assert not _control_route({'method':'POST','path':path,'raw_path':raw},owner_review=enabled)


def test_control_review_requires_explicit_typed_owner_control_and_resources(monkeypatch):
    w=world(monkeypatch)
    with pytest.raises(ValueError):MetadataAdmissionBoundary(lambda *a:None,admission=w[1].admission,
        lease_ms=500,attempts=3,resource_owner=w[-1],owner_review=True)
    with pytest.raises(ValueError):MetadataAdmissionBoundary(lambda *a:None,admission=w[1].admission,
        lease_ms=500,attempts=3,resource_owner=w[-1],owner_control=True,owner_review=1)


@pytest.mark.parametrize('fault',['foreign','absent_owner','resource','short_lease','untyped','changed_pin'])
def test_app_review_dependency_is_exact_and_original_lease_is_sufficient(monkeypatch,fault):
    w=world(monkeypatch,max_lease_ms=20000);other=world(monkeypatch,max_lease_ms=20000)
    options=dict(owner_metadata_service=w[1],owner_metadata_review_service=w[0],metadata_admission=w[1].admission,
        admission_configuration=AdmissionConfiguration(8,20000,20000,500,3,'c'*64),resource_owner=w[-1],
        access_service=w[1].access,app_origin=ORIGIN,runtime_control=w[1].runtime,manage_service_lifecycle=False)
    if fault=='foreign':options['owner_metadata_review_service']=other[0]
    elif fault=='absent_owner':options['owner_metadata_service']=None
    elif fault=='resource':options['resource_owner']=other[-1]
    elif fault=='short_lease':options['admission_configuration']=AdmissionConfiguration(8,20000,500,500,3,'c'*64)
    elif fault=='untyped':options['owner_metadata_review_service']=object()
    else:w[0]._initial=(other[1],*w[0]._initial[1:])
    with pytest.raises(ValueError):create_app(**options)


@pytest.mark.parametrize('fault',['bool_count','negative','unsafe','private_outer','private_count','cleanup','erased',
    'fulfilled','current','writable','sum','policy','bool_version'])
def test_review_response_contract_is_closed_strict_and_non_authorizing(fault):
    from pydantic import ValidationError
    from proofpack.evidence.owner_metadata_http import ReviewResult
    from proofpack.evidence.corpus_accounting import POLICY
    data={'id':'00000000-0000-0000-0000-000000000001','scope_sha256':'a'*64,
        'request_version':1,'gate_version':1,'control_version':1,'accounting_policy':POLICY,
        'counts':{'AFFECTED':1,'SHARED':0,'CONTEXT':0,'UNRELATED':0,'UNRESOLVED':0},'total_records':1,
        'historical':True,'read_only':True,'can_confirm_cleanup':False,'erasure_complete':False,'request_fulfilled':False}
    assert ReviewResult.model_validate(data).model_dump()==data
    if fault=='bool_count':data['counts']['AFFECTED']=True
    elif fault=='negative':data['counts']['AFFECTED']=-1
    elif fault=='unsafe':data['counts']['AFFECTED']=2**53
    elif fault=='private_outer':data['source_rows']=[{'private':'DO_NOT_DISCLOSE'}]
    elif fault=='private_count':data['counts']['private_reason']='DO_NOT_DISCLOSE'
    elif fault=='cleanup':data['can_confirm_cleanup']=True
    elif fault=='erased':data['erasure_complete']=True
    elif fault=='fulfilled':data['request_fulfilled']=True
    elif fault=='current':data['historical']=False
    elif fault=='writable':data['read_only']=False
    elif fault=='sum':data['total_records']=2
    elif fault=='policy':data['accounting_policy']='unknown'
    else:data['gate_version']=True
    with pytest.raises(ValidationError):ReviewResult.model_validate(data)
