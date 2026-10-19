"""Protected owner ASGI dispatch with genuine modeled domain/history reads."""
from dataclasses import replace
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_owner_policy_obligations import configured,no_sdk
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from proofpack.auth.service import IdentityProof
from proofpack.evidence.privacy_admission import AdmissionConfiguration,REGISTRY
from proofpack.evidence.privacy_http import _control_route
from proofpack.evidence.owner_metadata_http import PolicyObligationsResult

ORIGIN='https://proofpack.example.invalid';BASE='/api/v1/privacy/metadata-requests'
def fixture(monkeypatch):
    w=configured(monkeypatch);s,requests,reader,actor,repo,data,_,original,owner=w
    credentials=requests.access.login(IdentityProof(requests.access.config.issuer,'synthetic-origin',
        'origin@example.test',True,True,100,400,'Synthetic owner'))
    app=create_app(owner_metadata_service=requests,owner_metadata_review_service=s,metadata_admission=requests.admission,
        admission_configuration=AdmissionConfiguration(8,20000,20000,500,3,'a'*64),resource_owner=owner,
        access_service=requests.access,app_origin=ORIGIN,runtime_control=requests.runtime,manage_service_lifecycle=False)
    client=TestClient(app,base_url=ORIGIN);client.cookies.set(COOKIE,credentials.cookie)
    body=dict(expected_request_version=original['state_version'],expected_gate_version=original['gate_version'],expected_control_version=original['control_version'])
    return w,client,dict(Origin=ORIGIN,**{'X-CSRF-Token':credentials.csrf}),BASE+'/'+original['id']+'/policy-obligations',body

def test_configured_protected_read_has_only_expected_registry_bookkeeping(monkeypatch):
    w,client,headers,path,body=fixture(monkeypatch)
    before={k:v for k,v in w[5].items() if k!=REGISTRY};registry=w[5][REGISTRY]
    with client:response=client.post(path,json=body,headers=headers)
    assert response.status_code==200,response.text
    value=response.json();assert PolicyObligationsResult.model_validate(value).model_dump()==value
    assert value['source_records']>=value['validated_auth_records']>0
    assert value['id']==w[7]['id'] and value['scope_sha256']==w[7]['scope_sha256']
    assert before=={k:v for k,v in w[5].items() if k!=REGISTRY}
    assert w[5][REGISTRY].revision==registry.revision+2 and w[5][REGISTRY].data==registry.data
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)

@pytest.mark.parametrize('fault',['missing','csrf','origin','role','stale','query','extra'])
def test_denial_happens_without_policy_inventory_or_payload_delivery(monkeypatch,fault):
    w,client,headers,path,body=fixture(monkeypatch)
    monkeypatch.setattr(w[2],'read_auth_accounting',lambda **k:pytest.fail('denied policy read reached private inventory'))
    if fault=='missing':client.cookies.clear()
    elif fault=='csrf':headers.pop('X-CSRF-Token')
    elif fault=='origin':headers['Origin']='https://foreign.invalid'
    elif fault=='role':
        row=w[5][w[3].member.key];w[5][row.key]=replace(row,revision=row.revision+1,data={**row.data,'roles':['operator']})
    elif fault=='stale':body['expected_request_version']+=1
    elif fault=='query':path+='?family=session'
    elif fault=='extra':body['family']='session'
    with client:response=client.post(path,json=body,headers=headers)
    if fault=='extra':
        assert response.status_code==400 and response.json()['code']=='INVALID_REQUEST',response.text
    else:
        assert response.status_code in {401,403,409,422,503},response.text
    assert 'family_counts' not in response.text
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)

@pytest.mark.parametrize('fault',['method','encoded','suffix','query','disabled'])
def test_no_general_held_path_exemption(fault):
    path=BASE+'/00000000-0000-0000-0000-000000000001/policy-obligations'
    scope=dict(type='http',method='POST',path=path,raw_path=path.encode(),query_string=b'')
    if fault=='method':scope['method']='GET'
    elif fault=='encoded':scope['raw_path']=path.replace('policy','%70olicy').encode()
    elif fault=='suffix':scope['path']+='/';scope['raw_path']+=b'/'
    elif fault=='query':scope['query_string']=b'family=session'
    assert not _control_route(scope,owner_review=fault!='disabled')
