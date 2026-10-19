"""Configured protected collateral transport on actual ASGI and modeled state only."""
from dataclasses import replace
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_owner_accounting_review import world,no_sdk,LIMITS
from test_owner_collateral_review import BOUNDS
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview
from proofpack.evidence.privacy_admission import AdmissionConfiguration,REGISTRY
from proofpack.evidence.privacy_http import _control_route,MetadataAdmissionBoundary
from proofpack.app import create_app
from proofpack.auth.service import IdentityProof
from proofpack.auth.http import COOKIE

ORIGIN='https://proofpack.example.invalid';BASE='/api/v1/privacy/metadata-requests'
def fixture(monkeypatch,enabled=True):
 w=world(monkeypatch,max_lease_ms=20000);old,requests,reader,actor,repo,data,clock,original,owner=w
 service=OwnerMetadataReview(requests,reader,accounting_limits=LIMITS,max_response_bytes=8192,collateral_limits=BOUNDS if enabled else None)
 proof=IdentityProof(requests.access.config.issuer,'owner','owner@example.invalid',True,True,clock.value,clock.value+3600000,'Synthetic owner')
 credentials=requests.access.login(proof)
 app=create_app(owner_metadata_service=requests,owner_metadata_review_service=service,metadata_admission=requests.admission,
  admission_configuration=AdmissionConfiguration(8,20000,20000,500,3,'c'*64),resource_owner=owner,access_service=requests.access,app_origin=ORIGIN,runtime_control=requests.runtime,manage_service_lifecycle=False)
 client=TestClient(app,base_url=ORIGIN);client.cookies.set(COOKIE,credentials.cookie)
 body={'expected_request_version':original['state_version'],'expected_gate_version':original['gate_version'],'expected_control_version':original['control_version']}
 return w,client,{'Origin':ORIGIN,'X-CSRF-Token':credentials.csrf},BASE+'/'+original['id']+'/collateral-scope-proposal',body

def test_exact_configured_endpoint_returns_non_authorizing_scope_and_no_business_writes(monkeypatch):
 w,client,headers,path,body=fixture(monkeypatch);before={k:v for k,v in w[5].items() if k!=REGISTRY}
 with client:
  response=client.post(path,json=body,headers=headers);assert response.status_code==200,response.text
  r=response.json();assert r['id']==w[7]['id'] and r['scope_sha256']==w[7]['scope_sha256']
  assert r['historical'] is r['read_only'] is True and r['implicated_records']>0 and r['unresolved_records']>0
  assert all(r[k] is False for k in ['scope_changed','can_confirm_cleanup','erasure_complete','request_fulfilled'])
  assert r['additional_inspection_ids']==sorted(set(r['proposed_inspection_ids'])-set(r['original_inspection_ids']))
 assert before=={k:v for k,v in w[5].items() if k!=REGISTRY} and not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)
@pytest.mark.parametrize('enabled',[False,True])
def test_owner_context_only_advertises_explicit_configuration(monkeypatch,enabled):
 w,c,h,p,b=fixture(monkeypatch,enabled)
 with c:r=c.get(BASE+'/context')
 assert r.status_code==200
 if enabled:assert r.json()['collateral_review_available'] is True
 else:assert 'collateral_review_available' not in r.json()
@pytest.mark.parametrize('fault',['cookie','csrf','origin','role','mfa','stale','disabled'])
def test_authentication_and_configuration_deny_before_inventory(monkeypatch,fault):
 w,c,h,p,b=fixture(monkeypatch,fault!='disabled');monkeypatch.setattr(w[2],'read_scope_proposal',lambda **kw:pytest.fail('denied request read inventory'))
 if fault=='cookie':c.cookies.clear()
 if fault=='csrf':h.pop('X-CSRF-Token')
 if fault=='origin':h['Origin']='https://foreign.invalid'
 if fault=='role':
  r=w[5][w[3].member.key];w[5][r.key]=replace(r,revision=r.revision+1,data={**r.data,'roles':['operator']})
 if fault=='mfa':w[6].value+=601000
 if fault=='stale':b['expected_gate_version']=999
 with c:r=c.post(p,json=b,headers=h)
 assert r.status_code in ({503} if fault=='disabled' else {409} if fault=='stale' else {401,403}),r.text
@pytest.mark.parametrize('update',[{'inspection_ids':[]},{'expected_request_version':True},{'expected_gate_version':0},{'expected_control_version':1.5},{'scope_changed':True}])
def test_request_is_closed_and_strict(monkeypatch,update):
 w,c,h,p,b=fixture(monkeypatch);monkeypatch.setattr(w[2],'read_scope_proposal',lambda **kw:pytest.fail('invalid request read inventory'))
 with c:r=c.post(p,json=b|update,headers=h)
 assert r.status_code==400 and r.json()['code']=='INVALID_REQUEST'
@pytest.mark.parametrize('fault',['suffix','slash','encoded','method','review_disabled','untyped'])
def test_only_exact_opted_in_post_is_control(fault):
 path=BASE+'/00000000-0000-0000-0000-000000000001/collateral-scope-proposal';method='POST';raw=path.encode();review=True;collateral=True
 if fault=='suffix':path+='/unexpected';raw=path.encode()
 if fault=='slash':path+='/';raw=path.encode()
 if fault=='encoded':raw=raw.replace(b'collateral',b'%63ollateral')
 if fault=='method':method='GET'
 if fault=='review_disabled':review=False
 if fault=='untyped':collateral='true'
 assert not _control_route({'path':path,'raw_path':raw,'method':method},owner_review=review,collateral_review=collateral)

def response():
 ident='00000000-0000-0000-0000-000000000001';return dict(id=ident,scope_sha256='a'*64,request_version=1,gate_version=2,control_version=3,
  proposal_policy='whole-artifact-collateral-proposal-v1',original_inspection_ids=[ident],proposed_inspection_ids=[ident],additional_inspection_ids=[],
  implicated_records=1,unresolved_records=2,total_records=3,historical=True,read_only=True,scope_changed=False,can_confirm_cleanup=False,erasure_complete=False,request_fulfilled=False)
@pytest.mark.parametrize('fault',['extra','policy','duplicate','missing_original','additional','negative','bool','unsafe','sum','historical','cleanup','scope_changed','fulfilled'])
def test_response_is_closed_bounded_and_non_authorizing(fault):
 from proofpack.evidence.owner_metadata_http import CollateralResult
 r=response()
 if fault=='extra':r['objects']=['private/key']
 if fault=='policy':r['proposal_policy']='unknown'
 if fault=='duplicate':r['proposed_inspection_ids']*=2
 if fault=='missing_original':r['proposed_inspection_ids']=[]
 if fault=='additional':r['additional_inspection_ids']=r['original_inspection_ids']
 if fault=='negative':r['implicated_records']=-1
 if fault=='bool':r['implicated_records']=True
 if fault=='unsafe':r['total_records']=2**53
 if fault=='sum':r['total_records']=2
 if fault=='historical':r['historical']=False
 if fault=='cleanup':r['can_confirm_cleanup']=True
 if fault=='scope_changed':r['scope_changed']=True
 if fault=='fulfilled':r['request_fulfilled']=True
 with pytest.raises(ValidationError):CollateralResult(**r)
def test_response_positive():
 from proofpack.evidence.owner_metadata_http import CollateralResult
 assert CollateralResult(**response()).model_dump()==response()
