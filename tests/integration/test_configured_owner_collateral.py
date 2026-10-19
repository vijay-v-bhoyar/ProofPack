"""Actual configured ASGI/local-store collateral boundary; synthetic identity and STS/S3."""
from dataclasses import replace
from uuid import uuid4
import pytest
import test_configured_owner_review as baseline
from test_configured_owner_review import configured_review_case
from test_access_lifecycle import world,repository_factory,publication_case
from test_composition import composition_case
from test_owner_collateral_review import BOUNDS
from proofpack.evidence.repository import Key,Write
from proofpack.evidence.privacy_admission import REGISTRY

@pytest.fixture(autouse=True)
def configured_collateral(monkeypatch):
 original=baseline.configuration
 monkeypatch.setattr(baseline,'configuration',lambda:replace(original(),collateral_limits=BOUNDS))

def test_real_configured_factory_shares_limits_and_delivers_minimized_scope_without_business_writes(configured_review_case,monkeypatch):
 app,client,headers,path,body,request=configured_review_case;service=app.state.owner_metadata_review_service
 assert service.collateral_limits is BOUNDS and service.requests is app.state.owner_metadata_service
 assert service.reader.resource_owner is service.requests.resource_owner is app.state.resource_owner
 assert service.reader.tick is service.requests.tick_ns
 repository=service.requests.repository;original=repository.transact;seen=[]
 def guarded(writes,checks=()):
  assert all(w.key==REGISTRY for w in writes),'collateral read mutated business metadata'
  seen.extend(writes);return original(writes,checks)
 monkeypatch.setattr(repository,'transact',guarded)
 context=client.get('/api/v1/privacy/metadata-requests/context');assert context.status_code==200 and context.json()['collateral_review_available'] is True
 response=client.post(path.removesuffix('/review')+'/collateral-scope-proposal',json=body,headers=headers);assert response.status_code==200,response.text
 r=response.json();assert r['id']==request['id'] and r['scope_sha256']==request['scope_sha256']
 assert r['original_inspection_ids']==request['inspection_ids'] and r['proposed_inspection_ids']==request['inspection_ids'] and not r['additional_inspection_ids']
 assert r['implicated_records']>0 and r['unresolved_records']>0 and r['implicated_records']+r['unresolved_records']<=r['total_records']
 assert all(r[k] is False for k in ['scope_changed','can_confirm_cleanup','erasure_complete','request_fulfilled']) and seen
 assert not repository.snapshot((REGISTRY,))[REGISTRY].data['active']

def test_real_configured_post_reader_phantom_withholds_entire_collateral_response(configured_review_case,monkeypatch):
 app,client,headers,path,body,_=configured_review_case;service=app.state.owner_metadata_review_service;original=service.reader.read_scope_proposal;changed=[]
 def phantom(**kwargs):
  result=original(**kwargs);service.requests.repository.transact((Write(Key('state','future-collateral#'+str(uuid4())),None,{'private':'NEVER_DISCLOSE'}),));changed.append(True);return result
 monkeypatch.setattr(service.reader,'read_scope_proposal',phantom)
 response=client.post(path.removesuffix('/review')+'/collateral-scope-proposal',json=body,headers=headers)
 assert response.status_code==503 and response.json()['code']=='METADATA_REVIEW_HELD' and changed==[True]
 assert all(text not in response.text for text in ['NEVER_DISCLOSE','future-collateral#','proposed_inspection_ids','original_inspection_ids'])
 assert not service.requests.repository.snapshot((REGISTRY,))[REGISTRY].data['active']
