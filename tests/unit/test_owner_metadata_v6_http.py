"""Protected ASGI read reaches actual v6 history; synthetic identity/store only."""
from copy import deepcopy
from dataclasses import replace
import pytest
from test_owner_metadata_v6 import configured,no_sdk
import test_owner_policy_http as transport
from proofpack.evidence.owner_metadata_http import MetadataPolicyObligationsResult,MetadataReviewResult
from proofpack.evidence.privacy_admission import REGISTRY


def fixture(monkeypatch):
    monkeypatch.setattr(transport,'configured',configured)
    return transport.fixture(monkeypatch)


@pytest.mark.parametrize('operation',['review','policy-obligations'])
def test_current_protected_transport_delivers_v6_with_only_registry_bookkeeping(monkeypatch,operation):
    w,client,headers,path,body=fixture(monkeypatch);path=path.rsplit('/',1)[0]+'/'+operation
    before=deepcopy({k:v for k,v in w[5].items() if k!=REGISTRY});registry=w[5][REGISTRY]
    with client:response=client.post(path,json=body,headers=headers)
    assert response.status_code==200,response.text
    value=response.json();model=MetadataReviewResult if operation=='review' else MetadataPolicyObligationsResult
    assert model.model_validate(value).model_dump()==value and value['accounting_policy']=='conservative-family-accounting-v6'
    assert before=={k:v for k,v in w[5].items() if k!=REGISTRY}
    assert w[5][REGISTRY].revision==registry.revision+2 and w[5][REGISTRY].data==registry.data
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)


@pytest.mark.parametrize('fault',['missing','csrf','origin','role','stale','query','extra'])
def test_v6_keeps_original_owner_csrf_origin_and_fresh_scope_denials(monkeypatch,fault):
    w,client,headers,path,body=fixture(monkeypatch)
    monkeypatch.setattr(w[2],'read_metadata_accounting',lambda **k:pytest.fail('denied v6 request reached inventory'))
    if fault=='missing':client.cookies.clear()
    elif fault=='csrf':headers.pop('X-CSRF-Token')
    elif fault=='origin':headers['Origin']='https://foreign.invalid'
    elif fault=='role':
        row=w[5][w[3].member.key];w[5][row.key]=replace(row,revision=row.revision+1,data={**row.data,'roles':['operator']})
    elif fault=='stale':body['expected_request_version']+=1
    elif fault=='query':path+='?family=metadata-request'
    else:body['metadata_review']=True
    with client:response=client.post(path,json=body,headers=headers)
    if fault=='extra':assert response.status_code==400 and response.json()['code']=='INVALID_REQUEST',response.text
    else:assert response.status_code in {401,403,409,422,503},response.text
    assert 'metadata_family_counts' not in response.text
    assert not w[5][REGISTRY].data['active'] and w[-1].wait_for_drain(0)
