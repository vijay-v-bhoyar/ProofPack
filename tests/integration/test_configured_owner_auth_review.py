"""Genuine configured factory/ASGI/store auth review; synthetic provider identity/media."""
from dataclasses import replace
import pytest
from test_access_lifecycle import world,repository_factory,publication_case
from test_composition import composition_case
import test_configured_owner_review as original
from test_purpose_context_store import RUNTIME
from test_access_context_store import ACCESS
from test_auth_history_consumption_store import AUTH
from proofpack.evidence.owner_metadata_review import AuthReviewLimits
from proofpack.evidence.privacy_admission import REGISTRY
from proofpack.evidence.repository import Key,Write


@pytest.fixture
def configured_auth_case(world,publication_case,composition_case,request,monkeypatch):
    # Existing genuine factory/store fixture, unchanged clocks, limits, HTTP work
    # ownership, service lifecycle and teardown. Only explicit opt-in is new.
    configuration=original.configuration
    group=AuthReviewLimits(RUNTIME,ACCESS,AUTH)
    monkeypatch.setattr(original,'configuration',lambda:replace(configuration(),auth_review=group))
    yield from original.configured_review_case.__wrapped__(world,publication_case,composition_case,request)


def test_factory_http_delivers_exact_minimized_v5_without_business_mutation(configured_auth_case,monkeypatch):
    app,client,headers,path,body,request=configured_auth_case
    service=app.state.owner_metadata_review_service;repository=service.requests.repository
    assert service.auth_review is not None and service.reader.admission is app.state.metadata_admission
    original_write=repository.transact;writes=[]
    def guarded(changes,checks=()):
        assert all(w.key==REGISTRY for w in changes),'owner review mutated business history'
        writes.extend(changes);return original_write(changes,checks)
    monkeypatch.setattr(repository,'transact',guarded)
    response=client.post(path,json=body,headers=headers)
    assert response.status_code==200,response.text
    value=response.json()
    assert set(value)=={'id','scope_sha256','request_version','gate_version','control_version','accounting_policy',
        'counts','total_records','historical','read_only','can_confirm_cleanup','erasure_complete','request_fulfilled',
        'auth_history_policy_resolved','historical_auth_authority_proven'}
    assert value['id']==request['id'] and value['scope_sha256']==request['scope_sha256']
    assert value['accounting_policy']=='conservative-family-accounting-v5'
    assert value['historical'] is True and value['read_only'] is True
    assert all(value[k] is False for k in ['can_confirm_cleanup','erasure_complete','request_fulfilled',
        'auth_history_policy_resolved','historical_auth_authority_proven'])
    assert sum(value['counts'].values())==value['total_records'] and value['counts']['UNRESOLVED']>0
    assert writes and not repository.snapshot((REGISTRY,))[REGISTRY].data['active']
    assert not any(secret in response.text for secret in ['session#','cookie#','family_digests','result_json','example.invalid'])


@pytest.mark.parametrize('fault',['origin','cookie','stale'])
def test_configured_auth_request_is_denied_before_inventory(configured_auth_case,monkeypatch,fault):
    app,client,headers,path,body,_=configured_auth_case
    monkeypatch.setattr(app.state.owner_metadata_review_service.reader,'read_auth_accounting',
        lambda **kw:pytest.fail('denied configured auth request reached inventory'))
    if fault=='origin':headers=headers|{'Origin':'https://foreign.invalid'}
    elif fault=='cookie':client.cookies.clear()
    else:body=body|{'expected_request_version':999}
    response=client.post(path,json=body,headers=headers)
    assert response.status_code=={'origin':403,'cookie':401,'stale':409}[fault],response.text


def test_final_auth_source_race_has_no_partial_success_or_private_error(configured_auth_case,monkeypatch):
    app,client,headers,path,body,_=configured_auth_case;service=app.state.owner_metadata_review_service
    original_read=service.reader.read_auth_accounting;changed=[]
    def phantom(**kw):
        result=original_read(**kw)
        service.requests.repository.transact((Write(Key('state','unknown-auth-review#'+path.split('/')[-2]),None,
            {'private':'NEVER_DISCLOSE_AUTH_REVIEW'}),))
        changed.append(True);return result
    monkeypatch.setattr(service.reader,'read_auth_accounting',phantom)
    response=client.post(path,json=body,headers=headers)
    assert response.status_code==503 and response.json()['code']=='METADATA_REVIEW_HELD'
    assert changed==[True] and 'NEVER_DISCLOSE_AUTH_REVIEW' not in response.text
