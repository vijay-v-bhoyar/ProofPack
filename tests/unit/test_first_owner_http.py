"""Actual ASGI auth routes with the offline signed-provider fixture."""
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from test_first_owner import signing, setup, owner, head
from proofpack.app import create_app
from proofpack.auth.http import FLOW_COOKIE, COOKIE
from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionConfiguration, AdmissionLimits
from proofpack.runtime.control import RuntimeControl
from proofpack.runtime.ownership import ResourceOwner

OWNER_COOKIE='__Host-proofpack-owner-setup'
ORIGIN='https://proofpack.example.test'


def browser(w, *, enabled=True):
    runtime=RuntimeControl(w.access,instance_id='00000000-0000-4000-8000-000000000041',
        artifact_sha256=w.fence.config.artifact_sha256,controls_sha256='c'*64,environment='test')
    runtime.start()
    bounds=AdmissionConfiguration(8,300000,60000,120000,3,'a'*64)
    admission=PersistentAdmission(runtime,limits=AdmissionLimits(bounds.max_active,bounds.max_lease_ms),clock_ms=lambda:w.clock[0])
    admission.initialize(bounds.enrollment_sha256)
    app=create_app(access_service=w.access,signin_service=w.ordinary,app_origin=ORIGIN,
        owner_setup_service=owner(w) if enabled else None,data_fence=w.fence,
        runtime_control=runtime,metadata_admission=admission,admission_configuration=bounds,resource_owner=ResourceOwner())
    return TestClient(app,base_url=ORIGIN,follow_redirects=False)


def begin(w,client):
    result=client.get('/api/v1/auth/setup-owner')
    assert result.status_code==303
    parts=parse_qs(urlsplit(result.headers['location']).query)
    w.nonce=parts['nonce'][0]
    assert parts['acr_values']==['urn:cognito:loa:4']
    assert parts['max_age']==['600']
    return parts['state'][0]


def test_explicit_setup_round_trip_has_secure_distinct_cookie_and_current_owner(signing):
    w=setup(signing)
    with browser(w) as client:
        state=begin(w,client)
        assert client.cookies.get(OWNER_COOKIE) and not client.cookies.get(FLOW_COOKIE)
        result=client.get('/api/v1/auth/callback',params={'state':state,'code':'offline-code'})
        assert result.status_code==303 and result.headers['location']==ORIGIN+'/'
        assert client.cookies.get(COOKIE) and not client.cookies.get(OWNER_COOKIE)
        for header in result.headers.get_list('set-cookie'):
            assert 'Secure' in header and 'HttpOnly' in header and 'SameSite=lax' in header and 'Path=/' in header
        assert result.headers['cache-control']=='no-store'
        assert result.headers['referrer-policy']=='no-referrer'
        assert head(w).data['owner_ids']==[head(w).data['bootstrap_user_id']]


@pytest.mark.parametrize('query',[{'subject':'owner'},{'receipt':'a'*64},{'role':'owner'},{'invitation_id':'x'},{'mfa':'optional'}])
def test_owner_start_rejects_all_client_authority_fields(signing,query):
    w=setup(signing)
    with browser(w) as client:
        result=client.get('/api/v1/auth/setup-owner',params=query)
        assert result.status_code==400 and head(w) is None and w.requests==[]
        assert 'location' not in result.headers


def test_owner_start_is_unavailable_without_explicit_service(signing):
    w=setup(signing)
    with browser(w,enabled=False) as client:
        result=client.get('/api/v1/auth/setup-owner')
        assert result.status_code==503 and head(w) is None and w.requests==[]


def test_normal_login_clears_setup_cookie_and_setup_clears_normal_cookie(signing):
    w=setup(signing)
    with browser(w) as client:
        begin(w,client)
        result=client.get('/api/v1/auth/login')
        assert result.status_code==303 and client.cookies.get(FLOW_COOKIE) and not client.cookies.get(OWNER_COOKIE)
        begin(w,client)
        assert client.cookies.get(OWNER_COOKIE) and not client.cookies.get(FLOW_COOKIE)


def test_ambiguous_callback_rejects_both_cookies_without_provider_exchange(signing):
    w=setup(signing)
    with browser(w) as client:
        state=begin(w,client)
        result=client.get('/api/v1/auth/callback',params={'state':state,'code':'offline-code'},
            headers={'Cookie':OWNER_COOKIE+'='+client.cookies.get(OWNER_COOKIE)+'; '+FLOW_COOKIE+'='+'a'*43})
        assert result.status_code==403 and w.requests==[] and head(w) is None
        assert not client.cookies.get(OWNER_COOKIE)


def test_ordinary_cookie_cannot_select_owner_setup_and_error_clears_both(signing):
    w=setup(signing)
    with browser(w) as client:
        state=begin(w,client);value=client.cookies.get(OWNER_COOKIE);client.cookies.clear()
        result=client.get('/api/v1/auth/callback',params={'state':state,'code':'offline-code'},headers={'Cookie':FLOW_COOKIE+'='+value})
        assert result.status_code==403 and w.requests==[] and head(w) is None
        assert {h.split('=',1)[0] for h in result.headers.get_list('set-cookie')} >= {OWNER_COOKIE,FLOW_COOKIE}


def test_setup_callback_provider_error_is_redacted_and_never_bootstraps(signing):
    w=setup(signing)
    with browser(w) as client:
        state=begin(w,client)
        result=client.get('/api/v1/auth/callback',params={'state':state,'error':'access_denied','error_description':'private-description'})
        assert result.status_code==403 and w.requests==[] and head(w) is None
        assert 'private-description' not in result.text and state not in result.text
        assert not client.cookies.get(OWNER_COOKIE)


def test_app_rejects_setup_from_different_signin_owner(signing):
    w=setup(signing);foreign=setup(signing)
    with pytest.raises(ValueError):
        create_app(access_service=w.access,signin_service=w.ordinary,app_origin=ORIGIN,owner_setup_service=owner(foreign))


@pytest.mark.parametrize('path', ['/api/v1/auth/setup-owner?subject=x&subject=y',
    '/api/v1/auth/setup-owner?subject=%XX', '/api/v1/auth/callback?state=%XX&code=private-code'])
def test_malformed_setup_requests_clear_both_cookies_without_echo(signing,path):
    w=setup(signing)
    with browser(w) as client:
        begin(w,client)
        response=client.get(path)
        assert response.status_code==400 and w.requests==[] and head(w) is None
        assert 'private-code' not in response.text and '%XX' not in response.text
        assert {h.split('=',1)[0] for h in response.headers.get_list('set-cookie')} >= {OWNER_COOKIE,FLOW_COOKIE}


def test_protected_release_revocation_denies_setup_before_provider_or_owner(signing):
    w=setup(signing)
    with browser(w) as client:
        w.client.items.pop(w.ids[2])
        response=client.get('/api/v1/auth/setup-owner')
        assert response.status_code==503 and w.requests==[]
        assert 'location' not in response.headers and 'set-cookie' not in response.headers
