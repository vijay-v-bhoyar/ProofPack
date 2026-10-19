"""Ingress belongs to original configuration approval, not environment defaults."""
import json
import pytest
from urllib.parse import parse_qs,urlsplit
import uvicorn
from fastapi.testclient import TestClient

from test_host import host_files
from test_first_owner import signing,setup,head
from test_first_owner_http import browser
from test_alb_ingress import document,CIDRS,HttpInternalHop,ingress, test_actual_uvicorn_wrapper_only_accepts_fixed_https_origin_from_trusted_peer as exercise_http
from test_fresh_enrollment import world,run,approve_candidate
from proofpack.runtime import host


def test_wildcard_environment_does_not_broaden_configured_or_default_proxy_trust(signing,monkeypatch):
    monkeypatch.setenv('FORWARDED_ALLOW_IPS','*')
    exercise_http(signing,True,'10.24.0.8','https','https://proofpack.example.test',303)
    exercise_http(signing,True,'203.0.113.8','https','https://proofpack.example.test',403)
    exercise_http(signing,False,'10.24.0.8','https','https://proofpack.example.test',403)


def test_ingress_changes_raw_host_and_normalized_release_configuration(host_files):
    path,secret,data,_=host_files
    old=host.load_configuration(path,secret)
    data['ingress']=document();path.write_text(json.dumps(data))
    current=host.load_configuration(path,secret)
    assert current.configuration_sha256!=old.configuration_sha256
    assert current.enrollment_configuration_sha256!=old.enrollment_configuration_sha256
    assert host.enrollment_configuration_sha256(current.config)==current.enrollment_configuration_sha256


def test_prepared_release_cannot_acquire_new_trusted_subnets_without_new_review(host_files):
    w=world(host_files);approve_candidate(w,run(w))
    w.document['ingress']=document();w.path.write_text(json.dumps(w.document))
    changed=host.load_configuration(w.path,w.secret)
    with pytest.raises(host.HostConfigurationError):run(w,commit=True,loaded=changed)
    assert w.client.items=={}
    assert not any(name=='transact_write_items' for name,kwargs in w.client.calls)


def test_signed_owner_callback_keeps_secure_session_through_actual_http_proxy_wrapper(signing):
    w=setup(signing);original=browser(w);app=original.app;original.close();mod=ingress()
    configuration=uvicorn.Config(app,access_log=False,**mod.server_proxy_options(mod.IngressConfig('alb',CIDRS)))
    configuration.load()
    with TestClient(HttpInternalHop(configuration.loaded_app),base_url='https://proofpack.example.test',client=('10.24.0.8',50000),follow_redirects=False) as http:
        headers={'X-Forwarded-Proto':'https'}
        start=http.get('/api/v1/auth/setup-owner',headers=headers);assert start.status_code==303
        parameters=parse_qs(urlsplit(start.headers['location']).query);w.nonce=parameters['nonce'][0]
        callback=http.get('/api/v1/auth/callback',params={'state':parameters['state'][0],'code':'offline-code'},headers=headers)
        assert callback.status_code==303 and callback.headers['location']=='https://proofpack.example.test/'
        assert len(w.requests)==2
        me=http.get('/api/v1/me',headers=headers);assert me.status_code==200 and me.json()['roles']==['owner']
        assert head(w).data['owner_ids']==[me.json()['id']]
        assert http.get('/health/ready',headers=headers).status_code==503
        assert any('Secure' in value and 'HttpOnly' in value for value in callback.headers.get_list('set-cookie'))
