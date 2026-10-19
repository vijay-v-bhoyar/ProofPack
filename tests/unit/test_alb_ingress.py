"""Actual Uvicorn ingress handling with synthetic protected SDK state only."""
from dataclasses import replace
import importlib
import json

import pytest
from fastapi.testclient import TestClient
import uvicorn

from test_host import host_files, forbidden
from test_first_owner import signing, setup, head
from test_first_owner_http import browser
from test_fresh_enrollment import world, run, approve_candidate
from restore_consumer_model import install_model_transactions
from proofpack.runtime import host
from proofpack.auth.service import RUNTIME

CIDRS=('10.24.0.0/24','10.24.1.0/24')


def document():return {'mode':'alb','trusted_proxy_cidrs':list(CIDRS)}


def ingress():return importlib.import_module('proofpack.runtime.ingress')


def test_closed_host_ingress_loads_without_credential_or_target_io(host_files):
    path,secret,data,_=host_files;data['ingress']=document();path.write_text(json.dumps(data))
    loaded=host.load_configuration(path,secret)
    assert type(loaded.config.ingress) is ingress().IngressConfig
    assert loaded.config.ingress.trusted_proxy_cidrs==CIDRS
    assert host.main(['check-config','--config',str(path),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==0


@pytest.mark.parametrize('bad',[
    {'mode':'public','trusted_proxy_cidrs':list(CIDRS)},
    {'mode':'alb','trusted_proxy_cidrs':['*','10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':['0.0.0.0/0','10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':['127.0.0.0/24','10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':['169.254.0.0/16','10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':['203.0.113.0/24','10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':['10.24.0.7/24','10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':['10.24.0.0/24','10.24.0.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':['10.24.0.0/24','10.24.0.0/25']},
    {'mode':'alb','trusted_proxy_cidrs':['10.0.0.0/8','10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':['10.24.0.0/28','10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':['fd00::/64','10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':[True,'10.24.1.0/24']},
    {'mode':'alb','trusted_proxy_cidrs':[]},
    {'mode':'alb','trusted_proxy_cidrs':[CIDRS[0]]},
    {'mode':'alb','trusted_proxy_cidrs':list(CIDRS),'trust_all':True},
    {'mode':'alb','trusted_proxy_cidrs':','.join(CIDRS)},
])
def test_invalid_ingress_fails_before_credentials_and_does_not_echo(host_files,bad,capsys):
    path,secret,data,_=host_files;data['ingress']=bad;path.write_text(json.dumps(data))
    assert host.main(['check-config','--config',str(path),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==2
    output=capsys.readouterr();assert 'trusted_proxy_cidrs' not in output.err and output.out==''


def test_default_stays_untrusted_and_programmatic_trust_requires_typed_frozen_configuration(host_files):
    loaded=host.load_configuration(*host_files[:2]);mod=ingress()
    assert loaded.config.ingress is None and mod.server_proxy_options(None)=={'proxy_headers':False}
    valid=mod.IngressConfig('alb',CIDRS)
    assert mod.server_proxy_options(valid)=={'proxy_headers':True,'forwarded_allow_ips':','.join(CIDRS)}
    with pytest.raises(ValueError):replace(loaded.config,ingress=document())
    with pytest.raises(ValueError):mod.server_proxy_options(document())


class HttpInternalHop:
    def __init__(self,app):self.app=app
    async def __call__(self,scope,receive,send):
        if scope['type']=='http':scope=dict(scope,scheme='http')
        await self.app(scope,receive,send)


@pytest.mark.parametrize('enabled,peer,proto,origin,expected',[
    (True,'10.24.0.8','https','https://proofpack.example.test',303),
    (True,'10.24.1.8','https','https://proofpack.example.test',303),
    (True,'203.0.113.8','https','https://proofpack.example.test',403),
    (False,'10.24.0.8','https','https://proofpack.example.test',403),
    (True,'10.24.0.8',None,'https://proofpack.example.test',403),
    (True,'10.24.0.8','http','https://proofpack.example.test',403),
    (True,'10.24.0.8','https','https://wrong.example.test',403),
],ids=['trusted-a','trusted-b','untrusted-peer','no-trust','missing-proto','plain-http','wrong-host'])
def test_actual_uvicorn_wrapper_only_accepts_fixed_https_origin_from_trusted_peer(signing,enabled,peer,proto,origin,expected):
    w=setup(signing);original=browser(w);app=original.app;original.close()
    mod=ingress();configuration=uvicorn.Config(app,access_log=False,**mod.server_proxy_options(mod.IngressConfig('alb',CIDRS) if enabled else None))
    configuration.load()
    headers={} if proto is None else {'X-Forwarded-Proto':proto,'X-Forwarded-Host':'proofpack.example.test'}
    with TestClient(HttpInternalHop(configuration.loaded_app),base_url=origin,client=(peer,50000),follow_redirects=False) as http:
        response=http.get('/api/v1/auth/login',headers=headers)
        assert response.status_code==expected and w.requests==[] and head(w) is None
        if expected==303:
            assert response.headers['location'].startswith(w.ordinary.flows.config.provider_origin+'/oauth2/authorize?')
            assert any('Secure' in value and 'HttpOnly' in value for value in response.headers.get_list('set-cookie'))
        else:assert 'location' not in response.headers


def test_actual_fresh_configured_host_passes_exact_proxy_options_and_serves_http_target_hop(host_files,capsys):
    host_files[2]['ingress']=document()
    w=world(host_files);install_model_transactions(w.client);approve_candidate(w,run(w));run(w,commit=True);w.closed.clear()
    w.sts.get_caller_identity=lambda:{'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/ProofPackApp/synthetic-session'}
    entered=[]
    def server(app,**kwargs):
        assert kwargs['proxy_headers'] is True and kwargs['forwarded_allow_ips']==','.join(CIDRS)
        assert kwargs['workers']==1 and kwargs['access_log'] is kwargs['reload'] is False
        configuration=uvicorn.Config(app,**kwargs);configuration.load()
        with TestClient(HttpInternalHop(configuration.loaded_app),base_url=w.loaded.config.app_origin,client=('10.24.0.8',50000),follow_redirects=False) as http:
            assert app.state.composition_status=='started'
            response=http.get('/api/v1/auth/login',headers={'X-Forwarded-Proto':'https'})
            assert response.status_code==303
            assert http.get('/health/ready').status_code==503
            assert app.state.access_service.repository.snapshot((RUNTIME,))[RUNTIME].data['inspection_enabled'] is False
            entered.append(app.state.runtime_control.instance_id)
        assert app.state.composition_status=='closed' and app.state.resource_owner.wait_for_drain(0)
    assert host.main(['serve','--config',str(w.path),'--secrets-file',str(w.secret)],session_factory=w.Session,run_server=server)==0
    result=capsys.readouterr();assert result.out=='' and json.loads(result.err)['instance_id']==entered[0]
    assert sorted(w.closed)==['dynamodb','s3','sts']
