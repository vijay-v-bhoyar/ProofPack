"""Empty-install to invited operator using real configured ASGI/services.

SDK store/role/TableIds/approval and signed provider are synthetic. No real
business approval, AWS/IAM/provider, rendered browser or human acceptance.
"""
from urllib.parse import parse_qs, urlsplit
import json

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from test_host import host_files
from test_first_owner import signing
from test_fresh_enrollment import world, run, approve_candidate
from restore_consumer_model import install_model_transactions
from proofpack.auth.cognito import CognitoProvider
from proofpack.auth.http import COOKIE
from proofpack.auth.service import HEAD, RUNTIME, user_key
from proofpack.runtime import host, composition
from proofpack.runtime.control import DATA


@pytest.mark.parametrize('decision',['accept','wrong-notice','decline'])
def test_empty_install_owner_to_operator_notice_and_fresh_signin(host_files,signing,monkeypatch,capsys,decision):
    # Owner settings participate in the genuine initial configuration binding.
    host_files[2]['auth'].update(initial_owner_subject='owner',bootstrap_receipt_sha256='a'*64)
    w=world(host_files);install_model_transactions(w.client)
    assert w.client.items=={}
    candidate=run(w);approve_candidate(w,candidate);committed=run(w,commit=True)
    assert committed['status']=='ENROLLMENT_COMMITTED' and len(w.client.items)==10
    w.closed.clear()
    w.sts.get_caller_identity=lambda:{'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/ProofPackApp/synthetic-session'}
    context={'subject':'owner','nonce':None,'app':None};exchanges=[];entered=[]
    config=w.loaded.config

    def provider_response(request):
        exchanges.append((request.method,str(request.url)))
        if request.method=='POST':
            fields=parse_qs(request.content.decode())
            assert fields['client_id']==[config.oauth.client_id]
            assert fields['redirect_uri']==[config.oauth.redirect_uri]
            now=context['app'].state.signin_service.provider.tokens.now()//1000
            subject=context['subject']
            claims={'iss':config.auth.issuer,'aud':config.oauth.client_id,'sub':subject,
                'exp':now+3600,'iat':now,'auth_time':now,'token_use':'id','nonce':context['nonce'],
                'email':subject+'@example.invalid','email_verified':True,'name':'Synthetic '+subject,
                'acr':'urn:cognito:loa:4','amr':['pwd','otp','mfa']}
            token=jwt.encode(claims,signing[0],algorithm='RS256',headers={'kid':'offline-owner'})
            result={'token_type':'Bearer','id_token':token}
        else:
            assert str(request.url)==config.cognito.jwks_uri
            result=signing[1]
        return httpx.Response(200,headers={'content-type':'application/json'},stream=httpx.ByteStream(json.dumps(result).encode()))

    # Inject only offline HTTP transport at construction. Real token verification,
    # realm construction, factory ownership checks and callbacks remain intact.
    transport=httpx.MockTransport(provider_response)
    monkeypatch.setattr(composition,'CognitoProvider',lambda oauth,tokens:CognitoProvider(oauth,tokens,transport=transport))

    def server(app,**kwargs):
        context['app']=app;assert kwargs['workers']==1 and kwargs['reload'] is False
        with TestClient(app,base_url=config.app_origin,follow_redirects=False) as http:
            assert app.state.composition_status=='started'
            repo=app.state.access_service.repository
            rows=repo.snapshot((HEAD,RUNTIME,DATA))
            assert rows[HEAD] is None and rows[RUNTIME].data['runtime_epoch']==rows[DATA].data['epoch']==2
            assert rows[RUNTIME].data['inspection_enabled'] is False
            assert app.state.owner_setup_service.ordinary is app.state.signin_service

            def signin(path):
                response=http.get(path);assert response.status_code==303
                parameters=parse_qs(urlsplit(response.headers['location']).query)
                context['nonce']=parameters['nonce'][0]
                result=http.get('/api/v1/auth/callback',params={'state':parameters['state'][0],'code':'offline-code'})
                assert result.status_code==303 and result.headers['location']==config.app_origin+'/'

            def headers(session,key):
                return {'Origin':config.app_origin,'X-CSRF-Token':session['csrf_token'],'Idempotency-Key':key}

            signin('/api/v1/auth/setup-owner')
            me=http.get('/api/v1/me');assert me.status_code==200
            owner=me.json();assert owner['roles']==['owner']
            notice=http.get('/api/v1/auth/notice');assert notice.status_code==200
            assert notice.json()['optional_improvement_default'] is False
            response=http.post('/api/v1/invitations',headers=headers(owner,'first-operator'),json={
                'target_subject':'operator','target_email':'operator@example.invalid','roles':['operator'],'ttl_seconds':600})
            assert response.status_code==201
            invitation=response.json();ident=invitation['id']
            assert invitation['delivery_status']=='NOT_SENT'
            assert http.post('/api/v1/auth/logout',headers=headers(owner,'owner-logout')).status_code==204
            assert not http.cookies.get(COOKIE)

            context['subject']='operator'
            signin('/api/v1/auth/login?invitation_id='+ident)
            assert http.get('/api/v1/me').status_code==403
            session=http.get('/api/v1/auth/session');assert session.status_code==200
            pending=session.json();assert pending['status']=='invitation_pending' and pending['invitation_id']==ident
            details=http.get('/api/v1/invitations/'+ident);assert details.status_code==200
            assert details.json()['roles']==['operator']
            notice=http.get('/api/v1/auth/notice').json()
            assert notice['optional_improvement_default'] is notice['optional_publicity_default'] is False
            if decision=='decline':
                result=http.post('/api/v1/invitations/'+ident+'/decline',headers=headers(pending,'decline-invite'),json={})
                assert result.status_code==200 and result.json()['status']=='declined'
                assert not http.cookies.get(COOKIE)
                assert http.get('/api/v1/me').status_code==401
            else:
                result=http.post('/api/v1/invitations/'+ident+'/accept',headers=headers(pending,'accept-invite'),json={
                    'capability':invitation['capability'],'notice_version':notice['version'],
                    'notice_sha256':'0'*64 if decision=='wrong-notice' else notice['sha256']})
                if decision=='wrong-notice':
                    assert result.status_code==403
                    assert http.get('/api/v1/me').status_code==403
                else:
                    assert result.status_code==200 and result.json()['sign_in_required'] is True
                    assert not http.cookies.get(COOKIE)
                    signin('/api/v1/auth/login')
                    operator=http.get('/api/v1/me');assert operator.status_code==200
                    member=operator.json();assert member['roles']==['operator']
                    stored=repo.snapshot((user_key(member['id']),))[user_key(member['id'])]
                    assert stored.data['notice_sha256']==notice['sha256']
                    assert stored.data['improvement_reuse'] is stored.data['publicity_reuse'] is False
                    assert http.post('/api/v1/invitations',headers=headers(member,'no-owner-escalation'),json={
                        'target_subject':'other','target_email':'other@example.invalid','roles':['owner'],'ttl_seconds':600}).status_code==403
            final=repo.snapshot((HEAD,RUNTIME))
            assert len(final[HEAD].data['enabled_user_ids'])==(2 if decision=='accept' else 1)
            assert final[HEAD].data['owner_ids']==[owner['id']]
            assert final[RUNTIME].data['inspection_enabled'] is False
            assert http.get('/health/ready').status_code==503
            entered.append(app.state.runtime_control.instance_id)
        assert app.state.composition_status=='closed'
        assert app.state.resource_owner.wait_for_drain(0)

    assert host.main(['serve','--config',str(w.path),'--secrets-file',str(w.secret)],session_factory=w.Session,run_server=server)==0
    output=capsys.readouterr();assert output.out==''
    assert json.loads(output.err)['instance_id']==entered[0]
    assert sorted(w.closed)==['dynamodb','s3','sts']
    assert len(exchanges)==(6 if decision=='accept' else 4)
