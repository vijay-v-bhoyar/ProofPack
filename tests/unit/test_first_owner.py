"""Real auth/OAuth writers and signed offline provider; no live identity approval."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from restore_consumer_model import sdk_world, ISSUER
from proofpack.auth.cognito import CognitoConfig, CognitoProvider, CognitoTokens
from proofpack.auth.oauth import OAuthConfig, OAuthFlows, AuthRateLimited
from proofpack.auth.policy import Denied
from proofpack.auth.service import AccessService, AuthConfig, HEAD, RUNTIME, user_key
from proofpack.auth.signin import SignInService
from proofpack.evidence.repository import Key, Write, StoreUnavailable

NOW = 2000000000000


@pytest.fixture(scope='module')
def signing():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())),
        'kid': 'offline-owner', 'alg': 'RS256', 'use': 'sig'}
    return key, {'keys': [jwk]}


def setup(signing, **oauth_changes):
    repo, fence, client, ids = sdk_world()
    clock = [NOW]
    access = AccessService(repo, AuthConfig(repo.deployment, ISSUER, b'x'*32,
        initial_owner_subject='owner', bootstrap_receipt_sha256='a'*64), clock_ms=lambda: clock[0])
    oauth = OAuthConfig(repo.deployment, 'https://provider.example.test', 'syntheticClient',
        'https://proofpack.example.test/api/v1/auth/callback', b'z'*32, **oauth_changes)
    tokens = CognitoTokens(CognitoConfig(ISSUER, oauth.client_id), clock_ms=lambda: clock[0])
    world = SimpleNamespace(repo=repo, fence=fence, client=client, ids=ids, clock=clock,
        access=access, claims={}, nonce=None, requests=[], after_exchange=lambda: None)
    def transport(request):
        world.requests.append((request.method, str(request.url)))
        if request.method == 'POST':
            body = parse_qs(request.content.decode())
            assert body['redirect_uri'] == [oauth.redirect_uri]
            assert body['client_id'] == [oauth.client_id]
            assert body['code'] == ['offline-code']
            claims = dict(iss=ISSUER, aud=oauth.client_id, sub='owner', exp=NOW//1000+3600,
                iat=NOW//1000, auth_time=NOW//1000, token_use='id', nonce=world.nonce,
                email='owner@example.invalid', email_verified=True, name='Synthetic owner',
                acr='urn:cognito:loa:4', amr=['pwd','otp','mfa']) | world.claims
            token = jwt.encode(claims, signing[0], algorithm='RS256', headers={'kid':'offline-owner'})
            return httpx.Response(200, headers={'content-type':'application/json'},
                stream=httpx.ByteStream(json.dumps({'token_type':'Bearer','id_token':token}).encode()))
        assert str(request.url) == tokens.config.jwks_uri
        world.after_exchange()
        return httpx.Response(200, headers={'content-type':'application/json'},
            stream=httpx.ByteStream(json.dumps(signing[1]).encode()))
    provider = CognitoProvider(oauth, tokens, transport=httpx.MockTransport(transport))
    world.ordinary = SignInService(OAuthFlows(repo, oauth, clock_ms=lambda: clock[0]), provider, access)
    return world


def owner(world):
    return importlib.import_module('proofpack.auth.owner_setup').OwnerSetupSignIn(world.ordinary)


def start(world, service=None):
    service = service or owner(world)
    result = service.begin()
    parameters = parse_qs(urlsplit(result.authorization_url).query)
    world.nonce = parameters['nonce'][0]
    return service, dict(state=parameters['state'][0], browser_cookie=result.browser_cookie, code='offline-code')


def head(world):
    return world.repo.snapshot((HEAD,))[HEAD]


def test_constructor_is_no_io_and_setup_commits_owner_only_with_disabled_runtime(signing):
    w = setup(signing); w.client.calls.clear(); service = owner(w)
    assert w.client.calls == [] and w.requests == []
    service, args = start(w, service)
    credential = service.complete(**args)
    h = head(w); uid = h.data['bootstrap_user_id']
    rows = w.repo.snapshot((user_key(uid), RUNTIME))
    assert h.data['owner_ids'] == [uid] == h.data['enabled_user_ids']
    assert rows[user_key(uid)].data['roles'] == ['owner']
    assert rows[RUNTIME].data['inspection_enabled'] is False
    assert credential.cookie and credential.csrf
    assert w.access.resolve(credential.cookie).principal.roles == frozenset({'owner'})
    with pytest.raises(Denied): service.complete(**args)


def test_start_requires_native_mfa_and_reuses_closed_flow_shape(signing):
    w=setup(signing); service,args=start(w)
    key=Key('state','oauth-flow#'+hashlib.sha256(args['state'].encode()).hexdigest())
    data=w.repo.snapshot((key,))[key].data
    assert set(data)=={'browser_hash','configuration','created_at_ms','expires_at_ms','require_mfa','invitation_id','status'}
    assert data['require_mfa'] is True and data['invitation_id'] is None
    assert service.flows.config.private_key != w.ordinary.flows.config.private_key
    assert service.flows.config.redirect_uri == w.ordinary.flows.config.redirect_uri


@pytest.mark.parametrize('changes', [dict(sub='other'), dict(email_verified=False), dict(amr=['pwd'],acr='urn:cognito:loa:1'),
    dict(auth_time=NOW//1000-601), dict(auth_time=NOW//1000+1), dict(iss='https://wrong.example.test')])
def test_wrong_identity_or_mfa_never_creates_owner(signing, changes):
    w=setup(signing); service,args=start(w); w.claims=changes
    with pytest.raises(Denied):service.complete(**args)
    assert head(w) is None
    with pytest.raises(Denied):service.complete(**args)


@pytest.mark.parametrize('owner_first', [True,False], ids=['setup-to-login','login-to-setup'])
def test_realms_cannot_consume_each_others_pending_flow(signing, owner_first):
    w=setup(signing); service=owner(w)
    if owner_first:
        _,args=start(w,service); consumer=w.ordinary
    else:
        result=w.ordinary.flows.begin(require_mfa=True)
        parameters=parse_qs(urlsplit(result.authorization_url).query)
        args=dict(state=parameters['state'][0],browser_cookie=result.browser_cookie,code='offline-code')
        consumer=service
    before=deepcopy(w.client.items)
    with pytest.raises(Denied):consumer.complete(**args)
    assert w.client.items==before and w.requests==[] and head(w) is None


def test_ordinary_verified_signin_still_cannot_create_uninvited_owner(signing):
    w=setup(signing); owner(w)
    result=w.ordinary.flows.begin(require_mfa=True)
    p=parse_qs(urlsplit(result.authorization_url).query);w.nonce=p['nonce'][0]
    with pytest.raises(Denied):w.ordinary.complete(state=p['state'][0],browser_cookie=result.browser_cookie,code='offline-code')
    assert head(w) is None


def test_realms_share_login_and_callback_quotas(signing):
    w=setup(signing,login_starts_per_minute=1,callback_attempts_per_minute=1)
    service,args=start(w)
    with pytest.raises(AuthRateLimited):w.ordinary.flows.begin()
    service.flows.admit_callback()
    with pytest.raises(AuthRateLimited):w.ordinary.flows.admit_callback()
    assert head(w) is None


@pytest.mark.parametrize('configuration', ['approval','subject','oauth-key'])
def test_configuration_change_invalidates_pending_setup(signing, configuration):
    w=setup(signing); service,args=start(w)
    if configuration=='oauth-key':
        oauth=replace(w.ordinary.flows.config,private_key=b'y'*32)
        w.ordinary.flows=OAuthFlows(w.repo,oauth,clock_ms=lambda:w.clock[0])
        w.ordinary.provider=CognitoProvider(oauth,w.ordinary.provider.tokens,transport=w.ordinary.provider.transport)
    else:
        w.access.config=replace(w.access.config,**({'bootstrap_receipt_sha256':'b'*64} if configuration=='approval' else {'initial_owner_subject':'other'}))
    before=deepcopy(w.client.items)
    with pytest.raises((Denied,StoreUnavailable)):service.complete(**args)
    assert w.client.items==before and w.requests==[] and head(w) is None
    with pytest.raises(Denied):owner(w).complete(**args)


@pytest.mark.parametrize('missing', ['subject','approval','both'])
def test_setup_requires_explicit_preconfigured_approval(signing,missing):
    w=setup(signing)
    w.access.config=replace(w.access.config,**(
        {'initial_owner_subject':None} if missing=='subject' else
        {'bootstrap_receipt_sha256':None} if missing=='approval' else
        {'initial_owner_subject':None,'bootstrap_receipt_sha256':None}))
    before=deepcopy(w.client.items)
    with pytest.raises(ValueError):owner(w)
    assert w.client.items==before and w.requests==[]


@pytest.mark.parametrize('change', ['expiry','generation','approval'])
def test_change_during_provider_exchange_holds_before_membership(signing, change):
    w=setup(signing); service,args=start(w)
    def mutate():
        if change=='expiry':w.clock[0]+=300000
        elif change=='generation':w.client.items.pop(w.ids[2])
        else:w.access.config=replace(w.access.config,bootstrap_receipt_sha256='b'*64)
    w.after_exchange=mutate
    with pytest.raises((Denied,StoreUnavailable)):service.complete(**args)
    # Do not use protected readback after intentionally revoking the release.
    if change!='generation':assert head(w) is None
    assert not any(item.get('data',{}).get('M',{}).get('kind')=={'S':'bootstrap'} for item in w.client.items.values())


def test_flow_expiry_on_bootstrap_final_identity_check_prevents_owner_write(signing):
    w=setup(signing); service,args=start(w); original=w.repo.snapshot
    def slow(keys):
        result=original(keys)
        if HEAD in keys and RUNTIME in keys:w.clock[0]+=300000
        return result
    w.repo.snapshot=slow
    with pytest.raises(Denied):service.complete(**args)
    assert head(w) is None


def test_stricter_flow_mfa_expiry_on_final_identity_check_prevents_owner_write(signing):
    w=setup(signing,mfa_max_age_seconds=1);service,args=start(w);original=w.repo.snapshot
    def slow(keys):
        result=original(keys)
        if HEAD in keys and RUNTIME in keys:w.clock[0]+=1001
        return result
    w.repo.snapshot=slow
    with pytest.raises(Denied):service.complete(**args)
    assert head(w) is None


def test_lost_bootstrap_reply_is_not_retried_and_fresh_flow_reconciles_same_owner(signing):
    w=setup(signing); service,args=start(w);original=w.repo.transact;lost=[]
    def uncertain(writes,checks=()):
        result=original(writes,checks)
        if any(write.key==HEAD for write in writes):
            lost.append(True);raise StoreUnavailable('synthetic lost confirmation')
        return result
    w.repo.transact=uncertain
    with pytest.raises(StoreUnavailable):service.complete(**args)
    initial=head(w);assert initial is not None and len(lost)==1
    w.repo.transact=original
    service,args=start(w,service);credential=service.complete(**args)
    assert head(w)==initial and credential.cookie
    events=[item for item in w.client.items.values() if item.get('data',{}).get('M',{}).get('kind')=={'S':'bootstrap'}]
    assert len(events)==1


def test_historical_setup_does_not_reenable_disabled_owner(signing):
    w=setup(signing);service,args=start(w);service.complete(**args)
    h=head(w);key=user_key(h.data['bootstrap_user_id']);member=w.repo.snapshot((key,))[key]
    w.repo.transact((Write(key,member.revision,{**member.data,'enabled':False}),))
    service,args=start(w,service)
    with pytest.raises(Denied):service.complete(**args)
    assert w.repo.snapshot((key,))[key].data['enabled'] is False
    assert head(w)==h


@pytest.mark.parametrize('change',['access-approval','oauth-configuration'])
def test_dependency_change_during_bootstrap_read_holds_before_owner_effect(signing,change):
    w=setup(signing);service,args=start(w);original=w.repo.snapshot
    def changed(keys):
        result=original(keys)
        if HEAD in keys and RUNTIME in keys:
            if change=='access-approval':w.access.config=replace(w.access.config,bootstrap_receipt_sha256='b'*64)
            else:w.ordinary.flows.config=replace(w.ordinary.flows.config,private_key=b'q'*32)
        return result
    w.repo.snapshot=changed
    with pytest.raises(Denied):service.complete(**args)
    assert head(w) is None
