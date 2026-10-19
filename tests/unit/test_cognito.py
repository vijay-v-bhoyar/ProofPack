"""Offline RSA/protocol fixtures. No Cognito account, token or network is used."""
from dataclasses import replace
import base64
import json
from urllib.parse import parse_qs

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
import pytest

from proofpack.auth.cognito import CognitoConfig,CognitoProvider,CognitoTokens
from proofpack.auth.oauth import ExchangeMaterial,OAuthConfig
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import StoreUnavailable

ISSUER='https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Synthetic'
NONCE='n'*43
NOW=2000000000000


@pytest.fixture(scope='module')
def signing():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk={**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())),
        'kid':'synthetic-key','alg':'RS256','use':'sig'}
    return key,{'keys':[jwk]}


def claims():
    return {'iss':ISSUER,'aud':'syntheticClient','sub':'synthetic-owner','exp':NOW//1000+3600,
        'iat':NOW//1000,'auth_time':NOW//1000,'token_use':'id','nonce':NONCE,
        'email':'owner@example.invalid','email_verified':True,'name':'Synthetic owner',
        'acr':'urn:cognito:loa:4','amr':['pwd','otp','mfa']}


def encoded(signing,**changes):
    return jwt.encode({**claims(),**changes},signing[0],algorithm='RS256',headers={'kid':'synthetic-key'})


def verifier(clock=lambda:NOW):return CognitoTokens(CognitoConfig(ISSUER,'syntheticClient'),clock_ms=clock)


def test_signed_native_totp_proof_ignores_group_and_custom_role_claims(signing):
    proof=verifier().verify(encoded(signing,**{'cognito:groups':['owner'],'custom:role':'owner'}),expected_nonce=NONCE,jwks=signing[1])
    assert proof.mfa_verified and proof.email_verified and proof.auth_time_ms==NOW
    assert proof.subject=='synthetic-owner' and not hasattr(proof,'roles')


@pytest.mark.parametrize('changes',[
    {'iss':'https://evil.example.invalid'}, {'aud':'otherClient'}, {'aud':['syntheticClient']},
    {'token_use':'access'}, {'nonce':'x'*43}, {'email_verified':False}, {'email_verified':'true'},
    {'email':'bad'}, {'sub':'bad subject'}, {'name':'bad\nname'},
    {'exp':NOW//1000}, {'exp':True}, {'exp':str(NOW//1000+100)}, {'iat':NOW//1000+1},
    {'iat':True}, {'auth_time':NOW//1000+1}, {'auth_time':-1}, {'auth_time':1.2},
    {'exp':NOW//1000+86400}, {'nbf':NOW//1000+1}, {'nbf':False},
    {'identities':[{'providerName':'external'}]}, {'amr':'mfa'}, {'amr':[True]},
])
def test_signed_but_invalid_claims_are_denied(signing,changes):
    with pytest.raises(Denied):verifier().verify(encoded(signing,**changes),expected_nonce=NONCE,jwks=signing[1])


@pytest.mark.parametrize('missing',['iss','aud','sub','exp','iat','auth_time','nonce','email','email_verified','token_use'])
def test_required_signed_claims_cannot_be_omitted(signing,missing):
    payload=claims();del payload[missing]
    token=jwt.encode(payload,signing[0],algorithm='RS256',headers={'kid':'synthetic-key'})
    with pytest.raises(Denied):verifier().verify(token,expected_nonce=NONCE,jwks=signing[1])


@pytest.mark.parametrize('changes',[{'amr':[]},{'amr':['pwd','sms','mfa']},
    {'amr':['swk'],'acr':'urn:cognito:loa:3'}, {'amr':['pwd','otp','mfa','fed']},
    {'acr':'urn:cognito:loa:3'}, {'acr':'custom-level-four'}, {'amr':['mfa']},
    {'amr':[],'custom:mfa':'true'}])
def test_other_or_missing_authentication_methods_never_satisfy_owner_totp(signing,changes):
    proof=verifier().verify(encoded(signing,**changes),expected_nonce=NONCE,jwks=signing[1])
    assert proof.mfa_verified is False


def test_absent_mfa_claims_are_ordinary_identity_not_owner_mfa(signing):
    payload=claims();del payload['amr'];del payload['acr']
    token=jwt.encode(payload,signing[0],algorithm='RS256',headers={'kid':'synthetic-key'})
    assert not verifier().verify(token,expected_nonce=NONCE,jwks=signing[1]).mfa_verified


@pytest.mark.parametrize('header',[{'jku':'https://evil.example.invalid/keys'}, {'x5u':'https://evil.example.invalid'},
    {'crit':['evil']}, {'typ':'other'}, {'kid':'unknown-key'}])
def test_untrusted_key_urls_and_headers_do_not_select_keys(signing,header):
    token=jwt.encode(claims(),signing[0],algorithm='RS256',headers={'kid':'synthetic-key',**header})
    with pytest.raises(Denied):verifier().verify(token,expected_nonce=NONCE,jwks=signing[1])


def test_signature_modification_and_algorithm_confusion_denied(signing):
    good=encoded(signing);header,body,sig=good.split('.')
    modified=base64.urlsafe_b64encode(json.dumps({**claims(),'sub':'attacker'}).encode()).decode().rstrip('=')
    wrong_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    candidates=[header+'.'+modified+'.'+sig,
        jwt.encode(claims(),'synthetic-hmac-key-only-at-least-32-bytes',algorithm='HS256',headers={'kid':'synthetic-key'}),
        jwt.encode(claims(),wrong_key,algorithm='RS256',headers={'kid':'synthetic-key'}),'malformed',good+'x']
    for token in candidates:
        with pytest.raises(Denied):verifier().verify(token,expected_nonce=NONCE,jwks=signing[1])


@pytest.mark.parametrize('document',[{}, {'keys':[]}, {'keys':[{}]}, {'keys':'bad'},
    {'keys':[{'kid':'synthetic-key','kty':'EC','alg':'RS256','use':'sig'}]}])
def test_malformed_signing_document_is_dependency_failure(signing,document):
    with pytest.raises(StoreUnavailable):verifier().verify(encoded(signing),expected_nonce=NONCE,jwks=document)


def test_duplicate_kid_document_cannot_choose_arbitrary_key(signing):
    with pytest.raises(StoreUnavailable):verifier().verify(encoded(signing),expected_nonce=NONCE,jwks={'keys':signing[1]['keys']*2})


def test_duplicate_signed_claim_field_is_denied(signing):
    raw=json.dumps(claims())[:-1]+',"sub":"different-subject"}'
    token=jwt.api_jws.encode(raw.encode(),signing[0],algorithm='RS256',headers={'kid':'synthetic-key'})
    with pytest.raises(Denied):verifier().verify(token,expected_nonce=NONCE,jwks=signing[1])


def test_weak_rsa_signing_key_is_dependency_failure():
    key=rsa.generate_private_key(public_exponent=65537,key_size=1024)
    jwk={**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())),
        'kid':'synthetic-key','alg':'RS256','use':'sig'}
    token=jwt.encode(claims(),key,algorithm='RS256',headers={'kid':'synthetic-key'})
    with pytest.raises(StoreUnavailable):verifier().verify(token,expected_nonce=NONCE,jwks={'keys':[jwk]})


@pytest.mark.parametrize('operations',[['sign'],['verify','sign'],'verify',[]])
def test_signing_keys_cannot_advertise_other_operations(signing,operations):
    key={**signing[1]['keys'][0],'key_ops':operations}
    with pytest.raises(StoreUnavailable):verifier().verify(encoded(signing),expected_nonce=NONCE,jwks={'keys':[key]})


def response(document,status=200,headers=None):
    raw=document if isinstance(document,bytes) else json.dumps(document).encode()
    return httpx.Response(status,headers={'content-type':'application/json',**(headers or {})},stream=httpx.ByteStream(raw))


def provider(handler,clock=lambda:NOW):
    oauth=OAuthConfig('test','https://synthetic.auth.us-east-1.amazoncognito.com','syntheticClient',
        'https://proofpack.example.invalid/api/v1/auth/callback',b'only-local-synthetic-private-key-123')
    return CognitoProvider(oauth,verifier(clock),transport=httpx.MockTransport(handler))


def material():return ExchangeMaterial('v'*43,NONCE,None,NOW+300000)


def test_code_exchange_uses_fixed_endpoints_pkce_and_returns_only_verified_identity(signing):
    calls=[]
    def handler(request):
        calls.append((request.method,str(request.url)))
        if request.method=='POST':
            posted=parse_qs(request.content.decode())
            assert posted['code_verifier']==['v'*43] and posted['grant_type']==['authorization_code']
            assert posted['client_id']==['syntheticClient'] and posted['code']==['synthetic-code']
            assert posted['redirect_uri']==['https://proofpack.example.invalid/api/v1/auth/callback']
            return response({'token_type':'Bearer','id_token':encoded(signing),'access_token':'discard-me','refresh_token':'discard-me'})
        return response(signing[1])
    result=provider(handler).exchange('synthetic-code',material())
    assert result.mfa_verified and not hasattr(result,'refresh_token')
    assert calls==[('POST','https://synthetic.auth.us-east-1.amazoncognito.com/oauth2/token'),('GET',ISSUER+'/.well-known/jwks.json')]


@pytest.mark.parametrize('bad_response',[
    lambda:response({},302,{'location':'https://evil.example.invalid'}),
    lambda:response(b'x'*65537), lambda:response({},headers={'content-length':'65537'}),
    lambda:response({},headers={'content-encoding':'gzip'}),
    lambda:response({},headers={'content-type':'text/html'}),
    lambda:response(b'{"id_token":"a","id_token":"b"}'),
    lambda:response(b'{"value":NaN}'),lambda:response(b'not JSON'),lambda:response([]),
    lambda:response({'token_type':'Bearer'}),lambda:response({},503),
])
def test_bad_provider_response_is_sanitized_and_never_followed(bad_response):
    calls=[]
    def handler(request):calls.append(str(request.url));return bad_response()
    with pytest.raises(StoreUnavailable) as error:provider(handler).exchange('synthetic-code',material())
    assert len(calls)==1 and 'id_token' not in str(error.value)


@pytest.mark.parametrize('status',[400,401])
def test_provider_auth_rejection_does_not_echo_or_retry(status):
    calls=[]
    def handler(request):calls.append(request);return response({'error_description':'secret-sensitive-provider-message'},status)
    with pytest.raises(Denied) as error:provider(handler).exchange('synthetic-code',material())
    assert 'sensitive' not in str(error.value) and len(calls)==1


def test_transport_timeout_fails_without_retry():
    calls=[]
    def handler(request):calls.append(request);raise httpx.ReadTimeout('synthetic sensitive token')
    with pytest.raises(StoreUnavailable) as error:provider(handler).exchange('synthetic-code',material())
    assert 'sensitive' not in str(error.value) and len(calls)==1


def test_total_response_deadline_is_checked_before_acceptance(monkeypatch):
    from types import SimpleNamespace
    import proofpack.auth.cognito as module
    ticks=iter([0,6])
    monkeypatch.setattr(module,'time',SimpleNamespace(monotonic=lambda:next(ticks)))
    with pytest.raises(StoreUnavailable):provider(lambda request:response({})).exchange('synthetic-code',material())


def test_deeply_nested_response_is_bounded_dependency_failure():
    raw=b'{"nested":'+b'['*1500+b'0'+b']'*1500+b'}'
    with pytest.raises(StoreUnavailable):provider(lambda request:response(raw)).exchange('synthetic-code',material())


def test_exchange_expired_before_call_does_not_contact_provider():
    def handler(request):pytest.fail('expired flow must not contact provider')
    with pytest.raises(Denied):provider(handler,clock=lambda:NOW+300000).exchange('synthetic-code',material())


def test_exchange_expired_after_response_returns_no_identity(signing):
    clock=[NOW]
    def handler(request):
        if request.method=='POST':return response({'token_type':'Bearer','id_token':encoded(signing)})
        clock[0]=NOW+300000;return response(signing[1])
    with pytest.raises(Denied):provider(handler,clock=lambda:clock[0]).exchange('synthetic-code',material())


@pytest.mark.parametrize('issuer',['http://cognito-idp.us-east-1.amazonaws.com/us-east-1_Test',
    'https://evil.example.invalid/pool','https://cognito-idp.us-east-1.amazonaws.com/us-east-2_Test',
    ISSUER+'?url=https://evil.example.invalid',ISSUER+'/'])
def test_provider_issuer_cannot_select_arbitrary_key_url(issuer):
    with pytest.raises(ValueError):CognitoConfig(issuer,'syntheticClient')
