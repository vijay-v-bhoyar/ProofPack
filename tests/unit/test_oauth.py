from dataclasses import replace
from types import SimpleNamespace

import pytest

from proofpack.auth.oauth import OAuthConfig,OAuthFlows
from proofpack.evidence.repository import StoreUnavailable


def config():
    return OAuthConfig('test','https://synthetic.auth.us-east-1.amazoncognito.com','syntheticClient',
        'https://proofpack.example.invalid/api/v1/auth/callback',b'local-test-only-private-key-long-enough')


@pytest.mark.parametrize('changes',[
    {'provider_origin':'http://example.invalid'}, {'provider_origin':'https://example.invalid/'},
    {'provider_origin':'https://user:pass@example.invalid'}, {'provider_origin':'https://example.invalid?target=bad'},
    {'provider_origin':'https://example.invalid#fragment'}, {'provider_origin':'https://example.invalid:444'},
    {'provider_origin':'https://example.invalid\\evil'}, {'provider_origin':'https://example.invalid\n'},
    {'redirect_uri':'https://proofpack.example.invalid/callback'},
    {'redirect_uri':'https://proofpack.example.invalid/api/v1/auth/callback?next=https://evil.invalid'},
    {'client_id':'client&redirect_uri=bad'}, {'private_key':b'short'},
    {'flow_ttl_seconds':True}, {'flow_ttl_seconds':301}, {'flow_ttl_seconds':0},
    {'login_starts_per_minute':31}, {'callback_attempts_per_minute':0},
    {'mfa_max_age_seconds':True}, {'mfa_max_age_seconds':601}, {'native_totp_acr':'bad value'},
])
def test_oauth_rejects_unsafe_configuration(changes):
    with pytest.raises(ValueError):replace(config(),**changes)


@pytest.mark.parametrize('clock',[lambda:True,lambda:-1,lambda:float('nan')])
def test_oauth_untrusted_clock_denies_before_database(clock):
    flows=OAuthFlows(SimpleNamespace(deployment='test'),config(),clock_ms=clock)
    with pytest.raises(StoreUnavailable):flows.begin()


@pytest.mark.parametrize('invitation',['not-a-uuid','00000000000000000000000000000000',True,123])
def test_oauth_invitation_must_be_canonical_uuid(invitation):
    flows=OAuthFlows(SimpleNamespace(deployment='test'),config())
    with pytest.raises(ValueError):flows.begin(invitation_id=invitation)


def test_oauth_repository_scope_and_key_repr():
    with pytest.raises(ValueError):OAuthFlows(SimpleNamespace(deployment='other'),config())
    assert config().private_key.decode() not in repr(config())
