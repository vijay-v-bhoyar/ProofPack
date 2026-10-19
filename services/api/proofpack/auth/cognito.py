"""Cognito code exchange and strict ID-token verification. No role grants here.

Only fixed configuration selects endpoints. Tokens and provider response bodies
must never be logged, persisted or returned to a browser by this adapter.
"""
from dataclasses import dataclass
import hmac
import json
import re
import time

import httpx
import jwt

from proofpack.auth.oauth import ExchangeMaterial, OAuthConfig
from proofpack.auth.policy import Denied
from proofpack.auth.service import IdentityProof, canonical_email
from proofpack.evidence.repository import StoreUnavailable


@dataclass(frozen=True)
class CognitoConfig:
    issuer: str
    client_id: str
    native_totp_acr: str = 'urn:cognito:loa:4'
    max_token_lifetime_seconds: int = 3600

    def __post_init__(self):
        match = re.fullmatch(r'https://cognito-idp\.([a-z]{2}-[a-z]+-\d)\.amazonaws\.com/([a-z]{2}-[a-z]+-\d)_[A-Za-z0-9]+', self.issuer) if isinstance(self.issuer, str) else None
        if (match is None or match[1] != match[2]
                or not isinstance(self.client_id, str) or not re.fullmatch(r'[A-Za-z0-9]{1,128}', self.client_id)
                or not isinstance(self.native_totp_acr, str)
                or not re.fullmatch(r'[^\s"\\]{1,64}', self.native_totp_acr)
                or type(self.max_token_lifetime_seconds) is not int
                or not 300 <= self.max_token_lifetime_seconds <= 86400):
            raise ValueError('fixed Cognito issuer/client and bounded token policy required')

    @property
    def jwks_uri(self):
        return self.issuer + '/.well-known/jwks.json'


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def _json(raw: bytes):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON')))


class CognitoTokens:
    def __init__(self, config: CognitoConfig, *, clock_ms=None):
        self.config = config
        self.clock_ms = clock_ms or (lambda: int(time.time() * 1000))

    def now(self):
        now = self.clock_ms()
        if type(now) is not int or now < 0:
            raise StoreUnavailable('trusted server time unavailable')
        return now

    def verify(self, token: str, *, expected_nonce: str, jwks: dict) -> IdentityProof:
        if (not isinstance(token, str) or len(token) > 16384
                or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token)
                or not isinstance(expected_nonce, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', expected_nonce)):
            raise Denied('valid provider identity required')
        try:
            header_part, claims_part, _ = token.split('.')
            # Reject duplicate JSON fields before the library's signature/claim checks.
            header = _json(jwt.utils.base64url_decode(header_part))
            _json(jwt.utils.base64url_decode(claims_part))
            if (not isinstance(header, dict) or set(header) - {'alg', 'kid', 'typ'}
                    or header.get('alg') != 'RS256' or header.get('typ', 'JWT') != 'JWT'
                    or not isinstance(header.get('kid'), str)
                    or not re.fullmatch(r'[A-Za-z0-9_+/=-]{1,256}', header['kid'])):
                raise ValueError('unsupported token header')
        except (ValueError, TypeError, UnicodeError, RecursionError, jwt.PyJWTError) as exc:
            raise Denied('valid provider identity required') from exc
        # A malformed provider document is dependency failure, not a trusted key.
        try:
            keys = jwks['keys']
            if not isinstance(keys, list) or not 1 <= len(keys) <= 8:
                raise ValueError('bounded signing key set required')
            ids = [key['kid'] for key in keys]
            if any(not isinstance(kid, str) or not 1 <= len(kid) <= 256 for kid in ids) or len(set(ids)) != len(ids):
                raise ValueError('unique signing keys required')
            matches = [key for key in keys if key['kid'] == header['kid']]
            if not matches:
                raise Denied('provider signing key is not recognized')
            key = matches[0]
            if (key.get('kty') != 'RSA' or key.get('alg') != 'RS256' or key.get('use') != 'sig'
                    or set(key) - {'kty', 'kid', 'alg', 'use', 'n', 'e', 'key_ops'}
                    or ('key_ops' in key and key['key_ops'] != ['verify'])
                    or any(not isinstance(key.get(name), str) or not 1 <= len(key[name]) <= 1024 for name in ('n', 'e'))):
                raise ValueError('RSA signing key required')
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
            if not 2048 <= public_key.key_size <= 4096:
                raise ValueError('bounded RSA key size required')
        except (KeyError, ValueError, TypeError, AttributeError, jwt.PyJWTError) as exc:
            raise StoreUnavailable('provider signing keys unavailable') from exc
        try:
            claims = jwt.decode(token, public_key, algorithms=['RS256'], audience=self.config.client_id,
                issuer=self.config.issuer, options={'require': ['iss', 'aud', 'sub', 'exp', 'iat',
                    'auth_time', 'token_use', 'nonce', 'email', 'email_verified'], 'strict_aud': True,
                    'verify_exp': False, 'verify_iat': False, 'verify_nbf': False})
            # Use one injectable trusted clock and strict integer claims (no bool/string coercion).
            now = self.now()
            if (any(type(claims[name]) is not int for name in ('exp', 'iat', 'auth_time'))
                    or not 0 <= claims['auth_time'] <= claims['iat']
                    or not claims['iat'] * 1000 <= now < claims['exp'] * 1000
                    or not 0 < claims['exp'] - claims['iat'] <= self.config.max_token_lifetime_seconds
                    or ('nbf' in claims and (type(claims['nbf']) is not int
                        or not 0 <= claims['nbf'] * 1000 <= now or claims['nbf'] >= claims['exp']))
                    or claims['token_use'] != 'id' or claims['email_verified'] is not True
                    or not isinstance(claims['nonce'], str) or not claims['nonce'].isascii()
                    or not hmac.compare_digest(claims['nonce'], expected_nonce)
                    or not isinstance(claims['sub'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', claims['sub'])
                    or claims.get('identities') not in (None, [])):
                raise ValueError('invalid identity claims')
            email = canonical_email(claims['email'])
            name = claims.get('name', claims.get('cognito:username', 'Invited user'))
            if not isinstance(name, str) or not 1 <= len(name) <= 100 or any(ord(c) < 32 for c in name):
                raise ValueError('bounded display name required')
            amr = claims.get('amr', [])
            if not isinstance(amr, list) or len(amr) > 16 or any(not isinstance(method, str) or len(method) > 64 for method in amr):
                raise ValueError('invalid authentication methods')
            mfa = (claims.get('acr') == self.config.native_totp_acr
                and {'pwd', 'otp', 'mfa'} <= set(amr) and 'fed' not in amr)
            return IdentityProof(self.config.issuer, claims['sub'], email, True, mfa,
                claims['auth_time'] * 1000, claims['exp'] * 1000, name)
        except (ValueError, TypeError, KeyError, jwt.PyJWTError) as exc:
            raise Denied('valid provider identity required') from exc


class CognitoProvider:
    """Bounded code/JWKS transport; no redirects, proxy environment or retries.

    Each read has a three-second timeout plus a checked five-second per-response
    deadline. This is not a hard OS wall-clock sandbox for DNS/TLS. HTTPX transport
    injection exists for offline protocol tests only, never request input.
    """
    def __init__(self, oauth: OAuthConfig, tokens: CognitoTokens, *, transport=None):
        if oauth.client_id != tokens.config.client_id:
            raise ValueError('provider app client mismatch')
        self.oauth = oauth
        self.tokens = tokens
        self.transport = transport

    def _document(self, method, url, *, data=None):
        try:
            with httpx.Client(transport=self.transport, trust_env=False, follow_redirects=False,
                    timeout=httpx.Timeout(connect=2, read=3, write=2, pool=1),
                    limits=httpx.Limits(max_connections=2, max_keepalive_connections=0)) as client:
                deadline = time.monotonic() + 5
                with client.stream(method, url, data=data, headers={'Accept': 'application/json', 'Accept-Encoding': 'identity'}) as response:
                    if method == 'POST' and response.status_code in (400, 401):
                        raise Denied('provider sign-in failed; start again')
                    if (response.status_code != 200 or response.headers.get('content-encoding', 'identity') != 'identity'
                            or response.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json'):
                        raise StoreUnavailable('provider response unavailable')
                    length = response.headers.get('content-length')
                    if length is not None and (not length.isdecimal() or int(length) > 65536):
                        raise StoreUnavailable('provider response exceeds bounds')
                    body = bytearray()
                    for chunk in response.iter_raw():
                        if time.monotonic() >= deadline or len(body) + len(chunk) > 65536:
                            raise StoreUnavailable('provider response exceeds bounds')
                        body.extend(chunk)
                    if time.monotonic() >= deadline:
                        raise StoreUnavailable('provider response timed out')
                    result = _json(bytes(body))
                    if not isinstance(result, dict):
                        raise ValueError('object response required')
                    return result
        except (httpx.HTTPError, ValueError, UnicodeError, RecursionError) as exc:
            raise StoreUnavailable('provider transport unavailable') from exc

    def exchange(self, code: str, material: ExchangeMaterial) -> IdentityProof:
        if (not isinstance(material, ExchangeMaterial) or self.tokens.now() >= material.expires_at_ms
                or not isinstance(code, str) or not re.fullmatch(r'[\x21-\x7e]{1,2048}', code)):
            raise Denied('valid unexpired provider exchange required')
        document = self._document('POST', self.oauth.provider_origin + '/oauth2/token', data={
            'grant_type': 'authorization_code', 'client_id': self.oauth.client_id,
            'redirect_uri': self.oauth.redirect_uri, 'code': code, 'code_verifier': material.code_verifier})
        if document.get('token_type') != 'Bearer' or not isinstance(document.get('id_token'), str):
            raise StoreUnavailable('provider identity response unavailable')
        keys = self._document('GET', self.tokens.config.jwks_uri)
        if self.tokens.now() >= material.expires_at_ms:
            raise Denied('provider sign-in expired; start again')
        return self.tokens.verify(document['id_token'], expected_nonce=material.expected_nonce, jwks=keys)
