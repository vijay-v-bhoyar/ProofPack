"""Durable browser-bound Cognito authorization-code flow; no token exchange here.

Secrets returned by this component are trusted server inputs. Never serialize
ExchangeMaterial into an HTTP response or log a callback query string.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from proofpack.auth.policy import Denied
from proofpack.evidence.repository import DynamoRepository, Key, StoreConflict, StoreUnavailable, Write


class AuthRateLimited(RuntimeError):
    def __init__(self, retry_after_seconds=60):
        super().__init__('sign-in request limit reached')
        self.retry_after_seconds = retry_after_seconds


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _https(value: str, *, origin: bool = False):
    if not isinstance(value, str) or len(value) > 2048 or not value.isascii() or any(ord(c) <= 32 for c in value):
        raise ValueError('explicit HTTPS provider/callback configuration required')
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('invalid HTTPS port') from exc
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or port not in (None, 443) or '\\' in value or '%' in parsed.netloc
            or not re.fullmatch(r'[A-Za-z0-9.-]+', parsed.hostname)
            or (origin and parsed.path)):
        raise ValueError('explicit HTTPS provider/callback configuration required')
    return parsed


@dataclass(frozen=True)
class OAuthConfig:
    deployment: str
    provider_origin: str
    client_id: str
    redirect_uri: str
    private_key: bytes = field(repr=False)
    flow_ttl_seconds: int = 300
    native_totp_acr: str = 'urn:cognito:loa:4'
    mfa_max_age_seconds: int = 600
    login_starts_per_minute: int = 30
    callback_attempts_per_minute: int = 60

    def __post_init__(self):
        _https(self.provider_origin, origin=True)
        callback = _https(self.redirect_uri)
        if (callback.path != '/api/v1/auth/callback'
                or not isinstance(self.deployment, str) or not 1 <= len(self.deployment) <= 128
                or not isinstance(self.client_id, str) or not re.fullmatch(r'[A-Za-z0-9]{1,128}', self.client_id)
                or not isinstance(self.private_key, bytes) or len(self.private_key) < 32
                or type(self.flow_ttl_seconds) is not int or not 1 <= self.flow_ttl_seconds <= 300
                or not isinstance(self.native_totp_acr, str) or not re.fullmatch(r'[^\s"\\]{1,64}', self.native_totp_acr)
                or type(self.mfa_max_age_seconds) is not int or not 1 <= self.mfa_max_age_seconds <= 600
                or type(self.login_starts_per_minute) is not int or not 1 <= self.login_starts_per_minute <= 30
                or type(self.callback_attempts_per_minute) is not int or not 1 <= self.callback_attempts_per_minute <= 60):
            raise ValueError('fixed callback, client, deployment, key and bounded flow lifetime required')


@dataclass(frozen=True)
class AuthorizationStart:
    authorization_url: str = field(repr=False)
    browser_cookie: str = field(repr=False)
    expires_at_ms: int


@dataclass(frozen=True)
class ExchangeMaterial:
    code_verifier: str = field(repr=False)
    expected_nonce: str = field(repr=False)
    invitation_id: str | None
    expires_at_ms: int
    require_mfa: bool = False


class OAuthFlows:
    def __init__(self, repository, config: OAuthConfig, *, clock_ms=None):
        if repository.deployment != config.deployment:
            raise ValueError('repository deployment mismatch')
        self.repository = repository
        self.config = config
        self.clock_ms = clock_ms or (lambda: int(time.time() * 1000))
        # The binding is private-keyed so a key rotation invalidates old flows.
        self.binding = self._derive('configuration', json.dumps([
            config.deployment, config.provider_origin, config.client_id,
            config.redirect_uri, config.flow_ttl_seconds, config.native_totp_acr,
            config.mfa_max_age_seconds], separators=(',', ':')))

    def _now(self):
        value = self.clock_ms()
        if type(value) is not int or value < 0:
            raise StoreUnavailable('trusted server time unavailable')
        return value

    def _derive(self, purpose: str, value: str):
        message = json.dumps(['proofpack-oauth-v1', self.config.deployment, purpose, value], separators=(',', ':'))
        raw = hmac.new(self.config.private_key, message.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(raw).decode().rstrip('=')

    def _configuration_binding(self):
        # Constructors remain no-I/O; generation is captured only for an
        # admitted operation and rechecked before redirect/exchange output.
        if not isinstance(self.repository, DynamoRepository):
            return self.binding
        fence = self.repository._check_data_fence()
        if fence is None:
            return self.binding
        generation = fence.generation_sha256()
        return self._derive('restore-configuration', json.dumps(
            [self.binding, generation], separators=(',', ':')))

    def _check_binding(self, captured):
        if not hmac.compare_digest(captured, self._configuration_binding()):
            raise Denied('sign-in configuration changed; start again')

    @staticmethod
    def _capability(value):
        return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{43}', value) is not None

    def _quota_write(self, purpose, now):
        limit = {'login': self.config.login_starts_per_minute,
            'callback': self.config.callback_attempts_per_minute}[purpose]
        key = Key('state', 'oauth-quota#' + purpose)
        row = self.repository.snapshot((key,))[key]
        window = now // 60000 * 60000
        count = 0
        if row is not None:
            if row.data['window_start_ms'] > window:
                raise StoreUnavailable('sign-in quota clock moved backwards')
            if row.data['window_start_ms'] == window:
                count = int(row.data['count'])
        if count >= limit:
            raise AuthRateLimited(max(1, (window + 60000 - now + 999) // 1000))
        return Write(key, None if row is None else row.revision, {'window_start_ms': window, 'count': count + 1})

    def admit_callback(self):
        try:
            self.repository.transact((self._quota_write('callback', self._now()),))
        except StoreConflict as exc:
            raise AuthRateLimited(1) from exc

    def begin(self, *, invitation_id: str | None = None, require_mfa: bool = False) -> AuthorizationStart:
        if type(require_mfa) is not bool:
            raise ValueError('explicit MFA request required')
        if invitation_id is not None:
            try:
                if str(UUID(invitation_id)) != invitation_id:
                    raise ValueError('canonical invitation UUID required')
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError('canonical invitation UUID required') from exc
        now = self._now()
        binding = self._configuration_binding()
        state, cookie = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        ident = _hash(state)
        verifier = self._derive('verifier', ident + ':' + cookie)
        nonce = self._derive('nonce', ident + ':' + cookie)
        expires = now + self.config.flow_ttl_seconds * 1000
        quota = self._quota_write('login', now)
        try:
            self.repository.transact((Write(Key('state', 'oauth-flow#' + ident), None, {
                'browser_hash': _hash(cookie), 'configuration': binding,
                'created_at_ms': now, 'expires_at_ms': expires, 'require_mfa': require_mfa,
                'invitation_id': invitation_id, 'status': 'pending'}), quota))
        except StoreConflict as exc:
            raise AuthRateLimited(1) from exc
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        parameters = {'response_type': 'code', 'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri, 'scope': 'openid email profile',
            'state': state, 'nonce': nonce, 'code_challenge': challenge,
            'code_challenge_method': 'S256', 'prompt': 'login'}
        if require_mfa:
            parameters.update(acr_values=self.config.native_totp_acr, max_age=str(self.config.mfa_max_age_seconds))
        query = urlencode(parameters)
        self._check_binding(binding)
        if not now <= self._now() < expires:
            raise Denied('sign-in flow expired; start again')
        return AuthorizationStart(self.config.provider_origin + '/oauth2/authorize?' + query, cookie, expires)

    def consume(self, *, state: str, browser_cookie: str) -> ExchangeMaterial:
        """Claim once before code exchange/error handling; no recovery on ambiguity."""
        if not self._capability(state) or not self._capability(browser_cookie):
            raise Denied('valid browser-bound sign-in flow required')
        binding = self._configuration_binding()
        key = Key('state', 'oauth-flow#' + _hash(state))
        row = self.repository.snapshot((key,))[key]
        now = self._now()
        if (row is None or row.data['status'] != 'pending'
                or not hmac.compare_digest(row.data['configuration'], binding)
                or not hmac.compare_digest(row.data['browser_hash'], _hash(browser_cookie))
                or not row.data['created_at_ms'] <= now < row.data['expires_at_ms']):
            raise Denied('valid browser-bound sign-in flow required')
        try:
            self.repository.transact((Write(key, row.revision, {
                **row.data, 'status': 'consumed', 'consumed_at_ms': now}),))
        except StoreConflict as exc:
            raise Denied('sign-in flow already consumed; start again') from exc
        self._check_binding(binding)
        # Never exchange after a slow transaction has crossed the local deadline.
        current = self._now()
        if not now <= current < row.data['expires_at_ms']:
            raise Denied('sign-in flow expired; start again')
        material = _hash(state) + ':' + browser_cookie
        return ExchangeMaterial(self._derive('verifier', material), self._derive('nonce', material),
            row.data['invitation_id'], int(row.data['expires_at_ms']), row.data['require_mfa'])
