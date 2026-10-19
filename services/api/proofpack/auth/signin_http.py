"""Browser-facing OAuth redirects; callback query protection runs before routing."""
import re
import secrets
from urllib.parse import parse_qsl
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from proofpack.auth.http import COOKIE,FLOW_COOKIE
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import StoreUnavailable

PREFIX = '/api/v1/auth/'
OWNER_FLOW_COOKIE = '__Host-proofpack-owner-setup'
router = APIRouter(prefix='/api/v1/auth')


def clear_flow(response):
    response.delete_cookie(FLOW_COOKIE, path='/', secure=True, httponly=True, samesite='lax')
    response.delete_cookie(OWNER_FLOW_COOKIE, path='/', secure=True, httponly=True, samesite='lax')
    return response


def parse_query(raw: bytes):
    if len(raw) > 4096:
        raise ValueError('bounded authentication query required')
    text = raw.decode('ascii')
    if any(ord(c) < 33 or ord(c) > 126 for c in text) or re.search(r'%(?![0-9a-fA-F]{2})', text):
        raise ValueError('invalid authentication query')
    pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True, max_num_fields=5,
        encoding='utf-8', errors='strict')
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError('duplicate authentication field')
    return dict(pairs)


class OAuthQueryBoundary:
    """Mutate the original ASGI scope before routing/access-log response events.

    The server sees an empty query for all auth paths, including malformed ones.
    Parsed fields exist only during request handling; upstream proxy logs require
    separate deployment configuration. No code/state is copied into scope state.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope.get('path', '').startswith(PREFIX):
            return await self.app(scope, receive, send)
        raw = scope.get('query_string', b'')
        scope['query_string'] = b''
        path = scope.get('path', '')
        # Keep sensitive values in a short-lived closure rather than printable
        # request query/state fields; remove the closure after handling.
        try:
            query = parse_query(raw) if path in (PREFIX + 'login', PREFIX + 'setup-owner', PREFIX + 'callback') else {}
        except (ValueError, UnicodeError):
            request_id = secrets.token_hex(12)
            response = clear_flow(JSONResponse({'code': 'INVALID_REQUEST',
                'safe_message': 'Authentication request fields are invalid.', 'retryable': False,
                'request_id': request_id}, status_code=400,
                headers={'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
                    'X-Content-Type-Options': 'nosniff', 'X-Request-ID': request_id}))
            await response(scope, receive, send)
            return
        scope.setdefault('state', {})['_auth_query'] = lambda: query
        try:
            await self.app(scope, receive, send)
        finally:
            scope.get('state', {}).pop('_auth_query', None)
            query = None
            raw = b''


def service(request):
    result = request.app.state.signin_service
    if result is None:
        raise StoreUnavailable('provider sign-in is not configured')
    if str(request.base_url).rstrip('/') != request.app.state.app_origin:
        raise Denied('configured HTTPS application origin required')
    return result


def fields(request):
    reader = getattr(request.state, '_auth_query', None)
    if reader is None:
        raise StoreUnavailable('authentication query protection is required')
    return reader()


@router.get('/login')
def login(request: Request):
    signin = service(request)
    parameters = fields(request)
    if set(parameters) - {'invitation_id', 'mfa'} or ('mfa' in parameters and parameters['mfa'] != 'required'):
        raise ValueError('invalid login fields')
    invitation = parameters.get('invitation_id')
    if invitation is not None:
        try:
            if str(UUID(invitation)) != invitation:
                raise ValueError()
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError('canonical invitation UUID required') from exc
    start = signin.flows.begin(invitation_id=invitation, require_mfa=parameters.get('mfa') == 'required')
    response = clear_flow(RedirectResponse(start.authorization_url, status_code=303))
    response.set_cookie(FLOW_COOKIE, start.browser_cookie, max_age=signin.flows.config.flow_ttl_seconds,
        secure=True, httponly=True, samesite='lax', path='/')
    return response


@router.get('/setup-owner')
def setup_owner(request: Request):
    service(request)  # Fixed configured origin, never a request-provided target.
    if fields(request):
        raise ValueError('owner setup accepts no fields')
    setup = request.app.state.owner_setup_service
    if setup is None:
        raise StoreUnavailable('first owner setup is not configured')
    start = setup.begin()
    response = clear_flow(RedirectResponse(start.authorization_url, status_code=303))
    response.set_cookie(OWNER_FLOW_COOKIE, start.browser_cookie, max_age=setup.flows.config.flow_ttl_seconds,
        secure=True, httponly=True, samesite='lax', path='/')
    return response


@router.get('/callback')
def callback(request: Request):
    signin = service(request)
    # Both realms use the same fixed quota key. Admission happens once even for
    # ambiguous/invalid callbacks; selection never falls back after a denial.
    signin.flows.admit_callback()
    cookie_name = FLOW_COOKIE
    if OWNER_FLOW_COOKIE in request.cookies:
        if FLOW_COOKIE in request.cookies:
            raise Denied('ambiguous browser sign-in flow; start again')
        signin = request.app.state.owner_setup_service
        if signin is None:
            raise Denied('owner setup is unavailable; start again')
        cookie_name = OWNER_FLOW_COOKIE
    parameters = fields(request)
    if (set(parameters) - {'state', 'code', 'error', 'error_description'}
            or not re.fullmatch(r'[A-Za-z0-9_-]{43}', parameters.get('state', ''))
            or ('code' in parameters) == ('error' in parameters)
            or ('code' in parameters and not re.fullmatch(r'[\x21-\x7e]{1,2048}', parameters['code']))
            or ('error' in parameters and not re.fullmatch(r'[A-Za-z0-9_]{1,128}', parameters['error']))
            or ('error_description' in parameters and ('error' not in parameters
                or not 1 <= len(parameters['error_description']) <= 1024))):
        raise ValueError('invalid callback fields')
    credentials = signin.complete(state=parameters['state'], browser_cookie=request.cookies.get(cookie_name, ''),
        code=parameters.get('code'), provider_error=parameters.get('error'))
    response = clear_flow(RedirectResponse(request.app.state.app_origin + '/', status_code=303))
    response.set_cookie(COOKIE, credentials.cookie,
        max_age=max(0, (credentials.expires_at_ms - signin.access.now()) // 1000),
        secure=True, httponly=True, samesite='lax', path='/')
    return response
