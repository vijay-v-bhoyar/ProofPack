"""Optional ASGI lifetime registration; factory and ordinary-worker wiring are separate."""
from functools import partial
from contextlib import nullcontext
import re
import json
import secrets
from uuid import uuid4

import anyio

from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionHeld, bind_admission, _bind_control
from proofpack.evidence.repository import StoreConflict, StoreUnavailable
from proofpack.runtime.ownership import ResourceOwner
from proofpack.runtime.public_web import FrozenWeb


def _control_route(scope,*,owner_review=False,collateral_review=False):
    path=scope.get('path');method=scope.get('method')
    if type(collateral_review) is not bool or (collateral_review and not owner_review) or type(owner_review) is not bool or type(path) is not str or scope.get('raw_path') != path.encode('utf-8'):
        return False
    base='/api/v1/privacy/metadata-requests'
    if (method,path)==('GET',base+'/current'):
        return scope.get('query_string',b'')==b''
    if (method,path) in {('GET',base+'/context'),('POST',base),
            ('GET','/api/v1/auth/login'),('GET','/api/v1/auth/callback'),
            ('GET','/api/v1/auth/session'),('GET','/api/v1/auth/notice'),
            ('GET','/api/v1/me'),('POST','/api/v1/auth/logout')}:
        return True
    uuid=r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    if owner_review and method=='POST' and re.fullmatch(base+'/'+uuid+'/policy-obligations',path) is not None:
        return scope.get('query_string',b'')==b''
    return ((method=='GET' and re.fullmatch(base+'/'+uuid,path) is not None)
        or (method=='POST' and re.fullmatch(base+'/'+uuid+'/cancel',path) is not None)
        or (owner_review and method=='POST' and re.fullmatch(base+'/'+uuid+'/review',path) is not None)
        or (collateral_review and owner_review and method=='POST' and re.fullmatch(base+'/'+uuid+'/collateral-scope-proposal',path) is not None))


class MetadataAdmissionBoundary:
    def __init__(self, app, *, admission, lease_ms, attempts, resource_owner=None, owner_control=False, owner_review=False, collateral_review=False, public_web=None):
        if (not callable(app) or type(admission) is not PersistentAdmission
                or type(lease_ms) is not int or not 1 <= lease_ms <= admission.limits.max_lease_ms
                or type(attempts) is not int or not 1 <= attempts <= 3
                or (resource_owner is not None and type(resource_owner) is not ResourceOwner)
                or type(owner_control) is not bool or (owner_control and resource_owner is None)
                or type(owner_review) is not bool or (owner_review and not owner_control)
                or type(collateral_review) is not bool or (collateral_review and not owner_review)
                or (public_web is not None and (type(public_web) is not FrozenWeb or not owner_control
                    or admission.limits.max_active < len(public_web.assets)))):
            raise ValueError('explicit admission coordinator, lifetime and retry bounds required')
        self.app = app; self.admission = admission; self.lease_ms = lease_ms; self.attempts = attempts
        self.release_pending = False; self.resource_owner = resource_owner
        self.owner_control=owner_control;self.owner_review=owner_review;self.collateral_review=collateral_review;self._pending_control_ticket=None;self.public_web=public_web

    async def _run(self, operation):
        return await anyio.to_thread.run_sync(operation, abandon_on_cancel=False)

    async def _attempt(self, operation):
        for index in range(self.attempts):
            try:
                return await self._run(operation)
            except StoreConflict:
                if index+1 == self.attempts:
                    raise

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            await self.app(scope, receive, send)
            return
        if scope['type'] != 'http':
            if scope['type'] == 'websocket':
                await send({'type': 'websocket.close', 'code': 1013})
                return
            raise AdmissionHeld('unsupported unregistered application scope')
        if scope.get('path') == '/health/live' and scope.get('method') in {'GET', 'HEAD'}:
            body = b'{"status":"ok"}'
            await send({'type':'http.response.start', 'status':200, 'headers':[
                (b'content-type',b'application/json'), (b'content-length',str(len(body)).encode()),
                (b'cache-control',b'no-store'), (b'x-content-type-options',b'nosniff'),
                (b'referrer-policy',b'no-referrer'), (b'x-frame-options',b'DENY'),
                (b'content-security-policy',b"default-src 'none'; frame-ancestors 'none'")]})
            await send({'type':'http.response.body', 'body':body if scope['method']=='GET' else b'', 'more_body':False})
            return
        intent = None; uncertain = False; started = False; completed = False; ticket = None; release_unconfirmed = False
        control=self.owner_control and _control_route(scope,owner_review=self.owner_review,collateral_review=self.collateral_review)
        public=(self.public_web is not None and scope.get('method') in {'GET','HEAD'}
            and scope.get('path') in self.public_web.paths and scope.get('raw_path')==scope['path'].encode('utf-8'))
        prepare=self.admission._prepare_control if control else partial(self.admission.prepare,kind='http')
        admit=self.admission._admit_control if control else self.admission.admit
        checkpoint=self.admission._checkpoint_control if control else self.admission.checkpoint
        release=self.admission._release_control if control else self.admission.release
        bind=_bind_control if control else bind_admission
        if public:
            prepare=self.admission._prepare_public_asset;admit=self.admission._admit_public_asset
            checkpoint=self.admission._checkpoint_public_asset;release=self.admission._release_public_asset
        # File delivery performed by the server after application return would
        # outlive this registration. Force ordinary awaited body delivery instead.
        forwarded = {**scope, 'extensions': {key: value for key, value in scope.get('extensions', {}).items()
                     if key not in {'http.response.pathsend', 'http.response.zerocopysend'}}}
        async def guarded_send(message):
            nonlocal started, completed
            kind = message.get('type', '')
            if kind in {'http.response.pathsend', 'http.response.zerocopysend'}:
                raise AdmissionHeld('untracked file delivery unavailable')
            if kind.startswith('http.response.'):
                await self._run(partial(checkpoint, intent))
            if kind == 'http.response.start': started = True
            if kind == 'http.response.body' and not message.get('more_body', False): completed = True
            await send(message)
        try:
            if self.resource_owner is not None: ticket = self.resource_owner.acquire()
            intent = await self._run(partial(prepare, work_id=str(uuid4()), lease_ms=self.lease_ms))
            await self._attempt(partial(admit, intent))
            await self._run(partial(checkpoint, intent))
            with (nullcontext() if public else bind(self.admission, intent)):
                await self.app(forwarded, receive, guarded_send)
        except (AdmissionHeld, StoreConflict, StoreUnavailable):
            if not started:
                request_id=secrets.token_hex(12)
                body=json.dumps({'code':'METADATA_MAINTENANCE',
                    'safe_message':'This work is temporarily unavailable. Use the agreed manual process or contact your supervisor.',
                    'request_id':request_id,'retryable':True},separators=(',',':')).encode()
                await send({'type': 'http.response.start', 'status': 503, 'headers': [
                    (b'content-type', b'application/json'), (b'cache-control', b'no-store'),
                    (b'content-length',str(len(body)).encode()),(b'x-content-type-options', b'nosniff'),
                    (b'referrer-policy',b'no-referrer'),(b'x-frame-options',b'DENY'),
                    (b'content-security-policy',b"default-src 'none'; frame-ancestors 'none'"),
                    (b'x-request-id',request_id.encode())]})
                await send({'type': 'http.response.body', 'body':body if scope.get('method')!='HEAD' else b'',
                            'more_body': False})
            elif not completed:
                # Status/bytes already emitted cannot be recalled or replaced.
                await send({'type': 'http.response.body', 'body': b'', 'more_body': False})
        except BaseException as error:
            if not isinstance(error, Exception):
                uncertain = True  # Cancellation/termination is not executor-stop evidence.
            raise
        finally:
            try:
                if intent is not None and not uncertain:
                    with anyio.CancelScope(shield=True):
                        try:
                            await self._attempt(partial(release, intent))
                        except (AdmissionHeld, StoreConflict, StoreUnavailable):
                            self.release_pending = True; release_unconfirmed = True
                        except Exception:
                            self.release_pending = True; release_unconfirmed = True
                            raise
            except BaseException as error:
                if not isinstance(error, Exception):
                    uncertain = True
                    self.release_pending = True; release_unconfirmed = True
                raise
            finally:
                if (control or public) and (uncertain or release_unconfirmed):
                    self._pending_control_ticket=ticket
                    uncertain=True
                if ticket is not None and not uncertain:
                    self.resource_owner.release(ticket)
