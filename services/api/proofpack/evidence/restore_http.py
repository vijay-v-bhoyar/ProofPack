"""Protected restore admission outside configured data/auth/static handlers."""
import json
import secrets
from threading import BoundedSemaphore
import anyio

from proofpack.evidence.restore_fence import RestoreDataFence
from proofpack.evidence.repository import StoreUnavailable
from proofpack.evidence.privacy_admission import AdmissionHeld
from proofpack.runtime.ownership import ResourceOwner


class RestoreDataBoundary:
    def __init__(self, app, *, fence, resource_owner, max_active):
        if (not callable(app) or type(fence) is not RestoreDataFence
                or type(resource_owner) is not ResourceOwner
                or type(max_active) is not int or not 1 <= max_active <= 64):
            raise ValueError('exact shared restore fence, resource ownership and finite admission required')
        self.app, self.fence, self.resource_owner, self.max_active = app, fence, resource_owner, max_active
        self._requests = BoundedSemaphore(max_active)
        self._checks = BoundedSemaphore(max_active)
        self._initial = app, fence, resource_owner, max_active, self._requests, self._checks

    def _same(self):
        app, fence, owner, limit, requests, checks = self._initial
        if (self.app is not app or self.fence is not fence or self.resource_owner is not owner
                or type(self.max_active) is not int or self.max_active != limit
                or self._requests is not requests or self._checks is not checks):
            raise AdmissionHeld('original restore transport configuration changed')

    def _owned_check(self):
        self._same()
        owner, checks = self._initial[2], self._initial[5]
        if not checks.acquire(blocking=False):
            raise AdmissionHeld('restore check capacity held')
        ticket = None
        try:
            # The worker itself owns this ticket until actual synchronous return,
            # even if its asynchronous waiter has been cancelled.
            ticket = owner.acquire()
            self.fence.check()
            self._same()
        finally:
            if ticket is not None:
                owner.release(ticket)
            checks.release()

    async def _check(self):
        await anyio.to_thread.run_sync(self._owned_check, abandon_on_cancel=False)

    async def _held(self, scope, send):
        request_id = secrets.token_hex(12)
        body = json.dumps({'code':'RESTORE_ADMISSION_HELD',
            'safe_message':'This service is unavailable pending the agreed recovery review. Contact the service operator.',
            'request_id':request_id, 'retryable':False}, separators=(',', ':')).encode()
        await send({'type':'http.response.start', 'status':503, 'headers':[
            (b'content-type',b'application/json'), (b'content-length',str(len(body)).encode()),
            (b'cache-control',b'no-store'), (b'x-content-type-options',b'nosniff'),
            (b'referrer-policy',b'no-referrer'), (b'x-frame-options',b'DENY'),
            (b'content-security-policy',b"default-src 'none'; frame-ancestors 'none'"),
            (b'x-request-id',request_id.encode())]})
        await send({'type':'http.response.body','body':body if scope.get('method')!='HEAD' else b'', 'more_body':False})

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'lifespan':
            self._same()
            await self.app(scope, receive, send)
            return
        if scope['type'] != 'http':
            if scope['type'] == 'websocket':
                await send({'type':'websocket.close','code':1013})
                return
            raise AdmissionHeld('unsupported restore transport scope')
        if (scope.get('path') == '/health/live' and scope.get('method') in {'GET','HEAD'}
                and scope.get('raw_path') in {None,b'/health/live'}):
            body = b'{"status":"ok"}'
            await send({'type':'http.response.start','status':200,'headers':[
                (b'content-type',b'application/json'),(b'content-length',str(len(body)).encode()),
                (b'cache-control',b'no-store'),(b'x-content-type-options',b'nosniff'),
                (b'referrer-policy',b'no-referrer'),(b'x-frame-options',b'DENY'),
                (b'content-security-policy',b"default-src 'none'; frame-ancestors 'none'")]})
            await send({'type':'http.response.body','body':body if scope['method']=='GET' else b'', 'more_body':False})
            return
        try:
            self._same()
        except AdmissionHeld:
            await self._held(scope,send)
            return
        owner, requests = self._initial[2], self._initial[4]
        if not requests.acquire(blocking=False):
            await self._held(scope, send)
            return
        ticket = None
        started = completed = False
        async def guarded_send(message):
            nonlocal started, completed
            kind = message.get('type','')
            if kind in {'http.response.pathsend','http.response.zerocopysend'}:
                raise AdmissionHeld('untracked restore data delivery unavailable')
            if kind.startswith('http.response.'):
                await self._check()
            if kind == 'http.response.start': started = True
            if kind == 'http.response.body' and not message.get('more_body',False): completed = True
            await send(message)
        try:
            ticket = owner.acquire()
            await self._check()
            forwarded = {**scope, 'extensions': {k:v for k,v in scope.get('extensions',{}).items()
                if k not in {'http.response.pathsend','http.response.zerocopysend'}}}
            await self.app(forwarded, receive, guarded_send)
        except (AdmissionHeld, StoreUnavailable):
            if not started:
                await self._held(scope, send)
            elif not completed:
                await send({'type':'http.response.body','body':b'', 'more_body':False})
        finally:
            # Configured construction requires the inner metadata boundary,
            # which retains uncertain producer ownership. Our native checks
            # separately retain their own tickets until physical completion.
            if ticket is not None: owner.release(ticket)
            requests.release()
