"""Identity control plane. Only opaque server sessions authorize these routes."""
import asyncio
from collections import deque
import json
import re
from typing import Annotated
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter,Depends,Header,HTTPException,Query,Request,Response
from pydantic import BaseModel,ConfigDict,Field,StrictBool,StrictStr

from proofpack.auth.policy import Denied,Role,validate_csrf
from proofpack.evidence.repository import StoreUnavailable

COOKIE='__Host-proofpack-session'
FLOW_COOKIE='__Host-proofpack-oauth'
router=APIRouter(prefix='/api/v1')


class IdentityJSONLimit:
    """Read bounded identity bodies before framework JSON parsing, including chunked input."""
    def __init__(self,app,max_bytes=8192,prefixes=None):self.app=app;self.max_bytes=max_bytes;self.prefixes=prefixes

    async def __call__(self,scope,receive,send):
        path=scope.get('path','')
        relevant=any(path==prefix or path.startswith(prefix+'/') for prefix in
            (self.prefixes if self.prefixes is not None else ('/api/v1/invitations','/api/v1/users','/api/v1/owner-transfers','/api/v1/auth/logout','/api/v1/admin','/api/v1/recipes','/api/v1/stations','/api/v1/purposes','/api/v1/calibrations','/api/v1/labels','/api/v1/policies','/api/v1/evaluations','/api/v1/qualification-preparations','/api/v1/policy-qualifications','/api/v1/policy-activations','/api/v1/privacy','/api/v1/jobs')))
        relevant=relevant or (self.prefixes is None and (path=='/api/v1/inspections' or (path.startswith('/api/v1/inspections/') and path.endswith(('/close','/capture-permits','/prepare-capture','/complete','/exports','/handoffs','/respond','/cancel')))))
        if scope['type']!='http' or scope['method'] not in {'POST','PATCH','PUT'} or not relevant:
            return await self.app(scope,receive,send)
        body=bytearray()
        try:
            async with asyncio.timeout(5):
                while True:
                    event=await receive()
                    if event['type']=='http.disconnect':return
                    body.extend(event.get('body',b''))
                    if len(body)>self.max_bytes:return await self.error(scope,send,413,'BODY_LIMIT','Request body exceeds the identity limit.')
                    if not event.get('more_body',False):break
        except TimeoutError:
            return await self.error(scope,send,408,'BODY_TIMEOUT','Request body was not received in time.')
        events=deque([{'type':'http.request','body':bytes(body),'more_body':False}])
        async def replay():return events.popleft() if events else await receive()
        await self.app(scope,replay,send)

    @staticmethod
    async def error(scope,send,status,code,message):
        payload=json.dumps({'code':code,'safe_message':message,'request_id':scope.get('state',{}).get('request_id'),
                            'retryable':False}).encode()
        await send({'type':'http.response.start','status':status,'headers':[(b'content-type',b'application/json'),(b'content-length',str(len(payload)).encode())]})
        await send({'type':'http.response.body','body':payload})


def validate_origin(value):
    if not isinstance(value,str):raise ValueError('explicit HTTPS application origin required')
    parsed=urlsplit(value)
    if (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):raise ValueError('exact HTTPS origin required')
    return value


def access(request: Request):
    service=request.app.state.access_service
    if service is None:raise StoreUnavailable('identity is not configured')
    return service


def actor(request: Request,service=Depends(access)):
    try:current=service.resolve(request.cookies.get(COOKIE,''),allow_invitee=True)
    except Denied as exc:raise HTTPException(status_code=401) from exc
    if current.principal is None:raise Denied('membership activation required')
    return current


def invitee(request: Request,service=Depends(access)):
    try:return service.resolve(request.cookies.get(COOKIE,''),allow_invitee=True)
    except Denied as exc:raise HTTPException(status_code=401) from exc


def write_guard(request: Request,current):
    validate_csrf(expected_origin=request.app.state.app_origin,origin=request.headers.get('Origin'),
        csrf_header=request.headers.get('X-CSRF-Token'),csrf_hash=current.session.data['csrf_hash'])


def version(value: str) -> int:
    if not re.fullmatch(r'(?:[1-9][0-9]{0,11}|"[1-9][0-9]{0,11}")',value):
        raise ValueError('positive If-Match version required')
    return int(value.strip('"'))


Idempotency=Annotated[str,Header(alias='Idempotency-Key',min_length=1,max_length=128)]
IfMatch=Annotated[str,Header(alias='If-Match',min_length=1,max_length=14)]


class Body(BaseModel):model_config=ConfigDict(extra='forbid')


class InviteBody(Body):
    target_subject: StrictStr=Field(min_length=1,max_length=256)
    target_email: StrictStr=Field(min_length=3,max_length=254)
    roles: list[Role]=Field(max_length=3)
    ttl_seconds: int=Field(strict=True,ge=1,le=86400)


class AcceptBody(Body):
    capability: StrictStr=Field(min_length=1,max_length=128)
    notice_version: StrictStr=Field(min_length=1,max_length=128)
    notice_sha256: StrictStr=Field(pattern=r'^[a-f0-9]{64}$')


class AccessBody(Body):
    roles: list[Role]=Field(max_length=3)
    enabled: StrictBool


class TransferBody(Body):target_id: UUID


@router.get('/me')
def me(current=Depends(actor),service=Depends(access)):return service.me(current)


@router.get('/auth/notice')
def notice(current=Depends(invitee),service=Depends(access)):return service.operational_notice(current)


@router.get('/auth/session')
def session_view(current=Depends(invitee),service=Depends(access)):return service.session_view(current)


@router.get('/users')
def users(current=Depends(actor),service=Depends(access),limit: int=Query(100,ge=1,le=100),cursor: str | None=Query(None,max_length=2048)):
    return service.list_users(current,limit=limit,cursor=cursor)


@router.post('/invitations',status_code=201)
def invite(body: InviteBody,request: Request,key: Idempotency,current=Depends(actor),service=Depends(access)):
    write_guard(request,current)
    return service.create_invitation(current,**body.model_dump(),idempotency_key=key)


@router.get('/invitations')
def invitation_list(current=Depends(actor),service=Depends(access),limit: int=Query(100,ge=1,le=100),cursor: str | None=Query(None,max_length=2048)):
    return service.list_invitations(current,limit=limit,cursor=cursor)


@router.get('/invitations/{ident}')
def invitation_read(ident: UUID,current=Depends(invitee),service=Depends(access)):
    return service.read_invitation(current,invitation_id=str(ident))


@router.post('/invitations/{ident}/accept')
def accept(ident: UUID,body: AcceptBody,request: Request,response: Response,key: Idempotency,current=Depends(invitee),service=Depends(access)):
    write_guard(request,current)
    result=service.accept_invitation(current,invitation_id=str(ident),**body.model_dump(),idempotency_key=key)
    if current.member is None:response.delete_cookie(COOKIE,path='/',secure=True,httponly=True,samesite='lax')
    return result


@router.post('/invitations/{ident}/revoke')
def revoke(ident: UUID,request: Request,key: Idempotency,match: IfMatch,current=Depends(actor),service=Depends(access)):
    write_guard(request,current)
    return service.revoke_invitation(current,invitation_id=str(ident),expected_revision=version(match),idempotency_key=key)


@router.post('/invitations/{ident}/decline')
def decline(ident: UUID,request: Request,response: Response,key: Idempotency,current=Depends(invitee),service=Depends(access)):
    write_guard(request,current)
    result=service.decline_invitation(current,invitation_id=str(ident),idempotency_key=key)
    if current.member is None:response.delete_cookie(COOKIE,path='/',secure=True,httponly=True,samesite='lax')
    return result


@router.patch('/users/{ident}/access')
def update_access(ident: UUID,body: AccessBody,request: Request,key: Idempotency,match: IfMatch,current=Depends(actor),service=Depends(access)):
    write_guard(request,current)
    return service.change_access(current,user_id=str(ident),**body.model_dump(),expected_version=version(match),idempotency_key=key)


@router.post('/users/{ident}/sessions/revoke')
def revoke_sessions(ident: UUID,request: Request,key: Idempotency,match: IfMatch,current=Depends(actor),service=Depends(access)):
    write_guard(request,current)
    return service.revoke_sessions(current,user_id=str(ident),expected_version=version(match),idempotency_key=key)


@router.post('/owner-transfers',status_code=201)
def transfer(body: TransferBody,request: Request,key: Idempotency,match: IfMatch,current=Depends(actor),service=Depends(access)):
    write_guard(request,current)
    return service.begin_transfer(current,target_id=str(body.target_id),expected_target_version=version(match),idempotency_key=key)


@router.post('/owner-transfers/{ident}/accept')
def transfer_accept(ident: UUID,request: Request,key: Idempotency,current=Depends(actor),service=Depends(access)):
    write_guard(request,current)
    return service.accept_transfer(current,transfer_id=str(ident),idempotency_key=key)


@router.get('/owner-transfers/{ident}')
def transfer_read(ident: UUID,current=Depends(actor),service=Depends(access)):
    return service.read_transfer(current,str(ident))


@router.post('/auth/logout',status_code=204)
def logout(request: Request,key: Idempotency,service=Depends(access)):
    if request.headers.get('Origin')!=request.app.state.app_origin:raise Denied('origin required')
    service.logout(request.cookies.get(COOKIE,''),request.headers.get('X-CSRF-Token',''))
    response=Response(status_code=204)
    response.delete_cookie(COOKIE,path='/',secure=True,httponly=True,samesite='lax')
    response.delete_cookie(FLOW_COOKIE,path='/',secure=True,httponly=True,samesite='lax')
    return response
