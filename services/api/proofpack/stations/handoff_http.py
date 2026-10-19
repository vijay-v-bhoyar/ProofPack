"""Explicit scoped support actions; no notification or capture delegation."""
from uuid import UUID
from fastapi import APIRouter, Depends, Request
from proofpack.auth.http import actor, Idempotency, IfMatch, version, write_guard
from proofpack.evidence.repository import StoreUnavailable
from proofpack.stations.handoffs import HandoffCancel, HandoffRequest, HandoffResponse

router=APIRouter(prefix='/api/v1')


def handoffs(request:Request):
    service=request.app.state.handoff_service
    if service is None:raise StoreUnavailable('support handoff service is not configured')
    return service


@router.post('/inspections/{ident}/handoffs',status_code=201)
def create(ident:UUID,body:HandoffRequest,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(handoffs)):
    write_guard(request,current)
    return service.request(current,str(ident),expected_version=version(match),request=body,idempotency_key=key)


@router.get('/inspections/{ident}/handoffs/latest')
def latest(ident:UUID,current=Depends(actor),service=Depends(handoffs)):
    return service.latest(current,str(ident))


@router.get('/inspections/{ident}/handoffs/{request_id}')
def read(ident:UUID,request_id:UUID,current=Depends(actor),service=Depends(handoffs)):
    return service.read(current,str(ident),str(request_id))


@router.get('/handoffs/inbox')
def inbox(cursor:UUID|None=None,current=Depends(actor),service=Depends(handoffs)):
    return service.inbox(current,cursor=None if cursor is None else str(cursor))


@router.post('/inspections/{ident}/handoffs/{request_id}/respond')
def respond(ident:UUID,request_id:UUID,body:HandoffResponse,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(handoffs)):
    write_guard(request,current)
    return service.respond(current,str(ident),str(request_id),expected_version=version(match),response=body,idempotency_key=key)


@router.post('/inspections/{ident}/handoffs/{request_id}/cancel')
def cancel(ident:UUID,request_id:UUID,body:HandoffCancel,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(handoffs)):
    write_guard(request,current)
    return service.cancel(current,str(ident),str(request_id),expected_version=version(match),request=body,idempotency_key=key)
