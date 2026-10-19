"""Explicit owner transitions and role-scoped current versus historical metadata."""
import json
from typing import Literal
from uuid import UUID
from fastapi import APIRouter,Depends,Request
from proofpack.auth.http import actor,write_guard,IfMatch,Idempotency,version
from proofpack.evidence.repository import StoreUnavailable
from proofpack.planner.activation import ActivationRequest

router=APIRouter(prefix='/api/v1')


def service(request:Request):
    value=request.app.state.policy_activation_service
    if value is None:raise StoreUnavailable('genuine policy activation is not configured')
    return value


@router.get('/policies/active')
def current_policy(request:Request,scope:Literal['summary','owner']='summary',current=Depends(actor),value=Depends(service)):
    reader=request.app.state.active_policy_reader
    if reader is None:raise StoreUnavailable('trusted current policy reader is not configured')
    return value.current(current,reader,owner_view=scope=='owner')


@router.get('/policy-activations/{ident}')
def receipt(ident:UUID,current=Depends(actor),value=Depends(service)):return value.receipt(current,str(ident))


def transition(ident,operation,body,request,key,match,current,value):
    write_guard(request,current)
    selected=ActivationRequest.model_validate_json(json.dumps(body,allow_nan=False))
    if str(ident)!=selected.policy_id or operation!=selected.operation or version(match)!=selected.policy_state_version:
        raise ValueError('exact path, operation and candidate If-Match required')
    return value.transition(current,request=selected,idempotency_key=key)


@router.post('/policies/{ident}/bootstrap')
def bootstrap(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),value=Depends(service)):
    return transition(ident,'bootstrap',body,request,key,match,current,value)


@router.post('/policies/{ident}/promote')
def promote(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),value=Depends(service)):
    return transition(ident,'promote',body,request,key,match,current,value)


@router.post('/policies/{ident}/rollback')
def rollback(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),value=Depends(service)):
    return transition(ident,'rollback',body,request,key,match,current,value)
