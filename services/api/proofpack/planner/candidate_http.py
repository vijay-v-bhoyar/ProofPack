"""Role-scoped policy drafts; deliberately no evaluation/activation endpoint."""
import json
from typing import Annotated, Literal
from uuid import UUID
from fastapi import APIRouter, Depends, Query, Request
from proofpack.auth.http import actor, write_guard, IfMatch, Idempotency, version
from proofpack.auth.policy import Role
from proofpack.evidence.repository import StoreUnavailable
from proofpack.planner.candidates import PolicyDraft

router=APIRouter(prefix='/api/v1/policies')


def service(request:Request):
    value=request.app.state.policy_service
    if value is None:raise StoreUnavailable('policy catalog is not configured')
    return value


@router.get('')
def catalog(limit:Annotated[int,Query(ge=1,le=20)]=20,cursor:Annotated[str|None,Query(max_length=36)]=None,current=Depends(actor),value=Depends(service)):
    return value.list(current,limit=limit,cursor=cursor)


@router.post('',status_code=201)
def create(body:dict,request:Request,key:Idempotency,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.write(current,request=PolicyDraft.model_validate_json(json.dumps(body,allow_nan=False)),idempotency_key=key)


@router.get('/{ident}')
def read(ident:UUID,request:Request,revision:Annotated[int|None,Query(ge=1,le=1000)]=None,
         view:Literal['candidate','approved']|None=None,current=Depends(actor),value=Depends(service)):
    if view=='approved' or (view is None and not current.principal.roles.intersection({Role.OWNER,Role.REVIEWER})):
        activation=request.app.state.policy_activation_service;reader=request.app.state.active_policy_reader
        if activation is None or reader is None or activation.policies is not value:
            raise StoreUnavailable('shared trusted approved policy reader is not configured')
        return activation.current(current,reader,policy_id=str(ident),revision=revision)
    return value.get(current,str(ident),revision=revision)


@router.post('/{ident}/revisions',status_code=201)
def revise(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.write(current,request=PolicyDraft.model_validate_json(json.dumps(body,allow_nan=False)),idempotency_key=key,ident=str(ident),expected_version=version(match))
