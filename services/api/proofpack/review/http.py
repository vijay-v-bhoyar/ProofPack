"""Scoped review metadata and immutable operational-label revisions."""
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter,Depends,Query,Request

from proofpack.auth.http import IfMatch,Idempotency,actor,version,write_guard
from proofpack.evidence.repository import StoreUnavailable
from proofpack.review.labels import LabelRequest,ReviewTuple

router=APIRouter(prefix='/api/v1')


def labels(request:Request):
    service=request.app.state.label_service
    if service is None:raise StoreUnavailable('outcome review not configured')
    return service


@router.get('/review/context')
def context(before_observation_id:UUID,action_id:UUID|None=None,after_observation_id:UUID|None=None,
            current=Depends(actor),service=Depends(labels)):
    tuple_=ReviewTuple(before_observation_id=str(before_observation_id),action_id=None if action_id is None else str(action_id),
        after_observation_id=None if after_observation_id is None else str(after_observation_id))
    return service.context(current,tuple_)


@router.get('/labels')
def list_labels(limit:Annotated[int,Query(ge=1,le=20)]=20,cursor:Annotated[str|None,Query(max_length=36)]=None,
                current=Depends(actor),service=Depends(labels)):
    return service.list(current,limit=limit,cursor=cursor)


@router.get('/labels/{ident}')
def get_label(ident:UUID,revision:Annotated[int|None,Query(ge=1)]=None,current=Depends(actor),service=Depends(labels)):
    return service.get(current,str(ident),revision=revision)


@router.post('/labels',status_code=201)
def create_label(body:dict,request:Request,key:Idempotency,current=Depends(actor),service=Depends(labels)):
    write_guard(request,current)
    return service.write(current,request=LabelRequest.model_validate_json(json.dumps(body,allow_nan=False)),idempotency_key=key)


@router.post('/labels/{ident}/revisions',status_code=201)
def revise_label(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(labels)):
    write_guard(request,current)
    return service.write(current,request=LabelRequest.model_validate_json(json.dumps(body,allow_nan=False)),
        idempotency_key=key,ident=str(ident),expected_version=version(match))
