"""Dataset metadata selection, audited read and explicit retirement/declassification."""
import json
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, Request, Query
from proofpack.auth.http import actor, write_guard, IfMatch, Idempotency, version
from proofpack.auth.policy import Role
from proofpack.evidence.repository import StoreUnavailable
from proofpack.review.manifests import ManifestRequest, Consequence

router=APIRouter(prefix='/api/v1/datasets')


def service(request:Request):
    value=request.app.state.dataset_service
    if value is None:raise StoreUnavailable('dataset manifests are not configured')
    return value


@router.post('/manifests',status_code=201)
def create(body:dict,request:Request,key:Idempotency,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.create(current,request=ManifestRequest.model_validate_json(json.dumps(body,allow_nan=False)),idempotency_key=key)


@router.get('/manifests')
def catalog(limit:Annotated[int,Query(ge=1,le=20)]=20,cursor:Annotated[str|None,Query(max_length=36)]=None,current=Depends(actor),value=Depends(service)):
    return value.list(current,limit=limit,cursor=cursor)


@router.get('/manifests/{ident}')
def read(ident:UUID,current=Depends(actor),value=Depends(service)):
    value.access._fresh(current,Role.REVIEWER);return value.job(current,str(ident))


@router.get('/manifests/{ident}/request')
def selections(ident:UUID,current=Depends(actor),value=Depends(service)):return value.selections(current,str(ident))


@router.get('/manifests/{ident}/examples')
def examples(ident:UUID,start:Annotated[int,Query(ge=0,le=999)]=0,limit:Annotated[int,Query(ge=1,le=20)]=20,current=Depends(actor),value=Depends(service)):
    return value.examples(current,str(ident),start=start,limit=limit)


@router.post('/manifests/{ident}/retire')
def retire(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.retire(current,str(ident),request=Consequence.model_validate_json(json.dumps(body,allow_nan=False)),expected_version=version(match),idempotency_key=key)


@router.get('/groups/{ident}')
def group(ident:str,current=Depends(actor),value=Depends(service)):return value.group(current,ident)


@router.post('/groups/{ident}/declassify')
def declassify(ident:str,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.declassify(current,ident,request=Consequence.model_validate_json(json.dumps(body,allow_nan=False)),expected_version=version(match),idempotency_key=key)
