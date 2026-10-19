import json
from typing import Annotated,Literal
from uuid import UUID
from fastapi import APIRouter,Depends,Query,Request
from proofpack.auth.http import actor,write_guard,IfMatch,Idempotency,version
from proofpack.evidence.repository import StoreUnavailable
from proofpack.review.qualification_preparation import PreparationRequest
from proofpack.review.manifests import Consequence

router=APIRouter(prefix='/api/v1/qualification-preparations')


def service(request:Request):
    value=request.app.state.qualification_preparation_service
    if value is None:raise StoreUnavailable('qualification preparation is not configured')
    return value


@router.post('',status_code=201)
def create(body:dict,request:Request,key:Idempotency,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.create(current,request=PreparationRequest.model_validate_json(json.dumps(body,allow_nan=False)),idempotency_key=key)


@router.get('')
def catalog(limit:Annotated[int,Query(ge=1,le=20)]=20,cursor:Annotated[str|None,Query(max_length=36)]=None,
            scope:Literal['own','owner']='own',current=Depends(actor),value=Depends(service)):
    return value.list(current,limit=limit,cursor=cursor,owner_view=scope=='owner')


@router.get('/options')
def options(current=Depends(actor),value=Depends(service)):return value.options(current)


@router.get('/{ident}')
def read(ident:UUID,current=Depends(actor),value=Depends(service)):return value.job(current,str(ident))


@router.get('/{ident}/request')
def selections(ident:UUID,current=Depends(actor),value=Depends(service)):return value.selections(current,str(ident))


@router.get('/{ident}/entries')
def entries(ident:UUID,start:Annotated[int,Query(ge=0,le=1255)]=0,limit:Annotated[int,Query(ge=1,le=20)]=20,
            current=Depends(actor),value=Depends(service)):
    return value.entries(current,str(ident),start=start,limit=limit)


@router.post('/{ident}/retire')
def retire(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.retire(current,str(ident),request=Consequence.model_validate_json(json.dumps(body,allow_nan=False)),expected_version=version(match),idempotency_key=key)
