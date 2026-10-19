"""Recipe metadata endpoints. Qualification and reference proof cannot be uploaded here."""
from typing import Annotated,Literal
from uuid import UUID

from fastapi import APIRouter,Depends,Query,Request
from pydantic import BaseModel,ConfigDict,StrictStr,Field

from proofpack.auth.http import IfMatch,Idempotency,actor,version,write_guard
from proofpack.evidence.repository import StoreUnavailable

router=APIRouter(prefix='/api/v1/recipes')


def recipes(request: Request):
    service=request.app.state.recipe_service
    if service is None:raise StoreUnavailable('recipe service is not configured')
    return service


class DraftBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    content: dict


class ApprovalBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    qualification_id: UUID


class RetirementBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    reason: StrictStr=Field(min_length=1,max_length=120)


@router.get('')
def list_recipes(view:Literal['approved','candidates']='approved',limit:Annotated[int,Query(ge=1,le=20)]=20,
                 cursor:Annotated[str|None,Query(max_length=2048)]=None,current=Depends(actor),service=Depends(recipes)):
    return service.list(current,view=view,limit=limit,cursor=cursor)


@router.post('',status_code=201)
def create(body:DraftBody,request:Request,key:Idempotency,current=Depends(actor),service=Depends(recipes)):
    write_guard(request,current)
    return service.create(current,content=body.content,idempotency_key=key)


@router.get('/{ident}/draft')
def draft(ident:UUID,current=Depends(actor),service=Depends(recipes)):
    return service.draft(current,str(ident))


@router.put('/{ident}/draft')
def save(ident:UUID,body:DraftBody,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(recipes)):
    write_guard(request,current)
    return service.save(current,recipe_id=str(ident),content=body.content,expected_version=version(match),idempotency_key=key)


@router.get('/{ident}/qualifications/{qualification_id}')
def qualification(ident:UUID,qualification_id:UUID,current=Depends(actor),service=Depends(recipes)):
    return service.qualification(current,recipe_id=str(ident),qualification_id=str(qualification_id))


@router.post('/{ident}/approve')
def approve(ident:UUID,body:ApprovalBody,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(recipes)):
    write_guard(request,current)
    return service.approve(current,recipe_id=str(ident),qualification_id=str(body.qualification_id),
        expected_version=version(match),idempotency_key=key)


@router.post('/{ident}/retire')
def retire(ident:UUID,body:RetirementBody,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(recipes)):
    write_guard(request,current)
    return service.retire(current,recipe_id=str(ident),reason=body.reason,expected_version=version(match),idempotency_key=key)
