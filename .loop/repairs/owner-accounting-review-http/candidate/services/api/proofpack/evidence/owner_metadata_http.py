"""Strict owner maintenance transport; review grants no cleanup or fulfillment."""
from typing import Annotated,Literal
from fastapi import APIRouter,Depends,Request
from pydantic import BaseModel,ConfigDict,Field,StringConstraints,StrictBool,model_validator
from proofpack.auth.http import actor,write_guard,Idempotency
from proofpack.evidence.repository import StoreUnavailable
from proofpack.evidence.corpus_accounting import POLICY

router=APIRouter(prefix='/api/v1/privacy/metadata-requests')
Identifier=Annotated[str,StringConstraints(strict=True,pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
Version=Annotated[int,Field(strict=True,ge=1,le=9007199254740991)]


class Body(BaseModel):model_config=ConfigDict(extra='forbid',strict=True)


class CreateBody(Body):
    inspection_ids:list[Identifier]=Field(min_length=1,max_length=64)
    expected_gate_version:Version
    expected_control_version:Version
    interruption_acknowledged:StrictBool


class CancelBody(Body):
    confirmed_scope_sha256:Annotated[str,StringConstraints(strict=True,pattern=r'^[a-f0-9]{64}$')]
    expected_request_version:Version
    expected_gate_version:Version
    expected_control_version:Version
    no_erasure_acknowledged:StrictBool


class ReviewBody(Body):
    expected_request_version:Version
    expected_gate_version:Version
    expected_control_version:Version


Count=Annotated[int,Field(strict=True,ge=0,le=9007199254740991)]


class ReviewCounts(Body):
    AFFECTED:Count
    SHARED:Count
    CONTEXT:Count
    UNRELATED:Count
    UNRESOLVED:Count


class ReviewResult(Body):
    id:Identifier
    scope_sha256:Annotated[str,StringConstraints(strict=True,pattern=r'^[a-f0-9]{64}$')]
    request_version:Version
    gate_version:Version
    control_version:Version
    accounting_policy:Literal[POLICY]
    counts:ReviewCounts
    total_records:Count
    historical:StrictBool
    read_only:StrictBool
    can_confirm_cleanup:StrictBool
    erasure_complete:StrictBool
    request_fulfilled:StrictBool

    @model_validator(mode='after')
    def non_authorizing(self):
        if (self.historical is not True or self.read_only is not True
                or self.can_confirm_cleanup is not False or self.erasure_complete is not False
                or self.request_fulfilled is not False or sum(self.counts.model_dump().values())!=self.total_records):
            raise ValueError('closed non-authorizing complete review required')
        return self


def service(request:Request):
    value=request.app.state.owner_metadata_service
    if value is None:raise StoreUnavailable('owner metadata requests are not configured')
    return value


@router.get('/context')
def context(current=Depends(actor),value=Depends(service)):return value.context(current)


@router.post('',status_code=201)
def create(body:CreateBody,request:Request,key:Idempotency,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.create(current,**{**body.model_dump(),'inspection_ids':tuple(body.inspection_ids)},idempotency_key=key)


@router.get('/{ident}')
def read(ident:Identifier,current=Depends(actor),value=Depends(service)):return value.get(current,ident)


@router.post('/{ident}/cancel')
def cancel(ident:Identifier,body:CancelBody,request:Request,key:Idempotency,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.cancel(current,ident=ident,**body.model_dump(),idempotency_key=key)


def review_service(request:Request):
    value=request.app.state.owner_metadata_review_service
    if value is None:raise StoreUnavailable('owner metadata review is not configured')
    return value


@router.post('/{ident}/review',response_model=ReviewResult)
def review(ident:Identifier,body:ReviewBody,request:Request,current=Depends(actor),value=Depends(review_service)):
    write_guard(request,current)
    return value.read(current,ident=ident,**body.model_dump())
