"""Owner control endpoints. Startup/readiness evidence has no public write route."""
from uuid import UUID

from fastapi import APIRouter,Depends,Request
from pydantic import BaseModel,ConfigDict,Field,StrictStr

from proofpack.auth.http import IfMatch,Idempotency,actor,version,write_guard
from proofpack.evidence.repository import StoreUnavailable

router=APIRouter(prefix='/api/v1/admin')


def runtime(request: Request):
    service=request.app.state.runtime_control
    if service is None:raise StoreUnavailable('runtime control is not configured')
    return service


class DisableBody(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    reason: StrictStr=Field(min_length=1,max_length=120,pattern=r'^[A-Za-z0-9][A-Za-z0-9 _.-]{0,119}$')


class EnableBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    receipt_id: UUID


@router.get('/runtime')
def read_runtime(current=Depends(actor),service=Depends(runtime)):
    return service.read(current)


@router.get('/maintenance')
def read_maintenance(request:Request,current=Depends(actor)):
    service=request.app.state.maintenance_driver
    if service is None:raise StoreUnavailable('maintenance is not configured')
    return service.read(current)


@router.post('/disable-inspection')
def disable(body: DisableBody,request: Request,key: Idempotency,match: IfMatch,
            current=Depends(actor),service=Depends(runtime)):
    write_guard(request,current)
    return service.disable(current,expected_version=version(match),reason=body.reason,idempotency_key=key)


@router.get('/readiness/{receipt_id}')
def readiness(receipt_id:UUID,current=Depends(actor),service=Depends(runtime)):
    return service.readiness(current,str(receipt_id))


@router.post('/enable-inspection')
def enable(body: EnableBody,request: Request,key: Idempotency,match: IfMatch,
           current=Depends(actor),service=Depends(runtime)):
    write_guard(request,current)
    return service.enable(current,expected_version=version(match),receipt_id=str(body.receipt_id),idempotency_key=key)
