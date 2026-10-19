"""Station control and inspection admission endpoints. No camera/pass endpoint."""
from typing import Annotated,Literal
from uuid import UUID

from fastapi import APIRouter,Depends,Query,Request
from pydantic import BaseModel,ConfigDict,Field,StrictBool,StrictInt,StrictStr

from proofpack.auth.http import actor,Idempotency,IfMatch,version,write_guard
from proofpack.evidence.repository import StoreUnavailable

router=APIRouter(prefix='/api/v1')
Disposition=Literal['rework','reject','cancelled','human_accepted']


def stations(request:Request):
    service=request.app.state.station_service
    if service is None:raise StoreUnavailable('station lifecycle is not configured')
    return service


class Body(BaseModel):model_config=ConfigDict(extra='forbid')
class Profile(Body):
    name:StrictStr=Field(min_length=1,max_length=80)
    calibration_profile_id:StrictStr=Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
    disposition:Disposition|None=None
class Acquire(Body):
    expected_epoch:StrictInt=Field(ge=0)
    expected_owner_session_id:UUID|None
    takeover_ack:StrictBool=False
    reason:StrictStr|None=Field(default=None,min_length=1,max_length=120)
    disposition:Disposition|None=None
class Release(Body):
    expected_epoch:StrictInt=Field(ge=0)
    disposition:Disposition|None=None
class Heartbeat(Body):
    expected_epoch:StrictInt=Field(ge=0)
class Start(Body):
    station_id:UUID
    expected_version:StrictInt=Field(ge=1)
    expected_epoch:StrictInt=Field(ge=0)
    recipe_id:UUID
    kit_id:StrictStr=Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
class HumanDecision(Body):
    expected_epoch:StrictInt=Field(ge=0)
    disposition:Disposition
    reason:StrictStr=Field(min_length=1,max_length=120)
    human_check_confirmed:StrictBool
class Close(Body):
    expected_epoch:StrictInt=Field(ge=0)
    reason:StrictStr=Field(min_length=1,max_length=120)
    disposition:Disposition|None=None


@router.get('/stations')
def list_stations(limit:Annotated[int,Query(ge=1,le=20)]=20,cursor:UUID|None=None,current=Depends(actor),service=Depends(stations)):
    return service.list(current,limit=limit,cursor=None if cursor is None else str(cursor))


@router.get('/stations/{ident}')
def read_station(ident:UUID,current=Depends(actor),service=Depends(stations)):return service.view(current,str(ident))


@router.post('/stations',status_code=201)
def enroll(body:Profile,request:Request,key:Idempotency,current=Depends(actor),service=Depends(stations)):
    write_guard(request,current)
    if body.disposition is not None:raise ValueError('enrollment has no prior work to dispose')
    return service.enroll(current,name=body.name,calibration_profile_id=body.calibration_profile_id,idempotency_key=key)


@router.patch('/stations/{ident}')
def profile(ident:UUID,body:Profile,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(stations)):
    write_guard(request,current)
    return service.change(current,station_id=str(ident),expected_version=version(match),operation='profile',idempotency_key=key,**body.model_dump())


@router.post('/stations/{ident}/acquire')
def acquire(ident:UUID,body:Acquire,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(stations)):
    write_guard(request,current)
    data=body.model_dump();data['expected_owner_session_id']=None if body.expected_owner_session_id is None else str(body.expected_owner_session_id)
    return service.change(current,station_id=str(ident),expected_version=version(match),operation='acquire',idempotency_key=key,**data)


@router.post('/stations/{ident}/release')
def release(ident:UUID,body:Release,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(stations)):
    write_guard(request,current)
    return service.change(current,station_id=str(ident),expected_version=version(match),operation='release',idempotency_key=key,**body.model_dump())


@router.post('/stations/{ident}/heartbeat')
def heartbeat(ident:UUID,body:Heartbeat,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(stations)):
    write_guard(request,current)
    return service.change(current,station_id=str(ident),expected_version=version(match),operation='heartbeat',idempotency_key=key,**body.model_dump())


@router.post('/inspections',status_code=201)
def start(body:Start,request:Request,key:Idempotency,current=Depends(actor),service=Depends(stations)):
    write_guard(request,current)
    data=body.model_dump();data.update(station_id=str(body.station_id),recipe_id=str(body.recipe_id))
    return service.start(current,idempotency_key=key,**data)


@router.get('/inspections/{ident}')
def inspection(ident:UUID,request:Request,current=Depends(actor),service=Depends(stations)):
    observations=request.app.state.observation_service
    return service.inspection(current,str(ident)) if observations is None else observations.status(current,str(ident))


@router.post('/inspections/{ident}/close')
def close(ident:UUID,body:Close,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(stations)):
    write_guard(request,current)
    return service.close(current,inspection_id=str(ident),expected_version=version(match),idempotency_key=key,**body.model_dump())


@router.post('/inspections/{ident}/dispositions',status_code=201)
def disposition(ident:UUID,body:HumanDecision,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(stations)):
    write_guard(request,current)
    return service.record_disposition(current,inspection_id=str(ident),expected_version=version(match),idempotency_key=key,**body.model_dump())


@router.get('/inspections/{ident}/dispositions/latest')
def latest_disposition(ident:UUID,current=Depends(actor),service=Depends(stations)):
    return service.latest_disposition(current,str(ident))
