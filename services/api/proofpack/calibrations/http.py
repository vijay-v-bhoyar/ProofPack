"""Calibration metadata/diagnostic endpoints. Physical assurance has no public writer."""
from typing import Literal
from uuid import UUID
import json

from fastapi import APIRouter,Depends,Query,Request,Response
from pydantic import Field

from proofpack.auth.http import IfMatch,Idempotency,actor,version,write_guard
from proofpack.auth.policy import Role
from proofpack.calibrations.models import Enrollment,QualificationRequest
from proofpack.evidence.repository import StoreUnavailable
from proofpack.recipes.models import Contract
from proofpack.vision.mat import printable_mat

router=APIRouter(prefix='/api/v1')


def calibrations(request:Request):
    service=request.app.state.calibration_service
    if service is None:raise StoreUnavailable('calibration service not configured')
    return service


class Approval(Contract):
    report_id:str=Field(pattern=r'^[a-f0-9-]{36}$')
    physical_assurance_id:str|None=Field(default=None,pattern=r'^[a-f0-9-]{36}$')


class Retirement(Contract):reason:str=Field(min_length=1,max_length=120)


@router.get('/calibrations/mat')
def mat(current=Depends(actor),service=Depends(calibrations)):
    service.access._fresh(current)
    return Response(printable_mat(),media_type='image/png',headers={'Content-Disposition':'attachment; filename="proofpack-desktop-v1.png"'})


@router.get('/calibrations')
def listing(view:Literal['approved','candidates']='approved',limit:int=Query(20,ge=1,le=20),cursor:str|None=Query(None,max_length=36),current=Depends(actor),service=Depends(calibrations)):
    return service.list(current,view=view,limit=limit,cursor=cursor)


@router.post('/calibrations',status_code=201)
def enroll(body:dict,request:Request,key:Idempotency,current=Depends(actor),service=Depends(calibrations)):
    write_guard(request,current);return service.enroll(current,request=Enrollment.model_validate_json(json.dumps(body,allow_nan=False)),idempotency_key=key)


@router.get('/calibrations/{ident}/draft')
def draft(ident:UUID,current=Depends(actor),service=Depends(calibrations)):return service.draft(current,str(ident))


@router.put('/calibrations/{ident}/draft')
def save(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(calibrations)):
    write_guard(request,current)
    return service.enroll(current,request=Enrollment.model_validate_json(json.dumps(body,allow_nan=False)),ident=str(ident),expected_version=version(match),idempotency_key=key)


@router.post('/calibrations/{ident}/qualify',status_code=201)
def qualify(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(calibrations)):
    write_guard(request,current)
    return service.qualify(current,ident=str(ident),expected_version=version(match),request=QualificationRequest.model_validate_json(json.dumps(body,allow_nan=False)),idempotency_key=key)


@router.get('/calibration-jobs/{ident}')
def job(ident:UUID,current=Depends(actor),service=Depends(calibrations)):return service.job(current,str(ident))


@router.get('/calibrations/{ident}/reports/{report_id}')
def report(ident:UUID,report_id:UUID,current=Depends(actor),service=Depends(calibrations)):return service.report(current,str(ident),str(report_id))


@router.post('/calibrations/{ident}/approve')
def approve(ident:UUID,body:Approval,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(calibrations)):
    write_guard(request,current)
    return service.approve(current,ident=str(ident),expected_version=version(match),report_id=str(body.report_id),
        physical_assurance_id=None if body.physical_assurance_id is None else str(body.physical_assurance_id),idempotency_key=key)


@router.post('/calibrations/{ident}/retire')
def retire(ident:UUID,body:Retirement,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(calibrations)):
    write_guard(request,current)
    return service.retire(current,ident=str(ident),expected_version=version(match),reason=body.reason,idempotency_key=key)
