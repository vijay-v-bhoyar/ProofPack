"""Authenticated capture, bounded image upload and action acknowledgment."""
from uuid import UUID
import asyncio
from fastapi import APIRouter,Depends,Request
from pydantic import BaseModel,ConfigDict,Field,StrictInt,StrictBool
from starlette.concurrency import run_in_threadpool

from proofpack.auth.http import actor,Idempotency,IfMatch,version,write_guard
from proofpack.evidence.repository import StoreUnavailable
from proofpack.capture.multipart import receive_upload

router=APIRouter(prefix='/api/v1/inspections')


def capture(request:Request):
    service=request.app.state.capture_service
    if service is None:raise StoreUnavailable('capture pipeline is not configured')
    return service


class PermitBody(BaseModel):
    model_config=ConfigDict(extra='forbid')
    expected_epoch:StrictInt=Field(ge=0)
    retain_original_frame:StrictBool=False


class PrepareBody(BaseModel):model_config=ConfigDict(extra='forbid')


def observations(request:Request):
    service=request.app.state.observation_service
    if service is None:raise StoreUnavailable('observation worker preparation is not configured')
    return service


@router.get('/{ident}/capture-context')
def context(ident:UUID,current=Depends(actor),service=Depends(observations)):
    return service.context(current,str(ident))


@router.post('/{ident}/prepare-capture')
def prepare(ident:UUID,body:PrepareBody,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(observations)):
    write_guard(request,current)
    return service.prepare(current,inspection_id=str(ident),expected_version=version(match),idempotency_key=key)


@router.post('/{ident}/capture-permits',status_code=201)
def issue(ident:UUID,body:PermitBody,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(capture)):
    write_guard(request,current)
    return service.issue(current,inspection_id=str(ident),expected_version=version(match),
        expected_epoch=body.expected_epoch,idempotency_key=key,retain_original_frame=body.retain_original_frame)


@router.post('/{ident}/actions/{action_id}/complete')
def complete(ident:UUID,action_id:UUID,body:PrepareBody,request:Request,key:Idempotency,match:IfMatch,
             current=Depends(actor),service=Depends(observations)):
    write_guard(request,current)
    return service.acknowledge(current,inspection_id=str(ident),action_id=str(action_id),expected_version=version(match),idempotency_key=key)


@router.post('/{ident}/observations')
async def upload(ident:UUID,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(observations)):
    write_guard(request,current)
    expected=version(match)
    if any(len(request.headers.getlist(header))!=1 for header in ('idempotency-key','if-match','origin','x-csrf-token')):
        raise ValueError('unambiguous request authority headers required')
    beginning=asyncio.create_task(run_in_threadpool(service.begin_upload,current,str(ident)))
    token=None;processing=None
    try:
        token=await asyncio.shield(beginning)
        image=await receive_upload(request)
        processing=asyncio.create_task(run_in_threadpool(service.upload,current,inspection_id=str(ident),expected_version=expected,
            idempotency_key=key,image=image))
        return await asyncio.shield(processing)
    finally:
        if token is None:
            def release_late(task):
                if not task.cancelled() and task.exception() is None:service.end_upload(task.result())
            beginning.add_done_callback(release_late)
        elif processing is not None and not processing.done():
            def release_processing(task):
                if not task.cancelled():task.exception()
                service.end_upload(token)
            processing.add_done_callback(release_processing)
        else:service.end_upload(token)
