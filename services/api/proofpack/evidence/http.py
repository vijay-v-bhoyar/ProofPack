"""Bounded purpose/reference routes; no image decoding or proof booleans in HTTP."""
import asyncio
from uuid import UUID

from fastapi import APIRouter,Depends,Query,Request
from starlette.concurrency import run_in_threadpool

from proofpack.auth.http import IfMatch,Idempotency,actor,version,write_guard
from proofpack.capture.multipart import ImageMultipart,receive_upload
from proofpack.evidence.purposes import PurposeRequest
from proofpack.evidence.references import ReferenceRequest
from proofpack.evidence.repository import StoreUnavailable

router=APIRouter(prefix='/api/v1')


def purposes(request:Request):
    service=request.app.state.purpose_service
    if service is None:raise StoreUnavailable('operational purposes not configured')
    return service


def references(request:Request):
    service=request.app.state.reference_service
    if service is None:raise StoreUnavailable('reference intake not configured')
    return service


class ReferenceMultipart(ImageMultipart):
    def __init__(self,content_type):super().__init__(content_type,fields=('metadata',),field_limit=4096)
    def finish(self):
        parts,mime,payload=self.finish_parts()
        return ReferenceRequest.model_validate_json(parts['metadata']),mime,payload


@router.post('/purposes',status_code=201)
def create_purpose(body:PurposeRequest,request:Request,key:Idempotency,current=Depends(actor),service=Depends(purposes)):
    write_guard(request,current)
    return service.create(current,request=body,idempotency_key=key)


@router.get('/purposes/options')
def purpose_options(current=Depends(actor),service=Depends(purposes)):return service.options(current)


@router.get('/purposes')
def purpose_list(limit:int=Query(20,ge=1,le=20),cursor:str|None=Query(None,max_length=36),current=Depends(actor),service=Depends(purposes)):
    return service.list(current,limit=limit,cursor=cursor)


@router.get('/purposes/{ident}')
def purpose(ident:UUID,current=Depends(actor),service=Depends(purposes)):return service.get(current,str(ident))


@router.post('/purposes/{ident}/withdraw')
def withdraw(ident:UUID,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(purposes)):
    write_guard(request,current)
    return service.withdraw(current,ident=str(ident),expected_version=version(match),idempotency_key=key)


@router.get('/reference-assets/{ident}')
def reference(ident:UUID,current=Depends(actor),service=Depends(references)):return service.get(current,str(ident))


@router.post('/reference-assets',status_code=201)
async def upload(request:Request,key:Idempotency,current=Depends(actor),service=Depends(references)):
    write_guard(request,current)
    if any(len(request.headers.getlist(header))!=1 for header in ('idempotency-key','origin','x-csrf-token')):raise ValueError('unambiguous reference authority required')
    beginning=asyncio.create_task(run_in_threadpool(service.begin,current));ticket=None;processing=None
    try:
        ticket=await asyncio.shield(beginning)
        metadata,mime,payload=await receive_upload(request,parser_factory=ReferenceMultipart)
        processing=asyncio.create_task(run_in_threadpool(service.upload,current,ticket=ticket,request=metadata,payload=payload,content_type=mime,idempotency_key=key))
        return await asyncio.shield(processing)
    finally:
        if ticket is None:
            def release_late(task):
                if not task.cancelled() and task.exception() is None:service.end(task.result())
            beginning.add_done_callback(release_late)
        elif processing is not None and not processing.done():
            def release_processing(task):
                if not task.cancelled():task.exception()
                service.end(ticket)
            processing.add_done_callback(release_processing)
        else:service.end(ticket)
