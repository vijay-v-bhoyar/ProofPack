import hashlib
import json
from uuid import UUID
from fastapi import APIRouter,Depends,Request,Response,Query
from proofpack.auth.http import actor,IfMatch,Idempotency,version,write_guard
from proofpack.evidence.export_models import ExportRequest,ExportTicketRequest
from proofpack.evidence.repository import StoreUnavailable

router=APIRouter(prefix='/api/v1')


def exports(request:Request):
    service=request.app.state.export_service
    if service is None:raise StoreUnavailable('inspection exports not configured')
    return service


@router.get('/inspections/{ident}/export-context')
def context(ident:UUID,current=Depends(actor),service=Depends(exports)):return service.context(current,str(ident))


@router.get('/inspections/{ident}/exports')
def listing(ident:UUID,cursor:str|None=Query(default=None,max_length=1024),current=Depends(actor),service=Depends(exports)):
    return service.list(current,str(ident),cursor=cursor)


@router.post('/inspections/{ident}/exports',status_code=201)
def create(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(exports)):
    write_guard(request,current)
    return service.create(current,str(ident),request=ExportRequest.model_validate_json(json.dumps(body,allow_nan=False)),expected_version=version(match),idempotency_key=key)


@router.post('/jobs/{ident}/download-tickets',status_code=201)
def ticket(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(exports)):
    write_guard(request,current)
    return service.ticket(current,str(ident),request=ExportTicketRequest.model_validate_json(json.dumps(body,allow_nan=False)),expected_version=version(match),idempotency_key=key)


@router.get('/jobs/{ident}/download')
def download(ident:UUID,request:Request,current=Depends(actor),service=Depends(exports)):
    if request.headers.getlist('range') or request.headers.getlist('if-range') or request.query_params:raise ValueError('export URL capabilities and ranges unsupported')
    values=request.headers.getlist('x-export-ticket')
    if len(values)!=1:raise ValueError('one export ticket header required')
    payload,manifest,remaining=service.download(current,str(ident),values[0])
    return Response(payload,media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="proofpack-{ident}.zip"',
        'X-Export-Job-ID':str(ident),'X-Content-SHA256':hashlib.sha256(payload).hexdigest(),'X-Manifest-SHA256':manifest,
        'X-Remaining-Validity-Ms':str(remaining),'X-Export-Historical':'true','Cross-Origin-Resource-Policy':'same-origin','Cache-Control':'no-store'})
