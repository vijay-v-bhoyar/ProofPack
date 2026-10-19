"""No signed URLs, range delivery or transferable asset capabilities."""
from uuid import UUID

from fastapi import APIRouter,Depends,Request,Response

from proofpack.auth.http import actor
from proofpack.evidence.repository import StoreUnavailable

router=APIRouter(prefix='/api/v1')


def assets(request:Request):
    service=request.app.state.asset_service
    if service is None:raise StoreUnavailable('retained evidence reads not configured')
    return service


@router.get('/inspections/{ident}/evidence')
def latest(ident:UUID,current=Depends(actor),service=Depends(assets)):
    return service.latest(current,str(ident))


@router.get('/assets/{ident}')
def metadata(ident:UUID,current=Depends(actor),service=Depends(assets)):
    return service.read(current,str(ident))


@router.get('/inspections/{ident}/evidence/originals')
def originals(ident:UUID,current=Depends(actor),service=Depends(assets)):
    return service.originals(current,str(ident))


@router.get('/assets/{ident}/download')
def download(ident:UUID,request:Request,current=Depends(actor),service=Depends(assets)):
    if request.headers.getlist('range') or request.headers.getlist('if-range'):raise ValueError('range evidence reads unsupported')
    payload,receipt,version,binding,remaining=service.read(current,str(ident),binary=True)
    suffix='jpg' if receipt.content_type=='image/jpeg' else 'png'
    return Response(payload,media_type=receipt.content_type,headers={'Content-Disposition':f'inline; filename="evidence-{ident}.{suffix}"',
        'Cross-Origin-Resource-Policy':'same-origin','X-Asset-ID':str(ident),'X-Asset-State-Version':str(version),
        'X-Content-SHA256':receipt.source_sha256,'X-Evidence-Binding-SHA256':binding,
        'X-Remaining-Validity-Ms':str(remaining),'X-Evidence-Historical':'true','Cache-Control':'no-store'})
