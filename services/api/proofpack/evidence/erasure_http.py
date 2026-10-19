import json
from uuid import UUID
from fastapi import APIRouter,Depends,Request
from proofpack.auth.http import actor,IfMatch,Idempotency,version,write_guard
from proofpack.auth.policy import Role
from proofpack.evidence.erasure_models import ErasurePreview,ErasureConfirmation
from proofpack.evidence.repository import StoreUnavailable,StoreConflict
from proofpack.evidence.erasure import job_key
from proofpack.evidence.exports import InspectionExports
from proofpack.review.manifests import DatasetManifests
from proofpack.review.evaluations import PolicyEvaluations
from proofpack.review.qualification_preparation import QualificationPreparations
from proofpack.review.policy_qualification import PolicyQualifications
from proofpack.auth.service import ResourceUnavailable
from proofpack.recipes.models import Contract

router=APIRouter(prefix='/api/v1')
class Empty(Contract):pass


def erasure(request:Request):
    service=request.app.state.erasure_service
    if service is None:raise StoreUnavailable('reviewed erasure is not configured')
    return service


def job_service(request:Request,ident,current):
    access=request.app.state.access_service
    if access is None:raise StoreUnavailable('job services unavailable')
    access._fresh(current)
    key=job_key(str(ident));row=access.repository.snapshot((key,))[key]
    if row is None:raise ResourceUnavailable('job unavailable')
    kind=row.data.get('kind')
    service=request.app.state.export_service if kind=='inspection_export' else request.app.state.erasure_service if kind=='asset_erasure' else request.app.state.dataset_service if kind=='dataset_manifest' else request.app.state.evaluation_service if kind=='policy_evaluation' else request.app.state.qualification_preparation_service if kind=='policy_qualification_preparation' else request.app.state.policy_qualification_service if kind=='policy_qualification' else None
    if service is None:raise StoreUnavailable('job handler unavailable')
    return service


@router.post('/privacy/deletion-previews',status_code=201)
def preview(body:dict,request:Request,key:Idempotency,current=Depends(actor),service=Depends(erasure)):
    write_guard(request,current)
    return service.preview(current,request=ErasurePreview.model_validate_json(json.dumps(body,allow_nan=False)),idempotency_key=key)


@router.get('/privacy/deletion-previews/{ident}')
def preview_read(ident:UUID,current=Depends(actor),service=Depends(erasure)):return service.preview_read(current,str(ident))


@router.post('/privacy/deletions',status_code=201)
def confirm(body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(erasure)):
    write_guard(request,current)
    return service.confirm(current,request=ErasureConfirmation.model_validate_json(json.dumps(body,allow_nan=False)),expected_version=version(match),idempotency_key=key)


@router.get('/jobs/{ident}')
def job(ident:UUID,request:Request,current=Depends(actor)):return job_service(request,ident,current).job(current,str(ident))


@router.post('/jobs/{ident}/advance')
def advance(ident:UUID,body:Empty,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor)):
    write_guard(request,current)
    return job_service(request,ident,current).advance(current,str(ident),expected_version=version(match),idempotency_key=key)


@router.post('/jobs/{ident}/cancel')
def cancel(ident:UUID,body:Empty,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor)):
    write_guard(request,current);service=job_service(request,ident,current)
    if isinstance(service,(InspectionExports,DatasetManifests,PolicyEvaluations,QualificationPreparations,PolicyQualifications)):return service.cancel(current,str(ident),expected_version=version(match),idempotency_key=key)
    service.access._fresh(current,Role.OWNER);service.job(current,str(ident))
    raise StoreConflict('committed erasure cannot be cancelled or undo read denial')
