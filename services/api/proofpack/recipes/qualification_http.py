import json
from uuid import UUID
from fastapi import APIRouter,Depends,Request
from proofpack.auth.http import actor,IfMatch,Idempotency,version,write_guard
from proofpack.evidence.repository import StoreUnavailable
from proofpack.recipes.qualification_models import RecipeQualificationRequest

router=APIRouter(prefix='/api/v1')


def qualifications(request:Request):
    service=request.app.state.recipe_qualification_service
    if service is None:raise StoreUnavailable('recipe qualification not configured')
    return service


@router.post('/recipes/{ident}/qualify',status_code=201)
def qualify(ident:UUID,body:dict,request:Request,key:Idempotency,match:IfMatch,current=Depends(actor),service=Depends(qualifications)):
    write_guard(request,current)
    return service.run(current,ident=str(ident),expected_version=version(match),
        request=RecipeQualificationRequest.model_validate_json(json.dumps(body,allow_nan=False)),idempotency_key=key)


@router.get('/recipe-qualification-jobs/{ident}')
def job(ident:UUID,current=Depends(actor),service=Depends(qualifications)):return service.job(current,str(ident))


@router.get('/recipes/{ident}/qualification-reports/{report_id}')
def report(ident:UUID,report_id:UUID,current=Depends(actor),service=Depends(qualifications)):
    return service.report(current,str(ident),str(report_id))
