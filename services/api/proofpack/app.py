"""Application entrypoint. Inspection routes remain closed until dependencies exist."""
from contextlib import asynccontextmanager
import logging
from pathlib import Path
import secrets

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from proofpack import __version__
from proofpack.vision.runtime import runtime_proof
from proofpack.auth.http import IdentityJSONLimit,router as access_router,validate_origin
from proofpack.auth.policy import Denied
from proofpack.auth.service import ResourceUnavailable
from proofpack.auth.oauth import AuthRateLimited
from proofpack.auth.signin_http import OAuthQueryBoundary,clear_flow,router as signin_router
from proofpack.evidence.repository import StoreConflict,StoreUnavailable
from proofpack.runtime.http import router as runtime_router
from proofpack.recipes.http import router as recipe_router
from proofpack.stations.http import router as station_router
from proofpack.stations.service import StationRateLimited
from proofpack.stations.handoffs import InspectionHandoffs,HandoffLimited
from proofpack.stations.handoff_http import router as handoff_router
from proofpack.capture.http import router as capture_router
from proofpack.evidence.http import router as evidence_router
from proofpack.evidence.references import ReferenceRateLimited
from proofpack.calibrations.http import router as calibration_router
from proofpack.calibrations.service import CalibrationRateLimited
from proofpack.review.http import router as review_router
from proofpack.review.labels import ReviewRateLimited
from proofpack.evidence.reads_http import router as asset_router
from proofpack.evidence.reads import AssetReadLimited
from proofpack.evidence.exports import ExportLimited
from proofpack.evidence.export_http import router as export_router
from proofpack.evidence.improvement import ImprovementLimited
from proofpack.planner.candidates import PolicyLimited
from proofpack.planner.activation import PolicyActivations,ActivationLimited
from proofpack.planner.active import ActivePolicies
from proofpack.review.policy_qualification import PolicyQualifications
from proofpack.planner.candidate_http import router as policy_router
from proofpack.review.evaluation_models import EvaluationLimited
from proofpack.review.evaluation_http import router as evaluation_router
from proofpack.review.qualification_preparation_http import router as preparation_router
from proofpack.review.policy_qualification_http import router as policy_qualification_router
from proofpack.planner.activation_http import router as activation_router
from proofpack.review.manifests import DatasetLimited
from proofpack.review.manifest_http import router as dataset_router
from proofpack.evidence.improvement_http import router as improvement_router
from proofpack.evidence.erasure import ErasureLimited
from proofpack.evidence.erasure_http import router as erasure_router
from proofpack.recipes.qualification import RecipeQualificationLimited
from proofpack.recipes.qualification_http import router as recipe_qualification_router

log = logging.getLogger("proofpack")


def create_app(*,data_fence=None,owner_metadata_review_service=None,owner_metadata_service=None,metadata_admission=None,admission_configuration=None,resource_owner=None,access_service=None,app_origin=None,signin_service=None,owner_setup_service=None,runtime_control=None,recipe_service=None,station_service=None,capture_service=None,observation_service=None,purpose_service=None,reference_service=None,calibration_service=None,label_service=None,asset_service=None,recipe_qualification_service=None,erasure_service=None,export_service=None,improvement_service=None,dataset_service=None,policy_service=None,evaluation_service=None,qualification_preparation_service=None,policy_qualification_service=None,policy_activation_service=None,active_policy_reader=None,handoff_service=None,manage_service_lifecycle=True) -> FastAPI:
    from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionConfiguration
    from proofpack.evidence.privacy_http import MetadataAdmissionBoundary
    from proofpack.evidence.owner_metadata import OwnerMetadataRequests,OwnerMetadataBusy,OwnerMetadataLimited
    from proofpack.evidence.owner_metadata_http import router as owner_metadata_router
    from proofpack.evidence.owner_metadata_review import OwnerMetadataReview
    from proofpack.evidence.held_corpus import HeldCorpusHeld
    from proofpack.evidence.privacy_admission import AdmissionHeld
    from proofpack.runtime.ownership import ResourceOwner
    from proofpack.runtime.public_web import freeze_web
    from proofpack.evidence.restore_fence import RestoreDataFence
    from proofpack.evidence.restore_http import RestoreDataBoundary
    if data_fence is not None and (type(data_fence) is not RestoreDataFence or access_service is None
            or getattr(access_service.repository,'data_fence',None) is not data_fence
            or metadata_admission is None or resource_owner is None):
        raise ValueError('restore transport must share the exact fenced repository, admission and resource owner')
    if (data_fence is None and access_service is not None
            and getattr(access_service.repository,'data_fence',None) is not None):
        raise ValueError('fenced application data requires its shared restore transport boundary')
    if any(value is not None for value in (metadata_admission,admission_configuration,resource_owner)):
        if (type(metadata_admission) is not PersistentAdmission or type(admission_configuration) is not AdmissionConfiguration
                or type(resource_owner) is not ResourceOwner or metadata_admission.runtime is not runtime_control
                or access_service is None or metadata_admission.repository is not access_service.repository
                or metadata_admission.limits.max_active != admission_configuration.max_active
                or metadata_admission.limits.max_lease_ms != admission_configuration.max_lease_ms):
            raise ValueError('exact shared admission, configuration, runtime and resource ownership required')
    if type(manage_service_lifecycle) is not bool:raise ValueError('explicit service lifecycle ownership required')
    if owner_metadata_service is not None and (type(owner_metadata_service) is not OwnerMetadataRequests
            or metadata_admission is None or owner_metadata_service.access is not access_service
            or owner_metadata_service.admission is not metadata_admission or owner_metadata_service.resource_owner is not resource_owner):
        raise ValueError('owner metadata control must share exact access, admission and local resource authority')
    if owner_metadata_review_service is not None and (type(owner_metadata_review_service) is not OwnerMetadataReview
            or owner_metadata_service is None or owner_metadata_review_service.requests is not owner_metadata_service
            or owner_metadata_review_service._initial[0] is not owner_metadata_service
            or owner_metadata_review_service.reader.admission is not metadata_admission
            or owner_metadata_review_service.reader.resource_owner is not resource_owner
            or owner_metadata_service.limits.operation_timeout_ms > admission_configuration.http_lease_ms):
        raise ValueError('owner review requires exact shared owner/control dependencies and sufficient original HTTP lease')
    if access_service is not None:validate_origin(app_origin)
    if handoff_service is not None and (type(handoff_service) is not InspectionHandoffs
            or handoff_service.stations is not station_service or handoff_service.access is not access_service
            or handoff_service.runtime is not runtime_control or handoff_service.repository is not access_service.repository):
        raise ValueError('handoffs must share exact application station/access/runtime authority')
    if purpose_service is not None and (purpose_service.access is not access_service or purpose_service.runtime is not runtime_control):raise ValueError('purpose authority must share application services')
    if reference_service is not None and (reference_service.purposes is not purpose_service
            or (observation_service is not None and reference_service.registry is not observation_service.registry)):
        raise ValueError('reference intake must share purpose authority and the application worker budget')
    if calibration_service is not None and calibration_service.references is not reference_service:raise ValueError('calibration must share scoped references and worker budget')
    if evaluation_service is not None and (evaluation_service.policies is not policy_service or evaluation_service.datasets is not dataset_service):raise ValueError('evaluations must share policy and dataset authority')
    if qualification_preparation_service is not None and (evaluation_service is None or qualification_preparation_service.evaluations is not evaluation_service
            or qualification_preparation_service.access is not access_service or qualification_preparation_service.runtime is not runtime_control
            or qualification_preparation_service.repository is not access_service.repository):raise ValueError('preparation must share the application evaluation authority')
    if policy_qualification_service is not None and (type(policy_qualification_service) is not PolicyQualifications
            or policy_qualification_service.policies is not policy_service or policy_qualification_service.access is not access_service
            or policy_qualification_service.runtime is not runtime_control or policy_qualification_service.preparations is not qualification_preparation_service
            or (reference_service is not None and policy_qualification_service.registry is not reference_service.registry)):
        raise ValueError('qualification must share genuine policy, preparation and worker authority')
    if (policy_activation_service is None)!=(active_policy_reader is None):raise ValueError('paired activation and active reader required')
    if policy_activation_service is not None and (not isinstance(policy_activation_service,PolicyActivations)
            or policy_activation_service.reader is not policy_qualification_service or policy_activation_service.policies is not policy_service
            or type(active_policy_reader) is not ActivePolicies or active_policy_reader.activations is not policy_activation_service
            or (station_service is not None and station_service.policy_reader is not active_policy_reader)):
        raise ValueError('activation and live use must share exact genuine qualification authority')
    if policy_service is not None and (policy_service.access is not access_service or policy_service.runtime is not runtime_control):raise ValueError('policies must share application authority')
    if label_service is not None and label_service.purposes is not purpose_service:raise ValueError('labels must share scoped purpose authority')
    if asset_service is not None and asset_service.purposes is not purpose_service:raise ValueError('asset reads must share scoped purpose authority')
    if export_service is not None and export_service.assets is not asset_service:raise ValueError('exports must share scoped asset reads')
    if dataset_service is not None and (dataset_service.labels is not label_service or dataset_service.improvement is not improvement_service):raise ValueError('datasets must share label and improvement authority')
    if improvement_service is not None and improvement_service.assets is not asset_service:raise ValueError('improvement permissions must share scoped asset services')
    if erasure_service is not None and erasure_service.purposes is not purpose_service:raise ValueError('erasure must share scoped purpose authority')
    if recipe_qualification_service is not None and (recipe_qualification_service.recipes is not recipe_service or recipe_qualification_service.references is not reference_service):raise ValueError('qualification must share recipe/reference authority')
    if signin_service is not None:
        if (signin_service.access is not access_service
                or signin_service.flows.config.redirect_uri != app_origin + '/api/v1/auth/callback'):
            raise ValueError('sign-in must share the application access service and exact callback origin')
    if runtime_control is not None and runtime_control.access is not access_service:
        raise ValueError('runtime control must share the application access service')
    if owner_setup_service is not None:
        from proofpack.auth.owner_setup import OwnerSetupSignIn
        if (type(owner_setup_service) is not OwnerSetupSignIn or signin_service is None
                or owner_setup_service.ordinary is not signin_service
                or owner_setup_service.access is not access_service):
            raise ValueError('owner setup must share the exact configured sign-in and access service')
        owner_setup_service._check()
    if recipe_service is not None and recipe_service.access is not access_service:
        raise ValueError('recipe service must share the application access service')
    if station_service is not None and (station_service.access is not access_service
            or station_service.runtime is not runtime_control or station_service.recipes is not recipe_service):
        raise ValueError('station lifecycle must share application access/runtime/recipe services')
    if capture_service is not None and capture_service.stations is not station_service:
        raise ValueError('capture must share application station lifecycle')
    if observation_service is not None and observation_service.capture is not capture_service:
        raise ValueError('observations must share application capture authority')
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Dependency failure is a readiness denial, not a fake local fallback.
        try:
            app.state.runtime = runtime_proof()
        except RuntimeError:
            app.state.runtime = None
        try:yield
        finally:
            if manage_service_lifecycle and reference_service is not None:
                reference_service.close();reference_service.registry.close()
            if manage_service_lifecycle and observation_service is not None:observation_service.registry.close()
            if manage_service_lifecycle and policy_qualification_service is not None and reference_service is None and observation_service is None:policy_qualification_service.registry.close()

    app = FastAPI(title="ProofPack", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.owner_metadata_service=owner_metadata_service
    app.state.owner_metadata_review_service=owner_metadata_review_service
    app.state.access_service=access_service
    app.state.app_origin=app_origin
    app.state.signin_service=signin_service
    app.state.owner_setup_service=owner_setup_service
    app.state.runtime_control=runtime_control
    app.state.recipe_service=recipe_service
    app.state.station_service=station_service
    app.state.handoff_service=handoff_service
    app.state.capture_service=capture_service
    app.state.observation_service=observation_service
    app.state.purpose_service=purpose_service
    app.state.reference_service=reference_service
    app.state.calibration_service=calibration_service
    app.state.label_service=label_service
    app.state.asset_service=asset_service
    app.state.evaluation_service=evaluation_service
    app.state.qualification_preparation_service=qualification_preparation_service
    app.state.policy_qualification_service=policy_qualification_service
    app.state.policy_activation_service=policy_activation_service
    app.state.active_policy_reader=active_policy_reader
    app.state.policy_service=policy_service
    app.state.dataset_service=dataset_service
    app.state.improvement_service=improvement_service
    app.state.export_service=export_service
    app.state.maintenance_driver=None
    app.state.data_fence=data_fence
    app.state.erasure_service=erasure_service
    app.state.recipe_qualification_service=recipe_qualification_service
    app.add_middleware(IdentityJSONLimit)
    app.add_middleware(IdentityJSONLimit,max_bytes=262144,prefixes=('/api/v1/datasets',))
    app.include_router(owner_metadata_router)
    app.include_router(access_router)
    app.include_router(signin_router)
    app.include_router(runtime_router)
    app.include_router(recipe_router)
    app.include_router(station_router)
    app.include_router(handoff_router)
    app.include_router(capture_router)
    app.include_router(evidence_router)
    app.include_router(calibration_router)
    app.include_router(review_router)
    app.include_router(asset_router)
    app.include_router(erasure_router)
    app.include_router(export_router)
    app.include_router(improvement_router)
    app.include_router(dataset_router)
    app.include_router(activation_router)
    app.include_router(policy_router)
    app.include_router(evaluation_router)
    app.include_router(preparation_router)
    app.include_router(policy_qualification_router)
    app.include_router(recipe_qualification_router)

    def error(request,status,code,message,retryable=False):
        response=JSONResponse({'code':code,'safe_message':message,'retryable':retryable,
            'request_id':getattr(request.state,'request_id',None)},status_code=status)
        if request.url.path in {'/api/v1/auth/login','/api/v1/auth/setup-owner','/api/v1/auth/callback'}:clear_flow(response)
        return response

    @app.exception_handler(HeldCorpusHeld)
    async def owner_review_held(request,exc):
        return error(request,503,'METADATA_REVIEW_HELD','The original owner review is unavailable. Refresh its request or follow the agreed manual process.',True)

    @app.exception_handler(OwnerMetadataBusy)
    async def owner_metadata_busy(request,exc):
        return error(request,503,'METADATA_BUSY','Another owner maintenance operation is still in progress.',True)

    @app.exception_handler(OwnerMetadataLimited)
    async def owner_metadata_limited(request,exc):
        response=error(request,429,'METADATA_LIMIT','Owner maintenance allowance is exhausted.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(AdmissionHeld)
    async def owner_metadata_held(request,exc):
        return error(request,503,'METADATA_MAINTENANCE','This work is temporarily unavailable. Use the agreed manual process or contact your supervisor.',True)

    @app.exception_handler(RecipeQualificationLimited)
    async def recipe_qualification_limited(request,exc):
        response=error(request,429,'RECIPE_QUALIFICATION_LIMIT','Recipe qualification capacity or allowance is exhausted.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(EvaluationLimited)
    async def evaluation_limited(request,exc):
        response=error(request,429,'EVALUATION_LIMIT','Evaluation capacity or allowance is exhausted.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(ActivationLimited)
    async def activation_limited(request,exc):
        response=error(request,429,'POLICY_ACTIVATION_LIMIT','Policy transition allowance is exhausted.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(PolicyLimited)
    async def policy_limited(request,exc):
        response=error(request,429,'POLICY_LIMIT','Policy catalog capacity or allowance is exhausted.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(DatasetLimited)
    async def dataset_limited(request,exc):
        response=error(request,429,'DATASET_LIMIT','Dataset capacity or allowance is exhausted.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(ImprovementLimited)
    async def improvement_limited(request,exc):
        response=error(request,429,'IMPROVEMENT_LIMIT','Optional permission writes exceeded the configured allowance.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(ExportLimited)
    async def export_limited(request,exc):
        response=error(request,429,'EXPORT_LIMIT','Export capacity or allowance is exhausted.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(ErasureLimited)
    async def erasure_limited(request,exc):
        response=error(request,429,'ERASURE_LIMIT','Erasure admission or steps exceeded the configured allowance.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(AssetReadLimited)
    async def assets_limited(request,exc):
        response=error(request,429,'EVIDENCE_READ_LIMIT','Evidence reads are busy or their allowance is exhausted.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(ReviewRateLimited)
    async def review_limited(request,exc):
        return error(request,429,'REVIEW_RATE_LIMIT','Review write allowance exhausted. Try again later.',True)

    @app.exception_handler(AuthRateLimited)
    async def auth_limited(request,exc):
        response=error(request,429,'AUTH_RATE_LIMIT','Too many sign-in requests. Try again shortly.',True)
        response.headers['Retry-After']=str(exc.retry_after_seconds)
        return response

    @app.exception_handler(StationRateLimited)
    async def station_limited(request,exc):
        response=error(request,429,'STATION_RATE_LIMIT','Too many station control requests. Try again shortly.',True)
        response.headers['Retry-After']='1'
        return response

    @app.exception_handler(HandoffLimited)
    async def handoff_limited(request,exc):
        retry=exc.retry_after_seconds is not None
        message='Support metadata read allowance is temporarily exhausted.' if retry else 'Support request budget is exhausted. Stop and use the ordinary manual procedure.'
        response=error(request,429,'HANDOFF_LIMIT',message,retry)
        if retry:response.headers['Retry-After']=str(exc.retry_after_seconds)
        return response

    @app.exception_handler(ReferenceRateLimited)
    async def reference_limited(request,exc):
        response=error(request,429,'REFERENCE_RATE_LIMIT','Reference intake is busy or its allowance is exhausted.',True)
        response.headers['Retry-After']='60'
        return response

    @app.exception_handler(CalibrationRateLimited)
    async def calibration_limited(request,exc):
        response=error(request,429,'CALIBRATION_RATE_LIMIT','Calibration diagnostics are busy or their allowance is exhausted.',True)
        response.headers['Retry-After']='60';return response

    @app.exception_handler(Denied)
    async def denied(request,exc):return error(request,403,'ACCESS_DENIED','This action is not permitted.')

    @app.exception_handler(StoreConflict)
    async def conflict(request,exc):return error(request,409,'STATE_CONFLICT','State changed. Refresh before trying again.')

    @app.exception_handler(StoreUnavailable)
    async def unavailable(request,exc):return error(request,503,'DEPENDENCY_UNAVAILABLE','This workflow is currently unavailable.',True)

    @app.exception_handler(ResourceUnavailable)
    async def absent(request,exc):return error(request,404,'NOT_FOUND','Resource unavailable.')

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request,exc):return error(request,400,'INVALID_REQUEST','Request fields or headers are invalid.')

    @app.exception_handler(ValueError)
    async def invalid_value(request,exc):return error(request,400,'INVALID_REQUEST','Request fields or headers are invalid.')

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request,exc):
        response=error(request,exc.status_code,'AUTH_REQUIRED' if exc.status_code==401 else 'REQUEST_DENIED','Sign in with an invited account.' if exc.status_code==401 else 'Request unavailable.')
        if exc.status_code==405 and exc.headers and 'Allow' in exc.headers:response.headers['Allow']=exc.headers['Allow']
        return response

    @app.middleware("http")
    async def boundary_headers(request: Request, call_next):
        request.state.request_id = secrets.token_hex(12)
        response = await call_next(request)
        response.headers.update({"Cache-Control":"no-store", "X-Content-Type-Options":"nosniff",
            "Referrer-Policy":"no-referrer", "X-Frame-Options":"DENY",
            "Content-Security-Policy":"default-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            "X-Request-ID":request.state.request_id})
        return response

    @app.get("/health/live")
    def live():
        return {"status":"ok"}

    @app.get("/health/ready")
    def ready(request: Request):
        # Composition and local proof do not close the actual target/evidence gates.
        # Readiness stays denied until those complete controls are implemented.
        return JSONResponse({"status":"not_ready"}, status_code=503)

    packaged_web = Path(__file__).resolve().parent / 'web'
    web_dist = packaged_web if (packaged_web/'index.html').is_file() else Path(__file__).resolve().parents[3] / "apps/web/dist"
    public_web=freeze_web(web_dist) if (web_dist / 'index.html').is_file() else None
    app.state.public_web=public_web
    if public_web is not None:
        def public_response(path,request):
            asset=public_web.get(path)
            if asset is None:raise StarletteHTTPException(status_code=404)
            return Response(content=asset.content if request.method=='GET' else b'',media_type=asset.media_type,
                headers={'Content-Length':str(len(asset.content))})

        @app.api_route('/',methods=['GET','HEAD'],include_in_schema=False)
        def index(request:Request):return public_response('/',request)

        @app.api_route('/assets/{name}',methods=['GET','HEAD'],include_in_schema=False)
        def built_asset(name:str,request:Request):return public_response('/assets/'+name,request)

    @app.exception_handler(404)
    async def not_found(request: Request, exception):
        return JSONResponse({"code":"NOT_FOUND", "safe_message":"Resource unavailable.",
                             "request_id":request.state.request_id,"retryable":False},status_code=404)

    # Last registration is outermost among user middleware. Mutate the original
    # scope before any application middleware or server response/access logging.
    if metadata_admission is not None:
        app.add_middleware(MetadataAdmissionBoundary,admission=metadata_admission,
            lease_ms=admission_configuration.http_lease_ms,attempts=admission_configuration.attempts,resource_owner=resource_owner,owner_control=owner_metadata_service is not None,owner_review=owner_metadata_review_service is not None,collateral_review=owner_metadata_review_service is not None and owner_metadata_review_service.collateral_limits is not None,public_web=public_web if owner_metadata_service is not None else None)
    if data_fence is not None:
        app.add_middleware(RestoreDataBoundary,fence=data_fence,resource_owner=resource_owner,
            max_active=admission_configuration.max_active)
    app.add_middleware(OAuthQueryBoundary)
    return app


app = create_app()
