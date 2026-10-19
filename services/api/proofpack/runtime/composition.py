"""Explicit application composition. No credentials, SDK clients or calls at import."""
from contextlib import asynccontextmanager
from dataclasses import dataclass,field
import logging
import re
from threading import Lock
from time import monotonic,monotonic_ns
from proofpack.evidence.privacy_admission import AdmissionConfiguration, AdmissionLimits, PersistentAdmission
from proofpack.evidence.owner_metadata import OwnerMetadataRequests,OwnerMetadataLimits
from proofpack.evidence.owner_metadata_review import OwnerMetadataReview,OwnerReviewConfiguration
from proofpack.evidence.held_corpus import HeldCorpusReader
from proofpack.evidence.privacy_workers import AdmittedWorker
from proofpack.runtime.ownership import ResourceOwner
from proofpack.runtime.installation import InstallationConfig,verify_installation
from proofpack.runtime.public_web import FrozenWeb
from urllib.parse import urlsplit
from uuid import uuid4

import anyio
from starlette.concurrency import run_in_threadpool

from proofpack.app import create_app
from proofpack.auth.cognito import CognitoConfig,CognitoProvider,CognitoTokens
from proofpack.auth.http import validate_origin
from proofpack.auth.oauth import OAuthConfig,OAuthFlows
from proofpack.auth.service import AccessService,AuthConfig
from proofpack.auth.signin import SignInService
from proofpack.auth.owner_setup import OwnerSetupSignIn
from proofpack.runtime.ingress import IngressConfig
from proofpack.calibrations.service import CalibrationService
from proofpack.capture.observations import ObservationService
from proofpack.capture.service import CaptureService
from proofpack.stations.handoffs import HandoffLimits,InspectionHandoffs
from proofpack.evidence.objects import EvidenceObjects,ObjectConfig,ReferenceObjects
from proofpack.evidence.purposes import DataPurposes
from proofpack.evidence.references import ReferenceAssets
from proofpack.evidence.reads import AssetReads
from proofpack.evidence.erasure import AssetErasure
from proofpack.evidence.exports import InspectionExports
from proofpack.evidence.improvement import ImprovementPermissions,ImprovementConfig
from proofpack.evidence.repository import DynamoRepository
from proofpack.evidence.restore_fence import RestoreFenceConfig, RestoreDataFence
from proofpack.recipes.service import RecipeService
from proofpack.recipes.qualification import RecipeQualifications
from proofpack.review.labels import OutcomeLabels
from proofpack.review.evaluations import PolicyEvaluations
from proofpack.review.evaluation_models import EvaluationConfig
from proofpack.review.vision_replay import VisionReplayConfig
from proofpack.review.qualification_preparation import QualificationPreparations
from proofpack.review.policy_qualification import PolicyQualifications,QualificationConfig,installed_qualification_registry_sha256
from proofpack.review.policy_golden import CASE_IDS
from proofpack.planner.activation import PolicyActivations,ActivationConfig
from proofpack.planner.active import ActivePolicies
from proofpack.planner.contract_suite import ContractSuiteConfig
from proofpack.planner.contract_registry import installed_cases
from proofpack.review.manifests import DatasetManifests,DatasetConfig
from proofpack.planner.candidates import PolicyCandidates,PolicyCatalogConfig
from proofpack.runtime.control import RuntimeControl,sha,uuid
from proofpack.runtime.maintenance import MaintenanceDriver,validate_limits
from proofpack.stations.service import StationService
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.runtime import runtime_proof
from proofpack.vision.worker_limits import WorkerLimits

log=logging.getLogger('proofpack')


@dataclass(frozen=True)
class ApplicationConfig:
    app_origin:str
    environment:str
    artifact_sha256:str
    controls_sha256:str
    auth:AuthConfig=field(repr=False)
    oauth:OAuthConfig=field(repr=False)
    cognito:CognitoConfig
    objects:ObjectConfig
    state_table:str
    events_table:str
    worker_limits:WorkerLimits
    max_worker_processes:int
    purpose_max_lifetime_ms:int
    reference_uploads_per_minute:int
    recipe_qualification_runs_per_minute:int
    recipe_qualification_max_ms:int
    calibration_runs_per_minute:int
    calibration_max_diagnostic_ms:int
    label_writes_per_minute:int
    label_max_duration_ms:int
    label_review_validity_ms:int
    evidence_reads_per_minute:int
    evidence_max_concurrent:int
    evidence_read_window_ms:int
    export_jobs_per_minute:int
    export_job_lifetime_ms:int
    export_lease_ms:int
    export_page_size:int
    export_max_scan_rows:int
    export_max_records:int
    export_max_assets:int
    export_ticket_ms:int
    export_download_ms:int
    export_max_concurrent:int
    deletion_review_ms:int
    deletion_jobs_per_minute:int
    deletion_lease_ms:int
    deletion_version_page_size:int
    maintenance_enabled:bool
    maintenance_poll_ms:int
    maintenance_page_size:int
    maintenance_steps_per_minute:int
    maintenance_drain_ms:int
    operation_purpose_id:str|None
    improvement:ImprovementConfig=field(repr=False)
    evaluation:EvaluationConfig
    policy_catalog:PolicyCatalogConfig
    dataset:DatasetConfig
    local_database_endpoint:str|None=None
    vision_replay:VisionReplayConfig|None=None
    qualification_preparation:EvaluationConfig|None=None
    policy_contract_suite:ContractSuiteConfig|None=None
    policy_qualification:QualificationConfig|None=None
    policy_activation:ActivationConfig|None=None
    handoffs:HandoffLimits|None=None
    metadata_admission:AdmissionConfiguration|None=None
    owner_metadata:OwnerMetadataLimits|None=None
    owner_metadata_review:OwnerReviewConfiguration|None=None
    restore_fence:RestoreFenceConfig|None=None
    installation:InstallationConfig|None=None
    ingress:IngressConfig|None=None

    def __post_init__(self):
        if self.ingress is not None:
            if type(self.ingress) is not IngressConfig:
                raise ValueError('explicit typed ingress configuration required')
            IngressConfig(self.ingress.mode,self.ingress.trusted_proxy_cidrs)
        isolated_test = self.environment == 'test' and self.local_database_endpoint is not None
        if (self.installation is None and not isolated_test) or (self.installation is not None and type(self.installation) is not InstallationConfig):
            raise ValueError('configured non-test hosting requires an explicit approved installation')
        if self.restore_fence is None and not isolated_test:
            raise ValueError('configured non-test data access requires an explicit protected restore fence')
        if self.restore_fence is not None:
            fence = self.restore_fence
            if (type(fence) is not RestoreFenceConfig or type(self.metadata_admission) is not AdmissionConfiguration
                    or fence.artifact_sha256 != self.artifact_sha256
                    or fence.journal_arn != 'arn:aws:dynamodb:'+self.objects.region+':'+self.objects.account_id+':table/'+fence.journal_table
                    or fence.journal_table in {self.state_table,self.events_table}
                    or fence.max_check_ms > min(self.metadata_admission.http_lease_ms,self.metadata_admission.worker_lease_ms)):
                raise ValueError('exact artifact/target fence and shared sufficient admission windows required')
        if self.metadata_admission is not None and type(self.metadata_admission) is not AdmissionConfiguration:
            raise ValueError('explicit typed admission configuration required')
        if self.owner_metadata is not None and (type(self.owner_metadata) is not OwnerMetadataLimits
                or self.metadata_admission is None
                or self.owner_metadata.operation_timeout_ms > self.metadata_admission.http_lease_ms):
            raise ValueError('explicit owner metadata limits require admission and a sufficient original HTTP lease')
        if self.owner_metadata_review is not None and (type(self.owner_metadata_review) is not OwnerReviewConfiguration
                or self.owner_metadata is None or self.metadata_admission is None
                or self.owner_metadata.max_inspections > self.owner_metadata_review.corpus.analysis.dataset.corpus.max_inspections
                or self.owner_metadata.max_inspections > self.owner_metadata_review.accounting.max_scope):
            raise ValueError('typed review requires owner/admission and sufficient explicit scope bounds')
        if (self.owner_metadata_review is not None and self.owner_metadata_review.collateral_limits is not None
                and self.owner_metadata_review.collateral_limits.max_scope>self.owner_metadata.max_inspections):
            raise ValueError('collateral scope exceeds configured owner request capacity')
        if (self.owner_metadata_review is not None and self.owner_metadata_review.metadata_review is not None
                and (self.owner_metadata_review.metadata_review.max_inspections!=self.owner_metadata.max_inspections
                     or self.owner_metadata_review.metadata_review.writes_per_minute!=self.owner_metadata.writes_per_minute)):
            raise ValueError('metadata review must match original configured owner writer limits')
        if self.environment == 'beta' and self.metadata_admission is None:
            raise ValueError('beta requires explicit metadata admission configuration')
        if self.handoffs is not None and type(self.handoffs) is not HandoffLimits:raise ValueError('explicit typed handoff limits required')
        if not isinstance(self.evaluation,EvaluationConfig):raise ValueError('explicit evaluation configuration required')
        if self.vision_replay is not None and (not isinstance(self.vision_replay,VisionReplayConfig)
                or self.vision_replay.max_case_ms>self.evaluation.lease_ms):raise ValueError('vision replay configuration must fit the original evaluation lease')
        if (self.qualification_preparation is None)!=(self.policy_contract_suite is None):raise ValueError('paired preparation and software-suite configuration required')
        if self.qualification_preparation is not None and (not isinstance(self.qualification_preparation,EvaluationConfig)
                or not isinstance(self.policy_contract_suite,ContractSuiteConfig) or self.vision_replay is None
                or self.policy_contract_suite.max_cases<len(installed_cases()) or self.qualification_preparation.max_steps<len(installed_cases())+1):raise ValueError('explicit image-backed preparation bounds must cover every case')
        if (self.policy_qualification is None)!=(self.policy_activation is None):raise ValueError('paired qualification and activation configuration required')
        if self.policy_qualification is not None:
            q=self.policy_qualification;a=self.policy_activation
            if (not isinstance(q,QualificationConfig) or not isinstance(a,ActivationConfig) or self.qualification_preparation is None
                    or self.policy_contract_suite is None or q.max_reserved_cases<len(installed_cases())+len(CASE_IDS)
                    or q.jobs.max_steps<1+len(CASE_IDS) or self.policy_contract_suite.max_duration_ms>q.jobs.lease_ms
                    or a.qualification_registry_sha256!=installed_qualification_registry_sha256()):raise ValueError('complete installed qualification/activation configuration required')
        if not isinstance(self.policy_catalog,PolicyCatalogConfig):raise ValueError('explicit policy catalog configuration required')
        if not isinstance(self.dataset,DatasetConfig):raise ValueError('explicit dataset configuration required')
        if not isinstance(self.improvement,ImprovementConfig):raise ValueError('explicit separate improvement notice and limits required')
        validate_limits(self.maintenance_enabled,self.maintenance_poll_ms,self.maintenance_page_size,self.maintenance_steps_per_minute,self.maintenance_drain_ms)
        validate_origin(self.app_origin);sha(self.artifact_sha256);sha(self.controls_sha256)
        if (self.environment not in {'test','synthetic_demo','beta'}
                or self.auth.deployment!=self.oauth.deployment or self.auth.deployment!=self.objects.deployment
                or self.auth.issuer!=self.cognito.issuer or self.oauth.client_id!=self.cognito.client_id
                or self.oauth.native_totp_acr!=self.cognito.native_totp_acr
                or self.oauth.mfa_max_age_seconds>self.auth.mfa_grant_max_age_seconds
                or self.oauth.redirect_uri!=self.app_origin+'/api/v1/auth/callback'
                or self.auth.notice_version is None or self.auth.notice_text is None
                or not self.cognito.issuer.startswith('https://cognito-idp.'+self.objects.region+'.amazonaws.com/')):
            raise ValueError('shared explicit deployment, origin, provider and notice configuration required')
        if (not isinstance(self.worker_limits,WorkerLimits) or self.worker_limits.wall_ms>750
                or self.worker_limits.startup_ms>5000 or self.worker_limits.memory_mb>512 or self.worker_limits.cpu_seconds>30
                or type(self.max_worker_processes) is not int or not 1<=self.max_worker_processes<=2):
            raise ValueError('shared worker budget must stay within project bounds')
        if (self.state_table==self.events_table or any(not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,255}',name)
                for name in (self.state_table,self.events_table))):raise ValueError('distinct bounded state and events tables required')
        if self.operation_purpose_id is not None:uuid(self.operation_purpose_id)
        for name,maximum in (('purpose_max_lifetime_ms',31536000000),('reference_uploads_per_minute',100),
                ('recipe_qualification_runs_per_minute',100),('calibration_runs_per_minute',100),('label_writes_per_minute',100),('label_max_duration_ms',3600000),('label_review_validity_ms',60000),
                ('deletion_review_ms',60000),('deletion_jobs_per_minute',100),('deletion_version_page_size',1000),('evidence_reads_per_minute',120),('evidence_max_concurrent',2),('evidence_read_window_ms',5000)):
            if type(getattr(self,name)) is not int or not 1<=getattr(self,name)<=maximum:raise ValueError('explicit bounded service configuration required')
        for name,low,high in (('export_jobs_per_minute',1,20),('export_job_lifetime_ms',1000,3600000),('export_lease_ms',1000,60000),
                ('export_page_size',1,25),('export_max_scan_rows',1,5000),('export_max_records',1,512),('export_max_assets',1,3),
                ('export_ticket_ms',1,60000),('export_download_ms',1,30000),('export_max_concurrent',1,2)):
            if type(getattr(self,name)) is not int or not low<=getattr(self,name)<=high:raise ValueError('explicit bounded export configuration required')
        if type(self.deletion_lease_ms) is not int or not 1000<=self.deletion_lease_ms<=60000:raise ValueError('explicit bounded erasure lease required')
        if type(self.recipe_qualification_max_ms) is not int or not 1000<=self.recipe_qualification_max_ms<=60000:raise ValueError('explicit bounded recipe qualification window required')
        if type(self.calibration_max_diagnostic_ms) is not int or not 1000<=self.calibration_max_diagnostic_ms<=60000:raise ValueError('explicit bounded calibration window required')
        if self.local_database_endpoint is not None:
            parsed=urlsplit(self.local_database_endpoint)
            if (self.environment!='test' or parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.port is None
                    or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
                    or self.local_database_endpoint!=f'http://127.0.0.1:{parsed.port}'):
                raise ValueError('explicit exact loopback database allowed only for isolated tests')


@dataclass(frozen=True)
class ApplicationClients:
    """Ownership transfers only after successful application construction."""
    dynamodb:object=field(repr=False)
    s3:object=field(repr=False)
    sts:object=field(repr=False)


class ConfiguredStartupUnavailable(RuntimeError):pass


def _client(client,service,region,endpoint):
    try:
        settings=client.meta.config;retries=settings.retries or {}
        if (client.meta.service_model.service_name!=service or client.meta.region_name!=region
                or client.meta.endpoint_url!=endpoint or not 0<settings.connect_timeout<=2
                or not 0<settings.read_timeout<=3 or retries.get('total_max_attempts',retries.get('max_attempts',100)+1)!=1):raise ValueError()
    except (AttributeError,TypeError,ValueError) as exc:raise ValueError('fixed regional bounded '+service+' client required') from exc


def _target(config,clients):
    """Read-only target verification, before the first runtime transaction."""
    stage='caller identity'
    try:
        identity=clients.sts.get_caller_identity();account=config.objects.account_id
        if (identity.get('Account')!=account or not isinstance(identity.get('Arn'),str)
                or not re.fullmatch(r'arn:aws:sts::'+account+r':assumed-role/[A-Za-z0-9+=,.@_/-]{1,1024}',identity['Arn'])):
            raise ValueError('target role mismatch')
        for name in (config.state_table,config.events_table):
            stage='table metadata'
            table=clients.dynamodb.describe_table(TableName=name)['Table']
            expected='arn:aws:dynamodb:'+config.objects.region+':'+account+':table/'+name
            attributes={item['AttributeName']:item['AttributeType'] for item in table['AttributeDefinitions']}
            if (table.get('TableStatus')!='ACTIVE' or table.get('TableName')!=name
                    or (config.local_database_endpoint is None and table.get('TableArn')!=expected)
                    or len(table.get('KeySchema',[]))!=2 or {item['AttributeName']:item['KeyType'] for item in table['KeySchema']}!={'pk':'HASH','sk':'RANGE'}
                    or attributes.get('pk')!='S' or attributes.get('sk')!='S'):
                raise ValueError('target table mismatch')
    except Exception:
        raise ConfiguredStartupUnavailable('Configured '+stage+' validation failed; runtime was not started.') from None


def create_configured_app(config:ApplicationConfig,clients:ApplicationClients,*,clock_ms=None,tick_ns=None):
    """Construct only. Lifespan owns startup, all resource cleanup and one incarnation."""
    if not isinstance(config,ApplicationConfig) or not isinstance(clients,ApplicationClients):raise ValueError('explicit typed application configuration and clients required')
    if config.restore_fence is not None and config.restore_fence.release_kind=='initial-data-release':
        from proofpack.runtime.host import enrollment_configuration_sha256
        if config.restore_fence.initial_configuration_sha256!=enrollment_configuration_sha256(config):
            raise ValueError('original initial-release application configuration required')
    region=config.objects.region
    _client(clients.dynamodb,'dynamodb',region,config.local_database_endpoint or 'https://dynamodb.'+region+'.amazonaws.com')
    _client(clients.sts,'sts',region,'https://sts.'+region+'.amazonaws.com')
    s3_endpoint=clients.s3.meta.endpoint_url
    if s3_endpoint not in {'https://s3.'+region+'.amazonaws.com',*({'https://s3.amazonaws.com'} if region=='us-east-1' else set())}:
        raise ValueError('fixed regional S3 endpoint required')
    _client(clients.s3,'s3',region,s3_endpoint)
    data_fence=None if config.restore_fence is None else RestoreDataFence(clients.dynamodb,
        deployment=config.auth.deployment,state_table=config.state_table,events_table=config.events_table,
        config=config.restore_fence,tick=monotonic_ns if tick_ns is None else tick_ns)
    repository=DynamoRepository(clients.dynamodb,deployment=config.auth.deployment,state_table=config.state_table,events_table=config.events_table,data_fence=data_fence)
    access=AccessService(repository,config.auth,clock_ms=clock_ms)
    runtime=RuntimeControl(access,instance_id=str(uuid4()),artifact_sha256=config.artifact_sha256,controls_sha256=config.controls_sha256,environment=config.environment)
    admission=None;resource_owner=None;admission_runner=None
    if config.metadata_admission is not None:
        bounds=config.metadata_admission
        admission=PersistentAdmission(runtime,limits=AdmissionLimits(bounds.max_active,bounds.max_lease_ms),clock_ms=access.now)
        resource_owner=ResourceOwner()
        admission_runner=AdmittedWorker(admission,lease_ms=bounds.worker_lease_ms,attempts=bounds.attempts,resource_owner=resource_owner)
    owner_metadata=None if config.owner_metadata is None else OwnerMetadataRequests(access,admission,resource_owner,
        limits=config.owner_metadata,tick_ns=monotonic_ns)
    owner_review=None
    if config.owner_metadata_review is not None:
        review_bounds=config.owner_metadata_review
        reader=HeldCorpusReader(admission,resource_owner,inventory_limits=review_bounds.inventory,limits=review_bounds.corpus,tick=monotonic_ns)
        owner_review=OwnerMetadataReview(owner_metadata,reader,accounting_limits=review_bounds.accounting,max_response_bytes=review_bounds.max_response_bytes,
            collateral_limits=review_bounds.collateral_limits,auth_review=review_bounds.auth_review,metadata_review=review_bounds.metadata_review)
    recipes=RecipeService(access,environment=config.environment,artifact_sha256=config.artifact_sha256)
    tokens=CognitoTokens(config.cognito,clock_ms=clock_ms)
    flows=OAuthFlows(repository,config.oauth,clock_ms=clock_ms)
    signin=SignInService(flows,CognitoProvider(config.oauth,tokens),access)
    owner_setup=(None if config.auth.initial_owner_subject is None and config.auth.bootstrap_receipt_sha256 is None
        else OwnerSetupSignIn(signin))
    purposes=DataPurposes(access,runtime,max_lifetime_ms=config.purpose_max_lifetime_ms)
    frames=EvidenceObjects(clients.s3,config.objects);reference_objects=ReferenceObjects(clients.s3,config.objects)
    registry=WorkerRegistry(config.worker_limits,max_processes=config.max_worker_processes)
    try:
        references=ReferenceAssets(purposes,reference_objects,registry,max_uploads_per_minute=config.reference_uploads_per_minute)
        qualifications=RecipeQualifications(recipes,references,runs_per_minute=config.recipe_qualification_runs_per_minute,max_ms=config.recipe_qualification_max_ms)
        calibrations=CalibrationService(references,max_runs_per_minute=config.calibration_runs_per_minute,max_diagnostic_ms=config.calibration_max_diagnostic_ms)
        labels=OutcomeLabels(purposes,writes_per_minute=config.label_writes_per_minute,max_duration_ms=config.label_max_duration_ms,review_validity_ms=config.label_review_validity_ms)
        erasure=AssetErasure(purposes,frames,reference_objects,review_ms=config.deletion_review_ms,jobs_per_minute=config.deletion_jobs_per_minute,lease_ms=config.deletion_lease_ms,version_page_size=config.deletion_version_page_size)
        assets=AssetReads(purposes,frames,reference_objects,reads_per_minute=config.evidence_reads_per_minute,max_concurrent=config.evidence_max_concurrent,
            read_window_ms=config.evidence_read_window_ms)
        exports=InspectionExports(assets,jobs_per_minute=config.export_jobs_per_minute,job_lifetime_ms=config.export_job_lifetime_ms,lease_ms=config.export_lease_ms,page_size=config.export_page_size,max_scan_rows=config.export_max_scan_rows,max_records=config.export_max_records,max_assets=config.export_max_assets,ticket_ms=config.export_ticket_ms,download_ms=config.export_download_ms,max_concurrent=config.export_max_concurrent)
        improvement=ImprovementPermissions(assets,config.improvement)
        policies=PolicyCandidates(access,runtime,config.policy_catalog)
        datasets=DatasetManifests(labels,improvement,config.dataset)
        evaluations=PolicyEvaluations(policies,datasets,config.evaluation,
            vision_registry=registry if config.vision_replay is not None else None,vision_config=config.vision_replay)
        preparations=None if config.qualification_preparation is None else QualificationPreparations(evaluations,config.qualification_preparation,config.policy_contract_suite)
        policy_qualifications=None if config.policy_qualification is None else PolicyQualifications(policies,registry,config.policy_qualification,config.policy_contract_suite,preparations,tick_ns=tick_ns)
        activations=None if policy_qualifications is None else PolicyActivations(policies,config.policy_activation,policy_qualifications,tick_ns=tick_ns)
        if policy_qualifications is not None and policy_qualifications.registry_sha!=config.policy_activation.qualification_registry_sha256:raise ValueError('installed qualification registry changed before construction')
        active=None if activations is None else ActivePolicies(activations)
        stations=StationService(access,runtime,recipes,tick_ns=tick_ns,policy_reader=active)
        handoffs=None if config.handoffs is None else InspectionHandoffs(stations,limits=config.handoffs,tick_ns=tick_ns)
        capture=CaptureService(stations,worker_guard=registry.guard,tick_ns=tick_ns)
        observations=ObservationService(capture,registry,objects=None if config.operation_purpose_id is None else frames,purpose_id=config.operation_purpose_id)
        maintenance=MaintenanceDriver(access,runtime,exports,erasure,enabled=config.maintenance_enabled,poll_ms=config.maintenance_poll_ms,
            page_size=config.maintenance_page_size,steps_per_minute=config.maintenance_steps_per_minute,drain_ms=config.maintenance_drain_ms,admission_runner=admission_runner,datasets=datasets,evaluations=evaluations,preparations=preparations,qualifications=policy_qualifications)
        app=create_app(data_fence=data_fence,owner_metadata_review_service=owner_review,owner_metadata_service=owner_metadata,metadata_admission=admission,admission_configuration=config.metadata_admission,resource_owner=resource_owner,access_service=access,app_origin=config.app_origin,signin_service=signin,owner_setup_service=owner_setup,runtime_control=runtime,
            recipe_service=recipes,station_service=stations,handoff_service=handoffs,capture_service=capture,observation_service=observations,
            purpose_service=purposes,reference_service=references,calibration_service=calibrations,label_service=labels,asset_service=assets,recipe_qualification_service=qualifications,erasure_service=erasure,export_service=exports,improvement_service=improvement,dataset_service=datasets,policy_service=policies,evaluation_service=evaluations,qualification_preparation_service=preparations,policy_qualification_service=policy_qualifications,policy_activation_service=activations,active_policy_reader=active,manage_service_lifecycle=False)
    except BaseException:
        registry.close()
        raise
    base_lifespan=app.router.lifespan_context;started=False
    app.state.composition_status='constructed'
    app.state.composition_scope='local_synthetic' if config.local_database_endpoint else 'configured_target_not_release_approved'
    app.state.maintenance_driver=maintenance
    app.state.metadata_admission=admission
    app.state.resource_owner=resource_owner
    cleanup_lock=Lock();cleaned=False;cleanup_failed=False
    def close_owned():
        nonlocal cleaned,cleanup_failed
        with cleanup_lock:
            if cleaned:return
            cleaned=True
        for cleanup in (references.close,registry.close,clients.dynamodb.close,clients.s3.close,clients.sts.close):
            try:cleanup()
            except Exception:
                cleanup_failed=True;app.state.composition_status='failed'
                log.error('Configured application resource cleanup failed.')
    def startup_call(operation, *args):
        ticket = None if resource_owner is None else resource_owner.acquire()
        try:
            return operation(*args)
        finally:
            if ticket is not None:
                resource_owner.release(ticket)
    @asynccontextmanager
    async def lifespan(application):
        nonlocal started
        if started:raise ConfiguredStartupUnavailable('Application incarnation cannot be restarted.')
        started=True;application.state.composition_status='starting';failed=True
        try:
            if config.installation is not None:
                def check_installation():
                    frozen=getattr(application.state,'public_web',None)
                    if type(frozen) is not FrozenWeb:raise ConfiguredStartupUnavailable('Approved served installation is unavailable.')
                    verify_installation(config.installation,config.artifact_sha256,frozen_web=frozen)
                await run_in_threadpool(startup_call,check_installation)
            await run_in_threadpool(startup_call,runtime_proof)
            await run_in_threadpool(startup_call,_target,config,clients)
            if data_fence is not None:
                try:
                    await run_in_threadpool(startup_call,data_fence.verify_target)
                except Exception:
                    raise ConfiguredStartupUnavailable('Protected restore admission failed; runtime was not started.') from None
            await run_in_threadpool(startup_call,runtime.start)
            if admission is not None:
                await run_in_threadpool(startup_call,admission.require_enrollment,config.metadata_admission.enrollment_sha256)
            async with base_lifespan(application):
                maintenance.start()
                application.state.composition_status='started';failed=False
                yield
        except BaseException:
            failed=True
            raise
        finally:
            deadline=monotonic()+config.maintenance_drain_ms/1000
            application.state.composition_status='stopping'
            notification_lock=Lock()
            completion={'thread':False,'local':resource_owner is None,'requested':False}
            def note(which):
                with notification_lock:
                    completion[which]=True
                    ready=all(completion.values())
                if ready:close_owned()
            def request_cleanup():note('requested')
            try:
                if resource_owner is not None:
                    resource_owner.stop_accepting()
                    resource_owner.after_drain(lambda:note('local'))
                maintenance.request_stop()
                # Pin physical-exit notification before any cancellation point.
                # A processing-finally callback alone cannot authorize closure.
                maintenance.after_thread_exit(lambda:note('thread'))
                with anyio.CancelScope(shield=True):
                    maintenance_drained=await run_in_threadpool(maintenance.stop_and_drain)
                    local_drained=True
                    if resource_owner is not None:
                        remaining=max(0,int((deadline-monotonic())*1000))
                        local_drained=await run_in_threadpool(resource_owner.wait_for_drain,remaining)
                    drained=maintenance_drained and local_drained
                    if drained:await run_in_threadpool(close_owned)
                    application.state.composition_status='failed' if failed or cleanup_failed else 'closed'
                    if not drained:raise ConfiguredStartupUnavailable('Application shutdown did not drain; resource cleanup is deferred until actual executor exit.')
            except BaseException:
                application.state.composition_status='failed'
                maintenance.after_exit(request_cleanup)
                raise
    app.router.lifespan_context=lifespan
    return app
