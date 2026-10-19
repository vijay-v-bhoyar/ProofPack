"""Private host configuration; credential discovery only for explicit SDK commands."""
import argparse
import base64
from dataclasses import asdict,dataclass,field,replace
import hashlib
import ipaddress
import json
import re
from pathlib import Path
import sys
from typing import Literal
from time import monotonic_ns

from pydantic import Field

from proofpack.auth.cognito import CognitoConfig
from proofpack.auth.oauth import OAuthConfig
from proofpack.auth.service import AccessService,AuthConfig
from proofpack.evidence.objects import ObjectConfig
from proofpack.evidence.improvement import ImprovementConfig
from proofpack.review.evaluation_models import EvaluationConfig
from proofpack.review.vision_replay import VisionReplayConfig
from proofpack.planner.contract_suite import ContractSuiteConfig
from proofpack.review.policy_qualification import QualificationConfig,installed_qualification_registry_sha256
from proofpack.planner.activation import ActivationConfig
from proofpack.planner.candidates import PolicyCatalogConfig
from proofpack.review.manifests import DatasetConfig
from proofpack.recipes.models import Contract
from proofpack.runtime.composition import ApplicationConfig,ApplicationClients,create_configured_app,_client,_target
from proofpack.runtime.control import RuntimeControl,uuid
from proofpack.runtime.installation import InstallationConfig,verify_installation
from proofpack.runtime.ingress import IngressConfig,server_proxy_options
from proofpack.evidence.repository import DynamoRepository
from proofpack.vision.worker_limits import WorkerLimits
from proofpack.stations.handoffs import HandoffLimits
from proofpack.evidence.privacy_admission import AdmissionConfiguration
from proofpack.evidence.owner_metadata import OwnerMetadataLimits
from proofpack.runtime.review_host import OwnerReviewDocument
from proofpack.evidence.restore_fence import RestoreFenceConfig,RestoreDataFence
from proofpack.evidence.journal_anchors import AnchorCheckpoint


class HostConfigurationError(ValueError):pass


class Application(Contract):
    app_origin:str
    environment:Literal['synthetic_demo','beta']
    artifact_sha256:str
    controls_sha256:str
    operation_purpose_id:str|None


class Authentication(Contract):
    issuer:str
    initial_owner_subject:str|None
    bootstrap_receipt_sha256:str|None=Field(pattern=r'^[a-f0-9]{64}$')
    notice_version:str
    notice_text:str
    session_ttl_seconds:int
    invitation_ttl_seconds:int
    transfer_ttl_seconds:int
    mfa_grant_max_age_seconds:int
    id_token_max_lifetime_seconds:int


class Authorization(Contract):
    provider_origin:str
    client_id:str
    flow_ttl_seconds:int
    native_totp_acr:str
    mfa_max_age_seconds:int
    login_starts_per_minute:int
    callback_attempts_per_minute:int


class Resources(Contract):
    region:str
    account_id:str
    state_table:str
    events_table:str
    bucket:str
    kms_key_arn:str


class Limits(Contract):
    maintenance_enabled:bool
    maintenance_poll_ms:int
    maintenance_page_size:int
    maintenance_steps_per_minute:int
    maintenance_drain_ms:int
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
    worker:dict[str,int]
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


class ImprovementDocument(Contract):
    notice_version:str
    notice_text:str=Field(repr=False)
    max_lifetime_ms:int
    writes_per_minute:int
    review_ms:int


class DatasetDocument(Contract):
    max_examples:int
    jobs_per_minute:int
    step_attempts_per_minute:int
    lifetime_ms:int
    lease_ms:int
    max_steps:int
    reads_per_minute:int


class EvaluationDocument(Contract):
    jobs_per_minute:int
    step_attempts_per_minute:int
    reads_per_minute:int
    lifetime_ms:int
    lease_ms:int
    max_steps:int


class PolicyCatalogDocument(Contract):
    writes_per_minute:int
    reads_per_minute:int
    max_revisions:int


class VisionReplayDocument(Contract):
    max_case_ms:int
    max_report_bytes:int


class ContractSuiteDocument(Contract):
    max_cases:int
    max_duration_ms:int
    max_case_report_bytes:int
    max_report_bytes:int


class PolicyQualificationDocument(Contract):
    jobs:EvaluationDocument
    max_reserved_cases:int
    golden_case_ms:int


class PolicyActivationDocument(Contract):
    writes_per_minute:int
    reads_per_minute:int
    review_window_ms:int
    max_qualification_rows:int


class HandoffDocument(Contract):
    max_requests:int
    lifetime_ms:int
    reads_per_minute:int
    read_window_ms:int
    page_size:int
    metadata_retention_ms:int


class AdmissionDocument(Contract):
    max_active:int=Field(ge=1,le=64)
    max_lease_ms:int=Field(ge=1,le=300000)
    http_lease_ms:int=Field(ge=1,le=300000)
    worker_lease_ms:int=Field(ge=1,le=300000)
    attempts:int=Field(ge=1,le=3)
    enrollment_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')


class OwnerMetadataDocument(Contract):
    max_inspections:int=Field(ge=1,le=64)
    writes_per_minute:int=Field(ge=1,le=100)
    reads_per_minute:int=Field(ge=1,le=1000)
    operation_timeout_ms:int=Field(ge=1,le=20000)


class RestoreCheckpointDocument(Contract):
    sequence:int=Field(ge=0,lt=2**63-1)
    digest:str=Field(pattern=r'^[a-f0-9]{64}$')


class RestoreTargetIdsDocument(Contract):
    events:str=Field(pattern=r'^[A-Za-z0-9-]{1,128}$')
    state:str=Field(pattern=r'^[A-Za-z0-9-]{1,128}$')


class RestoreFenceDocument(Contract):
    journal_table:str
    journal_arn:str
    genesis_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    checkpoint:RestoreCheckpointDocument
    release_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    target_table_ids:RestoreTargetIdsDocument
    max_check_ms:int=Field(ge=1,le=300000)
    release_kind:Literal['restored-data-release','initial-data-release']='restored-data-release'
    journal_table_id:str|None=None

    def build(self, artifact_sha256):
        return RestoreFenceConfig(self.journal_table,self.journal_arn,self.genesis_sha256,
            AnchorCheckpoint(self.checkpoint.sequence,self.checkpoint.digest),self.release_sha256,
            tuple(sorted(self.target_table_ids.model_dump().items())),artifact_sha256,self.max_check_ms,self.release_kind,self.journal_table_id)


class InstallationDocument(Contract):
    wheel_path:str=Field(min_length=1,max_length=1024)


class IngressDocument(Contract):
    mode:Literal['alb']
    trusted_proxy_cidrs:list[str]=Field(min_length=2,max_length=2)

    def build(self):return IngressConfig(self.mode,tuple(self.trusted_proxy_cidrs))


class HostDocument(Contract):
    schema_version:int=Field(ge=1,le=1)
    deployment:str=Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$')
    application:Application
    auth:Authentication
    oauth:Authorization
    aws:Resources
    limits:Limits
    improvement:ImprovementDocument
    evaluation:EvaluationDocument
    policy_catalog:PolicyCatalogDocument
    dataset:DatasetDocument
    restore_fence:RestoreFenceDocument
    installation:InstallationDocument
    ingress:IngressDocument|None=None
    vision_replay:VisionReplayDocument|None=None
    qualification_preparation:EvaluationDocument|None=None
    policy_contract_suite:ContractSuiteDocument|None=None
    policy_qualification:PolicyQualificationDocument|None=None
    policy_activation:PolicyActivationDocument|None=None
    handoffs:HandoffDocument|None=None
    metadata_admission:AdmissionDocument
    owner_metadata:OwnerMetadataDocument|None=None
    owner_metadata_review:OwnerReviewDocument|None=None


class KeyDocument(Contract):
    capability_key_base64:str=Field(min_length=44,max_length=172,repr=False)
    oauth_private_key_base64:str=Field(min_length=44,max_length=172,repr=False)


class EnrollmentDocument(Contract):
    operation_id:str
    instance_id:str
    role_arn:str
    created_at_ms:int=Field(ge=1,lt=2**63-1)
    expires_at_ms:int=Field(ge=1,lt=2**63-1)


def load_enrollment(path):
    try:
        from proofpack.evidence.initial_release import EnrollmentIntent
        encoded,_=_document(path,4096)
        return EnrollmentIntent(**EnrollmentDocument.model_validate_json(encoded).model_dump())
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError):
        raise HostConfigurationError('Private first-install enrollment input is unavailable or invalid.') from None


@dataclass(frozen=True)
class LoadedConfiguration:
    config:ApplicationConfig=field(repr=False)
    configuration_sha256:str
    enrollment_configuration_sha256:str|None=None


def enrollment_configuration_sha256(config):
    """Normalized ordinary configuration; separately managed keys are not approval."""
    value=asdict(config)
    del value['restore_fence']['release_sha256']
    del value['restore_fence']['initial_configuration_sha256']
    del value['auth']['capability_key'];del value['oauth']['private_key']
    return hashlib.sha256(json.dumps(['fresh-enrollment-configuration/v1',value],sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def _document(path,max_bytes):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate key')
            result[key]=value
        return result
    def constant(value):raise ValueError('nonfinite number')
    with Path(path).open('rb') as stream:raw=stream.read(max_bytes+1)
    if not raw or len(raw)>max_bytes:raise ValueError('bounded input required')
    parsed=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=constant)
    return json.dumps(parsed,separators=(',',':'),allow_nan=False),hashlib.sha256(raw).hexdigest()


def load_configuration(config_path,secrets_path):
    try:
        encoded,fingerprint=_document(config_path,65536);settings=HostDocument.model_validate_json(encoded)
        encoded_keys,_=_document(secrets_path,4096);keys=KeyDocument.model_validate_json(encoded_keys)
        capability=base64.b64decode(keys.capability_key_base64,validate=True);private=base64.b64decode(keys.oauth_private_key_base64,validate=True)
        if not 32<=len(capability)<=128 or not 32<=len(private)<=128:raise ValueError('bounded keys required')
        auth=settings.auth;oauth=settings.oauth;resources=settings.aws;limits=settings.limits;application=settings.application
        if (auth.initial_owner_subject is None)!=(auth.bootstrap_receipt_sha256 is None):raise ValueError('paired bootstrap configuration required')
        worker=WorkerLimits.from_controls({'vision_worker':limits.worker})
        config=ApplicationConfig(**application.model_dump(),
            installation=InstallationConfig(settings.installation.wheel_path),
            ingress=None if settings.ingress is None else settings.ingress.build(),
            restore_fence=settings.restore_fence.build(application.artifact_sha256),
            improvement=ImprovementConfig(**settings.improvement.model_dump()),
            dataset=DatasetConfig(**settings.dataset.model_dump()),
            policy_catalog=PolicyCatalogConfig(**settings.policy_catalog.model_dump()),
            evaluation=EvaluationConfig(**settings.evaluation.model_dump()),
            vision_replay=None if settings.vision_replay is None else VisionReplayConfig(**settings.vision_replay.model_dump()),
            qualification_preparation=None if settings.qualification_preparation is None else EvaluationConfig(**settings.qualification_preparation.model_dump()),
            policy_contract_suite=None if settings.policy_contract_suite is None else ContractSuiteConfig(**settings.policy_contract_suite.model_dump()),
            policy_qualification=None if settings.policy_qualification is None else QualificationConfig(EvaluationConfig(**settings.policy_qualification.jobs.model_dump()),settings.policy_qualification.max_reserved_cases,settings.policy_qualification.golden_case_ms),
            policy_activation=None if settings.policy_activation is None else ActivationConfig(**settings.policy_activation.model_dump(),qualification_registry_sha256=installed_qualification_registry_sha256()),
            handoffs=None if settings.handoffs is None else HandoffLimits(**settings.handoffs.model_dump()),
            metadata_admission=None if settings.metadata_admission is None else AdmissionConfiguration(**settings.metadata_admission.model_dump()),
            owner_metadata=None if settings.owner_metadata is None else OwnerMetadataLimits(**settings.owner_metadata.model_dump()),
            owner_metadata_review=None if settings.owner_metadata_review is None else settings.owner_metadata_review.build(),
            auth=AuthConfig(settings.deployment,auth.issuer,capability,**auth.model_dump(exclude={'issuer','id_token_max_lifetime_seconds'})),
            oauth=OAuthConfig(deployment=settings.deployment,redirect_uri=application.app_origin+'/api/v1/auth/callback',private_key=private,**oauth.model_dump()),
            cognito=CognitoConfig(auth.issuer,oauth.client_id,native_totp_acr=oauth.native_totp_acr,max_token_lifetime_seconds=auth.id_token_max_lifetime_seconds),
            objects=ObjectConfig(settings.deployment,resources.bucket,resources.account_id,resources.region,resources.kms_key_arn),
            state_table=resources.state_table,events_table=resources.events_table,worker_limits=worker,max_worker_processes=limits.worker['max_processes'],
            **limits.model_dump(exclude={'worker'}))
        enrollment_fingerprint=enrollment_configuration_sha256(config)
        if config.restore_fence.release_kind=='initial-data-release':
            config=replace(config,restore_fence=replace(config.restore_fence,initial_configuration_sha256=enrollment_fingerprint))
        return LoadedConfiguration(config,fingerprint,enrollment_fingerprint)
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError):
        raise HostConfigurationError('Private host configuration is unavailable or invalid.') from None


def _close_host_clients(clients):
    complete=True
    for client in clients:
        try:client.close()
        except Exception:complete=False
    return complete


def _host_clients(loaded,session_factory=None):
    """One refreshable instance-role session; ownership is explicit."""
    owned=[]
    try:
        if session_factory is None:
            import boto3
            session_factory=boto3.Session
        from botocore.config import Config
        config=loaded.config;region=config.objects.region;session=session_factory(region_name=region)
        credentials=session.get_credentials()
        if credentials is None or credentials.method!='iam-role':raise ValueError('instance role required')
        transport=Config(connect_timeout=2,read_timeout=3,retries={'total_max_attempts':1})
        for service in ('dynamodb','s3','sts'):
            owned.append(session.client(service,region_name=region,endpoint_url=f'https://{service}.{region}.amazonaws.com',config=transport))
        return ApplicationClients(*owned)
    except Exception:
        _close_host_clients(owned)
        raise HostConfigurationError('Host SDK initialization failed; configured application was not constructed.') from None


def build_host_app(loaded:LoadedConfiguration,*,session_factory=None):
    """Transfer clients only after successful application construction."""
    try:verify_installation(loaded.config.installation,loaded.config.artifact_sha256)
    except Exception:
        raise HostConfigurationError('Local installation verification failed; application was not constructed.') from None
    clients=_host_clients(loaded,session_factory)
    try:
        return create_configured_app(loaded.config,clients)
    except Exception:
        _close_host_clients((clients.dynamodb,clients.s3,clients.sts))
        raise HostConfigurationError('Host SDK initialization failed; configured application was not constructed.') from None


def read_host_startup(loaded,*,instance_id,configuration_sha256,session_factory=None,clock_ms=None,tick_ns=None):
    """Private fixed-scope observation; no app, process handle or mutations."""
    clients=None
    try:
        if (type(loaded) is not LoadedConfiguration or type(loaded.config) is not ApplicationConfig
                or type(configuration_sha256) is not str or re.fullmatch('[a-f0-9]{64}',configuration_sha256) is None
                or configuration_sha256!=loaded.configuration_sha256):
            raise ValueError('original host document required')
        uuid(instance_id)
        config=loaded.config
        if (type(config.restore_fence) is not RestoreFenceConfig or config.metadata_admission is None
                or config.local_database_endpoint is not None or config.environment not in {'beta','synthetic_demo'}):
            raise ValueError('protected fixed host target required')
        tick=monotonic_ns if tick_ns is None else tick_ns
        started=tick();last=started
        if type(started) is not int or not 0<=started<2**63:
            raise ValueError('bounded private clock required')
        deadline=started+config.metadata_admission.http_lease_ms*1000000
        if deadline>=2**63:raise ValueError('bounded original private deadline required')
        def checkpoint():
            nonlocal last
            current=tick()
            if type(current) is not int or not last<=current<deadline:
                raise ValueError('original private deadline or clock held')
            last=current
        verify_installation(config.installation,config.artifact_sha256)
        checkpoint()
        clients=_host_clients(loaded,session_factory)
        checkpoint()
        region=config.objects.region
        for service,value in (('dynamodb',clients.dynamodb),('s3',clients.s3),('sts',clients.sts)):
            _client(value,service,region,'https://'+service+'.'+region+'.amazonaws.com')
        _target(config,clients);checkpoint()
        fence=RestoreDataFence(clients.dynamodb,deployment=config.auth.deployment,state_table=config.state_table,
            events_table=config.events_table,config=config.restore_fence,tick=tick)
        fence.verify_target();checkpoint()
        repository=DynamoRepository(clients.dynamodb,deployment=config.auth.deployment,state_table=config.state_table,
            events_table=config.events_table,data_fence=fence)
        access=AccessService(repository,config.auth,clock_ms=clock_ms)
        runtime=RuntimeControl(access,instance_id=instance_id,artifact_sha256=config.artifact_sha256,
            controls_sha256=config.controls_sha256,environment=config.environment)
        result=asdict(runtime.observe_startup());checkpoint()
        result.update(status='STARTUP_OBSERVED',configuration_sha256=configuration_sha256,
            readiness_approved=False,inspection_enablement_granted=False,request_fulfilled=False)
    except Exception:
        raise HostConfigurationError('Protected startup observation is unavailable; no recovery authority was granted.') from None
    finally:
        if clients is not None and not _close_host_clients((clients.dynamodb,clients.s3,clients.sts)):
            raise HostConfigurationError('Protected startup observation is unavailable; no recovery authority was granted.') from None
    try:checkpoint()
    except Exception:
        raise HostConfigurationError('Protected startup observation is unavailable; no recovery authority was granted.') from None
    return result


class Parser(argparse.ArgumentParser):
    def error(self,message):self.exit(2,'Invalid command arguments. Use --help for the accepted options.\n')


def main(argv=None,*,session_factory=None,run_server=None):
    parser=Parser(description='Validate, prepare/enroll a fresh installation, observe startup or serve explicitly configured ProofPack.')
    commands=parser.add_subparsers(dest='command',required=True,parser_class=Parser)
    for command in ('check-config','prepare-enrollment','enroll','read-startup','serve'):
        child=commands.add_parser(command);child.add_argument('--config',required=True);child.add_argument('--secrets-file',required=True)
        if command=='serve':
            child.add_argument('--bind',default='127.0.0.1');child.add_argument('--port',type=int,default=8080)
        if command=='read-startup':
            child.add_argument('--instance-id',required=True);child.add_argument('--configuration-sha256',required=True)
        if command in {'prepare-enrollment','enroll'}:child.add_argument('--enrollment-file',required=True)
    args=parser.parse_args(argv)
    try:
        loaded=load_configuration(args.config,args.secrets_file)
        if args.command=='check-config':
            print(json.dumps({'status':'CONFIGURATION_VALID','scope':'syntax_and_service_bounds_only','configuration_sha256':loaded.configuration_sha256}))
            return 0
        if args.command=='read-startup':
            result=read_host_startup(loaded,instance_id=args.instance_id,
                configuration_sha256=args.configuration_sha256,session_factory=session_factory)
            print(json.dumps(result))
            return 0
        if args.command in {'prepare-enrollment','enroll'}:
            from proofpack.runtime.enrollment import run_enrollment
            result=run_enrollment(loaded,load_enrollment(args.enrollment_file),commit=args.command=='enroll',session_factory=session_factory)
            print(json.dumps(result))
            return 0
        ipaddress.ip_address(args.bind)
        if not 1<=args.port<=65535:raise HostConfigurationError('invalid port')
        proxy_options=server_proxy_options(loaded.config.ingress)
        app=build_host_app(loaded,session_factory=session_factory)
        try:instance_id=uuid(app.state.runtime_control.instance_id)
        except (ValueError,TypeError,AttributeError):
            raise HostConfigurationError('Constructed startup reference is unavailable.') from None
        print(json.dumps({'status':'STARTUP_REFERENCE','scope':'attempt_identity_only','instance_id':instance_id,
            'configuration_sha256':loaded.configuration_sha256,
            'configured_artifact_sha256':loaded.config.artifact_sha256}),file=sys.stderr,flush=True)
        if run_server is None:
            import uvicorn
            run_server=uvicorn.run
        run_server(app,host=args.bind,port=args.port,workers=1,reload=False,access_log=False,**proxy_options)
        return 0
    except (HostConfigurationError,ValueError):
        print('Host command failed validation or initialization. No readiness or release approval was granted.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
