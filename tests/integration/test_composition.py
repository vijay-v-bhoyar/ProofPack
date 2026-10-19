"""Owned local composition. STS is intercepted; no AWS identity/deployment proof."""
from dataclasses import replace
import hashlib
from uuid import uuid4
from threading import Event,Thread

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from fastapi.testclient import TestClient
import pytest

from test_access_lifecycle import repository_factory,Clock,ISSUER,proof
from proofpack.auth.service import AuthConfig,HEAD,BootstrapApproval
from proofpack.auth.http import COOKIE
from proofpack.auth.cognito import CognitoConfig
from proofpack.auth.oauth import OAuthConfig
from proofpack.evidence.objects import ObjectConfig
from proofpack.runtime.composition import ApplicationConfig,ApplicationClients,ConfiguredStartupUnavailable,create_configured_app
from proofpack.runtime.control import RUNTIME,DATA,ALLOCATION
from proofpack.runtime.installation import InstallationConfig
from proofpack.vision.worker_limits import WorkerLimits
from proofpack.evidence.improvement import ImprovementConfig
from proofpack.evidence.privacy_admission import AdmissionConfiguration
from proofpack.evidence.restore_fence import RestoreFenceConfig
from proofpack.evidence.journal_anchors import AnchorCheckpoint
from proofpack.review.evaluation_models import EvaluationConfig
from proofpack.planner.candidates import PolicyCatalogConfig
from proofpack.review.manifests import DatasetConfig


def synthetic_restore_configuration(config):
    """Explicit target-check input only, never a genuine enrollment or release."""
    return RestoreFenceConfig('synthetic-protected-journal',
        'arn:aws:dynamodb:us-east-1:000000000000:table/synthetic-protected-journal',
        '9'*64, AnchorCheckpoint(0,'a'*64), 'b'*64,
        (('events','synthetic-events-creation'),('state','synthetic-state-creation')),
        config.artifact_sha256,1000)


def test_enabled_maintenance_shares_services_and_drains_before_exactly_once_cleanup(composition_case,monkeypatch):
    _,config,clients,stub,clock=composition_case;identity(stub)
    app=create_configured_app(replace(config,maintenance_enabled=True),clients,clock_ms=clock)
    driver=app.state.maintenance_driver;entered=Event();original=driver.poll_once;closed=[]
    def poll():
        result=original();entered.set();return result
    monkeypatch.setattr(driver,'poll_once',poll)
    for name,owned in [('references',app.state.reference_service),('registry',app.state.reference_service.registry),
            ('dynamodb',clients.dynamodb),('s3',clients.s3),('sts',clients.sts)]:
        original_close=owned.close
        def close(name=name,original_close=original_close):
            assert not driver._thread.is_alive();closed.append(name);original_close()
        monkeypatch.setattr(owned,'close',close)
    with TestClient(app):
        assert entered.wait(3)
        assert driver.services['inspection_export'] is app.state.export_service
        assert driver.services['asset_erasure'] is app.state.erasure_service
        assert driver.runtime is app.state.runtime_control and closed==[]
    assert sorted(closed)==['dynamodb','references','registry','s3','sts']
    assert app.state.composition_status=='closed' and not driver._thread.is_alive()


@pytest.mark.parametrize('finish_before_registration',[False,True])
def test_failed_maintenance_drain_defers_resource_cleanup_until_step_exits(composition_case,monkeypatch,finish_before_registration):
    _,config,clients,stub,clock=composition_case;identity(stub)
    app=create_configured_app(replace(config,maintenance_enabled=True),clients,clock_ms=clock)
    driver=app.state.maintenance_driver;entered=Event();release=Event();cleaned=Event();closed=[]
    def blocked_poll():
        entered.set();assert release.wait(6)
    monkeypatch.setattr(driver,'poll_once',blocked_poll)
    if finish_before_registration:
        original_after=driver.after_exit
        def register(callback):
            release.set();driver._thread.join(3);assert not driver._thread.is_alive()
            original_after(callback)
        monkeypatch.setattr(driver,'after_exit',register)
    for name,owned in [('references',app.state.reference_service),('registry',app.state.reference_service.registry),
            ('dynamodb',clients.dynamodb),('s3',clients.s3),('sts',clients.sts)]:
        original_close=owned.close
        def close(name=name,original_close=original_close):
            assert release.is_set();closed.append(name);original_close()
            if name=='sts':cleaned.set()
        monkeypatch.setattr(owned,'close',close)
    try:
        with pytest.raises(ConfiguredStartupUnavailable,match='did not drain'):
            with TestClient(app):assert entered.wait(3)
        assert app.state.composition_status=='failed'
        assert (not driver._thread.is_alive()) if finish_before_registration else (driver._thread.is_alive() and closed==[])
        assert driver._drain_failed
    finally:
        release.set();driver._thread.join(3)
    assert cleaned.wait(1) and sorted(closed)==['dynamodb','references','registry','s3','sts']
    assert app.state.composition_status=='failed' and not driver._thread.is_alive()


def test_maintenance_thread_start_failure_cleans_resources_without_joining_unstarted_thread(composition_case,monkeypatch):
    _,config,clients,stub,clock=composition_case;identity(stub)
    app=create_configured_app(replace(config,maintenance_enabled=True),clients,clock_ms=clock)
    class FailingThread(Thread):
        def start(self):raise RuntimeError('synthetic thread start failure')
    monkeypatch.setattr('proofpack.runtime.maintenance.Thread',FailingThread)
    with pytest.raises(RuntimeError,match='thread start failure'):
        with TestClient(app):pass
    assert app.state.composition_status=='failed' and app.state.maintenance_driver._thread is None


@pytest.fixture
def composition_case(repository_factory):
    repository=repository_factory();region='us-east-1';account='000000000000'
    settings=Config(connect_timeout=2,read_timeout=3,retries={'total_max_attempts':1})
    def client(service,endpoint):return boto3.client(service,region_name=region,endpoint_url=endpoint,
        aws_access_key_id='localtest',aws_secret_access_key='localtest',config=settings)
    clients=ApplicationClients(client('dynamodb',repository.client.meta.endpoint_url),client('s3','https://s3.us-east-1.amazonaws.com'),client('sts','https://sts.us-east-1.amazonaws.com'))
    config=ApplicationConfig(app_origin='https://proofpack.test',environment='test',artifact_sha256='a'*64,controls_sha256='b'*64,
        auth=AuthConfig(repository.deployment,ISSUER,b'synthetic-composition-capability-key'*2,notice_version='fixture-v1',notice_text='Synthetic operational notice.'),
        oauth=OAuthConfig(repository.deployment,'https://proofpack.auth.us-east-1.amazoncognito.com','fixtureclient',
            'https://proofpack.test/api/v1/auth/callback',b'synthetic-composition-oauth-key'*2),
        cognito=CognitoConfig(ISSUER,'fixtureclient'),objects=ObjectConfig(repository.deployment,'proofpack-test',account,region,
            'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-4000-8000-000000000001'),
        state_table=repository.tables['state'],events_table=repository.tables['events'],worker_limits=WorkerLimits(512,30,750,5000,2097152,65536,262144,4096,30,12,0),
        max_worker_processes=2,purpose_max_lifetime_ms=60000,reference_uploads_per_minute=8,calibration_runs_per_minute=8,
        recipe_qualification_runs_per_minute=8,recipe_qualification_max_ms=15000,calibration_max_diagnostic_ms=15000,label_writes_per_minute=8,label_max_duration_ms=60000,label_review_validity_ms=30000,
        evidence_reads_per_minute=8,evidence_max_concurrent=2,evidence_read_window_ms=5000,
        export_jobs_per_minute=8,export_job_lifetime_ms=60000,export_lease_ms=15000,export_page_size=25,export_max_scan_rows=500,export_max_records=128,export_max_assets=3,export_ticket_ms=30000,export_download_ms=20000,export_max_concurrent=2,
        deletion_review_ms=30000,deletion_jobs_per_minute=8,deletion_lease_ms=15000,deletion_version_page_size=20,
        maintenance_enabled=False,maintenance_poll_ms=250,maintenance_page_size=10,maintenance_steps_per_minute=60,maintenance_drain_ms=1000,
        dataset=DatasetConfig(1000,8,120,60000,15000,3000,120),
        policy_catalog=PolicyCatalogConfig(20,120,100),
        evaluation=EvaluationConfig(8,120,120,60000,15000,3000),
        improvement=ImprovementConfig('synthetic-improvement-v1','Synthetic optional-use notice; no real consent.',60000,8,30000),
        operation_purpose_id=None,local_database_endpoint=repository.client.meta.endpoint_url)
    stub=Stubber(clients.sts);stub.activate();s3_stub=Stubber(clients.s3);s3_stub.activate()
    try:yield repository,config,clients,stub,Clock()
    finally:
        stub.deactivate();s3_stub.deactivate()
        for owned in (clients.dynamodb,clients.s3,clients.sts):owned.close()


def identity(stub,account='000000000000',arn=None):
    stub.add_response('get_caller_identity',{'Account':account,'UserId':'SYNTHETIC:test',
        'Arn':arn or 'arn:aws:sts::'+account+':assumed-role/ProofPackTest/test-session'}, {})


@pytest.mark.parametrize('vision_enabled',[False,True])
def test_factory_constructs_without_io_and_starts_all_shared_services_disabled(composition_case,monkeypatch,vision_enabled):
    repository,config,clients,stub,clock=composition_case
    from proofpack.review.vision_replay import VisionReplayConfig
    if vision_enabled:config=replace(config,vision_replay=VisionReplayConfig())
    def unexpected(*args,**kwargs):raise AssertionError('factory construction must not call any SDK')
    with monkeypatch.context() as boundary:
        for owned in (clients.dynamodb,clients.s3,clients.sts):boundary.setattr(owned,'_make_api_call',unexpected)
        app=create_configured_app(config,clients,clock_ms=clock)
    state=app.state
    assert state.composition_status=='constructed' and state.runtime_control.handle is None
    assert repository.snapshot((RUNTIME,))[RUNTIME] is None
    assert state.observation_service.publisher is None
    assert state.reference_service.registry is state.observation_service.registry
    if vision_enabled:
        assert state.evaluation_service.vision.registry is state.reference_service.registry
        assert state.evaluation_service.vision.evaluations is state.evaluation_service
    else:assert state.evaluation_service.vision is None
    assert state.calibration_service.references is state.reference_service
    assert state.recipe_qualification_service.references is state.reference_service
    assert state.recipe_qualification_service.recipes is state.recipe_service
    assert state.label_service.purposes is state.purpose_service
    assert state.asset_service.purposes is state.purpose_service
    assert state.export_service.assets is state.asset_service
    assert state.erasure_service.purposes is state.purpose_service
    assert state.erasure_service.objects.frames is state.asset_service.frames
    assert state.capture_service.stations is state.station_service
    assert state.station_service.recipes is state.recipe_service
    assert state.signin_service.access is state.access_service
    identity(stub)
    with TestClient(app,base_url=config.app_origin) as client:
        assert state.composition_status=='started' and state.composition_scope=='local_synthetic'
        rows=repository.snapshot((RUNTIME,DATA,ALLOCATION,HEAD))
        assert rows[RUNTIME].data['inspection_enabled'] is False and rows[DATA] is not None and rows[ALLOCATION] is not None
        assert rows[HEAD] is None  # No implicit first owner or membership bootstrap.
        assert client.get('/health/ready').status_code==503
        assert client.get('/api/v1/me').status_code==401
        assert client.get('/api/v1/auth/login',follow_redirects=False).status_code==303
        assert 'oauth' in client.cookies.keys().__str__()
        assert client.post('/api/v1/auth/login',json={'subject':'owner','mfa_verified':True}).status_code==405
    stub.assert_no_pending_responses()
    assert state.composition_status=='closed'


def test_factory_with_explicit_purpose_connects_evidence_without_seeding_authority(composition_case):
    repository,config,clients,stub,clock=composition_case;purpose_id=str(uuid4())
    app=create_configured_app(replace(config,operation_purpose_id=purpose_id),clients,clock_ms=clock)
    assert app.state.observation_service.publisher is not None
    assert app.state.asset_service.frames is app.state.observation_service.publisher.objects
    identity(stub)
    with TestClient(app):
        assert app.state.runtime_control.handle is not None
        assert repository.query(prefix='purpose#',limit=20)[0]==[]
        assert repository.snapshot((HEAD,))[HEAD] is None


@pytest.mark.parametrize('kind',['wrong_account','root_identity','sts_failure','missing_table'])
def test_startup_target_failure_cannot_write_runtime_and_closes_owned_clients(composition_case,kind):
    repository,config,clients,stub,clock=composition_case
    if kind=='wrong_account':identity(stub,'111111111111')
    elif kind=='root_identity':identity(stub,arn='arn:aws:iam::000000000000:root')
    elif kind=='sts_failure':stub.add_client_error('get_caller_identity',service_error_code='AccessDenied',service_message='synthetic secret text')
    else:
        identity(stub);config=replace(config,state_table='missing-table-'+uuid4().hex)
    closed=[]
    for name in ('dynamodb','s3','sts'):
        owned=getattr(clients,name);close=owned.close
        owned.close=lambda name=name,close=close:(closed.append(name),close())
    app=create_configured_app(config,clients,clock_ms=clock)
    with pytest.raises(ConfiguredStartupUnavailable) as error:
        with TestClient(app):pass
    assert 'secret' not in str(error.value) and app.state.composition_status=='failed'
    assert set(closed)=={'dynamodb','s3','sts'}
    assert repository.snapshot((RUNTIME,))[RUNTIME] is None


def test_failed_opencv_proof_stops_before_any_target_request(composition_case,monkeypatch):
    repository,config,clients,stub,clock=composition_case
    def fail():raise RuntimeError('synthetic missing OpenCV 5')
    monkeypatch.setattr('proofpack.runtime.composition.runtime_proof',fail)
    app=create_configured_app(config,clients,clock_ms=clock)
    with pytest.raises(RuntimeError,match='missing OpenCV'):
        with TestClient(app):pass
    assert app.state.composition_status=='failed' and repository.snapshot((RUNTIME,))[RUNTIME] is None


def test_application_incarnation_cannot_restart_or_reenable_old_state(composition_case):
    repository,config,clients,stub,clock=composition_case;identity(stub)
    app=create_configured_app(config,clients,clock_ms=clock)
    with TestClient(app):epoch=app.state.runtime_control.handle.epoch
    with pytest.raises(ConfiguredStartupUnavailable,match='cannot be restarted'):
        with TestClient(app):pass
    assert repository.snapshot((RUNTIME,))[RUNTIME].data['runtime_epoch']==epoch


@pytest.mark.parametrize('changes',[
    {'environment':'beta'}, {'environment':'synthetic_demo'}, {'events_table':'same','state_table':'same'},
    {'app_origin':'http://proofpack.test'}, {'max_worker_processes':3}, {'operation_purpose_id':'not-a-uuid'},
    {'local_database_endpoint':'http://localhost:8001'}, {'local_database_endpoint':'http://127.0.0.1:8001/path'},
    {'artifact_sha256':'not-a-sha'}, {'purpose_max_lifetime_ms':0}, {'reference_uploads_per_minute':0},
    {'label_review_validity_ms':60001},
    {'recipe_qualification_runs_per_minute':0},{'recipe_qualification_max_ms':999},{'recipe_qualification_max_ms':60001},
    {'deletion_review_ms':0},{'deletion_jobs_per_minute':101},{'deletion_lease_ms':999},{'deletion_lease_ms':60001},{'deletion_version_page_size':1001},
    {'evidence_reads_per_minute':0},{'evidence_max_concurrent':3},{'evidence_read_window_ms':5001},
])
def test_configuration_mismatch_or_missing_bounds_never_creates_runtime(composition_case,changes):
    repository,config,clients,stub,clock=composition_case
    with pytest.raises(ValueError):create_configured_app(replace(config,**changes),clients,clock_ms=clock)
    assert repository.snapshot((RUNTIME,))[RUNTIME] is None


def test_configuration_repr_hides_keys_notice_and_owned_clients(composition_case):
    repository,config,clients,stub,clock=composition_case
    assert config.auth.capability_key.decode() not in repr(config)
    assert config.oauth.private_key.decode() not in repr(config)
    assert config.auth.notice_text not in repr(config)
    assert 'localtest' not in repr(clients)


@pytest.mark.parametrize('fault',['account','region','name','status','partition_key','key_type','attribute_type','missing_attribute'])
def test_regional_table_metadata_mismatch_denies_before_any_runtime_write(composition_case,fault,installation_wheel):
    repository,config,clients,stub,clock=composition_case
    regional=boto3.client('dynamodb',region_name=config.objects.region,aws_access_key_id='synthetic',aws_secret_access_key='synthetic',
        config=Config(connect_timeout=2,read_timeout=3,retries={'total_max_attempts':1}))
    owned=ApplicationClients(regional,clients.s3,clients.sts)
    config=replace(config,artifact_sha256=installation_wheel[1],installation=InstallationConfig(str(installation_wheel[0])))
    config=replace(config,environment='beta',local_database_endpoint=None,metadata_admission=AdmissionConfiguration(8,300000,60000,120000,3,'a'*64),restore_fence=synthetic_restore_configuration(config))
    table={'TableName':config.state_table,'TableStatus':'ACTIVE','TableArn':'arn:aws:dynamodb:us-east-1:000000000000:table/'+config.state_table,
        'KeySchema':[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],
        'AttributeDefinitions':[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'}]}
    if fault=='account':table['TableArn']=table['TableArn'].replace('000000000000','111111111111')
    elif fault=='region':table['TableArn']=table['TableArn'].replace('us-east-1','us-west-2')
    elif fault=='name':table['TableName']='other-table'
    elif fault=='status':table['TableStatus']='UPDATING'
    elif fault=='partition_key':table['KeySchema'][0]['AttributeName']='other'
    elif fault=='key_type':table['KeySchema'][0]['KeyType']='RANGE'
    elif fault=='attribute_type':table['AttributeDefinitions'][0]['AttributeType']='N'
    elif fault=='missing_attribute':table['AttributeDefinitions'].pop()
    identity(stub)
    with Stubber(regional) as data_stub:
        data_stub.add_response('describe_table',{'Table':table},{'TableName':config.state_table})
        app=create_configured_app(config,owned,clock_ms=clock)
        with pytest.raises(ConfiguredStartupUnavailable,match='table metadata'):
            with TestClient(app):pass
        data_stub.assert_no_pending_responses();stub.assert_no_pending_responses()
    assert repository.snapshot((RUNTIME,))[RUNTIME] is None


def test_fixed_target_check_accepts_correct_identity_and_primary_schema_without_calls_beyond_describe(composition_case,installation_wheel):
    from proofpack.runtime.composition import _target
    repository,config,clients,stub,clock=composition_case
    regional=boto3.client('dynamodb',region_name=config.objects.region,aws_access_key_id='synthetic',aws_secret_access_key='synthetic',
        config=Config(connect_timeout=2,read_timeout=3,retries={'total_max_attempts':1}))
    config=replace(config,artifact_sha256=installation_wheel[1],installation=InstallationConfig(str(installation_wheel[0])))
    config=replace(config,local_database_endpoint=None,environment='beta',metadata_admission=AdmissionConfiguration(8,300000,60000,120000,3,'a'*64),restore_fence=synthetic_restore_configuration(config));identity(stub)
    try:
        with Stubber(regional) as data_stub:
            for name in (config.state_table,config.events_table):
                data_stub.add_response('describe_table',{'Table':{'TableName':name,'TableStatus':'ACTIVE',
                    'TableArn':'arn:aws:dynamodb:us-east-1:000000000000:table/'+name,
                    'KeySchema':[{'AttributeName':'sk','KeyType':'RANGE'},{'AttributeName':'pk','KeyType':'HASH'}],
                    'AttributeDefinitions':[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'},
                        {'AttributeName':'other_index_key','AttributeType':'S'}]}},{'TableName':name})
            _target(config,ApplicationClients(regional,clients.s3,clients.sts));data_stub.assert_no_pending_responses();stub.assert_no_pending_responses()
    finally:regional.close()
    assert repository.snapshot((RUNTIME,))[RUNTIME] is None


def test_client_cleanup_failure_preserves_other_cleanup_and_does_not_log_provider_text(composition_case,monkeypatch,caplog):
    repository,config,clients,stub,clock=composition_case;identity(stub);closed=[]
    def fail_close():closed.append('dynamodb');raise RuntimeError('synthetic-secret-close-message')
    monkeypatch.setattr(clients.dynamodb,'close',fail_close)
    for name in ('s3','sts'):
        client=getattr(clients,name);original=client.close
        monkeypatch.setattr(client,'close',lambda name=name,original=original:(closed.append(name),original()))
    app=create_configured_app(config,clients,clock_ms=clock)
    with TestClient(app):pass
    assert set(closed)=={'dynamodb','s3','sts'} and app.state.composition_status=='failed'
    assert 'resource cleanup failed' in caplog.text and 'synthetic-secret' not in caplog.text


def test_runtime_start_failure_cleans_up_without_serving_configured_app(composition_case,monkeypatch):
    repository,config,clients,stub,clock=composition_case;identity(stub)
    app=create_configured_app(config,clients,clock_ms=clock)
    def fail():raise RuntimeError('synthetic runtime store failure')
    monkeypatch.setattr(app.state.runtime_control,'start',fail)
    with pytest.raises(RuntimeError,match='runtime store failure'):
        with TestClient(app):pass
    assert app.state.composition_status=='failed' and repository.snapshot((RUNTIME,))[RUNTIME] is None


def test_configured_shutdown_closes_the_actual_owned_diagnostic_worker(composition_case):
    repository,config,clients,stub,clock=composition_case;identity(stub);lease=None
    app=create_configured_app(config,clients,clock_ms=clock)
    try:
        with TestClient(app):
            registry=app.state.reference_service.registry
            lease=registry.diagnostic(runtime_id=app.state.runtime_control.instance_id);worker=lease.__enter__()
            assert worker.available
        assert not worker.available and app.state.composition_status=='closed'
    finally:
        if lease is not None:lease.__exit__(None,None,None)


@pytest.mark.parametrize('service',['dynamodb','s3','sts'])
@pytest.mark.parametrize('fault',['endpoint','retry','timeout'])
def test_client_endpoint_or_transport_budget_cannot_expand_runtime_authority(composition_case,service,fault):
    repository,config,clients,stub,clock=composition_case
    endpoint={'dynamodb':config.local_database_endpoint,'s3':'https://s3.us-east-1.amazonaws.com','sts':'https://sts.us-east-1.amazonaws.com'}[service]
    if fault=='endpoint':endpoint='https://wrong-target.example.invalid'
    owned=boto3.client(service,region_name='us-east-1',endpoint_url=endpoint,aws_access_key_id='synthetic',aws_secret_access_key='synthetic',
        config=Config(connect_timeout=2,read_timeout=5 if fault=='timeout' else 3,retries={'total_max_attempts':2 if fault=='retry' else 1}))
    try:
        with pytest.raises(ValueError):create_configured_app(config,replace(clients,**{service:owned}),clock_ms=clock)
    finally:owned.close()
    assert repository.snapshot((RUNTIME,))[RUNTIME] is None


@pytest.mark.parametrize('kind',['worker_deadline','worker_startup','notice','callback','deployment','provider_client'])
def test_semantic_configuration_bindings_are_required_before_startup(composition_case,kind):
    repository,config,clients,stub,clock=composition_case
    if kind=='worker_deadline':changes={'worker_limits':replace(config.worker_limits,wall_ms=751)}
    elif kind=='worker_startup':changes={'worker_limits':replace(config.worker_limits,startup_ms=5001)}
    elif kind=='notice':changes={'auth':replace(config.auth,notice_version=None,notice_text=None)}
    elif kind=='callback':changes={'oauth':replace(config.oauth,redirect_uri='https://other.example.invalid/api/v1/auth/callback')}
    elif kind=='deployment':changes={'oauth':replace(config.oauth,deployment='other-deployment')}
    else:changes={'cognito':replace(config.cognito,client_id='otherclient')}
    with pytest.raises(ValueError):create_configured_app(replace(config,**changes),clients,clock_ms=clock)
    assert repository.snapshot((RUNTIME,))[RUNTIME] is None


def test_explicit_local_owner_setup_uses_composed_http_services_without_auto_enabling_capture(composition_case):
    repository,config,clients,stub,clock=composition_case
    config=replace(config,auth=replace(config.auth,initial_owner_subject='owner',bootstrap_receipt_sha256='a'*64))
    identity(stub);app=create_configured_app(config,clients,clock_ms=clock)
    with TestClient(app,base_url=config.app_origin) as client:
        assert repository.snapshot((HEAD,))[HEAD] is None
        # Trusted synthetic bootstrap/proof fixture; no browser or provider bypass is installed.
        access=app.state.access_service
        access.bootstrap(BootstrapApproval(ISSUER,'owner','a'*64),proof(clock))
        credentials=access.login(proof(clock));client.cookies.set(COOKIE,credentials.cookie)
        assert client.get('/api/v1/me').json()['roles']==['owner']
        notice_sha=hashlib.sha256(config.auth.notice_text.encode()).hexdigest()
        response=client.post('/api/v1/purposes',json={'notice_version':config.auth.notice_version,'notice_sha256':notice_sha,
            'source_permission_reference':'synthetic-owned-reference','operational_use_acknowledged':True,'expires_at_ms':clock()+10000},
            headers={'Origin':config.app_origin,'X-CSRF-Token':credentials.csrf,'Idempotency-Key':'composed-purpose'})
        assert response.status_code==201,response.text
        assert response.json()['rights_independently_verified'] is False
        assert client.get('/api/v1/purposes').json()['purposes'][0]['id']==response.json()['id']
        assert app.state.observation_service.publisher is None
        assert repository.snapshot((RUNTIME,))[RUNTIME].data['inspection_enabled'] is False
        assert client.get('/health/ready').status_code==503


@pytest.mark.parametrize('enabled',[False,True])
def test_preparation_factory_and_driver_share_exact_services_without_implicit_readiness(composition_case,monkeypatch,enabled):
    from proofpack.planner.contract_suite import ContractSuiteConfig
    from proofpack.review.vision_replay import VisionReplayConfig
    repository,config,clients,stub,clock=composition_case
    config=replace(config,vision_replay=VisionReplayConfig(),qualification_preparation=EvaluationConfig(20,120,120,3600000,15000,340),
        policy_contract_suite=ContractSuiteConfig(256,15000,8192,1048576),maintenance_enabled=enabled)
    def unexpected(*args,**kwargs):raise AssertionError('construction must not contact SDK target')
    with monkeypatch.context() as boundary:
        for owned in (clients.dynamodb,clients.s3,clients.sts):boundary.setattr(owned,'_make_api_call',unexpected)
        app=create_configured_app(config,clients,clock_ms=clock)
    state=app.state;preparation=state.qualification_preparation_service
    assert preparation.evaluations is state.evaluation_service and preparation.runtime is state.runtime_control
    assert preparation.access is state.access_service and preparation.repository is state.access_service.repository
    assert state.maintenance_driver.services['policy_qualification_preparation'] is preparation
    assert repository.snapshot((RUNTIME,))[RUNTIME] is None and state.runtime_control.handle is None
    identity(stub)
    with TestClient(app,base_url=config.app_origin) as client:
        assert client.get('/health/ready').status_code==503
        assert repository.snapshot((RUNTIME,))[RUNTIME].data['inspection_enabled'] is False
        assert client.get('/api/v1/qualification-preparations/options').status_code==401


@pytest.mark.parametrize('enabled',[False,True])
def test_genuine_policy_factory_shares_writer_activation_live_reader_and_driver(composition_case,monkeypatch,enabled):
    from proofpack.review.policy_qualification import QualificationConfig,installed_qualification_registry_sha256,PolicyQualifications
    from proofpack.planner.activation import ActivationConfig
    from proofpack.planner.active import ActivePolicies
    from proofpack.planner.contract_suite import ContractSuiteConfig
    from proofpack.review.vision_replay import VisionReplayConfig
    _,config,clients,stub,clock=composition_case
    jobs=EvaluationConfig(20,120,120,3600000,15000,3000)
    config=replace(config,vision_replay=VisionReplayConfig(),qualification_preparation=jobs,
        policy_contract_suite=ContractSuiteConfig(256,15000,8192,1048576),
        policy_qualification=QualificationConfig(jobs,2000,5000),
        policy_activation=ActivationConfig(20,120,60000,80,installed_qualification_registry_sha256()),maintenance_enabled=enabled)
    app=create_configured_app(config,clients,clock_ms=clock);state=app.state
    q=state.policy_qualification_service;active=state.active_policy_reader;activation=state.policy_activation_service
    assert type(q) is PolicyQualifications and type(active) is ActivePolicies
    assert q.policies is state.policy_service and q.preparations is state.qualification_preparation_service
    assert q.registry is state.observation_service.registry is state.reference_service.registry
    assert q.access is state.access_service and q.runtime is state.runtime_control
    assert activation.reader is q and active.activations is activation and state.station_service.policy_reader is active
    assert state.maintenance_driver.services['policy_qualification'] is q
    assert state.maintenance_driver.services['policy_qualification_preparation'] is q.preparations
    assert not q.registry._bindings
    identity(stub);monkeypatch.setattr('proofpack.runtime.composition.runtime_proof',lambda:{'cv2_version':'5.0.0'})
    with TestClient(app,base_url='https://proofpack.test') as client:
        assert state.composition_status=='started'
        runtime=state.access_service.repository.snapshot((RUNTIME,))[RUNTIME]
        assert runtime.data['inspection_enabled'] is False
        assert client.get('/api/v1/policies/active').status_code==401
        assert client.get('/api/v1/policy-qualifications/options').status_code==401
    assert state.composition_status=='closed' and q.registry._closed
