"""Host inputs and command boundaries; no credential discovery or provider calls."""
import base64
import json
from types import SimpleNamespace

import pytest

from proofpack.runtime.host import HostConfigurationError,load_configuration,build_host_app,main


@pytest.fixture
def host_files(tmp_path,installation_wheel):
    document={'schema_version':1,'deployment':'synthetic-host',
        'restore_fence':{'journal_table':'synthetic-journal','journal_arn':'arn:aws:dynamodb:us-east-1:000000000000:table/synthetic-journal',
            'genesis_sha256':'9'*64,'checkpoint':{'sequence':0,'digest':'a'*64},'release_sha256':'c'*64,
            'target_table_ids':{'events':'synthetic-events-creation','state':'synthetic-state-creation'},'max_check_ms':1000},
        'metadata_admission':{'max_active':8,'max_lease_ms':300000,'http_lease_ms':60000,
            'worker_lease_ms':120000,'attempts':3,'enrollment_sha256':'a'*64},
        'evaluation':{'jobs_per_minute':8,'step_attempts_per_minute':120,'reads_per_minute':120,'lifetime_ms':60000,'lease_ms':15000,'max_steps':3000},
        'policy_catalog':{'writes_per_minute':20,'reads_per_minute':120,'max_revisions':100},
        'dataset':{'max_examples':1000,'jobs_per_minute':8,'step_attempts_per_minute':120,'lifetime_ms':60000,'lease_ms':15000,'max_steps':3000,'reads_per_minute':120},
        'improvement':{'notice_version':'synthetic-improvement-v1','notice_text':'Synthetic optional-use notice; no real consent.','max_lifetime_ms':60000,'writes_per_minute':8,'review_ms':30000},
        'application':{'app_origin':'https://proofpack.test','environment':'synthetic_demo','artifact_sha256':'a'*64,'controls_sha256':'b'*64,'operation_purpose_id':None},
        'auth':{'issuer':'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Synthetic','initial_owner_subject':None,'bootstrap_receipt_sha256':None,
            'notice_version':'synthetic-v1','notice_text':'Synthetic host notice, not participant consent.','session_ttl_seconds':3600,'invitation_ttl_seconds':3600,
            'transfer_ttl_seconds':600,'mfa_grant_max_age_seconds':600,'id_token_max_lifetime_seconds':3600},
        'oauth':{'provider_origin':'https://proofpack.auth.us-east-1.amazoncognito.com','client_id':'fixtureclient','flow_ttl_seconds':300,
            'native_totp_acr':'urn:cognito:loa:4','mfa_max_age_seconds':600,'login_starts_per_minute':30,'callback_attempts_per_minute':60},
        'aws':{'region':'us-east-1','account_id':'000000000000','state_table':'synthetic-state','events_table':'synthetic-events','bucket':'proofpack-synthetic',
            'kms_key_arn':'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-4000-8000-000000000001'},
        'limits':{'maintenance_enabled':False,'maintenance_poll_ms':250,'maintenance_page_size':10,'maintenance_steps_per_minute':60,'maintenance_drain_ms':1000,'export_jobs_per_minute':8,'export_job_lifetime_ms':60000,'export_lease_ms':15000,'export_page_size':25,'export_max_scan_rows':500,'export_max_records':128,'export_max_assets':3,'export_ticket_ms':30000,'export_download_ms':20000,'export_max_concurrent':2,'deletion_review_ms':30000,'deletion_jobs_per_minute':8,'deletion_lease_ms':15000,'deletion_version_page_size':20,'worker':{'memory_mb':512,'cpu_seconds':30,'wall_ms':750,'startup_ms':5000,'max_input_bytes':2097152,'max_metadata_bytes':65536,
            'max_reply_bytes':262144,'max_contours':4096,'max_candidates':30,'pixel_delta':12,'max_changed_pixels':0,'max_processes':2},
            'purpose_max_lifetime_ms':60000,'reference_uploads_per_minute':8,'recipe_qualification_runs_per_minute':8,'recipe_qualification_max_ms':15000,'calibration_runs_per_minute':8,'calibration_max_diagnostic_ms':15000,
            'label_writes_per_minute':8,'label_max_duration_ms':60000,'label_review_validity_ms':30000,
            'evidence_reads_per_minute':8,'evidence_max_concurrent':2,'evidence_read_window_ms':5000}}
    keys={'capability_key_base64':base64.b64encode(b'synthetic-capability-key-not-real'*2).decode(),
        'oauth_private_key_base64':base64.b64encode(b'synthetic-oauth-private-key-not-real'*2).decode()}
    wheel,digest=installation_wheel
    document['installation']={'wheel_path':str(wheel)}
    document['application']['artifact_sha256']=digest
    config=tmp_path/'host.json';secret=tmp_path/'keys.json'
    config.write_text(json.dumps(document),encoding='utf-8');secret.write_text(json.dumps(keys),encoding='utf-8')
    return config,secret,document,keys


def forbidden(*args,**kwargs):raise AssertionError('this command must not start SDK or server')


def test_vision_replay_host_configuration_is_explicit_opt_in_without_io(host_files):
    config,secret,document,_=host_files
    assert load_configuration(config,secret).config.vision_replay is None
    document['vision_replay']={'max_case_ms':15000,'max_report_bytes':32768}
    config.write_text(json.dumps(document),encoding='utf-8')
    assert main(['check-config','--config',str(config),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==0
    loaded=load_configuration(config,secret).config
    assert loaded.vision_replay.max_case_ms==loaded.evaluation.lease_ms==15000
    assert loaded.vision_replay.max_report_bytes==32768


def preparation_settings(document):
    document['vision_replay']={'max_case_ms':15000,'max_report_bytes':32768}
    document['qualification_preparation']={'jobs_per_minute':20,'step_attempts_per_minute':120,'reads_per_minute':120,
        'lifetime_ms':3600000,'lease_ms':15000,'max_steps':340}
    document['policy_contract_suite']={'max_cases':256,'max_duration_ms':15000,'max_case_report_bytes':8192,'max_report_bytes':1048576}


def test_preparation_host_configuration_is_paired_explicit_and_has_no_sdk_or_server_io(host_files):
    config,secret,document,_=host_files;initial=load_configuration(config,secret).config
    assert initial.qualification_preparation is initial.policy_contract_suite is None
    preparation_settings(document);config.write_text(json.dumps(document),encoding='utf-8')
    assert main(['check-config','--config',str(config),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==0
    loaded=load_configuration(config,secret).config
    assert loaded.qualification_preparation.max_steps==340 and loaded.policy_contract_suite.max_cases==256


@pytest.mark.parametrize('fault',['missing_suite','missing_preparation','missing_vision','insufficient_steps','insufficient_cases','expanded_lease','coerced_case_bound'])
def test_invalid_preparation_installation_is_rejected_before_io(host_files,fault):
    config,secret,document,_=host_files;preparation_settings(document)
    if fault.startswith('missing_'):document.pop({'missing_suite':'policy_contract_suite','missing_preparation':'qualification_preparation','missing_vision':'vision_replay'}[fault])
    elif fault=='insufficient_steps':document['qualification_preparation']['max_steps']=170
    elif fault=='insufficient_cases':document['policy_contract_suite']['max_cases']=169
    elif fault=='expanded_lease':document['qualification_preparation']['lease_ms']=60001
    else:document['policy_contract_suite']['max_cases']=True
    config.write_text(json.dumps(document),encoding='utf-8')
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)


@pytest.mark.parametrize('change',[{'max_case_ms':True},{'max_case_ms':0},{'max_case_ms':15001},
    {'max_report_bytes':False},{'max_report_bytes':32769},{'max_report_bytes':0},{'new_worker_pool':True}])
def test_vision_host_invalid_bounds_never_reach_sdk_or_server(host_files,change):
    config,secret,document,_=host_files
    document['vision_replay']={'max_case_ms':15000,'max_report_bytes':32768,**change}
    config.write_text(json.dumps(document),encoding='utf-8')
    assert main(['check-config','--config',str(config),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==2


def test_check_config_validates_without_sdk_or_server_and_hides_inputs(host_files,capsys):
    config,secret,document,keys=host_files
    assert main(['check-config','--config',str(config),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==0
    output=capsys.readouterr();result=json.loads(output.out)
    assert result['status']=='CONFIGURATION_VALID' and result['scope']=='syntax_and_service_bounds_only'
    for value in (*keys.values(),document['auth']['notice_text'],str(secret)):
        assert value not in output.out+output.err
    loaded=load_configuration(config,secret)
    assert loaded.config.local_database_endpoint is None and 'synthetic-capability' not in repr(loaded)


def test_well_formed_optional_bootstrap_binding_is_accepted_without_creating_owner(host_files):
    config,secret,document,keys=host_files
    document['auth'].update(initial_owner_subject='owner',bootstrap_receipt_sha256='a'*64)
    config.write_text(json.dumps(document),encoding='utf-8')
    loaded=load_configuration(config,secret)
    assert loaded.config.auth.initial_owner_subject=='owner' and loaded.config.auth.bootstrap_receipt_sha256=='a'*64


@pytest.mark.parametrize('fault',['unknown','environment','endpoint','profile','missing_bound','wrong_type','worker_deadline','mfa_age','unpaired_bootstrap','bootstrap_digest','duplicate','nonfinite','oversized','recursive','missing_policy','policy_bound','policy_type','missing_evaluation','evaluation_bound','evaluation_type'])
def test_invalid_host_document_cannot_reach_sdk_and_errors_do_not_echo_input(host_files,fault,capsys):
    config,secret,document,keys=host_files
    if fault=='unknown':document['private-secret-test']='do-not-echo-this-value'
    elif fault=='environment':document['application']['environment']='test'
    elif fault=='endpoint':document['aws']['endpoint_url']='http://127.0.0.1:8001'
    elif fault=='profile':document['aws']['profile']='private-profile'
    elif fault=='missing_bound':document['limits'].pop('label_writes_per_minute')
    elif fault=='wrong_type':document['limits']['label_writes_per_minute']=True
    elif fault=='worker_deadline':document['limits']['worker']['wall_ms']=751
    elif fault=='mfa_age':document['auth']['mfa_grant_max_age_seconds']=100
    elif fault=='unpaired_bootstrap':document['auth']['initial_owner_subject']='private-owner'
    elif fault=='bootstrap_digest':document['auth'].update(initial_owner_subject='private-owner',bootstrap_receipt_sha256='not-a-receipt-digest')
    elif fault=='missing_policy':document.pop('policy_catalog')
    elif fault=='policy_bound':document['policy_catalog']['max_revisions']=1001
    elif fault=='policy_type':document['policy_catalog']['reads_per_minute']=True
    elif fault=='missing_evaluation':document.pop('evaluation')
    elif fault=='evaluation_bound':document['evaluation']['max_steps']=10001
    elif fault=='evaluation_type':document['evaluation']['lease_ms']=True
    config.write_text(json.dumps(document),encoding='utf-8')
    if fault=='duplicate':config.write_text('{"schema_version":1,"schema_version":1}',encoding='utf-8')
    elif fault=='nonfinite':config.write_text('{"schema_version":NaN}',encoding='utf-8')
    elif fault=='oversized':config.write_bytes(b'x'*65537)
    elif fault=='recursive':config.write_text('['*2000+'0'+']'*2000,encoding='utf-8')
    assert main(['check-config','--config',str(config),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==2
    output=capsys.readouterr();assert not output.out and 'do-not-echo' not in output.err and 'private-owner' not in output.err


@pytest.mark.parametrize('fault',['unknown','duplicate','invalid_base64','short_key','oversized','missing'])
def test_bad_key_document_is_bounded_and_never_echoed(host_files,fault,capsys):
    config,secret,document,keys=host_files
    if fault=='unknown':keys['aws_secret_access_key']='do-not-echo-aws-key'
    elif fault=='invalid_base64':keys['capability_key_base64']='!'*44
    elif fault=='short_key':keys['capability_key_base64']=base64.b64encode(b'tiny').decode()
    secret.write_text(json.dumps(keys),encoding='utf-8')
    if fault=='duplicate':secret.write_text('{"private":"do-not-echo","private":"again"}',encoding='utf-8')
    elif fault=='oversized':secret.write_bytes(b'x'*4097)
    elif fault=='missing':secret.unlink()
    assert main(['check-config','--config',str(config),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==2
    assert 'do-not-echo' not in capsys.readouterr().err


class FakeClient:
    def __init__(self):self.closed=False
    def close(self):self.closed=True


class FakeSession:
    def __init__(self,*,method='iam-role',fail=None):self.credentials=SimpleNamespace(method=method);self.created=[];self.calls=[];self.fail=fail
    def get_credentials(self):return self.credentials
    def client(self,service,**kwargs):
        self.calls.append((service,kwargs))
        if service==self.fail:raise RuntimeError('do-not-echo-provider-secret')
        client=FakeClient();self.created.append(client);return client


def test_host_creates_one_refreshable_instance_role_session_with_fixed_bounded_clients(host_files,monkeypatch):
    config,secret,document,keys=host_files;loaded=load_configuration(config,secret);session=FakeSession();sessions=[];captured=[]
    def factory(**kwargs):sessions.append(kwargs);return session
    def compose(configuration,clients):captured.append((configuration,clients));return 'synthetic-app'
    monkeypatch.setattr('proofpack.runtime.host.create_configured_app',compose)
    assert build_host_app(loaded,session_factory=factory)=='synthetic-app'
    assert sessions==[{'region_name':'us-east-1'}] and len(session.created)==3
    for service,kwargs in session.calls:
        assert kwargs['endpoint_url']==f'https://{service}.us-east-1.amazonaws.com'
        assert kwargs['config'].connect_timeout==2 and kwargs['config'].read_timeout==3 and kwargs['config'].retries['total_max_attempts']==1
        assert 'aws_access_key_id' not in kwargs and 'aws_secret_access_key' not in kwargs and 'aws_session_token' not in kwargs
    assert captured[0][0] is loaded.config and not any(client.closed for client in session.created)


@pytest.mark.parametrize('method',['env','shared-credentials-file','assume-role','container-role','none'])
def test_host_refuses_unapproved_credential_sources_before_creating_clients(host_files,method):
    config,secret,document,keys=host_files;loaded=load_configuration(config,secret);session=FakeSession(method=method)
    with pytest.raises(HostConfigurationError):build_host_app(loaded,session_factory=lambda **kwargs:session)
    assert session.created==[]


def test_partial_sdk_initialization_failure_closes_owned_clients_without_echo(host_files):
    config,secret,document,keys=host_files;session=FakeSession(fail='s3')
    with pytest.raises(HostConfigurationError) as error:build_host_app(load_configuration(config,secret),session_factory=lambda **kwargs:session)
    assert len(session.created)==1 and session.created[0].closed and 'provider-secret' not in str(error.value)


def test_factory_construction_failure_returns_all_client_ownership_to_cleanup(host_files,monkeypatch):
    config,secret,document,keys=host_files;session=FakeSession()
    def fail(*args):raise RuntimeError('do-not-echo-provider-secret')
    monkeypatch.setattr('proofpack.runtime.host.create_configured_app',fail)
    with pytest.raises(HostConfigurationError):build_host_app(load_configuration(config,secret),session_factory=lambda **kwargs:session)
    assert len(session.created)==3 and all(client.closed for client in session.created)


def test_serve_command_enforces_single_worker_and_private_logging(host_files,monkeypatch):
    config,secret,document,keys=host_files;session=FakeSession();calls=[]
    app=SimpleNamespace(state=SimpleNamespace(runtime_control=SimpleNamespace(instance_id='00000000-0000-4000-8000-000000000001')))
    monkeypatch.setattr('proofpack.runtime.host.create_configured_app',lambda *args:app)
    result=main(['serve','--config',str(config),'--secrets-file',str(secret)],session_factory=lambda **kwargs:session,
        run_server=lambda *args,**kwargs:calls.append((args,kwargs)))
    assert result==0 and calls==[((app,),{'host':'127.0.0.1','port':8080,'workers':1,'reload':False,'access_log':False,'proxy_headers':False})]


@pytest.mark.parametrize('arguments',[['--workers','2'],['--reload'],['--private-secret-value'],['--bind','localhost'],['--port','0']])
def test_serve_rejects_unbounded_or_invalid_cli_options_before_sdk(host_files,arguments,capsys):
    config,secret,document,keys=host_files;args=['serve','--config',str(config),'--secrets-file',str(secret),*arguments]
    try:result=main(args,session_factory=forbidden,run_server=forbidden)
    except SystemExit as error:result=error.code
    assert result==2 and 'private-secret-value' not in capsys.readouterr().err


@pytest.mark.parametrize('field,value',[('maintenance_enabled',1),('maintenance_poll_ms',249),('maintenance_poll_ms',60001),
    ('maintenance_page_size',0),('maintenance_page_size',26),('maintenance_steps_per_minute',0),
    ('maintenance_steps_per_minute',121),('maintenance_drain_ms',999),('maintenance_drain_ms',60001)])
def test_invalid_maintenance_limits_fail_closed_without_sdk(host_files,field,value):
    config,secret,document,keys=host_files
    document['limits'][field]=value;config.write_text(json.dumps(document),encoding='utf-8')
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)
