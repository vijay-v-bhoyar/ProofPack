"""Private host command with synthetic role/creation/release identity only."""
from copy import deepcopy
from dataclasses import asdict
import json
from types import SimpleNamespace
from uuid import uuid4
import pytest

import proofpack.runtime.host as host
from test_host import host_files, forbidden
from restore_consumer_model import sdk_world
from proofpack.auth.service import AccessService
from proofpack.runtime.control import RuntimeControl


def configured(host_files):
    path,secret,document,keys=host_files
    repo,fence,client,ids=sdk_world(deployment=document['deployment'],
        artifact_sha256=document['application']['artifact_sha256'])
    document['aws']['state_table']=repo.tables['state'];document['aws']['events_table']=repo.tables['events']
    cfg=fence.config
    document['restore_fence']={'journal_table':cfg.journal_table,'journal_arn':cfg.journal_arn,
        'genesis_sha256':cfg.genesis_sha256,'checkpoint':asdict(cfg.checkpoint),'release_sha256':cfg.release_sha256,
        'target_table_ids':dict(cfg.target_table_ids),'max_check_ms':cfg.max_check_ms}
    path.write_text(json.dumps(document),encoding='utf-8');loaded=host.load_configuration(path,secret)
    access=AccessService(repo,loaded.config.auth,clock_ms=lambda:1000)
    original=RuntimeControl(access,instance_id=str(uuid4()),artifact_sha256=loaded.config.artifact_sha256,
        controls_sha256=loaded.config.controls_sha256,environment=loaded.config.environment)
    original.start();closed=[];made=[];session_calls=[]
    class Session:
        def __init__(self,method='iam-role',fail=None,bad_service=None,close_failure=None):
            self.method=method;self.fail=fail;self.bad_service=bad_service;self.close_failure=close_failure
        def get_credentials(self):return SimpleNamespace(method=self.method)
        def client(self,service,**kwargs):
            session_calls.append((service,kwargs))
            if service==self.fail:raise RuntimeError('private-provider-diagnostic-never-print')
            value=client if service=='dynamodb' else SimpleNamespace()
            value.meta=SimpleNamespace(service_model=SimpleNamespace(service_name=service),
                region_name='us-west-2' if service==self.bad_service else 'us-east-1',
                endpoint_url=kwargs['endpoint_url'],config=kwargs['config'])
            if service=='sts':value.get_caller_identity=lambda:{'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/synthetic/readback'}
            def close(service=service):
                closed.append(service)
                if service==self.close_failure:raise RuntimeError('private-close-diagnostic-never-print')
            value.close=close;made.append(service);return value
    return loaded,original,client,ids,Session,closed,made,session_calls


def call(loaded,original,session,**kwargs):
    return host.read_host_startup(loaded,instance_id=original.instance_id,
        configuration_sha256=loaded.configuration_sha256,session_factory=lambda **kw:session,**kwargs)


def test_private_readback_validates_original_document_and_exact_store_without_app_or_mutation(host_files,monkeypatch):
    loaded,original,client,ids,Session,closed,made,session_calls=configured(host_files)
    before=deepcopy(client.items);client.calls.clear();monkeypatch.setattr(host,'create_configured_app',forbidden)
    result=call(loaded,original,Session())
    assert result['status']=='STARTUP_OBSERVED' and result['configuration_sha256']==loaded.configuration_sha256
    assert result['instance_id']==original.instance_id and result['data_epoch']==result['startup_data_epoch']==1
    assert result['read_only'] is True and result['authority']=='none'
    assert result['readiness_approved'] is result['inspection_enablement_granted'] is result['request_fulfilled'] is False
    assert closed==made==['dynamodb','s3','sts'] and client.items==before
    assert not any(name in {'transact_write_items','query'} for name,_ in client.calls)
    assert 'private-' not in json.dumps(result) and 'notice' not in json.dumps(result) and 'roles' not in json.dumps(result)
    for name,kwargs in session_calls:
        assert kwargs['endpoint_url']=='https://'+name+'.us-east-1.amazonaws.com'
        assert kwargs['config'].retries['total_max_attempts']==1


@pytest.mark.parametrize('instance,digest',[('bad','a'*64),
    ('00000000-0000-4000-8000-000000000099','bad'),
    ('00000000-0000-4000-8000-000000000099','f'*64)],
    ids=['bad-instance','bad-digest','mismatched-digest'])
def test_original_reference_mismatch_denied_before_credential_discovery(host_files,instance,digest):
    loaded=host.load_configuration(*host_files[:2])
    with pytest.raises(host.HostConfigurationError):
        host.read_host_startup(loaded,instance_id=instance,configuration_sha256=digest,session_factory=forbidden)


@pytest.mark.parametrize('fault',['credentials','partial','transport','identity','release','missing-marker','close'])
def test_all_owned_clients_closed_once_and_no_success_on_held_readback(host_files,fault):
    loaded,original,client,ids,Session,closed,made,calls=configured(host_files)
    session=Session(method='env' if fault=='credentials' else 'iam-role',fail='s3' if fault=='partial' else None,
        bad_service='dynamodb' if fault=='transport' else None,close_failure='s3' if fault=='close' else None)
    if fault=='release':client.items.pop(ids[2])
    if fault=='missing-marker':
        ident=next(key for key in client.items if key[2]=='runtime-start#'+original.instance_id);client.items.pop(ident)
    if fault=='identity':
        real=session.client
        def wrong(service,**kwargs):
            value=real(service,**kwargs)
            if service=='sts':value.get_caller_identity=lambda:{'Account':'111111111111','Arn':'private-provider-diagnostic-never-print'}
            return value
        session.client=wrong
    before=deepcopy(client.items)
    with pytest.raises(host.HostConfigurationError):call(loaded,original,session)
    assert closed==made and len(closed)==len(set(closed)) and client.items==before


@pytest.mark.parametrize('fault',['backwards','deadline'])
def test_total_private_operation_budget_holds_before_output_and_does_not_renew(host_files,fault):
    loaded,original,client,ids,Session,closed,made,calls=configured(host_files)
    values=iter([100,99] if fault=='backwards' else [100,100+loaded.config.metadata_admission.http_lease_ms*1000000])
    with pytest.raises(host.HostConfigurationError):call(loaded,original,Session(),tick_ns=lambda:next(values))
    assert closed==made


def test_readback_cli_uses_original_reference_and_never_starts_server(host_files,capsys,monkeypatch):
    loaded,original,client,ids,Session,closed,made,calls=configured(host_files)
    monkeypatch.setattr(host,'create_configured_app',forbidden)
    code=host.main(['read-startup','--config',str(host_files[0]),'--secrets-file',str(host_files[1]),
        '--instance-id',original.instance_id,'--configuration-sha256',loaded.configuration_sha256],
        session_factory=lambda **kw:Session(),run_server=forbidden)
    captured=capsys.readouterr();assert code==0 and not captured.err
    result=json.loads(captured.out);assert result['status']=='STARTUP_OBSERVED' and result['authority']=='none'


def test_serve_reference_precedes_server_and_contains_no_secret_or_readiness_claim(host_files,capsys,monkeypatch):
    loaded=host.load_configuration(*host_files[:2]);ident=str(uuid4());fake=SimpleNamespace(state=SimpleNamespace(runtime_control=SimpleNamespace(instance_id=ident)))
    monkeypatch.setattr(host,'build_host_app',lambda *a,**k:fake)
    entered=[]
    def server(app,**kwargs):
        reference=json.loads(capsys.readouterr().err)
        assert reference=={'status':'STARTUP_REFERENCE','scope':'attempt_identity_only','instance_id':ident,
            'configuration_sha256':loaded.configuration_sha256,'configured_artifact_sha256':loaded.config.artifact_sha256}
        entered.append(app)
    assert host.main(['serve','--config',str(host_files[0]),'--secrets-file',str(host_files[1])],
        session_factory=forbidden,run_server=server)==0
    assert entered==[fake]
