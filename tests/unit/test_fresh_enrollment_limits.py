"""Adverse first-install transitions; all role/approval/table identities are synthetic."""
from copy import deepcopy
from dataclasses import asdict,replace
import json

from botocore.exceptions import ReadTimeoutError
import pytest

from test_host import host_files
from test_fresh_enrollment import world,run,approve_candidate,OP
from proofpack.runtime import host
from proofpack.runtime.control import RUNTIME


@pytest.mark.parametrize('fault',['cursor','scanned','bool-count','wrong-type','partial-item'])
def test_incomplete_empty_scan_never_creates_any_seed_record(host_files,fault):
    w=world(host_files);original=w.client.scan
    def bad(**kwargs):
        result=original(**kwargs)
        if fault=='cursor':result['LastEvaluatedKey']={'pk':{'S':'hidden'},'sk':{'S':'next'}}
        elif fault=='scanned':result['ScannedCount']=1
        elif fault=='bool-count':result['Count']=False
        elif fault=='wrong-type':result['Items']=()
        else:result['Items']=[{}]
        return result
    w.client.scan=bad
    with pytest.raises(host.HostConfigurationError):run(w)
    assert w.client.items=={} and not any(n=='transact_write_items' for n,k in w.client.calls)


@pytest.mark.parametrize('fault',['creation-id','ttl','role','new-data'])
def test_changed_target_during_second_frame_cannot_commit(host_files,fault):
    w=world(host_files);approve_candidate(w,run(w));calls=[]
    real_identity=w.sts.get_caller_identity
    def changing():
        calls.append(True)
        if len(calls)==2:
            if fault=='creation-id':w.client.ids[w.loaded.config.state_table]='replacement-creation'
            elif fault=='ttl':w.client.describe_time_to_live=lambda **kw:{'TimeToLiveDescription':{'TimeToLiveStatus':'ENABLED'}}
            elif fault=='role':return {'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/OrdinaryApp/synthetic'}
            else:w.client.items[(w.loaded.config.events_table,'deployment#foreign','late')]={'pk':{'S':'deployment#foreign'},'sk':{'S':'late'}}
        return real_identity()
    w.sts.get_caller_identity=changing
    with pytest.raises(host.HostConfigurationError):run(w,commit=True)
    assert not any(n=='transact_write_items' for n,k in w.client.calls)


def test_unknown_postcommit_read_keeps_effect_and_exact_later_retry_never_repeats_it(host_files):
    w=world(host_files);approve_candidate(w,run(w));reads=[]
    def lose(kw,result):
        reads.append(True)
        if len(reads)==2:raise ReadTimeoutError(endpoint_url='synthetic-private-provider')
    w.client.after_get=lose
    with pytest.raises(host.HostConfigurationError):run(w,commit=True)
    assert len(w.client.items)==10
    w.client.after_get=None;w.clock[0]=301001
    assert run(w,commit=True)['status']=='ENROLLMENT_COMMITTED'
    assert len([1 for n,k in w.client.calls if n=='transact_write_items'])==1


def test_explicit_retry_never_reopens_held_admission_or_replaces_current_runtime(host_files):
    w=world(host_files);approve_candidate(w,run(w));run(w,commit=True)
    for (table,pk,sk),item in w.client.items.items():
        if sk=='metadata-maintenance-gate':
            item['revision']={'N':'2'};item['data']['M']['phase']={'S':'HELD'}
        elif sk==RUNTIME.resource:
            item['revision']={'N':'2'};item['data']['M']['runtime_epoch']={'N':'2'}
    before=deepcopy(w.client.items);w.clock[0]=301001
    result=run(w,commit=True)
    assert result['status']=='ENROLLMENT_COMMITTED' and result['authority']=='none'
    assert w.client.items==before and len([1 for n,k in w.client.calls if n=='transact_write_items'])==1


def test_partial_existing_enrollment_is_not_repaired(host_files):
    w=world(host_files);approve_candidate(w,run(w));run(w,commit=True)
    key=next(k for k in w.client.items if k[2]=='anchor-head');del w.client.items[key]
    before=deepcopy(w.client.items)
    with pytest.raises(host.HostConfigurationError):run(w,commit=True)
    assert w.client.items==before and len([1 for n,k in w.client.calls if n=='transact_write_items'])==1


def test_missing_key_race_prevents_partial_bootstrap_transaction(host_files):
    w=world(host_files);approve_candidate(w,run(w))
    def racing():
        item={'pk':{'S':'deployment#'+w.loaded.config.auth.deployment},'sk':{'S':RUNTIME.resource},'revision':{'N':'1'},'data':{'M':{'foreign':{'BOOL':True}}}}
        w.client.items[w.client.identity(w.loaded.config.state_table,item)]=item
    w.client.before_commit=racing
    with pytest.raises(host.HostConfigurationError):run(w,commit=True)
    assert len(w.client.items)==1 and not any(k[2]=='anchor-root' for k in w.client.items)


@pytest.mark.parametrize('fault',['deadline','backwards-tick','backwards-wall','changed-config'])
def test_precredential_guard_preserves_original_configuration_and_allowance(host_files,monkeypatch,fault):
    w=world(host_files);approve_candidate(w,run(w));w.discovery.clear();w.closed.clear()
    ticks=iter([100,100+w.loaded.config.metadata_admission.http_lease_ms*1000000] if fault=='deadline' else [100,99] if fault=='backwards-tick' else [100,101])
    if fault=='changed-config':
        original=w.mod.verify_installation
        def changed(*args,**kwargs):
            result=original(*args,**kwargs);object.__setattr__(w.loaded.config,'controls_sha256','0'*64);return result
        monkeypatch.setattr(w.mod,'verify_installation',changed)
    walls=iter([1001,1000]) if fault=='backwards-wall' else None
    with pytest.raises(host.HostConfigurationError):
        w.mod.run_enrollment(w.loaded,w.intent,commit=True,session_factory=w.Session,
            tick_ns=lambda:next(ticks),clock_ms=(lambda:next(walls)) if walls else lambda:1001)
    assert w.discovery==[] and w.closed==[] and w.client.items=={}


@pytest.mark.parametrize('change',[{'created_at_ms':True},{'expires_at_ms':301001},{'operation_id':OP.upper().replace('11','AA')},
    {'role_arn':'arn:aws:iam::000000000000:role/path/Name'},{'instance_id':OP},{'extra':True}])
def test_closed_private_packet_rejects_coercion_expansion_and_changed_identity(host_files,tmp_path,change):
    w=world(host_files);packet=tmp_path/'enrollment.json';packet.write_text(json.dumps(asdict(w.intent)|change))
    with pytest.raises(host.HostConfigurationError):host.load_enrollment(packet)
    assert w.discovery==[] and w.client.items=={}


def test_private_cli_prepare_and_commit_use_same_intent_without_server_or_secret_echo(host_files,tmp_path,monkeypatch,capsys):
    w=world(host_files);packet=tmp_path/'enrollment.json';packet.write_text(json.dumps(asdict(w.intent)))
    monkeypatch.setattr(w.mod,'time_ns',lambda:1001000000)
    commands=['--config',str(w.path),'--secrets-file',str(w.secret),'--enrollment-file',str(packet)]
    server=[]
    assert host.main(['prepare-enrollment',*commands],session_factory=w.Session,run_server=lambda *a,**k:server.append(True))==0
    output=capsys.readouterr();assert not output.err;candidate=json.loads(output.out)
    approve_candidate(w,candidate)
    assert host.main(['enroll',*commands],session_factory=w.Session,run_server=lambda *a,**k:server.append(True))==0
    output=capsys.readouterr();assert not output.err and json.loads(output.out)['status']=='ENROLLMENT_COMMITTED'
    assert server==[]
    for value in (str(w.path),str(w.secret),str(packet),w.intent.role_arn,w.document['auth']['notice_text']):assert value not in output.out


def test_cleanup_failure_withholds_committed_output_and_never_rolls_back_the_effect(host_files,monkeypatch):
    w=world(host_files);approve_candidate(w,run(w));closed=[]
    def fail():closed.append('s3');raise RuntimeError('do-not-echo-private-material')
    w.s3.close=fail
    with pytest.raises(host.HostConfigurationError) as error:run(w,commit=True)
    assert len(w.client.items)==10 and closed==['s3'] and 'private-material' not in str(error.value)


def test_changed_initial_configuration_cannot_be_used_by_an_ordinary_configured_factory(host_files):
    w=world(host_files);from proofpack.runtime.composition import create_configured_app,ApplicationClients
    with pytest.raises(ValueError,match='initial-release application configuration'):
        create_configured_app(replace(w.loaded.config,maintenance_poll_ms=1001),ApplicationClients(w.client,w.s3,w.sts))
    assert w.client.calls==[]


def test_private_prepare_commit_then_ordinary_serve_lifespan_preserves_disabled_state(host_files,monkeypatch,capsys):
    from fastapi.testclient import TestClient
    from proofpack.evidence.repository import Key
    from proofpack.runtime.control import DATA
    from restore_consumer_model import install_model_transactions
    w=world(host_files);install_model_transactions(w.client)
    approve_candidate(w,run(w));run(w,commit=True);w.closed.clear()
    # Enrollment role is replaced by the ordinary host role for this distinct
    # synthetic command. No prepared/protected records are injected by the test.
    w.sts.get_caller_identity=lambda:{'Account':'000000000000','Arn':'arn:aws:sts::000000000000:assumed-role/ProofPackApp/synthetic-session'}
    entered=[]
    def server(app,**kwargs):
        assert kwargs['workers']==1 and kwargs['reload'] is False
        with TestClient(app) as http:
            assert app.state.composition_status=='started'
            runtime=app.state.runtime_control
            assert runtime.handle.instance_id!=w.intent.instance_id
            repository=app.state.access_service.repository
            rows=repository.snapshot((RUNTIME,DATA))
            assert rows[RUNTIME].data['runtime_epoch']==2 and rows[DATA].data['epoch']==2
            assert rows[RUNTIME].data['inspection_enabled'] is False
            assert http.get('/health/live').status_code==200
            assert http.get('/health/ready').status_code==503
            entered.append(runtime.handle.instance_id)
        assert app.state.composition_status=='closed'
    assert host.main(['serve','--config',str(w.path),'--secrets-file',str(w.secret)],session_factory=w.Session,run_server=server)==0
    output=capsys.readouterr();reference=json.loads(output.err)
    assert output.out=='' and reference['instance_id']==entered[0]
    assert sorted(w.closed)==['dynamodb','s3','sts']
