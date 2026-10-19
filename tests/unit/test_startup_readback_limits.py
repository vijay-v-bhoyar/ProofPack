"""Independent no-discovery, disclosure and final-output checks for HS."""
import json
import pytest

import proofpack.runtime.host as host
from test_host import host_files
from test_host_startup_readback import configured, call


@pytest.mark.parametrize('fault',['instance','document'])
def test_bad_original_reference_never_enters_credential_discovery(host_files,fault):
    loaded,original,client,ids,Session,closed,made,calls=configured(host_files);discovery=[]
    def spy(**kwargs):
        discovery.append(kwargs)
        raise RuntimeError('discovery-spy-must-not-be-called')
    with pytest.raises(host.HostConfigurationError):
        host.read_host_startup(loaded,instance_id='bad' if fault=='instance' else original.instance_id,
            configuration_sha256='f'*64 if fault=='document' else loaded.configuration_sha256,session_factory=spy)
    assert discovery==[] and made==closed==[]


@pytest.mark.parametrize('extra',[['--repair'],['--profile','private-profile-value'],
    ['--endpoint-url','http://127.0.0.1:8001'],['--workers','2'],['--bind','127.0.0.1']],
    ids=['repair','profile','endpoint','workers','bind'])
def test_readback_rejects_expansion_options_without_sdk_or_argument_echo(host_files,extra,capsys):
    loaded=host.load_configuration(*host_files[:2]);entered=[]
    def spy(*args,**kwargs):entered.append((args,kwargs))
    with pytest.raises(SystemExit) as error:
        host.main(['read-startup','--config',str(host_files[0]),'--secrets-file',str(host_files[1]),
            '--instance-id','00000000-0000-4000-8000-000000000099',
            '--configuration-sha256',loaded.configuration_sha256,*extra],session_factory=spy,run_server=spy)
    output=capsys.readouterr()
    assert error.value.code==2 and entered==[] and not output.out
    assert 'private-profile-value' not in output.err and '127.0.0.1:8001' not in output.err


def test_host_observation_has_only_closed_metadata_fields(host_files):
    loaded,original,client,ids,Session,closed,made,calls=configured(host_files)
    result=call(loaded,original,Session())
    assert set(result)=={'instance_id','runtime_epoch','control_version','data_epoch','startup_data_epoch',
        'runtime_state_version','data_state_version','marker_state_version','observed_at_ms',
        'restore_generation_sha256','read_only','authority','status','configuration_sha256',
        'readiness_approved','inspection_enablement_granted','request_fulfilled'}
    assert closed==made


def test_deadline_reached_during_cleanup_withholds_otherwise_valid_observation(host_files):
    loaded,original,client,ids,Session,closed,made,calls=configured(host_files)
    now=[0];session=Session();create=session.client
    def wrapping(service,**kwargs):
        value=create(service,**kwargs);close=value.close
        def finish():
            close()
            if service=='sts':now[0]=loaded.config.metadata_admission.http_lease_ms*1000000
        value.close=finish;return value
    session.client=wrapping
    with pytest.raises(host.HostConfigurationError):call(loaded,original,session,tick_ns=lambda:now[0])
    assert closed==made==['dynamodb','s3','sts']


def test_cleanup_failure_cli_has_no_partial_success_or_private_diagnostics(host_files,capsys):
    loaded,original,client,ids,Session,closed,made,calls=configured(host_files)
    code=host.main(['read-startup','--config',str(host_files[0]),'--secrets-file',str(host_files[1]),
        '--instance-id',original.instance_id,'--configuration-sha256',loaded.configuration_sha256],
        session_factory=lambda **kw:Session(close_failure='s3'))
    output=capsys.readouterr()
    assert code==2 and not output.out and 'No readiness or release approval' in output.err
    assert 'private-close' not in output.err and closed==made


def test_release_revocation_during_observation_is_not_converted_into_success(host_files):
    loaded,original,client,ids,Session,closed,made,calls=configured(host_files);touched=[]
    def revoke(request,response):
        if any(value['Get']['Key']['sk']['S']=='runtime' for value in request['TransactItems']):
            touched.append(True);client.items.pop(ids[2],None)
    client.after_get=revoke
    with pytest.raises(host.HostConfigurationError):call(loaded,original,Session())
    assert touched and closed==made
