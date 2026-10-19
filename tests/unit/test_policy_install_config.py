"""Configured policy installation is explicit and validated before provider use."""
import json
import pytest
from test_host import host_files,preparation_settings,forbidden
from proofpack.runtime.host import load_configuration,main,HostConfigurationError


def installation_settings(document):
    preparation_settings(document)
    document['policy_qualification']={'jobs':{'jobs_per_minute':20,'step_attempts_per_minute':120,'reads_per_minute':120,
        'lifetime_ms':3600000,'lease_ms':15000,'max_steps':3000},'max_reserved_cases':2000,'golden_case_ms':5000}
    document['policy_activation']={'writes_per_minute':20,'reads_per_minute':120,'review_window_ms':60000,'max_qualification_rows':80}


def test_explicit_paired_policy_installation_checks_without_provider_io(host_files):
    config,secret,document,_=host_files
    installation_settings(document);config.write_text(json.dumps(document),encoding='utf-8')
    assert main(['check-config','--config',str(config),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==0
    loaded=load_configuration(config,secret).config
    assert loaded.policy_qualification.max_reserved_cases==2000
    assert loaded.policy_qualification.jobs.max_steps==3000
    assert len(loaded.policy_activation.qualification_registry_sha256)==64
    assert loaded.policy_activation.review_window_ms==60000


@pytest.mark.parametrize('fault',['missing_qualification','missing_activation','missing_preparation','missing_suite','missing_vision',
    'too_few_cases','too_few_steps','software_window_exceeds_lease','golden_window_exceeds_lease','coerced_bound','client_registry_override'])
def test_bad_policy_installation_is_rejected_without_provider_io(host_files,fault):
    config,secret,document,_=host_files;installation_settings(document)
    if fault.startswith('missing_'):document.pop({'missing_qualification':'policy_qualification','missing_activation':'policy_activation',
        'missing_preparation':'qualification_preparation','missing_suite':'policy_contract_suite','missing_vision':'vision_replay'}[fault])
    elif fault=='too_few_cases':document['policy_qualification']['max_reserved_cases']=181
    elif fault=='too_few_steps':document['policy_qualification']['jobs']['max_steps']=12
    elif fault=='software_window_exceeds_lease':document['policy_qualification']['jobs']['lease_ms']=5000
    elif fault=='golden_window_exceeds_lease':document['policy_qualification']['golden_case_ms']=15001
    elif fault=='coerced_bound':document['policy_qualification']['max_reserved_cases']='2000'
    else:document['policy_activation']['qualification_registry_sha256']='a'*64
    config.write_text(json.dumps(document),encoding='utf-8')
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)
    assert main(['check-config','--config',str(config),'--secrets-file',str(secret)],session_factory=forbidden,run_server=forbidden)==2
