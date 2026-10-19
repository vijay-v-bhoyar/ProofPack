"""Strict explicit host policy; no SDK clients, provider or deployment acceptance."""
import json
from dataclasses import asdict
import pytest
from test_host import host_files,forbidden
from proofpack.runtime.host import load_configuration,HostConfigurationError
from proofpack.evidence.owner_metadata import OwnerMetadataLimits


def settings(document):
    document['metadata_admission']={'max_active':8,'max_lease_ms':20000,'http_lease_ms':20000,
        'worker_lease_ms':15000,'attempts':3,'enrollment_sha256':'c'*64}
    document['owner_metadata']=asdict(OwnerMetadataLimits(10,20,100,20000))


def test_owner_host_policy_is_explicit_typed_and_has_no_client_or_server_io(host_files,monkeypatch):
    config,secret,document,_=host_files
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    assert load_configuration(config,secret).config.owner_metadata is None
    settings(document);config.write_text(json.dumps(document),encoding='utf-8')
    assert load_configuration(config,secret).config.owner_metadata==OwnerMetadataLimits(10,20,100,20000)


@pytest.mark.parametrize('fault',['no_admission','lease','bool','unknown','scope','timeout','reads','writes'])
def test_owner_host_policy_denies_unsupported_or_unpaired_config_before_io(host_files,monkeypatch,fault):
    config,secret,document,_=host_files;settings(document)
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    if fault=='no_admission':document.pop('metadata_admission')
    elif fault=='lease':document['metadata_admission']['http_lease_ms']=19999
    else:
        key,value={'bool':('max_inspections',True),'unknown':('allow_cleanup',True),'scope':('max_inspections',65),
            'timeout':('operation_timeout_ms',20001),'reads':('reads_per_minute',1001),'writes':('writes_per_minute',101)}[fault]
        document['owner_metadata'][key]=value
    config.write_text(json.dumps(document),encoding='utf-8')
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)
