"""Explicit handoff host policy, without credential discovery or server startup."""
import json
from dataclasses import asdict
import pytest
from test_host import host_files, forbidden
from proofpack.runtime.host import load_configuration, HostConfigurationError
from proofpack.stations.handoffs import HandoffLimits


def test_host_accepts_explicit_handoff_policy_without_sdk_or_server_io(host_files,monkeypatch):
    config,secret,document,_=host_files
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    assert load_configuration(config,secret).config.handoffs is None
    policy=HandoffLimits(4,3600000,60,5000,20,30*86400000)
    document['handoffs']=asdict(policy);config.write_text(json.dumps(document),encoding='utf-8')
    loaded=load_configuration(config,secret)
    assert loaded.config.handoffs==policy


@pytest.mark.parametrize('change',[{'max_requests':True},{'max_requests':17},{'lifetime_ms':3600001},
    {'metadata_retention_ms':1000},{'read_window_ms':5001},{'page_size':21},{'send_email':True}])
def test_invalid_handoff_host_policy_is_rejected_before_io(host_files,monkeypatch,change):
    config,secret,document,_=host_files
    monkeypatch.setattr('boto3.Session',forbidden);monkeypatch.setattr('uvicorn.run',forbidden)
    document['handoffs']={**asdict(HandoffLimits(4,3600000,60,5000,20,30*86400000)),**change}
    config.write_text(json.dumps(document),encoding='utf-8')
    with pytest.raises(HostConfigurationError):load_configuration(config,secret)
