"""Mandatory configured installation admission before SDK discovery and startup writes."""
from dataclasses import replace
import json

import pytest
from fastapi.testclient import TestClient

from test_host import host_files
from proofpack.runtime import host,composition
from proofpack.runtime.installation import InstallationConfig,InstallationUnavailable
from proofpack.runtime.public_web import FrozenWeb,PublicAsset
from restore_consumer_model import factory_world


@pytest.mark.parametrize('action',['serve','readback'])
def test_invalid_local_archive_cannot_discover_credentials(host_files,tmp_path,action):
    loaded=host.load_configuration(*host_files[:2]);calls=[]
    loaded=replace(loaded,config=replace(loaded.config,installation=InstallationConfig(str(tmp_path/'missing.whl'))))
    def discovery(**kwargs):calls.append(kwargs);raise AssertionError('credential discovery forbidden')
    with pytest.raises(host.HostConfigurationError):
        if action=='serve':host.build_host_app(loaded,session_factory=discovery)
        else:host.read_host_startup(loaded,instance_id='00000000-0000-4000-8000-000000000001',
            configuration_sha256=loaded.configuration_sha256,session_factory=discovery)
    assert calls==[]


def test_check_config_does_not_open_wheel_or_discover_credentials(host_files,tmp_path,monkeypatch,capsys):
    path,secrets,document,_=host_files
    document['installation']['wheel_path']=str(tmp_path/'not-present.whl');path.write_text(json.dumps(document))
    called=[]
    def forbidden(*args,**kwargs):called.append('entered');raise AssertionError('no artifact or SDK IO')
    monkeypatch.setattr(host,'verify_installation',forbidden)
    assert host.main(['check-config','--config',str(path),'--secrets-file',str(secrets)],session_factory=forbidden)==0
    assert called==[] and json.loads(capsys.readouterr().out)['scope']=='syntax_and_service_bounds_only'


@pytest.mark.parametrize('change',[None,{}, {'wheel_path':'relative.whl'}, {'wheel_path':'https://example.test/p.whl'},
    {'wheel_path':True},{'wheel_path':'C:relative.whl'},{'wheel_path':'C:/approved.whl','bypass':True}])
def test_closed_host_input_requires_an_explicit_local_artifact(host_files,change):
    path,secrets,document,_=host_files
    if change is None:document.pop('installation')
    else:document['installation']=change
    path.write_text(json.dumps(document))
    with pytest.raises(host.HostConfigurationError):host.load_configuration(path,secrets)


def test_programmatic_non_test_configuration_cannot_omit_installation(host_files):
    config=host.load_configuration(*host_files[:2]).config
    for value in (None,{},str(config.installation.wheel_path)):
        with pytest.raises(ValueError):replace(config,installation=value)


@pytest.mark.parametrize('fault',['disk-digest','served-bytes','missing-snapshot'])
def test_configured_lifespan_checks_actual_installation_before_target_or_runtime_writes(host_files,monkeypatch,fault):
    app,config,clients,identities,closed=factory_world(host_files)
    repository=app.state.access_service.repository
    from copy import deepcopy
    before=deepcopy(clients.dynamodb.items);entered=[]
    def forbidden(*args,**kwargs):entered.append('target-or-runtime');raise AssertionError('startup writes forbidden')
    monkeypatch.setattr(composition,'runtime_proof',forbidden)
    monkeypatch.setattr(composition,'_target',forbidden)
    if fault=='disk-digest':
        # This immutable configured value must disagree with the actual archive.
        object.__setattr__(config,'artifact_sha256','0'*64)
    elif fault=='served-bytes':
        app.state.public_web=FrozenWeb(tuple(PublicAsset(a.path,a.media_type,a.content+b' ') for a in app.state.public_web.assets))
    else:app.state.public_web=None
    with pytest.raises((InstallationUnavailable,composition.ConfiguredStartupUnavailable)):
        with TestClient(app):pass
    assert entered==[] and clients.dynamodb.items==before
    assert sorted(closed)==['dynamodb','s3','sts'] and app.state.composition_status=='failed'


def test_installation_io_keeps_the_configured_resource_ticket_until_exit(host_files,monkeypatch):
    app,config,clients,identities,closed=factory_world(host_files)
    owner=app.state.resource_owner;observed=[]
    original=composition.verify_installation
    def bounded(*args,**kwargs):
        observed.append(not owner.wait_for_drain(0))
        original(*args,**kwargs)
        assert not owner.wait_for_drain(0) and closed==[]
        raise InstallationUnavailable('stop after verifying actual synthetic archive')
    monkeypatch.setattr(composition,'verify_installation',bounded)
    with pytest.raises(InstallationUnavailable):
        with TestClient(app):pass
    assert observed==[True] and owner.wait_for_drain(0)
    assert sorted(closed)==['dynamodb','s3','sts']
