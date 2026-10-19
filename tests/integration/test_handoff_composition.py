"""Configured construction only; provider identity is intercepted, not AWS proof."""
from dataclasses import replace
from fastapi.testclient import TestClient
import pytest
from test_composition import composition_case, identity
from test_access_lifecycle import repository_factory
from proofpack.runtime.composition import create_configured_app
from proofpack.runtime.control import RUNTIME
from proofpack.stations.handoffs import HandoffLimits, InspectionHandoffs


def test_configured_factory_installs_exact_shared_handoff_service_without_enabling_inspections(composition_case):
    repository,config,clients,stub,clock=composition_case
    limits=HandoffLimits(4,3600000,60,5000,20,30*86400000)
    installed=replace(config,handoffs=limits)
    identity(stub);app=create_configured_app(installed,clients,clock_ms=clock)
    with TestClient(app,base_url='https://proofpack.test'):
        service=app.state.handoff_service
        assert type(service) is InspectionHandoffs and service.limits==limits
        assert service.stations is app.state.station_service and service.access is app.state.access_service
        assert service.runtime is app.state.runtime_control and service.repository is app.state.access_service.repository
        assert service.runtime.matches(service.repository.snapshot((RUNTIME,))[RUNTIME])
        assert not service.repository.snapshot((RUNTIME,))[RUNTIME].data['inspection_enabled']
    assert app.state.composition_status=='closed'


def test_missing_handoff_configuration_leaves_feature_unavailable(composition_case):
    _,config,clients,stub,clock=composition_case
    assert config.handoffs is None
    identity(stub);app=create_configured_app(config,clients,clock_ms=clock)
    with TestClient(app,base_url='https://proofpack.test'):
        assert app.state.handoff_service is None


def test_configuration_rejects_an_untyped_handoff_policy_before_factory_io(composition_case):
    config=composition_case[1]
    with pytest.raises(ValueError):replace(config,handoffs={'max_requests':4})
