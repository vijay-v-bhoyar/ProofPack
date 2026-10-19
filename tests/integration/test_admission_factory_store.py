"""Owned local DynamoDB and real factory; provider identity/S3 remain intercepted."""
from dataclasses import replace
from threading import Event
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from test_composition import composition_case, identity
from test_access_lifecycle import repository_factory
from proofpack.evidence.privacy_admission import AdmissionConfiguration, AdmissionHeld, GATE, REGISTRY
from proofpack.auth.service import RUNTIME
from proofpack.runtime.composition import create_configured_app


def configured(case, **changes):
    repository,settings,clients,stub,clock = case
    bounds = AdmissionConfiguration(8,300000,60000,120000,3,'a'*64)
    return create_configured_app(replace(settings,metadata_admission=bounds,**changes),clients,clock_ms=clock)


def enroll(app):
    value = app.state.metadata_admission
    value.runtime.start()
    value.initialize('a'*64)  # Explicit synthetic setup, never automatic startup.
    return value


def test_actual_factory_absent_enrollment_is_not_new_install_authority(composition_case):
    repository,settings,clients,stub,clock = composition_case
    app = configured(composition_case); identity(stub)
    with pytest.raises(AdmissionHeld):
        with TestClient(app,base_url=settings.app_origin): pytest.fail('unenrolled startup succeeded')
    rows = repository.snapshot((GATE,REGISTRY,RUNTIME))
    assert rows[GATE] is rows[REGISTRY] is None
    assert rows[RUNTIME].data['inspection_enabled'] is False
    assert app.state.composition_status == 'failed'
    stub.assert_no_pending_responses()


def test_actual_http_and_readiness_are_registered_but_liveness_needs_no_store(composition_case,monkeypatch):
    repository,settings,clients,stub,clock = composition_case
    app = configured(composition_case); service = enroll(app); identity(stub)
    with TestClient(app,base_url=settings.app_origin) as client:
        assert client.get('/api/v1/me').status_code == 401
        assert client.get('/health/ready').status_code == 503
        assert repository.snapshot((REGISTRY,))[REGISTRY].data['active'] == {}
        with monkeypatch.context() as boundary:
            def forbidden(*args,**kwargs): pytest.fail('liveness accessed the store')
            boundary.setattr(service.repository,'snapshot',forbidden)
            for method in ('get','head'):
                response = getattr(client,method)('/health/live?code=PRIVATE')
                assert response.status_code == 200 and response.headers['cache-control'] == 'no-store'
                assert 'PRIVATE' not in response.text
    assert app.state.composition_status == 'closed'


def test_actual_held_gate_survives_a_successor_runtime_and_blocks_all_data_methods(composition_case):
    repository,settings,clients,stub,clock = composition_case
    first = configured(composition_case); service = enroll(first)
    service.hold(request_id=str(uuid4()),scope_sha256='b'*64)
    before = repository.snapshot((GATE,REGISTRY))
    successor = configured(composition_case); identity(stub)
    with TestClient(successor,base_url=settings.app_origin) as client:
        assert successor.state.runtime_control.handle.epoch == 2
        assert client.get('/health/live').status_code == 200
        assert client.head('/health/live').status_code == 200
        for method,path in (('get','/health/ready'),('post','/health/live'),('get','/api/v1/me'),('get','/')):
            assert getattr(client,method)(path).status_code == 503
    assert repository.snapshot((GATE,REGISTRY)) == before
    first.state.reference_service.close(); first.state.reference_service.registry.close()


def test_expired_prior_runtime_work_holds_successor_until_original_release(composition_case):
    repository,settings,clients,stub,clock = composition_case
    first = configured(composition_case); service = enroll(first)
    original = service.prepare(work_id=str(uuid4()),kind='http',lease_ms=500)
    service.admit(original); clock.value += 501
    successor = configured(composition_case); identity(stub)
    with TestClient(successor,base_url=settings.app_origin) as client:
        assert client.get('/api/v1/me').status_code == 503
        assert repository.snapshot((REGISTRY,))[REGISTRY].data['active']
        service.release(original)
        assert client.get('/api/v1/me').status_code == 401
    first.state.reference_service.close(); first.state.reference_service.registry.close()


def test_actual_maintenance_query_occurs_inside_the_shared_durable_registration(composition_case,monkeypatch):
    repository,settings,clients,stub,clock = composition_case
    app = configured(composition_case,maintenance_enabled=True); enroll(app); identity(stub)
    observed = Event(); service = app.state.metadata_admission
    original = service.repository.query
    def query(*args,**kwargs):
        active = repository.snapshot((REGISTRY,))[REGISTRY].data['active']
        assert any(value['kind'] == 'worker' for value in active.values())
        result = original(*args,**kwargs); observed.set(); return result
    monkeypatch.setattr(service.repository,'query',query)
    with TestClient(app,base_url=settings.app_origin) as client:
        assert observed.wait(3)
        assert client.get('/health/live').status_code == 200
    assert not app.state.maintenance_driver._thread.is_alive()
    assert repository.snapshot((REGISTRY,))[REGISTRY].data['active'] == {}


def test_actual_held_maintenance_cannot_query_an_ordinary_job(composition_case,monkeypatch):
    repository,settings,clients,stub,clock = composition_case
    app = configured(composition_case,maintenance_enabled=True); service = enroll(app)
    service.hold(request_id=str(uuid4()),scope_sha256='b'*64); identity(stub)
    def forbidden(*args,**kwargs): pytest.fail('held maintenance queried ordinary metadata')
    monkeypatch.setattr(service.repository,'query',forbidden)
    with TestClient(app,base_url=settings.app_origin) as client:
        assert app.state.maintenance_driver.poll_once() is False
        assert client.get('/health/live').status_code == 200
        assert client.get('/api/v1/me').status_code == 503
    assert not app.state.maintenance_driver._thread.is_alive()
    assert repository.snapshot((REGISTRY,))[REGISTRY].data['active'] == {}
