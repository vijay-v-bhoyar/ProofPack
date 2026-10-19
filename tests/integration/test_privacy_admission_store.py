"""Local durable bookkeeping only; no ASGI coverage or actual dead-host reconciliation."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest

from test_access_lifecycle import world, repository_factory
from proofpack.auth.service import RUNTIME
from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionLimits, AdmissionHeld, GATE, REGISTRY
from proofpack.evidence.repository import StoreConflict, StoreUnavailable
from proofpack.runtime.control import RuntimeControl
from proofpack.evidence.privacy_http import MetadataAdmissionBoundary
from proofpack.evidence.privacy_workers import AdmittedWorker
from proofpack.app import create_app
from proofpack.auth.http import COOKIE
from fastapi.testclient import TestClient
from test_maintenance import make_driver, erasure_case, publication_case, frame_read_case, reference_case
from test_erasure import commit, list_page


def runtime(world):
    value = RuntimeControl(world[0], instance_id=str(uuid4()), artifact_sha256='b'*64,
                           controls_sha256='c'*64, environment='test')
    value.start()
    return value


def setup(world, capacity=3):
    rt = runtime(world)
    service = PersistentAdmission(rt, limits=AdmissionLimits(capacity, 1000), clock_ms=world[2])
    service.initialize('a'*64)
    return service, rt


def work(service): return service.prepare(work_id=str(uuid4()), kind='worker', lease_ms=500)


def test_actual_hold_and_release_return_private_conditional_drain_rows(world):
    service, rt = setup(world); item = work(service); service.admit(item)
    request = str(uuid4()); service.hold(request_id=request, scope_sha256='c'*64)
    with pytest.raises(AdmissionHeld): service.drained(request_id=request, scope_sha256='c'*64)
    service.release(item)
    proof = service.drained(request_id=request, scope_sha256='c'*64)
    assert {row.key for row in service.assert_drained(proof)} == {GATE, REGISTRY, RUNTIME}
    assert rt.repository.snapshot((REGISTRY,))[REGISTRY].data['active'] == {}


def test_actual_conditional_capacity_cannot_admit_two_concurrent_workers(world):
    service, rt = setup(world, capacity=1); items = (work(service), work(service)); barrier = Barrier(2)
    def admit(item):
        barrier.wait(timeout=5)
        try: service.admit(item); return item
        except (AdmissionHeld, StoreConflict): return None
    with ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(admit, items))
    accepted = [item for item in results if item is not None]
    assert len(accepted) == 1 and len(rt.repository.snapshot((REGISTRY,))[REGISTRY].data['active']) == 1
    service.release(accepted[0])


def test_actual_gate_change_fences_prepared_registry_write(world, monkeypatch):
    service, rt = setup(world); item = work(service); original = rt.repository.transact; injected = False
    request = str(uuid4())
    def before(writes, checks=()):
        nonlocal injected
        if not injected and any(value.key == REGISTRY for value in writes):
            injected = True
            service.hold(request_id=request, scope_sha256='c'*64)
        return original(writes, checks)
    monkeypatch.setattr(rt.repository, 'transact', before)
    with pytest.raises((AdmissionHeld, StoreConflict)): service.admit(item)
    assert injected
    service.assert_drained(service.drained(request_id=request, scope_sha256='c'*64))


def test_actual_supersession_and_expiry_do_not_erase_old_work(world):
    service, old = setup(world); item = work(service); service.admit(item)
    request = str(uuid4()); service.hold(request_id=request, scope_sha256='c'*64)
    world[2].value += 2000
    current = runtime(world)
    successor = PersistentAdmission(current, limits=AdmissionLimits(3, 1000), clock_ms=world[2])
    successor.initialize('a'*64)
    with pytest.raises(AdmissionHeld): successor.drained(request_id=request, scope_sha256='c'*64)
    with pytest.raises(AdmissionHeld): successor.release(item)
    assert service.release(item)
    successor.assert_drained(successor.drained(request_id=request, scope_sha256='c'*64))


def test_actual_committed_admission_with_lost_reply_retains_original_deadline(world, monkeypatch):
    service, rt = setup(world); item = work(service); original = rt.repository.transact; injected = False
    def lost(writes, checks=()):
        nonlocal injected
        result = original(writes, checks)
        if not injected and any(value.key == REGISTRY for value in writes):
            injected = True; raise StoreUnavailable('synthetic lost transaction response')
        return result
    monkeypatch.setattr(rt.repository, 'transact', lost)
    assert service.admit(item) == item
    saved = rt.repository.snapshot((REGISTRY,))[REGISTRY].data['active'][item.work_id]
    assert int(saved['issued_at_ms']) == item.issued_at_ms and int(saved['expires_at_ms']) == item.expires_at_ms
    service.release(item)


def test_actual_authenticated_http_is_registered_and_held_without_identity_disclosure(world):
    service, rt = setup(world)
    app = create_app(access_service=world[0], app_origin='https://proofpack.test', runtime_control=rt)
    boundary = MetadataAdmissionBoundary(app, admission=service, lease_ms=500, attempts=3)
    with TestClient(boundary, base_url='https://proofpack.test') as client:
        client.cookies.set(COOKIE, world[4].cookie)
        response = client.get('/api/v1/me')
        assert response.status_code == 200 and response.json()['id'] == world[3]
        assert rt.repository.snapshot((REGISTRY,))[REGISTRY].data['active'] == {}
        service.hold(request_id=str(uuid4()), scope_sha256='c'*64)
        response = client.get('/api/v1/me')
        assert response.status_code == 503 and world[3] not in response.text


@pytest.fixture
def enrolled_erasure(world, request):
    setup(world)  # Explicit enrollment while the initial runtime is disabled.
    case = request.getfixturevalue('erasure_case')
    rt = case[0].runtime
    row = world[1].snapshot((RUNTIME,))[RUNTIME]
    rt.disable(world[5], expected_version=int(row.data['control_version']),
               reason='admission fixture stop', idempotency_key='admission-fixture-disable')
    service = PersistentAdmission(rt, limits=AdmissionLimits(3, 1000), clock_ms=world[2])
    service.initialize('a'*64)  # Reuses enrollment; never opens a held gate.
    return service, case


def test_registered_real_erasure_executor_still_reports_metadata_pending(world, enrolled_erasure):
    admission, case = enrolled_erasure; service = case[0]
    job = commit(world, case); list_page(case)
    driver, _ = make_driver(world, runtime=service.runtime, erasure=service,
        admission_runner=AdmittedWorker(admission, lease_ms=500, attempts=3))
    assert driver.poll_once()
    result = service.job(world[5], job['id'])
    assert result['status'] == 'metadata_pending' and result['erasure_complete'] is False
    assert world[1].snapshot((REGISTRY,))[REGISTRY].data['active'] == {}


def test_real_executor_hold_after_version_listing_prevents_delete_and_false_completion(world, enrolled_erasure, monkeypatch):
    admission, case = enrolled_erasure; service = case[0]
    job = commit(world, case); list_page(case, versions=('v1',))
    driver, _ = make_driver(world, runtime=service.runtime, erasure=service,
        admission_runner=AdmittedWorker(admission, lease_ms=500, attempts=3))
    original = service.objects.list; request = str(uuid4())
    def listing(*args):
        result = original(*args)
        admission.hold(request_id=request, scope_sha256='c'*64)
        return result
    monkeypatch.setattr(service.objects, 'list', listing)
    assert driver.poll_once() is False
    result = service.job(world[5], job['id'])
    assert result['status'] == 'processing' and not result['assets'][0]['live_versions_removed']
    assert result['assets'][0]['delete_acknowledgments'] == 0 and result['erasure_complete'] is False
    admission.assert_drained(admission.drained(request_id=request, scope_sha256='c'*64))
