"""Local dispatch/thread/transaction proof; provider storage is intercepted."""
from dataclasses import replace
from threading import Event
from types import SimpleNamespace
from uuid import UUID, uuid4
import json

import pytest

from test_access_lifecycle import world, repository_factory, publication_case, invite_and_join
from test_asset_reads import frame_read_case
from test_exports import export_case, create
from test_erasure import erasure_case, commit, list_page
from test_references import reference_case
from proofpack.auth.policy import Denied, Role
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.job_authority import issue
from proofpack.evidence.erasure import job_key
from proofpack.evidence.repository import Write, StoreConflict
from proofpack.runtime.control import RuntimeControl, RUNTIME
from proofpack.runtime.maintenance import MaintenanceDriver, MaintenanceStopped, QUOTA
from fastapi.testclient import TestClient
from proofpack.app import create_app
from proofpack.auth.http import COOKIE


def make_driver(world, *, runtime=None, exports=None, erasure=None, **limits):
    access, repository, *_ = world
    if runtime is None:
        runtime = RuntimeControl(access, instance_id=str(uuid4()), artifact_sha256='a'*64,
            controls_sha256='b'*64, environment='synthetic_demo');runtime.start()
    calls = []
    def advance(actor, ident, *, expected_version, idempotency_key, execution_gate):
        execution_gate();row = repository.snapshot((job_key(ident),))[job_key(ident)]
        assert row.revision == expected_version
        repository.transact((Write(row.key, row.revision, {**row.data, 'status': 'metadata_pending'}),))
        calls.append((ident, idempotency_key, actor.session.data['id']))
    def fake(): return SimpleNamespace(access=access, repository=repository, runtime=runtime, advance=advance)
    settings = dict(enabled=True, poll_ms=250, page_size=5, steps_per_minute=60, drain_ms=1000)
    settings.update(limits)
    return MaintenanceDriver(access, runtime, exports or fake(), erasure or fake(), **settings), calls


def record_job(world, number, **changes):
    access, repository, clock, uid, _, owner = world
    scope = {'schema_version': 1, 'kind': 'selected_live_asset_versions',
        'storage_binding_sha256': 'a'*64, 'assets': [{'id': str(uuid4())}]}
    data = {'id': str(UUID(int=number)), 'kind': 'asset_erasure', 'scope': scope,
        'scope_sha256': digest(scope), 'created_at_ms': clock(), 'created_by': uid,
        'status': 'queued', 'lease_until_ms': 0}
    data['processing_authority'] = issue(access, owner, data, Role.OWNER)
    data.update(changes)
    repository.transact((Write(job_key(data['id']), None, data),))
    return data


def test_bounded_fair_discovery_progresses_past_held_authority(world, monkeypatch):
    driver, calls = make_driver(world, page_size=2)
    first = record_job(world, 1, processing_authority=None);second = record_job(world, 2)
    sizes = [];original = world[1].query
    def query(**kwargs):
        sizes.append(kwargs['limit']);return original(**kwargs)
    monkeypatch.setattr(world[1], 'query', query)
    assert driver.poll_once() is False and calls == []
    assert driver.poll_once() is True and calls[0][0] == second['id']
    assert sizes == [2, 2]
    status = driver.read(world[5]);assert status['counts']['attempts'] == 2 and status['counts']['held'] == 1
    for private in ('cookie_ref', 'signature', first['id'], second['id']): assert private not in json.dumps(status)


def test_durable_step_allowance_survives_new_driver_and_resets_only_next_minute(world):
    driver, calls = make_driver(world, steps_per_minute=1)
    record_job(world, 1);second = record_job(world, 2)
    assert driver.poll_once()
    newer, newer_calls = make_driver(world, runtime=driver.runtime, steps_per_minute=1)
    assert newer.poll_once() is False and not newer_calls
    quota = world[1].snapshot((QUOTA,))[QUOTA];assert quota.data['count'] == 1
    world[2].value += 60000
    newer.poll_once()  # end of discovery range
    assert newer.poll_once() and newer_calls[0][0] == second['id']


@pytest.mark.parametrize('status', ['completed', 'cancelled', 'failed', 'metadata_pending', 'processing'])
def test_terminal_or_active_lease_jobs_are_not_dispatched(world, status):
    driver, calls = make_driver(world)
    record_job(world, 1, status=status, lease_until_ms=world[2]()+1000)
    assert not driver.poll_once() and not calls
    assert world[1].snapshot((QUOTA,))[QUOTA] is None


def test_expired_lease_gets_one_exact_version_attempt_and_unknown_kind_is_skipped(world):
    driver, calls = make_driver(world)
    record_job(world, 1, kind='future_evaluation')
    second = record_job(world, 2, status='processing', lease_until_ms=world[2]())
    assert driver.poll_once() and [x[0] for x in calls] == [second['id']]


def test_superseded_runtime_cannot_reserve_or_dispatch(world):
    driver, calls = make_driver(world);record_job(world, 1)
    RuntimeControl(world[0], instance_id=str(uuid4()), artifact_sha256='a'*64,
        controls_sha256='b'*64, environment='synthetic_demo').start()
    assert not driver.poll_once() and not calls
    assert driver.read(world[5])['state'] == 'superseded'
    assert driver.read(world[5])['local_instance_current'] is False
    assert world[1].snapshot((QUOTA,))[QUOTA] is None


def test_quota_reservation_conditionally_checks_the_observed_job(world, monkeypatch):
    driver, calls = make_driver(world);job = record_job(world, 1);original = world[1].transact
    def transact(writes, checks=()):
        if writes[0].key == QUOTA:
            row = world[1].snapshot((job_key(job['id']),))[job_key(job['id'])]
            original((Write(row.key, row.revision, {**row.data, 'status': 'metadata_pending'}),))
        return original(writes, checks)
    monkeypatch.setattr(world[1], 'transact', transact)
    assert not driver.poll_once() and not calls
    assert world[1].snapshot((QUOTA,))[QUOTA] is None


def test_stop_after_discovery_prevents_admission(world, monkeypatch):
    driver, calls = make_driver(world);record_job(world, 1);original = world[1].query
    def query(**kwargs):
        result = original(**kwargs);driver._stop.set();return result
    monkeypatch.setattr(world[1], 'query', query)
    assert not driver.poll_once() and not calls
    assert world[1].snapshot((QUOTA,))[QUOTA] is None


def test_background_export_uses_real_executor_and_stops_without_issuing_tickets(world, export_case, monkeypatch):
    service = export_case[0];job = create(export_case, selected=False)
    driver, _ = make_driver(world, runtime=service.runtime, exports=service)
    done = Event();original = service.advance
    def advance(*args, **kwargs):
        result = original(*args, **kwargs)
        if result['status'] == 'completed': done.set()
        return result
    monkeypatch.setattr(service, 'advance', advance)
    try:
        driver.start();assert done.wait(8), driver.read(world[5])
    finally: assert driver.stop_and_drain()
    assert not driver._thread.daemon and not driver._thread.is_alive()
    assert service.job(export_case[3], job['id'])['status'] == 'completed'
    assert world[1].query(prefix='export-ticket#', limit=5)[0] == []


def test_background_erasure_remains_truthfully_metadata_pending(world, erasure_case, monkeypatch):
    service = erasure_case[0];job = commit(world, erasure_case);list_page(erasure_case)
    driver, _ = make_driver(world, runtime=service.runtime, erasure=service)
    done = Event();original = service.advance
    def advance(*args, **kwargs):
        result = original(*args, **kwargs);done.set();return result
    monkeypatch.setattr(service, 'advance', advance)
    try:
        driver.start();assert done.wait(5)
    finally: assert driver.stop_and_drain()
    result = service.job(world[5], job['id'])
    assert result['status'] == 'metadata_pending' and result['erasure_complete'] is False


def test_stop_after_real_version_listing_prevents_delete_and_progress(world, erasure_case, monkeypatch):
    service = erasure_case[0];job = commit(world, erasure_case);list_page(erasure_case, versions=('v1',))
    driver, _ = make_driver(world, runtime=service.runtime, erasure=service)
    original = service.objects.list
    def listing(*args):
        result = original(*args);driver._stop.set();return result
    monkeypatch.setattr(service.objects, 'list', listing)
    assert not driver.poll_once()
    result = service.job(world[5], job['id'])
    assert result['status'] == 'processing' and not result['assets'][0]['live_versions_removed']
    assert result['assets'][0]['delete_acknowledgments'] == 0


def test_cancel_between_resolved_dispatch_and_real_export_claim_prevents_progress(world, export_case, monkeypatch):
    service = export_case[0];job = create(export_case, selected=False)
    driver, _ = make_driver(world, runtime=service.runtime, exports=service);original = service.advance
    def advance(actor, ident, **kwargs):
        service.cancel(actor, ident, expected_version=kwargs['expected_version'], idempotency_key='cancel-race')
        return original(actor, ident, **kwargs)
    monkeypatch.setattr(service, 'advance', advance)
    assert not driver.poll_once()
    current = service.job(export_case[3], job['id']);assert current['status'] == 'cancelled' and current['scanned_rows'] == 0


def test_diagnostics_require_current_owner_mfa_and_disabled_driver_does_no_io(world, monkeypatch):
    driver, calls = make_driver(world, enabled=False)
    _, _, operator, *_ = invite_and_join(world)
    with pytest.raises(Denied): driver.read(operator)
    def forbidden(*args, **kwargs): raise AssertionError('disabled worker must not query')
    monkeypatch.setattr(world[1], 'query', forbidden)
    driver.start();assert not driver.poll_once() and driver.stop_and_drain() and not calls
    with pytest.raises(RuntimeError): driver.start()
    assert driver.read(world[5])['state'] == 'disabled'


def test_constructor_does_no_io_or_thread_start(world, monkeypatch):
    base, _ = make_driver(world)
    def forbidden(*args, **kwargs): raise AssertionError('no construction I/O')
    monkeypatch.setattr(world[1], 'snapshot', forbidden);monkeypatch.setattr(world[1], 'query', forbidden)
    driver = MaintenanceDriver(world[0], base.runtime, base.services['inspection_export'], base.services['asset_erasure'],
        enabled=True, poll_ms=250, page_size=5, steps_per_minute=60, drain_ms=1000)
    assert driver._thread is None and driver._state == 'constructed'


def test_unexpected_executor_failure_is_minimized_and_attempt_is_charged(world):
    driver, _ = make_driver(world);record_job(world, 1)
    def fail(*args, **kwargs): raise RuntimeError('private-cookie-reference-and-provider-secret')
    driver.services['asset_erasure'].advance = fail
    assert not driver.poll_once()
    status = driver.read(world[5]);assert status['counts']['errors'] == 1 and status['last_reason'] == 'INTERNAL_ERROR'
    assert 'private-cookie' not in json.dumps(status)
    assert world[1].snapshot((QUOTA,))[QUOTA].data['count'] == 1


def test_owner_diagnostic_http_scope_and_expired_mfa(world):
    driver, _ = make_driver(world);app = create_app(access_service=world[0], app_origin='https://proofpack.test')
    app.state.maintenance_driver = driver
    _, credentials, _, *_ = invite_and_join(world)
    with TestClient(app, base_url='https://proofpack.test') as client:
        assert client.get('/api/v1/admin/maintenance').status_code == 401
        owner = {COOKIE: world[4].cookie}
        response = client.get('/api/v1/admin/maintenance', cookies=owner)
        assert response.status_code == 200 and response.json()['state'] == 'constructed'
        assert client.get('/api/v1/admin/maintenance', cookies={COOKIE: credentials.cookie}).status_code == 403
        world[2].value += 600001
        assert client.get('/api/v1/admin/maintenance', cookies=owner).status_code == 403


def test_cancellation_during_real_export_query_fences_completion(world, export_case, monkeypatch):
    service = export_case[0];job = create(export_case, selected=False)
    driver, _ = make_driver(world, runtime=service.runtime, exports=service)
    original = world[1].query
    def query(**kwargs):
        result = original(**kwargs)
        if kwargs['prefix'] == 'observation#':
            row = service._row(job['id'])
            service.cancel(export_case[3], job['id'], expected_version=row.revision, idempotency_key='cancel-during-query')
        return result
    monkeypatch.setattr(world[1], 'query', query)
    assert not driver.poll_once()
    current = service.job(export_case[3], job['id'])
    assert current['status'] == 'cancelled' and current['scanned_rows'] == 0 and current['scan_rows_reserved'] > 0


@pytest.mark.parametrize('cause', ['logout', 'mfa_expired'])
def test_automatic_dispatch_cannot_recreate_missing_current_authority(world, cause):
    driver, calls = make_driver(world);job = record_job(world, 1)
    if cause == 'logout': world[0].logout(world[4].cookie, world[4].csrf)
    else: world[2].value += 600001
    assert not driver.poll_once() and not calls
    assert world[1].snapshot((job_key(job['id']),))[job_key(job['id'])].data['status'] == 'queued'
    assert world[1].snapshot((QUOTA,))[QUOTA].data['count'] == 1


def test_runtime_replaced_after_budget_reservation_cannot_dispatch(world, monkeypatch):
    driver, calls = make_driver(world);record_job(world, 1);original = driver._reserve
    def reserve(job):
        original(job)
        RuntimeControl(world[0], instance_id=str(uuid4()), artifact_sha256='a'*64,
            controls_sha256='b'*64, environment='synthetic_demo').start()
    monkeypatch.setattr(driver, '_reserve', reserve)
    assert not driver.poll_once() and not calls
    assert driver._state == 'superseded' and world[1].snapshot((QUOTA,))[QUOTA].data['count'] == 1
