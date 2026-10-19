"""Actual ASGI scheduling against a protocol model, not deployed application coverage."""
from copy import deepcopy

import anyio
import pytest

from test_privacy_admission import world, hold, ident
from proofpack.evidence.privacy_http import MetadataAdmissionBoundary
from proofpack.evidence.privacy_admission import checkpoint_current, AdmissionHeld, REGISTRY
from proofpack.evidence.repository import StoreConflict, StoreUnavailable


def wrapper(service, app, **options):
    return MetadataAdmissionBoundary(app, admission=service, lease_ms=500, attempts=3, **options)


async def receive(): return {'type': 'http.request', 'body': b'', 'more_body': False}


def scope(**changes):
    return {'type': 'http', 'method': 'GET', 'path': '/private', 'headers': [], **changes}


def active(repo): return repo.rows[REGISTRY].data['active']


def test_success_preserves_thread_context_and_resets_it_after_complete_application():
    service, repo, runtime, clock = world(); messages = []; observations = []
    async def app(value, receive, send):
        assert len(active(repo)) == 1
        await anyio.to_thread.run_sync(checkpoint_current)
        observations.append('once')
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'OK', 'more_body': False})
        assert len(active(repo)) == 1  # Awaited background work remains inside admission.
    async def run():
        async def send(message): messages.append(deepcopy(message))
        await wrapper(service, app)(scope(), receive, send)
        with pytest.raises(AdmissionHeld): checkpoint_current()
    anyio.run(run)
    assert observations == ['once'] and not active(repo)
    assert messages[-1]['body'] == b'OK'


def test_held_entry_denies_without_business_execution_or_internal_payload():
    service, repo, runtime, clock = world(); hold(service); messages = []; executed = []
    async def app(*args): executed.append(True)
    async def run():
        async def send(message): messages.append(deepcopy(message))
        await wrapper(service, app)(scope(), receive, send)
    anyio.run(run)
    assert not executed and not active(repo)
    assert messages[0]['status'] == 503
    assert b'PRIVATE' not in messages[1]['body'] and b'00000000' not in messages[1]['body']
    assert (b'cache-control', b'no-store') in messages[0]['headers']


def test_hold_after_headers_suppresses_further_private_body_and_releases_finished_scope():
    service, repo, runtime, clock = world(); messages = []
    async def app(value, receive, send):
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'PRIVATE-DATA', 'more_body': False})
    async def run():
        async def send(message):
            messages.append(deepcopy(message))
            if message['type'] == 'http.response.start': hold(service)
        await wrapper(service, app)(scope(), receive, send)
    anyio.run(run)
    assert [m['status'] for m in messages if 'status' in m] == [200]
    assert [m['body'] for m in messages if 'body' in m] == [b'']
    assert not active(repo)
    service.assert_drained(service.drained(request_id=ident(90), scope_sha256='b'*64))


def test_background_execution_keeps_drain_held_after_response_completion():
    service, repo, runtime, clock = world(); blocked = []
    async def app(value, receive, send):
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'OK'})
        hold(service)
        with pytest.raises(AdmissionHeld): service.drained(request_id=ident(90), scope_sha256='b'*64)
        blocked.append(True)
        await anyio.sleep(0)
    async def run():
        async def send(message): pass
        await wrapper(service, app)(scope(), receive, send)
    anyio.run(run)
    assert blocked == [True] and not active(repo)


def test_cancellation_does_not_claim_unconfirmed_executor_has_drained():
    service, repo, runtime, clock = world()
    async def run():
        entered = anyio.Event()
        async def app(value, receive, send):
            entered.set()
            await anyio.sleep_forever()
        async def send(message): pass
        async with anyio.create_task_group() as group:
            group.start_soon(wrapper(service, app), scope(), receive, send)
            await entered.wait()
            group.cancel_scope.cancel()
    anyio.run(run)
    assert len(active(repo)) == 1
    hold(service); clock.value += 10000
    with pytest.raises(AdmissionHeld): service.drained(request_id=ident(90), scope_sha256='b'*64)


@pytest.mark.parametrize('error,expected_attempts', [(StoreConflict, 3), (StoreUnavailable, 1)])
def test_unconfirmed_release_remains_registered_and_is_reported_privately(monkeypatch, error, expected_attempts):
    service, repo, runtime, clock = world(); attempts = []
    def failed(item): attempts.append(item); raise error('PRIVATE-ERROR')
    monkeypatch.setattr(service, 'release', failed)
    async def app(value, receive, send):
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'OK'})
    boundary = wrapper(service, app)
    async def run():
        async def send(message): pass
        await boundary(scope(), receive, send)
    anyio.run(run)
    assert boundary.release_pending and len(active(repo)) == 1 and len(attempts) == expected_attempts
    assert all(item is attempts[0] for item in attempts)


def test_bounded_admission_retry_reuses_exact_intent_without_business_replay(monkeypatch):
    service, repo, runtime, clock = world(); original = service.admit; attempts = []; calls = []
    def conflict(item):
        attempts.append(item)
        if len(attempts) < 3: raise StoreConflict('synthetic admission contention')
        return original(item)
    monkeypatch.setattr(service, 'admit', conflict)
    async def app(value, receive, send):
        calls.append(True)
        await send({'type': 'http.response.start', 'status': 204, 'headers': []})
        await send({'type': 'http.response.body', 'body': b''})
    async def run():
        async def send(message): pass
        await wrapper(service, app)(scope(), receive, send)
    anyio.run(run)
    assert len(attempts) == 3 and all(item is attempts[0] for item in attempts)
    assert calls == [True] and not active(repo)


def test_expired_admission_cannot_emit_first_headers_but_completed_work_can_release():
    service, repo, runtime, clock = world(); messages = []
    async def app(value, receive, send):
        clock.value += 500
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
    async def run():
        async def send(message): messages.append(deepcopy(message))
        await wrapper(service, app)(scope(), receive, send)
    anyio.run(run)
    assert messages[0]['status'] == 503 and not active(repo)


def test_file_offload_cannot_escape_request_registration():
    service, repo, runtime, clock = world(); messages = []; extensions = []
    async def app(value, receive, send):
        extensions.append(value['extensions'])
        await send({'type': 'http.response.pathsend', 'path': 'PRIVATE-FILE'})
    async def run():
        async def send(message): messages.append(deepcopy(message))
        await wrapper(service, app)(scope(extensions={'http.response.pathsend': {}, 'http.response.zerocopysend': {}, 'other': {}}), receive, send)
    anyio.run(run)
    assert extensions == [{'other': {}}]
    assert messages[0]['status'] == 503 and b'PRIVATE-FILE' not in messages[1]['body']
    assert not active(repo)


def test_unexpected_application_error_is_not_replayed_and_terminal_scope_releases():
    service, repo, runtime, clock = world(); calls = []
    async def app(*args): calls.append(True); raise RuntimeError('synthetic application failure')
    async def run():
        async def send(message): pass
        with pytest.raises(RuntimeError): await wrapper(service, app)(scope(), receive, send)
    anyio.run(run)
    assert calls == [True] and not active(repo)


@pytest.mark.parametrize('kind,called', [('lifespan', True), ('websocket', False)])
def test_non_http_scope_is_explicit(kind, called):
    service, repo, runtime, clock = world(); calls = []; messages = []
    async def app(*args): calls.append(True)
    async def run():
        async def send(message): messages.append(deepcopy(message))
        await wrapper(service, app)(scope(type=kind), receive, send)
    anyio.run(run)
    assert bool(calls) == called and not active(repo)
    if kind == 'websocket': assert messages == [{'type': 'websocket.close', 'code': 1013}]


@pytest.mark.parametrize('field,value', [('lease_ms', 0), ('lease_ms', True), ('lease_ms', 1001),
                                       ('attempts', 0), ('attempts', 4), ('attempts', True)])
def test_explicit_lifetime_and_retry_bounds(field, value):
    service, repo, runtime, clock = world()
    options = {'lease_ms': 500, 'attempts': 3}; options[field] = value
    with pytest.raises(ValueError): MetadataAdmissionBoundary(None, admission=service, **options)


def test_shared_http_context_can_checkpoint_manual_maintenance_without_second_registration():
    from test_privacy_workers import driver
    data = world(); service, repo, runtime, clock = data; instance = driver(data); seen = []
    async def app(value, receive, send):
        await anyio.to_thread.run_sync(instance.checkpoint)
        seen.append(len(active(repo)))
        await send({'type': 'http.response.start', 'status': 204, 'headers': []})
        await send({'type': 'http.response.body', 'body': b''})
    async def run():
        async def send(message): pass
        await wrapper(service, app)(scope(), receive, send)
    anyio.run(run)
    assert seen == [1] and not active(repo)
