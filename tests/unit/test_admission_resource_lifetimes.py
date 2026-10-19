"""Actual ASGI scheduling with synthetic protocol state and local executor ownership."""
from copy import deepcopy
from threading import Event

import anyio
import pytest

from test_privacy_admission import world, hold
from test_privacy_http_admission import scope, receive
from proofpack.evidence.privacy_http import MetadataAdmissionBoundary
from proofpack.evidence.privacy_admission import AdmissionHeld, REGISTRY
from proofpack.evidence.privacy_workers import AdmittedWorker
from proofpack.runtime.ownership import ResourceOwner


def boundary(service, app, owner):
    return MetadataAdmissionBoundary(app,admission=service,lease_ms=500,attempts=3,resource_owner=owner)


async def response(scope,receive,send):
    await send({'type':'http.response.start','status':200,'headers':[]})
    await send({'type':'http.response.body','body':b'synthetic','more_body':False})


def test_local_scope_exists_before_the_first_admission_read_and_outlives_its_thread():
    service,repo,runtime,clock = world(); owner = ResourceOwner()
    entered = Event(); finish = Event(); original = service.prepare
    def prepare(**kwargs):
        entered.set()
        assert finish.wait(3)
        assert not owner.wait_for_drain(0)
        return original(**kwargs)
    service.prepare = prepare
    async def run():
        async def send(value): pass
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(boundary(service,response,owner),scope(),receive,send)
            assert await anyio.to_thread.run_sync(entered.wait,1)
            owner.stop_accepting()
            assert not owner.wait_for_drain(0)
            finish.set()
    try: anyio.run(run)
    finally: finish.set()
    assert owner.wait_for_drain(0) and not repo.rows[REGISTRY].data['active']


def test_canceled_http_scope_does_not_release_unknown_local_or_durable_ownership():
    service,repo,runtime,clock = world(); owner = ResourceOwner(); callbacks = []
    async def run():
        entered = anyio.Event()
        async def app(value,receive,send):
            entered.set(); await anyio.sleep_forever()
        async def send(value): pass
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(boundary(service,app,owner),scope(),receive,send)
            await entered.wait(); tasks.cancel_scope.cancel()
    anyio.run(run)
    owner.stop_accepting(); owner.after_drain(lambda:callbacks.append('unsafe close'))
    assert not owner.wait_for_drain(0) and not callbacks
    assert repo.rows[REGISTRY].data['active']


def test_termination_in_http_release_holds_local_owner_and_marks_release_pending():
    class Termination(BaseException): pass
    service,repo,runtime,clock = world(); owner = ResourceOwner()
    def interrupted(value): raise Termination()
    service.release = interrupted
    wrapper = boundary(service,response,owner)
    async def run():
        async def send(value): pass
        with pytest.raises(Termination): await wrapper(scope(),receive,send)
    anyio.run(run)
    assert not owner.wait_for_drain(0) and wrapper.release_pending
    assert repo.rows[REGISTRY].data['active']


def test_held_http_does_not_leak_local_ownership_or_run_business_work():
    service,repo,runtime,clock = world(); owner = ResourceOwner(); hold(service)
    async def forbidden(*args): pytest.fail('held work must not run')
    async def run():
        messages = []
        async def send(value): messages.append(value)
        await boundary(service,forbidden,owner)(scope(),receive,send)
        assert messages[0]['status'] == 503
    anyio.run(run)
    assert owner.wait_for_drain(0) and not repo.rows[REGISTRY].data['active']


def test_ordinary_application_exception_closes_known_finished_scope():
    service,repo,runtime,clock = world(); owner = ResourceOwner()
    async def failed(*args): raise RuntimeError('synthetic finished exception')
    async def run():
        async def send(value): pass
        with pytest.raises(RuntimeError): await boundary(service,failed,owner)(scope(),receive,send)
    anyio.run(run)
    assert owner.wait_for_drain(0) and not repo.rows[REGISTRY].data['active']


@pytest.mark.parametrize('method', ['GET','HEAD'])
def test_static_liveness_after_local_stop_needs_no_registry_or_downstream(method):
    service,repo,runtime,clock = world(initialized=False); owner = ResourceOwner(); owner.stop_accepting()
    def forbidden(*args,**kwargs): pytest.fail('liveness cannot use admission')
    service.prepare = forbidden
    async def app(*args): pytest.fail('liveness cannot invoke downstream')
    async def run():
        messages = []
        async def send(value): messages.append(deepcopy(value))
        await boundary(service,app,owner)(scope(path='/health/live',method=method),receive,send)
        assert messages[0]['status'] == 200
        assert (b'cache-control',b'no-store') in messages[0]['headers']
        assert messages[1]['body'] == (b'{"status":"ok"}' if method=='GET' else b'')
    anyio.run(run)


def test_held_worker_preparation_releases_local_owner_without_running_operation():
    service,repo,runtime,clock = world(); owner = ResourceOwner(); hold(service)
    runner = AdmittedWorker(service,lease_ms=500,attempts=3,resource_owner=owner)
    with pytest.raises(AdmissionHeld): runner.run(lambda:pytest.fail('held worker ran'))
    assert owner.wait_for_drain(0)


def test_cleanup_registration_before_stopping_is_not_authority_to_close_live_resources():
    owner = ResourceOwner(); called = []
    with pytest.raises(ValueError): owner.after_drain(lambda:called.append(True))
    assert not called
