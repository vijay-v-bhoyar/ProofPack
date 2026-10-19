"""Real factory/ASGI with an in-memory protocol store and prohibited SDK traffic."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import anyio
import pytest

from test_host import host_files
from test_privacy_admission import ModelRepository, ident
from proofpack.evidence.privacy_admission import AdmissionConfiguration, AdmissionHeld, GATE, REGISTRY
from proofpack.runtime.host import load_configuration, HostConfigurationError
from proofpack.runtime.composition import ApplicationClients, create_configured_app, ConfiguredStartupUnavailable
import proofpack.runtime.composition as composition


@pytest.fixture(autouse=True)
def prohibit_sdk(monkeypatch):
    from botocore.endpoint import Endpoint
    def denied(*args, **kwargs): pytest.fail('SDK calls prohibited in model factory test')
    monkeypatch.setattr(Endpoint, 'make_request', denied)


@pytest.fixture
def factory_model(host_files, monkeypatch):
    settings = load_configuration(*host_files[:2]).config
    bounds = AdmissionConfiguration(8, 300000, 60000, 120000, 3, 'a'*64)
    # Explicit isolated loopback model: no protected target or release is supplied.
    settings = replace(settings, environment='test',local_database_endpoint='http://127.0.0.1:8001',
        restore_fence=None,installation=None,metadata_admission=bounds)
    repo = ModelRepository(); repo.deployment = settings.auth.deployment
    repo.tables = {'state':settings.state_table, 'events':settings.events_table}
    closed = []
    def client(service):
        return SimpleNamespace(meta=SimpleNamespace(service_model=SimpleNamespace(service_name=service),
            region_name='us-east-1', endpoint_url='https://'+service+'.us-east-1.amazonaws.com',
            config=SimpleNamespace(connect_timeout=2, read_timeout=3, retries={'total_max_attempts':1})),
            close=lambda:closed.append(service))
    clients = ApplicationClients(client('dynamodb'), client('s3'), client('sts'))
    clients.dynamodb.meta.endpoint_url=settings.local_database_endpoint
    monkeypatch.setattr(composition, 'DynamoRepository', lambda *a, **k:repo)
    monkeypatch.setattr(composition, '_target', lambda *a:None)
    monkeypatch.setattr(composition, 'runtime_proof', lambda:{'synthetic_proof_stub':True})
    return settings, clients, repo, closed


def build(case, **kwargs): return create_configured_app(case[0], case[1], **kwargs)


def enrolled(app):
    service = app.state.metadata_admission
    service.runtime.start()
    service.initialize('a'*64)  # Explicit fixture enrollment, not factory startup.
    return service


def test_factory_uses_the_access_clock_when_no_override_is_supplied(factory_model):
    app = build(factory_model)
    assert app.state.metadata_admission.clock_ms.__self__ is app.state.access_service


def test_factory_constructs_without_store_or_sdk_io_and_shares_exact_owners(factory_model):
    app = build(factory_model)
    assert not factory_model[2].rows and not factory_model[3]
    runner = app.state.maintenance_driver._admission_runner
    assert runner.admission is app.state.metadata_admission
    assert runner.resource_owner is app.state.resource_owner
    assert app.user_middleware[0].cls.__name__ == 'OAuthQueryBoundary'
    assert app.user_middleware[1].cls.__name__ == 'MetadataAdmissionBoundary'


def test_startup_refuses_missing_enrollment_and_closes_clients_without_creating_gate(factory_model):
    app = build(factory_model, clock_ms=lambda:100)
    async def run():
        with pytest.raises(AdmissionHeld):
            async with app.router.lifespan_context(app): pytest.fail('missing enrollment must hold startup')
    anyio.run(run)
    assert GATE not in factory_model[2].rows and REGISTRY not in factory_model[2].rows
    assert sorted(factory_model[3]) == ['dynamodb','s3','sts']
    assert app.state.composition_status == 'failed'


async def request(app, path, method='GET', query=b''):
    messages = []
    async def receive(): return {'type':'http.request','body':b'','more_body':False}
    async def send(message): messages.append(deepcopy(message))
    await app({'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':method,
        'scheme':'https','path':path,'raw_path':path.encode(),'root_path':'','query_string':query,
        'headers':[],'client':('127.0.0.1',1),'server':('proofpack.test',443)}, receive, send)
    return messages


def test_held_factory_starts_without_reopening_and_fixed_liveness_has_no_store_reads(factory_model):
    app = build(factory_model, clock_ms=lambda:100); service = enrolled(app)
    service.hold(request_id=ident(90), scope_sha256='b'*64)
    before = deepcopy(factory_model[2].rows[GATE])
    async def run():
        async with app.router.lifespan_context(app):
            original = factory_model[2].snapshot
            def forbidden(*a): pytest.fail('liveness must not read store')
            factory_model[2].snapshot = forbidden
            try:
                for method in ('GET','HEAD'):
                    reply = await request(app,'/health/live',method,query=b'code=PRIVATE')
                    assert reply[0]['status'] == 200
                    assert reply[1]['body'] == (b'{"status":"ok"}' if method=='GET' else b'')
                    assert b'PRIVATE' not in repr(reply).encode()
            finally: factory_model[2].snapshot = original
            for path,method in (('/health/ready','GET'),('/health/live','POST'),('/api/v1/private','GET')):
                reply = await request(app,path,method)
                assert reply[0]['status'] == 503
    anyio.run(run)
    assert factory_model[2].rows[GATE] == before
    assert sorted(factory_model[3]) == ['dynamodb','s3','sts']


def test_shutdown_retains_clients_until_an_actual_foreground_scope_exits(factory_model):
    app = build(factory_model,clock_ms=lambda:100); enrolled(app)
    ticket = app.state.resource_owner.acquire()
    async def run():
        with pytest.raises(ConfiguredStartupUnavailable):
            async with app.router.lifespan_context(app): pass
    anyio.run(run)
    assert not factory_model[3]
    with pytest.raises(AdmissionHeld): app.state.resource_owner.acquire()
    app.state.resource_owner.release(ticket)
    assert sorted(factory_model[3]) == ['dynamodb','s3','sts']


@pytest.mark.parametrize('field,value', [('max_active',True),('max_lease_ms',300001),('http_lease_ms',0),
    ('worker_lease_ms',300001),('attempts',4),('enrollment_sha256','A'*64)])
def test_invalid_admission_bounds_rejected(field,value):
    args=dict(max_active=8,max_lease_ms=300000,http_lease_ms=60000,worker_lease_ms=120000,attempts=3,enrollment_sha256='a'*64)
    args[field]=value
    with pytest.raises(ValueError): AdmissionConfiguration(**args)


def test_beta_configuration_cannot_omit_admission(factory_model):
    with pytest.raises(ValueError): replace(factory_model[0],environment='beta',metadata_admission=None)


def test_actual_factory_waits_for_awaited_response_background_before_closing_clients(factory_model):
    from starlette.background import BackgroundTask
    from starlette.responses import PlainTextResponse
    app = build(factory_model,clock_ms=lambda:100); enrolled(app)
    async def run():
        entered = anyio.Event(); finish = anyio.Event(); ended = anyio.Event()
        async def background():
            assert factory_model[2].rows[REGISTRY].data['active']
            entered.set(); await finish.wait()
            assert not factory_model[3]
        async def endpoint(): return PlainTextResponse('synthetic',background=BackgroundTask(background))
        app.add_api_route('/unit-background',endpoint)
        async def perform():
            await request(app,'/unit-background'); ended.set()
        lifetime = app.router.lifespan_context(app)
        await lifetime.__aenter__()
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(perform)
            with anyio.fail_after(3): await entered.wait()
            with pytest.raises(ConfiguredStartupUnavailable): await lifetime.__aexit__(None,None,None)
            assert not factory_model[3] and not ended.is_set()
            assert factory_model[2].rows[REGISTRY].data['active']
            finish.set()
            with anyio.fail_after(3): await ended.wait()
        assert not factory_model[2].rows[REGISTRY].data['active']
        assert sorted(factory_model[3]) == ['dynamodb','s3','sts']
    anyio.run(run)


@pytest.mark.parametrize('change', [{'attempts':True},{'unexpected':'value'},{'max_active':0},
    {'http_lease_ms':300001},{'enrollment_sha256':'wrong'}])
def test_host_admission_document_rejects_invalid_fields_before_construction(host_files,change):
    import json
    config,secret,document,keys = host_files
    document['metadata_admission'] = dict(max_active=8,max_lease_ms=300000,http_lease_ms=60000,
        worker_lease_ms=120000,attempts=3,enrollment_sha256='a'*64)
    document['metadata_admission'].update(change)
    config.write_text(json.dumps(document),encoding='utf-8')
    with pytest.raises(HostConfigurationError): load_configuration(config,secret)


def test_host_admission_document_loads_exact_bounds(host_files):
    import json
    config,secret,document,keys = host_files
    fields = dict(max_active=8,max_lease_ms=300000,http_lease_ms=60000,
        worker_lease_ms=120000,attempts=3,enrollment_sha256='a'*64)
    document['metadata_admission'] = fields
    config.write_text(json.dumps(document),encoding='utf-8')
    assert vars(load_configuration(config,secret).config.metadata_admission) == fields


@pytest.mark.parametrize('worker_exits_first',[True,False])
def test_factory_waits_for_both_worker_and_http_owners_before_cleanup(factory_model,worker_exits_first):
    from threading import Event
    from starlette.background import BackgroundTask
    from starlette.responses import PlainTextResponse
    settings,clients,repo,closed = factory_model
    app = create_configured_app(replace(settings,maintenance_enabled=True),clients,clock_ms=lambda:100)
    enrolled(app)
    worker_entered = Event(); worker_finish = Event()
    maintenance = app.state.maintenance_driver
    def poll():
        worker_entered.set()
        assert worker_finish.wait(5)
        return False
    maintenance._poll_once = poll
    async def run():
        entered = anyio.Event(); finish = anyio.Event(); ended = anyio.Event()
        async def background(): entered.set(); await finish.wait()
        async def endpoint(): return PlainTextResponse('synthetic',background=BackgroundTask(background))
        app.add_api_route('/unit-joint-background',endpoint)
        async def perform(): await request(app,'/unit-joint-background'); ended.set()
        lifetime = app.router.lifespan_context(app); await lifetime.__aenter__()
        assert await anyio.to_thread.run_sync(worker_entered.wait,1)
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(perform)
            with anyio.fail_after(3): await entered.wait()
            with pytest.raises(ConfiguredStartupUnavailable): await lifetime.__aexit__(None,None,None)
            assert not closed
            if worker_exits_first:
                worker_finish.set()
                await anyio.to_thread.run_sync(maintenance._thread.join,1)
                assert not maintenance._thread.is_alive() and not closed
                finish.set()
            else:
                finish.set()
                with anyio.fail_after(3): await ended.wait()
                assert not closed
                worker_finish.set()
            with anyio.fail_after(3): await ended.wait()
        await anyio.to_thread.run_sync(maintenance._thread.join,1)
        assert not maintenance._thread.is_alive()
        if maintenance._exit_observer is not None:
            await anyio.to_thread.run_sync(maintenance._exit_observer.join,1)
            assert not maintenance._exit_observer.is_alive()
    try: anyio.run(run)
    finally:
        worker_finish.set()
        if maintenance._thread is not None: maintenance._thread.join(1)
    assert sorted(closed) == ['dynamodb','s3','sts']


def test_existing_held_gate_survives_a_new_actual_runtime_incarnation(factory_model):
    first = build(factory_model,clock_ms=lambda:100); original = enrolled(first)
    original.hold(request_id=ident(90),scope_sha256='b'*64)
    held = deepcopy(factory_model[2].rows[GATE])
    successor = build(factory_model,clock_ms=lambda:100)
    async def run():
        async with successor.router.lifespan_context(successor):
            assert successor.state.metadata_admission.runtime.handle.epoch == 2
            assert (await request(successor,'/health/live'))[0]['status'] == 200
            assert (await request(successor,'/private'))[0]['status'] == 503
    anyio.run(run)
    assert factory_model[2].rows[GATE] == held


@pytest.mark.parametrize('worker_enabled',[False,True])
def test_structured_shutdown_cancellation_cannot_skip_stop_and_deferred_cleanup(factory_model,worker_enabled):
    from threading import Event
    settings,clients,repo,closed = factory_model
    app = create_configured_app(replace(settings,maintenance_enabled=worker_enabled),clients,clock_ms=lambda:100)
    enrolled(app); ticket = app.state.resource_owner.acquire()
    maintenance = app.state.maintenance_driver
    entered = Event(); finish = Event()
    def poll(): entered.set(); assert finish.wait(5); return False
    maintenance._poll_once = poll
    async def run():
        with pytest.raises(ConfiguredStartupUnavailable):
            with anyio.CancelScope() as cancel:
                async with app.router.lifespan_context(app):
                    if worker_enabled: assert await anyio.to_thread.run_sync(entered.wait,1)
                    cancel.cancel()
        assert maintenance._stop.is_set()
        assert app.state.composition_status == 'failed' and not closed
        app.state.resource_owner.release(ticket)
        if worker_enabled:
            assert not closed; finish.set()
            await anyio.to_thread.run_sync(maintenance._thread.join,1)
            if maintenance._exit_observer is not None:
                await anyio.to_thread.run_sync(maintenance._exit_observer.join,1)
                assert not maintenance._exit_observer.is_alive()
        assert sorted(closed) == ['dynamodb','s3','sts']
    try: anyio.run(run)
    finally:
        finish.set(); maintenance.stop_and_drain()


def test_direct_task_cancellation_preserves_deferred_cleanup_until_foreground_exit(factory_model):
    import asyncio
    from threading import Event
    app = build(factory_model,clock_ms=lambda:100); enrolled(app)
    owner = app.state.resource_owner; ticket = owner.acquire()
    maintenance = app.state.maintenance_driver
    entered = Event(); finish = Event(); ended = Event(); original = maintenance.stop_and_drain
    def paused_drain():
        entered.set()
        try:
            assert finish.wait(5)
            return original()
        finally: ended.set()
    maintenance.stop_and_drain = paused_drain
    async def run():
        async def lifetime():
            async with app.router.lifespan_context(app): pass
        task = asyncio.create_task(lifetime())
        assert await anyio.to_thread.run_sync(entered.wait,1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert maintenance._stop.is_set()
        assert app.state.composition_status == 'failed' and not factory_model[3]
        owner.release(ticket)
        assert sorted(factory_model[3]) == ['dynamodb','s3','sts']
        finish.set()
        assert await anyio.to_thread.run_sync(ended.wait,1)
    try: anyio.run(run)
    finally:
        finish.set(); original()


def test_processing_finally_is_not_physical_thread_exit_for_resource_cleanup(factory_model):
    from threading import Event
    settings,clients,repo,closed = factory_model
    app = create_configured_app(replace(settings,maintenance_enabled=True),clients,clock_ms=lambda:100)
    enrolled(app); maintenance = app.state.maintenance_driver
    entered = Event(); finish_processing = Event(); processing_ended = Event(); exit_thread = Event(); cleanup_done = Event()
    original_run = maintenance._run
    def poll(): entered.set(); assert finish_processing.wait(5); return False
    def run():
        original_run(); processing_ended.set(); assert exit_thread.wait(5)
    maintenance._poll_once = poll; maintenance._run = run
    original_close = clients.sts.close
    def close():
        assert not maintenance._thread.is_alive()
        original_close(); cleanup_done.set()
    clients.sts.close = close
    async def exercise():
        with pytest.raises(ConfiguredStartupUnavailable):
            async with app.router.lifespan_context(app):
                assert await anyio.to_thread.run_sync(entered.wait,1)
                finish_processing.set()
        assert processing_ended.is_set() and maintenance._thread.is_alive()
        assert not closed and not cleanup_done.is_set()
        exit_thread.set()
        assert await anyio.to_thread.run_sync(cleanup_done.wait,1)
        assert sorted(closed) == ['dynamodb','s3','sts']
    try: anyio.run(exercise)
    finally:
        finish_processing.set(); exit_thread.set(); maintenance.stop_and_drain()
        if maintenance._exit_observer is not None: maintenance._exit_observer.join(1)
