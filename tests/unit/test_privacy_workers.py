"""Real driver control flow with model services, not actual worker/provider proof."""
from types import SimpleNamespace
import inspect
from concurrent.futures import Future

import pytest

from test_privacy_admission import world, hold, ident
from proofpack.evidence.privacy_workers import AdmittedWorker
from proofpack.evidence.privacy_admission import checkpoint_current, AdmissionHeld, REGISTRY
from proofpack.evidence.repository import StoreConflict, StoreUnavailable
from proofpack.runtime.maintenance import MaintenanceDriver


def active(repo): return repo.rows[REGISTRY].data['active']


def runner(service): return AdmittedWorker(service, lease_ms=500, attempts=3)


def test_worker_scope_is_active_until_operation_returns_and_context_is_reset():
    service, repo, runtime, clock = world(); entered = []
    def operation():
        checkpoint_current(service)
        entered.append(len(active(repo)))
        hold(service)
        with pytest.raises(AdmissionHeld): service.drained(request_id=ident(90), scope_sha256='b'*64)
        return 'done'
    assert runner(service).run(operation) == 'done'
    assert entered == [1] and not active(repo)
    with pytest.raises(AdmissionHeld): checkpoint_current()


def test_held_worker_never_executes_operation():
    service, repo, runtime, clock = world(); hold(service); calls = []
    with pytest.raises(AdmissionHeld): runner(service).run(lambda: calls.append(True))
    assert not calls and not active(repo)


@pytest.mark.parametrize('error,remains', [(RuntimeError, False), (KeyboardInterrupt, True)])
def test_known_exception_and_unconfirmed_termination_are_distinct(error, remains):
    service, repo, runtime, clock = world()
    def operation(): raise error('synthetic worker interruption')
    with pytest.raises(error): runner(service).run(operation)
    assert bool(active(repo)) == remains


def test_bookkeeping_retry_never_replays_worker_operation(monkeypatch):
    service, repo, runtime, clock = world(); original = service.admit; attempts = []; calls = []
    def admit(item):
        attempts.append(item)
        if len(attempts) < 3: raise StoreConflict('synthetic contention')
        return original(item)
    monkeypatch.setattr(service, 'admit', admit)
    assert runner(service).run(lambda: calls.append(True)) is None
    assert len(attempts) == 3 and all(item is attempts[0] for item in attempts)
    assert calls == [True] and not active(repo)


def test_release_failure_retains_registry_and_prevents_more_work(monkeypatch):
    service, repo, runtime, clock = world(); worker = runner(service); calls = []
    def release(item): raise StoreUnavailable('synthetic release outage')
    monkeypatch.setattr(service, 'release', release)
    assert worker.run(lambda: calls.append(True)) is None
    assert worker.release_pending and len(active(repo)) == 1
    with pytest.raises(AdmissionHeld): worker.run(lambda: calls.append(True))
    assert calls == [True]


def driver(world_value):
    service, repo, runtime, clock = world_value
    access = SimpleNamespace(repository=repo, now=lambda: clock.value)
    runtime.access = access
    exports = SimpleNamespace(access=access, runtime=runtime, repository=repo)
    erasure = SimpleNamespace(access=access, runtime=runtime, repository=repo)
    instance = MaintenanceDriver(access, runtime, exports, erasure, enabled=True, poll_ms=250,
        page_size=2, steps_per_minute=10, drain_ms=1000, admission_runner=runner(service))
    return instance


def test_real_driver_registers_before_ordinary_query_and_releases_empty_poll():
    data = world(); service, repo, runtime, clock = data; instance = driver(data); queries = []
    def query(**kwargs):
        checkpoint_current(service)
        queries.append(len(active(repo)))
        return [], None
    repo.query = query
    assert instance.poll_once() is False
    assert queries == [1] and not active(repo) and instance._counts['polls'] == 1


def test_real_driver_cannot_query_after_hold_or_use_unregistered_checkpoint():
    data = world(); service, repo, runtime, clock = data; instance = driver(data); queries = []
    repo.query = lambda **kwargs: (queries.append(True) or ([], None))
    with pytest.raises(AdmissionHeld): instance.checkpoint()
    hold(service)
    assert instance.poll_once() is False and not queries
    assert instance._reason == 'METADATA_ADMISSION_HELD'


def test_real_driver_mid_poll_hold_is_expected_held_not_internal_error():
    data = world(); service, repo, runtime, clock = data; instance = driver(data)
    def query(**kwargs): hold(service); return [], None
    repo.query = query
    assert instance.poll_once() is False and not active(repo)
    assert instance._reason == 'METADATA_ADMISSION_HELD' and instance._counts['errors'] == 0


@pytest.mark.parametrize('field,value', [('lease_ms', 0), ('lease_ms', True), ('lease_ms', 1001),
                                       ('attempts', 0), ('attempts', 4), ('attempts', True)])
def test_worker_lifetime_retry_bounds(field, value):
    service, repo, runtime, clock = world(); options = {'lease_ms': 500, 'attempts': 3}; options[field] = value
    with pytest.raises(ValueError): AdmittedWorker(service, **options)


def test_async_function_is_not_misclassified_as_completed_synchronous_work():
    service, repo, runtime, clock = world(); result = None
    async def deferred(): return 'later'
    try:
        with pytest.raises(ValueError): result = runner(service).run(deferred)
        assert not active(repo)
    finally:
        if inspect.iscoroutine(result): result.close()


def test_returned_awaitable_keeps_unknown_execution_registered():
    service, repo, runtime, clock = world(); created = []; worker = runner(service)
    async def deferred(): return 'later'
    def operation():
        value = deferred(); created.append(value); return value
    try:
        with pytest.raises(AdmissionHeld): worker.run(operation)
        assert worker.release_pending and len(active(repo)) == 1
    finally:
        for value in created: value.close()


def test_concurrent_future_is_not_mistaken_for_completed_work():
    service, repo, runtime, clock = world(); worker = runner(service); pending = Future()
    with pytest.raises(AdmissionHeld): worker.run(lambda: pending)
    assert worker.release_pending and len(active(repo)) == 1 and not pending.cancelled()
    pending.cancel()  # Test cleanup only; the coordinator does not infer executor completion.


def test_driver_rejects_runner_from_another_runtime_and_target():
    own = world(); foreign = world(); service, repo, runtime, clock = own
    access = SimpleNamespace(repository=repo, now=lambda: clock.value); runtime.access = access
    exports = SimpleNamespace(access=access, runtime=runtime, repository=repo)
    erasure = SimpleNamespace(access=access, runtime=runtime, repository=repo)
    with pytest.raises(ValueError):
        MaintenanceDriver(access, runtime, exports, erasure, enabled=True, poll_ms=250,
            page_size=2, steps_per_minute=10, drain_ms=1000, admission_runner=runner(foreign[0]))
