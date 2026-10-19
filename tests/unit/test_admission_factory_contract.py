"""Factory prerequisites against a protocol model; no provider/physical proof."""
from copy import deepcopy
from dataclasses import replace
from threading import Event, Thread

import pytest

from test_privacy_admission import world, intent, hold, ident, ModelRuntime
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Row
from proofpack.evidence.privacy_admission import PersistentAdmission, AdmissionHeld, GATE, REGISTRY


def test_existing_enrollment_is_read_only_and_preserves_held_state():
    service, repo, runtime, clock = world()
    hold(service); before = deepcopy(repo.rows)
    repo.transact = lambda *a, **k: pytest.fail('startup must not write enrollment')
    state = service.require_enrollment('a'*64)
    assert state.phase == 'HELD' and state.active_count == 0 and not state.foreign_active
    assert repo.rows == before


@pytest.mark.parametrize('missing', [GATE, REGISTRY])
def test_missing_enrollment_never_self_initializes(missing):
    service, repo, runtime, clock = world()
    del repo.rows[missing]; before = deepcopy(repo.rows)
    with pytest.raises(AdmissionHeld): service.require_enrollment('a'*64)
    assert repo.rows == before


def test_changed_enrollment_is_held_without_mutation():
    service, repo, runtime, clock = world(); before = deepcopy(repo.rows)
    with pytest.raises(AdmissionHeld): service.require_enrollment('b'*64)
    assert repo.rows == before


def test_open_restart_with_unconfirmed_work_refuses_new_work_until_original_executor_releases():
    service, repo, runtime, clock = world(); original = intent(service); service.admit(original)
    new_runtime = ModelRuntime(repo, number=2)
    repo.rows[RUNTIME] = Row(RUNTIME, 2, {'instance_id':new_runtime.instance_id,'runtime_epoch':1,'inspection_enabled':False})
    successor = PersistentAdmission(new_runtime, limits=service.limits, clock_ms=lambda:clock.value)
    state = successor.require_enrollment('a'*64)
    assert state.phase == 'OPEN' and state.active_count == 1 and state.foreign_active
    with pytest.raises(AdmissionHeld): intent(successor, 11)
    service.release(original)
    successor.admit(intent(successor, 12))


def test_foreign_entry_racing_after_prepare_cannot_be_ignored_by_admit():
    service, repo, runtime, clock = world(); prepared = intent(service)
    foreign = replace(prepared, work_id=ident(11), instance_id=ident(2))
    repo.rows[REGISTRY].data['active'][foreign.work_id] = vars(foreign)
    with pytest.raises(AdmissionHeld): service.admit(prepared)
    assert prepared.work_id not in repo.rows[REGISTRY].data['active']


def owner():
    from proofpack.runtime.ownership import ResourceOwner
    return ResourceOwner()


def test_local_ownership_stop_refuses_new_scopes_without_discarding_existing():
    value = owner(); ticket = value.acquire(); value.stop_accepting()
    with pytest.raises(AdmissionHeld): value.acquire()
    assert not value.wait_for_drain(0)
    value.release(ticket)
    assert value.wait_for_drain(0)


def test_cleanup_waits_for_last_real_scope_and_runs_once_outside_owner_lock():
    value = owner(); first = value.acquire(); second = value.acquire(); called = []
    def cleanup():
        assert value.wait_for_drain(0)
        called.append('closed')
    value.stop_accepting(); value.after_drain(cleanup)
    value.release(first); assert not called
    value.release(second); assert called == ['closed']
    with pytest.raises(ValueError): value.release(second)
    assert called == ['closed']


def test_foreign_ticket_cannot_release_another_owner_scope():
    first = owner(); second = owner(); token = first.acquire()
    with pytest.raises(ValueError): second.release(token)
    assert not first.wait_for_drain(0)
    first.release(token)


def test_no_local_zero_can_reopen_a_stopped_owner():
    value = owner(); value.stop_accepting(); called = []
    value.after_drain(lambda:called.append(1))
    assert called == [1] and value.wait_for_drain(0)
    with pytest.raises(AdmissionHeld): value.acquire()


@pytest.mark.parametrize('duration', [-1, True, 1.5, 300001])
def test_local_drain_wait_has_explicit_bounded_integer_duration(duration):
    with pytest.raises(ValueError): owner().wait_for_drain(duration)


def test_wait_observes_actual_scope_exit_on_another_thread():
    value = owner(); token = value.acquire(); entered = Event(); done = Event()
    def worker():
        entered.set(); value.wait_for_drain(1000); done.set()
    thread = Thread(target=worker); thread.start()
    assert entered.wait(1) and not done.is_set()
    value.release(token); thread.join(1)
    assert not thread.is_alive() and done.is_set()


def test_finished_worker_releases_local_scope_only_after_bookkeeping_attempt():
    from proofpack.evidence.privacy_workers import AdmittedWorker
    service,repo,runtime,clock = world(); local = owner()
    runner = AdmittedWorker(service,lease_ms=500,attempts=3,resource_owner=local)
    release = service.release
    def actual_release(value):
        assert not local.wait_for_drain(0)
        return release(value)
    service.release = actual_release
    assert runner.run(lambda:'finished') == 'finished'
    assert local.wait_for_drain(0) and not repo.rows[REGISTRY].data['active']


def test_deferred_worker_keeps_local_ownership_even_after_reported_future_completion():
    from concurrent.futures import Future
    from proofpack.evidence.privacy_workers import AdmittedWorker
    service,repo,runtime,clock = world(); local = owner(); future = Future()
    runner = AdmittedWorker(service,lease_ms=500,attempts=3,resource_owner=local)
    with pytest.raises(AdmissionHeld): runner.run(lambda:future)
    future.set_result('not a reconciliation proof')
    assert not local.wait_for_drain(0) and repo.rows[REGISTRY].data['active']


def test_termination_during_worker_release_cannot_claim_local_sdk_ownership_ended():
    from proofpack.evidence.privacy_workers import AdmittedWorker
    class Termination(BaseException): pass
    service,repo,runtime,clock = world(); local = owner()
    def interrupted(value): raise Termination()
    service.release = interrupted
    runner = AdmittedWorker(service,lease_ms=500,attempts=3,resource_owner=local)
    with pytest.raises(Termination): runner.run(lambda:'finished')
    assert not local.wait_for_drain(0) and runner.release_pending
