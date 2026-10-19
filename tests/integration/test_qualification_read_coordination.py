"""Local coordination cannot replace durable/fresh authority fences."""
from threading import Event, Thread
import pytest
from test_policy_qualification import qualification, policies, world, repository_factory
from proofpack.evidence.repository import StoreConflict, StoreUnavailable, Write
from proofpack.evidence.erasure import job_key
from proofpack.auth.policy import Denied
from proofpack.planner.activation import qualification_key
from contextlib import contextmanager


def test_metadata_window_excludes_a_local_commit_then_releases_on_exception(qualification):
    service, actor, request, _ = qualification
    entered = Event(); attempted = Event(); failures = []
    def writer():
        attempted.set()
        try:
            with service._metadata_window(actor):
                entered.set()
        except BaseException as exc:
            failures.append(exc)
    with pytest.raises(RuntimeError):
        with service._metadata_window(actor):
            with service._metadata_window(actor):
                thread = Thread(target=writer); thread.start()
                assert attempted.wait(1)
                assert not entered.wait(.05)
                raise RuntimeError('controlled reader failure')
    thread.join(2)
    assert not thread.is_alive() and entered.is_set() and failures == []


def test_external_job_change_during_read_still_conflicts(world, qualification, monkeypatch):
    service, actor, request, _ = qualification
    job = service.create(actor, request=request, idempotency_key='external-progress')
    original = service.access._commit; fired = []
    def commit(writes, checks=()):
        result = original(writes, checks)
        if not fired and any(w.key.resource.startswith('policy-qualification-access#') for w in writes):
            fired.append(True)
            key = job_key(job['id']); row = world[1].snapshot((key,))[key]
            world[1].transact((Write(key, row.revision, {**row.data, 'failure_reason': 'EXTERNAL_CHANGE'}),))
        return result
    monkeypatch.setattr(service.access, '_commit', commit)
    with pytest.raises(StoreConflict):
        service.job(actor, job['id'])
    assert fired


def test_local_window_timeout_does_not_enter_or_renew_authority(qualification, monkeypatch):
    service, actor, _, _ = qualification
    class Busy:
        def __init__(self): self.waits = []; self.released = False
        def acquire(self, *, timeout): self.waits.append(timeout); return False
        def release(self): self.released = True
    gate = Busy(); monkeypatch.setattr(service, '_metadata_lock', gate)
    with pytest.raises(StoreUnavailable):
        with service._metadata_window(actor):
            pytest.fail('busy gate cannot admit work')
    assert gate.waits == [service.config.jobs.lease_ms / 1000] and not gate.released


def test_processing_remains_readable_while_actual_software_executes_outside_gate(qualification, monkeypatch):
    service, actor, request, _ = qualification
    job = service.create(actor, request=request, idempotency_key='read-during-compute')
    executing = Event(); release = Event(); results = []; failures = []
    execute = service._execute
    def paused(*args, **kwargs):
        executing.set()
        assert release.wait(5), 'reader must finish without waiting for software execution'
        return execute(*args, **kwargs)
    monkeypatch.setattr(service, '_execute', paused)
    def advance():
        try:
            results.append(service.advance(actor, job['id'], expected_version=job['state_version'], idempotency_key='actual-step'))
        except BaseException as exc:
            failures.append(exc)
    thread = Thread(target=advance); thread.start()
    try:
        assert executing.wait(5)
        value = service.job(actor, job['id'])
        assert value['status'] == 'processing' and value['current'] and not value['report_current']
        assert value['steps_reserved'] == 1 and value['cases_reserved'] == 170 and not value['can_advance']
    finally:
        release.set(); thread.join(20)
    assert not thread.is_alive() and failures == []
    assert results[0]['steps_prepared'] == 1 and results[0]['cases_reserved'] == 170


def test_local_reservation_cannot_commit_in_a_metadata_window(qualification, monkeypatch):
    service, actor, request, _ = qualification
    job = service.create(actor, request=request, idempotency_key='read-before-reserve')
    attempted = Event(); committed = Event(); failures = []
    original = service.access._record
    def record(*args, **kwargs):
        value = original(*args, **kwargs)
        if args[1].startswith('policy-qualification-step:'):
            committed.set()
        return value
    monkeypatch.setattr(service.access, '_record', record)
    def advance():
        attempted.set()
        try:
            service.advance(actor, job['id'], expected_version=job['state_version'], idempotency_key='reserve-after-read')
        except BaseException as exc:
            failures.append(exc)
    with service._metadata_window(actor):
        thread = Thread(target=advance); thread.start()
        assert attempted.wait(1) and not committed.wait(.05)
        value = service.job(actor, job['id'])
        assert value['status'] == 'queued' and value['steps_reserved'] == 0
    thread.join(20)
    assert not thread.is_alive() and committed.is_set() and failures == []


def test_waiting_before_final_commit_cannot_outlive_the_original_case_deadline(world, qualification, monkeypatch):
    service, actor, request, _ = qualification
    job = service.create(actor, request=request, idempotency_key='wait-before-commit')
    original_window = service._metadata_window; original_execute = service._execute
    executed = []; expired = []
    def execute(*args, **kwargs):
        value = original_execute(*args, **kwargs)
        executed.append(True)
        return value
    @contextmanager
    def window(current):
        with original_window(current):
            if executed and not expired:
                expired.append(True)
                world[2].value = service._row(job['id']).data['expires_at_ms']
            yield
    monkeypatch.setattr(service, '_execute', execute)
    monkeypatch.setattr(service, '_metadata_window', window)
    with pytest.raises((Denied, StoreUnavailable, StoreConflict)):
        service.advance(actor, job['id'], expected_version=job['state_version'], idempotency_key='expired-at-commit')
    row = service._row(job['id'])
    assert executed and expired and row.data['processed'] == 0
    assert row.data['steps_reserved'] == 1 and row.data['cases_reserved'] == 170
    assert world[1].snapshot((qualification_key(job['id']),))[qualification_key(job['id'])] is None


@pytest.mark.parametrize('remaining', [0, 500])
def test_local_wait_is_capped_by_the_original_session(world, qualification, monkeypatch, remaining):
    service, actor, _, _ = qualification
    waits = []
    class Busy:
        def acquire(self, *, timeout): waits.append(timeout); return False
        def release(self): pytest.fail('an unacquired lock cannot be released')
    monkeypatch.setattr(service, '_metadata_lock', Busy())
    world[2].value = int(actor.session.data['expires_at_ms']) - remaining
    with pytest.raises(Denied if remaining == 0 else StoreUnavailable):
        with service._metadata_window(actor):
            pytest.fail('expired or busy session cannot admit work')
    assert waits == ([] if remaining == 0 else [.5])
