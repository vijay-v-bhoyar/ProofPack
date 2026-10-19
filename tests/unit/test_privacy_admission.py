"""Protocol model tests; no ASGI coverage, provider authentication or actual drain proof."""
from copy import deepcopy
from dataclasses import replace
from threading import RLock
from types import SimpleNamespace
from uuid import UUID

import pytest

from proofpack.evidence.repository import Key, Row, StoreConflict, StoreUnavailable
from proofpack.evidence.privacy_admission import (
    PersistentAdmission, AdmissionLimits, AdmissionHeld, GATE, REGISTRY,
)
from proofpack.auth.service import RUNTIME


def ident(number): return str(UUID(int=number))


class ModelRepository:
    """In-memory optimistic transaction model, deliberately not a DynamoDB substitute."""
    deployment = 'synthetic'
    tables = {'state': 'synthetic-state', 'events': 'synthetic-events'}
    def __init__(self):
        self.client = object(); self.rows = {}; self.lock = RLock(); self.before_commit = None; self.lose_reply = False
    def snapshot(self, keys):
        with self.lock: return {key: deepcopy(self.rows.get(key)) for key in keys}
    def transact(self, writes, checks=()):
        with self.lock:
            if self.before_commit:
                callback = self.before_commit; self.before_commit = None; callback()
            for row in checks:
                if self.rows.get(row.key) != row: raise StoreConflict('model source changed')
            for write in writes:
                current = self.rows.get(write.key)
                if (None if current is None else current.revision) != write.expected_revision:
                    raise StoreConflict('model revision changed')
            for write in writes:
                self.rows[write.key] = Row(write.key, 1 if write.expected_revision is None else write.expected_revision+1, deepcopy(write.data))
            if self.lose_reply:
                self.lose_reply = False; raise StoreUnavailable('synthetic lost reply')


class ModelRuntime:
    def __init__(self, repo, number=1): self.repository = repo; self.instance_id = ident(number)
    def matches(self, row):
        return row is not None and row.data['instance_id'] == self.instance_id and row.data['runtime_epoch'] == 1


def world(*, capacity=3, initialized=True):
    repo = ModelRepository(); runtime = ModelRuntime(repo); clock = SimpleNamespace(value=100)
    repo.rows[RUNTIME] = Row(RUNTIME, 1, {'instance_id': runtime.instance_id, 'runtime_epoch': 1, 'inspection_enabled': False})
    service = PersistentAdmission(runtime, limits=AdmissionLimits(capacity, 1000), clock_ms=lambda: clock.value)
    if initialized: service.initialize('a'*64)
    return service, repo, runtime, clock


def intent(service, number=10, kind='http', duration=500):
    return service.prepare(work_id=ident(number), kind=kind, lease_ms=duration)


def hold(service): return service.hold(request_id=ident(90), scope_sha256='b'*64)


def test_explicit_initialization_never_resets_an_existing_hold():
    service, repo, runtime, clock = world(initialized=False)
    with pytest.raises(AdmissionHeld): intent(service)
    first = service.initialize('a'*64); assert first == service.initialize('a'*64)
    hold(service); original = deepcopy(repo.rows)
    service.initialize('a'*64)
    assert repo.rows == original and repo.rows[GATE].data['phase'] == 'HELD'
    with pytest.raises(AdmissionHeld): service.initialize('c'*64)


def test_admission_retry_does_not_renew_and_release_is_bookkeeping_only():
    service, repo, runtime, clock = world()
    work = intent(service); first = service.admit(work); version = repo.rows[REGISTRY].revision
    clock.value += 100
    assert service.admit(work) == first and repo.rows[REGISTRY].revision == version
    service.checkpoint(work)
    assert service.release(work) is True and service.release(work) is False
    with pytest.raises(AdmissionHeld): service.checkpoint(work)
    assert repo.rows[GATE].data['phase'] == 'OPEN'


def test_hold_denies_new_work_and_existing_checkpoint_until_actual_release():
    service, repo, runtime, clock = world()
    work = intent(service); service.admit(work); prepared = intent(service, 11)
    receipt = hold(service)
    assert hold(service) == receipt
    with pytest.raises(AdmissionHeld): service.admit(prepared)
    with pytest.raises(AdmissionHeld): service.checkpoint(work)
    with pytest.raises(AdmissionHeld): service.drained(request_id=ident(90), scope_sha256='b'*64)
    service.release(work)
    proof = service.drained(request_id=ident(90), scope_sha256='b'*64)
    rows = service.assert_drained(proof)
    assert {row.key for row in rows} == {GATE, REGISTRY, RUNTIME}
    assert 'active' not in repr(proof)


def test_expiry_never_removes_unconfirmed_active_work_or_reopens_gate():
    service, repo, runtime, clock = world()
    work = intent(service); service.admit(work); hold(service); clock.value = 100000
    with pytest.raises(AdmissionHeld): service.drained(request_id=ident(90), scope_sha256='b'*64)
    with pytest.raises(AdmissionHeld): service.admit(work)
    assert ident(10) in repo.rows[REGISTRY].data['active']
    assert service.release(work) is True  # Executor has now ended; not a fresh work permission.
    service.assert_drained(service.drained(request_id=ident(90), scope_sha256='b'*64))


def test_gate_condition_fences_an_admission_racing_hold():
    service, repo, runtime, clock = world(); work = intent(service)
    repo.before_commit = lambda: hold(service)
    with pytest.raises((AdmissionHeld, StoreConflict)): service.admit(work)
    assert repo.rows[REGISTRY].data['active'] == {}
    service.assert_drained(service.drained(request_id=ident(90), scope_sha256='b'*64))


@pytest.mark.parametrize('operation', ['initialize', 'admit', 'hold', 'release'])
def test_lost_confirmation_reconciles_original_state_without_replacement(operation):
    service, repo, runtime, clock = world(initialized=operation != 'initialize')
    work = intent(service) if operation != 'initialize' else None
    if operation == 'release': service.admit(work)
    repo.lose_reply = True
    if operation == 'initialize': service.initialize('a'*64)
    elif operation == 'admit': assert service.admit(work) == work
    elif operation == 'hold': hold(service)
    else: service.release(work)
    active = repo.rows[REGISTRY].data['active']
    assert len(active) == (1 if operation == 'admit' else 0)


def test_capacity_is_bounded_and_an_original_intent_cannot_extend_its_deadline():
    service, repo, runtime, clock = world(capacity=1)
    first = intent(service); service.admit(first)
    with pytest.raises(AdmissionHeld): service.admit(intent(service, 11))
    with pytest.raises(AdmissionHeld): service.admit(replace(first, expires_at_ms=first.expires_at_ms+1))
    clock.value = first.expires_at_ms
    with pytest.raises(AdmissionHeld): service.admit(first)
    assert len(repo.rows[REGISTRY].data['active']) == 1


def test_restart_retains_old_work_and_cannot_release_someone_elses_admission():
    service, repo, runtime, clock = world(); work = intent(service); service.admit(work); hold(service)
    successor = ModelRuntime(repo, 2)
    repo.rows[RUNTIME] = Row(RUNTIME, 2, {'instance_id': successor.instance_id, 'runtime_epoch': 1, 'inspection_enabled': False})
    restarted = PersistentAdmission(successor, limits=AdmissionLimits(3, 1000), clock_ms=lambda: clock.value)
    restarted.initialize('a'*64)
    with pytest.raises(AdmissionHeld): restarted.release(work)
    with pytest.raises(AdmissionHeld): restarted.drained(request_id=ident(90), scope_sha256='b'*64)
    service.release(work)  # Original executor acknowledges its actual completion after supersession.
    restarted.assert_drained(restarted.drained(request_id=ident(90), scope_sha256='b'*64))


@pytest.mark.parametrize('changed', ['gate', 'registry', 'runtime'])
def test_any_drain_proof_source_change_holds(changed):
    service, repo, runtime, clock = world(); hold(service)
    proof = service.drained(request_id=ident(90), scope_sha256='b'*64)
    key = {'gate': GATE, 'registry': REGISTRY, 'runtime': RUNTIME}[changed]
    row = repo.rows[key]; repo.rows[key] = Row(key, row.revision+1, row.data)
    with pytest.raises(AdmissionHeld): service.assert_drained(proof)


@pytest.mark.parametrize('fault', ['missing_registry', 'gate_extra', 'unknown_phase', 'configuration', 'registry_extra', 'bool_epoch', 'active_wrong_key'])
def test_unsupported_or_partial_state_never_creates_permission(fault):
    service, repo, runtime, clock = world()
    if fault == 'missing_registry': del repo.rows[REGISTRY]
    elif fault == 'gate_extra': repo.rows[GATE].data['extra'] = 'PRIVATE'
    elif fault == 'unknown_phase': repo.rows[GATE].data['phase'] = 'UNKNOWN'
    elif fault == 'configuration': repo.rows[GATE].data['configuration_sha256'] = 'c'*64
    elif fault == 'registry_extra': repo.rows[REGISTRY].data['extra'] = True
    elif fault == 'bool_epoch': repo.rows[GATE].data['epoch'] = True
    elif fault == 'active_wrong_key': repo.rows[REGISTRY].data['active'][ident(88)] = {'work_id': ident(87)}
    with pytest.raises(AdmissionHeld) as error: intent(service)
    assert 'PRIVATE' not in str(error.value)


@pytest.mark.parametrize('field,value', [('max_active', 0), ('max_active', 65), ('max_active', True),
    ('max_lease_ms', 0), ('max_lease_ms', 300001), ('max_lease_ms', False)])
def test_explicit_supported_limits(field, value):
    kwargs = {'max_active': 3, 'max_lease_ms': 1000}; kwargs[field] = value
    with pytest.raises(ValueError): AdmissionLimits(**kwargs)


@pytest.mark.parametrize('fault', ['client', 'table', 'backwards', 'bool_clock', 'enabled_hold'])
def test_target_clock_and_disabled_runtime_are_required(fault):
    service, repo, runtime, clock = world()
    if fault == 'client': repo.client = object()
    elif fault == 'table': repo.tables = {**repo.tables, 'state': 'other'}
    elif fault == 'backwards': clock.value = 99
    elif fault == 'bool_clock': clock.value = True
    elif fault == 'enabled_hold': repo.rows[RUNTIME].data['inspection_enabled'] = True
    with pytest.raises(AdmissionHeld): hold(service) if fault == 'enabled_hold' else intent(service)


def test_successor_clock_skew_cannot_persist_an_unreadable_hold():
    service, repo, runtime, clock = world()
    clock.value = 200; work = intent(service); service.admit(work)
    successor = ModelRuntime(repo, 2)
    repo.rows[RUNTIME] = Row(RUNTIME, 2, {'instance_id': successor.instance_id, 'runtime_epoch': 1, 'inspection_enabled': False})
    restarted = PersistentAdmission(successor, limits=AdmissionLimits(3, 1000), clock_ms=lambda: 150)
    with pytest.raises(AdmissionHeld): hold(restarted)
    assert repo.rows[GATE].data['phase'] == 'OPEN'
    assert service.release(work) is True  # A failed hold must not make actual completion unrecordable.


@pytest.mark.parametrize('field', ['epoch', 'registry_revision', 'runtime_revision'])
def test_bool_equality_is_not_an_exact_drain_proof_version(field):
    service, repo, runtime, clock = world(); hold(service)
    proof = service.drained(request_id=ident(90), scope_sha256='b'*64)
    if field == 'epoch': forged = replace(proof, epoch=True)
    elif field == 'registry_revision': forged = replace(proof, registry=replace(proof.registry, revision=True))
    else: forged = replace(proof, runtime=replace(proof.runtime, revision=True))
    with pytest.raises(AdmissionHeld): service.assert_drained(forged)


def test_valid_admission_before_hold_commit_stays_releasable_across_clock_skew():
    service, repo, runtime, clock = world(); clock.value = 150
    competitor = PersistentAdmission(runtime, limits=AdmissionLimits(3, 1000), clock_ms=lambda: 200)
    work = intent(competitor)
    repo.before_commit = lambda: competitor.admit(work)
    hold(service)  # Admission commits before the gate closes, despite differing wall times.
    with pytest.raises(AdmissionHeld): service.drained(request_id=ident(90), scope_sha256='b'*64)
    assert competitor.release(work) is True
    service.assert_drained(service.drained(request_id=ident(90), scope_sha256='b'*64))
