"""Owner lost-reference recovery using actual auth/gate services and a modeled store."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from test_owner_metadata import world, create, cancel, no_sdk
from proofpack.auth.policy import Denied
from proofpack.auth.service import RUNTIME
from proofpack.evidence.owner_metadata import OwnerMetadataRequests, OwnerMetadataLimits, OwnerMetadataLimited, request_key
from proofpack.evidence.privacy_admission import GATE, AdmissionHeld
from proofpack.evidence.repository import StoreConflict, StoreUnavailable
from proofpack.runtime.control import DATA


def assert_closed(value, state):
    assert set(value) == {'status', 'request', 'unknown_writes_reconciled', 'inspection_resumption_authorized',
                          'can_confirm_cleanup', 'erasure_complete', 'request_fulfilled'}
    assert value['status'] == state
    for field in ['unknown_writes_reconciled', 'inspection_resumption_authorized', 'can_confirm_cleanup', 'erasure_complete', 'request_fulfilled']:
        assert value[field] is False


def test_open_gate_reports_only_current_absence_without_mutation_or_fulfillment():
    service, actor, repo, _, owner, _ = world(); before = deepcopy(repo.rows)
    result = service.recover_current(actor)
    assert_closed(result, 'open'); assert result['request'] is None
    assert repo.rows == before and owner.wait_for_drain(0)


def test_held_request_is_discovered_from_durable_gate_without_saved_id_or_writes():
    service, actor, repo, _, owner, _ = world(); created = create(service, actor)
    expected = service.get(actor, created['id']); before = deepcopy(repo.rows); reads = service._read_count
    result = service.recover_current(actor)
    assert_closed(result, 'held'); assert result['request'] == expected
    assert result['request']['id'] == created['id'] and result['request']['current_hold']
    assert repo.rows == before and service._read_count == reads + 1 and owner.wait_for_drain(0)
    assert 'DO_NOT_DISCLOSE' not in repr(result)


def test_fresh_owner_session_recovers_without_claiming_original_session_or_write_reconciliation():
    service, actor, repo, _, owner, proof = world(); first = create(service, actor)
    credentials = service.access.login(proof); fresh = service.access.resolve(credentials.cookie)
    before = deepcopy(repo.rows); value = service.recover_current(fresh)
    assert value['request']['id'] == first['id'] and value['request']['original_owner_session'] is False
    assert value['unknown_writes_reconciled'] is False and repo.rows == before and owner.wait_for_drain(0)


@pytest.mark.parametrize('fault', ['session', 'membership', 'mfa'])
def test_current_hold_recovery_requires_existing_fresh_owner_authority(fault):
    service, actor, repo, clock, owner, _ = world(); create(service, actor)
    if fault == 'session': repo.rows.pop(actor.session.key)
    elif fault == 'membership': repo.rows[actor.member.key] = replace(actor.member, data={**actor.member.data, 'roles': ['operator']})
    else: clock.value += 600001
    before = deepcopy(repo.rows)
    with pytest.raises(Denied): service.recover_current(actor)
    assert repo.rows == before and owner.wait_for_drain(0)


@pytest.mark.parametrize('fault', ['missing', 'scope', 'cancelled', 'foreign-id'])
def test_unprovable_gate_to_request_link_is_held_without_partial_record(fault):
    service, actor, repo, _, owner, _ = world(); first = create(service, actor); key = request_key(first['id'])
    if fault == 'missing': repo.rows.pop(key)
    elif fault == 'scope': repo.rows[key] = replace(repo.rows[key], data={**repo.rows[key].data, 'scope_sha256': 'f' * 64})
    elif fault == 'cancelled': repo.rows[key] = replace(repo.rows[key], data={**repo.rows[key].data, 'status': 'cancelled'})
    else: repo.rows[GATE] = replace(repo.rows[GATE], data={**repo.rows[GATE].data, 'request_id': '00000000-0000-0000-0000-000000000099'})
    before = deepcopy(repo.rows)
    with pytest.raises((AdmissionHeld, StoreConflict, StoreUnavailable, ValueError)): service.recover_current(actor)
    assert repo.rows == before and owner.wait_for_drain(0)


@pytest.mark.parametrize('which', ['gate', 'owner', 'data'])
def test_sources_changed_at_final_delivery_cannot_return_success(which, monkeypatch):
    service, actor, repo, _, owner, _ = world(); create(service, actor)
    original = service._checked_delivery
    def changed(current, rows):
        key = {'gate': GATE, 'owner': actor.member.key, 'data': DATA}[which]
        row = repo.rows[key]; repo.rows[key] = replace(row, revision=row.revision + 1)
        return original(current, rows)
    monkeypatch.setattr(service, '_checked_delivery', changed)
    with pytest.raises((Denied, StoreConflict, AdmissionHeld)): service.recover_current(actor)
    assert owner.wait_for_drain(0)


def test_cancelled_prior_request_does_not_reappear_as_a_current_hold():
    service, actor, repo, _, owner, _ = world(); first = create(service, actor); cancel(service, actor, first)
    before = deepcopy(repo.rows); result = service.recover_current(actor)
    assert_closed(result, 'open'); assert result['request'] is None
    assert request_key(first['id']) in repo.rows and repo.rows == before and owner.wait_for_drain(0)


def test_current_recovery_consumes_original_read_allowance_without_storage_write():
    original, actor, repo, _, owner, _ = world()
    service = OwnerMetadataRequests(original.access, original.admission, owner,
        limits=OwnerMetadataLimits(10, 20, 1, 20000), tick_ns=lambda: 1)
    before = deepcopy(repo.rows); assert service.recover_current(actor)['status'] == 'open'
    with pytest.raises(OwnerMetadataLimited): service.recover_current(actor)
    assert repo.rows == before and owner.wait_for_drain(0)


def test_original_deadline_is_not_reset_during_recovery(monkeypatch):
    original, actor, repo, _, owner, _ = world(); ticks = SimpleNamespace(value=1)
    service = OwnerMetadataRequests(original.access, original.admission, owner, limits=original.limits, tick_ns=lambda: ticks.value)
    snapshot = repo.snapshot
    def late(keys):
        result = snapshot(keys); ticks.value = 20_000_000_001; return result
    monkeypatch.setattr(repo, 'snapshot', late); before = deepcopy(repo.rows)
    with pytest.raises(AdmissionHeld): service.recover_current(actor)
    assert repo.rows == before and owner.wait_for_drain(0)


def test_unknown_previous_completion_prevents_new_recovery_admission():
    service, actor, repo, _, owner, _ = world(); service.release_pending = True; before = deepcopy(repo.rows)
    with pytest.raises(AdmissionHeld): service.recover_current(actor)
    assert repo.rows == before and owner.wait_for_drain(0)


@pytest.mark.parametrize('expired', [False, True])
def test_current_request_remains_readable_while_registered_business_work_is_unconfirmed(expired):
    service, actor, repo, clock, owner, _ = world()
    work = service.admission.prepare(work_id='00000000-0000-0000-0000-000000000080', kind='http', lease_ms=100)
    service.admission.admit(work); created = create(service, actor)
    if expired: clock.value += 101
    before = deepcopy(repo.rows); result = service.recover_current(actor)
    assert_closed(result, 'held'); assert result['request']['id'] == created['id']
    assert result['request']['active_count'] == 1 and result['request']['drain_status'] == 'waiting'
    assert result['request']['can_cancel'] is False and repo.rows == before
    # Local release does not discharge the still-registered business executor.
    assert owner.wait_for_drain(0)
