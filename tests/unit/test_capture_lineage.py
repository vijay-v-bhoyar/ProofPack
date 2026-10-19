"""Synthetic stored-shape graphs; not capture, provider, or physical proof."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from uuid import UUID
import pytest

from proofpack.evidence.capture_lineage import discover, CaptureDiscoveryHeld, OBSERVATION, COMPLETED
from proofpack.evidence.repository import Key, Row, Write, ErasureMarker
from proofpack.evidence.resource_bindings import prepare_linked
from proofpack.capture.provenance import inspection_context
from proofpack.calibrations.dependencies import digest
from proofpack.vision.worker_result import WorkerResult
from proofpack.verifier.core import Finding
from proofpack.planner.policy import TEMPLATES, ActionKind


DEPLOYMENT = 'capture-family-unit'
def uid(number):return str(UUID(int=number))
def key(prefix, number, table='state'):return Key(table, prefix + '#' + uid(number))


def event(number, operation, data, writes, checks=()):
    target = key('access' if operation.startswith('action-ack:') else 'capture', number, 'events')
    frozen, _ = prepare_linked(DEPLOYMENT, operation, (*writes, Write(target, None, {'kind': operation, **data})), checks)
    return Row(target, 1, next(value.data for value in frozen if value.key == target))


def family(*,recipe_id='fixture-recipe'):
    policy = {'policy_id': uid(20), 'policy_revision': 1, 'policy_revision_sha256': '1'*64,
        'behavior_sha256': '2'*64, 'activation_id': uid(21), 'activation_sha256': '3'*64,
        'qualification_id': uid(22), 'qualification_report_sha256': '4'*64}
    head = {'id': uid(1), 'station_id': uid(2), 'station_epoch': 1, 'kit_id': 'synthetic-kit',
        'recipe_id': recipe_id, 'recipe_revision': 1, 'calibration_profile_id': 'synthetic-mat', 'artifact_sha256': 'e'*64, 'recipe_active_version': 1, 'calibration_state_version': 1, 'policy_state_version': 1,
        'policy_provenance': policy, 'runtime_epoch': 1, 'runtime_instance_id': uid(4), 'control_version': 1,
        'data_epoch': 1, 'originating_session_id': uid(5), 'originating_user_id': uid(6), 'originating_access_version': 1,
        'state': 'CLOSED', 'created_at_ms': 10, 'closed_at_ms': 100, 'deadline_tick_ns': 0,
        'pending_sequence': None, 'latest_input_sequence': 1, 'verified_sequence': 1, 'corrections': 0,
        'latest_observation_id': uid(8)}
    root = Row(key('inspection', 1), 10, head)
    permit = Row(key('capture-permit', 7), 2, {'id': uid(7), 'inspection_id': uid(1), 'station_id': uid(2),
        'station_epoch': 1, 'runtime_instance_id': uid(4), 'runtime_epoch': 1, 'sequence': 1,
        'nonce_sha256': '5'*64, 'status': 'consumed', 'policy_provenance': policy, 'issued_tick_ns': 10,
        'issued_at_ms': 10, 'expires_tick_ns': 100, 'observation_deadline_tick_ns': 90, 'observation_id': uid(8)})
    result = WorkerResult(candidates=(), findings=(Finding.SATISFIED,), reason_codes=(), quality_ok=True,
        unknown_regions=0, scene_generation=1, scene_changed=False, source_sha256='a'*64, calibration_hash='b'*64)
    ob = {'id': uid(8), 'inspection_id': uid(1), 'permit_id': uid(7), 'sequence': 1, 'status': 'completed',
        'station_id': uid(2), 'station_epoch': 1, 'runtime_epoch': 1, 'originating_session_id': uid(5),
        'policy_provenance': policy, 'accepted_tick_ns': 20, 'permit_issued_tick_ns': 10, 'accepted_at_ms': 20,
        'source_sha256': 'a'*64, 'byte_length': 200, 'runtime_instance_id': uid(4), 'observation_deadline_tick_ns': 90,
        'worker_id': uid(11), 'result_json': result.model_dump_json(), 'asset_id': uid(8), 'evidence_sha256': 'c'*64,
        'completed_at_ms': 40}
    ob['context_sha256'] = digest(inspection_context(head, 1, ob))
    observation = Row(key('observation', 8), 3, ob)
    asset = Row(key('asset', 8), 1, {'storage_binding_sha256': 'd'*64, 'id': uid(8), 'status': 'committed',
        'read_denied': False, 'sha256': 'c'*64, 'input_sha256': 'a'*64, 'context_sha256': ob['context_sha256'],
        'object_key': 'deployments/' + DEPLOYMENT + '/frames/' + uid(8), 'object_version': 'version-1',
        'byte_length': 100, 'content_type': 'image/jpeg', 'purpose_id': uid(12), 'expires_at_ms': 1000,
        'data_origin': 'synthetic', 'observation_id': uid(8), 'derivation': 'rectified_roi_jpeg'})
    intent = Row(key('object-intent', 8), 3, {'observation_id': uid(8), 'asset_id': uid(8), 'status': 'linked',
        'key': asset.data['object_key'], 'source_sha256': 'a'*64, 'crop_sha256': 'c'*64,
        'context_sha256': ob['context_sha256'], 'purpose_id': uid(12), 'user_id': uid(6), 'created_at_ms': 30,
        'storage_binding_sha256': 'd'*64, 'version_id': 'version-1'})
    admission = event(9, 'observation_admitted', {'inspection_id': uid(1), 'observation_id': uid(8),
        'sequence': 1, 'source_sha256': 'a'*64, 'at_ms': 20},
        (Write(root.key, 1, {**head, 'state': 'OBSERVING'}), Write(permit.key, 1, permit.data),
         Write(observation.key, None, {k: v for k, v in ob.items() if k in OBSERVATION} | {'status': 'admitted'})),
        checks=(Row(key('purpose',12),1,{'allowed_uses':['operation']}),))
    terminal = event(10, 'observation_completed', {'inspection_id': uid(1), 'observation_id': uid(8), 'sequence': 1,
        'asset_id': uid(8), 'input_sha256': 'a'*64, 'crop_sha256': 'c'*64, 'state': 'OBSERVING', 'action_id': None,
        'at_ms': 40, 'policy_state_version': 1, 'policy_provenance': policy},
        (Write(root.key, 6, {**head, 'state': 'OBSERVING'}), Write(observation.key, 2, ob),
         Write(asset.key, None, asset.data), Write(intent.key, 2, intent.data)))
    return root, (permit, observation, asset, intent, admission, terminal)


def call(root, rows, **changes):
    return discover(root, rows, **({'deployment': DEPLOYMENT, 'max_records': 1000, 'max_payload_bytes': 1000000} | changes))


def edit(rows, prefix, **changes):
    return tuple(replace(r, data={**r.data, **changes}) if r.key.resource.startswith(prefix + '#') else r for r in rows)


def failed(status='failed', intent_status=None):
    root, rows = family(); root = replace(root, data={**root.data, 'latest_observation_id': None, 'verified_sequence': 0,
        'pending_observation_id': uid(8) if status == 'discarded' else None})
    observation = next(r for r in rows if r.key.resource.startswith('observation#'))
    data = {k: v for k, v in observation.data.items() if k not in COMPLETED}
    data.update(status=status, failure_reason='evidence_unavailable', failed_at_ms=120 if status == 'discarded' else 50)
    observation = replace(observation, revision=2, data=data)
    terminal = event(10, 'observation_failed', {'inspection_id': uid(1), 'observation_id': uid(8),
        'status': status, 'reason': data['failure_reason'], 'at_ms': data['failed_at_ms']},
        (Write(observation.key, 1, data), *((Write(root.key, 6, root.data),) if status == 'failed' else ())))
    selected = [r for r in rows if not r.key.resource.startswith(('observation#', 'asset#', 'object-intent#')) and r.key != terminal.key]
    selected.extend((observation, terminal))
    if intent_status:
        intent = next(r for r in rows if r.key.resource.startswith('object-intent#'))
        data = {**intent.data, 'status': intent_status}
        if intent_status == 'reserved':data.pop('version_id')
        selected.append(replace(intent, revision=1 if intent_status == 'reserved' else 2, data=data))
    return root, tuple(selected)


def action_family(acknowledged=False):
    root, rows = family(); root = replace(root, data={**root.data, 'corrections': 1,
        'current_action_id': None if acknowledged else uid(13)})
    rows = edit(rows, 'observation', result_json=WorkerResult(candidates=(), findings=(Finding.VIOLATED,), reason_codes=('missing',), quality_ok=True, unknown_regions=0, scene_generation=1, scene_changed=False, source_sha256='a'*64, calibration_hash='b'*64).model_dump_json())
    data = {'id': uid(13), 'kind': 'RECAPTURE', 'observation_id': uid(8), 'scene_generation': 1,
        'source_machine_version': 2, 'status': 'pending', 'message': TEMPLATES[ActionKind.RECAPTURE],
        'target_candidate_indices': [], 'policy_state_version': 1, 'policy_provenance': root.data['policy_provenance']}
    action = Row(key('action', 13), 1, data)
    previous = next(r for r in rows if r.key == key('capture', 10, 'events'))
    event_data = {k: v for k, v in previous.data.items() if k not in {'kind', 'resource_bindings'}}
    event_data.update(action_id=uid(13), state='ACTION_REQUIRED')
    observed = next(r for r in rows if r.key.resource.startswith('observation#'))
    asset = next(r for r in rows if r.key.resource.startswith('asset#')); intent = next(r for r in rows if r.key.resource.startswith('object-intent#'))
    terminal = event(10, 'observation_completed', event_data,
        (Write(root.key, 6, root.data), Write(observed.key, 2, observed.data), Write(asset.key, None, asset.data),
         Write(intent.key, 2, intent.data), Write(action.key, None, data)))
    values = [r for r in rows if r.key != previous.key]
    if acknowledged:
        action = replace(action, revision=2, data={**data, 'status': 'acknowledged'})
        values.append(event(14, 'action-ack:' + uid(1) + ':' + uid(13), {'actor_scope': 'user:' + uid(6),
            'at_ms': 60, 'session_id': uid(5), 'details': {'inspection_id': uid(1), 'action_id': uid(13), 'observation_id': uid(8)}},
            (Write(root.key, 7, root.data), Write(action.key, 1, action.data))))
    return root, (*values, action, terminal)


def test_complete_crop_family_is_detached_bounded_sorted_and_contains_no_payload():
    root, rows = family(); before = deepcopy((root, rows)); result = call(root, rows)
    assert len(result.records) == 6 and len(result.media) == 2 and len(result.links) == 7
    assert result == call(root, tuple(reversed(rows))) and (root, rows) == before
    assert all(not hasattr(r, 'data') for r in result.records)
    assert 'deployments/' not in repr(result) and 'result_json' not in repr(result)
    with pytest.raises(FrozenInstanceError):result.payload_bytes = 0
    root.data['kit_id'] = 'later-change'
    assert result.inspection.sha256 != digest(root.data)


@pytest.mark.parametrize('acknowledged', [False, True])
def test_historical_pending_and_acknowledged_actions_are_owned_without_current_pointer(acknowledged):
    root, rows = action_family(acknowledged); result = call(root, rows)
    assert sum(l.kind == 'issued_action' for l in result.links) == 1
    assert sum(l.kind == 'acknowledgment' for l in result.links) == int(acknowledged)


@pytest.mark.parametrize('status', ['failed', 'discarded'])
@pytest.mark.parametrize('intent_status', [None, 'reserved', 'uploaded'])
def test_terminal_failures_account_for_partial_effects_and_historical_closed_pointers(status, intent_status):
    root, rows = failed(status, intent_status); result = call(root, rows)
    assert len(result.media) == int(intent_status is not None)
    assert not any(r.key.resource.startswith('asset#') for r in result.records)


@pytest.mark.parametrize('status', ['issued', 'expired'])
def test_unused_permits_are_retained_even_after_root_closed(status):
    root, rows = family(); old = rows[0]
    data = {**old.data, 'id': uid(15), 'status': status, 'sequence': 2}; data.pop('observation_id')
    permit = Row(key('capture-permit', 15), 1 if status == 'issued' else 2, data)
    root = replace(root, data={**root.data, 'pending_permit_id': uid(15)})
    assert len(call(root, (*rows, permit)).records) == 7


def test_empty_closed_capture_family_is_valid_only_with_empty_head_counts_and_pointers():
    root, _ = family(); root = replace(root, data={**root.data, 'latest_input_sequence': 0, 'verified_sequence': 0, 'latest_observation_id': None})
    assert call(root, ()).records == ()


def test_independent_record_and_payload_bounds_accept_exact_boundary_then_hold():
    root, rows = family(); result = call(root, rows)
    assert call(root, rows, max_records=7, max_payload_bytes=result.payload_bytes) == result
    for changes in ({'max_records': 6}, {'max_payload_bytes': result.payload_bytes-1}):
        with pytest.raises(CaptureDiscoveryHeld):call(root, rows, **changes)


@pytest.mark.parametrize('field', ['max_records', 'max_payload_bytes'])
@pytest.mark.parametrize('value', [0, -1, True, 1.0, '10', None, 2**63])
def test_limits_are_explicit_positive_exact_bounded_integers(field, value):
    with pytest.raises(ValueError):call(*family(), **{field: value})


@pytest.mark.parametrize('deployment', ['', '../foreign', 'foreign target', None])
def test_deployment_identity_must_be_explicit_and_supported(deployment):
    with pytest.raises(ValueError):call(*family(), deployment=deployment)


@pytest.mark.parametrize('prefix', ['capture-permit', 'observation', 'asset', 'object-intent', 'capture'])
def test_missing_entire_family_or_peer_cannot_be_partial_success(prefix):
    root, rows = family()
    with pytest.raises(CaptureDiscoveryHeld):call(root, tuple(r for r in rows if not r.key.resource.startswith(prefix + '#')))


@pytest.mark.parametrize('field,value', [('state', 'OBSERVING'), ('latest_input_sequence', 2**63-1),
    ('deadline_tick_ns', 1), ('pending_sequence', 1), ('latest_observation_id', uid(99)),
    ('pending_permit_id', uid(99)), ('pending_observation_id', uid(99)), ('current_action_id', uid(99)),
    ('original_attempts_reserved', 1), ('original_asset_ids', [uid(99)]), ('corrections', 1)])
def test_inconsistent_root_or_active_work_is_held(field, value):
    root, rows = family(); root = replace(root, data={**root.data, field: value})
    with pytest.raises(CaptureDiscoveryHeld):call(root, rows)


@pytest.mark.parametrize('prefix,field,value', [
    ('capture-permit', 'inspection_id', uid(99)), ('capture-permit', 'station_epoch', 2),
    ('capture-permit', 'observation_id', uid(99)), ('capture-permit', 'status', 'issued'),
    ('observation', 'status', 'processing'), ('observation', 'sequence', 2), ('observation', 'permit_id', uid(99)),
    ('observation', 'originating_session_id', uid(99)), ('observation', 'context_sha256', 'f'*64),
    ('observation', 'source_sha256', 'f'*64), ('observation', 'result_json', '{}'),
    ('observation', 'original_asset_id', uid(99)), ('observation', 'completed_at_ms', 101),
    ('asset', 'storage_binding_sha256', 'f'*64), ('asset', 'purpose_id', uid(99)),
    ('asset', 'object_version', 'foreign'), ('asset', 'data_origin', 'unknown'), ('asset', 'status', 'unknown'),
    ('asset', 'input_sha256', 'f'*64), ('asset', 'content_type', 'text/plain'),
    ('object-intent', 'user_id', uid(99)), ('object-intent', 'key', 'deployments/foreign/frames/' + uid(8)),
    ('object-intent', 'status', 'uploaded'), ('object-intent', 'crop_sha256', 'f'*64),
    ('object-intent', 'storage_binding_sha256', 'bad'), ('object-intent', 'version_id', 'null'),
])
def test_known_schema_identity_provenance_and_target_corruption_hold(prefix, field, value):
    root, rows = family()
    with pytest.raises(CaptureDiscoveryHeld):call(root, edit(rows, prefix, **{field: value}))


@pytest.mark.parametrize('prefix', ['capture-permit', 'observation', 'asset', 'object-intent', 'capture'])
def test_unknown_schema_extensions_do_not_silently_join_supported_family(prefix):
    root, rows = family()
    with pytest.raises(CaptureDiscoveryHeld):call(root, edit(rows, prefix, schema_version=99))


@pytest.mark.parametrize('fault', ['duplicate', 'unknown_family', 'erased', 'wrong_table', 'revision_zero', 'revision_overflow', 'revision_bool'])
def test_unreconciled_or_malformed_inventory_rows_hold(fault):
    root, rows = family(); row = rows[0]
    if fault == 'duplicate':rows = (*rows, row)
    elif fault == 'unknown_family':rows = (*rows, Row(key('unknown', 99), 1, {}))
    elif fault == 'erased':rows = (ErasureMarker(row.key, 3, 'a'*64, 'b'*64), *rows[1:])
    elif fault == 'wrong_table':rows = (replace(row, key=Key('events', row.key.resource)), *rows[1:])
    else:rows = (replace(row, revision={'revision_zero': 0, 'revision_overflow': 2**63, 'revision_bool': True}[fault]), *rows[1:])
    with pytest.raises(CaptureDiscoveryHeld):call(root, rows)


@pytest.mark.parametrize('fault', ['missing_ack', 'orphan_ack', 'foreign_ack', 'missing_binding', 'bad_deployment', 'missing_action', 'wrong_action_status'])
def test_historical_action_and_typed_binding_closure_hold(fault):
    root, rows = action_family(True)
    if fault == 'missing_ack':rows = tuple(r for r in rows if not r.key.resource.startswith('access#'))
    elif fault == 'missing_action':rows = tuple(r for r in rows if not r.key.resource.startswith('action#'))
    elif fault == 'wrong_action_status':rows = edit(rows, 'action', status='pending')
    else:
        target = next(r for r in rows if r.key.resource.startswith('access#')); data = deepcopy(target.data)
        if fault == 'orphan_ack':data['details']['action_id'] = uid(99)
        elif fault == 'foreign_ack':data['details']['inspection_id'] = uid(99)
        elif fault == 'missing_binding':data.pop('resource_bindings')
        elif fault == 'bad_deployment':data['resource_bindings']['deployment'] = 'foreign'
        rows = tuple(replace(r, data=data) if r.key == target.key else r for r in rows)
    with pytest.raises(CaptureDiscoveryHeld):call(root, rows)


def test_denied_and_deleted_crop_metadata_keeps_historical_write_digest_distinct():
    root, rows = family(); asset = next(r for r in rows if r.key.resource.startswith('asset#'))
    for state in ('committed', 'deleted'):
        data = {**asset.data, 'status': state, 'read_denied': True, 'deletion_job_id': uid(30), 'denied_at_ms': 110}
        if state == 'deleted':data['live_versions_checked_at_ms'] = 120
        changed = tuple(replace(r, revision=2 if state == 'committed' else 3, data=data) if r.key == asset.key else r for r in rows)
        assert call(root, changed).media


def test_legacy_intent_without_original_target_is_held_not_backfilled():
    root, rows = failed('failed', 'reserved'); intent = next(r for r in rows if r.key.resource.startswith('object-intent#'))
    data = dict(intent.data); data.pop('storage_binding_sha256')
    with pytest.raises(CaptureDiscoveryHeld):call(root, tuple(replace(r, data=data) if r.key == intent.key else r for r in rows))

@pytest.mark.parametrize('field,value', [('recipe_id','../foreign'), ('recipe_id','x'*65), ('calibration_profile_id',True), ('calibration_profile_id','bad profile'), ('schema_version',2)])
def test_root_identifiers_and_unknown_schema_follow_existing_contract(field,value):
    root,rows=family();root=replace(root,data={**root.data,field:value})
    with pytest.raises(CaptureDiscoveryHeld):call(root,rows)

@pytest.mark.parametrize('fault',['admission_after_terminal','completion_after_close','wrong_verified_sequence','acknowledged_current_pointer','unknown_failure'])
def test_terminal_chronology_and_cleared_action_state_are_not_inferred_from_opaque_ids(fault):
    if fault=='acknowledged_current_pointer':
        root,rows=action_family(True);root=replace(root,data={**root.data,'current_action_id':uid(13)})
    elif fault=='unknown_failure':root,rows=failed();rows=edit(rows,'observation',failure_reason='invented_reason')
    else:
        root,rows=family()
        if fault=='wrong_verified_sequence':root=replace(root,data={**root.data,'verified_sequence':0})
        else:
            target=key('capture',9 if fault=='admission_after_terminal' else 10,'events')
            rows=tuple(replace(r,data={**r.data,'at_ms':101}) if r.key==target else r for r in rows)
    with pytest.raises(CaptureDiscoveryHeld):call(root,rows)

def test_completed_but_invalidated_measurement_is_historical_without_advancing_verification():
    root,rows=family();root=replace(root,data={**root.data,'verified_sequence':0})
    target=key('capture',10,'events')
    rows=tuple(replace(r,data={**r.data,'state':'INVALIDATED'}) if r.key==target else r for r in rows)
    result=call(root,rows)
    assert result.media and not hasattr(result,'machine_pass')

def test_failed_intent_cannot_name_a_purpose_absent_from_admitted_dependencies():
    root,rows=failed('failed','reserved');rows=edit(rows,'object-intent',purpose_id=uid(99))
    with pytest.raises(CaptureDiscoveryHeld):call(root,rows)
