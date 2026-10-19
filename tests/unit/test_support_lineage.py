from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from uuid import uuid4
import pytest

from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Key, Row, ErasureMarker, StoreUnavailable
from proofpack.evidence.support_lineage import discover, SupportDiscoveryHeld
from proofpack.stations.handoffs import InspectionHandoffs, handoff_key, inbox_key
from proofpack.stations.service import inspection_key


def make_pair(root=None, ident=None, *, created=1000, status='pending'):
    owner = str(uuid4()) if root is None else root.data['id']; ident = ident or str(uuid4())
    station = str(uuid4()) if root is None else root.data['station_id']
    root = root or Row(inspection_key(owner), 5, {'id': owner, 'station_id': station, 'kit_id': 'kit-one',
        'handoff_count': 1, 'latest_handoff_id': ident, 'state': 'CLOSED'})
    request = {'schema_version': 1, 'id': ident, 'inspection_id': owner, 'station_id': station,
        'station_epoch': 1, 'station_name': 'Desk', 'kit_reference': 'kit-one', 'source_inspection_revision': 3,
        'post_request_inspection_revision': 4, 'source_observation_id': None, 'reason_code': 'support_needed',
        'stop_acknowledged': True, 'sender_user_id': str(uuid4()), 'sender_session_id': str(uuid4()),
        'sender_cookie_resource': 'cookie#'+'b'*64, 'sender_role': 'operator', 'sender_access_version': 1,
        'recipient_user_id': str(uuid4()), 'recipient_access_version': 1, 'previous_accepted_handoff_id': None,
        'runtime_epoch': 1, 'runtime_instance_id': str(uuid4()), 'data_epoch': 1, 'created_at_ms': created,
        'expires_at_ms': created+1000, 'metadata_expires_at_ms': 10000, 'parent_metadata_expires_at_ms': 20000,
        'configuration': 'a'*64}
    data = {'schema_version': 1, 'id': ident, 'inspection_id': owner, 'request': request, 'request_sha256': digest(request),
        'status': status, 'decision': None, 'decision_sha256': None, 'metadata_expires_at_ms': 10000, 'ttl_epoch_seconds': 10}
    if status != 'pending':
        data['decision'] = {'kind': status, 'inspection_id': owner, 'handoff_id': ident, 'request_sha256': data['request_sha256'],
            'source_request_revision': 1, 'actor_user_id': request['recipient_user_id'], 'actor_session_id': str(uuid4()),
            'actor_role': 'reviewer', 'at_ms': created, 'acknowledge_no_capture_transfer': True}
        data['decision_sha256'] = digest(data['decision'])
    main = Row(handoff_key(owner, ident), 1 if status == 'pending' else 2, data)
    index = Row(inbox_key(request['recipient_user_id'], ident), 1, {'id': ident, 'inspection_id': owner,
        'recipient_user_id': request['recipient_user_id'], 'request_sha256': data['request_sha256'],
        'metadata_expires_at_ms': 10000, 'ttl_epoch_seconds': 10})
    return root, main, index


def reseal(main, index):
    main.data['request_sha256'] = digest(main.data['request'])
    index.data['request_sha256'] = main.data['request_sha256']
    if main.data['decision'] is not None:
        main.data['decision']['request_sha256'] = main.data['request_sha256']
        main.data['decision_sha256'] = digest(main.data['decision'])


def test_expired_integrity_mode_does_not_renew_normal_read_or_copy_private_fields():
    root, main, index = make_pair()
    with pytest.raises(StoreUnavailable):
        InspectionHandoffs.retained(main, root.data['id'], main.data['id'], now=lambda: 10000)
    result = discover(root, (main, index), now_ms=10000, max_records=2)
    assert {r.key for r in result.records} == {main.key, index.key}
    assert result.inspection.key == root.key and result.links == ()
    assert 'sender_cookie_resource' not in repr(result) and 'kit-one' not in repr(result)
    first = result.records
    main.data['request']['station_name'] = 'mutated'
    assert result.records == first
    with pytest.raises(FrozenInstanceError): result.records[0].revision = 9


def test_predecessor_relationship_is_exact_and_does_not_include_users_or_stations():
    root, prior, prior_index = make_pair(status='accepted')
    _, current, current_index = make_pair(root, created=1200)
    root.data.update(handoff_count=2, latest_handoff_id=current.data['id'])
    current.data['request']['previous_accepted_handoff_id'] = prior.data['id']; reseal(current, current_index)
    result = discover(root, (current_index, prior, current, prior_index), now_ms=1500, max_records=4)
    assert len(result.records) == 4 and len(result.links) == 1
    assert result.links[0].source == current.key and result.links[0].target == prior.key
    assert all(r.key.resource.startswith(('inspection-handoff#', 'handoff-inbox#')) for r in result.records)


@pytest.mark.parametrize('fault', ['missing_inbox', 'duplicate', 'inbox_root', 'inbox_key', 'inbox_hash', 'inbox_expiry',
    'extra_main', 'extra_request', 'extra_inbox', 'main_hash', 'future', 'root_id', 'root_count', 'root_latest',
    'station', 'kit', 'marker', 'unknown_family', 'revision', 'root_revision'])
def test_incomplete_ambiguous_or_foreign_relationship_holds(fault):
    root, main, index = make_pair(); rows = (main, index)
    if fault == 'missing_inbox': rows = (main,)
    elif fault == 'duplicate': rows = (main, index, index)
    elif fault == 'inbox_root': index.data['inspection_id'] = str(uuid4())
    elif fault == 'inbox_key': index = replace(index, key=inbox_key(str(uuid4()), main.data['id'])); rows = (main, index)
    elif fault == 'inbox_hash': index.data['request_sha256'] = '0'*64
    elif fault == 'inbox_expiry': index.data['metadata_expires_at_ms'] -= 1
    elif fault == 'extra_main': main.data['unrecognized'] = 'secret'
    elif fault == 'extra_request': main.data['request']['unrecognized'] = 'secret'; reseal(main, index)
    elif fault == 'extra_inbox': index.data['unrecognized'] = 'secret'
    elif fault == 'main_hash': main.data['request_sha256'] = '0'*64
    elif fault == 'future': main.data['request']['created_at_ms'] = 2000; reseal(main, index)
    elif fault == 'root_id': root.data['id'] = str(uuid4())
    elif fault == 'root_count': root.data['handoff_count'] = 0; root.data['latest_handoff_id'] = None
    elif fault == 'root_latest': root.data['latest_handoff_id'] = str(uuid4())
    elif fault == 'station': root.data['station_id'] = str(uuid4())
    elif fault == 'kit': root.data['kit_id'] = 'different'
    elif fault == 'marker': rows = (main, ErasureMarker(index.key, 2, 'a'*64, 'b'*64))
    elif fault == 'unknown_family': rows = (main, index, Row(Key('state', 'other#one'), 1, {}))
    elif fault == 'root_revision': root = replace(root, revision=2**63)
    else: rows = (replace(main, revision=True), index)
    with pytest.raises(SupportDiscoveryHeld): discover(root, rows, now_ms=1500, max_records=4)


def test_same_schema_and_hashes_do_not_admit_a_cross_inspection_parent():
    root, main, index = make_pair()
    foreign, prior, prior_index = make_pair(status='accepted')
    main.data['request']['previous_accepted_handoff_id'] = prior.data['id']; reseal(main, index)
    with pytest.raises(SupportDiscoveryHeld): discover(root, (main, index, prior, prior_index), now_ms=1500, max_records=4)


def test_valid_hashed_accepted_cycle_is_rejected_without_recursion():
    root, a, ai = make_pair(status='accepted'); _, b, bi = make_pair(root, status='accepted')
    root.data.update(handoff_count=2, latest_handoff_id=b.data['id'])
    a.data['request']['previous_accepted_handoff_id'] = b.data['id']; reseal(a, ai)
    b.data['request']['previous_accepted_handoff_id'] = a.data['id']; reseal(b, bi)
    with pytest.raises(SupportDiscoveryHeld): discover(root, (a, ai, b, bi), now_ms=1500, max_records=4)


def test_foreign_complete_family_is_validated_but_not_owned_by_selected_inspection():
    root, main, index = make_pair(); _, other, oi = make_pair()
    result = discover(root, (main, index, other, oi), now_ms=1500, max_records=4)
    assert {r.key for r in result.records} == {main.key, index.key}


def test_missing_all_records_does_not_become_empty_success():
    root, _, _ = make_pair()
    with pytest.raises(SupportDiscoveryHeld): discover(root, (), now_ms=1500, max_records=4)
    root.data.update(handoff_count=0, latest_handoff_id=None)
    assert discover(root, (), now_ms=1500, max_records=4).records == ()


@pytest.mark.parametrize('value', [None, 1, 'true'])
def test_expired_record_mode_is_explicit_not_a_coerced_flag(value):
    root, main, _ = make_pair()
    with pytest.raises(ValueError): InspectionHandoffs.retained(main, root.data['id'], main.data['id'], now=lambda: 1500, include_expired=value)


def test_input_bound_holds_before_any_family_is_accepted():
    root, main, index = make_pair()
    with pytest.raises(SupportDiscoveryHeld): discover(root, (main, index), now_ms=1500, max_records=1)
