from copy import deepcopy
from uuid import UUID
import hashlib
from dataclasses import FrozenInstanceError
import pytest
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Key, Row, Write
from proofpack.evidence.resource_bindings import prepare_linked
from proofpack.runtime.control import DATA, RUNTIME


def uid(number):
    return str(UUID(int=number))


def event(kind, details, writes, checks, number, at=100, actor_scope='a' * 64):
    key = Key('events', 'access#' + uid(number))
    data = {'kind': kind, 'actor_scope': actor_scope, 'at_ms': at,
            'session_id': uid(3), 'details': details}
    prepared, _ = prepare_linked('beta', kind, (*writes, Write(key, None, data)), checks)
    return next(Row(write.key, 1, write.data) for write in prepared if write.key == key)


def family():
    asset = Row(Key('state', 'asset#' + uid(6)), 3, {'id': uid(6), 'sha256': 'b' * 64})
    purpose = Row(Key('state', 'purpose#' + uid(7)), 4, {'id': uid(7)})
    source = {'id': uid(6), 'kind': 'frame', 'asset_revision': 3, 'asset_record_sha256': digest(asset.data),
              'sha256': 'b' * 64, 'data_origin': 'synthetic', 'purpose_id': uid(7), 'purpose_revision': 4,
              'purpose_record_sha256': digest(purpose.data), 'source_permission_reference': 'synthetic-rights',
              'expires_at_ms': 500}
    scope = {'schema_version': 1, 'kind': 'selected_optional_improvement',
             'configuration': 'c' * 64, 'assets': [source]}
    data = {'id': uid(1), 'status': 'preview', 'scope': scope, 'scope_sha256': digest(scope),
            'configuration': 'd' * 64, 'data_epoch': 1,
            'notice': {'version': 'notice-v1', 'sha256': hashlib.sha256(b'Notice').hexdigest(), 'text': 'Notice'},
            'runtime_binding': {'instance_id': uid(8), 'epoch': 1, 'artifact_sha256': 'e' * 64,
                                'controls_sha256': 'f' * 64, 'environment': 'synthetic_demo'},
            'owner_id': uid(2), 'session_id': uid(3), 'access_version': 1,
            'created_at_ms': 100, 'expires_at_ms': 200, 'source_expires_at_ms': 500, 'permission_id': None}
    preview = Row(Key('state', 'improvement-preview#' + uid(1)), 1, data)
    actor = (Row(Key('state', 'user#' + uid(2)), 1, {'id': uid(2)}),
             Row(Key('state', 'session#' + uid(3)), 1, {'id': uid(3)}))
    checks = (*actor, Row(DATA, 1, {'epoch': 1, 'changed_at_ms': 90}), Row(RUNTIME, 1, {'epoch': 1}), asset, purpose)
    quota = Write(Key('state', 'improvement-preview-quota#' + 'a' * 64), None, {'minute': 0, 'count': 1})
    created = event('improvement-preview', {'preview_id': uid(1), 'scope_sha256': data['scope_sha256']},
                    (Write(preview.key, None, data), quota), checks, 20)
    return preview, (created,)


def parse(preview, rows, **changes):
    from proofpack.evidence.improvement_lineage import discover
    return discover(preview, rows, **{'deployment': 'beta', 'max_records': 100,
                                     'max_payload_bytes': 100000, **changes})


def test_unconsumed_preview_has_no_invented_grant_or_authorization():
    preview, rows = family()
    result = parse(preview, rows)
    assert result.preview.key == preview.key
    assert result.grant is None and result.permission is None
    assert {record.key for record in result.records} == {row.key for row in rows}
    assert not hasattr(result, 'usable')


def checks(preview, epoch=1):
    return (Row(Key('state', 'user#' + uid(2)), 1, {'id': uid(2)}),
            Row(Key('state', 'session#' + uid(3)), 1, {'id': uid(3)}),
            Row(DATA, epoch, {'epoch': epoch, 'changed_at_ms': 90}), Row(RUNTIME, 1, {'epoch': 1}),
            Row(Key('state', 'asset#' + uid(6)), 3, {'id': uid(6), 'sha256': 'b' * 64}),
            Row(Key('state', 'purpose#' + uid(7)), 4, {'id': uid(7)}))


def committed(*, derived=False, withdrawn=False, repeat=False, grant_expires=300, confirm_actor_scope='a' * 64,
              confirm_data_revision=1, confirm_data_time=90):
    preview, rows = family(); p = preview.data
    data = {'id': uid(9), 'schema_version': 1, 'scope': deepcopy(p['scope']), 'scope_sha256': p['scope_sha256'],
            'configuration': p['scope']['configuration'], 'documented_permission_reference': 'separate-rights',
            'notice_version': p['notice']['version'], 'notice_sha256': p['notice']['sha256'],
            'owner_id': uid(2), 'created_at_ms': 120, 'notice_text': p['notice']['text'], 'expires_at_ms': grant_expires,
            'authority_basis': 'owner_attestation', 'rights_independently_verified': False,
            'derived_review_metadata_allowed': derived, 'optional_improvement': True, 'optional_publicity': False,
            'physical_truth_verified': False, 'independence_verified': False}
    data['sha256'] = digest(data)
    grant = Row(Key('state', 'improvement-grant#' + uid(9)), 1, data)
    head = Row(Key('state', 'improvement-permission#' + uid(9)), 1,
               {'id': uid(9), 'grant_sha256': data['sha256'], 'withdrawn': False})
    root = Row(preview.key, 2, {**p, 'status': 'committed', 'permission_id': uid(9)})
    confirm = event('improvement-confirm', {'permission_id': uid(9), 'scope_sha256': p['scope_sha256'],
                    'grant_sha256': data['sha256']},
                    (Write(root.key, 1, root.data), Write(grant.key, None, data), Write(head.key, None, head.data),
                     Write(DATA, confirm_data_revision, {'epoch': confirm_data_revision + 1, 'changed_at_ms': 120}), Write(Key('state', 'improvement-confirm-quota#' + confirm_actor_scope), None,
                                                     {'minute': 0, 'count': 1})),
                    (*tuple(Row(DATA, confirm_data_revision, {'epoch': 1, 'changed_at_ms': confirm_data_time})
                            if row.key == DATA else row for row in checks(preview)), preview),
                    21, 120, actor_scope=confirm_actor_scope)
    history = [*rows, grant, head, confirm]
    if withdrawn:
        latest = Row(head.key, 2, {**head.data, 'withdrawn': True, 'withdrawn_at_ms': 400})
        quota = Key('state', 'improvement-withdraw-quota#' + 'a' * 64)
        first = event('improvement-withdraw:' + uid(9), {'permission_id': uid(9), 'withdrawn': True},
                      (Write(head.key, 1, latest.data), Write(DATA, 2, {'epoch': 3}),
                       Write(quota, None, {'minute': 0, 'count': 1})),
                      (*checks(preview, 2)[:4], head, grant), 22, 400)
        history[2] = latest; history.append(first)
        if repeat:
            history.append(event('improvement-withdraw:' + uid(9), {'permission_id': uid(9), 'withdrawn': True},
                                 (Write(quota, 1, {'minute': 0, 'count': 2}),),
                                 (*checks(preview, 3)[:4], latest, grant), 23, 450))
    return root, tuple(history)


@pytest.mark.parametrize('derived', [False, True])
@pytest.mark.parametrize('withdrawn,repeat', [(False, False), (True, False), (True, True)])
def test_grant_and_expired_withdrawal_history_preserves_optional_boundary(derived, withdrawn, repeat):
    preview, rows = committed(derived=derived, withdrawn=withdrawn, repeat=repeat)
    result = parse(preview, rows)
    assert result.grant.key == Key('state', 'improvement-grant#' + uid(9))
    assert result.permission.revision == (2 if withdrawn else 1)
    assert {r.key for r in result.records} == {r.key for r in rows}
    assert not ({r.key for r in result.records} & {r.key for r in result.dependencies})
    assert not hasattr(result, 'usable')
    assert not any(text in repr(result) for text in ['Notice', 'separate-rights', 'synthetic-rights'])


def test_result_is_detached_and_bounds_count_the_root_and_all_payload_bytes():
    preview, rows = committed(withdrawn=True, repeat=True)
    result = parse(preview, rows)
    saved = deepcopy(result)
    assert parse(preview, rows, max_records=1 + len(rows), max_payload_bytes=result.payload_bytes) == result
    from proofpack.evidence.improvement_lineage import ImprovementHistoryHeld
    with pytest.raises(ImprovementHistoryHeld):parse(preview, rows, max_records=len(rows))
    with pytest.raises(ImprovementHistoryHeld):parse(preview, rows, max_payload_bytes=result.payload_bytes - 1)
    rows[1].data['notice_text'] = 'changed after parse'
    assert result == saved
    with pytest.raises(FrozenInstanceError):result.permission.revision = 99


@pytest.mark.parametrize('index', range(5))
def test_missing_history_peers_hold_instead_of_accepting_partial_scope(index):
    from proofpack.evidence.improvement_lineage import ImprovementHistoryHeld
    preview, rows = committed(withdrawn=True, repeat=True)
    with pytest.raises(ImprovementHistoryHeld):parse(preview, rows[:index] + rows[index + 1:])


@pytest.mark.parametrize('field,value', [
    ('schema_version', True), ('id', uid(99)), ('owner_id', uid(99)), ('configuration', '0' * 64),
    ('notice_version', 'different'), ('notice_text', 'changed'), ('created_at_ms', 200),
    ('expires_at_ms', 100), ('authority_basis', 'independent'), ('optional_improvement', False),
    ('optional_publicity', True), ('physical_truth_verified', True), ('independence_verified', True),
    ('rights_independently_verified', True), ('derived_review_metadata_allowed', 1),
    ('documented_permission_reference', 'not allowed whitespace'),
])
def test_changed_grant_fields_never_become_authority(field, value):
    from proofpack.evidence.improvement_lineage import ImprovementHistoryHeld
    preview, rows = deepcopy(committed())
    rows[1].data[field] = value
    with pytest.raises(ImprovementHistoryHeld):parse(preview, rows)


@pytest.mark.parametrize('bad', [True, 0, -1, 2**63, '100'])
@pytest.mark.parametrize('field', ['max_records', 'max_payload_bytes'])
def test_explicit_independent_bounds_are_typed_and_finite(field, bad):
    preview, rows = family()
    with pytest.raises(ValueError):parse(preview, rows, **{field: bad})


@pytest.mark.parametrize('fault', ['duplicate', 'foreign', 'unknown', 'marker', 'event-version', 'missing-binding'])
def test_unknown_or_unreconciled_rows_hold(fault):
    from proofpack.evidence.improvement_lineage import ImprovementHistoryHeld
    from proofpack.evidence.repository import ErasureMarker
    preview, rows = deepcopy(family())
    if fault == 'duplicate':rows += rows
    elif fault == 'foreign':rows += (Row(Key('state', 'user#' + uid(99)), 1, {'id': uid(99)}),)
    elif fault == 'unknown':preview.data['status'] = 'approved'
    elif fault == 'marker':rows = (ErasureMarker(rows[0].key, 1, '0' * 64, '1' * 64),)
    elif fault == 'event-version':rows = (Row(rows[0].key, 2, rows[0].data),)
    else:rows[0].data.pop('resource_bindings')
    with pytest.raises(ImprovementHistoryHeld):parse(preview, rows)


def test_self_consistent_grant_cannot_outlive_its_original_source_window():
    from proofpack.evidence.improvement_lineage import ImprovementHistoryHeld
    with pytest.raises(ImprovementHistoryHeld):parse(*committed(grant_expires=501))


def test_same_owner_session_confirmation_cannot_switch_actor_scope():
    from proofpack.evidence.improvement_lineage import ImprovementHistoryHeld
    with pytest.raises(ImprovementHistoryHeld):parse(*committed(confirm_actor_scope='b' * 64))


@pytest.mark.parametrize('field,value', [
    ('status', 'approved'), ('permission_id', uid(99)), ('data_epoch', True), ('access_version', 0),
    ('session_id', uid(99)), ('owner_id', uid(99)), ('expires_at_ms', 501), ('created_at_ms', 200),
    ('source_expires_at_ms', 501), ('configuration', 'not-a-hash'),
])
def test_self_consistent_changed_preview_still_requires_valid_schema_and_sources(field, value):
    from proofpack.evidence.improvement_lineage import ImprovementHistoryHeld
    preview, _ = family(); preview.data[field] = value
    quota = Write(Key('state', 'improvement-preview-quota#' + 'a' * 64), None, {'minute': 0, 'count': 1})
    created = event('improvement-preview', {'preview_id': uid(1), 'scope_sha256': preview.data['scope_sha256']},
                    (Write(preview.key, None, preview.data), quota), checks(preview), 20)
    with pytest.raises(ImprovementHistoryHeld):parse(preview, (created,))


@pytest.mark.parametrize('field,value', [
    ('kind', 'unknown'), ('data_origin', 'inferred'), ('asset_revision', True),
    ('purpose_revision', 0), ('asset_record_sha256', '0' * 64), ('purpose_record_sha256', '0' * 64),
    ('expires_at_ms', 99), ('source_permission_reference', ''),
])
def test_rehashed_scope_cannot_change_historical_source_references(field, value):
    from proofpack.evidence.improvement_lineage import ImprovementHistoryHeld
    preview, _ = family(); preview.data['scope']['assets'][0][field] = value
    preview.data['scope_sha256'] = digest(preview.data['scope'])
    quota = Write(Key('state', 'improvement-preview-quota#' + 'a' * 64), None, {'minute': 0, 'count': 1})
    created = event('improvement-preview', {'preview_id': uid(1), 'scope_sha256': preview.data['scope_sha256']},
                    (Write(preview.key, None, preview.data), quota), checks(preview), 20)
    with pytest.raises(ImprovementHistoryHeld):parse(preview, (created,))


def test_inventory_order_does_not_change_detached_family_identity():
    preview, rows = committed(withdrawn=True, repeat=True)
    assert parse(preview, rows) == parse(preview, tuple(reversed(rows)))


@pytest.mark.parametrize('change', [{'confirm_data_revision': 2}, {'confirm_data_time': 91}])
def test_confirmation_must_keep_exact_historical_data_revision_and_full_payload_digest(change):
    from proofpack.evidence.improvement_lineage import ImprovementHistoryHeld
    with pytest.raises(ImprovementHistoryHeld):parse(*committed(**change))
