"""Complete synthetic row-corpus selection, not native/provider or owner proof."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
import pytest
from botocore.client import BaseClient

from test_capture_lineage import family, uid, key, DEPLOYMENT
from test_human_lineage import history
from test_support_lineage import make_pair, reseal
from proofpack.evidence.repository import Row, Key, ErasureMarker
from proofpack.evidence.inspection_corpus import (
    derive, InspectionCorpusLimits, InspectionCorpusHeld,
)


LIMITS = InspectionCorpusLimits(1000, 4_000_000, 20, 20_000)


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError('pure corpus tests must not call an SDK')
    monkeypatch.setattr(BaseClient, '_make_api_call', deny)


def corpus():
    root, capture, human = history(2)
    _, main, inbox = make_pair(root, uid(400), created=50)
    main.data['request']['kit_reference'] = root.data['kit_id']; reseal(main, inbox)
    root = replace(root, data={**root.data, 'handoff_count': 1, 'latest_handoff_id': uid(400)})
    return (root, *capture, *human, main, inbox)


def run(rows, **changes):
    return derive(rows, **(dict(deployment=DEPLOYMENT, requested_inspections=(uid(1),),
        limits=LIMITS, now_ms=5000, deadline_ns=1000, tick=lambda: 1,
        checkpoint=lambda: None) | changes))


def test_derives_capture_human_and_expired_support_without_caller_family_lists():
    rows = corpus(); result = run(rows)
    assert len(result.families) == 1 and result.residual == ()
    selected = result.families[0]
    assert selected.inspection_id == uid(1) and selected.requested is True
    assert {r.key for r in selected.capture.records} == {r.key for r in rows[1:7]}
    assert len(selected.human.records) == 4 and len(selected.support.records) == 2
    covered = {selected.capture.inspection.key} | {r.key for f in
        (selected.capture, selected.human, selected.support) for r in f.records}
    assert covered == {r.key for r in rows}


@pytest.mark.parametrize('index', range(1, 13))
def test_omitting_each_required_capture_human_or_support_input_holds(index):
    rows = corpus()
    with pytest.raises(InspectionCorpusHeld):
        run(rows[:index] + rows[index+1:])


def test_all_input_orderings_have_identical_result_and_bounds():
    rows = corpus(); expected = run(rows)
    for changed in (tuple(reversed(rows)), rows[5:] + rows[:5], rows[::2] + rows[1::2]):
        assert run(changed) == expected


def test_common_station_recipe_user_and_runtime_do_not_merge_inspections():
    root, capture = family()
    second = replace(root, key=key('inspection', 100), data={**root.data, 'id': uid(100),
        'latest_input_sequence': 0, 'verified_sequence': 0, 'latest_observation_id': None})
    result = run((second, *capture, root))
    assert [f.inspection_id for f in result.families] == [uid(1), uid(100)]
    assert [f.requested for f in result.families] == [True, False]
    assert result.families[1].capture.records == ()
    assert result.families[1].human.records == result.families[1].support.records == ()


def test_other_family_nested_target_copy_and_unknown_remain_explicit_residual():
    rows = corpus()
    copied = Row(Key('state', 'dataset-example#unhandled'), 1,
        {'content': {'source_context': {'inspection_id': uid(1)}}})
    future = Row(Key('events', 'future-schema#opaque'), 1, {'body': {'private': 'DO_NOT_LOG'}})
    result = run((*rows, copied, future))
    assert {r.key for r in result.residual} == {copied.key, future.key}
    assert all(r.kind == 'live' for r in result.residual)
    assert 'DO_NOT_LOG' not in repr(result) and 'source_context' not in repr(result)


def test_reference_asset_with_shared_prefix_is_retained_without_inventing_an_observation():
    reference = Row(key('asset', 800), 1, {'id': uid(800), 'kind': 'reference',
        'purpose_id': uid(801), 'private_reference': 'RETAIN_UNTIL_REFERENCE_POLICY'})
    result = run((*corpus(), reference))
    assert len(result.residual) == 1 and result.residual[0].key == reference.key
    assert 'RETAIN_UNTIL_REFERENCE_POLICY' not in repr(result)


def test_frame_cannot_hide_from_its_capture_family_by_claiming_reference_kind():
    rows = corpus()
    changed = tuple(replace(r, data={**r.data, 'kind': 'reference'})
        if r.key.resource.startswith('asset#') else r for r in rows)
    with pytest.raises(InspectionCorpusHeld): run(changed)


def test_prior_marker_is_an_unresolved_obligation_not_a_removed_record():
    marker = ErasureMarker(Key('state', 'old#opaque'), 2, 'a'*64, 'b'*64)
    result = run((*corpus(), marker))
    assert len(result.residual) == 1
    assert result.residual[0].kind == 'erased'
    assert result.residual[0].sha256 == marker.reference_sha256
    assert result.residual[0].marker_resource_sha256 == marker.resource_sha256


@pytest.mark.parametrize('prefix,changes', [
    ('observation', {'inspection_id': uid(100)}),
    ('asset', {'observation_id': uid(100)}),
    ('capture-permit', {'inspection_id': uid(100)}),
    ('inspection-handoff', {'inspection_id': uid(100)}),
    ('handoff-inbox', {'inspection_id': uid(100)}),
])
def test_missing_or_wrong_parent_never_disappears_from_selection(prefix, changes):
    rows = corpus()
    altered = tuple(replace(r, data={**r.data, **changes})
        if r.key.resource.startswith(prefix+'#') else r for r in rows)
    with pytest.raises(InspectionCorpusHeld): run(altered)


def test_duplicate_even_identical_key_holds():
    rows = corpus()
    with pytest.raises(InspectionCorpusHeld): run((*rows, rows[0]))


@pytest.mark.parametrize('field', ['max_records', 'max_payload_bytes', 'max_inspections', 'max_work'])
def test_independent_limit_exact_success_and_one_below_holds(field):
    rows = corpus(); measured = run(rows)
    exact = {'max_records': len(rows), 'max_payload_bytes': measured.payload_bytes,
             'max_inspections': 1, 'max_work': measured.work}[field]
    assert run(rows, limits=replace(LIMITS, **{field: exact})) == measured
    if exact > 1:
        with pytest.raises(InspectionCorpusHeld):
            run(rows, limits=replace(LIMITS, **{field: exact-1}))
    else:
        with pytest.raises(ValueError): replace(LIMITS, **{field: 0})


@pytest.mark.parametrize('value', [True, 0, -1, 2**63, 1.5, None])
def test_limits_require_exact_finite_positive_integers(value):
    with pytest.raises(ValueError): replace(LIMITS, max_work=value)


@pytest.mark.parametrize('changes', [
    {'requested_inspections': ()}, {'requested_inspections': [uid(1)]},
    {'requested_inspections': (uid(1), uid(1))},
    {'requested_inspections': (uid(100), uid(1))},
    {'requested_inspections': ('not-an-id',)}, {'now_ms': True}, {'deadline_ns': True},
])
def test_scope_and_clock_configuration_are_strict(changes):
    with pytest.raises(ValueError): run(corpus(), **changes)


def test_absent_requested_root_holds():
    with pytest.raises(InspectionCorpusHeld): run(corpus(), requested_inspections=(uid(100),))


def test_requested_scope_bound_is_checked_before_callbacks_or_scope_processing():
    def forbidden():
        raise AssertionError('over-limit scope reached the execution checkpoint')
    with pytest.raises(InspectionCorpusHeld):
        run(corpus(), requested_inspections=(uid(1), uid(100)),
            limits=replace(LIMITS, max_inspections=1), checkpoint=forbidden)


@pytest.mark.parametrize('clock', [lambda: 1000, lambda: -1, lambda: True])
def test_invalid_or_expired_clock_holds(clock):
    with pytest.raises(InspectionCorpusHeld): run(corpus(), tick=clock)


def test_regressing_clock_holds():
    values = iter([2, 1])
    with pytest.raises(InspectionCorpusHeld): run(corpus(), tick=lambda: next(values))


def test_final_checkpoint_failure_yields_no_artifact():
    rows = corpus(); calls = 0
    def checkpoint():
        nonlocal calls
        calls += 1
    run(rows, checkpoint=checkpoint)
    final = calls; calls = 0
    def failing():
        nonlocal calls
        calls += 1
        if calls == final: raise RuntimeError('final control revalidation failed')
    with pytest.raises(RuntimeError, match='final control'):
        run(rows, checkpoint=failing)


def test_detached_payload_free_result_is_immutable():
    rows = corpus(); result = run(rows); saved = deepcopy(result)
    rows[0].data['kit_id'] = 'CHANGED_PRIVATE_INPUT'
    assert result == saved and 'CHANGED_PRIVATE_INPUT' not in repr(result)
    with pytest.raises(FrozenInstanceError): result.work = 0


def test_malformed_supported_root_and_wrong_table_hold():
    rows = corpus()
    for root in (replace(rows[0], revision=True), replace(rows[0], key=Key('events', rows[0].key.resource))):
        with pytest.raises(InspectionCorpusHeld): run((root, *rows[1:]))


@pytest.mark.parametrize('extra', [{}, {'kind': 'legacy_reference'}, {'kind': 'future_asset'}])
def test_parentless_asset_schemas_remain_explicit_unresolved_obligations(extra):
    asset = Row(key('asset', 810), 1, {'status': 'committed', 'sha256': 'd'*64,
        'purpose_id': uid(811), 'read_denied': False, 'data_origin': 'synthetic_demo',
        'expires_at_ms': 9999, **extra})
    result = run((*corpus(), asset))
    assert len(result.residual) == 1 and result.residual[0].key == asset.key
    assert result.residual[0].kind == 'live' and result.residual[0].revision == asset.revision
    assert 'future_asset' not in repr(result) and 'purpose_id' not in repr(result)


def test_required_capture_asset_without_parent_still_rejects_complete_family():
    rows = corpus()
    changed = tuple(replace(r, data={k:v for k,v in r.data.items() if k != 'observation_id'})
        if r.key.resource.startswith('asset#') else r for r in rows)
    with pytest.raises(InspectionCorpusHeld): run(changed)


def test_parentless_asset_in_wrong_table_is_not_silently_residual():
    asset = Row(Key('events', 'asset#'+uid(810)), 1, {'private': 'WRONG_TABLE'})
    with pytest.raises(InspectionCorpusHeld): run((*corpus(), asset))
