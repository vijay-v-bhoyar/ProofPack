"""Synthetic complete-corpus label joins; no native or user acceptance."""
from dataclasses import replace, FrozenInstanceError
from copy import deepcopy
import pytest
from botocore.client import BaseClient

from test_label_lineage import labels
from test_capture_lineage import uid, key, DEPLOYMENT
from proofpack.evidence.repository import Row, Key, ErasureMarker
from proofpack.evidence.inspection_corpus import InspectionCorpusLimits
from proofpack.evidence import label_corpus
from proofpack.evidence.label_corpus import derive, LabelCorpusHeld


LIMITS = InspectionCorpusLimits(2000, 8_000_000, 20, 40_000)


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    def deny(*args, **kwargs): raise AssertionError('pure label selection invoked SDK')
    monkeypatch.setattr(BaseClient, '_make_api_call', deny)


def corpus():
    root, capture, recipe, purposes, history = labels()
    return (root, *capture, recipe, *purposes, *history)


def run(rows, **changes):
    return derive(rows, **(dict(deployment=DEPLOYMENT, requested_inspections=(uid(1),),
        limits=LIMITS, now_ms=5000, deadline_ns=1000, tick=lambda: 1,
        checkpoint=lambda: None) | changes))


def test_derives_all_history_and_audits_from_revision_contexts():
    rows = corpus(); result = run(rows)
    assert len(result.families) == 1
    family = result.families[0]
    assert family.inspection_id == uid(1) and family.requested
    assert len(family.labels.records) == 5
    assert {r.key for r in result.shared_inputs} == {rows[7].key, rows[8].key}
    assert {r.key for r in result.residual} == {r.key for r in result.shared_inputs}
    assert result.inspections.families[0].capture == family.labels.capture
    assert 'Synthetic label note' not in repr(result)


@pytest.mark.parametrize('index', range(14))
def test_omit_each_required_root_capture_recipe_purpose_revision_head_or_event(index):
    rows = corpus()
    with pytest.raises(LabelCorpusHeld): run(rows[:index] + rows[index+1:])


def test_deterministic_across_input_orders():
    rows = corpus(); expected = run(rows)
    assert run(tuple(reversed(rows))) == expected
    assert run(rows[7:] + rows[:7]) == expected


def test_multiple_label_heads_are_joined_independently_with_complete_histories():
    rows = corpus(); other = labels(1, ident=uid(71), epoch_start=3)
    result = run((*rows, *other[-1]))
    assert len(result.families) == 1 and len(result.families[0].labels.records) == 8
    assert len(result.shared_inputs) == len(result.residual) == 2


def test_shared_station_recipe_runtime_user_does_not_assign_labels_to_other_inspection():
    rows = corpus(); root = rows[0]
    second = replace(root, key=key('inspection', 100), data={**root.data, 'id': uid(100),
        'latest_input_sequence': 0, 'verified_sequence': 0, 'latest_observation_id': None})
    result = run((*rows, second))
    assert len(result.inspections.families) == 2
    assert [f.inspection_id for f in result.families] == [uid(1)]
    assert result.inspections.families[1].requested is False


def test_revision_parents_cannot_split_one_label_between_inspections():
    rows = list(corpus()); root = rows[0]
    second = replace(root, key=key('inspection', 100), data={**root.data, 'id': uid(100),
        'latest_input_sequence': 0, 'verified_sequence': 0, 'latest_observation_id': None})
    changed = deepcopy(rows[9].data)
    changed['source_context']['inspection_id'] = uid(100)
    rows[9] = replace(rows[9], data=changed)
    with pytest.raises(LabelCorpusHeld): run((*rows, second))


def test_orphan_label_event_cannot_be_left_out_of_history():
    rows = list(corpus()); changed = deepcopy(rows[10].data)
    changed['details']['label_id'] = uid(100); rows[10] = replace(rows[10], data=changed)
    with pytest.raises(LabelCorpusHeld): run(tuple(rows))


def test_wrong_table_label_record_holds():
    rows = list(corpus()); rows[9] = replace(rows[9], key=Key('events', rows[9].key.resource))
    with pytest.raises(LabelCorpusHeld): run(tuple(rows))


def test_marker_in_place_of_required_purpose_is_not_historical_permission():
    rows = list(corpus()); rows[8] = ErasureMarker(rows[8].key, 2, 'a'*64, 'b'*64)
    with pytest.raises(LabelCorpusHeld): run(tuple(rows))


def test_unknown_nested_copy_and_prior_marker_remain_unresolved():
    rows = corpus(); unknown = Row(Key('state', 'idempotency#'+'f'*64), 1,
        {'result': {'source_context': {'inspection_id': uid(1)}, 'private': 'HIDDEN_COPY'}})
    marker = ErasureMarker(Key('state', 'old#opaque'), 2, 'a'*64, 'b'*64)
    result = run((*rows, marker, unknown))
    assert {r.key for r in result.residual} == {rows[7].key, rows[8].key, unknown.key, marker.key}
    assert len(result.shared_inputs) == 2 and 'HIDDEN_COPY' not in repr(result)


@pytest.mark.parametrize('field', ['max_records', 'max_payload_bytes', 'max_work'])
def test_exact_and_one_below_shared_bounds(field):
    rows = corpus(); result = run(rows)
    exact = {'max_records': len(rows), 'max_payload_bytes': result.inspections.payload_bytes,
             'max_work': result.work}[field]
    assert run(rows, limits=replace(LIMITS, **{field: exact})) == result
    with pytest.raises(LabelCorpusHeld):
        run(rows, limits=replace(LIMITS, **{field: exact-1}))


def test_oversized_requested_scope_never_reaches_callbacks():
    def forbidden(): raise AssertionError('oversized scope reached execution')
    with pytest.raises(LabelCorpusHeld):
        run(corpus(), requested_inspections=(uid(1), uid(100)),
            limits=replace(LIMITS, max_inspections=1), checkpoint=forbidden)


def test_one_monotonic_clock_covers_inspection_and_label_phases(monkeypatch):
    phase = False; original = label_corpus.inspection_derive
    def first(*args, **kwargs):
        nonlocal phase
        result = original(*args, **kwargs); phase = True; return result
    monkeypatch.setattr(label_corpus, 'inspection_derive', first)
    with pytest.raises(LabelCorpusHeld):
        run(corpus(), tick=lambda: 99 if phase else 100)


def test_input_change_between_phase_snapshots_holds(monkeypatch):
    rows = corpus(); original = label_corpus.inspection_derive
    def first(*args, **kwargs):
        result = original(*args, **kwargs)
        rows[8].data['withdrawn'] = True
        return result
    monkeypatch.setattr(label_corpus, 'inspection_derive', first)
    with pytest.raises(LabelCorpusHeld): run(rows)


def test_original_deadline_cannot_be_renewed_for_label_phase(monkeypatch):
    phase = False; original = label_corpus.inspection_derive
    def first(*args, **kwargs):
        nonlocal phase
        result = original(*args, **kwargs); phase = True; return result
    monkeypatch.setattr(label_corpus, 'inspection_derive', first)
    with pytest.raises(LabelCorpusHeld): run(corpus(), tick=lambda: 1000 if phase else 1)


def test_final_checkpoint_failure_returns_no_partial_family():
    rows = corpus(); count = 0
    def checkpoint():
        nonlocal count
        count += 1
    run(rows, checkpoint=checkpoint); final = count; count = 0
    def fail():
        nonlocal count
        count += 1
        if count == final: raise RuntimeError('final drain revalidation failed')
    with pytest.raises(RuntimeError, match='final drain'): run(rows, checkpoint=fail)


def test_empty_label_history_does_not_require_a_recipe_or_purpose_grant():
    from test_capture_lineage import family
    root, capture = family()
    result = run((root, *capture))
    assert result.families == result.shared_inputs == result.residual == ()


def test_detached_reference_only_result_is_immutable():
    rows = corpus(); result = run(rows); before = deepcopy(result)
    rows[9].data['note'] = 'NEW_PRIVATE_NOTE'
    assert result == before and 'NEW_PRIVATE_NOTE' not in repr(result)
    with pytest.raises(FrozenInstanceError): result.work = 0
