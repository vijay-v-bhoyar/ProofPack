from dataclasses import replace

from hypothesis import given, strategies as st
import pytest

from proofpack.verifier.core import (Conflict, Finding, Inspection, Observation, State,
                                    admit_sequence, close, effective_state, remaining_lease_ms, verify)


def observation(authority, seq, tick, **changes):
    return replace(Observation(f"o{seq}", seq, 1, tick, tick - .05,
                               (Finding.SATISFIED,), 1, True, 0, True, authority), **changes)


def stable(authority):
    i = Inspection("i", authority)
    for seq, tick in enumerate((10., 10.5, 11.), 1):
        i = verify(admit_sequence(i, seq), observation(authority, seq, tick), authority, tick + .01)
    return i


def test_three_observations_and_span_required(authority):
    i = Inspection("i", authority)
    for seq, tick in enumerate((10., 10.2, 10.4), 1):
        i = verify(admit_sequence(i, seq), observation(authority, seq, tick), authority, tick + .01)
        assert i.state == State.OBSERVING
    i = verify(admit_sequence(i, 4), observation(authority, 4, 11.), authority, 11.01)
    assert i.state == State.PASSED_CURRENT
    assert i.deadline_tick == pytest.approx(11.95)


@pytest.mark.parametrize("offset,expected", [(-.001, State.PASSED_CURRENT), (0, State.INVALIDATED), (.001, State.INVALIDATED)])
def test_expiry_exact_boundary(authority, offset, expected):
    i = stable(authority)
    assert effective_state(i, authority, i.deadline_tick + offset) == expected
    if expected == State.INVALIDATED:
        assert remaining_lease_ms(i, authority, i.deadline_tick + offset) == 0


@pytest.mark.parametrize("field,new", [("runtime", 2), ("control", 2), ("data", 2), ("station", 2),
    ("recipe", 2), ("calibration", 2), ("policy", 2), ("access", 2), ("session", "other"),
    ("artifact", "other"), ("enabled", False), ("operator_granted", False), ("dependencies_valid", False)])
def test_every_authority_change_withdraws_pass(authority, field, new):
    i = stable(authority)
    head = replace(authority, **{field:new})
    assert effective_state(i, head, 11.1) == State.INVALIDATED
    pending = admit_sequence(i, 4)
    assert verify(pending, observation(authority, 4, 11.2), head, 11.21).state == State.INVALIDATED


@pytest.mark.parametrize("changes", [{"quality_ok":False}, {"unknown_regions":1},
    {"findings":()}, {"findings":(Finding.VIOLATED,)}, {"findings":(Finding.UNOBSERVABLE,)},
    {"expected_constraints":0}, {"findings":(Finding.SATISFIED,Finding.SATISFIED)}])
def test_no_false_pass_when_predicate_missing(authority, changes):
    i = stable(authority)
    changed = verify(admit_sequence(i, 4), observation(authority, 4, 11.2, **changes), authority, 11.21)
    assert changed.state != State.PASSED_CURRENT
    assert changed.deadline_tick == 0
    assert changed.stable_ticks == ()


def test_evidence_failure_requires_review(authority):
    i = stable(authority)
    result = verify(admit_sequence(i, 4), observation(authority, 4, 11.2, evidence_durable=False), authority, 11.21)
    assert result.state == State.REVIEW_REQUIRED
    with pytest.raises(Conflict):
        admit_sequence(result, 5)


def test_pending_frame_never_extends_verified_result(authority):
    i = stable(authority)
    admitted = admit_sequence(i, 4)
    assert admitted.verified_sequence == 3
    assert admitted.deadline_tick == i.deadline_tick
    newest = admit_sequence(admitted, 5)
    with pytest.raises(Conflict, match="superseded"):
        verify(newest, observation(authority, 4, 11.1), authority, 11.11)


def test_delayed_worker_cannot_renew_from_completion(authority):
    i = admit_sequence(Inspection("i", authority), 1)
    assert verify(i, observation(authority, 1, 10.), authority, 10.95).state == State.INVALIDATED
    assert verify(i, observation(authority, 1, 10.), authority, 11.).deadline_tick == 0


def test_scene_change_resets_stability(authority):
    i = stable(authority)
    i = verify(admit_sequence(i, 4), observation(authority, 4, 11.2, scene=2), authority, 11.21)
    assert i.state == State.OBSERVING
    assert len(i.stable_ticks) == 1


def test_closed_or_review_cannot_restart_in_place(authority):
    i = stable(authority)
    closed = close(i, disposition="manual check complete")
    assert effective_state(closed, replace(authority, runtime=2), 10000.) == State.CLOSED
    assert close(closed) == closed
    with pytest.raises(Conflict):
        admit_sequence(closed, 4)
    with pytest.raises(Conflict):
        close(replace(i, state=State.REVIEW_REQUIRED))


def test_dependency_deadline_clamps_lease(authority):
    auth = replace(authority, valid_until_tick=11.2)
    i = stable(auth)
    assert i.deadline_tick == 11.2
    assert remaining_lease_ms(i, auth, 11.2) == 0


@given(delay=st.floats(min_value=1, max_value=1000, allow_nan=False, allow_infinity=False))
def test_property_expired_capture_never_passes(delay):
    # Independent bound oracle: arbitrary worker delays cannot refresh permit age.
    from proofpack.verifier.core import Authority
    auth = Authority(1,1,1,1,1,1,1,1,"s","a",True,True,True,10000.)
    i = admit_sequence(Inspection("i", auth), 1)
    result = verify(i, observation(auth, 1, 10.), auth, 10. + delay)
    assert result.state == State.INVALIDATED
    assert result.deadline_tick == 0
