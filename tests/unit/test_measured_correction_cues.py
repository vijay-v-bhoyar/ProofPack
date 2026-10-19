"""Pixel-based correction cues are not independent physical pose truth."""
import json
import cv2
import numpy as np
import pytest
from pydantic import ValidationError
from proofpack.recipes.models import Recipe
from proofpack.verifier.core import Finding
from proofpack.vision.pipeline import Envelope, measure
from proofpack.planner.policy import ActionKind, choose_action


def recipe(kind, count=1, flat=None):
    constraint = {'constraint_id': 'visible-part', 'part_class_id': kind, 'expected_count': count, 'required_visibility': 'Planar synthetic silhouette only'}
    if flat is not None:
        constraint['flat_reference_aspect_ratio'] = {'minimum': flat[0], 'maximum': flat[1]}
    return Recipe.model_validate_json(json.dumps({'recipe_id': 'correction-test', 'revision': 1, 'name': 'Authored synthetic correction case',
        'kit_sku': 'paper-only', 'constraints': [constraint], 'reference_asset_ids': ['analytic-reference'],
        'calibration_profile_id': 'analytic-mat', 'data_origin': 'synthetic'}))


def envelope():
    from proofpack.recipes.models import Origin
    return Envelope(600, 300, 5., .2, 30., 1., 127, Origin.SYNTHETIC, True)


def blank():
    return np.full((300, 600, 3), 255, np.uint8)


def test_two_touching_washers_are_not_a_flat_bracket_and_have_a_measured_separation_target():
    frame = blank()
    for center in ((100, 100), (140, 100)):
        cv2.circle(frame, center, 24, (0, 0, 0), -1)
        cv2.circle(frame, center, 8, (255, 255, 255), -1)
    result = measure(frame, recipe('flat_bracket'), envelope())
    assert result.findings == (Finding.UNOBSERVABLE,)
    assert result.unknown_regions == 1 and 'overlap' in result.reason_codes
    assert result.candidates[0].part_class is None and result.candidates[0].correction_reason == 'overlap'
    assert choose_action(result.reason_codes) == ActionKind.SEPARATE_REGION


def test_flat_reference_mismatch_abstains_then_fresh_matching_projection_can_satisfy():
    selected = recipe('bolt', flat=(4.5, 7.5))
    short = blank(); cv2.rectangle(short, (70, 90), (140, 110), (0, 0, 0), -1)
    result = measure(short, selected, envelope())
    assert result.findings == (Finding.UNOBSERVABLE,) and result.unknown_regions == 0
    assert result.candidates[0].correction_reason == 'not_flat' and 'not_flat' in result.reason_codes
    lo, hi = result.candidates[0].aspect_ratio_interval
    assert 1 <= lo <= hi < 4.5 and choose_action(result.reason_codes) == ActionKind.PLACE_FLAT
    fresh = blank(); cv2.rectangle(fresh, (70, 90), (190, 110), (0, 0, 0), -1)
    corrected = measure(fresh, selected, envelope())
    assert corrected.findings == (Finding.SATISFIED,) and 'not_flat' not in corrected.reason_codes


def test_legacy_recipe_canonical_body_is_unchanged_and_no_flatness_is_inferred():
    selected = recipe('bolt')
    assert 'flat_reference_aspect_ratio' not in selected.model_dump_json()
    frame = blank(); cv2.rectangle(frame, (70, 90), (140, 110), (0, 0, 0), -1)
    result = measure(frame, selected, envelope())
    assert 'not_flat' not in result.reason_codes


@pytest.mark.parametrize('bounds', [(0., 2.), (3., 2.), (1., 2001.)])
def test_flat_reference_rejects_invalid_bounds(bounds):
    with pytest.raises(ValidationError):
        recipe('bolt', flat=bounds)


def test_unresolved_projection_does_not_become_a_definite_missing_count():
    selected=recipe('bolt', count=2, flat=(4.5,7.5))
    frame=blank();cv2.rectangle(frame,(70,90),(140,110),(0,0,0),-1)
    measured=measure(frame,selected,envelope())
    assert measured.findings==(Finding.UNOBSERVABLE,)
    assert measured.candidates[0].correction_reason=='not_flat'


def test_convex_unknown_does_not_receive_an_invented_overlap_target():
    frame=blank();cv2.rectangle(frame,(70,90),(100,120),(0,0,0),-1)
    measured=measure(frame,recipe('washer'),envelope())
    assert measured.findings==(Finding.UNOBSERVABLE,)
    assert measured.candidates[0].correction_reason is None and 'overlap' not in measured.reason_codes
    assert choose_action(measured.reason_codes)==ActionKind.REVIEW
