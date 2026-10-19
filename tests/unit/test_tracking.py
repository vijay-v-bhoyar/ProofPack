import numpy as np
import pytest

from proofpack.vision.tracking import SceneTracker


def image():return np.full((50,60,3),100,np.uint8)


def test_single_pixel_change_and_unchanged_frame():
    tracker=SceneTracker(pixel_delta=0,max_changed_pixels=0)
    original=image()
    first=tracker.update(original,sequence=1,context='kit1')
    assert first.changed
    assert not tracker.update(original,sequence=2,context='kit1').changed
    changed=original.copy();changed[10,10]=0
    later=tracker.update(changed,sequence=3,context='kit1')
    assert later.changed and later.generation>first.generation and later.changed_pixels==1


def test_cumulative_small_drift_compared_with_scene_anchor():
    tracker=SceneTracker(pixel_delta=10,max_changed_pixels=0)
    for seq,value in enumerate([100,105,110],1):
        assert tracker.update(np.full((20,20,3),value,np.uint8),sequence=seq,context='one').changed==(seq==1)
    assert tracker.update(np.full((20,20,3),115,np.uint8),sequence=4,context='one').changed


def test_context_reset_and_invalidation_never_restore_old_generation():
    tracker=SceneTracker(pixel_delta=0,max_changed_pixels=0)
    first=tracker.update(image(),sequence=1,context='kit1')
    with pytest.raises(ValueError):tracker.update(image(),sequence=1,context='kit1')
    second=tracker.update(image(),sequence=1,context='kit2')
    assert second.changed and second.generation>first.generation
    tracker.invalidate()
    assert tracker.update(image(),sequence=2,context='kit2').generation>second.generation
