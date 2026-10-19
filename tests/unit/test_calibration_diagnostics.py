"""Nominal print geometry and real bounded-child diagnostics, not physical validation."""
from io import BytesIO
from uuid import uuid4

import cv2
import numpy as np
from PIL import Image
import pytest

from proofpack.calibrations.models import QualificationRequest
from proofpack.vision.calibration_diagnostics import CalibrationDiagnostic,CalibrationSettings
from proofpack.vision.fixtures import make_fixture,synthetic_profile
from proofpack.vision.mat import printable_mat,plane_corners
from proofpack.vision.worker import VisionWorker
from proofpack.vision.worker_limits import WorkerLimits


def test_nominal_print_artifact_has_known_dimensions_density_and_fiducials():
    with Image.open(BytesIO(printable_mat())) as image:
        assert image.size==(3200,2000) and np.allclose(image.info['dpi'],(304.8,304.8),atol=.02)
        reference=cv2.cvtColor(np.asarray(image.resize((800,500),Image.Resampling.NEAREST)),cv2.COLOR_RGB2BGR)
    from proofpack.vision.calibration import detect_markers
    assert len(detect_markers(reference,(0,1,2,3)))==4
    assert plane_corners()[0][0]==(-72.,-72.) and plane_corners()[2][2]==(671.,371.)


@pytest.mark.parametrize('changes',[{'max_displacement_px':21.},{'max_reprojection_error_px':6.},{'measurement_error_mm':-1.},
    {'min_area_px':0.},{'min_blur_variance':float('inf')},{'threshold_gray':0},{'threshold_gray':255}])
def test_calibration_settings_reject_outside_existing_envelope(changes):
    values={'max_displacement_px':2.,'max_reprojection_error_px':1.,'measurement_error_mm':.5,'min_area_px':30.,'min_blur_variance':1.,'threshold_gray':127,**changes}
    with pytest.raises(ValueError):CalibrationSettings.model_validate(values)


@pytest.mark.parametrize('cases',[[],[{'asset_id':str(uuid4()),'expected':'supported'}],
    [{'asset_id':'same','expected':'supported'},{'asset_id':'same','expected':'rejected'}],
    [{'asset_id':str(uuid4()),'expected':'supported'},{'asset_id':str(uuid4()),'expected':'supported'}]])
def test_qualification_case_schema_requires_distinct_positive_and_negative_cases(cases):
    import json
    with pytest.raises(ValueError):QualificationRequest.model_validate_json(json.dumps({'cases':cases}))


def test_diagnostic_reply_cannot_assert_physical_truth_or_omit_matching_geometry():
    profile=synthetic_profile();base={'accepted':True,'source_sha256':'a'*64,'profile':profile,'profile_sha256':profile.content_hash,
        'reason_codes':(),'blur_variance':2.,'max_displacement_px':0.,'max_reprojection_error_px':.2}
    assert CalibrationDiagnostic(**base).physical_truth_verified is False
    for change in ({'physical_truth_verified':True},{'profile_sha256':'b'*64},{'profile':None,'profile_sha256':None},{'reason_codes':('failed',)}):
        with pytest.raises(ValueError):CalibrationDiagnostic(**{**base,**change})


def test_actual_child_enrolls_and_rejects_marker_loss_and_scene_displacement_without_a_pass():
    frame,_=make_fixture(0,'complete',seed=4);ok,encoded=cv2.imencode('.png',frame);assert ok
    parameters={'mode':'enroll','profile_id':str(uuid4()),'revision':1,'camera_id':'synthetic-camera','mat_version':'desktop-v1','data_origin':'synthetic',
        'settings':{'max_displacement_px':2.,'max_reprojection_error_px':1.,'measurement_error_mm':.5,'min_area_px':30.,'min_blur_variance':1.,'threshold_gray':127}}
    with VisionWorker(WorkerLimits(512,30,750,5000,2097152,65536,262144,4096,30,12,0)) as worker:
        enrolled=worker.calibration(encoded.tobytes(),parameters=parameters);assert enrolled.accepted and enrolled.physical_truth_verified is False
        missing=frame.copy();missing[20:100,20:100]=255;ok,bad=cv2.imencode('.png',missing);assert ok
        result=worker.calibration(bad.tobytes(),parameters={'mode':'check','profile':enrolled.profile.model_dump(mode='json')})
        assert not result.accepted and result.reason_codes==('markers_missing_duplicate_or_extra',)
        moved=cv2.warpAffine(frame,np.float32([[1,0,5],[0,1,0]]),(800,500),borderValue=(255,255,255));ok,bad=cv2.imencode('.png',moved);assert ok
        result=worker.calibration(bad.tobytes(),parameters={'mode':'check','profile':enrolled.profile.model_dump(mode='json')})
        assert not result.accepted and result.reason_codes==('camera_or_mat_moved',) and worker.available
