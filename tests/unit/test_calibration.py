from dataclasses import replace

import cv2
import numpy as np
from pydantic import ValidationError
import pytest

from proofpack.vision.calibration import CalibrationError,CalibrationProfile,rectify
from proofpack.vision.fixtures import blank_mat,demo_recipe,make_fixture,synthetic_profile
from proofpack.vision.pipeline import measure
from proofpack.verifier.core import Finding


@pytest.mark.parametrize('index',range(3))
def test_markers_rectify_known_complete_recipe(index):
    image,_=make_fixture(index,'complete',seed=0)
    rectified,envelope=rectify(image,synthetic_profile())
    result=measure(rectified,demo_recipe(index),envelope)
    assert rectified.shape==(300,600,3)
    assert result.findings==(Finding.SATISFIED,)*4
    assert result.unknown_regions==0


@pytest.mark.parametrize('mutation',['missing','moved','duplicate','extra','mirror','wrong_shape'])
def test_invalid_marker_context_rejected(mutation):
    frame=blank_mat();profile=synthetic_profile()
    if mutation=='missing':frame[20:100,20:100]=255
    elif mutation=='moved':frame=cv2.warpAffine(frame,np.float32([[1,0,5],[0,1,0]]),(800,500),borderValue=(255,255,255))
    elif mutation=='duplicate':frame[408:472,708:772]=frame[28:92,28:92]
    elif mutation=='extra':
        extra=cv2.aruco.generateImageMarker(cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_4X4_50),4,64)
        frame[200:264,300:364]=cv2.cvtColor(extra,cv2.COLOR_GRAY2BGR)
    elif mutation=='mirror':frame=cv2.flip(frame,1)
    else:frame=frame[:400]
    with pytest.raises(CalibrationError):rectify(frame,profile)


def test_nonplanar_marker_layout_and_bad_scale_rejected():
    frame=blank_mat();profile=synthetic_profile()
    raw=profile.model_dump()
    raw['physical_height_mm']=200.
    with pytest.raises(ValidationError,match='isotropic'):
        CalibrationProfile.model_validate(raw)
    raw=profile.model_dump();quads=list(raw['plane_corners']);quad=list(quads[0]);quad[0]=(quad[0][0]+8,quad[0][1]);quads[0]=tuple(quad)
    raw['plane_corners']=tuple(quads)
    distorted=CalibrationProfile.model_validate(raw)
    with pytest.raises(CalibrationError,match='marker_residual'):
        rectify(frame,distorted)


def test_overlay_mapping_uses_rectified_measurements():
    image,_=make_fixture(0,'complete',seed=0)
    rectified,envelope=rectify(image,synthetic_profile())
    result=measure(rectified,demo_recipe(),envelope)
    for candidate in result.candidates:
        x,y,w,h=candidate.box
        assert 0<=x<x+w<=600 and 0<=y<y+h<=300
    # The first source washer is around (165,180); rectification removes (100,100).
    washer=next(c for c in result.candidates if c.part_class.value=='washer')
    assert 35<=washer.box[0]<=50 and 50<=washer.box[1]<=65
