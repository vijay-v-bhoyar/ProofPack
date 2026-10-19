from dataclasses import replace
from io import BytesIO

import cv2
import numpy as np
from PIL import Image
import pytest

from proofpack.recipes.models import Origin
from proofpack.verifier.core import Finding
from proofpack.vision.pipeline import Envelope, InvalidImage, decode_image, interval_finding, measure
from proofpack.vision.runtime import runtime_proof


def scene():
    image=np.full((300,600,3),255,np.uint8)
    cv2.circle(image,(70,100),30,(0,0,0),-1)
    cv2.circle(image,(70,100),12,(255,255,255),-1)
    hexagon=np.array([[180+30*np.cos(t),100+30*np.sin(t)] for t in np.arange(6)*np.pi/3],np.int32)
    cv2.fillPoly(image,[hexagon],(0,0,0))
    cv2.circle(image,(180,100),10,(255,255,255),-1)
    cv2.rectangle(image,(265,85),(285,115),(0,0,0),-1)
    cv2.rectangle(image,(280,94),(355,106),(0,0,0),-1)
    cv2.rectangle(image,(410,80),(510,120),(0,0,0),-1)
    cv2.circle(image,(430,100),8,(255,255,255),-1)
    cv2.circle(image,(490,100),8,(255,255,255),-1)
    return image


def envelope():
    return Envelope(600,300,5.,.2,30.,1.,127,Origin.SYNTHETIC,True)


@pytest.mark.opencv
def test_actual_opencv_five_and_geometry():
    proof=runtime_proof()
    assert proof["cv2_version"].startswith("5.")
    assert proof["oracles"]["contour_area_px"] == 1200
    assert proof["libraries"]


def test_known_synthetic_parts_and_missing(recipe):
    image=scene()
    result=measure(image,recipe,envelope())
    assert len(result.candidates)==4
    assert result.unknown_regions==0
    assert result.findings==(Finding.SATISFIED,)*4
    image[50:150,20:120]=255
    result=measure(image,recipe,envelope())
    assert result.findings[0]==Finding.VIOLATED
    assert "missing" in result.reason_codes


def test_extra_unknown_blocks_pass(recipe):
    image=scene()
    cv2.rectangle(image,(200,200),(225,225),(0,0,0),-1)
    result=measure(image,recipe,envelope())
    assert result.unknown_regions==1
    assert Finding.SATISFIED not in result.findings


def test_calibration_frame_origin_and_blur_abstain(recipe):
    for config in (replace(envelope(),markers_verified=False),replace(envelope(),width=601),
                   replace(envelope(),origin=Origin.PHYSICAL),replace(envelope(),min_blur_variance=1e9)):
        result=measure(scene(),recipe,config)
        assert result.findings==(Finding.UNOBSERVABLE,)*4
        assert not result.quality_ok


@pytest.mark.parametrize("measured,permitted,expected", [((10.2,10.8),(10.,11.),Finding.SATISFIED),
    ((9.9,10.1),(10.,11.),Finding.UNOBSERVABLE),((11.1,11.3),(10.,11.),Finding.VIOLATED),
    ((10.,11.),(10.,11.),Finding.SATISFIED),((float('nan'),11.),(10.,11.),Finding.UNOBSERVABLE)])
def test_measurement_interval_boundaries(measured,permitted,expected):
    assert interval_finding(measured,permitted)==expected


def test_bounded_decode_and_metadata_strip():
    image=scene()
    ok,encoded=cv2.imencode('.png',image)
    assert ok
    assert np.array_equal(decode_image(encoded.tobytes()),image)
    for bad in (b'',b'not an image',encoded.tobytes()[:30]):
        with pytest.raises(InvalidImage):
            decode_image(bad)
    with pytest.raises(InvalidImage):
        decode_image(encoded.tobytes(),max_pixels=100)
    with pytest.raises(InvalidImage):
        decode_image(encoded.tobytes(),max_bytes=100)
    output=BytesIO()
    Image.new('RGB',(20,20)).save(output,format='GIF')
    with pytest.raises(InvalidImage):
        decode_image(output.getvalue())
