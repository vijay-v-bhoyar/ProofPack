"""Approved-envelope marker checking and planar rectification; no hidden-geometry inference."""
import hashlib
from typing import Annotated, Self

import cv2
import numpy as np
from pydantic import Field, model_validator

from proofpack.recipes.models import Contract, Identifier, Origin
from proofpack.vision.pipeline import Envelope

Finite = Annotated[float, Field(allow_inf_nan=False)]
Point = tuple[Finite, Finite]
Quad = tuple[Point, Point, Point, Point]
FourQuads = tuple[Quad, Quad, Quad, Quad]


class CalibrationError(ValueError):
    """Safe reason code suitable for a failed inspection, not a traceback."""


class CalibrationProfile(Contract):
    profile_id: Identifier
    revision: int = Field(ge=1)
    camera_id: Identifier
    frame_width: int = Field(ge=16, le=2000)
    frame_height: int = Field(ge=16, le=2000)
    output_width: int = Field(ge=16, le=2000)
    output_height: int = Field(ge=16, le=2000)
    physical_width_mm: Finite = Field(gt=0)
    physical_height_mm: Finite = Field(gt=0)
    marker_ids: tuple[int, int, int, int]
    plane_corners: FourQuads
    enrolled_image_corners: FourQuads
    max_displacement_px: Finite = Field(gt=0, le=20)
    max_reprojection_error_px: Finite = Field(gt=0, le=5)
    measurement_error_mm: Finite = Field(ge=0)
    min_area_px: Finite = Field(gt=0)
    min_blur_variance: Finite = Field(ge=0)
    threshold_gray: int = Field(ge=1, le=254)
    data_origin: Origin
    # Physical lens qualification remains mandatory; this initial geometry
    # implementation supports only a separately qualified rectilinear lens.
    lens_model: str = Field(pattern=r"^rectilinear_qualified$")

    @model_validator(mode="after")
    def valid_geometry(self) -> Self:
        if max(self.frame_width*self.frame_height, self.output_width*self.output_height) > 2000000:
            raise ValueError("pixel bound exceeded")
        if len(set(self.marker_ids)) != 4 or any(not 0 <= i < 50 for i in self.marker_ids):
            raise ValueError("four distinct DICT_4X4_50 IDs required")
        if not np.isclose(self.output_width/self.physical_width_mm,
                          self.output_height/self.physical_height_mm, rtol=1e-6):
            raise ValueError("rectified plane must have an isotropic scale")
        for quads, width, height, margin in (
            (self.enrolled_image_corners,self.frame_width,self.frame_height,0),
            (self.plane_corners,self.output_width,self.output_height,2),
        ):
            for quad in quads:
                points=np.asarray(quad,dtype=np.float32)
                if (not cv2.isContourConvex(points) or cv2.contourArea(points) < 16
                        or (points[:,0] < -margin*width).any() or (points[:,0] > (1+margin)*width).any()
                        or (points[:,1] < -margin*height).any() or (points[:,1] > (1+margin)*height).any()):
                    raise ValueError("invalid or out-of-bounds marker quadrilateral")
        return self

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


def detect_markers(frame: np.ndarray, marker_ids: tuple[int,int,int,int]) -> FourQuads:
    if frame.dtype != np.uint8 or frame.ndim != 3 or frame.shape[2] != 3 or frame.size > 6000000:
        raise CalibrationError("frame_shape")
    dictionary=cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_4X4_50)
    parameters=cv2.aruco.DetectorParameters()
    parameters.cornerRefinementMethod=cv2.aruco.CORNER_REFINE_SUBPIX
    detector=cv2.aruco.ArucoDetector(dictionary,parameters)
    corners,ids,_=detector.detectMarkers(cv2.cvtColor(frame,cv2.COLOR_BGR2GRAY))
    found=[] if ids is None else [int(i) for i in ids.flatten()]
    if len(found)!=4 or set(found)!=set(marker_ids):
        raise CalibrationError("markers_missing_duplicate_or_extra")
    indexed={ident:quad.reshape(4,2) for ident,quad in zip(found,corners,strict=True)}
    return tuple(tuple(tuple(float(v) for v in point) for point in indexed[i]) for i in marker_ids)


def rectify(frame: np.ndarray, profile: CalibrationProfile) -> tuple[np.ndarray,Envelope]:
    if frame.shape[:2] != (profile.frame_height,profile.frame_width):
        raise CalibrationError("frame_shape")
    corners=detect_markers(frame,profile.marker_ids)
    source=np.asarray(corners,np.float64).reshape(-1,2)
    reference=np.asarray(profile.enrolled_image_corners,np.float64).reshape(-1,2)
    if np.linalg.norm(source-reference,axis=1).max() > profile.max_displacement_px:
        raise CalibrationError("camera_or_mat_moved")
    target=np.asarray(profile.plane_corners,np.float64).reshape(-1,2)
    homography,_=cv2.findHomography(source,target,method=0)
    if homography is None or not np.isfinite(homography).all() or abs(np.linalg.det(homography)) < 1e-12:
        raise CalibrationError("invalid_plane")
    projected=cv2.perspectiveTransform(source.reshape(1,-1,2),homography).reshape(-1,2)
    if np.linalg.norm(projected-target,axis=1).max() > profile.max_reprojection_error_px:
        raise CalibrationError("marker_residual")
    # Reject a projected ROI that requires pixels outside the admitted frame.
    roi=np.float64([[[0,0],[profile.output_width-1,0],
                     [profile.output_width-1,profile.output_height-1],[0,profile.output_height-1]]])
    try:
        image_roi=cv2.perspectiveTransform(roi,np.linalg.inv(homography)).reshape(-1,2)
    except np.linalg.LinAlgError as exc:
        raise CalibrationError("invalid_plane") from exc
    if (not np.isfinite(image_roi).all() or (image_roi<0).any()
            or (image_roi[:,0]>=profile.frame_width).any() or (image_roi[:,1]>=profile.frame_height).any()):
        raise CalibrationError("clipped_roi")
    result=cv2.warpPerspective(frame,homography,(profile.output_width,profile.output_height),
                               flags=cv2.INTER_LINEAR,borderMode=cv2.BORDER_CONSTANT,borderValue=(255,255,255))
    envelope=Envelope(profile.output_width,profile.output_height,
        profile.output_width/profile.physical_width_mm,profile.measurement_error_mm,
        profile.min_area_px,profile.min_blur_variance,profile.threshold_gray,profile.data_origin,True)
    return result,envelope
