"""Actual bounded-child marker/plane diagnostics, never physical truth or a live pass."""
import hashlib
import json
from typing import Literal

import cv2
import numpy as np
from pydantic import Field,model_validator

from proofpack.recipes.models import Contract,Identifier,Origin
from proofpack.vision.calibration import CalibrationError,CalibrationProfile,detect_markers,rectify
from proofpack.vision.mat import MARKER_IDS,plane_corners
from proofpack.vision.pipeline import InvalidImage,decode_image


class CalibrationSettings(Contract):
    max_displacement_px:float=Field(gt=0,le=20,allow_inf_nan=False)
    max_reprojection_error_px:float=Field(gt=0,le=5,allow_inf_nan=False)
    measurement_error_mm:float=Field(ge=0,allow_inf_nan=False)
    min_area_px:float=Field(gt=0,allow_inf_nan=False)
    min_blur_variance:float=Field(ge=0,allow_inf_nan=False)
    threshold_gray:int=Field(ge=1,le=254)


class EnrollmentParameters(Contract):
    mode:Literal['enroll']
    profile_id:Identifier
    revision:int=Field(ge=1)
    camera_id:Identifier
    mat_version:Literal['desktop-v1']
    data_origin:Origin
    settings:CalibrationSettings


class CheckParameters(Contract):
    mode:Literal['check']
    profile:CalibrationProfile


class CalibrationDiagnostic(Contract):
    accepted:bool
    source_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    profile:CalibrationProfile|None
    profile_sha256:str|None=Field(default=None,pattern=r'^[a-f0-9]{64}$')
    reason_codes:tuple[str,...]=Field(max_length=4)
    blur_variance:float|None=Field(default=None,ge=0,allow_inf_nan=False)
    max_displacement_px:float|None=Field(default=None,ge=0,allow_inf_nan=False)
    max_reprojection_error_px:float|None=Field(default=None,ge=0,allow_inf_nan=False)
    physical_truth_verified:Literal[False]=False

    @model_validator(mode='after')
    def provenance(self):
        if self.profile is not None and self.profile_sha256!=self.profile.content_hash:raise ValueError('diagnostic profile hash mismatch')
        if self.profile is None and self.profile_sha256 is not None:raise ValueError('missing diagnostic profile')
        if self.accepted and (self.profile is None or self.reason_codes or any(value is None for value in
            (self.blur_variance,self.max_displacement_px,self.max_reprojection_error_px))):raise ValueError('complete successful diagnostic required')
        if not self.accepted and not self.reason_codes:raise ValueError('failed diagnostic reason required')
        return self


def diagnose_calibration(payload,parameters,*,max_bytes):
    mode=parameters.get('mode') if isinstance(parameters,dict) else None
    spec=EnrollmentParameters.model_validate_json(json.dumps(parameters)) if mode=='enroll' else CheckParameters.model_validate_json(json.dumps(parameters))
    profile=None if mode=='enroll' else spec.profile
    source=hashlib.sha256(payload).hexdigest()
    try:
        frame=decode_image(payload,max_bytes=max_bytes)
        corners=detect_markers(frame,MARKER_IDS if profile is None else profile.marker_ids)
        if profile is None:
            profile=CalibrationProfile(profile_id=spec.profile_id,revision=spec.revision,camera_id=spec.camera_id,
                frame_width=frame.shape[1],frame_height=frame.shape[0],output_width=600,output_height=300,
                physical_width_mm=200.,physical_height_mm=100.,marker_ids=MARKER_IDS,plane_corners=plane_corners(),
                enrolled_image_corners=corners,data_origin=spec.data_origin,lens_model='rectilinear_qualified',**spec.settings.model_dump())
        rectify(frame,profile)
        observed=np.asarray(corners,np.float64).reshape(-1,2);enrolled=np.asarray(profile.enrolled_image_corners,np.float64).reshape(-1,2)
        target=np.asarray(profile.plane_corners,np.float64).reshape(-1,2)
        homography,_=cv2.findHomography(observed,target,method=0)
        projected=cv2.perspectiveTransform(observed.reshape(1,-1,2),homography).reshape(-1,2)
        blur=float(cv2.Laplacian(cv2.cvtColor(frame,cv2.COLOR_BGR2GRAY),cv2.CV_64F).var())
        if blur<profile.min_blur_variance:raise CalibrationError('blur_below_envelope')
        return CalibrationDiagnostic(accepted=True,source_sha256=source,profile=profile,profile_sha256=profile.content_hash,reason_codes=(),
            blur_variance=blur,max_displacement_px=float(np.linalg.norm(observed-enrolled,axis=1).max()),
            max_reprojection_error_px=float(np.linalg.norm(projected-target,axis=1).max()))
    except (CalibrationError,InvalidImage) as exc:
        return CalibrationDiagnostic(accepted=False,source_sha256=source,profile=profile,profile_sha256=None if profile is None else profile.content_hash,
            reason_codes=(str(exc) if isinstance(exc,CalibrationError) else 'invalid_image',))
