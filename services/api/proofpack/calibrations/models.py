from typing import Literal

from pydantic import Field,model_validator

from proofpack.recipes.models import Contract,Identifier,Origin
from proofpack.vision.calibration_diagnostics import CalibrationSettings


class Enrollment(Contract):
    name:str=Field(min_length=1,max_length=80)
    camera_id:Identifier
    mat_version:Literal['desktop-v1']
    reference_asset_id:str=Field(pattern=r'^[a-f0-9-]{36}$')
    data_origin:Origin
    settings:CalibrationSettings


class DiagnosticCase(Contract):
    asset_id:str=Field(pattern=r'^[a-f0-9-]{36}$')
    expected:Literal['supported','rejected']


class QualificationRequest(Contract):
    cases:tuple[DiagnosticCase,...]=Field(min_length=2,max_length=8)

    @model_validator(mode='after')
    def coverage(self):
        if len({item.asset_id for item in self.cases})!=len(self.cases) or {item.expected for item in self.cases}!={'supported','rejected'}:
            raise ValueError('distinct supported and rejected reference cases required')
        return self


class PhysicalReview(Contract):
    ruler_nominal_mm:float=Field(gt=0,allow_inf_nan=False)
    ruler_measured_mm:float=Field(gt=0,allow_inf_nan=False)
    ruler_uncertainty_mm:float=Field(ge=0,allow_inf_nan=False)
    lens_residual_px:float=Field(ge=0,allow_inf_nan=False)
    lens_evidence_asset_ids:tuple[str,...]=Field(min_length=1,max_length=9)
    scope_evidence_asset_ids:tuple[str,...]=Field(min_length=1,max_length=9)
    camera_id:Identifier
    reviewed_by:Identifier
    reviewer_access_version:int=Field(ge=1)
    independence_verified:bool
