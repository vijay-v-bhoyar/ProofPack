"""Bounded child result schema: no state, authority, tool or action permission field."""
from typing import Annotated,Literal
import base64
import hashlib

from pydantic import Field,model_validator

from proofpack.recipes.models import Contract,PartClass
from proofpack.verifier.core import Finding

Coordinate=Annotated[int,Field(ge=0,le=2000)]
Finite=Annotated[float,Field(ge=0,allow_inf_nan=False)]
Reason=Annotated[str,Field(pattern=r'^[a-z_]{1,64}$')]


class WorkerCandidate(Contract):
    part_class: PartClass | None
    box: tuple[Coordinate,Coordinate,Coordinate,Coordinate]
    dimension_interval_mm: tuple[Finite,Finite]
    correction_reason: Literal['overlap','not_flat'] | None = Field(default=None,exclude_if=lambda value:value is None)
    aspect_ratio_interval: tuple[Finite,Finite] | None = Field(default=None,exclude_if=lambda value:value is None)

    @model_validator(mode='after')
    def valid(self):
        if min(self.box[2:])<1 or self.dimension_interval_mm[0]>self.dimension_interval_mm[1]:
            raise ValueError('invalid candidate bounds')
        if self.aspect_ratio_interval is not None and not 1<=self.aspect_ratio_interval[0]<=self.aspect_ratio_interval[1]:
            raise ValueError('ordered finite projected aspect interval required')
        if (self.correction_reason=='overlap' and self.part_class is not None) or (self.correction_reason=='not_flat' and self.part_class is None):
            raise ValueError('correction cue differs from measured candidate class')
        return self


class WorkerResult(Contract):
    candidates: tuple[WorkerCandidate,...] = Field(max_length=30)
    findings: tuple[Finding,...] = Field(min_length=1,max_length=4)
    reason_codes: tuple[Reason,...] = Field(max_length=16)
    quality_ok: bool
    unknown_regions: int = Field(ge=0,le=30)
    scene_generation: int = Field(ge=1)
    scene_changed: bool
    source_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    calibration_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    rectified_size: tuple[Coordinate,Coordinate] | None = Field(default=None,exclude_if=lambda value:value is None)
    evidence_jpeg_base64: str | None = Field(default=None,max_length=218456,repr=False)
    evidence_sha256: str | None = Field(default=None,pattern=r'^[a-f0-9]{64}$')

    @model_validator(mode='after')
    def evidence_integrity(self):
        if self.rectified_size is not None:
            width,height=self.rectified_size
            if min(width,height)<16 or width*height>2000000:raise ValueError('bounded rectified dimensions required')
            if any(c.box[0]+c.box[2]>width or c.box[1]+c.box[3]>height for c in self.candidates):
                raise ValueError('candidate outside its measured crop')
        if any(c.correction_reason is not None and (self.rectified_size is None or not self.quality_ok or c.correction_reason not in self.reason_codes) for c in self.candidates):
            raise ValueError('correction target requires matching measured reason and crop')
        if (self.evidence_jpeg_base64 is None)!=(self.evidence_sha256 is None):raise ValueError('paired derived evidence required')
        if self.evidence_jpeg_base64 is not None:
            try:raw=base64.b64decode(self.evidence_jpeg_base64,validate=True)
            except (ValueError,UnicodeError) as exc:raise ValueError('bounded evidence encoding required') from exc
            if (not 0<len(raw)<=163840 or not raw.startswith(b'\xff\xd8') or not raw.endswith(b'\xff\xd9')
                    or hashlib.sha256(raw).hexdigest()!=self.evidence_sha256):raise ValueError('derived evidence integrity failed')
        return self

    def evidence_bytes(self):
        return None if self.evidence_jpeg_base64 is None else base64.b64decode(self.evidence_jpeg_base64,validate=True)
