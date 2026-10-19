"""Bounded image validation and explicit-envelope contour measurements.

Shape rules are development prototypes, not qualified hardware recognition.
Run decoding/analysis only inside the bounded process worker at the API boundary.
"""
from dataclasses import dataclass
from io import BytesIO
import warnings

import cv2
import numpy as np
from PIL import Image

from proofpack.recipes.models import Origin, PartClass, Recipe
from proofpack.verifier.core import Finding


class InvalidImage(ValueError):
    pass


def decode_image(payload: bytes, *, max_bytes: int = 2097152, max_pixels: int = 2000000) -> np.ndarray:
    if not payload or len(payload) > max_bytes:
        raise InvalidImage("image byte limit exceeded or empty")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(payload)) as image:
                if image.format not in {"JPEG", "PNG"} or getattr(image, "n_frames", 1) != 1:
                    raise InvalidImage("only single-frame JPEG/PNG accepted")
                if image.width * image.height > max_pixels or min(image.size) < 16:
                    raise InvalidImage("decoded image dimensions outside bounds")
                image.verify()
            # Pillow getexif() may load/close a PNG stream. Verify the original
            # bytes first, then inspect orientation using an independent stream.
            with Image.open(BytesIO(payload)) as image:
                if image.getexif().get(274, 1) != 1:
                    raise InvalidImage("orientation must be normalized before upload")
        result = cv2.imdecode(np.frombuffer(payload, np.uint8), cv2.IMREAD_COLOR)
        if result is None or result.shape[0] * result.shape[1] > max_pixels:
            raise InvalidImage("decode failed or exceeded pixel bound")
        return result
    except (OSError, SyntaxError, ValueError, Image.DecompressionBombError,
            Image.DecompressionBombWarning, cv2.error) as exc:
        raise InvalidImage("invalid or unsupported bounded image") from exc


@dataclass(frozen=True)
class Envelope:
    width: int
    height: int
    pixels_per_mm: float
    measurement_error_mm: float
    min_area_px: float
    min_blur_variance: float
    threshold_gray: int
    origin: Origin
    # Caller must independently validate observed mat markers against enrolled geometry.
    markers_verified: bool = False

    def __post_init__(self):
        values = (self.pixels_per_mm, self.measurement_error_mm, self.min_area_px, self.min_blur_variance)
        if (not all(np.isfinite(x) for x in values) or self.pixels_per_mm <= 0
                or min(self.measurement_error_mm, self.min_blur_variance) < 0 or self.min_area_px <= 0
                or self.width < 16 or self.height < 16 or self.width * self.height > 2000000
                or not 1 <= self.threshold_gray <= 254):
            raise ValueError("invalid measurement envelope")


@dataclass(frozen=True)
class Candidate:
    part_class: PartClass | None
    box: tuple[int, int, int, int]
    dimension_interval_mm: tuple[float, float]
    correction_reason: str | None = None
    aspect_ratio_interval: tuple[float, float] | None = None


@dataclass(frozen=True)
class Measurement:
    candidates: tuple[Candidate, ...]
    findings: tuple[Finding, ...]
    reason_codes: tuple[str, ...]
    quality_ok: bool
    unknown_regions: int


def interval_finding(measured: tuple[float, float], permitted: tuple[float, float]) -> Finding:
    lo, hi = measured
    low, high = permitted
    if not all(np.isfinite(x) for x in (*measured, *permitted)) or lo > hi or low > high:
        return Finding.UNOBSERVABLE
    if low <= lo <= hi <= high:
        return Finding.SATISFIED
    if hi < low or lo > high:
        return Finding.VIOLATED
    return Finding.UNOBSERVABLE


def measure(frame: np.ndarray, recipe: Recipe, envelope: Envelope, *,
            max_contours: int = 4096, max_candidates: int = 30) -> Measurement:
    def abstain(reason: str) -> Measurement:
        return Measurement((), tuple(Finding.UNOBSERVABLE for _ in recipe.constraints), (reason,), False, 0)
    if (frame.dtype != np.uint8 or frame.ndim != 3 or frame.shape[2] != 3
            or frame.shape[:2] != (envelope.height, envelope.width)):
        return abstain("frame_shape")
    if not envelope.markers_verified:
        return abstain("calibration")
    if recipe.data_origin != envelope.origin:
        return abstain("origin_mismatch")
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    if cv2.Laplacian(gray, cv2.CV_64F).var() < envelope.min_blur_variance:
        return abstain("blur")
    _, mask = cv2.threshold(gray, envelope.threshold_gray, 255, cv2.THRESH_BINARY_INV)
    contours, hierarchy = cv2.findContours(mask, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
    if len(contours)>max_contours:
        return abstain("too_many_regions")
    candidates = []
    reasons = set()
    if hierarchy is not None:
        for index, contour in enumerate(contours):
            if hierarchy[0][index][3] != -1 or cv2.contourArea(contour) < envelope.min_area_px:
                continue
            x, y, w, h = cv2.boundingRect(contour)
            if x <= 0 or y <= 0 or x+w >= envelope.width or y+h >= envelope.height:
                return abstain("clipped_roi")
            perimeter = cv2.arcLength(contour, True)
            polygon = cv2.approxPolyDP(contour, .025 * perimeter, True)
            holes = 0
            child = hierarchy[0][index][2]
            while child != -1:
                if cv2.contourArea(contours[child]) >= envelope.min_area_px / 4:
                    holes += 1
                child = hierarchy[0][child][0]
            aspect = max(w, h) / min(w, h)
            circularity = 4 * np.pi * cv2.contourArea(contour) / max(1, perimeter**2)
            kind = None
            if holes == 1 and aspect < 1.25:
                if len(polygon) == 6:
                    kind = PartClass.NUT
                elif len(polygon) >= 7 and circularity > .7:
                    kind = PartClass.WASHER
            elif holes == 2 and aspect >= 1.5 and cv2.isContourConvex(polygon):
                kind = PartClass.FLAT_BRACKET
            elif holes == 0 and aspect >= 2.5 and 4 <= len(polygon) <= 10:
                kind = PartClass.BOLT
            cue=None;projection=None
            if kind is None:
                reasons.add("unknown_or_overlap")
                if holes>=2 and not cv2.isContourConvex(polygon):
                    cue='overlap';reasons.add(cue)
            else:
                selected=next((c for c in recipe.constraints if c.part_class_id==kind),None)
                if (selected is not None and selected.expected_count>0 and not selected.permitted_variant_ids
                        and selected.flat_reference_aspect_ratio is not None):
                    long_side,short_side=sorted(cv2.minAreaRect(contour)[1],reverse=True)
                    error=envelope.measurement_error_mm*envelope.pixels_per_mm
                    if short_side>error:
                        projection=(max(1.,(long_side-error)/(short_side+error)),max(1.,(long_side+error)/(short_side-error)))
                    reference=selected.flat_reference_aspect_ratio
                    if projection is None or interval_finding(projection,(reference.minimum,reference.maximum))!=Finding.SATISFIED:
                        cue='not_flat';reasons.add(cue)
            dimension = max(w - 1, h - 1) / envelope.pixels_per_mm
            if len(candidates)>=max_candidates:
                return abstain("too_many_objects")
            candidates.append(Candidate(kind, (x, y, w, h),
                                        (max(0, dimension - envelope.measurement_error_mm),
                                         dimension + envelope.measurement_error_mm),cue,projection))
    unknowns = sum(c.part_class is None for c in candidates)
    enrolled = {c.part_class_id for c in recipe.constraints}
    extras = sum(c.part_class not in enrolled for c in candidates if c.part_class is not None)
    results = []
    for constraint in recipe.constraints:
        matching = [c for c in candidates if c.part_class == constraint.part_class_id]
        if unknowns:
            result = Finding.UNOBSERVABLE
        elif any(c.correction_reason=='not_flat' for c in matching):
            result = Finding.UNOBSERVABLE
        elif len(matching) != constraint.expected_count:
            result = Finding.VIOLATED
            reasons.add("missing" if len(matching) < constraint.expected_count else "extra")
        elif constraint.permitted_variant_ids:
            result = Finding.UNOBSERVABLE
            reasons.add("unsupported_variant")
        elif constraint.dimension_mm:
            dimensions = [interval_finding(c.dimension_interval_mm,
                         (constraint.dimension_mm.minimum, constraint.dimension_mm.maximum)) for c in matching]
            result = (Finding.VIOLATED if Finding.VIOLATED in dimensions else
                      Finding.UNOBSERVABLE if Finding.UNOBSERVABLE in dimensions else Finding.SATISFIED)
        else:
            result = Finding.SATISFIED
        results.append(result)
    if extras:
        reasons.add("extra")
    return Measurement(tuple(candidates), tuple(results), tuple(sorted(reasons)), True, unknowns + extras)
