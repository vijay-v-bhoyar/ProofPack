from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from math import isfinite

from proofpack.recipes.models import Origin


class Split(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    VALIDATION = "VALIDATION"
    FROZEN_TEST = "FROZEN_TEST"


@dataclass(frozen=True)
class Example:
    example_id: str
    kit_group: str
    session_group: str
    operator_group: str
    split: Split
    origin: Origin
    permitted: bool
    expires_at: float
    label_revision: int
    reviewer_independent: bool


def manifest(examples: tuple[Example, ...], *, now: float) -> dict:
    if not isfinite(now):
        raise ValueError("valid authority time required")
    if not examples or len(examples) > 1000 or len({e.example_id for e in examples}) != len(examples):
        raise ValueError("manifest must have 1–1000 distinct examples")
    groups = {}
    for e in examples:
        if not e.permitted or not isfinite(e.expires_at) or now >= e.expires_at or e.label_revision < 1:
            raise ValueError("unavailable permission or reviewed label")
        for category, group in (("kit", e.kit_group), ("session", e.session_group), ("operator", e.operator_group)):
            if not group:
                raise ValueError("grouping identity required")
            key = (category, group)
            if key in groups and groups[key] != e.split:
                raise ValueError("group leakage across splits")
            groups[key] = e.split
    rows = [{"id": e.example_id, "label_revision": e.label_revision, "split": e.split.value,
             "origin": e.origin.value, "independent": e.reviewer_independent,
             "kit_group": e.kit_group, "session_group": e.session_group,
             "operator_group": e.operator_group, "permitted": e.permitted,
             "expires_at": e.expires_at} for e in sorted(examples, key=lambda x:x.example_id)]
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"rows": rows, "sha256": digest, "expires_at": min(e.expires_at for e in examples)}


def throughput(*, correct_completions: int, total_operator_seconds: float) -> float:
    if correct_completions < 0 or not isfinite(total_operator_seconds) or total_operator_seconds <= 0:
        raise ValueError("positive total effort and nonnegative completions required")
    return correct_completions * 3600 / total_operator_seconds
