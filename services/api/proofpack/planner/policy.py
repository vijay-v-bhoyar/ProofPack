from dataclasses import dataclass, replace
from enum import StrEnum

from proofpack.verifier.core import Conflict, Inspection, State


class ActionKind(StrEnum):
    RECAPTURE = "RECAPTURE"
    SEPARATE_REGION = "SEPARATE_REGION"
    PLACE_FLAT = "PLACE_FLAT"
    REVIEW = "REVIEW"


TEMPLATES = {
    ActionKind.RECAPTURE: "Check lighting and capture another image.",
    ActionKind.SEPARATE_REGION: "Separate the parts in the highlighted region, then recheck.",
    ActionKind.PLACE_FLAT: "Place the highlighted part flat on the work surface, then recheck.",
    ActionKind.REVIEW: "Stop automated checking and ask the supervisor for manual review.",
}


@dataclass(frozen=True)
class Action:
    action_id: str
    kind: ActionKind
    observation_id: str
    scene: int
    source_version: int
    policy_mode: str = "deterministic_policy"

    @property
    def message(self) -> str:
        return TEMPLATES[self.kind]


DEFAULT_PRIORITY = (ActionKind.SEPARATE_REGION, ActionKind.PLACE_FLAT, ActionKind.RECAPTURE)
REASON_ACTIONS = {
    "overlap": ActionKind.SEPARATE_REGION, "not_flat": ActionKind.PLACE_FLAT,
    **{reason: ActionKind.RECAPTURE for reason in ("blur", "glare", "motion", "missing", "extra")},
}


def choose_action(reason_codes: tuple[str, ...], *, priority=DEFAULT_PRIORITY) -> ActionKind:
    if (not isinstance(priority, tuple) or len(priority) != 3
            or any(not isinstance(item, ActionKind) for item in priority) or set(priority) != set(DEFAULT_PRIORITY)):
        raise ValueError("installed corrective-action permutation required")
    eligible = {REASON_ACTIONS[reason] for reason in reason_codes if reason in REASON_ACTIONS}
    return next((kind for kind in priority if kind in eligible), ActionKind.REVIEW)


def issue(inspection: Inspection, action: Action, *, latest_observation_id: str,
          max_requests: int = 2) -> Inspection:
    if inspection.state != State.OBSERVING:
        raise Conflict("action requires a current unresolved observation")
    if (action.source_version != inspection.version or action.scene != inspection.scene
            or action.observation_id != latest_observation_id):
        raise Conflict("stale proposal")
    kind = action.kind if inspection.corrections < max_requests else ActionKind.REVIEW
    return replace(inspection, state=State.REVIEW_REQUIRED if kind == ActionKind.REVIEW else State.ACTION_REQUIRED,
                   corrections=inspection.corrections + (kind != ActionKind.REVIEW),
                   stable_ticks=(), deadline_tick=0, version=inspection.version + 1)


def acknowledge(inspection: Inspection, action: Action, action_id: str) -> Inspection:
    if action.action_id != action_id or action.scene != inspection.scene:
        raise Conflict("acknowledgment does not match issued action")
    if inspection.state != State.ACTION_REQUIRED or inspection.version != action.source_version + 1:
        raise Conflict("action is no longer pending")
    return replace(inspection, state=State.OBSERVING, version=inspection.version + 1,
                   stable_ticks=(), deadline_tick=0)
