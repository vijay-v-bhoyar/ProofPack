"""Pure F4 decisions. Persistence must condition-check the same authority snapshot."""
from dataclasses import dataclass, replace
from enum import StrEnum
from math import isfinite


class State(StrEnum):
    CREATED = "CREATED"
    OBSERVING = "OBSERVING"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    PASSED_CURRENT = "PASSED_CURRENT"
    INVALIDATED = "INVALIDATED"
    CLOSED = "CLOSED"


class Finding(StrEnum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    UNOBSERVABLE = "UNOBSERVABLE"


@dataclass(frozen=True)
class Authority:
    """All values originate in the repository, never directly from browser fields."""
    runtime: int
    control: int
    data: int
    station: int
    recipe: int
    calibration: int
    policy: int
    access: int
    session: str
    artifact: str
    enabled: bool
    operator_granted: bool
    dependencies_valid: bool
    valid_until_tick: float


@dataclass(frozen=True)
class Observation:
    observation_id: str
    sequence: int
    scene: int
    accepted_tick: float
    permit_tick: float
    findings: tuple[Finding, ...]
    expected_constraints: int
    quality_ok: bool
    unknown_regions: int
    evidence_durable: bool
    authority: Authority


@dataclass(frozen=True)
class Inspection:
    inspection_id: str
    authority: Authority
    state: State = State.CREATED
    version: int = 1
    latest_input_sequence: int = 0
    verified_sequence: int = 0
    scene: int = 0
    stable_ticks: tuple[float, ...] = ()
    deadline_tick: float = 0
    corrections: int = 0
    disposition: str | None = None


class Conflict(ValueError):
    pass


def authority_valid(bound: Authority, current: Authority, now: float) -> bool:
    return (bound == current and current.enabled and current.operator_granted
            and current.dependencies_valid and isfinite(now)
            and now < current.valid_until_tick)


def effective_state(inspection: Inspection, current: Authority, now: float) -> State:
    if inspection.state == State.CLOSED:
        return State.CLOSED
    if not authority_valid(inspection.authority, current, now):
        return State.INVALIDATED
    if inspection.state == State.PASSED_CURRENT and now >= inspection.deadline_tick:
        return State.INVALIDATED
    return inspection.state


def remaining_lease_ms(inspection: Inspection, current: Authority, now: float) -> int:
    if effective_state(inspection, current, now) != State.PASSED_CURRENT:
        return 0
    # Floor milliseconds: rounding up must never extend authority.
    return max(0, int((min(inspection.deadline_tick, current.valid_until_tick) - now) * 1000))


def admit_sequence(inspection: Inspection, sequence: int) -> Inspection:
    if inspection.state in {State.CLOSED, State.REVIEW_REQUIRED}:
        raise Conflict("terminal inspection cannot accept capture")
    if sequence != inspection.latest_input_sequence + 1:
        raise Conflict("sequence must be the next admitted input")
    return replace(inspection, latest_input_sequence=sequence, version=inspection.version + 1)


def verify(inspection: Inspection, observation: Observation, current: Authority, now: float,
           *, lease_ms: int = 1500, max_age_ms: int = 1000,
           stable_count: int = 3, stable_span_ms: int = 1000) -> Inspection:
    if inspection.state in {State.CLOSED, State.REVIEW_REQUIRED, State.ACTION_REQUIRED}:
        raise Conflict("closed/review/action-waiting inspection cannot publish a finding")
    if observation.sequence != inspection.latest_input_sequence or observation.sequence <= inspection.verified_sequence:
        raise Conflict("superseded or replayed observation")
    ticks = (now, observation.accepted_tick, observation.permit_tick)
    fresh = (all(isfinite(t) for t in ticks)
             and observation.permit_tick <= observation.accepted_tick <= now
             and now < observation.permit_tick + max_age_ms / 1000)
    valid = (authority_valid(inspection.authority, current, now)
             and observation.authority == current and fresh)
    if not valid:
        return replace(inspection, state=State.INVALIDATED, stable_ticks=(), deadline_tick=0,
                       version=inspection.version + 1)
    if not observation.evidence_durable:
        return replace(inspection, state=State.REVIEW_REQUIRED, stable_ticks=(), deadline_tick=0,
                       version=inspection.version + 1)
    all_satisfied = (observation.expected_constraints > 0
                     and len(observation.findings) == observation.expected_constraints
                     and all(f == Finding.SATISFIED for f in observation.findings)
                     and observation.quality_ok and observation.unknown_regions == 0)
    ticks_before = inspection.stable_ticks if observation.scene == inspection.scene else ()
    if ticks_before and observation.accepted_tick <= ticks_before[-1]:
        raise Conflict("non-monotone accepted observation")
    stable = (*ticks_before, observation.accepted_tick) if all_satisfied else ()
    # Keep a bounded window large enough to demonstrate the required span.
    if len(stable) > 32:
        stable = (stable[0], *stable[-31:])
    sufficiently_stable = (len(stable) >= stable_count
                           and (stable[-1] - stable[0]) * 1000 >= stable_span_ms)
    deadline = min(observation.accepted_tick + lease_ms / 1000,
                   observation.permit_tick + max_age_ms / 1000, current.valid_until_tick)
    state = State.PASSED_CURRENT if all_satisfied and sufficiently_stable and now < deadline else State.OBSERVING
    return replace(inspection, state=state, version=inspection.version + 1,
                   verified_sequence=observation.sequence, scene=observation.scene,
                   stable_ticks=stable, deadline_tick=deadline if state == State.PASSED_CURRENT else 0)


def close(inspection: Inspection, *, disposition: str | None = None) -> Inspection:
    if inspection.state == State.CLOSED:
        return inspection
    if inspection.state == State.REVIEW_REQUIRED and not (disposition or inspection.disposition):
        raise Conflict("unresolved review requires a separate disposition before closure")
    return replace(inspection, state=State.CLOSED, disposition=disposition or inspection.disposition,
                   stable_ticks=(), deadline_tick=0, version=inspection.version + 1)
