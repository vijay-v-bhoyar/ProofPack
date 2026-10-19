"""Bounded observational decision replay, never counterfactual physical truth."""
from dataclasses import dataclass
from typing import Literal
from pydantic import Field,model_validator
from proofpack.recipes.models import Contract
from proofpack.review.labels import UUIDText
from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.rollback import RollbackTarget
from proofpack.planner.policy import ActionKind,choose_action
from proofpack.verifier.core import Finding
from proofpack.vision.worker_result import Reason


class EvaluationLimited(RuntimeError):pass


@dataclass(frozen=True)
class EvaluationConfig:
    jobs_per_minute:int
    step_attempts_per_minute:int
    reads_per_minute:int
    lifetime_ms:int
    lease_ms:int
    max_steps:int

    def __post_init__(self):
        if any(type(v) is not int or not lo<=v<=hi for v,lo,hi in (
            (self.jobs_per_minute,1,20),(self.step_attempts_per_minute,1,120),(self.reads_per_minute,1,120),
            (self.lifetime_ms,1000,3600000),(self.lease_ms,1000,60000),(self.max_steps,1,10000))):
            raise ValueError('explicit bounded evaluation configuration required')


class EvaluationRequest(Contract):
    runner:Literal['decision_replay_v1']
    policy_id:UUIDText
    policy_revision:int=Field(ge=1,le=1000)
    policy_state_version:int=Field(ge=1,le=9007199254740991)
    policy_revision_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    manifest_id:UUIDText
    manifest_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    historical_diagnostic_acknowledged:bool
    frozen_holdout_acknowledged:bool
    rollback_target:RollbackTarget|None=Field(default=None,exclude_if=lambda value:value is None)

    @model_validator(mode='after')
    def acknowledged(self):
        if self.historical_diagnostic_acknowledged is not True:raise ValueError('explicit historical diagnostic acknowledgment required')
        return self


def parse_evaluation_request(text):
    import json
    from proofpack.review.vision_replay import VisionReplayRequest
    raw=json.loads(text)
    model=VisionReplayRequest if isinstance(raw,dict) and raw.get('runner')=='vision_replay_v1' else EvaluationRequest
    return model.model_validate_json(text)


class MeasuredDecision(Contract):
    observation_id:UUIDText
    sequence:int=Field(ge=1)
    findings:tuple[Finding,...]=Field(min_length=1,max_length=4)
    reason_codes:tuple[Reason,...]=Field(max_length=16)
    quality_ok:bool
    unknown_regions:int=Field(ge=0,le=30)
    calibration_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')


CLASSIFICATIONS=('observed_match','counterfactual_unknown','no_recorded_outcome','not_actionable','incorrect_finding')


def empty_counts():
    return {side:{**{key:0 for key in CLASSIFICATIONS},'declared_resolved':0,'declared_unresolved':0}
        for side in ('baseline','candidate')}


def replay_decision(label,spec):
    import json
    if not isinstance(spec,PolicyDraft):raise ValueError('installed typed policy required')
    context=label['source_context']
    if (not isinstance(context['observations'],(list,tuple)) or not 1<=len(context['observations'])<=2
            or type(label['duration_ms']) is not int or not 1<=label['duration_ms']<=3600000
            or label['method'] not in {'physical_manual_check','reference_comparison','synthetic_fixture'}):raise ValueError('bounded declared review data required')
    observations=tuple(MeasuredDecision.model_validate_json(json.dumps(x,allow_nan=False)) for x in context['observations'])
    if not 1<=len(observations)<=2 or label['outcome'] not in {'resolved','unresolved','incorrect_finding'}:raise ValueError('bounded reviewed tuple required')
    before=observations[0]
    if before.observation_id!=context['tuple']['before_observation_id']:raise ValueError('exact before observation required')
    recorded=None if context.get('action') is None else ActionKind(context['action']['kind'])
    has_after=(len(observations)==2 and context['tuple'].get('after_observation_id')==observations[1].observation_id
        and observations[1].sequence>before.sequence and context['tuple'].get('action_id') is not None
        and context.get('action',{}).get('id')==context['tuple']['action_id'])
    if (recorded is None)!=(not has_after):raise ValueError('acknowledged ordered action/after tuple required')
    applicable=not before.quality_ok or before.unknown_regions>0 or any(x!=Finding.SATISFIED for x in before.findings)
    baseline=choose_action(before.reason_codes) if applicable else None
    candidate=choose_action(before.reason_codes,priority=spec.priority) if applicable else None
    def result(action):
        status=('not_actionable' if not applicable else 'incorrect_finding' if label['outcome']=='incorrect_finding'
            else 'no_recorded_outcome' if not has_after or action==ActionKind.REVIEW
            else 'observed_match' if action==recorded else 'counterfactual_unknown')
        return {'action':None if action is None else action.value,'classification':status,
            'declared_resolved':(label['outcome']=='resolved') if status=='observed_match' else None}
    return {'before_observation_id':before.observation_id,'reason_codes':list(before.reason_codes),
        'before_findings':[x.value for x in before.findings],'applicable':applicable,
        'recorded_action':None if recorded is None else recorded.value,'label_outcome':label['outcome'],
        'declared_review_duration_ms':label['duration_ms'],'review_method':label['method'],
        'baseline':result(baseline),'candidate':result(candidate),'diagnostic_only':True,
        'independent_benchmark_qualified':False,'promotion_eligible':False,'operator_effort_measured':False}
