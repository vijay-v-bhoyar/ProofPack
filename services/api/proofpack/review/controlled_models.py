"""Bounded offline experiment contracts; no app authorization or activation."""
from dataclasses import dataclass,asdict
import hashlib,json
from pathlib import Path

from proofpack.calibrations.dependencies import canonical,digest
from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.policy import ActionKind,DEFAULT_PRIORITY,REASON_ACTIONS,choose_action
from proofpack.verifier.core import Finding
from proofpack.vision.worker_result import WorkerResult

ARMS=('single_frame_v1','fixed_recapture_v1','rule_priority_v1','candidate_priority_v1')
OUTCOMES=('correct_satisfaction','correct_rejection','incorrect_satisfaction','incorrect_rejection','unresolved','technical_failure','not_run')
FLAGS={'diagnostic_only':True,'physical_truth_verified':False,'independent_benchmark_qualified':False,
       'promotion_eligible':False,'operator_effort_measured':False,'machine_pass':False,'dimension_truth_accuracy_measured':False}


@dataclass(frozen=True)
class ControlledConfig:
    max_episodes:int
    arms:int
    max_response_states_per_episode:int
    max_actions_per_arm:int
    max_observations_per_arm:int
    max_measurements_per_episode:int
    max_measurements_per_run:int
    max_case_ms:int
    max_run_ms:int
    max_case_report_bytes:int
    max_run_report_bytes:int
    max_manifest_bytes:int
    max_candidate_bytes:int
    max_json_depth:int

    def __post_init__(self):
        bounds={'max_episodes':(1,144),'arms':(4,4),'max_response_states_per_episode':(1,13),
            'max_actions_per_arm':(0,2),'max_observations_per_arm':(1,3),'max_measurements_per_episode':(4,12),
            'max_measurements_per_run':(4,1728),'max_case_ms':(1,15000),'max_run_ms':(1,600000),
            'max_case_report_bytes':(512,131072),'max_run_report_bytes':(1024,33554432),
            'max_manifest_bytes':(1,1048576),'max_candidate_bytes':(1,8192),'max_json_depth':(1,32)}
        if any(type(getattr(self,k)) is not int or not lo<=getattr(self,k)<=hi for k,(lo,hi) in bounds.items()):
            raise ValueError('explicit bounded controlled experiment configuration required')
        if self.max_observations_per_arm!=self.max_actions_per_arm+1 or self.max_run_ms<self.max_case_ms:
            raise ValueError('consistent capture/action/time opportunity bounds required')

    @property
    def sha256(self):return digest(asdict(self))


def bounded_read(path:Path,limit:int):
    if path.is_symlink() or not path.is_file():raise ValueError('regular bounded local input required')
    with path.open('rb') as stream:payload=stream.read(limit+1)
    if not 0<len(payload)<=limit:raise ValueError('local input exceeds admitted byte bound')
    return payload


def strict_json(payload,max_depth):
    if type(max_depth) is not int or not 1<=max_depth<=32:raise ValueError('bounded JSON depth required')
    def pairs(values):
        result={}
        for key,value in values:
            if key in result:raise ValueError('duplicate JSON member')
            result[key]=value
        return result
    def constant(value):raise ValueError('finite JSON values required')
    try:
        value=json.loads(payload,object_pairs_hook=pairs,parse_constant=constant);pending=[(value,1)]
        while pending:
            item,depth=pending.pop()
            if isinstance(item,(dict,list)):
                if depth>max_depth:raise ValueError('JSON nesting exceeds admitted depth')
                pending.extend((child,depth+1) for child in (item.values() if isinstance(item,dict) else item))
        return value
    except (RecursionError,UnicodeError,json.JSONDecodeError) as exc:raise ValueError('bounded strict JSON required') from exc


def candidate(path:Path,config:ControlledConfig):
    payload=bounded_read(path,config.max_candidate_bytes)
    value=PolicyDraft.model_validate_json(canonical(strict_json(payload,config.max_json_depth)))
    return value,hashlib.sha256(payload).hexdigest()


def verdict(result:WorkerResult):
    if not isinstance(result,WorkerResult):raise ValueError('typed measured result required')
    if not result.quality_ok or result.unknown_regions or Finding.UNOBSERVABLE in result.findings:return 'unresolved'
    if all(f==Finding.SATISFIED for f in result.findings):return 'satisfied'
    return 'rejected' if Finding.VIOLATED in result.findings else 'unresolved'


def outcome(result,truth_complete):
    if type(truth_complete) is not bool:raise ValueError('explicit synthetic completeness required')
    value=verdict(result)
    if value=='unresolved':return 'unresolved'
    if value=='satisfied':return 'correct_satisfaction' if truth_complete else 'incorrect_satisfaction'
    return 'incorrect_rejection' if truth_complete else 'correct_rejection'


def select_action(arm,result,definition):
    if arm not in ARMS or not isinstance(definition,PolicyDraft):raise ValueError('installed arm and candidate required')
    if arm=='single_frame_v1' or verdict(result)=='satisfied':return None
    if arm=='fixed_recapture_v1':
        eligible={REASON_ACTIONS[reason] for reason in result.reason_codes if reason in REASON_ACTIONS}
        return ActionKind.RECAPTURE if ActionKind.RECAPTURE in eligible else ActionKind.REVIEW
    return choose_action(tuple(result.reason_codes),priority=DEFAULT_PRIORITY if arm=='rule_priority_v1' else definition.priority)


def arm_order(index):
    if type(index) is not int or index<0:raise ValueError('nonnegative episode index required')
    offset=index%len(ARMS);return ARMS[offset:]+ARMS[:offset]
