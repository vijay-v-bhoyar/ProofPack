from collections import Counter
from dataclasses import replace
from pathlib import Path
import json
import pytest
import yaml

from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.policy import ActionKind
from proofpack.review.controlled_models import ControlledConfig,ARMS,arm_order,candidate,outcome,select_action,strict_json
from proofpack.vision.worker_result import WorkerResult


def configuration():
    return ControlledConfig(**yaml.safe_load((Path(__file__).resolve().parents[2]/'docs/controls.yaml').read_text())['controlled_baselines'])


def measured(*,unknown=0,quality=True,findings=('VIOLATED',),reasons=('overlap','missing')):
    return WorkerResult.model_validate_json(json.dumps({'candidates':[],'findings':findings,'reason_codes':reasons,
        'quality_ok':quality,'unknown_regions':unknown,'scene_generation':1,'scene_changed':False,'source_sha256':'a'*64,'calibration_hash':'b'*64}))


def proposal():return PolicyDraft.model_validate_json(json.dumps({'name':'configured','algorithm':'reason_priority_v1','priority':['RECAPTURE','PLACE_FLAT','SEPARATE_REGION']}))


def test_all_arms_share_reason_eligibility_and_static_cannot_spend_actions():
    value=measured();definition=proposal()
    assert select_action(ARMS[0],value,definition) is None
    assert select_action(ARMS[1],value,definition)==ActionKind.RECAPTURE
    assert select_action(ARMS[2],value,definition)==ActionKind.SEPARATE_REGION
    assert select_action(ARMS[3],value,definition)==ActionKind.RECAPTURE
    overlap=measured(reasons=('overlap',))
    assert select_action(ARMS[1],overlap,definition)==ActionKind.REVIEW
    assert select_action(ARMS[3],overlap,definition)==ActionKind.SEPARATE_REGION
    for arm in ARMS:assert select_action(arm,measured(findings=('SATISFIED',)),definition) is None


@pytest.mark.parametrize('change',[{'unknown':1},{'quality':False},{'findings':('UNOBSERVABLE',)}])
def test_unknown_complete_kit_is_never_an_incorrect_rejection(change):
    assert outcome(measured(**change),True)=='unresolved'


def test_visible_finding_correctness_is_separate_from_kit_truth():
    assert outcome(measured(),True)=='incorrect_rejection'
    assert outcome(measured(),False)=='correct_rejection'
    assert outcome(measured(findings=('SATISFIED',)),True)=='correct_satisfaction'
    assert outcome(measured(findings=('SATISFIED',)),False)=='incorrect_satisfaction'


def test_balanced_order_gives_every_arm_every_position():
    for position in range(4):assert Counter(arm_order(i)[position] for i in range(144))==Counter({a:36 for a in ARMS})
    for value in (-1,True,1.5):
        with pytest.raises(ValueError):arm_order(value)


@pytest.mark.parametrize('change',[{'max_case_ms':True},{'max_run_ms':600001},{'max_actions_per_arm':3},
    {'max_manifest_bytes':1048577},{'max_candidate_bytes':8193},{'max_observations_per_arm':2}])
def test_bounds_and_opportunity_relationships_cannot_be_coerced_or_widened(change):
    with pytest.raises(ValueError):replace(configuration(),**change)


@pytest.mark.parametrize('payload',['{"a":1,"a":2}','{"a":NaN}','{"a":Infinity}','['*1500+'0'+']'*1500],ids=['duplicate','nan','infinity','deep'])
def test_ambiguous_or_nonfinite_json_is_rejected(payload):
    with pytest.raises(ValueError):strict_json(payload,configuration().max_json_depth)


def test_candidate_is_exact_typed_file_with_no_arbitrary_algorithm(tmp_path):
    path=tmp_path/'candidate.json';path.write_text(proposal().model_dump_json())
    value,sha=candidate(path,configuration());assert value==proposal() and len(sha)==64
    path.write_text(path.read_text().replace('reason_priority_v1','arbitrary-code'))
    with pytest.raises(ValueError):candidate(path,configuration())
