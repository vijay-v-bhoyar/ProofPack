"""Actual bounded local OpenCV on new analytic synthetic golden images only."""
from pathlib import Path
import json
import pytest
import yaml
from uuid import uuid4
from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.policy import DEFAULT_PRIORITY
from proofpack.review.policy_golden import build_plan,measure_case
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker_limits import WorkerLimits


def test_all_installed_golden_images_are_measured_with_exact_frozen_expected_outcomes():
    controls=yaml.safe_load(Path('docs/controls.yaml').read_text(encoding='utf-8'))
    registry=WorkerRegistry(WorkerLimits.from_controls(controls),max_processes=1)
    plan=build_plan();same=build_plan();assert plan==same and len(plan.inputs)==12
    spec=PolicyDraft(name='Installed default',algorithm='reason_priority_v1',priority=DEFAULT_PRIORITY);results=[]
    try:
        for index in range(12):
            content,guard=measure_case(plan,index,spec,registry,str(uuid4()) if index==0 else runtime,gate=lambda:None,max_case_ms=15000)
            # Registry diagnostic workers share one runtime incarnation.
            runtime=registry._runtime_id;guard();results.append(content)
    finally:registry.close()
    Path('evidence/local/policy-golden-first-results.json').write_text(json.dumps({'manifest':json.loads(plan.manifest_json),'manifest_sha256':plan.sha256,'results':results},indent=2)+'\n',encoding='utf-8')
    assert all(x['passed'] for x in results),[(x['case_id'],x['expected'],x['actual']) for x in results if not x['passed']]
    assert sum(x['new_pixel_measurement'] for x in results)==12 and all(x['physical_truth_verified'] is False for x in results)
