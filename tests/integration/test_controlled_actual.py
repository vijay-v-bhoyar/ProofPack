"""Actual local CV; synthetic model outcomes, not physical/independent truth."""
from pathlib import Path
import pytest,yaml

from proofpack.review.controlled_models import ControlledConfig,candidate
from proofpack.review.controlled import ControlledExperiment
from proofpack.vision.controlled_fixtures import ControlledBundle
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker_limits import WorkerLimits

ROOT=Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('index',[0,8,16,24,32,40],ids=['complete','missing','wrong_variant','overlap','glare','removal_snapshot'])
def test_actual_cv_four_arm_condition_keeps_source_truth_and_provenance(index):
    controls=yaml.safe_load((ROOT/'docs/controls.yaml').read_text());config=ControlledConfig(**controls['controlled_baselines'])
    bundle=ControlledBundle(ROOT/'fixtures/synthetic/controlled-v1',config)
    definition,sha=candidate(ROOT/'fixtures/synthetic/controlled-candidate.json',config)
    registry=WorkerRegistry(WorkerLimits.from_controls(controls),max_processes=1)
    try:value=ControlledExperiment(bundle,definition,sha,registry,config).case(index)
    finally:registry.close()
    assert value['status']=='COMPLETE' and 4<=value['reserved_measurements']<=12
    assert len({r['tracking_context_sha256'] for r in value['arms'].values()})==4
    assert not value['machine_pass'] and not value['physical_truth_verified'] and not value['promotion_eligible']
    for arm,result in value['arms'].items():
        assert result['outcome']!='incorrect_satisfaction'
        assert result['reserved_measurements']==len(result['observations'])
        assert all(o['calibration_hash']==bundle.profile.content_hash and o['source_sha256']==bundle.metadata['images'][o['image']]['sha256'] for o in result['observations'])
        if index==0:assert result['outcome']=='correct_satisfaction'
    assert registry._diagnostics=={}
