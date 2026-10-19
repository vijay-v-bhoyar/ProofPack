"""Real resource-limited child workers, synthetic images; not a camera/ARM proof."""
import hashlib
from uuid import uuid4

import cv2
import numpy as np
import pytest

from proofpack.vision.fixtures import demo_recipe,make_fixture,synthetic_profile
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker import WorkerBusy,WorkerUnavailable
from proofpack.vision.worker_limits import WorkerLimits
from proofpack.vision.worker_result import WorkerResult


def limits():return WorkerLimits(512,30,750,5000,2097152,65536,262144,4096,30,12,0)


def test_registry_warms_reuses_two_slots_and_enforces_fenced_replacement():
    runtime=str(uuid4());first,second,third=(str(uuid4()) for _ in range(3))
    registry=WorkerRegistry(limits(),max_processes=2)
    try:
        ident=registry.prepare(station_id=first,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
        assert registry.prepare(station_id=first,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)==ident
        registry.guard(first,1,runtime)
        registry.prepare(station_id=second,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
        with pytest.raises(WorkerBusy):registry.prepare(station_id=third,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
        with pytest.raises(WorkerUnavailable):registry.prepare(station_id=first,epoch=1,runtime_id=runtime,calibration_sha256='b'*64)
        registry.retire(second)
        with pytest.raises(WorkerUnavailable):registry.prepare(station_id=second,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
        registry.prepare(station_id=third,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
        with registry.analyze(station_id=first,epoch=1,runtime_id=runtime,calibration_sha256='a'*64):
            with pytest.raises(WorkerBusy):registry.retire(first)
            with pytest.raises(WorkerBusy):
                with registry.analyze(station_id=first,epoch=1,runtime_id=runtime,calibration_sha256='a'*64):pass
        with pytest.raises(WorkerUnavailable):registry.guard(first,2,runtime)
        with pytest.raises(WorkerUnavailable):registry.guard(first,1,str(uuid4()))
    finally:registry.close()
    assert registry._bindings=={}


def test_failed_worker_cannot_restart_same_fence_and_shutdown_reaps_inflight_context():
    runtime=str(uuid4());station=str(uuid4());registry=WorkerRegistry(limits(),max_processes=1)
    try:
        first=registry.prepare(station_id=station,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
        with registry.analyze(station_id=station,epoch=1,runtime_id=runtime,calibration_sha256='a'*64) as binding:binding.worker.close()
        with pytest.raises(WorkerUnavailable):registry.guard(station,1,runtime)
        with pytest.raises(WorkerUnavailable):registry.prepare(station_id=station,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
        second=registry.prepare(station_id=station,epoch=2,runtime_id=runtime,calibration_sha256='a'*64)
        assert first!=second
        with registry.analyze(station_id=station,epoch=2,runtime_id=runtime,calibration_sha256='a'*64) as binding:
            registry.close();assert not binding.worker.available
        assert registry._bindings=={}
    finally:registry.close()


def test_real_worker_returns_bounded_rectified_evidence_with_distinct_provenance():
    runtime=str(uuid4());station=str(uuid4());profile=synthetic_profile();recipe=demo_recipe()
    frame,_=make_fixture(0,'complete',seed=1);ok,encoded=cv2.imencode('.png',frame);assert ok
    payload=encoded.tobytes()
    with WorkerRegistry(limits(),max_processes=1) as registry:
        registry.prepare(station_id=station,epoch=1,runtime_id=runtime,calibration_sha256=profile.content_hash)
        with registry.analyze(station_id=station,epoch=1,runtime_id=runtime,calibration_sha256=profile.content_hash) as binding:
            result=binding.worker.analyze(payload,recipe,profile,sequence=1,inspection_id=str(uuid4()))
        image=result.evidence_bytes();assert image and len(image)<=163840
        assert hashlib.sha256(image).hexdigest()==result.evidence_sha256
        assert result.source_sha256==hashlib.sha256(payload).hexdigest() and result.source_sha256!=result.evidence_sha256
        crop=cv2.imdecode(np.frombuffer(image,np.uint8),cv2.IMREAD_COLOR)
        assert crop.shape[:2]==(profile.output_height,profile.output_width)
        assert crop.shape[:2]!=frame.shape[:2]
        assert result.evidence_jpeg_base64 not in repr(result)


def test_invalidation_closes_owned_inflight_worker_and_cannot_kill_newer_binding():
    runtime=str(uuid4());station=str(uuid4())
    with WorkerRegistry(limits(),max_processes=1) as registry:
        registry.prepare(station_id=station,epoch=1,runtime_id=runtime,calibration_sha256='a'*64)
        with registry.analyze(station_id=station,epoch=1,runtime_id=runtime,calibration_sha256='a'*64) as binding:
            registry.invalidate(station,1,runtime);assert not binding.worker.available
        assert registry._bindings=={}
        registry.prepare(station_id=station,epoch=2,runtime_id=runtime,calibration_sha256='a'*64)
        registry.invalidate(station,1,runtime)
        registry.guard(station,2,runtime)


@pytest.mark.parametrize('changes',[{'evidence_jpeg_base64':'not base64','evidence_sha256':'a'*64},
    {'evidence_jpeg_base64':None,'evidence_sha256':'a'*64},
    {'evidence_jpeg_base64':'/9j/2Q==','evidence_sha256':'a'*64}])
def test_derived_evidence_cannot_omit_pair_or_forge_hash(changes):
    raw={'candidates':[],'findings':['SATISFIED'],'reason_codes':[],'quality_ok':True,'unknown_regions':0,
        'scene_generation':1,'scene_changed':False,'source_sha256':'a'*64,'calibration_hash':'b'*64,**changes}
    import json
    with pytest.raises(ValueError):WorkerResult.model_validate_json(json.dumps(raw))
