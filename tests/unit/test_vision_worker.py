import json
from pathlib import Path
import subprocess
import sys
from dataclasses import asdict

import cv2
from pydantic import ValidationError
import pytest

from proofpack.vision.fixtures import demo_recipe,make_fixture,synthetic_profile
from proofpack.vision.worker import VisionPool,VisionWorker,WorkerBusy,WorkerUnavailable
from proofpack.vision.worker_limits import WorkerLimits
from proofpack.vision.worker_result import WorkerResult
from proofpack.verifier.core import Finding


def limits(**changes):
    values=dict(memory_mb=512,cpu_seconds=30,wall_ms=750,startup_ms=5000,max_input_bytes=2097152,
        max_metadata_bytes=65536,max_reply_bytes=262144,max_contours=4096,max_candidates=30,
        pixel_delta=12,max_changed_pixels=0)
    return WorkerLimits(**{**values,**changes})


def encoded(condition='complete'):
    frame,_=make_fixture(0,condition,seed=1)
    ok,data=cv2.imencode('.png',frame);assert ok
    return data.tobytes()


@pytest.mark.integration
def test_real_resource_limited_worker_measures_tracks_and_abstains():
    with VisionWorker(limits()) as worker:
        assert worker.resource_receipt['memory_mb']==512
        assert worker.process_id is not None
        profile=synthetic_profile();recipe=demo_recipe()
        first=worker.analyze(encoded(),recipe,profile,sequence=1,inspection_id='kit')
        assert first.findings==(Finding.SATISFIED,)*4
        assert first.scene_changed
        with pytest.raises(ValueError,match='bindings'):
            worker.analyze(encoded(),recipe,profile.model_copy(update={'profile_id':'other'}),sequence=2,inspection_id='kit')
        second=worker.analyze(encoded(),recipe,profile,sequence=2,inspection_id='kit')
        assert second.scene_generation==first.scene_generation and not second.scene_changed
        missing=worker.analyze(encoded('post_pass_removal'),recipe,profile,sequence=3,inspection_id='kit')
        assert missing.scene_changed and missing.findings[0]==Finding.VIOLATED
        malformed=worker.analyze(b'invalid',recipe,profile,sequence=4,inspection_id='kit')
        assert not malformed.quality_ok and malformed.findings==(Finding.UNOBSERVABLE,)*4
        again=worker.analyze(encoded(),recipe,profile,sequence=5,inspection_id='kit')
        assert again.scene_generation>missing.scene_generation and again.scene_changed


@pytest.mark.integration
def test_worker_rejects_overlap_inflight_and_closed_process():
    worker=VisionWorker(limits())
    worker._busy.acquire()
    with pytest.raises(WorkerBusy):worker.analyze(encoded(),demo_recipe(),synthetic_profile(),sequence=1,inspection_id='kit')
    worker._busy.release();worker.close()
    with pytest.raises(WorkerUnavailable):worker.analyze(encoded(),demo_recipe(),synthetic_profile(),sequence=1,inspection_id='kit')


@pytest.mark.parametrize('field,value',[('memory_mb',0),('wall_ms',0),('startup_ms',0),('max_reply_bytes',2**30),('pixel_delta',True)])
def test_missing_or_unbounded_limits_denied(field,value):
    with pytest.raises(ValueError):limits(**{field:value})


def test_child_cannot_return_pass_authority_or_unbounded_data():
    with pytest.raises(ValidationError):
        WorkerResult.model_validate_json(json.dumps({'passed':True,'authority':{'enabled':True}}))


@pytest.mark.integration
def test_wall_deadline_terminates_worker_and_requires_explicit_new_incarnation():
    worker=VisionWorker(limits(wall_ms=1))
    with pytest.raises(WorkerUnavailable):
        worker.analyze(encoded(),demo_recipe(),synthetic_profile(),sequence=1,inspection_id='kit')
    assert not worker._process.is_alive()
    with pytest.raises(WorkerUnavailable):
        worker.analyze(encoded(),demo_recipe(),synthetic_profile(),sequence=2,inspection_id='kit')


def test_pool_releases_capacity_once_on_close_and_failed_start(monkeypatch):
    import proofpack.vision.worker as module
    closed=[]
    class FakeWorker:
        def __init__(self,limits):pass
        def close(self):closed.append(True)
    monkeypatch.setattr(module,'VisionWorker',FakeWorker)
    pool=VisionPool(limits(),max_processes=2)
    with pool.lease(),pool.lease():
        with pytest.raises(WorkerBusy):
            with pool.lease():raise AssertionError('third lease admitted')
    assert len(closed)==2
    def fail(limits):raise WorkerUnavailable('startup failed')
    monkeypatch.setattr(module,'VisionWorker',fail)
    with pytest.raises(WorkerUnavailable):
        with pool.lease():raise AssertionError('failed startup yielded a worker')
    monkeypatch.setattr(module,'VisionWorker',FakeWorker)
    with pool.lease(),pool.lease():pass
    assert len(closed)==4


def test_controls_are_required_complete_and_admitted():
    section={**asdict(limits()),'max_processes':2}
    assert WorkerLimits.from_controls({'vision_worker':section})==limits()
    for bad in ({},{**section,'max_processes':3},{key:value for key,value in section.items() if key!='memory_mb'}):
        with pytest.raises(ValueError):WorkerLimits.from_controls({'vision_worker':bad})


@pytest.mark.integration
def test_os_memory_bound_is_enforced_in_an_owned_subprocess():
    # No injected diagnostic operation exists in the production worker protocol.
    source=Path(__file__).resolve().parents[2]/'services/api'
    code=f"""import sys,json
sys.path.insert(0,{str(source)!r})
from proofpack.vision.worker_limits import WorkerLimits,apply_resource_limits
limits=WorkerLimits(128,30,750,5000,2097152,65536,262144,4096,30,12,0)
receipt=apply_resource_limits(limits)
try:
    blob=bytearray(512*1024*1024)
except MemoryError:
    print(json.dumps({{'allocation_denied':True,'limits':receipt}}),flush=True)
else:
    raise SystemExit('memory limit did not reject allocation')
"""
    result=subprocess.run([sys.executable,'-c',code],capture_output=True,timeout=15)
    assert result.returncode==0,result.stderr.decode(errors='replace')
    assert json.loads(result.stdout)['allocation_denied'] is True
