"""Real CV/child process -> pure verifier. Durable/authenticated integration is separate."""
import cv2

from proofpack.verifier.core import Finding,Inspection,Observation,State,admit_sequence,verify
from proofpack.vision.fixtures import demo_recipe,make_fixture,synthetic_profile
from proofpack.vision.worker import VisionWorker
from proofpack.vision.worker_limits import WorkerLimits


def test_measured_complete_then_removed_part_withdraws_current_result(authority):
    recipe=demo_recipe();profile=synthetic_profile()
    limits=WorkerLimits(512,30,750,5000,2097152,65536,262144,4096,30,12,0)
    inspection=Inspection('kit',authority)
    with VisionWorker(limits) as worker:
        for sequence,(condition,tick) in enumerate((('complete',10.),('complete',10.5),('complete',11.),('post_pass_removal',11.2)),1):
            frame,_=make_fixture(0,condition,seed=1)
            ok,encoded=cv2.imencode('.png',frame);assert ok
            result=worker.analyze(encoded.tobytes(),recipe,profile,sequence=sequence,inspection_id='kit')
            inspection=admit_sequence(inspection,sequence)
            observation=Observation(f'o{sequence}',sequence,result.scene_generation,tick,tick-.01,
                tuple(result.findings),len(recipe.constraints),result.quality_ok,result.unknown_regions,
                True,authority)
            # True marks an explicit test evidence fixture, not a real S3 commit.
            inspection=verify(inspection,observation,authority,tick+.02)
            if sequence==3:assert inspection.state==State.PASSED_CURRENT
            if sequence==4:
                assert result.findings[0]==Finding.VIOLATED
                assert inspection.state!=State.PASSED_CURRENT
                assert inspection.deadline_tick==0
