"""Fault-test original child timeout/cleanup; substituted child is not browser proof."""
from pathlib import Path
import json,os,sys
import pytest
import test_owner_review_browser as baseline
from test_access_lifecycle import world,repository_factory,publication_case
from test_composition import composition_case
from proofpack.evidence.privacy_admission import REGISTRY

def test_native_timeout_retains_partial_stdout_and_reaps_only_owned_child(world,publication_case,composition_case,monkeypatch):
    actual_popen=baseline.subprocess.Popen
    actual_factory=baseline.create_configured_app
    children=[];applications=[]
    def configured(*args,**kwargs):
        app=actual_factory(*args,**kwargs);applications.append(app);return app
    def launch(args,*rest,**kwargs):
        if isinstance(args,(list,tuple)) and len(args)>1 and Path(args[0]).name.lower() in {'node','node.exe'} and args[1]=='-e':
            # Keep original pipes/process-group ownership and consume but never retain stdin.
            command=[sys.executable,'-c',"import sys,time; sys.stdin.read(); print('SYNTHETIC_TIMEOUT_OUTPUT',flush=True); time.sleep(90)"]
            process=actual_popen(command,*rest,**kwargs);children.append(process);return process
        return actual_popen(args,*rest,**kwargs)
    monkeypatch.setattr(baseline,'create_configured_app',configured)
    monkeypatch.setattr(baseline.subprocess,'Popen',launch)
    with pytest.raises(AssertionError,match='owned review browser exceeded original 60-second fixture bound'):
        baseline.test_actual_configured_https_owner_review_uses_published_cv_history(world,publication_case,composition_case)
    assert len(children)==1 and children[0].poll() is not None
    assert len(applications)==1
    app=applications[0]
    assert app.state.composition_status=='closed' and app.state.resource_owner.wait_for_drain(0)
    assert not app.state.owner_metadata_service.repository.snapshot((REGISTRY,))[REGISTRY].data['active']
    output=Path(os.environ['PROOFPACK_PYTEST_EVIDENCE_PATH']).parent
    logs=list(output.glob('review-https-timeout-*.partial.log'))
    assert len(logs)==1 and logs[0].read_bytes().splitlines()==[b'SYNTHETIC_TIMEOUT_OUTPUT']
    (output/'timeout-retention-branch.json').write_text(json.dumps({
        'scope':'actual configured HTTPS/local-store/CV setup; only Node child replaced with an owned Python emitter; no Chrome or provider/physical/human acceptance',
        'original_child_timeout_seconds':60,'original_failure_preserved':True,
        'child_exited':True,'application_closed':True,'resource_drain_verified':True,
        'server_cleanup':'original finally block completed without error',
        'partial_output':logs[0].name,'partial_stdout_exact':True,'stdin_retained':False,
        'parent_complete':False,'beta_decision':'NO_GO'},indent=2)+'\n')
