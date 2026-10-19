"""Negative SDK-budget and dependency guards for the private first-install entrypoint."""
from dataclasses import replace
import json
import shutil

import pytest

from test_host import host_files
from test_fresh_enrollment import world,run,approve_candidate,OP,INSTANCE,ROLE
from proofpack.runtime import host
from proofpack.runtime.composition import ApplicationClients
from proofpack.runtime.enrollment import EnrollmentIntent,_Operation,_plan,run_enrollment


def test_original_32_call_allowance_stops_the_next_sdk_attempt(host_files):
    w=world(host_files);plan=_plan(w.loaded,w.intent)
    op=_Operation(w.loaded,w.intent,ApplicationClients(w.client,w.s3,w.sts),plan,lambda:1001,lambda:1)
    for _ in range(32):op.call('get_caller_identity')
    with pytest.raises(ValueError,match='SDK allowance'):op.call('get_caller_identity')
    assert len(w.identity)==32 and w.client.items=={}


def test_restored_configuration_cannot_enter_fresh_enrollment_or_credential_discovery(host_files):
    loaded=host.load_configuration(*host_files[:2]);entered=[]
    def forbidden(**kwargs):entered.append(True);raise AssertionError('wrong release kind must stop first')
    with pytest.raises(host.HostConfigurationError):
        run_enrollment(loaded,EnrollmentIntent(OP,INSTANCE,ROLE,1000,301000),commit=False,session_factory=forbidden)
    assert entered==[]


def test_changed_approved_wheel_is_rejected_before_discovery_and_any_store_call(host_files,tmp_path):
    w=world(host_files);source=w.loaded.config.installation.wheel_path;wheel=tmp_path/'approved.whl'
    shutil.copy2(source,wheel);w.document['installation']['wheel_path']=str(wheel)
    w.path.write_text(json.dumps(w.document));w.loaded=host.load_configuration(w.path,w.secret)
    approve_candidate(w,run(w));w.discovery.clear();w.identity.clear();w.client.calls.clear()
    with wheel.open('ab') as stream:stream.write(b'changed after approval')
    with pytest.raises(host.HostConfigurationError):run(w,commit=True)
    assert w.discovery==w.identity==w.client.calls==[] and w.client.items=={}


def test_configuration_change_during_credential_discovery_cannot_become_a_new_baseline(host_files):
    w=world(host_files);approve_candidate(w,run(w));w.closed.clear();w.identity.clear();w.client.calls.clear()
    def changed(**kwargs):
        object.__setattr__(w.loaded.config,'controls_sha256','0'*64)
        return w.Session(**kwargs)
    with pytest.raises(host.HostConfigurationError):
        run_enrollment(w.loaded,w.intent,commit=True,session_factory=changed,clock_ms=lambda:1001)
    assert w.identity==w.client.calls==[] and w.client.items=={}
    assert sorted(w.closed)==['dynamodb','s3','sts']
