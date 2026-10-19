"""Private signed-grant contracts using real local access; no external forgery claim."""
from copy import deepcopy
import hashlib
from uuid import uuid4
import pytest
from test_access_lifecycle import world,repository_factory,invite_and_join
from proofpack.auth.policy import Denied,Role
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.job_authority import issue,resolve,scope_sha256


@pytest.fixture
def grant(world):
    access,_,clock,*_=world
    _,_,actor,*_=invite_and_join(world,'qualification-reviewer',roles=(Role.REVIEWER,))
    job={'id':str(uuid4()),'kind':'policy_qualification','requested_by':actor.member.data['id'],
        'configuration':'a'*64,'data_epoch':1,'artifact_sha256':'b'*64,'controls_sha256':'c'*64,
        'environment':'synthetic_demo','created_at_ms':clock(),'expires_at_ms':clock()+1000,
        'request_json':'{}','request_sha256':hashlib.sha256(b'{}').hexdigest(),'example_count':13,
        'validation_runtime':{'runtime_epoch':1},'control_version':1,'registry_sha256':'d'*64,
        'software_cases':170,'source_examples':0,'preparation_count':0,'preparation_pages':0,
        'required_case_count':182,'golden_cases':12,'golden_manifest_sha256':'e'*64}
    job['processing_authority']=issue(access,actor,job,Role.REVIEWER)
    return access,actor,job


def resign(access,job):
    body=job['processing_authority']['body']
    job['processing_authority']['signature']=access._token('maintenance-authority',digest(body))


def test_qualification_grant_is_capped_at_original_job_expiry(grant):
    access,actor,job=grant
    assert job['processing_authority']['body']['expires_at_ms']==job['expires_at_ms']
    assert resolve(access,job).session.data['id']==actor.session.data['id']


def test_qualification_grant_cannot_be_issued_for_another_requester(grant):
    access,actor,job=grant;job['requested_by']=str(uuid4())
    with pytest.raises(Denied):issue(access,actor,job,Role.REVIEWER)


@pytest.mark.parametrize('invalid',['requester','expiry'])
def test_even_server_signed_qualification_grant_needs_matching_requester_and_job_deadline(grant,invalid):
    access,_,job=grant
    if invalid=='requester':
        job['requested_by']=str(uuid4())
        job['processing_authority']['body']['scope_sha256']=scope_sha256(job)
    else:job['processing_authority']['body']['expires_at_ms']=job['expires_at_ms']+1
    resign(access,job)
    with pytest.raises(Denied):resolve(access,job)


def test_qualification_deadline_and_progress_cannot_renew_grant(world,grant):
    access,_,job=grant;original=deepcopy(job['processing_authority'])
    job.update(status='completed',processed=13,steps_reserved=13,cases_reserved=182)
    assert resolve(access,job).member.data['id']==job['requested_by']
    world[2].value=job['expires_at_ms']
    with pytest.raises(Denied):resolve(access,job)
    assert job['processing_authority']==original
