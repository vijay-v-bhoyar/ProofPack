"""Recorded comparison intent and original-request availability, no source privilege grant."""
from test_evaluations import evaluations,world,repository_factory,manifest_case,publication_case,review_case
from proofpack.auth.policy import Denied
import pytest


def test_comparison_metadata_records_original_candidate_state_without_source_role_inheritance(world,evaluations):
    service,actor,_,request,*_=evaluations
    job=service.create(actor,request=request,idempotency_key='recorded-state')
    assert job['policy_state_version']==request.policy_state_version
    assert job.get('rollback_target') is None and job['can_read_request']
    owner=service.job(world[5],job['id'])
    assert owner['policy_state_version']==request.policy_state_version and not owner['can_read_request']
    with pytest.raises(Denied):service.selections(world[5],job['id'])
