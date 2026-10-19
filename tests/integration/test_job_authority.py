"""Real local access state; no provider, background driver or privacy completion proof."""
from copy import deepcopy
from dataclasses import replace
from uuid import uuid4

import pytest

from test_access_lifecycle import world, repository_factory, invite_and_join, proof
from proofpack.auth.policy import Denied, Role
from proofpack.auth.service import user_key
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.job_authority import issue, resolve
from proofpack.evidence.repository import Write


@pytest.fixture
def job_case(world):
    access, _, clock, _, _, _ = world
    _, credentials, actor, *_ = invite_and_join(world)
    job = {'id': str(uuid4()), 'kind': 'inspection_export', 'requested_by': actor.member.data['id'],
        'inspection_id': str(uuid4()), 'inspection_revision': 1, 'inspection_sha256': 'a' * 64,
        'configuration': 'b' * 64, 'artifact_sha256': 'c' * 64, 'controls_sha256': 'd' * 64,
        'environment': 'synthetic', 'data_epoch': 1, 'created_at_ms': clock(),
        'expires_at_ms': clock() + 60000, 'selected': [], 'status': 'queued'}
    job['processing_authority'] = issue(access, actor, job, Role.OPERATOR)
    return access, actor, credentials, job


def test_current_grant_resolves_and_mutable_progress_does_not_change_scope(job_case):
    access, actor, credentials, job = job_case
    result = resolve(access, job)
    assert result.session.data['id'] == actor.session.data['id']
    assert result.cookie.key.resource != credentials.cookie
    job.update(status='processing', stage=2, scanned=4, lease_token='private-attempt')
    assert resolve(access, job).principal == result.principal


@pytest.mark.parametrize('field', ['schema_version', 'job_id', 'kind', 'scope_sha256', 'cookie_ref',
    'user_id', 'session_id', 'access_version', 'session_epoch', 'role', 'issued_at_ms', 'expires_at_ms'])
def test_any_signed_field_tampering_is_denied(job_case, field):
    access, _, _, job = job_case
    job['processing_authority']['body'][field] = 'tampered'
    with pytest.raises(Denied): resolve(access, job)


@pytest.mark.parametrize('field', ['id', 'requested_by', 'inspection_id', 'inspection_revision',
    'inspection_sha256', 'configuration', 'artifact_sha256', 'controls_sha256', 'environment',
    'data_epoch', 'created_at_ms', 'expires_at_ms', 'selected'])
def test_immutable_scope_changes_invalidate_reference(job_case, field):
    access, _, _, job = job_case
    if field in ('id', 'requested_by', 'inspection_id'):
        job[field] = str(uuid4())
    elif isinstance(job[field], int):
        job[field] += 1
    elif isinstance(job[field], list):
        job[field].append({'id': str(uuid4())})
    else:
        job[field] += '-changed'
    with pytest.raises(Denied): resolve(access, job)


@pytest.mark.parametrize('record', [None, {}, {'body': {}}, {'body': {}, 'signature': None}, []])
def test_legacy_and_malformed_references_are_held(job_case, record):
    access, _, _, job = job_case
    job['processing_authority'] = record
    with pytest.raises(Denied): resolve(access, job)


def test_original_expiry_and_clock_rollback_are_not_renewed(world, job_case):
    access, actor, _, job = job_case
    original = deepcopy(job['processing_authority'])
    world[2].value = int(original['body']['expires_at_ms'])
    with pytest.raises(Denied): resolve(access, job)
    world[2].value = int(original['body']['issued_at_ms']) - 1
    with pytest.raises(Denied): resolve(access, job)
    assert job['processing_authority'] == original


def test_logout_holds_reference_and_new_login_needs_explicit_rebind(world, job_case):
    access, actor, credentials, job = job_case
    access.logout(credentials.cookie, credentials.csrf)
    with pytest.raises(Denied): resolve(access, job)
    newer = access.login(proof(world[2], 'operator', mfa=False))
    with pytest.raises(Denied): resolve(access, job)
    job['processing_authority'] = issue(access, access.resolve(newer.cookie), job, Role.OPERATOR)
    assert resolve(access, job).session.data['id'] == newer.session_id
    assert job['expires_at_ms'] == job['processing_authority']['body']['expires_at_ms']


@pytest.mark.parametrize('enabled,roles', [(False, (Role.OPERATOR,)), (True, (Role.REVIEWER,))])
def test_current_membership_change_holds_old_reference(world, job_case, enabled, roles):
    access, actor, _, job = job_case
    access.change_access(world[5], user_id=actor.member.data['id'], roles=roles, enabled=enabled,
        expected_version=int(actor.member.data['access_version']), idempotency_key='change-maintenance-grant')
    with pytest.raises(Denied): resolve(access, job)


def test_current_session_epoch_is_required(world, job_case):
    access, actor, _, job = job_case
    row = world[1].snapshot((user_key(actor.member.data['id']),))[user_key(actor.member.data['id'])]
    world[1].transact((Write(row.key, row.revision, {**row.data, 'session_epoch': int(row.data['session_epoch']) + 1}),))
    with pytest.raises(Denied): resolve(access, job)


def test_key_rotation_holds_reference(job_case):
    access, _, _, job = job_case
    access.config = replace(access.config, capability_key=b'rotated-synthetic-key' * 3)
    with pytest.raises(Denied): resolve(access, job)


def test_reference_cannot_outlive_short_original_session(world, job_case):
    access, _, _, job = job_case
    short = replace(proof(world[2], 'operator', mfa=False), expires_at_ms=world[2]() + 1000)
    actor = access.resolve(access.login(short).cookie)
    job['processing_authority'] = issue(access, actor, job, Role.OPERATOR)
    assert job['processing_authority']['body']['expires_at_ms'] == world[2]() + 1000
    world[2].value += 1000
    with pytest.raises(Denied): resolve(access, job)


@pytest.mark.parametrize('field,value', [('schema_version', True), ('cookie_ref', 'user#invalid'),
    ('expires_at_ms', 999999999), ('role', 'owner')])
def test_signed_but_semantically_invalid_reference_is_denied(job_case, field, value):
    access, _, _, job = job_case
    record = job['processing_authority'];record['body'][field] = value
    record['signature'] = access._token('maintenance-authority', digest(record['body']))
    with pytest.raises(Denied): resolve(access, job)


def test_owner_mfa_bound_and_explicit_successor_rebind(world):
    access, _, clock, _, _, owner = world
    scope = {'schema_version': 1, 'assets': [str(uuid4())]}
    job = {'id': str(uuid4()), 'kind': 'asset_erasure', 'scope': scope, 'scope_sha256': digest(scope),
        'created_at_ms': clock(), 'created_by': owner.member.data['id']}
    job['processing_authority'] = issue(access, owner, job, Role.OWNER)
    expires = job['processing_authority']['body']['expires_at_ms']
    clock.value = expires - 1
    assert resolve(access, job).member.data['id'] == job['created_by']
    clock.value = expires
    with pytest.raises(Denied): resolve(access, job)
    with pytest.raises(Denied): issue(access, owner, job, Role.OWNER)
    # An explicitly granted, MFA-qualified owner may continue the committed scope.
    fresh = access.resolve(access.login(proof(clock)).cookie)
    _, _, successor, *_ = invite_and_join((*world[:5], fresh), 'successor', roles=(Role.OWNER,), mfa=True)
    job['processing_authority'] = issue(access, successor, job, Role.OWNER)
    assert resolve(access, job).member.data['id'] == successor.member.data['id'] != job['created_by']
    job['scope']['assets'].append(str(uuid4()))
    with pytest.raises(Denied): resolve(access, job)


def test_wrong_job_kind_role_or_requestor_cannot_issue(job_case, world):
    access, actor, _, job = job_case
    with pytest.raises(Denied): issue(access, world[5], job, Role.OWNER)
    with pytest.raises(Denied): issue(access, world[5], job, Role.OPERATOR)
    job['kind'] = 'future_evaluation'
    with pytest.raises(Denied): issue(access, actor, job, Role.OPERATOR)


def test_reviewer_reference_resolves_with_current_reviewer_grant(world, job_case):
    access, _, _, job = job_case
    _, _, reviewer, *_ = invite_and_join(world, 'reviewer', roles=(Role.REVIEWER,))
    job['requested_by'] = reviewer.member.data['id']
    job['processing_authority'] = issue(access, reviewer, job, Role.REVIEWER)
    assert resolve(access, job).principal.roles == frozenset({Role.REVIEWER})
