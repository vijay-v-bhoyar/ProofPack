"""Invited-member exact approved reads never disclose private candidates."""
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from test_active_policy import active, qualification, policies, world, repository_factory
from test_policy_delivery import installed_app, ORIGIN
from test_policy_candidates import invite_and_join, draft
from proofpack.auth.http import COOKIE
from proofpack.auth.policy import Role
from proofpack.review.manifests import Consequence
from test_access_lifecycle import proof
from dataclasses import replace
from proofpack.auth.service import RUNTIME
from proofpack.evidence.repository import Write
from proofpack.runtime.control import DATA
from proofpack.planner.activation import PolicyActivations


def client_for(qualification, active, credentials):
    service = qualification[0]
    app = installed_app(service)
    # Use the same genuine reader instance as the activation fixture.
    app.state.policy_activation_service = active[0].activations
    app.state.active_policy_reader = active[0]
    return TestClient(app, base_url=ORIGIN, cookies={COOKIE: credentials.cookie})


def test_invited_operator_reads_exact_approved_policy_without_candidate_disclosure(world, qualification, active):
    _, credentials, *_ = invite_and_join(world, 'approved-reader', roles=(Role.OPERATOR,))
    candidate = qualification[3]
    with client_for(qualification, active, credentials) as client:
        response = client.get('/api/v1/policies/' + candidate['id'])
        assert response.status_code == 200, response.text
        result = response.json()
        assert result['policy']['id'] == candidate['id'] and result['policy']['revision'] == candidate['revision']
        assert result['current'] and result['current_qualification_verified'] and result['scope'] == 'summary'
        assert result['inspection_enablement_granted'] is False
        assert set(result) == {'policy', 'active_version', 'current', 'current_qualification_verified', 'remaining_ms', 'historical_head', 'inspection_enablement_granted', 'scope'}
        assert set(result['policy']) == {'id', 'revision', 'revision_sha256', 'behavior_sha256', 'name', 'mode'}
        assert client.get('/api/v1/policies').status_code == 403
        assert client.get('/api/v1/policies/' + candidate['id'], params={'view': 'candidate'}).status_code == 403


@pytest.mark.parametrize('role', [Role.OWNER, Role.REVIEWER, Role.OPERATOR])
def test_explicit_approved_view_is_member_scope_and_default_candidate_authority_stays_separate(world, qualification, active, role):
    credentials = world[4] if role == Role.OWNER else qualification[0].access.login(proof(world[2], 'policy-reviewer', mfa=False)) if role == Role.REVIEWER else invite_and_join(world, 'approved-explicit', roles=(Role.OPERATOR,))[1]
    candidate = qualification[3]
    with client_for(qualification, active, credentials) as client:
        response = client.get('/api/v1/policies/' + candidate['id'], params={'view': 'approved', 'revision': candidate['revision']})
        assert response.status_code == 200, response.text
        assert response.json()['scope'] == 'summary' and 'spec' not in response.json()
        if role != Role.OPERATOR:
            default = client.get('/api/v1/policies/' + candidate['id'])
            assert default.status_code == 200 and default.json()['status'] == 'draft'


@pytest.mark.parametrize('selection', ['unknown', 'draft', 'wrong_revision'])
def test_nonactive_selections_never_fall_back_to_a_candidate_or_another_policy(world, qualification, active, selection):
    service, reviewer, _, candidate = qualification
    ident = candidate['id']; params = {'view': 'approved'}
    if selection == 'unknown':
        ident = str(uuid4())
    elif selection == 'draft':
        ident = service.policies.write(reviewer, request=draft('Private new draft'), idempotency_key='private-new')['id']
    else:
        params['revision'] = candidate['revision'] + 1
    with client_for(qualification, active, world[4]) as client:
        response = client.get('/api/v1/policies/' + ident, params=params)
        assert response.status_code == 404, response.text
        assert 'Private new draft' not in response.text and 'spec' not in response.json()


def test_approved_read_keeps_held_head_honest_and_denies_revoked_caller(world, qualification, active):
    service, reviewer, _, candidate = qualification
    _, credentials, operator, *_ = invite_and_join(world, 'approved-revoked', roles=(Role.OPERATOR,))
    job = service.job(reviewer, active[3]['id'])
    service.retire(world[5], job['id'], expected_version=job['state_version'], idempotency_key='held-approved', request=Consequence(acknowledged=True, reason='source-retired'))
    with client_for(qualification, active, credentials) as client:
        result = client.get('/api/v1/policies/' + candidate['id'], params={'view': 'approved'})
        assert result.status_code == 200, result.text
        assert result.json()['current'] is False and result.json()['remaining_ms'] == 0
        world[0].change_access(world[5], user_id=operator.member.data['id'], roles=(Role.OPERATOR,), enabled=False, expected_version=1, idempotency_key='revoke-approved')
        assert client.get('/api/v1/policies/' + candidate['id'], params={'view': 'approved'}).status_code == 401


def test_owner_without_recent_mfa_can_read_only_member_approved_scope(world, qualification, active):
    credentials = world[0].login(proof(world[2], mfa=False))
    with client_for(qualification, active, credentials) as client:
        path = '/api/v1/policies/' + qualification[3]['id']
        assert client.get(path, params={'view': 'approved'}).status_code == 200
        assert client.get(path).status_code == 403
        assert client.get('/api/v1/policies/active', params={'scope': 'owner'}).status_code == 403


@pytest.mark.parametrize('change', ['data', 'runtime', 'caller', 'deadline', 'configuration'])
def test_approved_by_id_fences_changes_after_read_audit(world, qualification, active, monkeypatch, change):
    service = qualification[0]; access = service.access; original = access._commit; changed = []
    _, credentials, operator, *_ = invite_and_join(world, 'approved-race', roles=(Role.OPERATOR,))
    def commit(writes, checks=()):
        result = original(writes, checks)
        if not changed and any(w.key.resource.startswith('active-policy-access#') for w in writes):
            changed.append(True)
            if change == 'caller':
                access.change_access(world[5], user_id=operator.member.data['id'], roles=(Role.OPERATOR,), enabled=False, expected_version=1, idempotency_key='race-revoke')
            elif change == 'deadline':
                world[2].value += 60000
            elif change == 'configuration':
                active[0].activations.config = replace(active[0].activations.config, review_window_ms=59999)
            else:
                key = DATA if change == 'data' else RUNTIME
                row = world[1].snapshot((key,))[key]
                data = {**row.data, 'epoch': int(row.data['epoch']) + 1} if change == 'data' else {**row.data, 'instance_id': str(uuid4())}
                world[1].transact((Write(key, row.revision, data),))
        return result
    monkeypatch.setattr(access, '_commit', commit)
    with client_for(qualification, active, credentials) as client:
        result = client.get('/api/v1/policies/' + qualification[3]['id'], params={'view': 'approved'})
        assert result.status_code in {403, 409, 503}, result.text
        assert changed and 'policy' not in result.json()


def test_approved_by_id_uses_existing_stable_actor_read_quota_and_audit(world, qualification, active):
    reader = active[0]; base = reader.activations
    # The changed bound belongs to an explicitly reconstructed shared service;
    # current qualification is held because its original activation config differs.
    limited = PolicyActivations(base.policies, replace(base.config, reads_per_minute=1), base.reader)
    from proofpack.planner.active import ActivePolicies
    reader = ActivePolicies(limited)
    _, credentials, operator, *_ = invite_and_join(world, 'approved-limited', roles=(Role.OPERATOR,))
    result = limited.current(operator, reader, policy_id=qualification[3]['id'])
    assert not result['current']
    from proofpack.planner.activation import ActivationLimited
    with pytest.raises(ActivationLimited):
        limited.current(operator, reader, policy_id=qualification[3]['id'])
    rows, _ = world[1].query(table='events', prefix='active-policy-access#', limit=20)
    assert any(row.data.get('selected_policy_id') == qualification[3]['id'] and row.data['scope'] == 'summary' for row in rows)


def test_bad_selectors_absent_active_and_missing_reader_stay_closed(world, qualification):
    service = qualification[0]; candidate = qualification[3]
    with TestClient(installed_app(service), base_url=ORIGIN, cookies={COOKIE: world[4].cookie}) as client:
        path = '/api/v1/policies/' + candidate['id']
        assert client.get(path, params={'view': 'approved'}).status_code == 404
        for params in ({'view': 'all'}, {'view': 'approved', 'revision': 0}, {'view': 'approved', 'revision': 1001}, {'view': 'approved', 'revision': 'true'}):
            assert client.get(path, params=params).status_code == 400
        assert client.get('/api/v1/policies/not-an-id', params={'view': 'approved'}).status_code == 400
        client.app.state.active_policy_reader = None
        assert client.get(path, params={'view': 'approved'}).status_code == 503
