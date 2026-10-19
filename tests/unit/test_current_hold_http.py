"""Actual ASGI owner/control boundaries on modeled data, no provider/native database."""
from copy import deepcopy
from dataclasses import replace

import pytest

from test_owner_metadata_http import client_world, body, BASE
from test_owner_metadata import no_sdk
from proofpack.auth.http import COOKIE
from proofpack.evidence.owner_metadata import request_key
from proofpack.evidence.privacy_http import _control_route
from proofpack.evidence.privacy_admission import REGISTRY


def test_actual_app_recovers_current_request_without_retained_id_while_ordinary_data_is_held():
    service, _, repo, _, owner, client, headers = client_world()
    with client:
        first = client.post(BASE, json=body(client), headers=headers); assert first.status_code == 201
        assert client.get('/api/v1/users').status_code == 503
        before = deepcopy(repo.rows); response = client.get(BASE + '/current')
        assert response.status_code == 200, response.text
        result = response.json(); assert result['status'] == 'held' and result['request']['id'] == first.json()['id']
        assert result['request']['current_hold'] and result['unknown_writes_reconciled'] is False
        assert result['request_fulfilled'] is False and result['inspection_resumption_authorized'] is False
        # Candidate CR-T01: existing HTTP control registration must remain active.
        assert {k: v for k, v in repo.rows.items() if k != REGISTRY} == {k: v for k, v in before.items() if k != REGISTRY}
        assert repo.rows[REGISTRY].revision == before[REGISTRY].revision + 2
        assert repo.rows[REGISTRY].data == before[REGISTRY].data and repo.rows[REGISTRY].data['active'] == {}
    assert owner.wait_for_drain(0)


def test_open_current_literal_route_is_not_parsed_as_a_request_uuid():
    _, _, repo, _, owner, client, _ = client_world()
    with client:
        before = deepcopy(repo.rows); response = client.get(BASE + '/current')
        assert response.status_code == 200, response.text
        assert response.json()['status'] == 'open' and response.json()['request'] is None
        # Candidate CR-T01: registration/release, not unregistered transport.
        assert {k: v for k, v in repo.rows.items() if k != REGISTRY} == {k: v for k, v in before.items() if k != REGISTRY}
        assert repo.rows[REGISTRY].revision == before[REGISTRY].revision + 2
        assert repo.rows[REGISTRY].data == before[REGISTRY].data and repo.rows[REGISTRY].data['active'] == {}
    assert owner.wait_for_drain(0)


@pytest.mark.parametrize('fault,expected', [('signed-out', 401), ('operator', 403), ('mfa', 403)])
def test_current_route_does_not_grant_new_authority(fault, expected):
    _, actor, repo, clock, _, client, _ = client_world()
    if fault == 'signed-out': client.cookies.clear()
    elif fault == 'operator': repo.rows[actor.member.key] = replace(repo.rows[actor.member.key], data={**actor.member.data, 'roles': ['operator']})
    else: clock.value += 600001
    with client:
        response = client.get(BASE + '/current')
        assert response.status_code == expected, response.text
        assert 'scope_sha256' not in response.text and 'DO_NOT_DISCLOSE' not in response.text


def test_unconfigured_current_route_is_unavailable():
    _, _, _, _, _, client, _ = client_world(enabled=False)
    with client: assert client.get(BASE + '/current').status_code == 503


@pytest.mark.parametrize('suffix,method', [('/current?inspection_ids=anything', 'GET'), ('/cur%72ent', 'GET'), ('/current/more', 'GET'), ('/current', 'POST')])
def test_selector_encoded_similar_and_write_routes_get_no_held_mode_exemption(suffix, method):
    _, _, repo, _, _, client, headers = client_world()
    with client:
        first = client.post(BASE, json=body(client), headers=headers); assert first.status_code == 201
        before = deepcopy(repo.rows); response = client.request(method, BASE + suffix, headers=headers)
        assert response.status_code == 503, response.text
        assert first.json()['id'] not in response.text and repo.rows == before


def test_query_selector_is_rejected_even_when_gate_is_open():
    _, _, _, _, _, client, _ = client_world()
    with client: assert client.get(BASE + '/current?scope=all').status_code == 422


@pytest.mark.parametrize('method,path,raw,query,expected', [
    ('GET', BASE + '/current', (BASE + '/current').encode(), b'', True),
    ('POST', BASE + '/current', (BASE + '/current').encode(), b'', False),
    ('GET', BASE + '/current/', (BASE + '/current/').encode(), b'', False),
    ('GET', BASE + '/current', (BASE + '/cur%72ent').encode(), b'', False),
    ('GET', BASE + '/current', (BASE + '/current').encode(), b'scope=all', False),
])
def test_current_control_recognition_is_exact(method, path, raw, query, expected):
    assert _control_route(dict(method=method, path=path, raw_path=raw, query_string=query)) is expected
