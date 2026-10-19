"""Real auth/purpose writers on modeled storage; no legal or hosted proof."""
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from botocore.client import BaseClient
from test_auth_head_integrity import world
from proofpack.auth.policy import Denied
from proofpack.evidence.purposes import DataPurposes, PurposeRequest
from proofpack.evidence.repository import Row, StoreConflict, StoreUnavailable
from proofpack.runtime.control import RuntimeControl


@pytest.fixture(autouse=True)
def no_sdk(monkeypatch):
    monkeypatch.setattr(BaseClient, '_make_api_call', lambda *a, **k: pytest.fail('purpose model invoked SDK'))


def setup():
    access, repo, _, credentials, _ = world()
    clock = SimpleNamespace(value=1000)
    access.clock_ms = lambda: clock.value
    access.config = replace(access.config, notice_version='synthetic-v1', notice_text='Synthetic purpose notice')
    actor = access.resolve(credentials.cookie)
    runtime = RuntimeControl(access, instance_id=str(uuid4()), artifact_sha256='a'*64,
                             controls_sha256='b'*64, environment='test')
    runtime.start()
    service = DataPurposes(access, runtime, max_lifetime_ms=10000)
    notice = access.operational_notice(actor)
    request = PurposeRequest(notice_version=notice['version'], notice_sha256=notice['sha256'],
                             source_permission_reference='synthetic-source', operational_use_acknowledged=True,
                             expires_at_ms=1100)
    return service, actor, repo, clock, request


@pytest.mark.parametrize('fault', ['expiry', 'past-expiry', 'clock-reversal', 'notice-version',
                                  'notice-text', 'runtime', 'lifetime', 'revoked-owner'])
def test_final_purpose_admission_denies_changed_intent_without_business_writes(monkeypatch, fault):
    service, actor, repo, clock, request = setup()
    access = service.access
    original = access._prepare_linked
    expected = {}

    def prepare(operation, writes, checks=()):
        result = original(operation, writes, checks)
        if operation == 'purpose-create':
            if fault == 'expiry': clock.value = request.expires_at_ms
            elif fault == 'past-expiry': clock.value = request.expires_at_ms + 1
            elif fault == 'clock-reversal': clock.value -= 1
            elif fault == 'notice-version': access.config = replace(access.config, notice_version='synthetic-v2')
            elif fault == 'notice-text': access.config = replace(access.config, notice_text='Changed synthetic notice')
            elif fault == 'runtime': service.runtime.handle = replace(service.runtime.handle, artifact_sha256='f'*64)
            elif fault == 'lifetime': service.max_lifetime_ms = 1
            else:
                member = repo.rows[actor.member.key]
                repo.rows[member.key] = Row(member.key, member.revision + 1, {**member.data, 'enabled': False})
            expected['rows'] = deepcopy(repo.rows)
        return result

    monkeypatch.setattr(access, '_prepare_linked', prepare)
    denied = False
    try:
        service.create(actor, request=request, idempotency_key='exact-purpose')
    except (Denied, ValueError, StoreConflict, StoreUnavailable):
        denied = True
    assert 'rows' in expected, 'probe did not reach the original linked-write boundary'
    assert repo.rows == expected['rows'], 'purpose/data/replay/event writes escaped final admission'
    assert denied, 'changed purpose intent was not rejected'


def test_still_valid_purpose_commits_original_expiry_and_exact_retry_does_not_renew(monkeypatch):
    service, actor, repo, clock, request = setup()
    original = service.access._prepare_linked

    def prepare(operation, writes, checks=()):
        result = original(operation, writes, checks)
        if operation == 'purpose-create': clock.value = request.expires_at_ms - 1
        return result

    monkeypatch.setattr(service.access, '_prepare_linked', prepare)
    result = service.create(actor, request=request, idempotency_key='exact-purpose')
    assert result['expires_at_ms'] == 1100 and result['rights_independently_verified'] is False
    assert result['optional_improvement'] is result['optional_publicity'] is False
    before = deepcopy(repo.rows)
    clock.value = request.expires_at_ms
    assert service.create(actor, request=request, idempotency_key='exact-purpose') == result
    assert repo.rows == before
    with pytest.raises(StoreUnavailable): service.permitted(result['id'])
    with pytest.raises(StoreConflict):
        service.create(actor, request=request.model_copy(update={'expires_at_ms':1200}), idempotency_key='exact-purpose')
    assert repo.rows == before


def test_lost_commit_reply_reconciles_original_purpose_after_expiry_without_new_writes():
    service, actor, repo, clock, request = setup()
    repo.lose_reply = True
    with pytest.raises(StoreUnavailable):
        service.create(actor, request=request, idempotency_key='lost-reply')
    before = deepcopy(repo.rows)
    assert sum(key.resource.startswith('purpose#') for key in repo.rows) == 1
    clock.value = request.expires_at_ms
    result = service.create(actor, request=request, idempotency_key='lost-reply')
    assert result['expires_at_ms'] == request.expires_at_ms and repo.rows == before
    with pytest.raises(StoreUnavailable): service.permitted(result['id'])
