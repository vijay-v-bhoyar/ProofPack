"""Owned local storage with synthetic identity; no provider or policy acceptance."""
from dataclasses import replace

import pytest
from test_access_lifecycle import world, repository_factory
from test_purpose_history_store import prepare
from test_owner_accounting_review_store import inventory
from proofpack.auth.policy import Denied
from proofpack.evidence.purposes import PurposeRequest
from proofpack.evidence.repository import StoreConflict


@pytest.mark.parametrize('fault', ['expiry', 'past-expiry', 'notice-version', 'notice-text', 'runtime', 'lifetime'])
def test_actual_store_final_purpose_denial_leaves_no_new_business_records(world, monkeypatch, fault):
    service, actor, _ = prepare(world, 'created', False)
    access = service.access
    clock = world[2]
    notice = access.operational_notice(actor)
    request = PurposeRequest(notice_version=notice['version'], notice_sha256=notice['sha256'],
                             source_permission_reference='synthetic-final-commit', operational_use_acknowledged=True,
                             expires_at_ms=clock()+1000)
    before = inventory(world[1])
    original = access._prepare_linked
    reached = []

    def linked(operation, writes, checks=()):
        result = original(operation, writes, checks)
        if operation == 'purpose-create':
            reached.append(operation)
            if fault == 'expiry': clock.value = request.expires_at_ms
            elif fault == 'past-expiry': clock.value = request.expires_at_ms + 1
            elif fault == 'notice-version': access.config = replace(access.config, notice_version='changed-synthetic-v2')
            elif fault == 'notice-text': access.config = replace(access.config, notice_text='Changed synthetic notice')
            elif fault == 'runtime': service.runtime.handle = replace(service.runtime.handle, artifact_sha256='f'*64)
            else: service.max_lifetime_ms = 1
        return result

    monkeypatch.setattr(access, '_prepare_linked', linked)
    with pytest.raises((Denied, StoreConflict)):
        service.create(actor, request=request, idempotency_key='denied-final-purpose')
    assert reached == ['purpose-create']
    assert inventory(world[1]) == before
