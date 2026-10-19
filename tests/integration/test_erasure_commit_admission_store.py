"""Actual owned store, real review/confirmation writers, synthetic identity and S3."""
from dataclasses import replace

import pytest

from test_access_lifecycle import world, repository_factory
from test_references import reference_case
from test_erasure import erasure_case, reviewed
from test_owner_accounting_review_store import inventory
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import StoreConflict, StoreUnavailable


@pytest.mark.parametrize('fault', [
    'runtime-handle', 'runtime-service', 'repository', 'storage-frames',
    'storage-references', 'storage-binding', 'review-limit', 'job-limit',
    'lease-limit', 'page-limit', 'clock-reversal', 'expiry',
])
def test_final_asset_confirmation_denies_changed_review_without_business_writes(
        world, erasure_case, monkeypatch, fault):
    service = erasure_case[0]
    preview, request = reviewed(world, erasure_case)
    access, repository, clock = world[:3]
    before = inventory(repository)
    original = access._prepare_linked
    reached = []
    # Separate preview creation from confirmation so reversal inside the review
    # lifetime cannot masquerade as a still-valid final authorization clock.
    clock.value += 10

    def prepare(operation, writes, checks=()):
        result = original(operation, writes, checks)
        if operation == 'erasure-confirm':
            reached.append(operation)
            if fault == 'runtime-handle':
                service.runtime.handle = replace(service.runtime.handle, artifact_sha256='f'*64)
            elif fault == 'runtime-service': service.runtime = object()
            elif fault == 'repository': service.repository = object()
            elif fault == 'storage-frames':
                store = service.objects.frames
                store.config = replace(store.config, bucket='changed-erasure-target')
            elif fault == 'storage-references':
                store = service.objects.references
                store.config = replace(store.config, bucket='changed-erasure-target')
            elif fault == 'storage-binding': service.storage = 'e'*64
            elif fault == 'review-limit': service.review_ms = True
            elif fault == 'job-limit': service.jobs_per_minute = 1
            elif fault == 'lease-limit': service.lease_ms += 1
            elif fault == 'page-limit': service.objects.page_size += 1
            elif fault == 'clock-reversal': clock.value -= 1
            else: clock.value = clock.value - 10 + preview['remaining_ms']
        return result

    monkeypatch.setattr(access, '_prepare_linked', prepare)
    rejected = False
    try:
        service.confirm(world[5], request=request, expected_version=preview['state_version'],
                        idempotency_key='final-reviewed-erasure')
    except (Denied, StoreConflict, StoreUnavailable):
        rejected = True
    finally:
        # Check every original state/event row, including denials, job, quota,
        # preview, DATA, replay and linked provenance; no subset-only assertion.
        assert reached == ['erasure-confirm']
        assert inventory(repository) == before, 'business records escaped final review admission'
    assert rejected, 'changed confirmation intent was accepted'


def test_valid_final_asset_confirmation_and_expired_exact_retry_do_not_renew(
        world, erasure_case, monkeypatch):
    service = erasure_case[0]
    preview, request = reviewed(world, erasure_case)
    access, repository, clock = world[:3]
    expires = clock.value + preview['remaining_ms']
    original = access._prepare_linked
    reached = []

    def prepare(operation, writes, checks=()):
        result = original(operation, writes, checks)
        if operation == 'erasure-confirm':
            reached.append(operation)
            clock.value = expires - 1
        return result

    monkeypatch.setattr(access, '_prepare_linked', prepare)
    result = service.confirm(world[5], request=request, expected_version=preview['state_version'],
                             idempotency_key='valid-final-reviewed-erasure')
    assert reached == ['erasure-confirm']
    assert result['status'] == 'queued' and result['erasure_complete'] is False
    before = inventory(repository)
    clock.value = expires
    retry = service.confirm(world[5], request=request, expected_version=preview['state_version'],
                            idempotency_key='valid-final-reviewed-erasure')
    assert retry == result and inventory(repository) == before
    assert reached == ['erasure-confirm'], 'exact retry attempted new admission'
