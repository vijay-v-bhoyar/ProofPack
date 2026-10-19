"""Real auth/runtime/erasure writers, modeled asset/repository and no SDK calls."""
from copy import deepcopy
from dataclasses import asdict, replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from botocore.config import Config

from test_purpose_commit_admission import setup as purpose_setup, no_sdk
from proofpack.auth.policy import Denied
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.erasure import AssetErasure, job_key
from proofpack.evidence.erasure_models import ErasurePreview, ErasureConfirmation
from proofpack.evidence.objects import EvidenceObjects, ReferenceObjects, ObjectConfig, ObjectReceipt
from proofpack.evidence.repository import Key, Write, StoreConflict, StoreUnavailable


def setup():
    purposes, actor, repo, clock, _ = purpose_setup()
    config = ObjectConfig(repo.deployment, 'synthetic-erasure-model', '000000000000', 'us-east-1',
        'arn:aws:kms:us-east-1:000000000000:key/00000000-0000-4000-8000-000000000001')
    client = SimpleNamespace(meta=SimpleNamespace(region_name='us-east-1',
        endpoint_url='https://s3.us-east-1.amazonaws.com',
        config=Config(connect_timeout=2, read_timeout=3, retries={'total_max_attempts':1})))
    frames, references = EvidenceObjects(client, config), ReferenceObjects(client, config)
    ident = str(uuid4())
    receipt = ObjectReceipt(ident, references.key(ident), 'synthetic-version', 'a'*64, 'b'*64, 10, 'image/png')
    # This is explicitly a synthetic committed-asset model, not upload proof.
    repo.transact((Write(Key('state','asset#'+ident), None, {
        'id':ident, 'kind':'reference', 'status':'committed', 'sha256':receipt.source_sha256,
        'byte_length':receipt.byte_length, 'content_type':receipt.content_type,
        'object_receipt':asdict(receipt), 'storage_binding_sha256':digest(asdict(config)),
        'read_denied':False, 'deletion_job_id':None}),))
    service = AssetErasure(purposes, frames, references, review_ms=1000,
        jobs_per_minute=8, lease_ms=15000, version_page_size=3)
    preview = service.preview(actor, request=ErasurePreview(asset_ids=(ident,)), idempotency_key='review')
    request = ErasureConfirmation(preview_id=preview['id'], confirmed_digest=preview['scope_sha256'],
        erase_asset_versions_acknowledged=True, understands_remaining_metadata_and_backups=True)
    return service, actor, repo, clock, preview, request


@pytest.mark.parametrize('fault', [
    'runtime', 'access', 'purposes', 'repository', 'objects', 'frames', 'references',
    'client', 'clock-source', 'frames-config', 'references-config', 'objects-config',
    'storage-binding', 'review-limit', 'job-limit', 'lease-limit', 'page-limit',
    'clock-reversal', 'expiry',
])
def test_changed_final_asset_intent_has_no_modeled_business_writes(monkeypatch, fault):
    service, actor, repo, clock, preview, request = setup()
    access = service.access
    original = access._prepare_linked
    before = deepcopy(repo.rows)
    clock.value += 10
    reached = []

    def prepare(operation, writes, checks=()):
        result = original(operation, writes, checks)
        if operation == 'erasure-confirm':
            reached.append(operation)
            if fault == 'runtime': service.runtime.handle = replace(service.runtime.handle, artifact_sha256='f'*64)
            elif fault == 'access': service.access = object()
            elif fault == 'purposes': service.purposes = object()
            elif fault == 'repository': service.repository = object()
            elif fault == 'objects': service.objects = object()
            elif fault == 'frames': service.objects.frames = object()
            elif fault == 'references': service.objects.references = object()
            elif fault == 'client': service.objects.frames.client = object()
            elif fault == 'clock-source': access.clock_ms = lambda: clock.value
            elif fault == 'frames-config': service.objects.frames.config = replace(service.objects.frames.config, bucket='changed-target')
            elif fault == 'references-config': service.objects.references.config = replace(service.objects.references.config, bucket='changed-target')
            elif fault == 'objects-config': service.objects.config = None
            elif fault == 'storage-binding': service.storage = 'e'*64
            elif fault == 'review-limit': service.review_ms = True
            elif fault == 'job-limit': service.jobs_per_minute = 1
            elif fault == 'lease-limit': service.lease_ms += 1
            elif fault == 'page-limit': service.objects.page_size += 1
            elif fault == 'clock-reversal': clock.value -= 1
            else: clock.value = 2000
        return result

    monkeypatch.setattr(access, '_prepare_linked', prepare)
    with pytest.raises((Denied, StoreConflict, StoreUnavailable)):
        service.confirm(actor, request=request, expected_version=preview['state_version'], idempotency_key='confirm')
    assert reached == ['erasure-confirm'] and repo.rows == before


@pytest.mark.parametrize('lost_reply', [False, True])
def test_valid_confirmation_preserves_job_and_exact_retry_after_review_expiry(monkeypatch, lost_reply):
    service, actor, repo, clock, preview, request = setup()
    original = service.access._prepare_linked
    reached = []

    def prepare(operation, writes, checks=()):
        result = original(operation, writes, checks)
        if operation == 'erasure-confirm':
            reached.append(operation)
            clock.value = 1999
        return result

    monkeypatch.setattr(service.access, '_prepare_linked', prepare)
    repo.lose_reply = lost_reply
    if lost_reply:
        with pytest.raises(StoreUnavailable):
            service.confirm(actor, request=request, expected_version=preview['state_version'], idempotency_key='confirm')
    else:
        result = service.confirm(actor, request=request, expected_version=preview['state_version'], idempotency_key='confirm')
        assert result['status'] == 'queued' and result['erasure_complete'] is False
    before = deepcopy(repo.rows)
    jobs = [row for key,row in repo.rows.items() if key.resource.startswith('maintenance-job#')]
    assert len(jobs) == 1
    job = jobs[0]
    assert job.data['scope_sha256'] == preview['scope_sha256']
    original_expiry = job.data['processing_authority']['body']['expires_at_ms']
    clock.value = 2000
    retry = service.confirm(actor, request=request, expected_version=preview['state_version'], idempotency_key='confirm')
    assert retry['id'] == job.data['id'] and retry['status'] == 'queued'
    assert repo.rows == before and reached == ['erasure-confirm']
    assert repo.rows[job_key(retry['id'])].data['processing_authority']['body']['expires_at_ms'] == original_expiry
    with pytest.raises(StoreConflict):
        service.confirm(actor, request=request.model_copy(update={'confirmed_digest':'c'*64}),
            expected_version=preview['state_version'], idempotency_key='confirm')
    assert repo.rows == before
