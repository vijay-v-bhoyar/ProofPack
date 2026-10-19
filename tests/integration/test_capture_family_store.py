"""Actual local CV/database writer records; SDK object protocol is intercepted."""
import pytest
import cv2
from test_access_lifecycle import world, repository_factory, publication_case
from test_original_frames import original_case
from proofpack.evidence.capture_lineage import discover, CaptureDiscoveryHeld
from proofpack.evidence.repository import Key, StoreUnavailable
from proofpack.stations.service import inspection_key, station_key
from proofpack.evidence.erasure import AssetErasure
from proofpack.evidence.erasure_models import ErasurePreview, ErasureConfirmation
from proofpack.vision.fixtures import make_fixture


def inventory(repo):
    result = []
    for table in ('state', 'events'):
        cursor = None
        for _ in range(100):
            rows, cursor = repo.partition_page(table=table, limit=100, start_resource=cursor)
            result.extend(rows)
            if cursor is None:break
        else:raise AssertionError('bounded fixture inventory exhausted')
    return result


def capture_rows(repo, ident):
    # Fixture selector only. Production still needs complete-family classification,
    # an actual barrier and all non-capture copy/resource families.
    rows = inventory(repo)
    observation_ids = {r.data['id'] for r in rows if r.key.resource.startswith('observation#') and r.data.get('inspection_id') == ident}
    selected = []
    for row in rows:
        prefix = row.key.resource.split('#', 1)[0]; data = row.data
        if prefix in {'capture-permit', 'observation', 'capture'} and data.get('inspection_id') == ident:
            selected.append(row)
        elif prefix in {'action', 'asset', 'object-intent'} and data.get('observation_id') in observation_ids:
            selected.append(row)
        elif prefix == 'access' and data.get('kind', '').startswith('action-ack:' + ident + ':'):
            selected.append(row)
    return tuple(selected)


def closed(world, case):
    service, capture, started, operator = case[:4]; repo = world[1]; key = inspection_key(started['inspection_id'])
    root = repo.snapshot((key,))[key]; station = repo.snapshot((station_key(root.data['station_id']),))[station_key(root.data['station_id'])]
    capture.stations.close(operator, inspection_id=started['inspection_id'], expected_version=root.revision,
        expected_epoch=int(station.data['epoch']), reason='capture family fixture close', disposition='cancelled', idempotency_key='family-close')
    return repo.snapshot((key,))[key]


def check(world, root):
    repo = world[1]; rows = capture_rows(repo, root.data['id'])
    result = discover(root, rows, deployment=repo.deployment, max_records=1000, max_payload_bytes=2000000)
    assert {r.key for r in result.records} == {r.key for r in rows}
    assert not any(r.key.resource.startswith(('user#', 'session#', 'station#', 'purpose#')) for r in result.records)
    return result, rows


@pytest.mark.parametrize('retain', [False, True])
def test_closed_actual_crop_and_selected_original_families_are_complete(world, publication_case, original_case, retain):
    if retain:original_case[1]()
    else:publication_case[-1]()
    root = closed(world, publication_case); result, rows = check(world, root)
    assert len(result.media) == (4 if retain else 2)
    assert any(r.key.resource.startswith('capture-permit#') for r in result.records)
    assert result.dependencies  # Actual shared authorization/configuration dependencies remain non-owned.
    with pytest.raises(CaptureDiscoveryHeld):
        discover(root, tuple(r for r in rows if not r.key.resource.startswith('object-intent#')),
            deployment=world[1].deployment, max_records=1000, max_payload_bytes=2000000)


def test_acknowledged_action_remains_owned_after_current_action_pointer_cleared(world, publication_case):
    service, capture, started, operator = publication_case[:4]
    status, admission, payload = publication_case[-1]('post_pass_removal')
    assert status['action'] is not None
    service.acknowledge(operator, inspection_id=started['inspection_id'], action_id=status['action']['id'],
        expected_version=status['state_version'], idempotency_key='family-ack')
    root = closed(world, publication_case); assert root.data['current_action_id'] is None
    result, _ = check(world, root)
    assert any(l.kind == 'acknowledgment' for l in result.links)


def test_failed_storage_keeps_reserved_intent_without_inventing_asset(world, publication_case, monkeypatch):
    def unavailable(**kwargs):raise StoreUnavailable('synthetic pre-upload outage')
    monkeypatch.setattr(publication_case[7], 'put', unavailable)
    with pytest.raises(StoreUnavailable):publication_case[-1]()
    result, _ = check(world, closed(world, publication_case))
    assert len(result.media) == 1 and result.media[0].status == 'reserved'
    assert not any(r.key.resource.startswith('asset#') for r in result.records)


def admit(world, case):
    service, capture, started, operator = case[:4]; key = inspection_key(started['inspection_id'])
    root = world[1].snapshot((key,))[key]
    permit = capture.issue(operator, inspection_id=started['inspection_id'], expected_version=root.revision,
        expected_epoch=int(root.data['station_epoch']), idempotency_key='family-permit')
    frame, _ = make_fixture(0, 'complete', seed=1); ok, encoded = cv2.imencode('.png', frame); assert ok
    admission = capture.admit(operator, inspection_id=started['inspection_id'], expected_version=permit['inspection_state_version'],
        permit_id=permit['permit_id'], nonce=permit['nonce'], sequence=permit['sequence'], payload=encoded.tobytes(), content_type='image/png')
    return admission


def test_closed_pending_observation_requires_terminal_discard_before_family_acceptance(world, publication_case):
    admission = admit(world, publication_case); root = closed(world, publication_case)
    rows = capture_rows(world[1], root.data['id'])
    with pytest.raises(CaptureDiscoveryHeld):discover(root, rows, deployment=world[1].deployment, max_records=1000, max_payload_bytes=2000000)
    publication_case[0].fail(admission['id'], reason='observation_expired')
    result, _ = check(world, root)
    assert root.data['pending_observation_id'] == admission['id']
    assert not result.media


def test_unused_issued_permit_is_retained_after_close(world, publication_case):
    _, capture, started, operator = publication_case[:4]; key = inspection_key(started['inspection_id'])
    root = world[1].snapshot((key,))[key]
    permit = capture.issue(operator, inspection_id=started['inspection_id'], expected_version=root.revision,
        expected_epoch=int(root.data['station_epoch']), idempotency_key='family-unused')
    result, _ = check(world, closed(world, publication_case))
    assert [r.key.resource for r in result.records] == ['capture-permit#' + permit['permit_id']]


@pytest.mark.parametrize('selection', ['crop', 'original', 'both'])
def test_denied_actual_media_still_validates_without_restoring_delivery(world, publication_case, original_case, selection):
    reads, observe, operator, objects, purpose, started, capture = original_case
    ob, _, _ = observe(); root = closed(world, publication_case)
    crop = ob.data['asset_id']; original = ob.data['original_asset_id']
    ids = (crop, original) if selection == 'both' else (crop if selection == 'crop' else original,)
    erasure = AssetErasure(reads.purposes, objects, reads.references, review_ms=30000, jobs_per_minute=8, lease_ms=15000, version_page_size=3)
    preview = erasure.preview(world[5], request=ErasurePreview(asset_ids=ids), idempotency_key='family-erasure-preview')
    erasure.confirm(world[5], request=ErasureConfirmation(preview_id=preview['id'], confirmed_digest=preview['scope_sha256'],
        erase_asset_versions_acknowledged=True, understands_remaining_metadata_and_backups=True),
        expected_version=preview['state_version'], idempotency_key='family-erasure-confirm')
    result, _ = check(world, root); assert len(result.media) == 4
    for ident in ids:
        with pytest.raises(StoreUnavailable):reads.read(operator, ident, binary=True)

def test_repeated_frames_and_historical_acknowledgment_survive_later_observation(world,publication_case):
    service,capture,started,operator=publication_case[:4]
    for _ in range(3):publication_case[-1]()
    status,_,_=publication_case[-1]('post_pass_removal')
    service.acknowledge(operator,inspection_id=started['inspection_id'],action_id=status['action']['id'],expected_version=status['state_version'],idempotency_key='family-repeat-ack')
    publication_case[-1]()
    root=closed(world,publication_case);result,_=check(world,root)
    assert root.data['latest_input_sequence']==5 and len(result.media)==10
    assert sum(link.kind=='acknowledgment' for link in result.links)==1


def test_two_selected_originals_reconcile_attempts_and_ordered_completed_history(world,publication_case,original_case):
    original_case[1]()
    publication_case[5].value+=500000000;world[2].value+=500
    original_case[1]()
    root=closed(world,publication_case);result,_=check(world,root)
    assert root.data['original_attempts_reserved']==2 and len(root.data['original_asset_ids'])==2
    assert len(result.media)==8

def test_partial_original_upload_keeps_crop_uploaded_and_original_reserved_without_assets(world,publication_case,original_case,monkeypatch):
    objects=original_case[3];put=objects.put;calls=0
    def fail_second(**kwargs):
        nonlocal calls
        calls+=1
        if calls==2:raise StoreUnavailable('synthetic original upload outage')
        return put(**kwargs)
    monkeypatch.setattr(objects,'put',fail_second)
    with pytest.raises(StoreUnavailable):original_case[1]()
    root=closed(world,publication_case);result,_=check(world,root)
    assert calls==2 and root.data['original_attempts_reserved']==1
    assert len(result.media)==2 and {m.status for m in result.media}=={'reserved','uploaded'}
    assert not any(r.key.resource.startswith('asset#') for r in result.records)
