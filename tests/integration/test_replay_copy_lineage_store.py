"""Actual local writer outputs; synthetic identities, no complete-erasure authority."""
from copy import deepcopy
import pytest

from test_access_lifecycle import world, repository_factory, capture_world, capture_permit
from test_capture_family_store import inventory
from proofpack.auth.policy import Role
from proofpack.evidence.repository import Row
from proofpack.evidence.replay_lineage import discover, ReplayHistoryHeld


def outputs(repo, operation):
    # Fixture selector only: production complete inventory/classification is unfinished.
    values = inventory(repo)
    roots = [r for r in values if r.key.resource.startswith('idempotency#')
             and r.data.get('resource_bindings', {}).get('operation') == operation]
    assert len(roots) == 1
    root = roots[0]
    peers = tuple(r for r in values if r.key.table == 'events'
                  and r.data.get('resource_bindings') == root.data['resource_bindings'])
    return root, peers


def parse(repo, root, peers):
    return discover(root, peers, deployment=repo.deployment, max_records=100,
                    max_payload_bytes=1000000)


def invitation(world):
    service, repo, clock, uid, credentials, owner = world
    result = service.create_invitation(owner, target_subject='replay-candidate',
        target_email='replay-candidate@example.invalid', roles=(Role.OPERATOR,),
        ttl_seconds=60, idempotency_key='replay-copy-invite')
    return result, outputs(repo, 'invite')


def test_actual_ordinary_writer_private_reply_is_historical_reference_only(world):
    result, (root, peers) = invitation(world)
    parsed = parse(world[1], root, peers)
    assert parsed.replay.key == root.key and len(parsed.events) == 1
    assert result['capability'] not in repr(parsed) and 'replay-candidate' not in repr(parsed)


def test_original_retry_reuses_exact_output_without_duplicate_family(world):
    result, (root, peers) = invitation(world)
    service, repo, clock, uid, credentials, owner = world
    replayed = service.create_invitation(owner, target_subject='replay-candidate',
        target_email='replay-candidate@example.invalid', roles=(Role.OPERATOR,),
        ttl_seconds=60, idempotency_key='replay-copy-invite')
    assert replayed == result and outputs(repo, 'invite') == (root, peers)
    assert parse(repo, root, peers).replay.key == root.key


def test_logout_does_not_erase_history_or_recreate_authority(world):
    _, (root, peers) = invitation(world)
    service, repo, clock, uid, credentials, owner = world
    service.logout(credentials.cookie, credentials.csrf)
    assert parse(repo, root, peers).replay.key == root.key
    assert outputs(repo, 'invite') == (root, peers)


def test_actual_direct_capture_writer_uses_capture_peer_without_access_substitute(world, recipe):
    capture, started, operator, credentials, clock = capture_world(world, recipe)
    permit = capture_permit(capture, started, operator)
    admission = capture.admit(operator, inspection_id=started['inspection_id'],
        expected_version=permit['inspection_state_version'], permit_id=permit['permit_id'],
        nonce=permit['nonce'], sequence=permit['sequence'], payload=b'synthetic unprocessed frame',
        idempotency_key='replay-copy-upload', content_type='image/png')
    root, peers = outputs(world[1], 'observation_admitted')
    assert root.data['result']['observation_id'] == admission['id']
    assert len(peers) == 1 and peers[0].key.resource.startswith('capture#')
    assert parse(world[1], root, peers).replay.key == root.key


@pytest.mark.parametrize('corruption', ['missing_peer', 'different_business_digest'])
def test_actual_writer_family_rejects_incomplete_or_altered_supplied_evidence(world, corruption):
    _, (root, peers) = invitation(world)
    if corruption == 'missing_peer':
        peers = ()
    else:
        data = deepcopy(peers[0].data)
        data['resource_bindings']['writes'][0]['sha256'] = 'f' * 64
        peers = (Row(peers[0].key, peers[0].revision, data),)
    with pytest.raises(ReplayHistoryHeld): parse(world[1], root, peers)
