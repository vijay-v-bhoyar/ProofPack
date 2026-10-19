"""Actual support writers and typed family relationships, not cleanup admission."""
import pytest
from test_inspection_handoffs import setup_case, request, respond
from test_access_lifecycle import world, repository_factory, invite_and_join
from proofpack.auth.policy import Role
from proofpack.evidence.repository import Erase, StoreUnavailable
from proofpack.evidence.support_lineage import discover, SupportDiscoveryHeld
from proofpack.stations.handoffs import InspectionHandoffs
from proofpack.stations.service import inspection_key


def family(world, case):
    repo = world[1]; key = inspection_key(case[1]['inspection_id'])
    root = repo.snapshot((key,))[key]
    mains, cm = repo.query(prefix='inspection-handoff#', limit=100)
    inboxes, ci = repo.query(prefix='handoff-inbox#', limit=100)
    assert cm is None and ci is None
    return root, tuple(mains+inboxes)


def test_actual_expired_handoff_and_inbox_are_discoverable_without_restoring_delivery(world, recipe):
    case = setup_case(world, recipe); view = request(case)
    root, rows = family(world, case); main = next(r for r in rows if r.key.resource.startswith('inspection-handoff#'))
    expiry = int(main.data['metadata_expires_at_ms'])
    with pytest.raises(StoreUnavailable):
        InspectionHandoffs.retained(main, root.data['id'], view['id'], now=lambda: expiry)
    result = discover(root, rows, now_ms=expiry, max_records=10)
    assert {r.key for r in result.records} == {r.key for r in rows} and len(result.records) == 2
    assert main.data['request']['sender_cookie_resource'] not in repr(result)


def test_actual_accepted_successor_family_binds_every_main_and_recipient_inbox(world, recipe):
    case = setup_case(world, recipe); first = respond(case, request(case))
    other_id, _, other, *_ = invite_and_join(world, 'cleanup-next-reviewer', roles=(Role.REVIEWER,))
    successor = request(case, actor=case[3], target=other_id, key='successor')
    respond(case, successor, actor=other, key='accept-next')
    root, rows = family(world, case)
    result = discover(root, rows, now_ms=world[2](), max_records=10)
    assert len(result.records) == 4 and len(result.links) == 1
    assert result.links[0].kind == 'previous_accepted'
    assert result.links[0].source.resource.endswith(successor['id']) and result.links[0].target.resource.endswith(first['id'])


def test_actual_superseded_pending_family_is_an_exact_same_inspection_chain(world, recipe):
    case = setup_case(world, recipe, lifetime_ms=1000); old = request(case)
    world[2].value += 1000
    current = request(case, key='new-intent')
    root, rows = family(world, case)
    result = discover(root, rows, now_ms=world[2](), max_records=10)
    assert len(result.records) == 4 and len(result.links) == 1
    assert result.links[0].kind == 'superseded_by'
    assert result.links[0].source.resource.endswith(old['id']) and result.links[0].target.resource.endswith(current['id'])


def test_actual_erased_inbox_marker_requires_reconciliation_instead_of_partial_family_success(world, recipe):
    case = setup_case(world, recipe); request(case); root, rows = family(world, case)
    index = next(r for r in rows if r.key.resource.startswith('handoff-inbox#'))
    world[1].transact((Erase(index.key, index.revision, 'a'*64),))
    marker = world[1].erasures((index.key,))[index.key]
    assert marker is not None
    with pytest.raises(SupportDiscoveryHeld):
        discover(root, tuple(marker if r.key == index.key else r for r in rows), now_ms=world[2](), max_records=10)


@pytest.mark.parametrize('status', ['declined', 'cancelled'])
def test_actual_decline_and_cancellation_retain_owned_history_without_false_assignment(world, recipe, status):
    from proofpack.stations.handoffs import HandoffCancel
    case = setup_case(world, recipe); view = request(case)
    if status == 'declined':
        respond(case, view, decision='declined')
    else:
        case[0].cancel(case[2], case[1]['inspection_id'], view['id'], expected_version=view['state_version'],
            request=HandoffCancel(request_sha256=view['request_sha256']), idempotency_key='cancel-history')
    root, rows = family(world, case)
    result = discover(root, rows, now_ms=world[2](), max_records=10)
    assert len(result.records) == 2 and result.links == ()
    assert next(r for r in rows if r.key.resource.startswith('inspection-handoff#')).data['status'] == status
