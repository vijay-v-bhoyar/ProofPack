"""Real disposition writers on owned local store; synthetic identity and CV."""
import pytest
from test_access_lifecycle import world, repository_factory
from test_dispositions import decision_case
from test_owner_accounting_review_store import inventory
from proofpack.auth.policy import Denied
from proofpack.evidence.repository import StoreConflict
from proofpack.stations.service import inspection_key


@pytest.mark.parametrize('boundary', ['same-intent', 'changed-body', 'revoked-session'])
def test_winner_committed_after_initial_replay_miss_preserves_exact_result_or_denial(
        world, decision_case, monkeypatch, boundary):
    service, operator, credentials, args = decision_case
    access, repository = world[:2]
    original = access._idempotency
    winner = []
    reached = []
    expected_inventory = []

    def interleave(actor, operation, key, body):
        result = original(actor, operation, key, body)
        if operation == 'inspection-disposition:'+args['inspection_id'] and not reached:
            assert result[2] is None
            reached.append(operation)
            # Commit a genuine winner, then return the delayed caller's real
            # original absence observation. No fabricated replay or result.
            winning_args = {**args, 'reason':'Different original decision'} if boundary=='changed-body' else args
            winner.append(service.record_disposition(operator, **winning_args))
            work = repository.snapshot((inspection_key(args['inspection_id']),))[inspection_key(args['inspection_id'])]
            assert work.revision == 2 and work.data['latest_disposition_id'] == winner[0]['id']
            if boundary == 'revoked-session': access.logout(credentials.cookie, credentials.csrf)
            expected_inventory.extend(inventory(repository))
        return result

    monkeypatch.setattr(access, '_idempotency', interleave)
    try:
        if boundary == 'same-intent':
            delayed = service.record_disposition(operator, **args)
            assert delayed == winner[0]
            assert delayed['decision']['machine_approval'] is False
            assert delayed['decision']['independent_truth_verified'] is False
        else:
            with pytest.raises((Denied, StoreConflict)):
                service.record_disposition(operator, **args)
    finally:
        assert reached == ['inspection-disposition:'+args['inspection_id']]
        assert expected_inventory and inventory(repository) == expected_inventory
    human = [row for row in expected_inventory if row.key.resource.startswith('human-disposition#'+args['inspection_id']+'#')]
    assert len(human) == 1 and human[0].data['id'] == winner[0]['id']
