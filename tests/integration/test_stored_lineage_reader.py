"""Decode actual stored audit/replay rows; no cleanup or ownership inference."""
from test_access_lifecycle import repository_factory, world, publication_case
from proofpack.evidence.resource_lineage import decode


def test_actual_stored_capture_and_shared_outputs_decode_without_live_state_substitution(world, publication_case):
    service, capture, started, operator, credentials, clock, registry, objects, purpose, observe = publication_case
    observe()
    operations = set()
    for table, prefix in [('events', 'access#'), ('events', 'runtime#'), ('events', 'capture#'), ('state', 'idempotency#')]:
        rows, cursor = world[1].query(prefix=prefix, table=table, limit=100)
        assert rows and cursor is None
        for row in rows:
            result = decode(row, deployment=world[1].deployment)
            operations.add(result.operation)
            assert result.writes or result.checks
            assert all(ref.key != row.key for ref in (*result.writes, *result.checks))
    assert {'bootstrap', 'runtime_started', 'observation_admitted', 'observation_completed'} <= operations
