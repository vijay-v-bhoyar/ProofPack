import pytest
from test_access_lifecycle import world, repository_factory, publication_case
from test_labels import review_case
from test_manifests import manifest_case, create, finish
from proofpack.review.datasets import Split
from proofpack.review.manifests import job_key, entry_key, manifest_key
from proofpack.evidence.resource_lineage import decode
from proofpack.evidence.repository import Write, StoreUnavailable, StoreConflict
from proofpack.auth.policy import Denied


def events(repo, kind, ident):
    found = []
    cursor = None
    for _ in range(10):
        rows, cursor = repo.partition_page(table='events', limit=100, start_resource=cursor)
        found.extend(row for row in rows if row.data.get('kind') == kind
                     and row.data.get('dataset_id') == ident)
        if cursor is None:
            return found
    raise AssertionError('bounded fixture inventory exhausted')


def test_dataset_example_and_seal_commit_retain_atomic_typed_lineage(world, manifest_case):
    service, actor, *_ = manifest_case
    result = finish(service, actor, create(manifest_case, split=Split.FROZEN_TEST))
    assert result['status'] == 'completed'
    found = events(world[1], 'dataset-example-committed', result['id'])
    assert len(found) == 1
    event = found[0]
    binding = decode(event, deployment=world[1].deployment)
    assert event.revision == 1 and event.data['index'] == 0
    assert binding.operation == 'dataset-example-committed'
    written = {ref.key: ref for ref in binding.writes}
    assert {job_key(result['id']), entry_key(result['id'], 0), manifest_key(result['id'])} <= set(written)
    for key, ref in written.items():
        row = world[1].snapshot((key,))[key]
        assert row.revision == ref.revision
    before = len(found)
    service.advance(actor, result['id'], expected_version=1, idempotency_key='step-1')
    assert len(events(world[1], 'dataset-example-committed', result['id'])) == before


def test_dataset_source_failure_retains_only_its_atomic_job_transition(world, manifest_case):
    service, actor, *_ = manifest_case
    first = finish(service, actor, create(manifest_case, split=Split.FROZEN_TEST))
    assert first['status'] == 'completed'
    result = finish(service, actor, create(manifest_case, split=Split.DEVELOPMENT, key='conflict'))
    assert result['status'] == 'failed' and result['failure_reason'] == 'SPLIT_CONFLICT'
    found = events(world[1], 'dataset-source-failed', result['id'])
    assert len(found) == 1
    event = found[0]
    binding = decode(event, deployment=world[1].deployment)
    assert binding.operation == 'dataset-source-failed' and event.data['index'] == 0
    assert event.data['failure_reason'] == 'SPLIT_CONFLICT'
    assert {ref.key for ref in binding.writes} == {job_key(result['id'])}
    assert world[1].snapshot((entry_key(result['id'], 0),))[entry_key(result['id'], 0)] is None


@pytest.mark.parametrize('transition', ['completion', 'failure'])
@pytest.mark.parametrize('boundary', ['lease', 'effective', 'role', 'binding'])
def test_linked_preparation_cannot_leave_a_late_or_unbound_transition(
        world, manifest_case, monkeypatch, transition, boundary):
    service, actor, *_ = manifest_case
    job = create(manifest_case)
    if transition == 'failure':
        def unavailable(*args, **kwargs):
            raise StoreUnavailable('deliberate source hold')
        monkeypatch.setattr(service, '_example', unavailable)
    target = 'dataset-example-committed' if transition == 'completion' else 'dataset-source-failed'
    prepare = service.access._prepare_linked
    fired = False
    def prepare_then_change(operation, writes, checks=()):
        nonlocal fired
        result = prepare(operation, writes, checks)
        if operation == target:
            fired = True
            row = service._row(job['id'])
            if boundary in ('lease', 'effective'):
                world[2].value = row.data['lease_until_ms' if boundary == 'lease' else 'effective_deadline_ms']
            elif boundary == 'role':
                member = world[1].snapshot((actor.member.key,))[actor.member.key]
                world[1].transact((Write(member.key, member.revision,
                    {**member.data, 'roles': [], 'access_version': member.data['access_version'] + 1}),))
            else:
                raise ValueError('deliberate binding preparation failure')
        return result
    monkeypatch.setattr(service.access, '_prepare_linked', prepare_then_change)
    with pytest.raises((Denied, StoreConflict, StoreUnavailable, ValueError)):
        service.advance(actor, job['id'], expected_version=job['state_version'], idempotency_key='guarded-step')
    row = service._row(job['id'])
    assert fired and row.data['status'] == 'processing'
    assert row.data['steps_reserved'] == 1 and row.data['processed'] == 0
    assert row.data['failure_reason'] is None
    assert not events(world[1], target, job['id'])
    for key in (entry_key(job['id'], 0), manifest_key(job['id'])):
        assert world[1].snapshot((key,))[key] is None
