"""Actual deployment partition traversal, including unknown rows and markers."""
import pytest
from test_access_lifecycle import repository_factory
from proofpack.evidence.repository import Key, Write, Erase, Row, ErasureMarker, StoreUnavailable


def test_real_partition_pages_preserve_all_rows_markers_and_table_deployment_isolation(repository_factory):
    repo = repository_factory(); foreign = repository_factory()
    keys = [Key('state', name) for name in ['asset#a', 'new-unknown-family#b', 'z-erased#c']]
    repo.transact(tuple(Write(key, None, {'private': 'synthetic value'}) for key in keys))
    repo.transact((Erase(keys[-1], 1, 'a'*64), Write(Key('events', 'capture#one'), None, {'kind': 'synthetic'})))
    foreign.transact((Write(keys[0], None, {'foreign': True}), Write(Key('events', 'capture#foreign'), None, {})))
    found = []; cursor = None; visited = set()
    for _ in range(10):
        page, following = repo.partition_page(limit=1, start_resource=cursor)
        found.extend(page)
        if following is None:
            break
        assert following not in visited
        visited.add(following); cursor = following
    else:
        pytest.fail('bounded traversal failed to terminate')
    assert [row.key for row in found] == keys
    assert all(isinstance(row, Row) for row in found[:-1])
    assert found[1].key.resource.startswith('new-unknown-family#')
    assert isinstance(found[-1], ErasureMarker) and not hasattr(found[-1], 'data')
    assert all('foreign' not in str(row) for row in found)
    events, following = repo.partition_page(table='events', limit=100)
    assert [row.key for row in events] == [Key('events', 'capture#one')] and following is None
    # Ordinary application reads still withhold the scrubbed record.
    assert repo.snapshot((keys[-1],))[keys[-1]] is None


@pytest.mark.parametrize('fault', ['fractional_revision', 'unknown_header'])
def test_real_malformed_record_prevents_a_partial_inventory_result(repository_factory, fault):
    repo = repository_factory(); key = Key('state', 'z-invalid')
    repo.transact((Write(Key('state', 'a-valid'), None, {}),))
    item = {**repo.key(key), 'revision': {'N': '1'}, 'data': {'M': {}}}
    if fault == 'fractional_revision':
        item['revision'] = {'N': '1.5'}
    else:
        item['unknown_header'] = {'S': 'unrecognized protocol'}
    repo.client.put_item(TableName=repo.tables['state'], Item=item)
    with pytest.raises(StoreUnavailable):
        repo.partition_page(limit=100)


def test_real_transplanted_marker_holds_inventory_without_returning_prior_live_rows(repository_factory):
    repo = repository_factory(); key = Key('state', 'z-erased')
    repo.transact((Write(Key('state', 'a-live'), None, {}), Write(key, None, {'private': 'removed'})))
    repo.transact((Erase(key, 1, 'a'*64),))
    marker = repo.client.get_item(TableName=repo.tables['state'], Key=repo.key(key), ConsistentRead=True)['Item']
    marker['payload_erasure']['M']['resource_sha256'] = {'S': 'b'*64}
    repo.client.put_item(TableName=repo.tables['state'], Item=marker)
    with pytest.raises(StoreUnavailable):
        repo.partition_page(limit=100)
