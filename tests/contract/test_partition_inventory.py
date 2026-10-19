"""Bounded complete-partition reads; source enumeration is not cleanup authority."""
import boto3
import pytest
from botocore.stub import Stubber

from proofpack.evidence.repository import DynamoRepository, Key, Row, ErasureMarker, StoreUnavailable


def repository():
    client = boto3.client('dynamodb', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
    return DynamoRepository(client, deployment='demo', state_table='proofpack-state', events_table='proofpack-events')


def raw(repo, resource, revision='1', data=None):
    return {**repo.key(Key('state', resource)), 'revision': {'N': revision},
            'data': repo.serialize.serialize({} if data is None else data)}


def parameters(table='state', limit=3, start=None):
    result = {'TableName': 'proofpack-' + table, 'ConsistentRead': True, 'Limit': limit,
              'KeyConditionExpression': '#pk = :deployment', 'ExpressionAttributeNames': {'#pk': 'pk'},
              'ExpressionAttributeValues': {':deployment': {'S': 'deployment#demo'}}}
    if start is not None:
        result['ExclusiveStartKey'] = {'pk': {'S': 'deployment#demo'}, 'sk': {'S': start}}
    return result


def test_one_partition_page_keeps_unknown_families_and_validated_erasure_markers():
    repo = repository()
    marker = raw(repo, 'z-erased#one', '2')
    marker['payload_erasure'] = repo.serialize.serialize({'schema_version': 1, 'reference_sha256': 'a'*64,
        'resource_sha256': repo._erasure_identity(Key('state', 'z-erased#one'))})
    items = [raw(repo, 'inspection#one', data={'status': 'closed'}),
             raw(repo, 'new-unrecognized-family#one', data={'retain_for_review': True}), marker]
    with Stubber(repo.client) as stub:
        stub.add_response('query', {'Items': items, 'LastEvaluatedKey': repo.key(Key('state', 'z-erased#one'))}, parameters())
        rows, cursor = repo.partition_page(limit=3)
        assert [r.key.resource for r in rows] == ['inspection#one', 'new-unrecognized-family#one', 'z-erased#one']
        assert isinstance(rows[0], Row) and rows[1].data == {'retain_for_review': True}
        assert isinstance(rows[2], ErasureMarker) and not hasattr(rows[2], 'data')
        assert cursor == 'z-erased#one'
        stub.assert_no_pending_responses()


def test_exact_event_continuation_and_empty_advancing_page_are_preserved():
    repo = repository()
    with Stubber(repo.client) as stub:
        stub.add_response('query', {'Items': [raw(repo, 'capture#b')], 'LastEvaluatedKey': repo.key(Key('events', 'capture#b'))},
                          parameters('events', 1, 'capture#a'))
        rows, cursor = repo.partition_page(table='events', limit=1, start_resource='capture#a')
        assert [row.key for row in rows] == [Key('events', 'capture#b')] and cursor == 'capture#b'
        stub.add_response('query', {'Items': [], 'LastEvaluatedKey': repo.key(Key('events', 'capture#c'))},
                          parameters('events', 1, 'capture#b'))
        assert repo.partition_page(table='events', limit=1, start_resource=cursor) == ([], 'capture#c')
        stub.add_response('query', {'Items': []}, parameters('events', 1, 'capture#c'))
        assert repo.partition_page(table='events', limit=1, start_resource='capture#c') == ([], None)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('field,value', [('limit', 0), ('limit', -1), ('limit', 101), ('limit', True), ('limit', 1.0),
    ('limit', '1'), ('table', 'foreign'), ('table', None), ('table', []),
    ('start_resource', ''), ('start_resource', 'x'*257), ('start_resource', 1), ('start_resource', False)])
def test_invalid_request_is_rejected_before_any_sdk_call(monkeypatch, field, value):
    repo = repository()
    def unexpected(**kwargs):
        pytest.fail('invalid partition request reached SDK')
    monkeypatch.setattr(repo.client, 'query', unexpected)
    with pytest.raises(ValueError):
        repo.partition_page(**{field: value})


@pytest.mark.parametrize('fault', ['foreign_item', 'missing_key', 'compound_key', 'duplicate', 'unordered', 'too_many',
    'bad_data', 'extra_header', 'fractional_revision', 'boolean_revision', 'zero_revision', 'overflow_revision',
    'foreign_cursor', 'same_cursor', 'backwards_cursor', 'short_cursor', 'long_cursor', 'extra_cursor',
    'wrong_items_type', 'nonadvancing_item', 'corrupt_marker'])
def test_malformed_or_nonprogressing_provider_page_holds_inventory(monkeypatch, fault):
    repo = repository(); items = [raw(repo, 'b'), raw(repo, 'c')]
    reply = {'Items': items, 'LastEvaluatedKey': repo.key(Key('state', 'c'))}
    if fault == 'foreign_item': items[0]['pk'] = {'S': 'deployment#foreign'}
    elif fault == 'missing_key': del items[0]['sk']
    elif fault == 'compound_key': items[0]['sk']['N'] = '1'
    elif fault == 'duplicate': items[1] = items[0]
    elif fault == 'unordered': items.reverse()
    elif fault == 'too_many': items.extend([raw(repo, 'd'), raw(repo, 'e')])
    elif fault == 'bad_data': items[0]['data'] = {'L': []}
    elif fault == 'extra_header': items[0]['unexpected'] = {'S': 'unknown protocol'}
    elif fault == 'fractional_revision': items[0]['revision'] = {'N': '1.1'}
    elif fault == 'boolean_revision': items[0]['revision'] = {'BOOL': True}
    elif fault == 'zero_revision': items[0]['revision'] = {'N': '0'}
    elif fault == 'overflow_revision': items[0]['revision'] = {'N': str(2**63)}
    elif fault == 'foreign_cursor': reply['LastEvaluatedKey']['pk'] = {'S': 'deployment#foreign'}
    elif fault == 'same_cursor': reply['LastEvaluatedKey']['sk'] = {'S': 'a'}
    elif fault == 'backwards_cursor': reply['LastEvaluatedKey']['sk'] = {'S': 'b'}
    elif fault == 'short_cursor': reply['LastEvaluatedKey']['sk'] = {'S': ''}
    elif fault == 'long_cursor': reply['LastEvaluatedKey']['sk'] = {'S': 'x'*257}
    elif fault == 'extra_cursor': reply['LastEvaluatedKey']['extra'] = {'S': 'field'}
    elif fault == 'wrong_items_type': reply['Items'] = {}
    elif fault == 'nonadvancing_item': items[0] = raw(repo, 'a')
    else:
        items[0]['payload_erasure'] = repo.serialize.serialize({'schema_version': 1})
    calls = []
    def respond(**kwargs):
        calls.append(kwargs)
        return reply
    monkeypatch.setattr(repo.client, 'query', respond)
    with pytest.raises(StoreUnavailable):
        repo.partition_page(limit=3, start_resource='a')
    assert calls == [parameters(limit=3, start='a')]


def test_provider_failure_has_no_memory_fallback():
    repo = repository()
    with Stubber(repo.client) as stub:
        stub.add_client_error('query', service_error_code='InternalServerError', expected_params=parameters())
        with pytest.raises(StoreUnavailable):
            repo.partition_page(limit=3)
        stub.assert_no_pending_responses()


def test_explicit_empty_provider_continuation_is_a_terminal_page():
    repo = repository()
    with Stubber(repo.client) as stub:
        stub.add_response('query', {'Items': [], 'LastEvaluatedKey': {}}, parameters())
        assert repo.partition_page(limit=3) == ([], None)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('field,value', [('Count', 3), ('Count', True), ('ScannedCount', 1)])
def test_contradictory_reported_page_count_cannot_establish_complete_inventory(monkeypatch, field, value):
    repo = repository()
    response = {'Items': [raw(repo, 'a'), raw(repo, 'b')], field: value}
    monkeypatch.setattr(repo.client, 'query', lambda **kwargs: response)
    with pytest.raises(StoreUnavailable):
        repo.partition_page(limit=3)
