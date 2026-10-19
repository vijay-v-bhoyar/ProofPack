"""Protected release fixtures are test-injected, never actual release approval."""
from copy import deepcopy
from dataclasses import asdict, replace
from types import SimpleNamespace
import hashlib
import json
import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from proofpack.evidence.restore_fence import RestoreFenceConfig, RestoreDataFence, RestoreFenceHeld, PROOFS
from proofpack.evidence.journal_anchors import AnchorCheckpoint
from proofpack.evidence.repository import DynamoRepository, Key, Write, Erase, StoreConflict, StoreUnavailable


def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
ARN = 'arn:aws:dynamodb:us-east-1:000000000000:table/protected-journal'


class Client:
    def __init__(self):
        self.meta = SimpleNamespace(config=SimpleNamespace(retries={'total_max_attempts': 1}, connect_timeout=1, read_timeout=1))
        self.items = {}; self.calls = []; self.before_commit = None; self.after_query = None; self.after_get = None
        self.ids = {'restored-events': 'events-creation-1', 'restored-state': 'state-creation-1'}
        self.lost_reply = False

    def identity(self, table, key): return table, key['pk']['S'], key['sk']['S']

    def describe_table(self, **kw):
        self.calls.append(('describe_table', deepcopy(kw))); name = kw['TableName']
        return {'Table': {'TableName': name, 'TableArn': ARN.rsplit('/', 1)[0]+'/'+name,
            'TableId': self.ids.get(name, 'journal-creation-1'), 'TableStatus': 'ACTIVE',
            'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'}, {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
            'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}]}}

    def describe_time_to_live(self, **kw):
        self.calls.append(('describe_time_to_live', deepcopy(kw)))
        return {'TimeToLiveDescription': {'TimeToLiveStatus': 'DISABLED'}}

    def transact_get_items(self, **kw):
        self.calls.append(('transact_get_items', deepcopy(kw)))
        result = []
        for request in kw['TransactItems']:
            value = request['Get']; item = self.items.get(self.identity(value['TableName'], value['Key']))
            result.append({} if item is None else {'Item': deepcopy(item)})
        if self.after_get: self.after_get(kw, result)
        return {'Responses': result}

    def transact_write_items(self, **kw):
        self.calls.append(('transact_write_items', deepcopy(kw)))
        if self.before_commit: self.before_commit()
        staged = []
        for request in kw['TransactItems']:
            if 'ConditionCheck' in request:
                v = request['ConditionCheck']; old = self.items.get(self.identity(v['TableName'], v['Key']))
                valid = (old is not None and old['body'] == v['ExpressionAttributeValues'][':body']
                         and old['sha256'] == v['ExpressionAttributeValues'][':sha'])
            else:
                v = request['Put']; item = v['Item']; identity = self.identity(v['TableName'], item)
                old = self.items.get(identity)
                valid = (old is None if v['ConditionExpression'].startswith('attribute_not_exists') else
                    old is not None and old['revision'] == v['ExpressionAttributeValues'][':expected'] and 'payload_erasure' not in old)
                staged.append((identity, deepcopy(item)))
            if not valid:
                raise ClientError({'Error': {'Code': 'TransactionCanceledException'},
                    'CancellationReasons': [{'Code': 'ConditionalCheckFailed'}]}, 'TransactWriteItems')
        self.items.update(staged)
        if self.lost_reply: raise ReadTimeoutError(endpoint_url='synthetic-local')
        return {}

    def query(self, **kw):
        self.calls.append(('query', deepcopy(kw)))
        prefix = kw['ExpressionAttributeValues'].get(':prefix', {'S': ''})['S']
        values = [deepcopy(item) for (table, pk, sk), item in sorted(self.items.items())
                  if table == kw['TableName'] and pk == kw['ExpressionAttributeValues'][':deployment']['S'] and sk.startswith(prefix)]
        if self.after_query: self.after_query()
        return {'Items': values[:kw['Limit']], 'Count': min(len(values), kw['Limit']), 'ScannedCount': min(len(values), kw['Limit'])}


def world(tick=lambda: 1, max_check_ms=1000, *, deployment='synthetic', artifact_sha256='b'*64):
    client = Client(); tables = {'state': 'restored-state', 'events': 'restored-events'}
    root = {'schema': 1, 'kind': 'journal_root', 'genesis': '9'*64, 'sequence': 0, 'previous': '0'*64}
    anchor_digest = lambda b: hashlib.sha256(canonical(['sealed-journal-history/v1', deployment, ARN, b]).encode()).hexdigest()
    point = AnchorCheckpoint(0, anchor_digest(root))
    config = RestoreFenceConfig('protected-journal', ARN, '9'*64, point, 'a'*64,
        (('events', client.ids['restored-events']), ('state', client.ids['restored-state'])), artifact_sha256, max_check_ms)
    body = {'schema_version': 1, 'kind': 'restored-data-release', 'deployment': deployment,
        'target_tables': tables, 'target_table_ids': dict(config.target_table_ids), 'journal_arn': ARN,
        'genesis_sha256': config.genesis_sha256, 'checkpoint': asdict(point), 'artifact_sha256': config.artifact_sha256,
        'writer_protocol': 'metadata-payload-erasure/v1', **{k: 'c'*64 for k in PROOFS}}
    digest = hashlib.sha256(canonical(['restored-data-release/v1', deployment, ARN, body]).encode()).hexdigest()
    config = replace(config, release_sha256=digest)
    fence = RestoreDataFence(client, deployment=deployment, state_table=tables['state'], events_table=tables['events'], config=config, tick=tick)
    head = {'schema': 1, 'kind': 'journal_head', 'genesis': '9'*64, 'sequence': 0, 'digest': point.digest}
    raw = [root, head, body]
    identities = []
    for index, request in enumerate(fence._gets()):
        key = request['Get']['Key']; identity = client.identity('protected-journal', key); identities.append(identity)
        client.items[identity] = {**key, 'body': {'S': canonical(raw[index])},
                                 'sha256': {'S': anchor_digest(raw[index]) if index < 2 else digest}}
    plain = DynamoRepository(client, deployment=deployment, state_table=tables['state'], events_table=tables['events'])
    plain.transact((Write(Key('state', 'private#one'), None, {'private': 'NEVER_RETURN_WHEN_HELD'}),))
    repo = DynamoRepository(client, deployment=deployment, state_table=tables['state'], events_table=tables['events'], data_fence=fence)
    client.calls.clear()
    return repo, fence, client, identities


def invoke(repo, operation):
    key = Key('state', 'private#one')
    if operation == 'snapshot': return repo.snapshot((key,))
    if operation == 'erasures': return repo.erasures((key,))
    if operation == 'inventory_snapshot': return repo.inventory_snapshot((key,))
    if operation == 'query': return repo.query(prefix='private#')
    if operation == 'partition_page': return repo.partition_page(table='state')
    return repo.transact((Write(key, 1, {'changed': True}),))


OPERATIONS = ['snapshot', 'erasures', 'inventory_snapshot', 'query', 'partition_page', 'transact']


@pytest.mark.parametrize('operation', OPERATIONS)
def test_exact_protected_release_allows_only_original_repository_operation(operation):
    repo, fence, client, identities = world(); invoke(repo, operation)
    if operation == 'transact':
        transaction = [kw for name, kw in client.calls if name == 'transact_write_items'][-1]
        checks = [v['ConditionCheck'] for v in transaction['TransactItems'] if 'ConditionCheck' in v]
        assert len(checks) == 3 and all(c['TableName'] == 'protected-journal' for c in checks)
    elif operation in {'snapshot', 'erasures', 'inventory_snapshot'}:
        transaction = [kw for name, kw in client.calls if name == 'transact_get_items'][-1]
        assert len(transaction['TransactItems']) == 4
        assert [v['Get']['TableName'] for v in transaction['TransactItems']][-3:] == ['protected-journal']*3


@pytest.mark.parametrize('operation', OPERATIONS)
@pytest.mark.parametrize('part', [0, 1, 2])
def test_missing_any_protected_row_denies_every_data_entrypoint(operation, part):
    repo, fence, client, identities = world(); del client.items[identities[part]]; before = deepcopy(client.items)
    with pytest.raises(StoreUnavailable): invoke(repo, operation)
    assert client.items == before
    for name, kw in client.calls:
        if name == 'transact_get_items': assert all(v['Get']['TableName'] == 'protected-journal' for v in kw['TransactItems'])
        assert name not in {'query', 'transact_write_items'}


@pytest.mark.parametrize('part', [0, 1, 2])
def test_commit_time_protected_change_is_an_atomic_condition_not_a_preflight_only_check(part):
    repo, fence, client, identities = world(); key = Key('state', 'private#one')
    def quarantine(): client.items.pop(identities[part], None)
    client.before_commit = quarantine
    with pytest.raises(StoreConflict): repo.transact((Write(key, 1, {'unsafe': True}),))
    assert client.items[client.identity('restored-state', repo.key(key))]['revision'] == {'N': '1'}


@pytest.mark.parametrize('operation', ['query', 'partition_page'])
def test_query_postcheck_withholds_previously_read_data_on_revocation(operation):
    repo, fence, client, identities = world(); client.after_query = lambda: client.items.pop(identities[2])
    with pytest.raises(StoreUnavailable): invoke(repo, operation)


@pytest.mark.parametrize('fault', ['body', 'hash', 'schema_bool', 'extra', 'wrong_artifact', 'head_bool', 'creation_id'])
def test_hash_and_canonical_body_and_creation_identity_are_all_required(fault):
    repo, fence, client, identities = world()
    item = client.items[identities[1 if fault == 'head_bool' else 2]]
    body = json.loads(item['body']['S'])
    if fault == 'body': body['effects_sha256'] = 'd'*64
    elif fault == 'hash': item['sha256']['S'] = 'd'*64
    elif fault == 'schema_bool': body['schema_version'] = True
    elif fault == 'extra': body['unreviewed'] = True
    elif fault == 'wrong_artifact': body['artifact_sha256'] = 'd'*64
    elif fault == 'head_bool': body['sequence'] = False
    else: client.ids['restored-state'] = 'new-creation'
    item['body']['S'] = canonical(body)
    with pytest.raises(StoreUnavailable): repo.snapshot((Key('state', 'private#one'),))


@pytest.mark.parametrize('fault', ['fence_removed', 'client', 'deployment', 'tables', 'config', 'clock_bool'])
def test_attached_repository_and_original_configuration_cannot_be_swapped(fault):
    repo, fence, client, identities = world()
    if fault == 'fence_removed': repo.data_fence = None
    elif fault == 'client': repo.client = Client()
    elif fault == 'deployment': repo.deployment = 'different'
    elif fault == 'tables': repo.tables['state'] = 'other'
    elif fault == 'config': object.__setattr__(fence.config, 'max_check_ms', True)
    else: fence.tick = lambda: True
    with pytest.raises(StoreUnavailable): repo.snapshot((Key('state', 'private#one'),))


@pytest.mark.parametrize('operation', ['snapshot', 'transact'])
def test_three_protected_rows_leave_exactly97_business_items(operation):
    repo, fence, client, identities = world()
    keys = tuple(Key('state', 'new#'+str(i)) for i in range(98))
    if operation == 'snapshot':
        assert len(repo.snapshot(keys[:97])) == 97
        with pytest.raises(ValueError): repo.snapshot(keys)
    else:
        repo.transact(tuple(Write(k, None, {}) for k in keys[:97]))
        with pytest.raises(ValueError): repo.transact(tuple(Write(k, 1, {}) for k in keys))


def test_lost_commit_reply_keeps_effect_and_does_not_retry():
    repo, fence, client, identities = world(); client.lost_reply = True; key = Key('state', 'private#one')
    with pytest.raises(StoreUnavailable): repo.transact((Write(key, 1, {'committed': True}),))
    assert client.items[client.identity('restored-state', repo.key(key))]['revision'] == {'N': '2'}
    assert sum(name == 'transact_write_items' for name, _ in client.calls) == 1


def test_absolute_fence_deadline_starts_at_first_clock_sample_not_second():
    calls = [0]
    def tick():
        calls[0] += 1
        return 1 if calls[0] == 1 else 1000001
    repo, fence, client, identities = world(tick=tick, max_check_ms=1)
    with pytest.raises(StoreUnavailable): repo.snapshot((Key('state', 'private#one'),))
    assert not client.calls
