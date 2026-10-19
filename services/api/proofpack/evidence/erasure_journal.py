"""Private append-only journal storage; receipts never authorize payload removal."""
from dataclasses import dataclass, field
import hashlib
import json
import math
import re

from botocore.exceptions import BotoCoreError, ClientError
from proofpack.evidence.repository import DynamoRepository

MAXIMUM = 2**63 - 1
HASH = re.compile(r'[a-f0-9]{64}')
TABLE = re.compile(r'[A-Za-z0-9_.-]{3,255}')
ARN = re.compile(r'arn:(?:aws|aws-us-gov|aws-cn):dynamodb:[a-z0-9-]+:[0-9]{12}:table/([A-Za-z0-9_.-]{3,255})')


class JournalHeld(RuntimeError):
    pass


class JournalConflict(ValueError):
    pass


@dataclass(frozen=True)
class JournalLimits:
    max_record_bytes: int
    max_sdk_calls: int

    def __post_init__(self):
        if (type(self.max_record_bytes) is not int or not 1 <= self.max_record_bytes <= 131072
                or type(self.max_sdk_calls) is not int or not 1 <= self.max_sdk_calls <= 32):
            raise ValueError('explicit finite journal record and SDK-call bounds required')


@dataclass(frozen=True)
class JournalIntent:
    reference_sha256: str = field(repr=False)
    resource_sha256: str = field(repr=False)
    source_revision: int
    source_payload_sha256: str = field(repr=False)
    classification_sha256: str = field(repr=False)
    confirmation_sha256: str = field(repr=False)
    created_at_ms: int

    def __post_init__(self):
        values = (self.reference_sha256, self.resource_sha256, self.source_payload_sha256,
                  self.classification_sha256, self.confirmation_sha256)
        if (any(type(v) is not str or HASH.fullmatch(v) is None for v in values)
                or type(self.source_revision) is not int or not 1 <= self.source_revision < MAXIMUM
                or type(self.created_at_ms) is not int or not 1 <= self.created_at_ms <= MAXIMUM):
            raise ValueError('exact minimized journal intent required')


@dataclass(frozen=True)
class JournalEntry:
    intent: JournalIntent = field(repr=False)
    sha256: str
    can_erase: bool = False
    restore_authorized: bool = False
    request_fulfilled: bool = False


def _body(intent):
    if type(intent) is not JournalIntent:
        raise ValueError('exact immutable journal intent required')
    intent = JournalIntent(**{name: getattr(intent, name) for name in JournalIntent.__dataclass_fields__})
    return {'schema_version': 1, 'kind': 'metadata-erasure-intent',
            **{name: getattr(intent, name) for name in JournalIntent.__dataclass_fields__}}


def _table_name(value):
    if type(value) is not str:
        raise ValueError('explicit journal and primary table identities required')
    if TABLE.fullmatch(value):
        return value
    match = ARN.fullmatch(value)
    if match:
        return match.group(1)
    raise ValueError('supported exact table identity required')


class DynamoErasureJournal:
    def __init__(self, repository, *, journal_table, expected_table_arn, limits):
        if type(repository) is not DynamoRepository or type(limits) is not JournalLimits:
            raise ValueError('explicit repository and journal limits required')
        if (type(journal_table) is not str or TABLE.fullmatch(journal_table) is None
                or type(expected_table_arn) is not str or ARN.fullmatch(expected_table_arn) is None
                or ARN.fullmatch(expected_table_arn).group(1) != journal_table
                or set(repository.tables) != {'state', 'events'}
                or journal_table in {_table_name(v) for v in repository.tables.values()}
                or type(repository.deployment) is not str or not 1 <= len(repository.deployment) <= 256):
            raise ValueError('journal must have an explicit separate table and exact ARN')
        self.repository = repository
        self.table = journal_table
        self.table_arn = expected_table_arn
        self.limits = limits
        client = repository.client
        try:
            config = client.meta.config
            retries = dict(config.retries)
            single = (type(retries.get('total_max_attempts')) is int and retries['total_max_attempts'] == 1
                      or 'total_max_attempts' not in retries and type(retries.get('max_attempts')) is int
                      and retries['max_attempts'] == 0)
            timeouts = (config.connect_timeout, config.read_timeout)
            if not single or any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in timeouts):
                raise ValueError('single-attempt bounded SDK configuration required')
        except (AttributeError, TypeError) as exc:
            raise ValueError('explicit bounded SDK client required') from exc
        self._initial = (repository, client, repository.deployment, tuple(sorted(repository.tables.items())),
                         journal_table, expected_table_arn, limits, config, retries, timeouts)
        self._limits_initial = (limits.max_record_bytes, limits.max_sdk_calls)
        self._sdk_initial = (json.dumps(retries, sort_keys=True, allow_nan=False),
                             tuple((type(v), v) for v in timeouts))

    def _check(self):
        repository, client, deployment, tables, table, arn, limits, config, retries, timeouts = self._initial
        try:
            valid = (self.repository is repository and repository.client is client
                and type(repository.deployment) is str and repository.deployment == deployment
                and type(repository.tables) is dict and set(repository.tables) == {'state', 'events'}
                and all(type(v) is str for v in repository.tables.values())
                and tuple(sorted(repository.tables.items())) == tables
                and type(self.table) is str and self.table == table
                and type(self.table_arn) is str and self.table_arn == arn and self.limits is limits
                and type(limits.max_record_bytes) is int and type(limits.max_sdk_calls) is int
                and (limits.max_record_bytes, limits.max_sdk_calls) == self._limits_initial
                and client.meta.config is config and type(config.retries) is dict
                and json.dumps(config.retries, sort_keys=True, allow_nan=False) == self._sdk_initial[0]
                and tuple((type(v), v) for v in (config.connect_timeout, config.read_timeout)) == self._sdk_initial[1])
        except (AttributeError, TypeError, ValueError):
            valid = False
        if not valid:
            raise JournalHeld('original journal configuration changed')

    def _protocol(self, *, deadline_ns, tick, checkpoint, required_calls):
        self._check()
        if (type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM
                or not callable(tick) or not callable(checkpoint)):
            raise ValueError('original finite journal deadline and checkpoints required')
        if self.limits.max_sdk_calls < required_calls:
            raise JournalHeld('journal protocol call allowance insufficient before effects')
        last = -1
        calls = 0

        def check():
            nonlocal last
            self._check()
            checkpoint()
            now = tick()
            if type(now) is not int or not 0 <= now < deadline_ns or now < last:
                raise JournalHeld('original journal deadline or clock invalid')
            last = now
            checkpoint()
            self._check()

        def call(name, **arguments):
            nonlocal calls
            check()
            if calls >= self.limits.max_sdk_calls:
                raise JournalHeld('journal SDK-call bound exhausted')
            calls += 1
            try:
                result = getattr(self._initial[1], name)(**arguments)
            except (ClientError, BotoCoreError):
                check()
                raise
            check()
            return result

        check()
        return call, check

    def _target(self, call):
        response = call('describe_table', TableName=self.table)
        if type(response) is not dict or type(response.get('Table')) is not dict:
            raise JournalHeld('intact journal table description required')
        description = response['Table']
        attributes = description.get('AttributeDefinitions')
        if (type(attributes) is not list or len(attributes) != 2
                or any(type(value) is not dict for value in attributes)):
            raise JournalHeld('exact journal key definitions required')
        if (description.get('TableName') != self.table or description.get('TableArn') != self.table_arn
                or description.get('TableStatus') != 'ACTIVE'
                or description.get('KeySchema') != [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                                                    {'AttributeName': 'sk', 'KeyType': 'RANGE'}]
                or sorted(attributes, key=lambda x: str(x.get('AttributeName', '')))
                != [{'AttributeName': 'pk', 'AttributeType': 'S'}, {'AttributeName': 'sk', 'AttributeType': 'S'}]
                or description.get('GlobalSecondaryIndexes') or description.get('LocalSecondaryIndexes')):
            raise JournalHeld('exact independent active journal table required')
        response = call('describe_time_to_live', TableName=self.table)
        ttl = response.get('TimeToLiveDescription') if type(response) is dict else None
        if type(ttl) is not dict or ttl.get('TimeToLiveStatus') != 'DISABLED':
            raise JournalHeld('journal TTL must be disabled')

    def _key(self, reference, resource):
        if any(type(v) is not str or HASH.fullmatch(v) is None for v in (reference, resource)):
            raise ValueError('exact opaque journal reference and resource digests required')
        return {'pk': {'S': 'deployment#' + self._initial[2]},
                'sk': {'S': 'resource#' + resource + '#reference#' + reference}}

    def _encoded(self, intent):
        return self._digest(_body(intent))

    def _digest(self, body):
        encoded = json.dumps(['metadata-erasure-journal/v1', self._initial[2], body],
                             sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        if len(encoded) > self.limits.max_record_bytes:
            raise JournalHeld('journal record byte bound exhausted')
        return hashlib.sha256(encoded).hexdigest()

    def _item(self, intent):
        body = _body(intent)
        item = {**self._key(intent.reference_sha256, intent.resource_sha256),
                'data': {'M': {k: {'N': str(v)} if type(v) is int else {'S': v} for k, v in body.items()}},
                'sha256': {'S': self._digest(body)}}
        size = len(json.dumps(item, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())
        if size > self.limits.max_record_bytes:
            raise JournalHeld('complete stored journal record byte bound exhausted')
        return item

    def _read(self, call, reference, resource):
        key = self._key(reference, resource)
        response = call('get_item', TableName=self.table, Key=key, ConsistentRead=True)
        if type(response) is not dict or not set(response) <= {'Item', 'ResponseMetadata', 'ConsumedCapacity'}:
            raise JournalHeld('intact journal lookup response required')
        if 'Item' not in response:
            return None
        item = response['Item']
        try:
            if (type(item) is not dict or set(item) != {'pk', 'sk', 'data', 'sha256'}
                    or item['pk'] != key['pk'] or item['sk'] != key['sk'] or set(item['data']) != {'M'}):
                raise ValueError('closed item required')
            raw = item['data']['M']
            fields = set(JournalIntent.__dataclass_fields__)
            if type(raw) is not dict or set(raw) != fields | {'schema_version', 'kind'}:
                raise ValueError('closed body required')
            body = {}
            for name, value in raw.items():
                number = name in {'schema_version', 'source_revision', 'created_at_ms'}
                kind = 'N' if number else 'S'
                if type(value) is not dict or set(value) != {kind} or type(value[kind]) is not str:
                    raise ValueError('exact scalar required')
                if number:
                    if re.fullmatch(r'[1-9][0-9]{0,18}', value[kind]) is None:
                        raise ValueError('bounded integer required')
                    body[name] = int(value[kind])
                else:
                    if len(value[kind]) > 64:
                        raise ValueError('bounded text required')
                    body[name] = value[kind]
            if body.pop('schema_version') != 1 or body.pop('kind') != 'metadata-erasure-intent':
                raise ValueError('supported journal schema required')
            intent = JournalIntent(**body)
            if intent.reference_sha256 != reference or intent.resource_sha256 != resource or item != self._item(intent):
                raise ValueError('original journal digest and identity required')
            return JournalEntry(intent, self._encoded(intent))
        except (KeyError, TypeError, ValueError) as exc:
            raise JournalHeld('intact minimized journal record required') from exc

    def append(self, intent, *, deadline_ns, tick, checkpoint):
        self._check()
        if type(intent) is not JournalIntent:
            raise ValueError('exact immutable journal intent required')
        item = self._item(intent)
        call, check = self._protocol(deadline_ns=deadline_ns, tick=tick, checkpoint=checkpoint, required_calls=7)
        try:
            self._target(call)
            entry = self._read(call, intent.reference_sha256, intent.resource_sha256)
            if entry is None:
                try:
                    call('put_item', TableName=self.table, Item=item,
                         ConditionExpression='attribute_not_exists(#pk) AND attribute_not_exists(#sk)',
                         ExpressionAttributeNames={'#pk': 'pk', '#sk': 'sk'})
                except (ClientError, BotoCoreError):
                    pass  # An exact readback is the only acknowledgment, including lost replies.
                entry = self._read(call, intent.reference_sha256, intent.resource_sha256)
            if entry is None:
                raise JournalHeld('journal write outcome remains unconfirmed')
            if entry.intent != intent:
                raise JournalConflict('original journal identity has different immutable intent')
            self._target(call)
            check()
            return entry
        except (ClientError, BotoCoreError) as exc:
            raise JournalHeld('journal storage outcome unavailable') from exc

    def read(self, *, reference_sha256, resource_sha256, deadline_ns, tick, checkpoint):
        self._key(reference_sha256, resource_sha256)
        call, check = self._protocol(deadline_ns=deadline_ns, tick=tick, checkpoint=checkpoint, required_calls=5)
        try:
            self._target(call)
            entry = self._read(call, reference_sha256, resource_sha256)
            self._target(call)
            check()
            return entry
        except (ClientError, BotoCoreError) as exc:
            raise JournalHeld('journal storage outcome unavailable') from exc
