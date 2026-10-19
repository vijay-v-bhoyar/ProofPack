"""Independent sealed intent history; never erase or restore authority."""
from dataclasses import dataclass
import hashlib
import json
from botocore.exceptions import BotoCoreError, ClientError
from proofpack.evidence.erasure_journal import DynamoErasureJournal, JournalIntent, JournalHeld, JournalConflict, HASH, MAXIMUM, _body
from proofpack.evidence.journal_scope import JournalScopeLimits, journal_scope_sha256, read_journal_scope

ZERO = '0' * 64


class _StorageUnknown(JournalHeld):
    pass


def _sha(value):
    if type(value) is not str or HASH.fullmatch(value) is None:
        raise ValueError('exact opaque digest required')
    return value


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


@dataclass(frozen=True)
class JournalAnchorLimits:
    max_scopes: int
    max_total_intents: int
    max_item_bytes: int
    max_sdk_calls: int
    max_work: int

    def __post_init__(self):
        if any(type(getattr(self, k)) is not int or not 1 <= getattr(self, k) <= MAXIMUM
               for k in self.__dataclass_fields__):
            raise ValueError('explicit positive finite anchor limits required')


@dataclass(frozen=True)
class AnchorCheckpoint:
    sequence: int
    digest: str

    def __post_init__(self):
        if type(self.sequence) is not int or not 0 <= self.sequence < MAXIMUM:
            raise ValueError('exact finite anchor sequence required')
        _sha(self.digest)


@dataclass(frozen=True)
class AnchorReceipt:
    checkpoint: AnchorCheckpoint
    genesis_sha256: str
    scopes: int
    intents: int
    sdk_calls_reserved: int
    work_reserved: int
    historical: bool = True
    sealed_history_complete: bool = False
    can_erase: bool = False
    restore_authorized: bool = False
    request_fulfilled: bool = False
    global_history_complete: bool = False
    independent_iam_verified: bool = False


@dataclass(frozen=True)
class SealedScope:
    checkpoint: AnchorCheckpoint
    scope_sha256: str
    intents: tuple[JournalIntent, ...]


@dataclass(frozen=True)
class SealedHistoryManifest:
    receipt: AnchorReceipt
    source_deployment: str
    source_tables: tuple[tuple[str, str], ...]
    journal_arn: str
    scopes: tuple[SealedScope, ...]


class _Operation:
    def __init__(self, store, deadline, tick, checkpoint, calls, work):
        self.store, self.deadline, self.tick, self.checkpoint = store, deadline, tick, checkpoint
        if type(deadline) is not int or not 1 <= deadline <= MAXIMUM or not callable(tick) or not callable(checkpoint):
            raise ValueError('original finite deadline and trusted clock/checkpoint required')
        self.calls, self.work, self.last = 0, 0, -1
        self.reserved = calls, work
        store._check()
        if calls > store.limits.max_sdk_calls or work > store.limits.max_work:
            raise JournalHeld('complete anchor operation cannot fit original allowances')
        self.check()

    def check(self, work=0):
        self.store._check()
        self.work += work
        if self.work > self.reserved[1]:
            raise JournalHeld('original anchor work exhausted')
        for _ in range(2):
            self.checkpoint()
            self.store._check()
            now = self.tick()
            if type(now) is not int or not self.last <= now < self.deadline or now < 0:
                raise JournalHeld('original anchor deadline or clock invalid')
            self.last = now

    def spend(self, calls, work):
        self.check(work)
        self.calls += calls
        if self.calls > self.reserved[0]:
            raise JournalHeld('original cumulative anchor SDK allowance exhausted')

    def call(self, name, **kwargs):
        self.spend(1, 1)
        try:
            result = getattr(self.store.journal._initial[1], name)(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            self.check()
            raise _StorageUnknown('anchor storage outcome unavailable') from exc
        self.check()
        return result


class JournalAnchorStore:
    def __init__(self, journal, *, genesis_sha256, limits):
        if type(journal) is not DynamoErasureJournal or type(limits) is not JournalAnchorLimits:
            raise ValueError('exact journal and explicit anchor limits required')
        _sha(genesis_sha256)
        if limits.max_item_bytes > journal.limits.max_record_bytes:
            raise ValueError('anchor item capacity must tighten original journal capacity')
        self.journal, self.genesis_sha256, self.limits = journal, genesis_sha256, limits
        self._initial = journal, genesis_sha256, limits, tuple(getattr(limits, k) for k in limits.__dataclass_fields__)
        journal._check()

    def _check(self):
        journal, genesis, limits, values = self._initial
        if (self.journal is not journal or type(self.genesis_sha256) is not str or self.genesis_sha256 != genesis
                or self.limits is not limits or tuple(getattr(limits, k) for k in limits.__dataclass_fields__) != values
                or any(type(getattr(limits, k)) is not int for k in limits.__dataclass_fields__)):
            raise JournalHeld('original anchor configuration changed')
        DynamoErasureJournal._check(journal)

    def _key(self, name):
        return {'pk': {'S': 'deployment#' + self.journal._initial[2]}, 'sk': {'S': name}}

    def _digest(self, body):
        return hashlib.sha256(_json(['sealed-journal-history/v1', self.journal._initial[2], self.journal._initial[5], body]).encode()).hexdigest()

    def _root(self):
        return {'schema': 1, 'kind': 'journal_root', 'genesis': self.genesis_sha256, 'sequence': 0, 'previous': ZERO}

    def _head(self, point):
        return {'schema': 1, 'kind': 'journal_head', 'genesis': self.genesis_sha256, 'sequence': point.sequence, 'digest': point.digest}

    def _item(self, name, body, op):
        op.check(1)
        item = {**self._key(name), 'body': {'S': _json(body)}, 'sha256': {'S': self._digest(body)}}
        if len(_json(item).encode()) > self.limits.max_item_bytes:
            raise JournalHeld('complete anchor SDK item byte bound exhausted')
        return item

    def _get(self, name, op):
        result = op.call('get_item', TableName=self.journal.table, Key=self._key(name), ConsistentRead=True)
        if type(result) is not dict or not set(result) <= {'Item', 'ResponseMetadata', 'ConsumedCapacity'}:
            raise JournalHeld('intact anchor response required')
        if 'Item' not in result:
            return None
        item = result['Item']
        try:
            if type(item) is not dict or set(item) != {'pk', 'sk', 'body', 'sha256'}:
                raise ValueError()
            if any(type(v) is not dict or set(v) != {'S'} or type(v['S']) is not str
                   or len(v['S']) > self.limits.max_item_bytes for v in item.values()):
                raise ValueError()
            if item['pk'] != self._key(name)['pk'] or item['sk'] != self._key(name)['sk']:
                raise ValueError()
            body = json.loads(item['body']['S'])
            if type(body) is not dict or self._item(name, body, op) != item:
                raise ValueError()
            return body
        except (ValueError, TypeError, KeyError, RecursionError):
            raise JournalHeld('closed canonical anchor item required') from None

    def _current(self, op):
        root, head = self._get('anchor-root', op), self._get('anchor-head', op)
        if (root != self._root() or type(root.get('schema')) is not int or type(root.get('sequence')) is not int
                or type(head) is not dict or set(head) != {'schema', 'kind', 'genesis', 'sequence', 'digest'}):
            raise JournalHeld('exact enrolled root and head required')
        try:
            point = AnchorCheckpoint(head['sequence'], head['digest'])
        except ValueError:
            raise JournalHeld('exact enrolled checkpoint required') from None
        if head != self._head(point) or type(head['schema']) is not int or point.sequence > self.limits.max_scopes:
            raise JournalHeld('bounded original journal head required')
        if point.sequence == 0 and point.digest != self._digest(root):
            raise JournalHeld('original genesis head required')
        return point

    def _target(self, op):
        DynamoErasureJournal._target(self.journal, op.call)

    def _transaction(self, puts, op):
        try:
            op.call('transact_write_items', TransactItems=puts)
        except _StorageUnknown:
            pass  # Only matching durable readback acknowledges an uncertain commit.

    def _put(self, name, body, op, previous=None):
        value = {'TableName': self.journal.table, 'Item': self._item(name, body, op)}
        if previous is None:
            value.update(ConditionExpression='attribute_not_exists(#pk) AND attribute_not_exists(#sk)',
                         ExpressionAttributeNames={'#pk': 'pk', '#sk': 'sk'})
        else:
            value.update(ConditionExpression='#body = :old', ExpressionAttributeNames={'#body': 'body'},
                         ExpressionAttributeValues={':old': {'S': _json(previous)}})
        return {'Put': value}

    def _receipt(self, point, scopes, intents, op, *, complete=False):
        self._target(op)
        op.check()
        return AnchorReceipt(point, self.genesis_sha256, scopes, intents, *op.reserved, sealed_history_complete=complete)

    def initialize(self, *, deadline_ns, tick, checkpoint):
        op = _Operation(self, deadline_ns, tick, checkpoint, 10, 32)
        self._target(op)
        root, head = self._get('anchor-root', op), self._get('anchor-head', op)
        if root is None and head is None:
            result = op.call('query', TableName=self.journal.table, KeyConditionExpression='#pk = :pk',
                             ExpressionAttributeNames={'#pk': 'pk'}, ExpressionAttributeValues={':pk': self._key('')['pk']},
                             Limit=1, ConsistentRead=True)
            if type(result) is not dict or result.get('Items') != [] or result.get('Count') != 0 or result.get('LastEvaluatedKey'):
                raise JournalHeld('exclusive empty deployment enrollment required')
            root = self._root()
            point = AnchorCheckpoint(0, self._digest(root))
            self._transaction([self._put('anchor-root', root, op), self._put('anchor-head', self._head(point), op)], op)
        point = self._current(op)
        return self._receipt(point, 0, 0, op)

    def _intents(self, values, op):
        if type(values) is not tuple or not values or len(values) > self.limits.max_total_intents:
            raise JournalHeld('bounded nonempty original scope required')
        result = []
        for value in values:
            op.check(1)
            body = _body(value)
            result.append(JournalIntent(**{k: body[k] for k in JournalIntent.__dataclass_fields__}))
        return tuple(result)

    def _scope(self, intents, expected, op):
        count = len(intents)
        op.spend(5 * count, 3 * count + 2)
        limits = JournalScopeLimits(count, self.limits.max_item_bytes, 5 * count, 3 * count + 2)
        read_journal_scope(self.journal, intents, expected_sha256=expected, limits=limits,
                           deadline_ns=op.deadline, tick=op.tick, checkpoint=op.check)

    def seal(self, intents, *, expected_head, scope_sha256, deadline_ns, tick, checkpoint):
        if type(expected_head) is not AnchorCheckpoint:
            raise ValueError('exact original head checkpoint required')
        expected_head = AnchorCheckpoint(expected_head.sequence, expected_head.digest)
        _sha(scope_sha256)
        if type(intents) is not tuple or not intents:
            raise ValueError('original nonempty immutable scope required')
        n = len(intents)
        op = _Operation(self, deadline_ns, tick, checkpoint, 11 + 5 * n, 64 + 8 * n)
        if expected_head.sequence >= self.limits.max_scopes:
            raise JournalHeld('original sealed history capacity exhausted')
        copies = self._intents(intents, op)
        body = {'schema': 1, 'kind': 'journal_anchor', 'genesis': self.genesis_sha256,
                'sequence': expected_head.sequence + 1, 'previous': expected_head.digest,
                'scope_sha256': scope_sha256, 'intents': [_body(v) for v in copies]}
        point = AnchorCheckpoint(body['sequence'], self._digest(body))
        self._item('anchor#' + point.digest, body, op)  # Complete-item admission before effects.
        self._target(op)
        current = self._current(op)
        if current not in (expected_head, point):
            raise JournalConflict('original journal head advanced or differs')
        self._scope(copies, scope_sha256, op)
        existing = self._get('anchor#' + point.digest, op)
        if existing is not None and existing != body:
            raise JournalConflict('immutable scope anchor differs')
        if current == expected_head:
            self._transaction([self._put('anchor#' + point.digest, body, op),
                               self._put('anchor-head', self._head(point), op, self._head(expected_head))], op)
        if self._current(op) != point or self._get('anchor#' + point.digest, op) != body:
            raise JournalHeld('original sealed scope outcome remains unconfirmed')
        # The receipt remains historical; this cannot be used as a cleanup grant.
        return self._receipt(point, 1, n, op)

    def read_history(self, *, expected_head, deadline_ns, tick, checkpoint):
        return self._read_history(expected_head=expected_head, deadline_ns=deadline_ns,
                                  tick=tick, checkpoint=checkpoint, manifest=False)

    def read_manifest(self, *, expected_head, deadline_ns, tick, checkpoint):
        """Private verified intent inventory, not restore or cleanup authority."""
        return self._read_history(expected_head=expected_head, deadline_ns=deadline_ns,
                                  tick=tick, checkpoint=checkpoint, manifest=True)

    def _read_history(self, *, expected_head, deadline_ns, tick, checkpoint, manifest):
        if type(expected_head) is not AnchorCheckpoint:
            raise ValueError('independently retained exact checkpoint required')
        expected_head = AnchorCheckpoint(expected_head.sequence, expected_head.digest)
        scopes = expected_head.sequence
        if scopes > self.limits.max_scopes:
            raise JournalHeld('complete original history exceeds scope capacity')
        capacity = self.limits.max_total_intents if scopes else 0
        op = _Operation(self, deadline_ns, tick, checkpoint, 8 + scopes + 5 * capacity, 64 + 16 * scopes + 8 * capacity)
        self._target(op)
        if self._current(op) != expected_head:
            raise JournalConflict('current journal differs from trusted checkpoint')
        point, count = expected_head, 0
        verified_scopes = []
        while point.sequence:
            body = self._get('anchor#' + point.digest, op)
            if (type(body) is not dict or set(body) != {'schema', 'kind', 'genesis', 'sequence', 'previous', 'scope_sha256', 'intents'}
                    or type(body['schema']) is not int or body['schema'] != 1 or body['kind'] != 'journal_anchor'
                    or body['genesis'] != self.genesis_sha256 or type(body['sequence']) is not int
                    or body['sequence'] != point.sequence or self._digest(body) != point.digest
                    or type(body['intents']) is not list or not body['intents']
                    or len(body['intents']) > self.limits.max_total_intents - count):
                raise JournalHeld('complete original bounded scope anchor required')
            try:
                _sha(body['previous']); _sha(body['scope_sha256'])
                values = []
                for value in body['intents']:
                    op.check(1)
                    if type(value) is not dict or set(value) != set(JournalIntent.__dataclass_fields__) | {'schema_version', 'kind'}:
                        raise ValueError()
                    intent = JournalIntent(**{k: value[k] for k in JournalIntent.__dataclass_fields__})
                    if _body(intent) != value or type(value['schema_version']) is not int:
                        raise ValueError()
                    values.append(intent)
            except (ValueError, TypeError, KeyError):
                raise JournalHeld('exact original minimized anchor intents required') from None
            copies = tuple(values)
            count += len(copies)
            self._scope(copies, body['scope_sha256'], op)
            if manifest:
                verified_scopes.append(SealedScope(point, body['scope_sha256'], copies))
            point = AnchorCheckpoint(point.sequence - 1, body['previous'])
        if point.digest != self._digest(self._root()) or self._current(op) != expected_head:
            raise JournalHeld('original complete genesis-to-head history required')
        receipt = self._receipt(expected_head, scopes, count, op, complete=True)
        if not manifest:
            return receipt
        # Copy only identities frozen and checked by the journal protocol. The
        # target restore repository must remain separate from this source view.
        source = self.journal._initial
        result = SealedHistoryManifest(receipt, source[2], source[3], source[5], tuple(verified_scopes))
        op.check()
        return result
