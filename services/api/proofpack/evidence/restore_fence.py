"""Consume protected restore release state; never create release or erase authority."""
from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json
import re

from botocore.exceptions import BotoCoreError, ClientError

from proofpack.evidence.erasure_journal import (
    ARN, HASH, MAXIMUM, TABLE, DynamoErasureJournal, JournalLimits,
)
from proofpack.evidence.journal_anchors import AnchorCheckpoint, ZERO, _json
from proofpack.evidence.repository import DynamoRepository, StoreUnavailable
from proofpack.evidence.initial_release import FIELDS as INITIAL_FIELDS,validate_fields


class RestoreFenceHeld(StoreUnavailable):
    pass


def _sha(value):
    if type(value) is not str or HASH.fullmatch(value) is None:
        raise ValueError('exact opaque restore binding required')
    return value


@dataclass(frozen=True)
class RestoreFenceConfig:
    journal_table: str
    journal_arn: str
    genesis_sha256: str
    checkpoint: AnchorCheckpoint
    release_sha256: str
    target_table_ids: tuple[tuple[str, str], ...]
    artifact_sha256: str
    max_check_ms: int
    release_kind: str = 'restored-data-release'
    journal_table_id: str | None = None
    initial_configuration_sha256: str | None = None

    def __post_init__(self):
        if (type(self.journal_table) is not str or TABLE.fullmatch(self.journal_table) is None
                or type(self.journal_arn) is not str or ARN.fullmatch(self.journal_arn) is None
                or ARN.fullmatch(self.journal_arn).group(1) != self.journal_table
                or type(self.checkpoint) is not AnchorCheckpoint
                or type(self.target_table_ids) is not tuple or len(self.target_table_ids) != 2
                or any(type(v) is not tuple or len(v) != 2 for v in self.target_table_ids)
                or tuple(v[0] for v in self.target_table_ids) != ('events', 'state')
                or any(type(v) is not str or re.fullmatch(r'[A-Za-z0-9-]{1,128}', v) is None
                       for _, v in self.target_table_ids)
                or len({v for _, v in self.target_table_ids}) != 2
                or type(self.max_check_ms) is not int or not 1 <= self.max_check_ms <= 300000):
            raise ValueError('exact protected journal/checkpoint/target creation identities and finite check bound required')
        AnchorCheckpoint(self.checkpoint.sequence, self.checkpoint.digest)
        if (type(self.release_kind) is not str or self.release_kind not in {'restored-data-release','initial-data-release'}
                or (self.release_kind=='restored-data-release' and (self.journal_table_id is not None or self.initial_configuration_sha256 is not None))
                or (self.release_kind=='initial-data-release' and (self.checkpoint.sequence!=0
                    or type(self.journal_table_id) is not str or re.fullmatch(r'[A-Za-z0-9-]{1,128}',self.journal_table_id) is None
                    or self.journal_table_id in dict(self.target_table_ids).values()))):
            raise ValueError('exact separate release kind and fresh journal creation identity required')
        if self.initial_configuration_sha256 is not None:_sha(self.initial_configuration_sha256)
        for value in (self.genesis_sha256, self.release_sha256, self.artifact_sha256):
            _sha(value)


PROOFS = frozenset({'backup_sha256', 'source_identity_sha256', 'source_inventory_sha256',
    'target_inventory_sha256', 'effects_sha256', 'classification_sha256', 'confirmation_sha256',
    'media_coverage_sha256', 'runtime_generation_sha256'})


class RestoreDataFence:
    def __init__(self, client, *, deployment, state_table, events_table, config, tick):
        if type(config) is not RestoreFenceConfig or not callable(tick):
            raise ValueError('exact restore fence configuration and trusted monotonic clock required')
        RestoreFenceConfig(**{k: getattr(config, k) for k in config.__dataclass_fields__})
        if state_table == events_table:
            raise ValueError('distinct restored physical tables required')
        repository = DynamoRepository(client, deployment=deployment, state_table=state_table, events_table=events_table)
        self._journal = DynamoErasureJournal(repository, journal_table=config.journal_table,
            expected_table_arn=config.journal_arn, limits=JournalLimits(16384, 16))
        self.config, self.tick = config, tick
        self._initial = client, deployment, tuple(sorted(repository.tables.items())), config, tick
        self._configuration = _json(asdict(config))
        # A target with the same name but a new creation identity has a new key.
        self._target_digest = hashlib.sha256(_json(['restored-target/v1', deployment,
            self._initial[2], config.target_table_ids, config.journal_arn]).encode()).hexdigest()

    def _same(self):
        try:
            if self.config is not self._initial[3] or self.tick is not self._initial[4]:
                raise ValueError()
            RestoreFenceConfig(**{k: getattr(self.config, k) for k in self.config.__dataclass_fields__})
            if _json(asdict(self.config)) != self._configuration:
                raise ValueError()
            self._journal._check()
        except (ValueError, TypeError, AttributeError, RuntimeError) as exc:
            raise RestoreFenceHeld('original restore fence configuration changed') from exc

    def assert_repository(self, client, deployment, tables):
        self._same()
        if (client is not self._initial[0] or type(deployment) is not str or deployment != self._initial[1]
                or type(tables) is not dict or any(type(k) is not str or type(v) is not str for k, v in tables.items())
                or tuple(sorted(tables.items())) != self._initial[2]):
            raise RestoreFenceHeld('exact original fenced repository required')

    def _key(self, name):
        return {'pk': {'S': 'deployment#'+self._initial[1]}, 'sk': {'S': name}}

    def _anchor_digest(self, body):
        return hashlib.sha256(_json(['sealed-journal-history/v1', self._initial[1],
                                     self.config.journal_arn, body]).encode()).hexdigest()

    def _release_digest(self, body):
        return hashlib.sha256(_json([self.config.release_kind+'/v1', self._initial[1],
                                     self.config.journal_arn, body]).encode()).hexdigest()

    def _fixed(self):
        root = {'schema': 1, 'kind': 'journal_root', 'genesis': self.config.genesis_sha256,
                'sequence': 0, 'previous': ZERO}
        point = self.config.checkpoint
        head = {'schema': 1, 'kind': 'journal_head', 'genesis': self.config.genesis_sha256,
                'sequence': point.sequence, 'digest': point.digest}
        if point.sequence == 0 and point.digest != self._anchor_digest(root):
            raise RestoreFenceHeld('original genesis checkpoint differs')
        return root, head

    def _gets(self):
        return [{'Get': {'TableName': self.config.journal_table, 'Key': self._key(name)}}
                for name in ('anchor-root', 'anchor-head', 'restore-admission#'+self._target_digest)]

    def _validate(self, responses):
        if type(responses) is not list or len(responses) != 3:
            raise RestoreFenceHeld('complete protected restore state required')
        fixed = self._fixed()
        raw = []
        for index, response in enumerate(responses):
            try:
                if type(response) is not dict or set(response) != {'Item'}:
                    raise ValueError()
                item = response['Item']
                if type(item) is not dict or set(item) != {'pk', 'sk', 'body', 'sha256'}:
                    raise ValueError()
                if any(type(v) is not dict or set(v) != {'S'} or type(v['S']) is not str
                       or len(v['S']) > 16384 for v in item.values()):
                    raise ValueError()
                if any(item[k] != self._gets()[index]['Get']['Key'][k] for k in ('pk', 'sk')):
                    raise ValueError()
                body = json.loads(item['body']['S'])
                if type(body) is not dict or _json(body) != item['body']['S']:
                    raise ValueError()
                if index < 2:
                    if body != fixed[index] or item['sha256']['S'] != self._anchor_digest(body):
                        raise ValueError()
                    # bool == int is insufficient for a closed canonical row.
                    if type(body['schema']) is not int or type(body['sequence']) is not int:
                        raise ValueError()
                else:
                    expected = {'schema_version': 1, 'kind': self.config.release_kind,
                        'deployment': self._initial[1], 'target_tables': dict(self._initial[2]),
                        'target_table_ids': dict(self.config.target_table_ids),
                        'journal_arn': self.config.journal_arn, 'genesis_sha256': self.config.genesis_sha256,
                        'checkpoint': asdict(self.config.checkpoint), 'artifact_sha256': self.config.artifact_sha256,
                        'writer_protocol': 'metadata-payload-erasure/v1'}
                    proof_fields=PROOFS
                    if self.config.release_kind=='initial-data-release':
                        expected['journal_table_id']=self.config.journal_table_id
                        if self.config.initial_configuration_sha256 is None:raise ValueError()
                        expected['configuration_sha256']=self.config.initial_configuration_sha256
                        proof_fields=INITIAL_FIELDS
                    if (set(body) != set(expected) | proof_fields or type(body['schema_version']) is not int
                            or any(body.get(k) != v for k, v in expected.items())
                            or type(body['checkpoint']) is not dict
                            or type(body['checkpoint']['sequence']) is not int
                            or (self.config.release_kind=='restored-data-release' and any(type(body[k]) is not str or HASH.fullmatch(body[k]) is None for k in PROOFS))
                            or item['sha256']['S'] != self.config.release_sha256
                            or self._release_digest(body) != self.config.release_sha256):
                        raise ValueError()
                    if self.config.release_kind=='initial-data-release':
                        intent=validate_fields(body)
                        if intent.role_arn.split(':')[4]!=self.config.journal_arn.split(':')[4]:raise ValueError()
                raw.append(deepcopy(item))
            except (ValueError, TypeError, KeyError, RecursionError) as exc:
                raise RestoreFenceHeld('intact original protected restore release required') from exc
        return tuple(raw)

    def begin(self, checkpoint=lambda: None):
        return _FenceOperation(self, checkpoint)

    def check(self):
        self.begin().finish()

    def generation_sha256(self):
        operation = self.begin()
        generation = json.loads(operation.rows[2]['body']['S'])['runtime_generation_sha256']
        operation.finish()
        return generation

    def verify_target(self):
        """Read-only startup prerequisite; actual release writers remain external."""
        operation = self.begin()
        self._journal._target(operation.call)
        operation.finish()


class _FenceOperation:
    def __init__(self, fence, checkpoint):
        self.fence, self.checkpoint = fence, checkpoint
        self.calls, self.last, self.deadline = 0, -1, None
        self.guard()
        self._target()
        self.rows = self.capture()

    def guard(self):
        for _ in range(2):
            self.fence._same()
            self.checkpoint()
            self.fence._same()
            now = self.fence.tick()
            self.fence._same()
            if (type(now) is not int or not 0 <= now <= MAXIMUM or now < self.last
                    or self.deadline is not None and now >= self.deadline):
                raise RestoreFenceHeld('original restore fence deadline or clock invalid')
            if self.deadline is None:
                self.deadline = now + self.fence.config.max_check_ms * 1000000
                if self.deadline > MAXIMUM:
                    raise RestoreFenceHeld('finite original restore fence deadline required')
            self.last = now
            self.checkpoint()
            self.fence._same()

    def before_data_call(self):
        self.guard()
        self.calls += 1
        if self.calls > 8:
            raise RestoreFenceHeld('original restore fence SDK allowance exhausted')

    def call(self, name, **kwargs):
        self.before_data_call()
        try:
            value = getattr(self.fence._initial[0], name)(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            self.guard()
            raise RestoreFenceHeld('protected restore state unavailable') from exc
        self.guard()
        return value

    def _target(self):
        fence = self.fence
        prefix = fence.config.journal_arn.rsplit('/', 1)[0]+'/'
        ids = dict(fence.config.target_table_ids)
        for role, name in fence._initial[2]:
            response = self.call('describe_table', TableName=name)
            table = response.get('Table') if type(response) is dict else None
            if (type(table) is not dict or table.get('TableName') != name
                    or table.get('TableArn') != prefix+name or table.get('TableId') != ids[role]
                    or table.get('TableStatus') != 'ACTIVE'):
                raise RestoreFenceHeld('exact active target creation identity required')
        if fence.config.release_kind=='initial-data-release':
            response=self.call('describe_table',TableName=fence.config.journal_table)
            table=response.get('Table') if type(response) is dict else None
            if (type(table) is not dict or table.get('TableName')!=fence.config.journal_table
                    or table.get('TableArn')!=fence.config.journal_arn or table.get('TableStatus')!='ACTIVE'
                    or table.get('TableId')!=fence.config.journal_table_id):
                raise RestoreFenceHeld('exact initial journal creation identity required')

    def capture(self):
        response = self.call('transact_get_items', TransactItems=self.get_items())
        values = response.get('Responses') if type(response) is dict else None
        return self.fence._validate(values)

    def get_items(self):
        self.guard()
        return self.fence._gets()

    def validate(self, values):
        rows = self.fence._validate(values)
        if rows != self.rows:
            raise RestoreFenceHeld('original protected restore release changed')
        self.guard()

    def condition_items(self):
        self.guard()
        return [{'ConditionCheck': {'TableName': self.fence.config.journal_table,
            'Key': {k: row[k] for k in ('pk', 'sk')},
            'ConditionExpression': '#body = :body AND #sha = :sha',
            'ExpressionAttributeNames': {'#body': 'body', '#sha': 'sha256'},
            'ExpressionAttributeValues': {':body': row['body'], ':sha': row['sha256']}}}
            for row in deepcopy(self.rows)]

    def recheck(self):
        if self.capture() != self.rows:
            raise RestoreFenceHeld('original protected restore state changed before output')
        self.finish()

    def finish(self):
        self.guard()
