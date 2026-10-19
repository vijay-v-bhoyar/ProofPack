"""Private backup/target reconciliation; never restoration or erasure authority."""
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json

from botocore.exceptions import BotoCoreError, ClientError

from proofpack.evidence.erasure_journal import (
    ARN, HASH, MAXIMUM, DynamoErasureJournal, JournalHeld, _table_name,
)
from proofpack.evidence.inventory import (
    InventoryLimits, InventoryPass, InventoryEntry, InventoryHeld,
    collect, _target, _validated_pass,
)
from proofpack.evidence.journal_anchors import AnchorCheckpoint, JournalAnchorStore
from proofpack.evidence.repository import DynamoRepository, Key


@dataclass(frozen=True)
class RestoreInventoryLimits:
    inventory: InventoryLimits
    max_sdk_calls: int
    max_work: int

    def __post_init__(self):
        if (type(self.inventory) is not InventoryLimits
                or any(type(v) is not int or not 1 <= v <= MAXIMUM
                       for v in (self.max_sdk_calls, self.max_work))):
            raise ValueError('explicit typed finite restore inventory limits required')


@dataclass(frozen=True)
class RestoreIntentMatch:
    resource_sha256: str
    reference_sha256: str = field(repr=False)
    status: str
    entry: InventoryEntry | None = field(repr=False)


@dataclass(frozen=True)
class RestoreInventoryResult:
    checkpoint: AnchorCheckpoint
    genesis_sha256: str
    source_deployment: str
    source_tables: tuple[tuple[str, str], ...]
    journal_arn: str
    target_tables: tuple[tuple[str, str], ...]
    target_arns: tuple[tuple[str, str], ...]
    backup_sha256: str
    artifact_sha256: str
    source_inventory_sha256: str
    target_inventory_sha256: str
    matches: tuple[RestoreIntentMatch, ...] = field(repr=False)
    inventory: InventoryPass = field(repr=False)
    sdk_calls_reserved: int
    work_reserved: int
    can_erase: bool = False
    restore_authorized: bool = False
    can_release: bool = False
    request_fulfilled: bool = False


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def read_restore_inventory(store, target, *, expected_head, target_arns,
                           backup_sha256, source_inventory, artifact_sha256,
                           limits, deadline_ns, tick, checkpoint):
    """Caller supplies the real host isolation/drain checkpoint and provenance.

    Two matching scans under that barrier are not independently proven backup
    provenance, an atomic database snapshot, approved effects or a release grant.
    """
    if (type(store) is not JournalAnchorStore or type(target) is not DynamoRepository
            or type(expected_head) is not AnchorCheckpoint
            or type(limits) is not RestoreInventoryLimits
            or type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM
            or not callable(tick) or not callable(checkpoint)
            or any(type(v) is not str or HASH.fullmatch(v) is None
                   for v in (backup_sha256, artifact_sha256))
            or type(target_arns) is not tuple or len(target_arns) != 2
            or any(type(v) is not tuple or len(v) != 2 for v in target_arns)):
        raise ValueError('exact source, isolated target, backup, artifact and original bounds required')
    store._check()
    source = store.journal._initial
    original = source[0]
    original_tables = dict(source[3])
    target_identity = _target(target)
    names = {role: _table_name(name) for role, name in target.tables.items()}
    forbidden = {_table_name(name) for name in original_tables.values()} | {store.journal.table}
    if (target is original or target.deployment != source[2] or set(names) != {'state', 'events'}
            or len(set(names.values())) != 2 or set(names.values()) & forbidden):
        raise JournalHeld('distinct isolated tables with original logical deployment required')
    if tuple(role for role, _ in target_arns) != ('events', 'state'):
        raise ValueError('canonical exact target ARN mapping required')
    prefix = source[5].rsplit('/', 1)[0] + '/'
    for role, arn in target_arns:
        if type(arn) is not str or ARN.fullmatch(arn) is None or arn != prefix + names[role]:
            raise JournalHeld('supported exact same-account/region target mapping required')
        physical = target.tables[role]
        if physical != names[role] and physical != arn:
            raise JournalHeld('repository physical target differs from exact ARN')
    target_binding = DynamoErasureJournal(target, journal_table=source[4],
        expected_table_arn=source[5], limits=source[6])
    inventory_limits = limits.inventory
    bounds = (limits.inventory.page_size, limits.inventory.max_pages,
              limits.inventory.max_records, limits.inventory.max_summary_bytes,
              limits.max_sdk_calls, limits.max_work)
    head = AnchorCheckpoint(expected_head.sequence, expected_head.digest)
    scopes = head.sequence
    capacity = store.limits.max_total_intents if scopes else 0
    calls_reserved = 2 * (8 + scopes + 5 * capacity) + 8 + 2 * limits.inventory.max_pages
    work_reserved = 2 * (64 + 16 * scopes + 8 * capacity) + 8 * limits.inventory.max_records + 6 * capacity + 64
    if scopes > store.limits.max_scopes or calls_reserved > limits.max_sdk_calls or work_reserved > limits.max_work:
        raise JournalHeld('complete original restore inventory cannot fit cumulative allowances')
    last = -1
    work = 0

    def same():
        store._check()
        target_binding._check()
        current = (limits.inventory.page_size, limits.inventory.max_pages,
                   limits.inventory.max_records, limits.inventory.max_summary_bytes,
                   limits.max_sdk_calls, limits.max_work)
        if (limits.inventory is not inventory_limits or current != bounds
                or any(type(v) is not int for v in current) or _target(target) != target_identity):
            raise JournalHeld('original restore inventory bindings changed')

    def guard(cost=0):
        nonlocal last, work
        work += cost
        if work > work_reserved:
            raise JournalHeld('original restore inventory work exhausted')
        for _ in range(2):
            same()
            checkpoint()
            same()
            now = tick()
            same()
            if type(now) is not int or not 0 <= now < deadline_ns or now < last:
                raise JournalHeld('original restore deadline or clock invalid')
            last = now

    guard()
    _validated_pass(original, source_inventory, limits.inventory, _target(original))
    backup = deepcopy(source_inventory)
    _validated_pass(original, backup, limits.inventory, _target(original))
    backup_fingerprint = _digest([backup.deployment, backup.tables, backup.summary_sha256, backup.summary_bytes])

    def same_backup():
        _validated_pass(original, source_inventory, limits.inventory, _target(original))
        if (source_inventory != backup or _digest([source_inventory.deployment, source_inventory.tables,
                source_inventory.summary_sha256, source_inventory.summary_bytes]) != backup_fingerprint):
            raise JournalHeld('original supplied backup inventory changed')

    def check_backup():
        guard()
        same_backup()

    def describe_target():
        for role, arn in target_arns:
            guard(1)
            try:
                response = target.client.describe_table(TableName=target.tables[role])
                guard()
                table = response.get('Table') if type(response) is dict else None
                if (type(table) is not dict or table.get('TableArn') != arn
                        or table.get('TableName') != names[role] or table.get('TableStatus') != 'ACTIVE'
                        or table.get('KeySchema') != [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                                                     {'AttributeName': 'sk', 'KeyType': 'RANGE'}]
                        or type(table.get('AttributeDefinitions')) is not list
                        or any(type(v) is not dict for v in table['AttributeDefinitions'])
                        or sorted(table['AttributeDefinitions'], key=lambda v: str(v.get('AttributeName', '')))
                        != [{'AttributeName': 'pk', 'AttributeType': 'S'},
                            {'AttributeName': 'sk', 'AttributeType': 'S'}]):
                    raise JournalHeld('exact active restored table required')
                response = target.client.describe_time_to_live(TableName=target.tables[role])
                guard()
            except (BotoCoreError, ClientError) as exc:
                raise JournalHeld('restored target identity unavailable') from exc
            ttl = response.get('TimeToLiveDescription') if type(response) is dict else None
            if type(ttl) is not dict or ttl.get('TimeToLiveStatus') != 'DISABLED':
                raise JournalHeld('isolated restored target TTL must be disabled')

    options = dict(expected_head=head, deadline_ns=deadline_ns, tick=tick, checkpoint=guard)
    history = store.read_manifest(**options)
    describe_target()
    inventory = collect(target, limits=limits.inventory, deadline_ns=deadline_ns, tick=tick, checkpoint=guard)
    if inventory.entries != backup.entries:
        raise JournalHeld('complete target inventory differs from supplied backup')
    entries = {}
    for entry in inventory.entries:
        guard(1)
        digest = DynamoRepository._erasure_identity(original, entry.key)
        if digest in entries:
            raise JournalHeld('ambiguous original resource identity')
        entries[digest] = entry
    intents = {}
    for scope in history.scopes:
        for intent in scope.intents:
            guard(1)
            previous = intents.get(intent.resource_sha256)
            if previous is not None and previous != intent:
                raise JournalHeld('conflicting sealed intents for original resource')
            intents[intent.resource_sha256] = intent
    matches = []
    for digest, intent in sorted(intents.items()):
        guard(1)
        entry = entries.get(digest)
        status = 'unresolved_absent'
        if entry is not None:
            if entry.kind == 'live':
                if entry.revision != intent.source_revision or entry.payload_sha256 != intent.source_payload_sha256:
                    raise JournalHeld('restored live source differs from original intent')
                status = 'pending_effect'
            else:
                if (entry.revision != intent.source_revision + 1 or entry.reference_sha256 != intent.reference_sha256
                        or entry.resource_sha256 != intent.resource_sha256):
                    raise JournalHeld('restored marker differs from original intent')
                status = 'marker_observed'
        matches.append(RestoreIntentMatch(digest, intent.reference_sha256, status, entry))
    check_backup()
    following = collect(target, limits=limits.inventory, deadline_ns=deadline_ns, tick=tick, checkpoint=guard)
    if following != inventory:
        raise JournalHeld('complete restored inventory changed before delivery')
    if store.read_manifest(**options) != history:
        raise JournalHeld('trusted sealed history changed before delivery')
    describe_target()
    check_backup()
    result = RestoreInventoryResult(head, history.receipt.genesis_sha256, source[2], source[3], source[5],
        target_identity[1], target_arns, backup_sha256, artifact_sha256, backup.summary_sha256,
        inventory.summary_sha256, tuple(matches), inventory, calls_reserved, work_reserved)
    guard()
    same_backup()
    return result
