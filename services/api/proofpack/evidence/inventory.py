"""Finite payload-free enumeration; never ownership, a barrier, or removal authority."""
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from decimal import Decimal
import hashlib
import json
import re
import time

from proofpack.evidence.repository import Key, Row, ErasureMarker, StoreUnavailable
from proofpack.evidence.resource_bindings import _payload_sha256


class InventoryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class InventoryLimits:
    page_size: int
    max_pages: int
    max_records: int
    max_summary_bytes: int

    def __post_init__(self):
        if any(type(value) is not int or not 1 <= value <= 2**63-1 for value in
               (self.page_size, self.max_pages, self.max_records, self.max_summary_bytes)) or self.page_size > 100:
            raise ValueError('explicit finite inventory limits required')


@dataclass(frozen=True)
class InventoryEntry:
    key: Key
    revision: int
    kind: str
    payload_sha256: str | None
    reference_sha256: str | None
    resource_sha256: str | None


@dataclass(frozen=True)
class InventoryPass:
    deployment: str
    tables: tuple[tuple[str, str], ...]
    entries: tuple[InventoryEntry, ...]
    pages: int
    summary_sha256: str
    summary_bytes: int


@dataclass(frozen=True)
class InventoryReadSet:
    inventory: InventoryPass
    rows: tuple[Row, ...] = field(repr=False)
    markers: tuple[ErasureMarker, ...]
    snapshot_batches: int
    payload_bytes: int


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _target(repository):
    if (type(repository.deployment) is not str or not 1 <= len(repository.deployment) <= 256
            or type(repository.tables) is not dict or set(repository.tables) != {'state', 'events'}
            or any(type(value) is not str or not value for value in repository.tables.values())):
        raise InventoryHeld('exact supported inventory target required')
    return repository.deployment, tuple(sorted(repository.tables.items())), id(repository.client)


def _entry(repository, row, table):
    if (not isinstance(row, (Row, ErasureMarker)) or not isinstance(row.key, Key) or row.key.table != table
            or type(row.key.resource) is not str or not 1 <= len(row.key.resource) <= 256
            or type(row.revision) is not int or not 1 <= row.revision <= 2**63-1):
        raise InventoryHeld('intact typed inventory record required')
    if isinstance(row, Row):
        try:
            digest = _payload_sha256(row.data)
        except (ValueError, TypeError, ArithmeticError) as exc:
            raise InventoryHeld('canonical inventory payload required') from exc
        return InventoryEntry(row.key, row.revision, 'live', digest, None, None)
    if (row.revision < 2 or any(type(value) is not str or re.fullmatch('[a-f0-9]{64}', value) is None
                              for value in (row.reference_sha256, row.resource_sha256))
            or row.resource_sha256 != repository._erasure_identity(row.key)):
        raise InventoryHeld('intact minimal inventory marker required')
    return InventoryEntry(row.key, row.revision, 'erased', None, row.reference_sha256, row.resource_sha256)


def collect(repository, *, limits, deadline_ns, checkpoint, tick=time.monotonic_ns):
    """An admitted caller must supply its real authority/barrier checkpoint."""
    if (not isinstance(limits, InventoryLimits) or not callable(checkpoint) or not callable(tick)
            or type(deadline_ns) is not int or not 1 <= deadline_ns <= 2**63-1):
        raise ValueError('finite limits, absolute deadline and trusted checkpoint required')
    target = _target(repository); client = repository.client; last_tick = -1
    def guard():
        nonlocal last_tick
        if repository.client is not client or _target(repository) != target:
            raise InventoryHeld('inventory target changed')
        checkpoint()
        if repository.client is not client or _target(repository) != target:
            raise InventoryHeld('inventory target changed')
        now = tick()
        if repository.client is not client or _target(repository) != target:
            raise InventoryHeld('inventory target changed')
        if type(now) is not int or now < last_tick or now < 0 or now >= deadline_ns:
            raise InventoryHeld('inventory deadline or clock invalid')
        last_tick = now
    guard()
    body = {'deployment': target[0], 'tables': dict(target[1]), 'entries': []}
    size = len(_encoded(body)); summaries = []; seen = set(); pages = 0
    if size > limits.max_summary_bytes:
        raise InventoryHeld('inventory summary budget exhausted')
    for table, _ in target[1]:
        cursor = None; cursors = set()
        while True:
            guard()
            if pages >= limits.max_pages:
                raise InventoryHeld('inventory page budget exhausted')
            try:
                rows, following = repository.partition_page(table=table, limit=limits.page_size, start_resource=cursor)
            except StoreUnavailable as exc:
                raise InventoryHeld('inventory page unavailable') from exc
            pages += 1; guard()
            if type(rows) is not list or len(rows) > limits.page_size:
                raise InventoryHeld('bounded inventory page required')
            previous = cursor
            for row in rows:
                entry = _entry(repository, row, table)
                if entry.key in seen or (previous is not None and entry.key.resource <= previous):
                    raise InventoryHeld('duplicate or nonprogressing inventory record')
                if len(summaries) >= limits.max_records:
                    raise InventoryHeld('inventory record budget exhausted')
                value = asdict(entry); size += len(_encoded(value)) + bool(summaries)
                if size > limits.max_summary_bytes:
                    raise InventoryHeld('inventory summary budget exhausted')
                summaries.append(entry); body['entries'].append(value); seen.add(entry.key); previous = entry.key.resource
            if following is None:
                break
            if (type(following) is not str or not 1 <= len(following) <= 256 or following in cursors
                    or (cursor is not None and following <= cursor) or (previous is not None and following < previous)):
                raise InventoryHeld('progressing inventory cursor required')
            cursors.add(following); cursor = following
    encoded = _encoded(body)
    if len(encoded) != size or len(encoded) > limits.max_summary_bytes:
        raise InventoryHeld('exact inventory summary budget required')
    digest = hashlib.sha256(encoded).hexdigest(); guard()
    return InventoryPass(target[0], target[1], tuple(summaries), pages, digest, len(encoded))


def _validated_pass(repository, inventory, limits, target):
    if (type(inventory) is not InventoryPass or type(inventory.entries) is not tuple
            or type(inventory.tables) is not tuple or inventory.deployment != target[0]
            or inventory.tables != target[1] or type(inventory.pages) is not int
            or not 2 <= inventory.pages <= limits.max_pages
            or len(inventory.entries) > limits.max_records
            or type(inventory.summary_bytes) is not int
            or not 1 <= inventory.summary_bytes <= limits.max_summary_bytes
            or type(inventory.summary_sha256) is not str
            or re.fullmatch('[a-f0-9]{64}', inventory.summary_sha256) is None):
        raise InventoryHeld('intact bounded original inventory required')
    previous = None
    for entry in inventory.entries:
        if (type(entry) is not InventoryEntry or type(entry.key) is not Key
                or type(entry.key.table) is not str or entry.key.table not in {'state', 'events'}
                or type(entry.key.resource) is not str or not 1 <= len(entry.key.resource) <= 256
                or type(entry.revision) is not int or not 1 <= entry.revision <= 2**63-1):
            raise InventoryHeld('intact inventory entry required')
        identity = (entry.key.table, entry.key.resource)
        if previous is not None and identity <= previous:
            raise InventoryHeld('ordered unique inventory entries required')
        previous = identity
        if entry.kind == 'live':
            if (type(entry.payload_sha256) is not str or re.fullmatch('[a-f0-9]{64}', entry.payload_sha256) is None
                    or entry.reference_sha256 is not None or entry.resource_sha256 is not None):
                raise InventoryHeld('intact live inventory reference required')
        elif entry.kind == 'erased':
            if (entry.revision < 2 or entry.payload_sha256 is not None
                    or any(type(v) is not str or re.fullmatch('[a-f0-9]{64}', v) is None
                           for v in (entry.reference_sha256, entry.resource_sha256))
                    or entry.resource_sha256 != repository._erasure_identity(entry.key)):
                raise InventoryHeld('intact inventory marker reference required')
        else:
            raise InventoryHeld('supported inventory entry kind required')
    encoded = _encoded({'deployment': inventory.deployment, 'tables': dict(inventory.tables),
                        'entries': [asdict(entry) for entry in inventory.entries]})
    if len(encoded) != inventory.summary_bytes or hashlib.sha256(encoded).hexdigest() != inventory.summary_sha256:
        raise InventoryHeld('original inventory summary mismatch')


def _private_payload_size(data):
    # _entry has already enforced the writer's canonical storable domain.
    def number(value):
        if type(value) is Decimal and value.is_finite() and value == value.to_integral_value():
            return int(value)
        raise ValueError()
    return len(json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False, default=number).encode())


def _snapshot_capacity(repository):
    try:
        capacity = getattr(repository, 'snapshot_capacity', 100)
    except StoreUnavailable as exc:
        raise InventoryHeld('original inventory snapshot capacity unavailable') from exc
    if type(capacity) is not int or not 1 <= capacity <= 100:
        raise InventoryHeld('exact bounded inventory snapshot capacity required')
    return capacity


def reconcile(repository, inventory, *, limits, max_snapshot_batches, max_payload_bytes,
              deadline_ns, checkpoint, tick=time.monotonic_ns):
    """Read-only private inputs; real admission/drain and final scope review are external."""
    if (type(limits) is not InventoryLimits or not callable(checkpoint) or not callable(tick)
            or any(type(n) is not int or not 1 <= n <= 2**63-1
                   for n in (max_snapshot_batches, max_payload_bytes, deadline_ns))):
        raise ValueError('explicit finite read-set limits, deadline and admission required')
    target = _target(repository); client = repository.client
    capacity = _snapshot_capacity(repository)
    _validated_pass(repository, inventory, limits, target)
    batches = (len(inventory.entries) + capacity-1) // capacity
    if batches > max_snapshot_batches:
        raise InventoryHeld('inventory snapshot budget exhausted')
    last_tick = -1
    def read_tick():
        nonlocal last_tick
        now = tick()
        if (repository.client is not client or _target(repository) != target or _snapshot_capacity(repository) != capacity or type(now) is not int
                or now < last_tick or now < 0 or now >= deadline_ns):
            raise InventoryHeld('inventory read-set target, deadline or clock invalid')
        last_tick = now
        return now
    def guard():
        if repository.client is not client or _target(repository) != target or _snapshot_capacity(repository) != capacity:
            raise InventoryHeld('inventory read-set target changed')
        checkpoint()
        if repository.client is not client or _target(repository) != target or _snapshot_capacity(repository) != capacity:
            raise InventoryHeld('inventory read-set target changed')
        read_tick()
    guard()
    private = []; markers = []; size = 0
    for offset in range(0, len(inventory.entries), capacity):
        entries = inventory.entries[offset:offset+capacity]
        keys = tuple(entry.key for entry in entries)
        guard()
        try:
            values = repository.inventory_snapshot(keys)
        except StoreUnavailable:
            raise InventoryHeld('inventory read-set snapshot unavailable') from None
        guard()
        if type(values) is not dict or set(values) != set(keys):
            raise InventoryHeld('exact complete inventory snapshot response required')
        for expected in entries:
            row = deepcopy(values[expected.key])
            if row is None or getattr(row, 'key', None) != expected.key or _entry(repository, row, expected.key.table) != expected:
                raise InventoryHeld('inventory snapshot source changed or missing')
            if isinstance(row, Row):
                size += _private_payload_size(row.data)
                if size > max_payload_bytes:
                    raise InventoryHeld('inventory private payload budget exhausted')
                private.append(row)
            else:
                markers.append(row)
    guard()
    following = collect(repository, limits=limits, deadline_ns=deadline_ns, checkpoint=guard, tick=read_tick)
    if (following.deployment, following.tables, following.entries, following.summary_sha256, following.summary_bytes) != (
            inventory.deployment, inventory.tables, inventory.entries, inventory.summary_sha256, inventory.summary_bytes):
        raise InventoryHeld('complete follow-up inventory changed')
    guard()
    return InventoryReadSet(inventory, tuple(private), tuple(markers), batches, size)
