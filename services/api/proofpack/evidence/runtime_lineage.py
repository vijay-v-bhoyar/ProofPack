"""Private startup provenance only; no ownership, retention or cleanup authority."""
from dataclasses import asdict, dataclass, field
from decimal import Decimal
import hashlib
import json
import re
from uuid import UUID

from proofpack.auth.service import RUNTIME
from proofpack.runtime.control import ALLOCATION, DATA
from proofpack.runtime.startup_schema import restore_startup, valid_data_write
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode, InvalidResourceBindings, MissingResourceBindings

MAXIMUM = 2**63-1
POLICY = 'runtime-startup-provenance-v1'


class RuntimeLineageHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeLineageLimits:
    max_records: int
    max_payload_bytes: int
    max_work: int
    max_summary_bytes: int

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (
                self.max_records, self.max_payload_bytes, self.max_work, self.max_summary_bytes)):
            raise ValueError('explicit finite runtime lineage limits required')


@dataclass(frozen=True)
class RuntimeRecord:
    key: Key
    revision: int
    sha256: str


@dataclass(frozen=True)
class RuntimeStartup:
    policy: str
    records: tuple[RuntimeRecord, ...] = field(repr=False)
    instance_id: str = field(repr=False)
    runtime_epoch: int
    artifact_sha256: str
    controls_sha256: str
    started_at_ms: int
    event_at_ms: int
    summary_sha256: str
    summary_bytes: int
    payload_bytes: int
    work: int
    read_only: bool = True
    can_confirm_cleanup: bool = False


def _hold():
    raise RuntimeLineageHeld('intact original supported runtime startup snapshots required')


def _integer(value, *, minimum=0):
    if (type(value) not in (int, Decimal)
            or type(value) is Decimal and (not value.is_finite() or value != value.to_integral_value())
            or not minimum <= value <= MAXIMUM):
        _hold()
    return int(value)


def _number(value):
    if type(value) is Decimal:
        return _integer(value)
    _hold()


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False, default=_number).encode()


def discover(event, marker, startup_runtime, *, deployment, now_ms, limits,
             deadline_ns, tick, checkpoint, created_allocation=None, created_data=None):
    """Validate original writer snapshots; callers must establish inventory/scope bindings.

    Checked historical heads are deliberately not returned as current payload evidence.
    A missing original written snapshot never becomes a reconstructed timestamp.
    """
    if (type(limits) is not RuntimeLineageLimits or type(deadline_ns) is not int
            or not 1 <= deadline_ns <= MAXIMUM or not callable(tick) or not callable(checkpoint)):
        raise ValueError('explicit original runtime lineage execution bounds required')
    now_ms = _integer(now_ms)
    work = 0
    last = -1

    def check(cost=0):
        nonlocal work, last
        work += cost
        if work > limits.max_work:
            raise RuntimeLineageHeld('runtime lineage work bound exhausted')
        checkpoint()
        current = tick()
        if type(current) is not int or not 0 <= current < deadline_ns or current < last:
            raise RuntimeLineageHeld('original runtime lineage deadline or clock invalid')
        last = current
        checkpoint()

    check()
    rows = (event, marker, startup_runtime) + (() if created_allocation is None else (created_allocation,)) + (
        () if created_data is None else (created_data,))
    if len(rows) > limits.max_records:
        raise RuntimeLineageHeld('runtime lineage record bound exhausted')
    references = {}
    payload_bytes = 0
    try:
        for row in rows:
            check(1)
            if type(row) is not Row or type(row.key) is not Key or type(row.data) is not dict:
                _hold()
            if (type(row.key.table) is not str or row.key.table not in {'state', 'events'}
                    or type(row.key.resource) is not str or not 1 <= len(row.key.resource) <= 256
                    or row.key in references or type(row.revision) is not int or not 1 <= row.revision <= MAXIMUM):
                _hold()
            payload_bytes += len(_encoded(row.data))
            if payload_bytes > limits.max_payload_bytes:
                raise RuntimeLineageHeld('runtime lineage payload bound exhausted')
            references[row.key] = RuntimeRecord(row.key, row.revision, _payload_sha256(row.data))
        data = event.data
        if set(data) != {'kind', 'instance_id', 'runtime_epoch', 'control_version', 'at_ms', 'resource_bindings'}:
            _hold()
        instance = data['instance_id']
        if type(instance) is not str or str(UUID(instance)) != instance:
            _hold()
        if (data['kind'] != 'runtime_started' or event.key.table != 'events'
                or not event.key.resource.startswith('runtime#')
                or str(UUID(event.key.resource[len('runtime#'):])) != event.key.resource[len('runtime#'):]
                or event.revision != 1):
            _hold()
        epoch = _integer(data['runtime_epoch'], minimum=1)
        control = _integer(data['control_version'], minimum=1)
        event_time = _integer(data['at_ms'])
        if event_time > now_ms:
            _hold()
        startup=restore_startup(marker.data)
        if (marker.key != Key('state', 'runtime-start#' + instance) or marker.revision != 1
                or _integer(marker.data['runtime_epoch'], minimum=1) != epoch
                or type(marker.data['environment']) is not str
                or marker.data['environment'] not in {'test', 'synthetic_demo', 'beta'}):
            _hold()
        for name in ('artifact_sha256', 'controls_sha256'):
            if type(marker.data[name]) is not str or re.fullmatch('[a-f0-9]{64}', marker.data[name]) is None:
                _hold()
        state = startup_runtime.data
        if (startup_runtime.key != RUNTIME or set(state) != {'runtime_epoch', 'control_version',
                'inspection_enabled', 'instance_id', 'artifact_sha256', 'controls_sha256', 'started_at_ms',
                'environment', 'enable_receipt_id', 'enable_expires_at_ms', 'reason'}
                or state['instance_id'] != instance or _integer(state['runtime_epoch'], minimum=1) != epoch
                or _integer(state['control_version'], minimum=1) != control
                or state['inspection_enabled'] is not False or state['enable_receipt_id'] is not None
                or state['enable_expires_at_ms'] is not None or state['reason'] != 'runtime_started'
                or any(state[name] != marker.data[name] for name in ('artifact_sha256', 'controls_sha256', 'environment'))):
            _hold()
        started = _integer(state['started_at_ms'])
        if started > event_time:
            _hold()
        envelope = decode(event, deployment=deployment)
        writes = {ref.key: ref for ref in envelope.writes}
        checks = {ref.key: ref for ref in envelope.checks}
        if (envelope.operation != 'runtime_started' or not {RUNTIME, marker.key} <= writes.keys()
                or not writes.keys() <= {RUNTIME, marker.key, ALLOCATION, DATA}
                or not checks.keys() <= {ALLOCATION, DATA} or writes.keys() & checks.keys()):
            _hold()
        for key in (ALLOCATION, DATA):
            if (key in writes) == (key in checks):
                _hold()
        if startup is not None and DATA not in writes:
            _hold()
        if set(references) != set(writes) | {event.key}:
            _hold()
        for key, ref in writes.items():
            check(1)
            actual = references[key]
            if (actual.revision != ref.revision or actual.sha256 != ref.sha256
                    or key==DATA and not valid_data_write(startup,ref.previous_revision,ref.revision)
                    or key not in (RUNTIME,DATA) and (ref.previous_revision is not None or ref.revision != 1)):
                _hold()
        if created_allocation is not None and (created_allocation.key != ALLOCATION
                or set(created_allocation.data) != {'slots'} or type(created_allocation.data['slots']) is not dict
                or created_allocation.data['slots']):
            _hold()
        if created_data is not None and (created_data.key != DATA
                or set(created_data.data) != {'epoch', 'changed_at_ms'}
                or _integer(created_data.data['epoch'], minimum=1) != (1 if startup is None else startup[2])
                or not event_time <= _integer(created_data.data['changed_at_ms']) <= now_ms):
            _hold()
        ordered = tuple(references[key] for key in sorted(references, key=lambda key: (key.table, key.resource)))
        summary = _encoded({'policy': POLICY, 'deployment': deployment, 'records': [asdict(ref) for ref in ordered]})
        if len(summary) > limits.max_summary_bytes:
            raise RuntimeLineageHeld('runtime lineage summary bound exhausted')
        check()
        return RuntimeStartup(POLICY, ordered, instance, epoch, marker.data['artifact_sha256'],
            marker.data['controls_sha256'], started, event_time, hashlib.sha256(summary).hexdigest(),
            len(summary), payload_bytes, work)
    except (ValueError, TypeError, KeyError, AttributeError, ArithmeticError,
            InvalidResourceBindings, MissingResourceBindings):
        _hold()
