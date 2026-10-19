"""Supplied owner-transfer history; no current access, retention or cleanup grant."""
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from decimal import Decimal
import hashlib
import json
import re

from proofpack.auth.service import HEAD, digest
from proofpack.evidence.inventory import _encoded, _private_payload_size
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode, InvalidResourceBindings, MissingResourceBindings
from proofpack.evidence.replay_lineage import discover as replay_discover, ReplayHistoryHeld
from proofpack.runtime.control import uuid

MAXIMUM = 2**63-1
POLICY = 'owner-transfer-history-v1'


class TransferHistoryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class TransferHistoryLimits:
    max_records: int
    max_payload_bytes: int
    max_dependencies: int
    max_work: int
    max_summary_bytes: int

    def __post_init__(self):
        if any(type(value) is not int or not 1 <= value <= MAXIMUM for value in (
                self.max_records, self.max_payload_bytes, self.max_dependencies, self.max_work, self.max_summary_bytes)):
            raise ValueError('independent explicit finite transfer history limits required')


@dataclass(frozen=True)
class TransferRecord:
    key: Key
    revision: int
    sha256: str


@dataclass(frozen=True)
class TransferDependency:
    key: Key
    revision: int
    sha256: str
    kind: str


@dataclass(frozen=True)
class TransferHistory:
    policy: str
    state: str
    transfer: TransferRecord = field(repr=False)
    records: tuple[TransferRecord, ...] = field(repr=False)
    dependencies: tuple[TransferDependency, ...] = field(repr=False)
    payload_bytes: int
    work: int
    summary_bytes: int
    summary_sha256: str
    historical: bool = True
    read_only: bool = True
    grants_current_access: bool = False
    can_confirm_cleanup: bool = False


def _hold():
    raise TransferHistoryHeld('intact complete supplied owner-transfer history required')


def _number(value, minimum=0):
    if (type(value) not in (int, Decimal) or type(value) is Decimal and
            (not value.is_finite() or value != value.to_integral_value()) or not minimum <= value <= MAXIMUM):
        _hold()
    return int(value)


def _sha(value):
    if type(value) is not str or re.fullmatch('[a-f0-9]{64}', value) is None: _hold()
    return value


def _body(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False))


def discover(transfer, rows, *, deployment, limits, deadline_ns, tick, checkpoint):
    """Validate supplied peers; complete inventory and authorization are external."""
    if (type(rows) is not tuple or type(limits) is not TransferHistoryLimits
            or type(deployment) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}', deployment) is None
            or type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM
            or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact bounded transfer inputs and original execution fence required')
    work = 0; last = -1
    def checked_tick():
        nonlocal last
        now = tick()
        if type(now) is not int or not 0 <= now < deadline_ns or now < last:
            raise TransferHistoryHeld('original transfer history deadline or clock invalid')
        last = now
    def check(cost=0):
        nonlocal work
        work += cost
        if work > limits.max_work: raise TransferHistoryHeld('transfer history work bound exhausted')
        checkpoint(); checked_tick(); checkpoint(); checked_tick()
    try:
        check()
        if len(rows)+1 > limits.max_records: raise TransferHistoryHeld('transfer history record bound exhausted')
        copies = {}; references = {}; payload_bytes = 0
        for row in (transfer, *rows):
            check(1)
            if (type(row) is not Row or type(row.key) is not Key or type(row.data) is not dict
                    or type(row.key.table) is not str or row.key.table not in {'state', 'events'}
                    or type(row.key.resource) is not str or not 1 <= len(row.key.resource) <= 256
                    or type(row.revision) is not int or not 1 <= row.revision <= MAXIMUM or row.key in copies): _hold()
            reference = TransferRecord(row.key, row.revision, _payload_sha256(row.data))
            payload_bytes += _private_payload_size(row.data)
            if payload_bytes > limits.max_payload_bytes: raise TransferHistoryHeld('transfer history payload bound exhausted')
            copies[row.key] = deepcopy(row); references[row.key] = reference
        root = copies[transfer.key]; data = root.data
        if set(data) != {'id', 'source_id', 'source_version', 'target_id', 'target_version', 'status', 'expires_at_ms'}: _hold()
        ident = uuid(data['id']); source = uuid(data['source_id']); target = uuid(data['target_id'])
        source_version = _number(data['source_version'], 1); target_version = _number(data['target_version'], 1)
        expires = _number(data['expires_at_ms'], 1); accepted = data['status']=='accepted'
        if (root.key != Key('state', 'owner-transfer#'+ident) or source==target
                or data['status'] not in {'pending', 'accepted'} or root.revision != (2 if accepted else 1)): _hold()
        initial_sha = _payload_sha256({**data, 'status':'pending'})
        source_key = Key('state', 'user#'+source); target_key = Key('state', 'user#'+target)
        groups = {}
        for original in rows:
            check(1); row = copies[original.key]; binding = decode(row, deployment=deployment)
            if binding.operation not in {'begin-transfer', 'accept-transfer'}: _hold()
            token = hashlib.sha256(_encoded(asdict(binding))).hexdigest()
            if token not in groups: groups[token] = (binding, [], [])
            prior, events, replays = groups[token]
            if prior != binding: _hold()
            if row.key.table=='events' and re.fullmatch('access#[a-f0-9-]{36}', row.key.resource):
                uuid(row.key.resource.split('#')[1]); events.append(row)
            elif row.key.table=='state' and re.fullmatch('idempotency#[a-f0-9]{64}', row.key.resource): replays.append(row)
            else: _hold()
        dependencies = set(); begin_times = []; accept_times = []
        for binding, events, replays in groups.values():
            check(1)
            if len(events)!=1 or len(replays)!=1: _hold()
            event, replay = events[0], replays[0]
            replay_discover(replay, (event,), deployment=deployment,
                max_records=limits.max_records, max_payload_bytes=limits.max_payload_bytes)
            check()
            value = event.data
            if set(value) != {'kind', 'actor_scope', 'session_id', 'at_ms', 'resource_bindings'}: _hold()
            _sha(value['actor_scope']); session = uuid(value['session_id'])
            at = _number(value['at_ms']); replay_at = _number(replay.data['at_ms'])
            writes = {ref.key:ref for ref in binding.writes}; checked = {ref.key:ref for ref in binding.checks}
            cookies = [key for key in checked if key.table=='state' and re.fullmatch('cookie#[a-f0-9]{64}', key.resource)]
            if len(cookies)!=1: _hold()
            authority = {HEAD, source_key, target_key, Key('state', 'session#'+session), cookies[0]}
            result = replay.data['result']
            if binding.operation=='begin-transfer':
                if (set(writes)!={root.key} or set(checked)!=authority or at>=expires or expires>at+600000
                        or set(result)!={'id','expires_at_ms'} or result['id']!=ident or _number(result['expires_at_ms'],1)!=expires
                        or replay.data['body_hash'] != _body({'target_id':target, 'target_version':target_version})
                        or writes[root.key].previous_revision is not None or writes[root.key].revision!=1
                        or writes[root.key].sha256!=initial_sha): _hold()
                begin_times.append((at, replay_at))
            else:
                if (not accepted or set(writes)!={HEAD, root.key, source_key, target_key}
                        or set(checked)!=authority|{root.key} or at>=expires
                        or set(result)!={'owner_id','sign_in_required'} or result['owner_id']!=target
                        or result['sign_in_required'] is not True or replay.data['body_hash']!=_body({'id':ident})
                        or checked[root.key].revision!=1 or checked[root.key].sha256!=initial_sha
                        or writes[root.key].previous_revision!=1 or writes[root.key].revision!=2
                        or writes[root.key].sha256!=references[root.key].sha256): _hold()
                for key in (HEAD, source_key, target_key):
                    check(1)
                    if writes[key].previous_revision!=checked[key].revision: _hold()
                accept_times.append((at, replay_at))
            for kind, refs in (('write', binding.writes), ('check', binding.checks)):
                for ref in refs:
                    check(1)
                    if ref.key==root.key: continue
                    dependencies.add(TransferDependency(ref.key, ref.revision, ref.sha256, kind))
                    if len(dependencies)>limits.max_dependencies:
                        raise TransferHistoryHeld('transfer history dependency bound exhausted')
        if len(begin_times)!=1 or len(accept_times)!=(1 if accepted else 0): _hold()
        if accepted and accept_times[0][0]<begin_times[0][1]: _hold()
        records = tuple(references[key] for key in sorted(references, key=lambda key:(key.table,key.resource)))
        deps = tuple(sorted(dependencies, key=lambda ref:(ref.key.table, ref.key.resource, ref.revision, ref.sha256, ref.kind)))
        state = 'ACCEPTED_HISTORY' if accepted else 'PENDING_HISTORY'
        check(len(records)+len(deps))
        summary = _encoded({'policy':POLICY, 'deployment':deployment, 'state':state,
            'records':[asdict(ref) for ref in records], 'dependencies':[asdict(ref) for ref in deps]})
        if len(summary)>limits.max_summary_bytes: raise TransferHistoryHeld('transfer history summary bound exhausted')
        summary_sha256 = hashlib.sha256(summary).hexdigest()
        check(len(records))
        # Recheck caller-owned mutable inputs after the final authority callback.
        for original in (transfer, *rows):
            if (original.key not in references or original.revision!=references[original.key].revision
                    or _payload_sha256(original.data)!=references[original.key].sha256): _hold()
        checked_tick()
        return TransferHistory(POLICY,state,references[root.key],records,deps,payload_bytes,work,
            len(summary),summary_sha256)
    except (ReplayHistoryHeld, InvalidResourceBindings, MissingResourceBindings, ValueError, TypeError,
            KeyError, AttributeError, ArithmeticError, RecursionError):
        raise TransferHistoryHeld('intact complete supported transfer history unavailable') from None
