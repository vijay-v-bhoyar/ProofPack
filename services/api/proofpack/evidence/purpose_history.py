"""Operational purpose writer history, without rights or inspection ownership."""
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from decimal import Decimal
import hashlib
import json
import re

from proofpack.auth.service import HEAD, RUNTIME, digest
from proofpack.runtime.control import DATA, uuid
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.inventory import _encoded, _private_payload_size
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode, InvalidResourceBindings, MissingResourceBindings
from proofpack.evidence.replay_lineage import discover as replay_discover, ReplayHistoryHeld
from proofpack.evidence.originals import ORIGINAL_NOTICE_VERSION, ORIGINAL_NOTICE_SHA256, ORIGINAL_NOTICE_TEXT

MAXIMUM = 2**63-1
POLICY = 'purpose-history-v1'
BASE = frozenset('id allowed_uses withdrawn expires_at_ms source_permission_reference notice_version notice_sha256 authority_basis rights_independently_verified owner_user_id owner_access_version created_at_ms optional_improvement optional_publicity'.split())
ORIGINAL = frozenset('original_capture_retention_allowed original_capture_notice_version original_capture_notice_sha256 original_capture_notice_text'.split())


class PurposeHistoryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class PurposeHistoryLimits:
    max_records: int
    max_payload_bytes: int
    max_dependencies: int
    max_work: int
    max_summary_bytes: int

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (
                self.max_records, self.max_payload_bytes, self.max_dependencies, self.max_work, self.max_summary_bytes)):
            raise ValueError('independent explicit finite purpose history limits required')


@dataclass(frozen=True)
class PurposeRecord:
    key: Key
    revision: int
    sha256: str


@dataclass(frozen=True)
class PurposeDependency:
    key: Key
    revision: int
    sha256: str
    kind: str


@dataclass(frozen=True)
class PurposeHistory:
    policy: str
    state: str
    purpose: PurposeRecord = field(repr=False)
    records: tuple[PurposeRecord, ...] = field(repr=False)
    dependencies: tuple[PurposeDependency, ...] = field(repr=False)
    payload_bytes: int
    work: int
    summary_bytes: int
    summary_sha256: str
    historical: bool = True
    rights_independently_verified: bool = False
    can_confirm_cleanup: bool = False


def _hold():
    raise PurposeHistoryHeld('intact complete supported purpose history required')


def _n(value, *, minimum=0, maximum=MAXIMUM):
    if (type(value) not in (int, Decimal)
            or type(value) is Decimal and (not value.is_finite() or value != value.to_integral_value())
            or not minimum <= value <= maximum):
        _hold()
    return int(value)


def _sha(value):
    if type(value) is not str or re.fullmatch('[a-f0-9]{64}', value) is None: _hold()
    return value


def _body_digest(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False))


def discover(purpose, rows, *, deployment, limits, deadline_ns, tick, checkpoint):
    """Validate explicitly supplied history; full inventory and authority are external."""
    if (type(rows) is not tuple or type(limits) is not PurposeHistoryLimits
            or type(deployment) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}',deployment) is None
            or type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM
            or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact bounded purpose history inputs and original execution fence required')
    work = 0; last = -1
    def check(cost=0):
        nonlocal work, last
        work += cost
        if work > limits.max_work: raise PurposeHistoryHeld('purpose history work bound exhausted')
        checkpoint(); current = tick()
        if type(current) is not int or not 0 <= current < deadline_ns or current < last:
            raise PurposeHistoryHeld('original purpose history deadline or clock invalid')
        last = current; checkpoint()
    try:
        check()
        if len(rows)+1 > limits.max_records: raise PurposeHistoryHeld('purpose history record bound exhausted')
        copies = {}; payload_bytes = 0; references = {}
        for row in (purpose,*rows):
            check(1)
            if (type(row) is not Row or type(row.key) is not Key or type(row.data) is not dict
                    or type(row.key.table) is not str or row.key.table not in {'state','events'}
                    or type(row.key.resource) is not str or not 1 <= len(row.key.resource) <= 256
                    or type(row.revision) is not int or not 1 <= row.revision <= MAXIMUM or row.key in copies): _hold()
            digest_value = _payload_sha256(row.data); payload_bytes += _private_payload_size(row.data)
            if payload_bytes > limits.max_payload_bytes: raise PurposeHistoryHeld('purpose history payload bound exhausted')
            copies[row.key] = deepcopy(row); references[row.key] = PurposeRecord(row.key,row.revision,digest_value)
        root = copies[purpose.key]; data = root.data; ident = uuid(data['id']); owner = uuid(data['owner_user_id'])
        withdrawn = data['withdrawn']; has_original = bool(set(data)&ORIGINAL)
        expected = BASE | (ORIGINAL if has_original else frozenset()) | ({'withdrawn_at_ms'} if withdrawn is True else set())
        if (root.key != Key('state','purpose#'+ident) or set(data) != expected or type(withdrawn) is not bool
                or root.revision != (2 if withdrawn else 1) or data['allowed_uses'] != ['operation']
                or type(data['allowed_uses']) is not list or data['authority_basis'] != 'owner_attestation'
                or any(data[name] is not False for name in ('rights_independently_verified','optional_improvement','optional_publicity'))): _hold()
        _n(data['owner_access_version'],minimum=1)
        created = _n(data['created_at_ms']); expires = _n(data['expires_at_ms'],minimum=1,maximum=9007199254740991)
        if not created < expires <= created+31536000000: _hold()
        if (type(data['source_permission_reference']) is not str
                or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,63}',data['source_permission_reference']) is None
                or type(data['notice_version']) is not str or not 1 <= len(data['notice_version']) <= 128): _hold()
        _sha(data['notice_sha256'])
        if has_original and (data['original_capture_retention_allowed'] is not True
                or data['original_capture_notice_version'] != ORIGINAL_NOTICE_VERSION
                or data['original_capture_notice_sha256'] != ORIGINAL_NOTICE_SHA256
                or data['original_capture_notice_text'] != ORIGINAL_NOTICE_TEXT): _hold()
        withdrawn_at = _n(data['withdrawn_at_ms']) if withdrawn else None
        if withdrawn and withdrawn_at < created: _hold()
        initial = {k:v for k,v in data.items() if k != 'withdrawn_at_ms'} | {'withdrawn':False}
        initial_sha = _payload_sha256(initial)
        create_body = {k:data[k] for k in ('notice_version','notice_sha256','source_permission_reference')}
        create_body.update(operational_use_acknowledged=True,expires_at_ms=expires)
        if has_original: create_body.update(original_capture_retention_acknowledged=True,original_capture_notice_sha256=ORIGINAL_NOTICE_SHA256)
        groups = {}
        for original in rows:
            check(1); row = copies[original.key]
            binding = decode(row,deployment=deployment)
            if binding.operation not in {'purpose-create','purpose-withdraw'}: _hold()
            token = hashlib.sha256(_encoded(asdict(binding))).hexdigest()
            if token not in groups: groups[token] = (binding,[],[])
            prior,events,replays = groups[token]
            if binding != prior: _hold()
            if row.key.table == 'events' and re.fullmatch('access#[a-f0-9-]{36}',row.key.resource):
                uuid(row.key.resource.split('#')[1]); events.append(row)
            elif row.key.table == 'state' and re.fullmatch('idempotency#[a-f0-9]{64}',row.key.resource): replays.append(row)
            else: _hold()
        dependencies = set(); creation_times = []; withdrawal_times = []; noop_times = []
        for binding,events,replays in groups.values():
            check(1)
            if len(events) != 1 or len(replays) != 1: _hold()
            event,replay = events[0],replays[0]
            replay_discover(replay,(event,),deployment=deployment,max_records=limits.max_records,
                            max_payload_bytes=limits.max_payload_bytes)
            check()
            e = event.data; access_time = _n(e['at_ms']); replay_time = _n(replay.data['at_ms'])
            if set(e) != {'kind','actor_scope','session_id','at_ms','details','resource_bindings'}: _hold()
            _sha(e['actor_scope']); session = uuid(e['session_id'])
            if type(e['details']) is not dict or replay.data['result'] != {'id':ident} or set(replay.data['result']) != {'id'}: _hold()
            writes = {ref.key:ref for ref in binding.writes}; checks = {ref.key:ref for ref in binding.checks}
            users = [k for k in checks if k.table=='state' and k.resource.startswith('user#')]
            cookies = [k for k in checks if k.table=='state' and re.fullmatch('cookie#[a-f0-9]{64}',k.resource)]
            if len(users)!=1 or len(cookies)!=1: _hold()
            uuid(users[0].resource[len('user#'):])
            authority = {HEAD,Key('state','session#'+session),users[0],cookies[0]}
            if binding.operation == 'purpose-create':
                if (e['details'] != {'purpose_id':ident,'notice_sha256':data['notice_sha256']}
                        or users[0] != Key('state','user#'+owner) or set(writes) != {root.key,DATA}
                        or set(checks) != authority|{RUNTIME,DATA} or access_time < created
                        or replay.data['body_hash'] != _body_digest(create_body)):_hold()
                written = writes[root.key]
                if written.previous_revision is not None or written.revision != 1 or written.sha256 != initial_sha: _hold()
                creation_times.append((access_time,replay_time))
            elif e['details'] == {'purpose_id':ident}:
                if (not withdrawn or set(writes) != {root.key,DATA} or set(checks) != authority|{root.key,DATA}
                        or writes[root.key].previous_revision != 1 or writes[root.key].revision != 2
                        or writes[root.key].sha256 != references[root.key].sha256
                        or checks[root.key].revision != 1 or checks[root.key].sha256 != initial_sha
                        or access_time < withdrawn_at
                        or replay.data['body_hash'] != _body_digest({'id':ident,'expected_version':1})): _hold()
                withdrawal_times.append((access_time,replay_time))
            elif set(e['details'])=={'purpose_id','already_withdrawn'} and e['details']['purpose_id']==ident and e['details']['already_withdrawn'] is True:
                if (not withdrawn or writes or set(checks) != authority|{root.key}
                        or checks[root.key].revision != 2 or checks[root.key].sha256 != references[root.key].sha256
                        or access_time < withdrawn_at
                        or replay.data['body_hash'] != _body_digest({'id':ident,'expected_version':2})): _hold()
                noop_times.append((access_time,replay_time))
            else: _hold()
            if DATA in writes:
                if DATA not in checks or writes[DATA].previous_revision != checks[DATA].revision: _hold()
            for kind,refs in (('write',binding.writes),('check',binding.checks)):
                for ref in refs:
                    check(1)
                    if ref.key == root.key: continue
                    dependencies.add(PurposeDependency(ref.key,ref.revision,ref.sha256,kind))
                    if len(dependencies)>limits.max_dependencies: raise PurposeHistoryHeld('purpose history dependency bound exhausted')
        if len(creation_times)!=1 or len(withdrawal_times)!=(1 if withdrawn else 0): _hold()
        if withdrawn and creation_times[0][1] > withdrawn_at: _hold()
        if any(start < withdrawal_times[0][1] for start,_ in noop_times): _hold()
        records = tuple(references[k] for k in sorted(references,key=lambda k:(k.table,k.resource)))
        deps = tuple(sorted(dependencies,key=lambda r:(r.key.table,r.key.resource,r.revision,r.sha256,r.kind)))
        state = 'WITHDRAWN_HISTORY' if withdrawn else 'ACTIVE_HISTORY'
        check(len(records)+len(deps))
        summary = _encoded({'policy':POLICY,'deployment':deployment,'state':state,
            'records':[asdict(r) for r in records],'dependencies':[asdict(r) for r in deps]})
        if len(summary)>limits.max_summary_bytes: raise PurposeHistoryHeld('purpose history summary bound exhausted')
        check()
        return PurposeHistory(POLICY,state,references[root.key],records,deps,payload_bytes,work,len(summary),hashlib.sha256(summary).hexdigest())
    except (ReplayHistoryHeld,InvalidResourceBindings,MissingResourceBindings,ValueError,TypeError,KeyError,AttributeError,ArithmeticError,RecursionError):
        raise PurposeHistoryHeld('intact complete supported purpose history unavailable') from None
