"""Private complete metadata-request provenance; never retention or cleanup authority."""
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
import re

from proofpack.auth.service import HEAD, digest
from proofpack.evidence.auth_history import validate as validate_auth
from proofpack.evidence.inspection_scope import inspection_scope, scope_sha256 as scope_digest
from proofpack.evidence.inspection_corpus import CorpusReference
from proofpack.evidence.inventory import InventoryPass, _encoded, _private_payload_size
from proofpack.evidence.metadata_request_contract import validate_request
from proofpack.evidence.privacy_admission import DrainProof, AdmissionHeld, GATE, REGISTRY
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode
from proofpack.runtime.control import DATA, RUNTIME, integer, uuid, sha

MAXIMUM = 2**63 - 1
POLICY = 'held-metadata-request-history-v1'
REVIEW_POLICY = 'METADATA_RETENTION_POLICY_REQUIRED'
OPERATIONS = frozenset(('owner-metadata-create', 'owner-metadata-cancel'))
FAMILIES = frozenset(('metadata-request', 'metadata-operation', 'metadata-event', 'metadata-quota'))


class MetadataHistoryHeld(RuntimeError): pass


@dataclass(frozen=True)
class MetadataHistoryLimits:
    max_records: int
    max_payload_bytes: int
    max_dependencies: int
    max_work: int
    max_summary_bytes: int
    max_inspections: int
    writes_per_minute: int

    def __post_init__(self):
        if (any(type(v) is not int or not 1 <= v <= MAXIMUM for v in asdict(self).values())
                or self.max_inspections > 64 or self.writes_per_minute > 100):
            raise ValueError('independent finite metadata history and original writer limits required')


@dataclass(frozen=True)
class MetadataRecord:
    reference: CorpusReference = field(repr=False)
    family: str
    inspection_ids: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True)
class MetadataHistory:
    policy: str
    inventory_sha256: str
    proof_sha256: str
    scope_sha256: str
    configuration_sha256: str
    auth_history_sha256: str
    requested_inspections: tuple[str, ...] = field(repr=False)
    records: tuple[MetadataRecord, ...] = field(repr=False)
    source_records: int
    payload_bytes: int
    dependencies: int
    historical_dependencies_unavailable: int
    work: int
    summary_bytes: int
    summary_sha256: str
    historical_authority_proven: bool = False
    policy_resolved: bool = False
    read_only: bool = True
    can_confirm_cleanup: bool = False
    request_fulfilled: bool = False


def _hold():
    raise MetadataHistoryHeld('complete metadata request history and unresolved retention obligations required')


def _projection(value):
    return {k: v for k, v in asdict(value).items() if k not in {'summary_bytes', 'summary_sha256'}}


def validate(value, inventory, proof, auth_history, *, scope_sha256, requested_inspections, checkpoint):
    if type(value) is not MetadataHistory: _hold()
    original_size, original_digest = value.summary_bytes, value.summary_sha256
    checkpoint()
    validate_auth(auth_history, inventory, proof, scope_sha256=scope_sha256,
                  requested_inspections=requested_inspections, checkpoint=checkpoint)
    if (type(value) is not MetadataHistory or value.policy != POLICY
            or value.inventory_sha256 != inventory.summary_sha256
            or value.proof_sha256 != hashlib.sha256(_encoded(asdict(proof))).hexdigest()
            or value.scope_sha256 != scope_sha256 or value.requested_inspections != requested_inspections
            or value.auth_history_sha256 != auth_history.summary_sha256
            or value.historical_authority_proven is not False or value.policy_resolved is not False
            or value.read_only is not True or value.can_confirm_cleanup is not False or value.request_fulfilled is not False
            or type(value.records) is not tuple or len(value.records) > len(inventory.entries)
            or type(value.source_records) is not int or value.source_records != len(inventory.entries)
            or any(type(v) is not int or not 0 <= v <= MAXIMUM for v in (value.dependencies, value.historical_dependencies_unavailable))
            or any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (value.payload_bytes, value.work, value.summary_bytes))):
        _hold()
    if type(value.configuration_sha256) is not str: _hold()
    sha(value.configuration_sha256)
    index = {e.key: e for e in inventory.entries}; previous = None
    coverage=set(); counts={family:0 for family in FAMILIES}; operations_expected=0
    for record in value.records:
        checkpoint()
        if type(record) is not MetadataRecord or record.family not in FAMILIES: _hold()
        r = record.reference
        if type(r) is not CorpusReference or type(r.key) is not Key: _hold()
        entry = index.get(r.key); order = (r.key.table, r.key.resource)
        if (entry is None or entry.kind != 'live' or r.kind != 'live' or r.revision != entry.revision
                or r.sha256 != entry.payload_sha256 or r.marker_resource_sha256 is not None
                or previous is not None and order <= previous
                or type(record.inspection_ids) is not tuple): _hold()
        previous = order
        coverage.add(r.key);counts[record.family]+=1
        if record.family == 'metadata-request':
            if (r.key.table!='state' or not r.key.resource.startswith('metadata-request#') or r.revision not in (1,2)
                    or not record.inspection_ids or any(type(i) is not str for i in record.inspection_ids)
                    or tuple(sorted(set(record.inspection_ids))) != record.inspection_ids): _hold()
            uuid(r.key.resource.split('#',1)[1]);operations_expected+=r.revision
            for ident in record.inspection_ids: uuid(ident)
        else:
            if record.inspection_ids: _hold()  # Causality does not copy inspection content.
            prefix={'metadata-operation':('state','idempotency#[a-f0-9]{64}'),
                    'metadata-event':('events','access#[a-f0-9-]{36}'),
                    'metadata-quota':('state','metadata-owner-quota#[a-f0-9]{64}')}[record.family]
            if r.key.table!=prefix[0] or re.fullmatch(prefix[1],r.key.resource) is None: _hold()
            if record.family=='metadata-event':uuid(r.key.resource.split('#',1)[1])
    required={k for k in index if k.table=='state' and k.resource.startswith(('metadata-request#','metadata-owner-quota#'))}
    if (not required <= coverage or counts['metadata-operation']!=operations_expected
            or counts['metadata-event']!=operations_expected or not 1<=counts['metadata-quota']<=operations_expected): _hold()
    checkpoint()
    # Encode after the final external callback, against the original expected
    # digest/length; a callback cannot persistently replace result fields.
    payload = _encoded(_projection(value))
    if (value.summary_bytes!=original_size or value.summary_sha256!=original_digest
            or len(payload)!=original_size or hashlib.sha256(payload).hexdigest()!=original_digest): _hold()
    return value


def derive(rows, inventory, proof, auth_history, *, configuration_sha256, requested_inspections,
           scope_sha256, now_ms, limits, deadline_ns, tick, checkpoint):
    if (type(rows) is not tuple or type(inventory) is not InventoryPass or type(proof) is not DrainProof
            or type(limits) is not MetadataHistoryLimits or type(deadline_ns) is not int
            or not 1 <= deadline_ns <= MAXIMUM or not callable(tick) or not callable(checkpoint)):
        raise ValueError('original complete held inventory, metadata limits and lifetime required')
    frozen_limits = asdict(limits); work = 0; last = -1
    def clock():
        nonlocal last
        current = tick()
        if type(current) is not int or not 0 <= last <= current < deadline_ns: _hold()
        last = current
    last = 0
    def check(cost=0):
        nonlocal work
        if asdict(limits) != frozen_limits: _hold()
        work += cost
        if work > frozen_limits['max_work']: raise MetadataHistoryHeld('metadata history work exhausted')
        checkpoint(); clock(); checkpoint(); clock()
    try:
        check(); sha(configuration_sha256)
        if type(configuration_sha256) is not str or type(now_ms) is not int or not 0 <= now_ms <= MAXIMUM: _hold()
        typed = inspection_scope(inventory.deployment, requested_inspections, max_inspections=limits.max_inspections)
        if scope_digest(typed) != scope_sha256: _hold()
        validate_auth(auth_history, inventory, proof, scope_sha256=scope_sha256,
                      requested_inspections=requested_inspections, checkpoint=check)
        if len(rows) != len(inventory.entries) or len(rows) > limits.max_records: _hold()
        expected = {e.key: e for e in inventory.entries}
        if len(expected) != len(rows): _hold()
        raw = {}; original = {}; payload_bytes = 0
        for row in rows:
            check(1)
            if type(row) not in (Row, ErasureMarker) or type(row.key) is not Key or row.key in raw: _hold()
            e = expected.get(row.key)
            if e is None or type(row.revision) is not int or row.revision != e.revision: _hold()
            if type(row) is Row:
                if type(row.data) is not dict or e.kind != 'live' or _payload_sha256(row.data) != e.payload_sha256: _hold()
                payload_bytes += _private_payload_size(row.data)
            elif e.kind != 'erased' or row.reference_sha256 != e.reference_sha256 or row.resource_sha256 != e.resource_sha256: _hold()
            if payload_bytes > limits.max_payload_bytes: raise MetadataHistoryHeld('metadata history payload exhausted')
            raw[row.key] = deepcopy(row); original[row.key] = row
        records = {}; events = {}; operations = {}; quotas = {}; roots = []
        dependencies = 0; unavailable = 0; quota_steps = {}
        def live(key):
            check(1); row = raw.get(key)
            if type(row) is not Row: _hold()
            return row
        def add(row, family, ids=()):
            check(1)
            if row.key in records: _hold()
            records[row.key] = MetadataRecord(CorpusReference(row.key,row.revision,'live',_payload_sha256(row.data)),family,ids)
        for key, row in raw.items():
            check(1)
            if key.table == 'state' and key.resource.startswith('metadata-request#'):
                roots.append(live(key))
            if key.table == 'state' and key.resource.startswith('metadata-owner-quota#'):
                if re.fullmatch('metadata-owner-quota#[a-f0-9]{64}', key.resource) is None: _hold()
                quota = live(key)
                if (set(quota.data) != {'minute','count'} or integer(quota.data['minute']) > now_ms//60000
                        or not 1 <= integer(quota.data['count']) <= limits.writes_per_minute): _hold()
                quotas[key] = quota
            if type(row) is not Row: continue
            declared = row.data.get('resource_bindings',{}).get('operation') if type(row.data.get('resource_bindings',{})) is dict else None
            kind = row.data.get('kind')
            if (type(declared) is str and declared.startswith('owner-metadata-')
                    or type(kind) is str and kind.startswith('owner-metadata-')):
                binding = decode(row,deployment=inventory.deployment)
                if binding.operation not in OPERATIONS: _hold()
                if key.table == 'events':
                    if (re.fullmatch('access#[a-f0-9-]{36}',key.resource) is None
                            or row.revision != 1 or set(row.data) != {'kind','actor_scope','at_ms','session_id','resource_bindings'}
                            or kind != binding.operation): _hold()
                    uuid(key.resource.split('#',1)[1])
                    token = _payload_sha256(row.data['resource_bindings'])
                    events.setdefault(token,[]).append((row,binding))
                elif key.table == 'state' and re.fullmatch('idempotency#[a-f0-9]{64}',key.resource):
                    if row.revision != 1 or set(row.data) != {'body_hash','result','at_ms','resource_bindings'}: _hold()
                    sha(row.data['body_hash']); operations[key] = (row,binding)
                else: _hold()
        used_events=set();used_operations=set()
        def snapshot(keys): return {key:live(key) for key in keys}
        auth_keys={r.reference.key for r in auth_history.records}
        active=live(Key('state','metadata-request#'+uuid(proof.request_id)))
        gate=live(GATE)
        if (active.data.get('status')!='held' or active.data.get('scope_sha256')!=scope_sha256
                or proof.scope_sha256!=scope_sha256 or gate.data.get('request_id')!=proof.request_id
                or gate.data.get('scope_sha256')!=scope_sha256 or gate.data.get('phase')!='HELD'): _hold()
        for root in roots:
            check(1)
            value, peers = validate_request(root,deployment=inventory.deployment,
                configuration_sha256=configuration_sha256,max_inspections=limits.max_inspections,
                now=lambda:now_ms,snapshot=snapshot)
            ids=tuple(value['scope']['inspection_ids'])
            for ident in ids:
                inspection=live(Key('state','inspection#'+ident))
                if inspection.data.get('id') != ident: _hold()
            add(root,'metadata-request',ids)
            for number, operation in enumerate(peers):
                check(1)
                if operation.key in used_operations or operation.key not in operations: _hold()
                op,binding=operations[operation.key]
                token=_payload_sha256(op.data['resource_bindings']); matches=events.get(token,())
                if len(matches) != 1: _hold()
                event,event_binding=matches[0]
                if event.key in used_events or event_binding != binding: _hold()
                at=integer(event.data['at_ms']); replay_at=integer(op.data['at_ms'])
                base=integer(value['created_at_ms'] if number==0 else value['cancelled_at_ms'])
                if not base <= at <= replay_at <= now_ms: _hold()
                session=live(Key('state','session#'+uuid(event.data['session_id'])))
                user=live(Key('state','user#'+uuid(session.data['user_id'])))
                actor_scope=digest(session.data['issuer']+'\0'+session.data['subject'])
                if (event.data['actor_scope'] != actor_scope
                        or session.key not in auth_keys or user.key not in auth_keys): _hold()
                if number==0:
                    if (event.data['session_id']!=value['owner_session_id'] or user.data['id']!=value['owner_user_id']
                            or actor_scope!=value['creator_scope']): _hold()
                    body={'inspection_ids':list(ids),'expected_gate_version':integer(value['initial_gate_revision']),
                          'expected_control_version':integer(value['initial_control_version']),'interruption_acknowledged':True}
                else:
                    if user.data['id'] != value['cancelled_by_user_id']: _hold()
                    gate_write=next(r for r in binding.writes if r.key==GATE)
                    body={'id':value['id'],'confirmed_scope_sha256':value['scope_sha256'],'expected_request_version':1,
                          'expected_gate_version':gate_write.previous_revision,
                          'expected_control_version':integer(value['cancelled_control_version'])-1,'no_erasure_acknowledged':True}
                if op.data['body_hash'] != digest(json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False)): _hold()
                writes={r.key:r for r in binding.writes};checks={r.key:r for r in binding.checks}
                quota_key=Key('state','metadata-owner-quota#'+actor_scope)
                expected_writes={root.key,GATE,quota_key} if number==0 else {root.key,GATE,REGISTRY,RUNTIME,DATA,quota_key}
                cookie_keys=[k for k in checks if k.table=='state' and k.resource.startswith('cookie#')]
                if len(cookie_keys)!=1 or set(writes)!=expected_writes: _hold()
                cookie=live(cookie_keys[0])
                if cookie.key not in auth_keys or cookie.data['session_id']!=session.data['id'] or cookie.data['user_id']!=user.data['id']: _hold()
                authority={HEAD,session.key,user.key,cookie.key}
                expected_checks=(authority|{REGISTRY,RUNTIME,DATA}|{Key('state','inspection#'+i) for i in ids}
                                 if number==0 else authority|{peers[0].key})
                if set(checks)!=expected_checks: _hold()
                if number==0:
                    if writes[GATE].previous_revision!=integer(value['initial_gate_revision']): _hold()
                    current_runtime=live(RUNTIME)
                    if current_runtime.revision==checks[RUNTIME].revision:
                        for declared,actual in (('initial_control_version','control_version'),('initial_runtime_epoch','runtime_epoch')):
                            if integer(value[declared])!=integer(current_runtime.data[actual]): _hold()
                        if value['initial_runtime_id']!=current_runtime.data['instance_id']: _hold()
                    if user.revision==checks[user.key].revision and integer(value['owner_access_version'])!=integer(user.data['access_version']): _hold()
                elif writes[GATE].previous_revision!=integer(value['initial_gate_revision'])+1: _hold()
                if user.revision==checks[user.key].revision and (user.data.get('enabled') is not True or 'owner' not in user.data.get('roles',())): _hold()
                dependencies+=len(binding.writes)+len(binding.checks)
                if dependencies > limits.max_dependencies: raise MetadataHistoryHeld('metadata history dependencies exhausted')
                for ref in (*binding.writes,*binding.checks):
                    current=live(ref.key)
                    if current.revision < ref.revision: _hold()
                    if current.revision==ref.revision:
                        if _payload_sha256(current.data)!=ref.sha256: _hold()
                    else: unavailable+=1
                quota_steps.setdefault(quota_key,[]).append((writes[quota_key],base//60000,at//60000))
                add(op,'metadata-operation');add(event,'metadata-event')
                used_operations.add(op.key);used_events.add(event.key)
        if used_operations!=set(operations) or used_events!={e.key for values in events.values() for e,_ in values}: _hold()
        if set(quota_steps)!=set(quotas): _hold()
        for key, steps in quota_steps.items():
            check(1);row=quotas[key];previous_minute=None;previous_count=0
            steps.sort(key=lambda item:item[0].revision)
            if len(steps)!=row.revision: _hold()
            for revision,(ref,lo,hi) in enumerate(steps,1):
                check(1)
                if ref.revision!=revision or ref.previous_revision!=(None if revision==1 else revision-1): _hold()
                found=[]
                for minute in range(lo,hi+1):
                    check(1)
                    if previous_minute is not None and minute<previous_minute: continue
                    count=previous_count+1 if minute==previous_minute else 1
                    if count>limits.writes_per_minute: continue
                    if _payload_sha256({'minute':minute,'count':count})==ref.sha256: found.append((minute,count))
                    if len(found)>1: _hold()
                if len(found)!=1: _hold()
                previous_minute,previous_count=found[0]
            if row.data!={'minute':previous_minute,'count':previous_count}: _hold()
            add(row,'metadata-quota')
        check(len(rows)+len(records))
        result=MetadataHistory(POLICY,inventory.summary_sha256,hashlib.sha256(_encoded(asdict(proof))).hexdigest(),
            scope_sha256,configuration_sha256,auth_history.summary_sha256,requested_inspections,
            tuple(records[k] for k in sorted(records,key=lambda k:(k.table,k.resource))),
            len(rows),payload_bytes,dependencies,unavailable,work,0,'')
        payload=_encoded(_projection(result))
        if len(payload)>limits.max_summary_bytes: raise MetadataHistoryHeld('metadata history summary exhausted')
        result=replace(result,summary_bytes=len(payload),summary_sha256=hashlib.sha256(payload).hexdigest())
        validate(result,inventory,proof,auth_history,scope_sha256=scope_sha256,
                 requested_inspections=requested_inspections,checkpoint=check)
        check()
        # Final source check follows the last external callback; no new allowance.
        for key,row in original.items():
            clock();e=expected[key]
            if row.key!=key or row.revision!=e.revision: _hold()
            if type(row) is Row:
                if _payload_sha256(row.data)!=e.payload_sha256: _hold()
            elif row.reference_sha256!=e.reference_sha256 or row.resource_sha256!=e.resource_sha256: _hold()
        if asdict(limits)!=frozen_limits: _hold()
        clock()
        return result
    except MetadataHistoryHeld: raise
    except (AdmissionHeld,ValueError,TypeError,KeyError,AttributeError,StopIteration,ArithmeticError,RecursionError):
        raise MetadataHistoryHeld('intact complete supported metadata history unavailable') from None
