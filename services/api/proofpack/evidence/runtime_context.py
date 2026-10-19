"""Original held runtime context; private metadata, never a removal capability."""
from dataclasses import asdict, dataclass, field
import hashlib
import re

from proofpack.auth.service import RUNTIME
from proofpack.runtime.control import ALLOCATION, DATA, uuid
from proofpack.runtime.startup_schema import restore_startup, valid_data_write
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.inventory import InventoryPass, InventoryEntry, _encoded, _private_payload_size
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode, InvalidResourceBindings, MissingResourceBindings
from proofpack.evidence.runtime_lineage import discover, RuntimeLineageLimits, RuntimeLineageHeld, _integer
from proofpack.evidence.privacy_admission import DrainProof
from proofpack.evidence.replay_corpus import ReplayCorpus
from proofpack.evidence.inspection_corpus import CorpusReference

MAXIMUM = 2**63-1
POLICY = 'runtime-maintenance-context-v1'
RETENTION = {'VALIDATED_RUNTIME_PROVENANCE': 'retained_original_runtime_provenance',
    'VALIDATED_EMPTY_ALLOCATION_FENCE': 'retained_original_empty_allocation_fence',
    'VALIDATED_DATA_EPOCH_FENCE': 'retained_original_data_epoch_fence'}


class RuntimeContextHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeContextLimits:
    max_records: int
    max_payload_bytes: int
    max_work: int
    max_summary_bytes: int

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (
                self.max_records, self.max_payload_bytes, self.max_work, self.max_summary_bytes)):
            raise ValueError('independent explicit finite runtime context limits required')


@dataclass(frozen=True)
class RuntimeContextRecord:
    reference: CorpusReference = field(repr=False)
    policy: str


@dataclass(frozen=True)
class RuntimeContext:
    policy: str
    inventory_sha256: str
    proof_sha256: str
    scope_sha256: str
    requested_inspections: tuple[str, ...] = field(repr=False)
    origins: tuple[CorpusReference, ...] = field(repr=False)
    records: tuple[RuntimeContextRecord, ...] = field(repr=False)
    obligations: tuple[CorpusReference, ...] = field(repr=False)
    source_records: int
    payload_bytes: int
    work: int
    summary_sha256: str
    summary_bytes: int
    read_only: bool = True
    can_confirm_cleanup: bool = False


def _projection(context):
    return {k: v for k, v in asdict(context).items() if k not in {'summary_sha256', 'summary_bytes'}}


def validate(context, inventory, proof, *, scope_sha256, requested_inspections,checkpoint=lambda:None):
    """Verify a fresh private result's bindings; does not authenticate its producer."""
    if (type(context) is not RuntimeContext or context.policy != POLICY
            or context.inventory_sha256 != inventory.summary_sha256 or context.scope_sha256 != scope_sha256
            or context.proof_sha256 != hashlib.sha256(_encoded(asdict(proof))).hexdigest()
            or context.requested_inspections != requested_inspections or context.read_only is not True
            or context.can_confirm_cleanup is not False or type(context.source_records) is not int
            or context.source_records != len(inventory.entries)
            or any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (context.payload_bytes, context.work, context.summary_bytes))
            or any(type(v) is not tuple or len(v)>len(inventory.entries) for v in (context.origins, context.records, context.obligations))):
        raise RuntimeContextHeld('original non-authorizing runtime context binding required')
    index = {entry.key: entry for entry in inventory.entries}
    def reference(ref):
        checkpoint()
        if type(ref) is not CorpusReference or type(ref.key) is not Key:
            raise RuntimeContextHeld('typed original context reference required')
        entry = index.get(ref.key)
        if (entry is None or entry.kind != 'live' or ref.kind != 'live' or type(ref.revision) is not int
                or ref.revision != entry.revision or ref.sha256 != entry.payload_sha256 or ref.marker_resource_sha256 is not None):
            raise RuntimeContextHeld('original live context reference required')
        return ref.key
    def ordered(refs):
        identities = [(reference(r).table, r.key.resource) for r in refs]
        if identities != sorted(set(identities)):
            raise RuntimeContextHeld('ordered unique context references required')
    ordered(context.origins); ordered(context.obligations)
    if any(type(r) is not RuntimeContextRecord or type(r.policy) is not str or r.policy not in RETENTION for r in context.records):
        raise RuntimeContextHeld('explicit supported runtime context policy required')
    ordered(tuple(r.reference for r in context.records))
    if {r.reference.key for r in context.records} & {r.key for r in context.obligations}:
        raise RuntimeContextHeld('retained and unresolved runtime identities overlap')
    payload = _encoded(_projection(context))
    if len(payload) != context.summary_bytes or hashlib.sha256(payload).hexdigest() != context.summary_sha256:
        raise RuntimeContextHeld('intact complete runtime context summary required')
    return context


def derive(rows, selection, inventory, proof, *, requested_inspections, scope_sha256,
           now_ms, limits, deadline_ns, tick, checkpoint):
    if (type(rows) is not tuple or type(selection) is not ReplayCorpus or type(inventory) is not InventoryPass
            or type(proof) is not DrainProof or type(limits) is not RuntimeContextLimits
            or type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM
            or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact private runtime context inputs and original bounds required')
    work = 0; last = -1
    def check(cost=0):
        nonlocal work, last
        work += cost
        if work > limits.max_work: raise RuntimeContextHeld('runtime context work bound exhausted')
        checkpoint(); current = tick()
        if type(current) is not int or not 0 <= current < deadline_ns or current < last:
            raise RuntimeContextHeld('original runtime context deadline or clock invalid')
        last = current; checkpoint()
    def hold(): raise RuntimeContextHeld('supported complete original runtime context required')
    try:
        check(); now_ms = _integer(now_ms)
        if (type(requested_inspections) is not tuple or not requested_inspections
                or any(type(v) is not str for v in requested_inspections)
                or requested_inspections != tuple(sorted(set(requested_inspections)))
                or type(scope_sha256) is not str or re.fullmatch('[a-f0-9]{64}', scope_sha256) is None
                or proof.scope_sha256 != scope_sha256): hold()
        for ident in requested_inspections: uuid(ident)
        if type(inventory.entries) is not tuple or len(rows) != len(inventory.entries) or len(rows) > limits.max_records:
            raise RuntimeContextHeld('complete original runtime context record bound required')
        entries = {}; previous = None
        for e in inventory.entries:
            check(1)
            if type(e) is not InventoryEntry or type(e.key) is not Key: hold()
            identity = (e.key.table, e.key.resource)
            if previous is not None and identity <= previous: hold()
            previous = identity; entries[e.key] = e
        summary = _encoded({'deployment':inventory.deployment,'tables':dict(inventory.tables),
            'entries':[asdict(e) for e in inventory.entries]})
        if len(summary) != inventory.summary_bytes or hashlib.sha256(summary).hexdigest() != inventory.summary_sha256: hold()
        raw = {}; payload_bytes = 0
        for row in rows:
            check(1)
            if type(row) not in (Row, ErasureMarker) or type(row.key) is not Key or row.key in raw: hold()
            e = entries.get(row.key)
            if e is None or type(row.revision) is not int or row.revision != e.revision: hold()
            if type(row) is Row:
                if e.kind != 'live' or _payload_sha256(row.data) != e.payload_sha256: hold()
                payload_bytes += _private_payload_size(row.data)
            elif e.kind != 'erased' or row.reference_sha256 != e.reference_sha256 or row.resource_sha256 != e.resource_sha256: hold()
            if payload_bytes > limits.max_payload_bytes: raise RuntimeContextHeld('runtime context payload bound exhausted')
            raw[row.key] = row
        def ref(key):
            e = entries.get(key)
            if e is None or e.kind != 'live': hold()
            return CorpusReference(key, e.revision, 'live', e.payload_sha256)
        for r in (proof.gate, proof.registry, proof.runtime):
            check(1)
            current = ref(r.key)
            if current.revision != r.revision or current.sha256 != r.sha256: hold()
        runtime = raw.get(RUNTIME)
        base = {'runtime_epoch','control_version','inspection_enabled','instance_id','artifact_sha256','controls_sha256',
                'started_at_ms','environment','enable_receipt_id','enable_expires_at_ms','reason'}
        if type(runtime) is not Row or set(runtime.data) not in (base, base | {'enable_receipt_sha256','enable_owner_id'}): hold()
        d = runtime.data; instance = uuid(d['instance_id']); epoch = _integer(d['runtime_epoch'],minimum=1)
        control = _integer(d['control_version'],minimum=1); started = _integer(d['started_at_ms'])
        if (d['inspection_enabled'] is not False or started > now_ms or type(d['reason']) is not str
                or not 1 <= len(d['reason']) <= 512 or d['environment'] not in {'test','synthetic_demo','beta'}
                or any(d.get(name) is not None for name in ('enable_receipt_id','enable_expires_at_ms','enable_receipt_sha256','enable_owner_id'))): hold()
        for name in ('artifact_sha256','controls_sha256'):
            if type(d[name]) is not str or re.fullmatch('[a-f0-9]{64}',d[name]) is None: hold()
        allocation = raw.get(ALLOCATION); data = raw.get(DATA)
        if (type(allocation) is not Row or set(allocation.data) != {'slots'}
                or type(allocation.data['slots']) is not dict or allocation.data['slots']): hold()
        if type(data) is not Row or set(data.data) not in ({'epoch'},{'epoch','changed_at_ms'}): hold()
        _integer(data.data['epoch'],minimum=1)
        if 'changed_at_ms' in data.data and _integer(data.data['changed_at_ms']) > now_ms: hold()
        origins = []; origin_specs = {}
        for f in selection.datasets.permissions.labels.inspections.families:
            check(1); r = ref(f.capture.inspection.key)
            if r.revision != f.capture.inspection.revision or r.sha256 != f.capture.inspection.sha256: hold()
            root = raw[r.key].data; ident = uuid(root['runtime_instance_id'])
            spec = (_integer(root['runtime_epoch'],minimum=1),root['artifact_sha256'])
            created = _integer(root['created_at_ms'])
            if created > now_ms or ident in origin_specs and origin_specs[ident][:2] != spec: hold()
            if ident == instance and (spec != (epoch,d['artifact_sha256']) or created < started
                    or _integer(root['control_version'],minimum=1) > control): hold()
            earliest = min(created,origin_specs.get(ident,(*spec,created))[2])
            origin_specs[ident] = (*spec,earliest); origins.append(r)
        records = {ALLOCATION: RuntimeContextRecord(ref(ALLOCATION),'VALIDATED_EMPTY_ALLOCATION_FENCE'),
                   DATA: RuntimeContextRecord(ref(DATA),'VALIDATED_DATA_EPOCH_FENCE')}
        obligations = {}; matched = False; seen_instances = set()
        for row in rows:
            check(1)
            if type(row) is not Row or row.key.table != 'events' or row.data.get('kind') != 'runtime_started': continue
            ident = row.data.get('instance_id')
            if ident != instance and ident not in origin_specs: continue
            if ident in seen_instances: hold()
            seen_instances.add(ident)
            marker_key = Key('state','runtime-start#'+ident); marker = raw.get(marker_key)
            if type(marker) is not Row: hold()
            if (set(row.data) != {'kind','instance_id','runtime_epoch','control_version','at_ms','resource_bindings'}
                    or row.key.table != 'events' or not row.key.resource.startswith('runtime#')
                    or row.revision != 1): hold()
            uuid(row.key.resource[len('runtime#'):]); event_epoch=_integer(row.data['runtime_epoch'],minimum=1)
            event_control=_integer(row.data['control_version'],minimum=1); event_time=_integer(row.data['at_ms'])
            if event_time > now_ms: hold()
            startup=restore_startup(marker.data)
            if (marker.revision != 1
                    or _integer(marker.data['runtime_epoch'],minimum=1) != event_epoch
                    or type(marker.data['environment']) is not str
                    or marker.data['environment'] not in {'test','synthetic_demo','beta'}): hold()
            for name in ('artifact_sha256','controls_sha256'):
                if type(marker.data[name]) is not str or re.fullmatch('[a-f0-9]{64}',marker.data[name]) is None: hold()
            if ident in origin_specs and (origin_specs[ident][:2] != (event_epoch,marker.data['artifact_sha256'])
                    or event_time > origin_specs[ident][2]): hold()
            envelope = decode(row,deployment=inventory.deployment)
            if envelope.operation != 'runtime_started': hold()
            writes={r.key:r for r in envelope.writes};checks={r.key:r for r in envelope.checks}
            if (not {RUNTIME,marker_key} <= writes.keys() or not writes.keys() <= {RUNTIME,marker_key,ALLOCATION,DATA}
                    or not checks.keys() <= {ALLOCATION,DATA} or writes.keys() & checks.keys()
                    or any((k in writes)==(k in checks) for k in (ALLOCATION,DATA))): hold()
            if startup is not None and DATA not in writes: hold()
            for key,written in writes.items():
                check(1)
                if key==DATA and not valid_data_write(startup,written.previous_revision,written.revision): hold()
                if key not in (RUNTIME,DATA) and (written.previous_revision is not None or written.revision!=1): hold()
            marker_ref=writes[marker_key]
            if marker_ref.sha256!=_payload_sha256(marker.data) or marker_ref.revision!=marker.revision: hold()
            if ident != instance:
                obligations[row.key]=ref(row.key); obligations[marker_key]=ref(marker_key); continue
            matched = True
            if (event_epoch != epoch or event_control > control
                    or any(marker.data[name]!=d[name] for name in ('artifact_sha256','controls_sha256','environment'))
                    or event_time < started): hold()
            if instance in origin_specs and _integer(row.data['at_ms']) > origin_specs[instance][2]: hold()
            writes = {r.key:r for r in envelope.writes}
            original_ref = writes.get(RUNTIME)
            if original_ref is None: hold()
            initial = Row(RUNTIME,original_ref.revision,{**{k:d[k] for k in base},
                'control_version':row.data['control_version'],'inspection_enabled':False,
                'enable_receipt_id':None,'enable_expires_at_ms':None,'reason':'runtime_started'})
            missing = _payload_sha256(initial.data) != original_ref.sha256
            created = {}
            for key, head in ((ALLOCATION,allocation),(DATA,data)):
                written = writes.get(key)
                if written is not None:
                    if head.revision != written.revision or _payload_sha256(head.data) != written.sha256: missing = True
                    else: created['created_allocation' if key==ALLOCATION else 'created_data'] = head
            if missing:
                obligations[row.key]=ref(row.key); obligations[marker_key]=ref(marker_key); continue
            remaining = limits.max_work-work
            if remaining < 1: raise RuntimeContextHeld('runtime context work exhausted before startup validation')
            startup = discover(row,marker,initial,deployment=inventory.deployment,now_ms=now_ms,
                limits=RuntimeLineageLimits(limits.max_records,limits.max_payload_bytes,remaining,limits.max_summary_bytes),
                deadline_ns=deadline_ns,tick=tick,checkpoint=lambda:check(),**created)
            check(startup.work)
            records[row.key]=RuntimeContextRecord(ref(row.key),'VALIDATED_RUNTIME_PROVENANCE')
            records[marker_key]=RuntimeContextRecord(ref(marker_key),'VALIDATED_RUNTIME_PROVENANCE')
        if not matched: hold()
        order = lambda values:tuple(sorted(values,key=lambda r:(r.key.table,r.key.resource)))
        context = RuntimeContext(POLICY,inventory.summary_sha256,hashlib.sha256(_encoded(asdict(proof))).hexdigest(),
            scope_sha256,requested_inspections,order(origins),tuple(records[k] for k in sorted(records,key=lambda k:(k.table,k.resource))),
            order(obligations.values()),len(rows),payload_bytes,work,'',1)
        payload = _encoded(_projection(context))
        if len(payload) > limits.max_summary_bytes: raise RuntimeContextHeld('runtime context summary bound exhausted')
        from dataclasses import replace
        context = replace(context,summary_sha256=hashlib.sha256(payload).hexdigest(),summary_bytes=len(payload))
        check(); return validate(context,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
    except (RuntimeLineageHeld,InvalidResourceBindings,MissingResourceBindings,ValueError,TypeError,KeyError,AttributeError,ArithmeticError):
        raise RuntimeContextHeld('exact original runtime context unavailable') from None
