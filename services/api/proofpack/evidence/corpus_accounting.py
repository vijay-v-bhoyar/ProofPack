"""Private conservative inventory accounting; never an executable cleanup plan."""
from dataclasses import asdict, dataclass, field
import hashlib
import re

from proofpack.evidence.capture_lineage import CaptureRecord
from proofpack.evidence.support_lineage import SupportRecord
from proofpack.evidence.replay_lineage import ReplayRecord
from proofpack.evidence.inspection_corpus import CorpusReference
from proofpack.evidence.inventory import InventoryPass, InventoryEntry, _encoded
from proofpack.evidence.privacy_admission import DrainProof, AdmissionReference
from proofpack.evidence.replay_corpus import ReplayCorpus
from proofpack.evidence.reference_corpus import ReferenceCorpus
from proofpack.evidence.repository import Key
from proofpack.runtime.control import uuid
from proofpack.evidence.runtime_context import validate as validate_runtime_context
from proofpack.evidence.purpose_corpus import validate as validate_purpose_corpus,CONTEXT_POLICY as PURPOSE_CONTEXT_POLICY

from proofpack.evidence.access_context import validate as validate_access_context, CONTEXT_POLICY as ACCESS_CONTEXT_POLICY

from proofpack.evidence.auth_history import validate as validate_auth_history, REVIEW_POLICY as AUTH_REVIEW_POLICY
from proofpack.evidence.metadata_history import validate as validate_metadata_history, REVIEW_POLICY as METADATA_REVIEW_POLICY

MAXIMUM = 2**63-1
POLICY = 'conservative-family-accounting-v1'
RUNTIME_POLICY = 'conservative-family-accounting-v2'
PURPOSE_POLICY = 'conservative-family-accounting-v3'
ACCESS_POLICY = 'conservative-family-accounting-v4'
AUTH_POLICY = 'conservative-family-accounting-v5'
METADATA_POLICY = 'conservative-family-accounting-v6'
DISPOSITIONS = ('AFFECTED','SHARED','CONTEXT','UNRELATED','UNRESOLVED')


class AccountingHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class AccountingLimits:
    max_records: int
    max_scope: int
    max_relationships: int
    max_work: int
    max_summary_bytes: int

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (
                self.max_records,self.max_scope,self.max_relationships,self.max_work,self.max_summary_bytes)):
            raise ValueError('independent finite accounting limits required')


@dataclass(frozen=True)
class AccountedRecord:
    reference: InventoryEntry = field(repr=False)
    disposition: str
    reason: str
    inspection_ids: tuple[str, ...] = field(repr=False)
    policies: tuple[str, ...]


@dataclass(frozen=True)
class AccountingLink:
    source: Key = field(repr=False)
    inspection: Key = field(repr=False)
    policy: str


@dataclass(frozen=True)
class CorpusAccounting:
    policy: str
    inventory_sha256: str
    summary_sha256: str
    requested_inspections: tuple[str, ...] = field(repr=False)
    entries: tuple[AccountedRecord, ...] = field(repr=False)
    relationships: tuple[AccountingLink, ...] = field(repr=False)
    counts: tuple[tuple[str, int], ...]
    work: int
    summary_bytes: int


def account(selection, inventory, proof, *, requested_inspections, scope_sha256,
            limits, deadline_ns, tick, checkpoint,reference_corpus=None,runtime_context=None,purpose_corpus=None,access_context=None,auth_history=None,metadata_history=None):
    """Called with server-produced metadata inside the original held-reader lifetime.

    Standalone objects, hashes and this diagnostic do not establish authority.
    Original raw/source/proof validation remains the orchestration's duty.
    """
    if purpose_corpus is not None and runtime_context is None:
        raise AccountingHeld('explicit original runtime context required with purpose context')
    if (type(selection) is not ReplayCorpus or type(inventory) is not InventoryPass
            or type(proof) is not DrainProof or type(limits) is not AccountingLimits
            or type(requested_inspections) is not tuple or not requested_inspections
            or type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM
            or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact private accounting inputs, scope, limits and clock required')
    if len(requested_inspections) > limits.max_scope:
        raise AccountingHeld('accounting requested-scope bound exhausted')
    if (any(type(v) is not str for v in requested_inspections)
            or tuple(sorted(set(requested_inspections))) != requested_inspections):
        raise ValueError('ordered unique inspection UUIDs required')
    for ident in requested_inspections: uuid(ident)
    if (type(scope_sha256) is not str or re.fullmatch('[a-f0-9]{64}',scope_sha256) is None
            or proof.scope_sha256 != scope_sha256):
        raise AccountingHeld('accounting scope does not match original drain')
    work = 0; last_tick = -1

    def check(cost=0):
        nonlocal work,last_tick
        work += cost
        if work > limits.max_work: raise AccountingHeld('accounting work bound exhausted')
        checkpoint(); now = tick()
        if type(now) is not int or not 0 <= now < deadline_ns or now < last_tick:
            raise AccountingHeld('original accounting deadline or monotonic clock invalid')
        last_tick = now; checkpoint()

    def bounded(values):
        check()
        if type(values) is not tuple or len(values) > limits.max_records:
            raise AccountingHeld('bounded immutable accounting collection required')
        return values

    def key(value):
        if (type(value) is not Key or type(value.table) is not str or value.table not in {'state','events'}
                or type(value.resource) is not str or not 1 <= len(value.resource) <= 256):
            raise AccountingHeld('exact original accounting identity required')
        return value

    def number(value):
        return type(value) is int and 1 <= value <= MAXIMUM

    def sha(value):
        return type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None

    check()
    if (type(inventory.summary_bytes) is not int or not 1 <= inventory.summary_bytes <= limits.max_summary_bytes
            or not sha(inventory.summary_sha256) or type(inventory.deployment) is not str
            or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}',inventory.deployment) is None
            or type(inventory.tables) is not tuple or len(inventory.tables) != 2
            or any(type(t) is not tuple or len(t) != 2 or type(t[0]) is not str
                or type(t[1]) is not str or not 1 <= len(t[1]) <= 256 for t in inventory.tables)
            or inventory.tables != tuple(sorted(inventory.tables))
            or {t[0] for t in inventory.tables} != {'state','events'}):
        raise AccountingHeld('bounded exact original inventory summary required')
    index = {}; previous = None
    for entry in bounded(inventory.entries):
        check(1)
        if type(entry) is not InventoryEntry or not number(entry.revision):
            raise AccountingHeld('typed original inventory reference required')
        k = key(entry.key); identity = (k.table,k.resource)
        if previous is not None and identity <= previous:
            raise AccountingHeld('ordered unique original inventory required')
        previous = identity
        if entry.kind == 'live':
            if not sha(entry.payload_sha256) or entry.reference_sha256 is not None or entry.resource_sha256 is not None:
                raise AccountingHeld('intact live accounting reference required')
        elif entry.kind == 'erased':
            if entry.revision < 2 or entry.payload_sha256 is not None or not sha(entry.reference_sha256) or not sha(entry.resource_sha256):
                raise AccountingHeld('intact retained marker required')
        else: raise AccountingHeld('unsupported inventory kind')
        index[k] = entry
    encoded = _encoded({'deployment':inventory.deployment,'tables':dict(inventory.tables),
        'entries':[asdict(entry) for entry in inventory.entries]})
    check(len(index))
    if len(encoded) != inventory.summary_bytes or hashlib.sha256(encoded).hexdigest() != inventory.summary_sha256:
        raise AccountingHeld('original inventory accounting digest mismatch')
    del encoded

    def reference(record):
        check(1)
        if type(record) not in {CaptureRecord,SupportRecord,ReplayRecord,AdmissionReference,CorpusReference}:
            raise AccountingHeld('supported exact family reference required')
        k = key(record.key); entry = index.get(k)
        if entry is None or not number(record.revision) or record.revision != entry.revision or not sha(record.sha256):
            raise AccountingHeld('missing or changed family accounting reference')
        if type(record) is CorpusReference:
            if record.kind != entry.kind or record.marker_resource_sha256 != entry.resource_sha256:
                raise AccountingHeld('original family marker identity mismatch')
            expected = entry.payload_sha256 if entry.kind == 'live' else entry.reference_sha256
        else:
            if entry.kind != 'live': raise AccountingHeld('erased family input is unavailable')
            expected = entry.payload_sha256
        if record.sha256 != expected: raise AccountingHeld('family accounting payload mismatch')
        return k

    datasets = selection.datasets; permissions = datasets.permissions
    labels = permissions.labels; inspections = labels.inspections
    roots = {}; original = set()
    for family in bounded(inspections.families):
        check(1); ident = uuid(family.inspection_id)
        if ident in roots or type(family.requested) is not bool or family.requested != (ident in requested_inspections):
            raise AccountingHeld('exact unique original inspection scope required')
        root = reference(family.capture.inspection)
        if root != Key('state','inspection#'+ident): raise AccountingHeld('inspection root identity mismatch')
        roots[ident] = root
        for record in (family.capture.inspection,*bounded(family.capture.records),*bounded(family.human.records),*bounded(family.support.records)):
            k = reference(record)
            if k in original: raise AccountingHeld('overlapping original family accounting')
            original.add(k)
    for record in bounded(inspections.residual):
        k = reference(record)
        if k in original: raise AccountingHeld('duplicate original residual accounting')
        original.add(k)
    if original != set(index) or not set(requested_inspections) <= roots.keys():
        raise AccountingHeld('complete original inventory coverage required')

    owners = {}; policies = {}; context = set(); unresolved = {}; links = set()

    def force(k,reason):
        check(1); unresolved.setdefault(k,set()).add(reason)

    def membership(records, ids, policy, uncertain=False):
        ids = bounded(ids)
        if any(type(i) is not str or i not in roots for i in ids) or tuple(sorted(set(ids))) != ids:
            raise AccountingHeld('validated inspection memberships required')
        check(len(ids))
        seen = set()
        for record in bounded(records):
            k = reference(record)
            if k in seen: raise AccountingHeld('duplicate family membership')
            seen.add(k); policies.setdefault(k,set()).add(policy)
            owners.setdefault(k,set()).update(ids)
            if uncertain or not ids: force(k,'INCOMPLETE_SOURCE_SCOPE')
            for ident in ids:
                check(1); link = (k,roots[ident],policy)
                if link not in links and len(links) >= limits.max_relationships:
                    raise AccountingHeld('accounting relationship bound exhausted')
                links.add(link)

    for f in inspections.families:
        membership((f.capture.inspection,*f.capture.records),(f.inspection_id,),'CAPTURE_CONTENT')
        membership(f.human.records,(f.inspection_id,),'HUMAN_CONTENT')
        membership(f.support.records,(f.inspection_id,),'SUPPORT_CONTENT')
    for f in bounded(labels.families):
        if type(f.requested) is not bool or f.requested != (f.inspection_id in requested_inspections):
            raise AccountingHeld('label scope flag mismatch')
        membership(f.labels.records,(f.inspection_id,),'LABEL_CONTENT')
        for r in (f.labels.recipe,*bounded(f.labels.purposes)):
            k = reference(r); context.add(k); policies.setdefault(k,set()).add('VALIDATED_LABEL_CONTEXT')
    for f in bounded(permissions.families):
        membership((f.history.preview,*f.history.records),f.inspection_ids,'OPTIONAL_PERMISSION_CONTENT',
            bool(bounded(f.unresolved_reference_sources)))
    for f in bounded(datasets.families):
        membership((f.history.job,*f.history.records),f.inspection_ids,'DATASET_ARTIFACT_CONTENT',
            bool(bounded(f.unresolved_intents)))
    for f in bounded(datasets.groups):
        records = (f.history.group,*bounded(f.history.history))
        membership(records,f.copied_inspection_ids,'SHARED_GROUP_HISTORY',True)
        for r in records: force(reference(r),'COLLATERAL_POLICY_REQUIRED')
    for f in bounded(selection.families):
        membership((f.history.replay,),f.inspection_ids,'REPLAY_RESULT_CONTENT',
            bool(bounded(f.unresolved_source_keys)))
        for event in bounded(f.history.events): reference(event)
    purpose_records={}
    if purpose_corpus is not None:
        validate_purpose_corpus(purpose_corpus,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
        purpose_records={r.key:r for r in bounded(purpose_corpus.records)}
    for obligation in bounded(selection.obligations):
        k=reference(obligation.replay)
        if not (obligation.reason=='BUSINESS_CODEC_UNSUPPORTED' and k in purpose_records):force(k,'REPLAY_POLICY_REQUIRED')
    if reference_corpus is not None:
        if type(reference_corpus) is not ReferenceCorpus:raise AccountingHeld('typed private reference corpus required')
        for f in bounded(reference_corpus.families):
            for r in (f.intent,*bounded(f.records)):
                k=reference(r);policies.setdefault(k,set()).add('REFERENCE_UPLOAD_HISTORY')
                force(k,'INSPECTION_ORIGIN_NOT_RECORDED')
    for record in (proof.gate,proof.registry,proof.runtime):
        k = reference(record); context.add(k); policies.setdefault(k,set()).add('EXACT_DRAIN_CONTEXT')
    if runtime_context is not None:
        validate_runtime_context(runtime_context,inventory,proof,scope_sha256=scope_sha256,
                                 requested_inspections=requested_inspections,checkpoint=check)
        for record in bounded(runtime_context.records):
            k = reference(record.reference); context.add(k); policies.setdefault(k,set()).add(record.policy)
    for record in purpose_records.values():
        k=reference(record);context.add(k);policies.setdefault(k,set()).add(PURPOSE_CONTEXT_POLICY)
    if access_context is not None:
        if runtime_context is None: raise AccountingHeld('explicit runtime context required with access context')
        validate_access_context(access_context,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
        for record in bounded(access_context.records):
            k=reference(record);context.add(k);policies.setdefault(k,set()).add(ACCESS_CONTEXT_POLICY)
    if auth_history is not None:
        if access_context is None or runtime_context is None: raise AccountingHeld('original auth/access/runtime derivations required')
        validate_auth_history(auth_history,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
        for record in bounded(auth_history.records):
            k=reference(record.reference)
            if k not in context:
                policies.setdefault(k,set()).add(AUTH_REVIEW_POLICY)
                force(k,'OPERATIONAL_AUTH_POLICY_REQUIRED')
    if metadata_history is not None:
        if auth_history is None or access_context is None or runtime_context is None:
            raise AccountingHeld('original metadata/auth/access/runtime derivations required')
        validate_metadata_history(metadata_history,inventory,proof,auth_history,
            scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
        for record in bounded(metadata_history.records):
            k=reference(record.reference)
            if record.family=='metadata-request':
                membership((record.reference,),record.inspection_ids,'VALIDATED_METADATA_REQUEST_SCOPE')
                force(k,METADATA_REVIEW_POLICY)
            else:
                context.add(k);policies.setdefault(k,set()).add('VALIDATED_METADATA_OPAQUE_OR_SHARED_CONTEXT')
    residual = set()
    for r in bounded(selection.residual):
        k = reference(r)
        if k in residual: raise AccountingHeld('duplicate final residual accounting')
        residual.add(k)
    if set(owners) | context | residual != set(index):
        raise AccountingHeld('unaccounted or extra inventory entries')

    entries = []; counts = {name:0 for name in DISPOSITIONS}; requested = set(requested_inspections)
    for k, entry in index.items():
        check(1); known = owners.get(k,set())
        if entry.kind == 'erased': disposition,reason = 'UNRESOLVED','MARKER_JOURNAL_REQUIRED'
        elif k in unresolved: disposition,reason = 'UNRESOLVED',sorted(unresolved[k])[0]
        elif known:
            relevant = known & requested
            if relevant and known-requested: disposition,reason = 'SHARED','MIXED_INSPECTION_ARTIFACT'
            elif relevant: disposition,reason = 'AFFECTED','VALIDATED_CONTENT_MEMBERSHIP'
            else: disposition,reason = 'UNRELATED','SUPPORTED_OTHER_INSPECTION_CONTENT'
        elif k in context: disposition,reason = 'CONTEXT','VALIDATED_INTERPRETATION_OR_FENCE'
        else: disposition,reason = 'UNRESOLVED','UNSUPPORTED_FAMILY_POLICY'
        counts[disposition] += 1
        entries.append(AccountedRecord(entry,disposition,reason,tuple(sorted(known)),tuple(sorted(policies.get(k,())))))
    ordered = sorted(links,key=lambda v:(v[0].table,v[0].resource,v[1].table,v[1].resource,v[2]))
    check(len(ordered))
    relationships = tuple(AccountingLink(*v) for v in ordered)
    hasher = hashlib.sha256(); size = 0
    def bind(value):
        nonlocal size
        check(1); payload = _encoded(value)
        framed = str(len(payload)).encode()+b':'+payload
        size += len(framed)
        if size > limits.max_summary_bytes: raise AccountingHeld('accounting output summary bound exhausted')
        hasher.update(framed); check()
    policy = POLICY if runtime_context is None else RUNTIME_POLICY
    if purpose_corpus is not None:policy=PURPOSE_POLICY
    if access_context is not None:policy=ACCESS_POLICY
    header = (policy,inventory.summary_sha256,requested_inspections)
    if runtime_context is not None: header += (runtime_context.summary_sha256,)
    if purpose_corpus is not None:header += (purpose_corpus.summary_sha256,)
    if access_context is not None:header += (access_context.summary_sha256,)
    if auth_history is not None:header += (auth_history.summary_sha256,)
    if auth_history is not None:
        policy=AUTH_POLICY
        header=(AUTH_POLICY,*header[1:])
    if metadata_history is not None:
        policy=METADATA_POLICY
        header=(METADATA_POLICY,*header[1:],metadata_history.summary_sha256)
    bind(header)
    for entry in entries: bind(asdict(entry))
    for link in relationships: bind(asdict(link))
    result = CorpusAccounting(policy,inventory.summary_sha256,hasher.hexdigest(),requested_inspections,tuple(entries),
        relationships,tuple(counts.items()),work,size)
    check()
    return result
