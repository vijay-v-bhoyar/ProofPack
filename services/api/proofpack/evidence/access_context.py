"""Exact inspection-origin access context; no authentication or cleanup grant."""
from dataclasses import asdict, dataclass, field, replace
from copy import deepcopy
import hashlib
import re
from proofpack.auth.service import identity_key
from proofpack.auth.session_schema import session_generation
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.inventory import InventoryPass, InventoryEntry, _encoded, _private_payload_size
from proofpack.evidence.inspection_corpus import CorpusReference
from proofpack.evidence.label_corpus import _inspection_references
from proofpack.evidence.replay_corpus import ReplayCorpus
from proofpack.evidence.privacy_admission import DrainProof
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.runtime_lineage import _integer as stored_integer, RuntimeLineageHeld
from proofpack.runtime.control import uuid

MAXIMUM = 2**63-1
POLICY = 'inspection-origin-access-context-v1'
CONTEXT_POLICY = 'VALIDATED_INSPECTION_ORIGIN_ACCESS_CONTEXT'
RETENTION_REASON = 'retained_original_user_session_identity_for_inspection_interpretation'


class AccessContextHeld(RuntimeError): pass


@dataclass(frozen=True)
class AccessContextLimits:
    max_records: int
    max_payload_bytes: int
    max_work: int
    max_summary_bytes: int

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (
                self.max_records, self.max_payload_bytes, self.max_work, self.max_summary_bytes)):
            raise ValueError('explicit independent finite access context limits required')


@dataclass(frozen=True)
class AccessOrigin:
    inspection: CorpusReference = field(repr=False)
    member: CorpusReference = field(repr=False)
    session: CorpusReference = field(repr=False)
    identity: CorpusReference = field(repr=False)
    cookies: tuple[CorpusReference, ...] = field(repr=False)


@dataclass(frozen=True)
class AccessContext:
    policy: str
    inventory_sha256: str
    proof_sha256: str
    scope_sha256: str
    requested_inspections: tuple[str, ...] = field(repr=False)
    origins: tuple[AccessOrigin, ...] = field(repr=False)
    records: tuple[CorpusReference, ...] = field(repr=False)
    source_records: int
    payload_bytes: int
    work: int
    summary_bytes: int
    summary_sha256: str
    read_only: bool = True
    can_confirm_cleanup: bool = False


def _projection(value):
    return {k: v for k, v in asdict(value).items() if k not in {'summary_bytes', 'summary_sha256'}}


def validate(value, inventory, proof, *, scope_sha256, requested_inspections, checkpoint):
    def hold(): raise AccessContextHeld('intact original non-authorizing access context required')
    checkpoint()
    if (type(value) is not AccessContext or value.policy != POLICY or value.inventory_sha256 != inventory.summary_sha256
            or value.proof_sha256 != hashlib.sha256(_encoded(asdict(proof))).hexdigest()
            or value.scope_sha256 != scope_sha256 or value.requested_inspections != requested_inspections
            or value.read_only is not True or value.can_confirm_cleanup is not False
            or type(value.source_records) is not int or value.source_records != len(inventory.entries)
            or any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (value.payload_bytes, value.work, value.summary_bytes))
            or any(type(v) is not tuple or len(v) > len(inventory.entries) for v in (value.origins, value.records))): hold()
    index = {e.key: e for e in inventory.entries}
    def reference(r, prefix):
        checkpoint()
        if type(r) is not CorpusReference or type(r.key) is not Key: hold()
        k = r.key
        if type(k.table) is not str or k.table != 'state' or type(k.resource) is not str or not k.resource.startswith(prefix+'#'): hold()
        ident = k.resource[len(prefix)+1:]
        if prefix in {'identity', 'cookie'}:
            if re.fullmatch('[a-f0-9]{64}', ident) is None: hold()
        else:
            try: uuid(ident)
            except ValueError: hold()
        e = index.get(k)
        if (e is None or e.kind != 'live' or r.kind != 'live' or type(r.revision) is not int
                or r.revision != e.revision or r.sha256 != e.payload_sha256 or r.marker_resource_sha256 is not None): hold()
        return k
    roots = []; records = set(); link_count = 0
    for origin in value.origins:
        checkpoint()
        if type(origin) is not AccessOrigin or type(origin.cookies) is not tuple or len(origin.cookies) > len(index): hold()
        root = reference(origin.inspection, 'inspection'); roots.append(root.resource.split('#')[1])
        for ref, prefix in ((origin.member, 'user'), (origin.session, 'session'), (origin.identity, 'identity')):
            records.add(reference(ref, prefix)); link_count += 1
        cookies = [reference(r, 'cookie') for r in origin.cookies]
        if cookies != sorted(set(cookies), key=lambda k: (k.table, k.resource)): hold()
        records.update(cookies); link_count += len(cookies)
    if roots != list(requested_inspections) or link_count > value.work: hold()
    actual = []
    for r in value.records:
        if type(r) is not CorpusReference or type(r.key) is not Key or type(r.key.resource) is not str: hold()
        actual.append(reference(r, r.key.resource.split('#')[0]))
    if actual != sorted(records, key=lambda k: (k.table, k.resource)): hold()
    payload = _encoded(_projection(value)); checkpoint()
    if len(payload) != value.summary_bytes or hashlib.sha256(payload).hexdigest() != value.summary_sha256: hold()
    return value


def derive(rows, selection, inventory, proof, *, requested_inspections, scope_sha256, now_ms, limits, deadline_ns, tick, checkpoint):
    if (type(rows) is not tuple or type(selection) is not ReplayCorpus or type(inventory) is not InventoryPass
            or type(proof) is not DrainProof or type(limits) is not AccessContextLimits or type(deadline_ns) is not int
            or not 1 <= deadline_ns <= MAXIMUM or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact original access context inputs and independent finite bounds required')
    work = 0; last = -1
    def check(cost=0):
        nonlocal work, last
        work += cost
        if work > limits.max_work: raise AccessContextHeld('access context work exhausted')
        checkpoint(); current = tick()
        if type(current) is not int or not 0 <= current < deadline_ns or current < last:
            raise AccessContextHeld('original access context deadline or clock invalid')
        last = current; checkpoint()
    def hold(): raise AccessContextHeld('complete exact inspection-origin access context required')
    def integer(v, minimum=0):
        try: return stored_integer(v, minimum=minimum)
        except RuntimeLineageHeld: hold()
    def sha(v):
        if type(v) is not str or re.fullmatch('[a-f0-9]{64}', v) is None: hold()
    try:
        check(); integer(now_ms)
        if (type(requested_inspections) is not tuple or not requested_inspections
                or requested_inspections != tuple(sorted(set(requested_inspections)))): hold()
        for ident in requested_inspections: uuid(ident)
        sha(scope_sha256)
        if proof.scope_sha256 != scope_sha256: hold()
        if type(inventory.entries) is not tuple or len(rows) != len(inventory.entries) or len(rows) > limits.max_records:
            raise AccessContextHeld('complete bounded access context inventory required')
        entries = {}; previous = None
        for e in inventory.entries:
            check(1)
            if (type(e) is not InventoryEntry or type(e.key) is not Key or type(e.key.table) is not str
                    or e.key.table not in {'state','events'} or type(e.key.resource) is not str
                    or not 1 <= len(e.key.resource) <= 256 or type(e.revision) is not int
                    or not 1 <= e.revision <= MAXIMUM or type(e.kind) is not str): hold()
            if e.kind == 'live':
                sha(e.payload_sha256)
                if e.reference_sha256 is not None or e.resource_sha256 is not None: hold()
            elif e.kind == 'erased':
                sha(e.reference_sha256); sha(e.resource_sha256)
                if e.revision < 2 or e.payload_sha256 is not None: hold()
            else: hold()
            identity = (e.key.table, e.key.resource)
            if previous is not None and identity <= previous: hold()
            previous = identity; entries[e.key] = e
        summary = _encoded({'deployment': inventory.deployment, 'tables': dict(inventory.tables), 'entries': [asdict(e) for e in inventory.entries]})
        if len(summary) != inventory.summary_bytes or hashlib.sha256(summary).hexdigest() != inventory.summary_sha256: hold()
        expected = {e.key: CorpusReference(e.key, e.revision, e.kind,
            e.payload_sha256 if e.kind == 'live' else e.reference_sha256, e.resource_sha256) for e in inventory.entries}
        if _inspection_references(selection.datasets.permissions.labels.inspections) != expected: hold()
        raw = {}; payload_bytes = 0
        for row in rows:
            check(1)
            if type(row) not in (Row, ErasureMarker) or type(row.key) is not Key or row.key in raw: hold()
            e = entries.get(row.key)
            if e is None or type(row.revision) is not int or row.revision != e.revision: hold()
            if type(row) is Row:
                if type(row.data) is not dict or e.kind != 'live' or _payload_sha256(row.data) != e.payload_sha256: hold()
                payload_bytes += _private_payload_size(row.data)
            elif e.kind != 'erased' or row.reference_sha256 != e.reference_sha256 or row.resource_sha256 != e.resource_sha256: hold()
            if payload_bytes > limits.max_payload_bytes: raise AccessContextHeld('access context payload exhausted')
            raw[row.key] = deepcopy(row)
        for r in (proof.gate, proof.registry, proof.runtime):
            check(1)
            if expected.get(r.key) != CorpusReference(r.key, r.revision, 'live', r.sha256): hold()
        def live(key):
            check(1); row = raw.get(key)
            if type(row) is not Row: hold()
            return row.data
        requested = set(requested_inspections); selected = {}
        for family in selection.datasets.permissions.labels.inspections.families:
            check(1)
            if type(family.requested) is not bool or family.requested != (family.inspection_id in requested): hold()
            if family.requested:
                ref = family.capture.inspection
                if expected.get(ref.key) != CorpusReference(ref.key, ref.revision, 'live', ref.sha256): hold()
                if family.inspection_id in selected: hold()
                selected[family.inspection_id] = ref.key
        if set(selected) != requested: hold()
        sessions = {}; origin_data = []
        for ident in requested_inspections:
            check(1); root_key = selected[ident]; root = live(root_key)
            user = uuid(root['originating_user_id']); session = uuid(root['originating_session_id'])
            version = integer(root['originating_access_version'], 1); at = integer(root['created_at_ms'])
            if root_key != Key('state', 'inspection#'+ident) or at > now_ms: hold()
            member_key = Key('state', 'user#'+user); session_key = Key('state', 'session#'+session)
            m = live(member_key); s = live(session_key)
            base = {'id','issuer','subject','email_hash','display_name','roles','enabled','invited','access_version','session_epoch','last_mfa_ms','created_at_ms'}
            notice = {'notice_version','notice_sha256','notice_acknowledged_at_ms','improvement_reuse','publicity_reuse'}
            if set(m) not in (base, base|notice): hold()
            if (m['id'] != user or type(m['issuer']) is not str or not m['issuer'].startswith('https://')
                    or type(m['subject']) is not str or not 1 <= len(m['subject']) <= 256
                    or type(m['display_name']) is not str or not 1 <= len(m['display_name']) <= 100
                    or any(ord(c) < 32 for c in m['display_name']) or type(m['enabled']) is not bool or m['invited'] is not True
                    or type(m['roles']) is not list or len(m['roles']) > 3 or any(type(r) is not str or r not in {'owner','operator','reviewer'} for r in m['roles'])
                    or len(m['roles']) != len(set(m['roles']))): hold()
            sha(m['email_hash']); member_created = integer(m['created_at_ms'])
            member_version = integer(m['access_version'], 1); member_epoch = integer(m['session_epoch'], 1)
            if member_created > at or version > member_version: hold()
            if m['last_mfa_ms'] is not None and integer(m['last_mfa_ms']) > now_ms: hold()
            if 'notice_version' in m:
                if (type(m['notice_version']) is not str or not 1 <= len(m['notice_version']) <= 128
                        or m['improvement_reuse'] is not False or m['publicity_reuse'] is not False
                        or not member_created <= integer(m['notice_acknowledged_at_ms']) <= at): hold()
                sha(m['notice_sha256'])
            try: session_generation(s)
            except ValueError: hold()
            if (s['id'] != session or s['user_id'] != user or s['issuer'] != m['issuer'] or s['subject'] != m['subject'] or s['email_hash'] != m['email_hash']
                    or type(s['display_name']) is not str or not 1 <= len(s['display_name']) <= 100 or any(ord(c) < 32 for c in s['display_name'])
                    or type(s['active']) is not bool or type(s['mfa_verified']) is not bool or s['restricted_invitation_id'] is not None
                    or integer(s['access_version'], 1) != version or integer(s['session_epoch'], 1) > member_epoch): hold()
            sha(s['csrf_hash']); created = integer(s['created_at_ms']); authenticated = integer(s['auth_time_ms'])
            if not member_created <= created <= at or authenticated > created or integer(s['expires_at_ms']) <= at: hold()
            identity = identity_key(m['issuer'], m['subject']); index = live(identity)
            if set(index) != {'user_id'} or index['user_id'] != user: hold()
            previous = sessions.setdefault(session, user)
            if previous != user: hold()
            origin_data.append((root_key, member_key, session_key, identity))
        cookies = {session: [] for session in sessions}
        for row in raw.values():
            check(1)
            if type(row) is Row and row.key.table == 'state' and row.key.resource.startswith('cookie#') and row.data.get('session_id') in sessions:
                if (re.fullmatch('cookie#[a-f0-9]{64}', row.key.resource) is None or set(row.data) != {'session_id','user_id'}
                        or row.data['user_id'] != sessions[row.data['session_id']]): hold()
                cookies[row.data['session_id']].append(row.key)
        origins = []; records = set()
        for root, member, session, identity in origin_data:
            linked = cookies[session.resource.split('#')[1]]; check(3+len(linked))
            linked = sorted(linked, key=lambda k: (k.table, k.resource))
            origins.append(AccessOrigin(expected[root], expected[member], expected[session], expected[identity], tuple(expected[k] for k in linked)))
            records.update((member, session, identity, *linked))
        check(len(records)+len(origins))
        result = AccessContext(POLICY, inventory.summary_sha256, hashlib.sha256(_encoded(asdict(proof))).hexdigest(), scope_sha256,
            requested_inspections, tuple(origins), tuple(expected[k] for k in sorted(records, key=lambda k: (k.table,k.resource))),
            len(rows), payload_bytes, work, 0, '')
        payload = _encoded(_projection(result)); check()
        if len(payload) > limits.max_summary_bytes: raise AccessContextHeld('access context summary exhausted')
        result = replace(result, summary_bytes=len(payload), summary_sha256=hashlib.sha256(payload).hexdigest())
        validate(result, inventory, proof, scope_sha256=scope_sha256, requested_inspections=requested_inspections, checkpoint=check)
        check(); return result
    except AccessContextHeld: raise
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise AccessContextHeld('supported original access context required') from error
