"""Inventory-bound auth history review. Structural evidence supplies no retention right."""
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
import hashlib
import re

from proofpack.auth.service import HEAD, identity_key, digest
from proofpack.auth.session_schema import session_generation
from proofpack.evidence.access_context import validate as validate_access_context
from proofpack.evidence.inspection_corpus import CorpusReference
from proofpack.evidence.inventory import _encoded, _private_payload_size
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode, InvalidResourceBindings, MissingResourceBindings
from proofpack.evidence.replay_lineage import discover as replay_discover, ReplayHistoryHeld
from proofpack.evidence.invitation_history import discover as invitations, InvitationHistoryLimits, InvitationHistoryHeld
from proofpack.evidence.transfer_history import discover as transfers, TransferHistoryLimits, TransferHistoryHeld, _number, _sha, _body
from proofpack.runtime.control import uuid

MAXIMUM = 2**63-1
POLICY = 'held-authentication-history-v1'
REVIEW_POLICY = 'VALIDATED_AUTH_HISTORY_REQUIRES_OPERATIONAL_POLICY'
OPERATIONS = frozenset(('bootstrap', 'invite', 'accept-invite', 'revoke-invite', 'decline-invite',
    'begin-transfer', 'accept-transfer', 'change-access', 'revoke-sessions'))
INVITATIONS = frozenset(('invite', 'accept-invite', 'revoke-invite', 'decline-invite'))
TRANSFERS = frozenset(('begin-transfer', 'accept-transfer'))
FAMILIES = frozenset(('access-head', 'bootstrap', 'user', 'identity', 'session', 'cookie',
    'invitation', 'owner-transfer', 'access-replay', 'oauth-flow', 'oauth-quota'))
CLASSES = frozenset(('CURRENT_SCHEMA_AND_LINKS', 'BOOTSTRAP_BINDING', 'INVITATION_HISTORY',
    'OWNER_TRANSFER_HISTORY', 'ACCESS_RESULT_AND_BINDING', 'OAUTH_SCHEMA_ONLY'))


class AuthHistoryHeld(RuntimeError): pass


@dataclass(frozen=True)
class AuthHistoryLimits:
    max_records: int
    max_payload_bytes: int
    max_dependencies: int
    max_work: int
    max_summary_bytes: int

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= MAXIMUM for v in asdict(self).values()):
            raise ValueError('independent explicit finite auth history limits required')


@dataclass(frozen=True)
class AuthRecord:
    reference: CorpusReference = field(repr=False)
    family: str
    validation: str


@dataclass(frozen=True)
class AuthHistory:
    policy: str
    inventory_sha256: str
    proof_sha256: str
    scope_sha256: str
    requested_inspections: tuple[str, ...] = field(repr=False)
    records: tuple[AuthRecord, ...] = field(repr=False)
    family_digests: tuple[str, ...] = field(repr=False)
    source_records: int
    payload_bytes: int
    dependencies: int
    historical_dependencies_unavailable: int
    invitation_families: int
    transfer_families: int
    work: int
    summary_bytes: int
    summary_sha256: str
    historical_authority_proven: bool = False
    policy_resolved: bool = False
    read_only: bool = True
    can_confirm_cleanup: bool = False


def _hold():
    raise AuthHistoryHeld('complete supported auth history and unresolved policy obligations required')


def _projection(value):
    return {k: v for k, v in asdict(value).items() if k not in {'summary_bytes', 'summary_sha256'}}


def validate(value, inventory, proof, *, scope_sha256, requested_inspections, checkpoint):
    checkpoint()
    if (type(value) is not AuthHistory or value.policy != POLICY or value.inventory_sha256 != inventory.summary_sha256
            or value.proof_sha256 != hashlib.sha256(_encoded(asdict(proof))).hexdigest()
            or value.scope_sha256 != scope_sha256 or value.requested_inspections != requested_inspections
            or value.policy_resolved is not False or value.can_confirm_cleanup is not False
            or value.read_only is not True or value.historical_authority_proven is not False
            or type(value.records) is not tuple or len(value.records) > len(inventory.entries)
            or type(value.source_records) is not int or value.source_records != len(inventory.entries)
            or any(type(v) is not int or not 0 <= v <= MAXIMUM for v in
                (value.dependencies, value.historical_dependencies_unavailable, value.invitation_families, value.transfer_families))
            or any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (value.payload_bytes, value.work, value.summary_bytes))
            or type(value.family_digests) is not tuple): _hold()
    index = {e.key: e for e in inventory.entries}; previous = None
    for record in value.records:
        checkpoint()
        if type(record) is not AuthRecord or record.family not in FAMILIES or record.validation not in CLASSES: _hold()
        r = record.reference
        if type(r) is not CorpusReference or type(r.key) is not Key: _hold()
        entry = index.get(r.key); order = (r.key.table, r.key.resource)
        if (entry is None or entry.kind != 'live' or r.kind != 'live' or r.revision != entry.revision
                or r.sha256 != entry.payload_sha256 or r.marker_resource_sha256 is not None
                or previous is not None and order <= previous): _hold()
        previous = order
    if value.family_digests != tuple(sorted(value.family_digests)): _hold()
    for token in value.family_digests: _sha(token)
    encoded = _encoded(_projection(value)); checkpoint()
    if len(encoded) != value.summary_bytes or hashlib.sha256(encoded).hexdigest() != value.summary_sha256: _hold()
    return value


def derive(rows, inventory, proof, access_context, *, requested_inspections, scope_sha256,
           now_ms, limits, deadline_ns, tick, checkpoint):
    if (type(rows) is not tuple or type(limits) is not AuthHistoryLimits or type(deadline_ns) is not int
            or not 1 <= deadline_ns <= MAXIMUM or not callable(tick) or not callable(checkpoint)):
        raise ValueError('original held auth inventory, independent finite limits and execution fence required')
    work = 0; last = -1
    def clock():
        nonlocal last
        current = tick()
        if type(current) is not int or not 0 <= current < deadline_ns or current < last: _hold()
        last = current
    def check(cost=0):
        nonlocal work
        work += cost
        if work > limits.max_work: raise AuthHistoryHeld('auth history work exhausted')
        checkpoint(); clock(); checkpoint(); clock()
    try:
        check(); _number(now_ms)
        validate_access_context(access_context, inventory, proof, scope_sha256=scope_sha256,
            requested_inspections=requested_inspections, checkpoint=check)
        if len(rows) > limits.max_records or len(rows) != len(inventory.entries): _hold()
        expected = {e.key: e for e in inventory.entries}
        if len(expected) != len(rows): _hold()
        raw = {}; original = {}; payload_bytes = 0
        for row in rows:
            check(1)
            if type(row) not in (Row, ErasureMarker) or type(row.key) is not Key or row.key in raw: _hold()
            entry = expected.get(row.key)
            if entry is None or type(row.revision) is not int or row.revision != entry.revision: _hold()
            if type(row) is Row:
                if type(row.data) is not dict or entry.kind != 'live' or _payload_sha256(row.data) != entry.payload_sha256: _hold()
                payload_bytes += _private_payload_size(row.data)
            elif entry.kind != 'erased' or row.reference_sha256 != entry.reference_sha256 or row.resource_sha256 != entry.resource_sha256: _hold()
            if payload_bytes > limits.max_payload_bytes: raise AuthHistoryHeld('auth history payload exhausted')
            raw[row.key] = deepcopy(row); original[row.key] = row
        records = {}; groups = {}; dependency_count = 0; unavailable = 0; family_digests = []
        def live(key):
            check(1); row = raw.get(key)
            if type(row) is not Row: _hold()
            return row
        def add(row, family, validation='CURRENT_SCHEMA_AND_LINKS'):
            check(1)
            if row.key in records: _hold()
            records[row.key] = AuthRecord(CorpusReference(row.key, row.revision, 'live', _payload_sha256(row.data)), family, validation)
        def text(value, maximum):
            if type(value) is not str or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value): _hold()
        def roles(value):
            if type(value) is not list or len(value) > 3 or any(type(r) is not str or r not in {'owner','operator','reviewer'} for r in value) or len(set(value)) != len(value): _hold()
        def refs(binding):
            nonlocal dependency_count, unavailable
            dependency_count += len(binding.writes)+len(binding.checks)
            if dependency_count > limits.max_dependencies: raise AuthHistoryHeld('auth history dependencies exhausted')
            for ref in (*binding.writes, *binding.checks):
                check(1); row = live(ref.key)
                if row.revision < ref.revision: _hold()
                if row.revision == ref.revision:
                    if _payload_sha256(row.data) != ref.sha256: _hold()
                else: unavailable += 1  # A historical hash is not an available historical payload.
        def child_limits(cls):
            check()
            if limits.max_work-work < 1: _hold()
            return cls(limits.max_records, limits.max_payload_bytes, limits.max_dependencies,
                limits.max_work-work, limits.max_summary_bytes)

        head = live(HEAD); h = head.data
        if set(h) != set('schema_version enabled_user_ids owner_ids pending_invitation_ids bootstrap_scope bootstrap_receipt bootstrap_user_id'.split()) or _number(h['schema_version'],1) != 1: _hold()
        for name in ('enabled_user_ids', 'owner_ids', 'pending_invitation_ids'):
            ids = h[name]
            if type(ids) is not list or len(ids)>5 or any(type(i) is not str for i in ids) or len(ids)!=len(set(ids)): _hold()
            for ident in ids: uuid(ident)
        if not h['owner_ids'] or not set(h['owner_ids']) <= set(h['enabled_user_ids']) or len(h['enabled_user_ids'])+len(h['pending_invitation_ids'])>5: _hold()
        uuid(h['bootstrap_user_id']); _sha(h['bootstrap_scope']); _sha(h['bootstrap_receipt']); add(head,'access-head')
        members = {}; sessions = {}; identities = {}; cookies = []; invitation_roots = []; transfer_roots = []
        for row in raw.values():
            check(1)
            if row.key.table != 'state' or row.key == HEAD: continue
            prefix, _, suffix = row.key.resource.partition('#')
            if prefix not in FAMILIES: continue
            if type(row) is not Row: _hold()
            d = row.data
            if prefix == 'user':
                uuid(suffix)
                base = set('id issuer subject email_hash display_name roles enabled invited access_version session_epoch last_mfa_ms created_at_ms'.split())
                notice = set('notice_version notice_sha256 notice_acknowledged_at_ms improvement_reuse publicity_reuse'.split())
                if set(d) not in (base, base|notice) or d['id'] != suffix: _hold()
                text(d['issuer'],2048); text(d['subject'],256); text(d['display_name'],100); roles(d['roles']); _sha(d['email_hash'])
                if not d['issuer'].startswith('https://') or type(d['enabled']) is not bool or d['invited'] is not True: _hold()
                created = _number(d['created_at_ms']); _number(d['access_version'],1); _number(d['session_epoch'],1)
                if created > now_ms or d['last_mfa_ms'] is not None and _number(d['last_mfa_ms']) > now_ms: _hold()
                if 'notice_version' in d:
                    text(d['notice_version'],128); _sha(d['notice_sha256'])
                    if not created <= _number(d['notice_acknowledged_at_ms']) <= now_ms or d['improvement_reuse'] is not False or d['publicity_reuse'] is not False: _hold()
                members[suffix] = row; add(row,prefix)
            elif prefix == 'identity':
                _sha(suffix)
                if set(d) != {'user_id'}: _hold()
                uuid(d['user_id']); identities[row.key] = row; add(row,prefix)
            elif prefix == 'session':
                uuid(suffix)
                try: session_generation(d)
                except ValueError: _hold()
                if d['id'] != suffix: _hold()
                text(d['issuer'],2048); text(d['subject'],256); text(d['display_name'],100); _sha(d['email_hash']); _sha(d['csrf_hash'])
                created = _number(d['created_at_ms']); expires = _number(d['expires_at_ms'],1)
                if not d['issuer'].startswith('https://') or not _number(d['auth_time_ms']) <= created < expires or created>now_ms or expires-created>3600000 or type(d['active']) is not bool or type(d['mfa_verified']) is not bool: _hold()
                if d['restricted_invitation_id'] is not None:
                    uuid(d['restricted_invitation_id'])
                    if any(d[n] is not None for n in ('user_id','access_version','session_epoch')): _hold()
                else:
                    uuid(d['user_id']); _number(d['access_version'],1); _number(d['session_epoch'],1)
                sessions[suffix] = row; add(row,prefix)
            elif prefix == 'cookie':
                _sha(suffix)
                if set(d) != {'session_id','user_id'}: _hold()
                uuid(d['session_id'])
                if d['user_id'] is not None: uuid(d['user_id'])
                cookies.append(row); add(row,prefix)
            elif prefix == 'invitation': invitation_roots.append(row)
            elif prefix == 'owner-transfer': transfer_roots.append(row)
            elif prefix == 'oauth-flow':
                _sha(suffix)
                base = set('browser_hash configuration created_at_ms expires_at_ms require_mfa invitation_id status'.split())
                status = d.get('status')
                if status not in ('pending','consumed') or set(d) != base|({'consumed_at_ms'} if status=='consumed' else set()): _hold()
                _sha(d['browser_hash'])
                if type(d['configuration']) is not str or re.fullmatch('[A-Za-z0-9_-]{43}',d['configuration']) is None or type(d['require_mfa']) is not bool: _hold()
                created = _number(d['created_at_ms']); expires = _number(d['expires_at_ms'],1)
                if not created <= now_ms or not 1 <= expires-created <= 300000: _hold()
                if d['invitation_id'] is not None: uuid(d['invitation_id'])
                if status=='consumed':
                    consumed=_number(d['consumed_at_ms'])
                    if not created <= consumed <= now_ms or consumed>=expires: _hold()
                if row.revision != (2 if status=='consumed' else 1): _hold()
                add(row,prefix,'OAUTH_SCHEMA_ONLY')
            elif prefix == 'oauth-quota':
                if suffix not in ('login','callback') or set(d) != {'window_start_ms','count'}: _hold()
                window = _number(d['window_start_ms']); count = _number(d['count'],1)
                if window%60000 or window>now_ms or count > (30 if suffix=='login' else 60): _hold()
                add(row,prefix,'OAUTH_SCHEMA_ONLY')
        if {u for u,r in members.items() if r.data['enabled']} != set(h['enabled_user_ids']) or {u for u,r in members.items() if r.data['enabled'] and 'owner' in r.data['roles']} != set(h['owner_ids']): _hold()
        if h['bootstrap_user_id'] not in members: _hold()
        bootstrap_member = members[h['bootstrap_user_id']].data
        if digest(bootstrap_member['issuer']+'\0'+bootstrap_member['subject']) != h['bootstrap_scope']: _hold()
        if set(identities) != {identity_key(m.data['issuer'],m.data['subject']) for m in members.values()}: _hold()
        for key,row in identities.items():
            check(1); m = members.get(row.data['user_id'])
            if m is None or identity_key(m.data['issuer'],m.data['subject']) != key: _hold()
        for row in sessions.values():
            check(1); d = row.data
            if d['restricted_invitation_id'] is not None:
                inv = live(Key('state','invitation#'+d['restricted_invitation_id'])).data
                if d['issuer'] != inv['issuer'] or d['subject'] != inv['target_subject'] or d['email_hash'] != inv['target_email_hash'] or _number(d['expires_at_ms']) > _number(inv['expires_at_ms']): _hold()
            else:
                m = members.get(d['user_id'])
                if m is None or any(d[k] != m.data[k] for k in ('issuer','subject','email_hash')) or _number(d['access_version'],1)>_number(m.data['access_version'],1) or _number(d['session_epoch'],1)>_number(m.data['session_epoch'],1) or _number(d['created_at_ms'])<_number(m.data['created_at_ms']): _hold()
        for row in cookies:
            check(1); s = sessions.get(row.data['session_id'])
            if s is None or s.data['user_id'] != row.data['user_id']: _hold()
        if len(cookies)!=len(sessions) or {r.data['session_id'] for r in cookies}!=set(sessions): _hold()
        for root in invitation_roots:
            check(1)
            if root.data.get('status')=='accepted':
                member=members.get(root.data.get('accepted_user_id'))
                if member is None or member.data['issuer']!=root.data['issuer'] or member.data['subject']!=root.data['target_subject'] or member.data['email_hash']!=root.data['target_email_hash']: _hold()

        def touches_auth(binding_data):
            if type(binding_data) is not dict: return False
            if binding_data.get('operation') in OPERATIONS: return True
            writes=binding_data.get('writes')
            if type(writes) is not list or len(writes)>99: _hold()
            for w in writes:
                check(1)
                if (type(w) is dict and w.get('table')=='state' and type(w.get('resource')) is str
                        and (w['resource']==HEAD.resource or w['resource'].partition('#')[0] in FAMILIES)): return True
            return False

        peers = []
        for row in raw.values():
            check(1)
            if type(row) is not Row: continue
            binding_data = row.data.get('resource_bindings')
            # The live AccessService also writes calibration/capture/review events here.
            # Namespace alone supplies no family membership or disposition.
            is_event = row.key.table=='events' and row.key.resource.startswith('access#') and (
                row.data.get('kind') in OPERATIONS or touches_auth(binding_data))
            is_replay = row.key.table=='state' and row.key.resource.startswith('idempotency#') and touches_auth(binding_data)
            if not is_event and not is_replay: continue
            if _number(row.data['at_ms'])>now_ms: _hold()
            binding = decode(row,deployment=inventory.deployment)
            if binding.operation not in OPERATIONS: _hold()
            if is_event:
                uuid(row.key.resource.partition('#')[2])
                if row.data.get('kind') != binding.operation: _hold()
            else: _sha(row.key.resource.partition('#')[2])
            refs(binding); peers.append(row)
            token = hashlib.sha256(_encoded(asdict(binding))).hexdigest()
            groups.setdefault(token,(binding,[]))[1].append(row)
        invite_peers = tuple(r for r in peers if r.data['resource_bindings']['operation'] in INVITATIONS)
        if invitation_roots:
            family = invitations(tuple(invitation_roots),invite_peers,deployment=inventory.deployment,
                limits=child_limits(InvitationHistoryLimits),deadline_ns=deadline_ns,tick=tick,checkpoint=lambda:check())
            check(family.work); family_digests.append(family.summary_sha256)
            for r in (*invitation_roots,*invite_peers): add(r,'invitation' if r in invitation_roots else 'access-replay','INVITATION_HISTORY')
        elif invite_peers: _hold()
        pending = {r.data['id'] for r in invitation_roots if r.data.get('status')=='pending'}
        if pending != set(h['pending_invitation_ids']): _hold()
        claimed_transfers = set()
        for root in transfer_roots:
            check(1)
            matching = []
            for peer in peers:
                check(1); b = peer.data['resource_bindings']
                if b['operation'] in TRANSFERS and any(w['table']==root.key.table and w['resource']==root.key.resource for w in b['writes']): matching.append(peer)
            family = transfers(root,tuple(matching),deployment=inventory.deployment,
                limits=child_limits(TransferHistoryLimits),deadline_ns=deadline_ns,tick=tick,checkpoint=lambda:check())
            check(family.work); family_digests.append(family.summary_sha256); add(root,'owner-transfer','OWNER_TRANSFER_HISTORY')
            for r in matching:
                if r.key in claimed_transfers: _hold()
                claimed_transfers.add(r.key); add(r,'access-replay','OWNER_TRANSFER_HISTORY')
        if {r.key for r in peers if r.data['resource_bindings']['operation'] in TRANSFERS} != claimed_transfers: _hold()
        bootstraps = 0
        for binding, grouped in groups.values():
            check(1)
            if binding.operation in INVITATIONS|TRANSFERS: continue
            events = [r for r in grouped if r.key.table=='events']; replays = [r for r in grouped if r.key.table=='state']
            if len(events)!=1: _hold()
            event = events[0]; d = event.data; at = _number(d['at_ms'])
            if at>now_ms: _hold()
            writes = {r.key:r for r in binding.writes}; checked = {r.key:r for r in binding.checks}
            if binding.operation=='bootstrap':
                bootstraps += 1
                if replays or set(d) != {'kind','actor_id','at_ms','receipt','resource_bindings'} or d['actor_id'] != h['bootstrap_user_id'] or d['receipt'] != h['bootstrap_receipt']: _hold()
                required = {HEAD, Key('state','user#'+d['actor_id']), identity_key(bootstrap_member['issuer'],bootstrap_member['subject'])}
                runtime = Key('state','runtime')
                if set(writes) not in (required,required|{runtime}) or set(checked) != ({runtime} if runtime not in writes else set()) or any(r.previous_revision is not None for r in binding.writes): _hold()
                initial = {**h,'enabled_user_ids':[d['actor_id']],'owner_ids':[d['actor_id']],'pending_invitation_ids':[]}
                if writes[HEAD].sha256 != _payload_sha256(initial): _hold()
                add(event,'bootstrap','BOOTSTRAP_BINDING'); continue
            if binding.operation not in {'change-access','revoke-sessions'} or len(replays)!=1: _hold()
            replay = replays[0]
            replay_discover(replay,(event,),deployment=inventory.deployment,max_records=limits.max_records,max_payload_bytes=limits.max_payload_bytes)
            if set(d) != {'kind','actor_scope','session_id','at_ms','resource_bindings'}: _hold()
            s = sessions.get(uuid(d['session_id']))
            if s is None or s.data['user_id'] is None or digest(s.data['issuer']+'\0'+s.data['subject']) != d['actor_scope']: _hold()
            result = replay.data['result']; change = binding.operation=='change-access'
            if set(result) != ({'user_id','access_version','enabled','roles'} if change else {'user_id','access_version'}): _hold()
            target = Key('state','user#'+uuid(result['user_id'])); version = _number(result['access_version'],2)
            body = {'id':result['user_id'],'version':version-1}
            if change:
                roles(result['roles'])
                if result['roles'] != sorted(result['roles']) or type(result['enabled']) is not bool: _hold()
                body.update(roles=result['roles'],enabled=result['enabled'])
            authority = {HEAD,Key('state','session#'+s.data['id']),Key('state','user#'+s.data['user_id']),target}
            cookie_keys = [k for k in checked if k.table=='state' and k.resource.startswith('cookie#')]
            if len(cookie_keys)!=1: _hold()
            authority.add(cookie_keys[0])
            cookie = live(cookie_keys[0]).data
            if (cookie['session_id'] != s.data['id'] or cookie['user_id'] != s.data['user_id'] or set(checked)!=authority
                    or set(writes) != ({HEAD,target} if change else {target}) or result['user_id'] not in members
                    or writes[target].previous_revision is None or _number(replay.data['at_ms']) < at
                    or replay.data['body_hash'] != _body(body)): _hold()
            current = live(target)
            if _number(current.data['access_version'],1) < version: _hold()
            if current.revision==writes[target].revision:
                if _number(current.data['access_version'],1)!=version or change and (current.data['roles']!=result['roles'] or current.data['enabled']!=result['enabled']): _hold()
            add(event,'access-replay','ACCESS_RESULT_AND_BINDING'); add(replay,'access-replay','ACCESS_RESULT_AND_BINDING')
        if bootstraps != 1: _hold()
        check(len(records)+len(rows))
        result = AuthHistory(POLICY,inventory.summary_sha256,hashlib.sha256(_encoded(asdict(proof))).hexdigest(),scope_sha256,
            requested_inspections,tuple(records[k] for k in sorted(records,key=lambda k:(k.table,k.resource))),tuple(sorted(family_digests)),
            len(rows),payload_bytes,dependency_count,unavailable,len(invitation_roots),len(transfer_roots),work,0,'')
        payload = _encoded(_projection(result))
        if len(payload)>limits.max_summary_bytes: raise AuthHistoryHeld('auth history summary exhausted')
        result = replace(result,summary_bytes=len(payload),summary_sha256=hashlib.sha256(payload).hexdigest())
        validate(result,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
        check()
        for key,row in original.items():
            e = expected[key]
            if row.key!=key or row.revision!=e.revision: _hold()
            if type(row) is Row:
                if _payload_sha256(row.data)!=e.payload_sha256: _hold()
            elif row.reference_sha256!=e.reference_sha256 or row.resource_sha256!=e.resource_sha256: _hold()
        clock()
        return result
    except AuthHistoryHeld: raise
    except (InvitationHistoryHeld,TransferHistoryHeld,ReplayHistoryHeld,InvalidResourceBindings,MissingResourceBindings,
            ValueError,TypeError,KeyError,AttributeError,ArithmeticError,RecursionError):
        raise AuthHistoryHeld('intact complete supported auth history unavailable') from None
