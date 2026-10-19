"""Separate revocable improvement-use attestations; no training or truth certification."""
from dataclasses import asdict, dataclass, field
import hashlib
from uuid import uuid4
from pydantic import Field, model_validator

from proofpack.auth.policy import Denied, Role
from proofpack.auth.service import RUNTIME, ResourceUnavailable
from proofpack.calibrations.dependencies import digest, canonical
from proofpack.evidence.repository import Key, Write, StoreConflict, StoreUnavailable
from proofpack.recipes.models import Contract, Identifier
from proofpack.review.labels import UUIDText
from proofpack.runtime.control import DATA, integer, uuid


class ImprovementLimited(RuntimeError): pass


@dataclass(frozen=True)
class ImprovementConfig:
    notice_version: str
    notice_text: str = field(repr=False)
    max_lifetime_ms: int
    writes_per_minute: int
    review_ms: int

    def __post_init__(self):
        if (not isinstance(self.notice_version, str) or not 1 <= len(self.notice_version) <= 128
                or not isinstance(self.notice_text, str) or not self.notice_text.strip() or not 1 <= len(self.notice_text) <= 16384
                or any(type(v) is not int or not lo <= v <= hi for v, lo, hi in (
                    (self.max_lifetime_ms, 1, 31536000000), (self.writes_per_minute, 1, 100), (self.review_ms, 1, 60000)))):
            raise ValueError('explicit bounded improvement notice and limits required')


class ImprovementPreview(Contract):
    asset_ids: tuple[UUIDText, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode='after')
    def distinct(self):
        if len(set(self.asset_ids)) != len(self.asset_ids): raise ValueError('distinct selected assets required')
        return self


class ImprovementConfirmation(Contract):
    preview_id: UUIDText
    confirmed_scope_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    documented_permission_reference: Identifier
    notice_version: str = Field(min_length=1, max_length=128)
    notice_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    optional_improvement_acknowledged: bool
    limitations_acknowledged: bool
    derived_review_metadata_acknowledged: bool = False
    expires_at_ms: int = Field(gt=0, le=9007199254740991)


def preview_key(ident): return Key('state', 'improvement-preview#' + uuid(ident))
def permission_key(ident): return Key('state', 'improvement-permission#' + uuid(ident))
def grant_key(ident): return Key('state', 'improvement-grant#' + uuid(ident))


class ImprovementPermissions:
    def __init__(self, assets, config):
        if not isinstance(config, ImprovementConfig): raise ValueError('typed improvement configuration required')
        self.assets = assets; self.access = assets.access; self.repository = assets.repository
        self.purposes = assets.purposes; self.runtime = assets.runtime; self.config = config
        self.notice_sha256 = hashlib.sha256(config.notice_text.encode()).hexdigest()
        self.configuration = digest({'notice_version': config.notice_version, 'notice_sha256': self.notice_sha256,
            'frames': asdict(assets.frames.config), 'references': asdict(assets.references.config)})
        self.preview_configuration = digest({'scope_configuration':self.configuration,'max_lifetime_ms':config.max_lifetime_ms,
            'writes_per_minute':config.writes_per_minute,'review_ms':config.review_ms})

    @staticmethod
    def _merge(*groups):
        result = {}
        for group in groups:
            for row in group:
                if row is None: continue
                if row.key in result and result[row.key] != row: raise StoreConflict('improvement authority changed')
                result[row.key] = row
        if len(result) > 90: raise StoreUnavailable('bounded improvement dependency set required')
        return result

    def _scope(self, actor, ids):
        actor = self.access._fresh(actor); rows = self._merge(actor.rows); selected = []; deadline = 9007199254740991
        for ident in sorted(ids):
            actor, current, asset, _, _, receipt, expires, _ = self.assets._snapshot(actor, uuid(ident), binary=False)
            purpose = current[Key('state', 'purpose#' + asset.data['purpose_id'])]
            reference = purpose.data.get('source_permission_reference')
            if not isinstance(reference, str) or not reference or purpose.data.get('id', asset.data['purpose_id']) != asset.data['purpose_id']:
                raise StoreUnavailable('documented original operational permission required')
            rows = self._merge(rows.values(), current.values())
            selected.append({'id': ident, 'kind': 'reference' if asset.data.get('kind') == 'reference' else 'frame',
                'asset_revision': asset.revision, 'asset_record_sha256': digest(asset.data), 'sha256': receipt.source_sha256,
                'data_origin': asset.data['data_origin'], 'purpose_id': asset.data['purpose_id'], 'purpose_revision': purpose.revision,
                'purpose_record_sha256': digest(purpose.data), 'source_permission_reference': purpose.data['source_permission_reference'],
                'expires_at_ms': expires})
            deadline = min(deadline, expires)
        return actor, rows, {'schema_version': 1, 'kind': 'selected_optional_improvement',
            'configuration': self.configuration, 'assets': selected}, deadline

    def _fence(self, actor, rows, deadline, role):
        if self.access.now() >= deadline: raise StoreUnavailable('improvement review or source expired')
        final = self.repository.snapshot(tuple(rows))
        if any(final[k] != row for k, row in rows.items()): raise StoreConflict('improvement source changed')
        self.access._fresh(actor, role)
        if self.access.now() >= deadline: raise StoreUnavailable('improvement review expired')

    def _quota(self, actor, kind):
        key = Key('state', 'improvement-' + kind + '-quota#' + actor.scope)
        row = self.repository.snapshot((key,))[key]; minute = self.access.now() // 60000
        if row is not None and integer(row.data['minute']) > minute: raise StoreUnavailable('improvement allowance clock moved backwards')
        count = 0 if row is None or integer(row.data['minute']) != minute else integer(row.data['count'])
        if count >= self.config.writes_per_minute: raise ImprovementLimited('improvement write allowance exhausted')
        return Write(key, None if row is None else row.revision, {'minute': minute, 'count': count + 1})

    def options(self, actor):
        self.access._fresh(actor, Role.OWNER)
        return {'notice': {'version': self.config.notice_version, 'sha256': self.notice_sha256, 'text': self.config.notice_text},
            'server_time_ms': self.access.now(), 'max_lifetime_ms': self.config.max_lifetime_ms, 'max_assets': 16}

    def preview(self, actor, *, request, idempotency_key):
        actor = self.access._fresh(actor, Role.OWNER)
        if not isinstance(request, ImprovementPreview): raise ValueError('typed improvement scope required')
        idem, body_hash, prior = self.access._idempotency(actor, 'improvement-preview', idempotency_key, request.model_dump(mode='json'))
        if prior is not None: return self.preview_read(actor, prior.data['result']['id'])
        now = self.access.now(); actor, rows, scope, expiry = self._scope(actor, request.asset_ids)
        deadline = min(now + self.config.review_ms, expiry); ident = str(uuid4())
        record = {'id': ident, 'status': 'preview', 'scope': scope, 'scope_sha256': digest(scope),
            'configuration': self.preview_configuration, 'data_epoch': integer(rows[DATA].data['epoch']),
            'notice': {'version':self.config.notice_version,'sha256':self.notice_sha256,'text':self.config.notice_text},
            'runtime_binding': asdict(self.runtime.handle),
            'owner_id': actor.member.data['id'], 'session_id': actor.session.data['id'], 'access_version': integer(actor.member.data['access_version']),
            'created_at_ms': now, 'expires_at_ms': deadline, 'source_expires_at_ms': expiry, 'permission_id': None}
        self._fence(actor, rows, deadline, Role.OWNER)
        result = self.access._record(actor, 'improvement-preview', idem, body_hash, {'id': ident},
            (Write(preview_key(ident), None, record), self._quota(actor, 'preview')), tuple(rows.values()),
            before_commit=lambda: self._fence(actor, rows, deadline, Role.OWNER), event_details={'preview_id': ident, 'scope_sha256': record['scope_sha256']})
        return self.preview_read(actor, result['id'])

    def _binding(self, actor, preview):
        actor = self.access._fresh(actor, Role.OWNER); data = preview.data
        if (self.runtime.handle is None or data['status'] != 'preview' or data['owner_id'] != actor.member.data['id']
                or data['session_id'] != actor.session.data['id'] or integer(data['access_version']) != integer(actor.member.data['access_version'])
                or data['runtime_binding'] != asdict(self.runtime.handle)
                or data['configuration'] != self.preview_configuration or not integer(data['created_at_ms']) <= self.access.now() < integer(data['expires_at_ms'])
                or digest(data['scope']) != data['scope_sha256']): raise StoreConflict('current original-owner improvement review required')
        return actor

    def preview_read(self, actor, ident):
        actor = self.access._fresh(actor, Role.OWNER); row = self.repository.snapshot((preview_key(ident),))[preview_key(ident)]
        if row is None: raise ResourceUnavailable('improvement preview unavailable')
        can_confirm = False
        try:
            actor = self._binding(actor, row)
            actor, rows, scope, _ = self._scope(actor, tuple(a['id'] for a in row.data['scope']['assets']))
            can_confirm = digest(scope) == row.data['scope_sha256'] and integer(rows[DATA].data['epoch']) == integer(row.data['data_epoch'])
            self._fence(actor, self._merge(rows.values(), (row,)), integer(row.data['expires_at_ms']), Role.OWNER)
        except (Denied, StoreConflict, StoreUnavailable): can_confirm = False
        self.access._fresh(actor, Role.OWNER)
        return {'id': ident, 'state_version': row.revision, 'status': row.data['status'],
            'scope_sha256': row.data['scope_sha256'], 'assets': self._public_assets(row.data['scope']),
            'remaining_review_ms': max(0, integer(row.data['expires_at_ms']) - self.access.now()),
            'source_expires_at_ms': integer(row.data['source_expires_at_ms']), 'data_epoch': integer(row.data['data_epoch']),
            'server_time_ms':self.access.now(),'max_lifetime_ms':self.config.max_lifetime_ms,
            'notice': row.data['notice'],
            'can_confirm': can_confirm, 'permission_id': row.data['permission_id']}

    def confirm(self, actor, *, request, expected_version, idempotency_key):
        actor = self.access._fresh(actor, Role.OWNER)
        if not isinstance(request, ImprovementConfirmation) or type(expected_version) is not int or expected_version < 1:
            raise ValueError('typed exact-version improvement confirmation required')
        if request.optional_improvement_acknowledged is not True or request.limitations_acknowledged is not True:
            raise Denied('separate explicit optional improvement acknowledgments required')
        body = {'request': request.model_dump(mode='json',exclude_unset=True), 'expected_version': expected_version}
        idem, body_hash, prior = self.access._idempotency(actor, 'improvement-confirm', idempotency_key, body)
        if prior is not None: return self.get(actor, prior.data['result']['id'])
        key = preview_key(request.preview_id); preview = self.repository.snapshot((key,))[key]
        if preview is None: raise ResourceUnavailable('improvement preview unavailable')
        actor = self._binding(actor, preview)
        if (preview.revision != expected_version or request.confirmed_scope_sha256 != preview.data['scope_sha256']
                or request.notice_version != self.config.notice_version or request.notice_sha256 != self.notice_sha256):
            raise StoreConflict('exact improvement scope and notice required')
        actor, rows, scope, expiry = self._scope(actor, tuple(a['id'] for a in preview.data['scope']['assets']))
        if digest(scope) != request.confirmed_scope_sha256 or integer(rows[DATA].data['epoch']) != integer(preview.data['data_epoch']):
            raise StoreConflict('improvement scope or data authority changed')
        if not self.access.now() < request.expires_at_ms <= min(expiry, self.access.now() + self.config.max_lifetime_ms):
            raise ValueError('explicit improvement expiry within source rights required')
        ident = str(uuid4()); now = self.access.now()
        grant = {'id': ident, 'schema_version': 1, 'scope': scope, 'scope_sha256': digest(scope), 'configuration': self.configuration,
            'documented_permission_reference': request.documented_permission_reference, 'notice_version': request.notice_version,
            'notice_sha256': request.notice_sha256, 'owner_id': actor.member.data['id'], 'created_at_ms': now,
            'notice_text': self.config.notice_text,
            'expires_at_ms': request.expires_at_ms, 'authority_basis': 'owner_attestation', 'rights_independently_verified': False,
            'derived_review_metadata_allowed': request.derived_review_metadata_acknowledged is True,
            'optional_improvement': True, 'optional_publicity': False, 'physical_truth_verified': False, 'independence_verified': False}
        grant['sha256'] = digest(grant); rows = self._merge(rows.values(), (preview,))
        self._fence(actor, rows, min(integer(preview.data['expires_at_ms']), request.expires_at_ms), Role.OWNER)
        def before_commit():
            self._binding(actor, preview)
            self._fence(actor, rows, min(integer(preview.data['expires_at_ms']), request.expires_at_ms, expiry), Role.OWNER)
        result = self.access._record(actor, 'improvement-confirm', idem, body_hash, {'id': ident},
            (Write(grant_key(ident), None, grant), Write(permission_key(ident), None, {'id': ident, 'grant_sha256': grant['sha256'], 'withdrawn': False}),
             Write(key, preview.revision, {**preview.data, 'status': 'committed', 'permission_id': ident}), self.purposes.advance(rows[DATA]), self._quota(actor, 'confirm')),
            tuple(rows.values()), before_commit=before_commit,
            event_details={'permission_id': ident, 'scope_sha256': grant['scope_sha256'], 'grant_sha256': grant['sha256']})
        return self.get(actor, result['id'])

    def _load(self, ident):
        keys = (permission_key(ident), grant_key(ident)); rows = self.repository.snapshot(keys); head, grant = (rows[k] for k in keys)
        if head is None or grant is None: raise ResourceUnavailable('improvement permission unavailable')
        try:
            if (grant.revision != 1 or grant.data['id'] != ident or head.data['id'] != ident or type(head.data['withdrawn']) is not bool
                    or head.data['grant_sha256'] != grant.data['sha256'] or digest({k:v for k,v in grant.data.items() if k != 'sha256'}) != grant.data['sha256']
                    or digest(grant.data['scope']) != grant.data['scope_sha256'] or grant.data['authority_basis'] != 'owner_attestation'
                    or hashlib.sha256(grant.data['notice_text'].encode()).hexdigest() != grant.data['notice_sha256']
                    or any(grant.data[k] is not False for k in ('rights_independently_verified', 'optional_publicity', 'physical_truth_verified', 'independence_verified'))
                    or grant.data['optional_improvement'] is not True): raise ValueError()
        except (KeyError, TypeError, ValueError, AttributeError) as exc: raise StoreUnavailable('intact improvement grant required') from exc
        return head, grant

    @staticmethod
    def _public_assets(scope):
        return [{**{k:a[k] for k in ('id', 'kind', 'sha256', 'data_origin', 'purpose_id', 'source_permission_reference')}, 'expires_at_ms':integer(a['expires_at_ms'])} for a in scope['assets']]

    def _validate(self, actor, head, grant):
        data = grant.data
        if head.data['withdrawn'] is True: raise StoreUnavailable('improvement permission withdrawn')
        if (data['configuration'] != self.configuration or not integer(data['created_at_ms']) <= self.access.now() < integer(data['expires_at_ms'])
                or integer(data['expires_at_ms'])-integer(data['created_at_ms']) > self.config.max_lifetime_ms):
            raise StoreUnavailable('improvement permission configuration or lifetime held')
        actor, rows, scope, expiry = self._scope(actor, tuple(a['id'] for a in data['scope']['assets']))
        if digest(scope) != data['scope_sha256']: raise StoreConflict('improvement source scope changed')
        rows = self._merge(rows.values(), (head, grant)); deadline = min(expiry, integer(data['expires_at_ms']))
        role = Role.REVIEWER if Role.REVIEWER in actor.principal.roles else Role.OWNER
        self._fence(actor, rows, deadline, role)
        return actor, rows, deadline

    def get(self, actor, ident):
        actor = self.purposes.candidate(actor); head, grant = self._load(uuid(ident)); usable = False
        try: actor, _, _ = self._validate(actor, head, grant); usable = True
        except (Denied, StoreUnavailable, StoreConflict): pass
        actor = self.access._fresh(actor, Role.REVIEWER if Role.REVIEWER in actor.principal.roles else Role.OWNER)
        expected = self._merge(actor.rows, (head, grant)); final = self.repository.snapshot(tuple(expected))
        if any(final[k] != row for k, row in expected.items()): raise StoreConflict('improvement permission changed')
        data = grant.data
        return {k:data[k] for k in ('id', 'scope_sha256', 'documented_permission_reference', 'notice_version', 'notice_sha256', 'authority_basis',
            'rights_independently_verified', 'optional_improvement', 'optional_publicity', 'physical_truth_verified', 'independence_verified')} | {
            'state_version': head.revision, 'grant_sha256': data['sha256'], 'withdrawn': head.data['withdrawn'], 'usable': usable,
            'derived_review_metadata_allowed': data.get('derived_review_metadata_allowed') is True,
            'held_reason': None if usable else 'WITHDRAWN' if head.data['withdrawn'] else 'SOURCE_NOTICE_OR_LIFETIME_HELD',
            'expires_at_ms': integer(data['expires_at_ms']), 'assets': self._public_assets(data['scope']),
            'notice': {'version':data['notice_version'],'sha256':data['notice_sha256'],'text':data['notice_text']}}

    def authorize(self, actor, ident, *, asset_ids, expected_version):
        actor = self.access._fresh(actor, Role.REVIEWER); head, grant = self._load(uuid(ident))
        if type(expected_version) is not int or expected_version < 1 or head.revision != expected_version:
            raise StoreConflict('current improvement permission version required')
        ids = tuple(uuid(v) for v in asset_ids)
        if not 1 <= len(ids) <= 16 or len(set(ids)) != len(ids) or not set(ids) <= {a['id'] for a in grant.data['scope']['assets']}:
            raise Denied('selected improvement scope required')
        return self._validate(actor, head, grant)

    def withdraw(self, actor, ident, *, expected_version, idempotency_key):
        actor = self.access._fresh(actor, Role.OWNER); ident = uuid(ident)
        if type(expected_version) is not int or expected_version < 1: raise ValueError('exact permission version required')
        idem, body_hash, prior = self.access._idempotency(actor, 'improvement-withdraw:' + ident, idempotency_key, {'expected_version': expected_version})
        if prior is not None: return self.get(actor, ident)
        head, grant = self._load(ident)
        if head.revision != expected_version: raise StoreConflict('improvement permission changed')
        epoch = self.purposes.head(); runtime = self.repository.snapshot((RUNTIME,))[RUNTIME]
        if not self.runtime.matches(runtime): raise Denied('current improvement runtime required')
        writes = () if head.data['withdrawn'] else (Write(head.key, head.revision, {**head.data, 'withdrawn': True, 'withdrawn_at_ms': self.access.now()}), self.purposes.advance(epoch))
        self.access._record(actor, 'improvement-withdraw:' + ident, idem, body_hash, {'id': ident}, (*writes, self._quota(actor, 'withdraw')),
            (head, grant, epoch, runtime), event_details={'permission_id': ident, 'withdrawn': True})
        return self.get(actor, ident)

    def list(self, actor, *, limit=20, cursor=None):
        actor = self.purposes.candidate(actor)
        if type(limit) is not int or not 1 <= limit <= 20: raise ValueError('bounded improvement page required')
        rows, last = self.repository.query(prefix='improvement-permission#', limit=limit,
            start_resource=None if cursor is None else permission_key(cursor).resource)
        values = [self.get(actor, row.data['id']) for row in rows]
        self.purposes.candidate(actor)
        return {'permissions': values, 'next_cursor': None if last is None else last.split('#',1)[1]}
