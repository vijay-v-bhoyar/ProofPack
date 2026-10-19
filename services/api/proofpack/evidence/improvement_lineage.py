"""Parse admitted optional-permission history; never confer current rights."""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import re

from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.capture_lineage import CaptureRecord, CaptureLink, _n, _shape, _record
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode
from proofpack.runtime.control import DATA, RUNTIME, uuid, sha


class ImprovementHistoryHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class ImprovementFamily:
    preview: CaptureRecord
    grant: CaptureRecord | None
    permission: CaptureRecord | None
    records: tuple[CaptureRecord, ...]
    links: tuple[CaptureLink, ...]
    dependencies: tuple[CaptureRecord, ...]
    payload_bytes: int


PREVIEW = frozenset('id status scope scope_sha256 configuration data_epoch notice runtime_binding owner_id session_id access_version created_at_ms expires_at_ms source_expires_at_ms permission_id'.split())
GRANT = frozenset('id schema_version scope scope_sha256 configuration documented_permission_reference notice_version notice_sha256 owner_id created_at_ms notice_text expires_at_ms authority_basis rights_independently_verified derived_review_metadata_allowed optional_improvement optional_publicity physical_truth_verified independence_verified sha256'.split())
SOURCE = frozenset('id kind asset_revision asset_record_sha256 sha256 data_origin purpose_id purpose_revision purpose_record_sha256 source_permission_reference expires_at_ms'.split())
EVENT = frozenset('kind actor_scope at_ms session_id details resource_bindings'.split())


def discover(preview, rows, *, deployment, max_records, max_payload_bytes):
    """Caller proves complete inventory/barrier admission and source-family closure."""
    if (type(deployment) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', deployment) is None
            or type(rows) is not tuple
            or any(type(v) is not int or not 1 <= v <= 2**63-1 for v in (max_records, max_payload_bytes))):
        raise ValueError('explicit bounded improvement history required')
    if 1 + len(rows) > max_records:
        raise ImprovementHistoryHeld('improvement record bound exhausted')
    try:
        copies = {}; size = 0
        for row in (preview, *rows):
            if (isinstance(row, ErasureMarker) or not isinstance(row, Row) or not isinstance(row.key, Key)
                    or type(row.data) is not dict or type(row.revision) is not int
                    or not 1 <= row.revision <= 2**63-1 or row.key in copies):
                raise ValueError()
            _payload_sha256(row.data); size += len(canonical(row.data).encode())
            if size > max_payload_bytes:
                raise ImprovementHistoryHeld('improvement payload bound exhausted')
            copies[row.key] = deepcopy(row)
        root = copies[preview.key]; p = root.data; _shape(p, PREVIEW)
        if root.key != Key('state', 'improvement-preview#' + uuid(p['id'])):
            raise ValueError()
        uuid(p['owner_id']); uuid(p['session_id']); sha(p['configuration']); sha(p['scope_sha256'])
        _n(p['access_version'], positive=True); _n(p['data_epoch'], positive=True)
        created = _n(p['created_at_ms']); expires = _n(p['expires_at_ms'], positive=True)
        source_expires = _n(p['source_expires_at_ms'], positive=True)
        if not created < expires <= source_expires:
            raise ValueError()
        scope = p['scope']; _shape(scope, frozenset(('schema_version', 'kind', 'configuration', 'assets')))
        if (_n(scope['schema_version'], positive=True) != 1 or scope['kind'] != 'selected_optional_improvement'
                or digest(scope) != p['scope_sha256'] or type(scope['assets']) is not list
                or not 1 <= len(scope['assets']) <= 16):
            raise ValueError()
        sha(scope['configuration']); source_keys = []; source_refs = {}
        for asset in scope['assets']:
            _shape(asset, SOURCE); ident = uuid(asset['id']); purpose = uuid(asset['purpose_id'])
            if asset['kind'] not in {'frame', 'reference'} or asset['data_origin'] not in {'synthetic', 'physical'}:
                raise ValueError()
            for field in ('asset_record_sha256', 'purpose_record_sha256', 'sha256'):sha(asset[field])
            if type(asset['source_permission_reference']) is not str or not asset['source_permission_reference']:
                raise ValueError()
            if _n(asset['expires_at_ms'], positive=True) < source_expires:
                raise ValueError()
            source_keys.append(ident)
            for key, revision, value in (
                (Key('state', 'asset#' + ident), asset['asset_revision'], asset['asset_record_sha256']),
                (Key('state', 'purpose#' + purpose), asset['purpose_revision'], asset['purpose_record_sha256']),
            ):
                record = CaptureRecord(key, _n(revision, positive=True), value)
                if key in source_refs and source_refs[key] != record:raise ValueError()
                source_refs[key] = record
        if source_keys != sorted(set(source_keys)) or min(a['expires_at_ms'] for a in scope['assets']) != source_expires:
            raise ValueError()
        notice = p['notice']; _shape(notice, frozenset(('version', 'sha256', 'text')))
        if (type(notice['version']) is not str or not 1 <= len(notice['version']) <= 128
                or type(notice['text']) is not str or not notice['text']
                or hashlib.sha256(notice['text'].encode()).hexdigest() != sha(notice['sha256'])):
            raise ValueError()
        runtime = p['runtime_binding']; _shape(runtime, frozenset(('instance_id', 'epoch', 'artifact_sha256', 'controls_sha256', 'environment')))
        uuid(runtime['instance_id']); _n(runtime['epoch'], positive=True)
        sha(runtime['artifact_sha256']); sha(runtime['controls_sha256'])
        if runtime['environment'] not in {'test', 'synthetic_demo', 'beta'}:raise ValueError()
        committed = p['status'] == 'committed'
        if (p['status'] not in {'preview', 'committed'} or root.revision != (2 if committed else 1)
                or (not committed and p['permission_id'] is not None)):
            raise ValueError()
        ident = uuid(p['permission_id']) if committed else None
        gkey = Key('state', 'improvement-grant#' + ident) if committed else None
        hkey = Key('state', 'improvement-permission#' + ident) if committed else None
        grant = None; head = None; events = []
        for original in rows:
            row = copies[original.key]
            if row.key == gkey:grant = row
            elif row.key == hkey:head = row
            elif row.key.table == 'events':
                _shape(row.data, EVENT)
                if row.revision != 1 or row.key.resource != 'access#' + uuid(row.key.resource.removeprefix('access#')):
                    raise ValueError()
                sha(row.data['actor_scope']); uuid(row.data['session_id']); _n(row.data['at_ms'])
                events.append((row, decode(row, deployment=deployment)))
            else:raise ValueError()
        if committed:
            if grant is None or head is None or grant.revision != 1:raise ValueError()
            g = grant.data; _shape(g, GRANT)
            if (uuid(g['id']) != ident or _n(g['schema_version'], positive=True) != 1
                    or sha(g['sha256']) != digest({k: v for k, v in g.items() if k != 'sha256'})
                    or canonical(g['scope']) != canonical(scope) or g['scope_sha256'] != p['scope_sha256']
                    or g['configuration'] != scope['configuration'] or g['owner_id'] != p['owner_id']
                    or g['notice_version'] != notice['version'] or g['notice_sha256'] != notice['sha256']
                    or g['notice_text'] != notice['text'] or g['authority_basis'] != 'owner_attestation'
                    or g['optional_improvement'] is not True or type(g['derived_review_metadata_allowed']) is not bool
                    or any(g[name] is not False for name in ('rights_independently_verified', 'optional_publicity', 'physical_truth_verified', 'independence_verified'))
                    or type(g['documented_permission_reference']) is not str
                    or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', g['documented_permission_reference']) is None):
                raise ValueError()
            if (not created <= _n(g['created_at_ms']) < min(expires, _n(g['expires_at_ms'], positive=True))
                    or g['expires_at_ms'] > source_expires):
                raise ValueError()
            h = head.data
            if type(h.get('withdrawn')) is not bool:raise ValueError()
            _shape(h, frozenset(('id', 'grant_sha256', 'withdrawn')), {'withdrawn_at_ms'} if h['withdrawn'] else frozenset())
            if h['id'] != ident or h['grant_sha256'] != g['sha256'] or head.revision != (2 if h['withdrawn'] else 1):raise ValueError()
            if h['withdrawn'] and _n(h['withdrawn_at_ms']) < g['created_at_ms']:raise ValueError()
        initial = {**p, 'status': 'preview', 'permission_id': None}
        owned = set(copies); links = set(); dependencies = set(); counts = {'preview': 0, 'confirm': 0, 'withdraw': 0}; original_actor_scopes = set(); review_data_refs = set()

        def equal(ref, key, revision, payload):
            if ref is None or ref.key != key or ref.revision != revision or ref.sha256 != _payload_sha256(payload):raise ValueError()

        for row, binding in events:
            e = row.data; kind = e['kind']; checked = {r.key: r for r in binding.checks}; written = {r.key: r for r in binding.writes}
            if kind != binding.operation or RUNTIME not in checked or DATA not in checked:raise ValueError()
            if not any(key.resource.startswith('user#') and key.table == 'state' for key in checked):raise ValueError()
            if Key('state', 'session#' + e['session_id']) not in checked:raise ValueError()
            if kind in {'improvement-preview', 'improvement-confirm'}:
                original_actor_scopes.add(e['actor_scope'])
                review_data_refs.add((checked[DATA].revision, checked[DATA].sha256))
                if e['session_id'] != p['session_id'] or Key('state', 'user#' + p['owner_id']) not in checked:raise ValueError()
                for key, reference in source_refs.items():
                    actual = checked.get(key)
                    if actual is None or (actual.revision, actual.sha256) != (reference.revision, reference.sha256):raise ValueError()
            if kind == 'improvement-preview':
                counts['preview'] += 1; _shape(e['details'], frozenset(('preview_id', 'scope_sha256')))
                if e['details'] != {'preview_id': p['id'], 'scope_sha256': p['scope_sha256']} or not created <= e['at_ms'] < expires:raise ValueError()
                quota = Key('state', 'improvement-preview-quota#' + e['actor_scope'])
                if set(written) != {root.key, quota} or written[root.key].previous_revision is not None:raise ValueError()
                equal(written.get(root.key), root.key, 1, initial)
            elif kind == 'improvement-confirm' and committed:
                counts['confirm'] += 1; _shape(e['details'], frozenset(('permission_id', 'scope_sha256', 'grant_sha256')))
                if e['details'] != {'permission_id': ident, 'scope_sha256': p['scope_sha256'], 'grant_sha256': g['sha256']}:raise ValueError()
                if not g['created_at_ms'] <= e['at_ms'] < min(expires, g['expires_at_ms']):raise ValueError()
                quota = Key('state', 'improvement-confirm-quota#' + e['actor_scope'])
                if set(written) != {root.key, gkey, hkey, DATA, quota}:raise ValueError()
                equal(checked.get(root.key), root.key, 1, initial); equal(written.get(root.key), root.key, 2, p)
                equal(written.get(gkey), gkey, 1, g); equal(written.get(hkey), hkey, 1, {'id': ident, 'grant_sha256': g['sha256'], 'withdrawn': False})
                if written[root.key].previous_revision != 1 or any(written[k].previous_revision is not None for k in (gkey, hkey)):raise ValueError()
                links.update((CaptureLink(root.key, gkey, 'committed_grant'), CaptureLink(hkey, gkey, 'grant_head')))
            elif committed and kind == 'improvement-withdraw:' + ident:
                _shape(e['details'], frozenset(('permission_id', 'withdrawn')))
                if e['details'].get('permission_id') != ident or e['details'].get('withdrawn') is not True or h['withdrawn'] is not True:raise ValueError()
                if e['at_ms'] < h['withdrawn_at_ms']:raise ValueError()
                equal(checked.get(gkey), gkey, 1, g)
                quota = Key('state', 'improvement-withdraw-quota#' + e['actor_scope'])
                if hkey in written:
                    counts['withdraw'] += 1
                    if set(written) != {hkey, DATA, quota} or written[hkey].previous_revision != 1:raise ValueError()
                    equal(checked.get(hkey), hkey, 1, {'id': ident, 'grant_sha256': g['sha256'], 'withdrawn': False})
                    equal(written.get(hkey), hkey, 2, h)
                else:
                    if set(written) != {quota}:raise ValueError()
                    equal(checked.get(hkey), hkey, 2, h)
            else:raise ValueError()
            if DATA in written:
                if written[DATA].previous_revision != checked[DATA].revision or written[DATA].revision != checked[DATA].revision + 1:raise ValueError()
            for reference in (*binding.writes, *binding.checks):
                if reference.key not in owned:dependencies.add(CaptureRecord(reference.key, reference.revision, reference.sha256))
            links.add(CaptureLink(root.key, row.key, 'permission_history'))
        if (counts != {'preview': 1, 'confirm': int(committed), 'withdraw': int(committed and h['withdrawn'])}
                or len(original_actor_scopes) != 1 or len(review_data_refs) != 1):raise ValueError()
        return ImprovementFamily(_record(root), None if grant is None else _record(grant), None if head is None else _record(head),
            tuple(_record(copies[r.key]) for r in sorted(rows, key=lambda r: (r.key.table, r.key.resource))),
            tuple(sorted(links, key=lambda r: (r.source.table, r.source.resource, r.target.table, r.target.resource, r.kind))),
            tuple(sorted(dependencies, key=lambda r: (r.key.table, r.key.resource, r.revision, r.sha256))), size)
    except ImprovementHistoryHeld:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ImprovementHistoryHeld('complete supported optional-improvement history required') from exc
